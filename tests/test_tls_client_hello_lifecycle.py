import gc
import hashlib
import os
import random
import subprocess
import sys
import unittest
import weakref
from dataclasses import fields, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import analysis.flow_state_coordinator as coordinator_module
from analysis import (
    FeatureContractVersion, FlowCoordinationError, FlowDirection, FlowObservationWindowClosureReason,
    FlowObservationWindowManager, FlowStateCoordinator, TCPStreamStatus, TLSClientHelloStatus,
    analyze_packet, analyze_tls_client_hello, extract_flow_feature_snapshot,
)
from application import run_flow_observation_session
from capture import CaptureError, PcapPacketSource
from ml import project_flow_features
from tests.pcap_scenarios import pcap_bytes
from tests.test_dns_correlation_lifecycle import manager
from tests.test_dns_stream_lifecycle import raw, framed
from tests.test_dns_transaction_statistics_lifecycle import run_packets
from tests.test_flow_feature_snapshot import snapshot_features
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ldap import message as ldap_message
from tests.test_tls_handshake_framing import message
from tests.test_tls_record_framing import packet, wire
from tests.test_tls_client_hello import body, extension, parse, selected_body


def record(instance, data, **kwargs):
    return instance.record(analyze_packet(packet(data, **kwargs))).active_window


def hello_observable(value):
    hello = value.client_hello
    representation = None if hello is None else (
        hello.legacy_version, hello.random, hello.session_id, hello.cipher_suites, hello.compression_methods,
        hello.extensions_present, tuple((item.extension_type, item.data, item.supported_groups,
                                         item.signature_algorithms, item.alpn_protocols) for item in hello.extensions))
    return (value.identity.ip_version, value.identity.source_port, value.direction.value, value.consumed_offset,
            value.status.value, value.reason, value.failure_offset, representation)


def observable(window):
    framing = window.tls_handshake_state
    return (window.key.sequence_number, window.identity.ip_version, window.identity.source_port,
            None if window.closure_reason is None else window.closure_reason.value,
            tuple(map(hello_observable, window.tls_client_hellos)),
            tuple(None if value is None or value.unavailable_reason is None else value.unavailable_reason.value
                  for value in (framing.forward, framing.reverse)),
            window.tls_handshake_statistics)


def traffic():
    output = []
    forward = message(selected_body()) + message(body()) + message(body(extensions=()) + b'trailing')
    reverse = message(body(session=b'other', extensions=(extension(65000, b'\x00'),))) + message(b'\x03')
    left = wire(forward[:3], 22) + wire(b'ignored', 23) + wire(forward[3:], 22)
    right = wire(reverse[:8], 22) + wire(b'', 22) + wire(reverse[8:], 22)
    for phase in range(4):
        for ipv6, client in ((False, 12345), (True, 12345), (True, 12346)):
            data, seq, back = ((left[:6], 100, False), (right[:10], 900, True),
                               (left[6:], 106, False), (right[10:], 910, True))[phase]
            output.append(packet(data, sequence=seq, reverse=back, seconds=len(output), ipv6=ipv6,
                                 client_port=client, extensions=(0, 43, 60) if ipv6 else ()))
    return tuple(output)


def replay():
    instance = FlowObservationWindowManager('client-hello', timedelta(seconds=60), max_active_windows=3)
    events, references = [], []
    sources = traffic() + (packet(b'gap', sequence=5000, seconds=12),
                           packet(wire(message(body()), 22), client_port=12347, seconds=13))
    for source in sources:
        update = instance.record(analyze_packet(source))
        references.append(weakref.ref(update.active_window))
        references.extend(weakref.ref(value) for value in update.active_window.tls_client_hellos)
        events.extend(observable(window) for window in (update.active_window,) + update.closed_windows)
    events.extend(observable(window) for window in instance.end_capture_session())
    del update, instance
    gc.collect()
    return tuple(events), tuple(ref() is None for ref in references)


class TLSClientHelloLifecycleTests(unittest.TestCase):
    def test_eligible_empty_flow_and_ineligible_ports_have_no_analysis(self):
        for port in (443, 80, 8443, 853):
            state = FlowStateCoordinator().record(analyze_packet(packet(b'', port=port)))
            self.assertEqual(state.tls_client_hellos, ())
        with patch.object(coordinator_module, 'analyze_tls_client_hello', side_effect=AssertionError('ineligible')):
            for port in (80, 8443, 853):
                self.assertEqual(run_packets((packet(wire(message(body()), 22), port=port),))[0].tls_client_hellos, ())

    def test_completed_messages_are_published_in_wire_order(self):
        data = message(body(session=b'A')) + message(body(session=b'B'))
        window, = run_packets((packet(wire(data, 22)),))
        self.assertEqual(tuple(value.client_hello.session_id for value in window.tls_client_hellos), (b'A', b'B'))
        self.assertEqual(window.tls_handshake_statistics.forward.total_message_count, 2)

    def test_partial_then_later_completion_is_emitted_once(self):
        instance = manager()
        last = message(body(session=b'last'))
        first_data = wire(message(body(session=b'A')) + last[:6], 22)
        first = record(instance, first_data)
        self.assertEqual(tuple(value.client_hello.session_id for value in first.tls_client_hellos), (b'A',))
        final_data = wire(last[6:], 22)
        final = record(instance, final_data, sequence=100 + len(first_data))
        self.assertEqual(tuple(value.client_hello.session_id for value in final.tls_client_hellos), (b'last',))
        duplicate = record(instance, final_data, sequence=100 + len(first_data))
        self.assertEqual(duplicate.tls_client_hellos, ())
        self.assertEqual(duplicate.tls_handshake_statistics.forward.total_message_count, 2)

    def test_one_byte_tcp_fragments_never_publish_incomplete_handshake(self):
        data, instance = wire(message(body()), 22), manager()
        for index, byte in enumerate(data):
            active = record(instance, bytes((byte,)), sequence=100 + index)
            self.assertEqual(len(active.tls_client_hellos), int(index == len(data) - 1))
        self.assertIs(active.tls_client_hellos[0].status, TLSClientHelloStatus.COMPLETE)

    def test_seeded_tcp_and_record_fragmentation_preserve_every_result(self):
        raws = tuple(body(session=bytes((i,))) for i in range(8))
        data = b''.join(map(message, raws))
        rng = random.Random(26)
        for _ in range(4):
            cuts = sorted({0, len(data)} | {rng.randrange(len(data)) for _ in range(50)})
            stream = b''.join(wire(data[a:b], 22) for a, b in zip(cuts, cuts[1:]))
            cuts = sorted({0, len(stream)} | {rng.randrange(len(stream)) for _ in range(70)})
            instance, values = manager(), []
            for a, b in zip(cuts, cuts[1:]):
                values.extend(record(instance, stream[a:b], sequence=100 + a).tls_client_hellos)
            self.assertEqual(tuple(value.client_hello for value in values), tuple(parse(raw).client_hello for raw in raws))

    def test_one_byte_record_payloads_cross_every_handshake_boundary(self):
        data, instance, values = message(selected_body()), manager(), []
        for index, byte in enumerate(data):
            active = record(instance, wire(bytes((byte,)), 22), sequence=100 + 6 * index)
            values.extend(active.tls_client_hellos)
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0].client_hello, parse(selected_body()).client_hello)

    def test_non_handshake_record_is_not_parsed_or_appended(self):
        data = message(body())
        stream = wire(data[:6], 22) + wire(b'not handshake', 23) + wire(data[6:], 22)
        window, = run_packets((packet(stream),))
        self.assertEqual(len(window.tls_client_hellos), 1)
        self.assertIs(window.tls_client_hellos[0].status, TLSClientHelloStatus.COMPLETE)

    def test_only_client_hello_type_enters_parser(self):
        data = b''.join(message(body(), kind) for kind in (0, 2, 11, 255))
        with patch.object(coordinator_module, 'analyze_tls_client_hello', side_effect=AssertionError('wrong type')):
            window, = run_packets((packet(wire(data, 22)),))
        self.assertEqual(window.tls_client_hellos, ())
        self.assertEqual(window.tls_handshake_statistics.forward.total_message_count, 4)

    def test_malformed_and_incomplete_bodies_do_not_stop_later_messages(self):
        raws = (body(suites=()), b'\x03', body(), body(extensions=(extension(65000),) * 1025))
        window, = run_packets((packet(wire(b''.join(map(message, raws)), 22)),))
        self.assertEqual(tuple(value.status for value in window.tls_client_hellos),
                         (TLSClientHelloStatus.MALFORMED, TLSClientHelloStatus.INCOMPLETE,
                          TLSClientHelloStatus.COMPLETE, TLSClientHelloStatus.UNSUPPORTED))
        self.assertEqual(window.tls_handshake_statistics.forward.total_message_count, 4)
        self.assertEqual(window.tls_handshake_statistics.forward.total_message_length_bytes, sum(map(len, raws)))

    def test_ipv4_ipv6_extensions_both_directions_and_port_orientation(self):
        for ipv6, extensions in ((False, ()), (True, ()), (True, (0,)), (True, (60,)), (True, (0, 43, 60))):
            for reverse in (False, True):
                window, = run_packets((packet(wire(message(body()), 22), ipv6=ipv6, extensions=extensions, reverse=reverse),))
                value, = window.tls_client_hellos
                self.assertEqual(value.identity.ip_version, 6 if ipv6 else 4)
                self.assertIs(value.direction, FlowDirection.REVERSE if reverse else FlowDirection.FORWARD)
        window, = run_packets((packet(wire(message(body()), 22), port=12345, client_port=443),))
        self.assertEqual(len(window.tls_client_hellos), 1)

    def test_opposite_partial_directions_and_independent_client_ports(self):
        first, second = message(body(session=b'forward')), message(body(session=b'reverse'))
        instance = manager()
        record(instance, wire(first[:6], 22))
        record(instance, wire(second[:8], 22), reverse=True, sequence=900)
        other = record(instance, wire(message(body(session=b'other')), 22), client_port=12346)
        forward = record(instance, wire(first[6:], 22), sequence=111)
        reverse = record(instance, wire(second[8:], 22), reverse=True, sequence=913)
        for window, session, direction in ((other, b'other', FlowDirection.FORWARD),
                                            (forward, b'forward', FlowDirection.FORWARD),
                                            (reverse, b'reverse', FlowDirection.REVERSE)):
            value, = window.tls_client_hellos
            self.assertEqual(value.client_hello.session_id, session)
            self.assertIs(value.direction, direction)
        self.assertEqual(reverse.tls_handshake_statistics.forward.total_message_count, 1)
        self.assertEqual(reverse.tls_handshake_statistics.reverse.total_message_count, 1)

    def test_ldap_and_dns_precedence_do_not_invoke_client_hello_parser(self):
        with patch.object(coordinator_module, 'analyze_tls_client_hello', side_effect=AssertionError('precedence')):
            for port, data, field in ((389, ldap_message(), 'ldap_stream_state'), (53, framed(raw()), 'dns_stream_state')):
                for kwargs in ({'client_port': port}, {'port': port, 'client_port': 443}):
                    state = FlowStateCoordinator().record(analyze_packet(packet(data, **kwargs)))
                    self.assertIsNotNone(getattr(state, field))
                    self.assertEqual(state.tls_client_hellos, ())

    def test_dns_and_ldap_parsers_are_not_invoked_for_client_hello(self):
        with patch.object(coordinator_module, 'analyze_dns_message', side_effect=AssertionError('DNS')):
            with patch('analysis.ldap_stream_framing._message', side_effect=AssertionError('LDAP')):
                window, = run_packets((packet(wire(message(selected_body()), 22)),))
        self.assertIs(window.tls_client_hellos[0].status, TLSClientHelloStatus.COMPLETE)

    def test_gap_conflict_overlap_sticky_failure_never_fabricate_hello(self):
        data = wire(message(body())[:8], 22)
        for sequence, payload, reason in ((5000, b'gap', TCPStreamStatus.GAP), (105, b'xxx', TCPStreamStatus.CONFLICT),
                                          (110, data[10:] + b'extra', TCPStreamStatus.OVERLAP)):
            instance = manager()
            record(instance, data)
            failed = record(instance, payload, sequence=sequence)
            self.assertIs(failed.tls_handshake_state.forward.unavailable_reason, reason)
            self.assertEqual(failed.tls_client_hellos, ())
            later = record(instance, wire(message(body()), 22), sequence=6000)
            self.assertIs(later.tls_handshake_state.forward.unavailable_reason, reason)
            self.assertEqual(later.tls_client_hellos, ())

    def test_fin_reset_and_incomplete_closure_preserve_published_results(self):
        for flags, reason in ((17, TCPStreamStatus.FIN), (20, TCPStreamStatus.RESET)):
            instance = manager()
            window = record(instance, wire(message(body()) + b'\x01', 22), flags=flags)
            self.assertEqual(len(window.tls_client_hellos), 1)
            self.assertIs(window.tls_handshake_state.forward.stream.status, reason)
            closed = instance.close(window.identity)
            self.assertIs(closed.tls_client_hellos, window.tls_client_hellos)
        for suffix in (b'\x01', message(body())[:8]):
            window, = run_packets((packet(wire(suffix, 22)),))
            self.assertEqual(window.tls_client_hellos, ())

    def test_explicit_close_and_repeated_finalization_do_not_reparse(self):
        instance = manager()
        active = record(instance, wire(message(body()), 22))
        with patch.object(coordinator_module, 'analyze_tls_client_hello', side_effect=AssertionError('reparse')):
            closed = instance.close(active.identity)
            for _ in range(3):
                self.assertIs(replace(closed).tls_client_hellos, active.tls_client_hellos)
            self.assertEqual(instance.end_capture_session(), ())
            self.assertEqual(instance.end_capture_session(), ())

    def test_capacity_and_inactivity_separate_analysis_ownership(self):
        for capacity, kwargs, reason in ((1, {'ipv6': True}, FlowObservationWindowClosureReason.CAPACITY),
                                         (2, {'seconds': 5}, FlowObservationWindowClosureReason.INACTIVITY)):
            instance = manager(capacity)
            first = record(instance, wire(message(body(session=b'first')), 22))
            update = instance.record(analyze_packet(packet(wire(message(body(session=b'new')), 22), **kwargs)))
            closed, = update.closed_windows
            self.assertIs(closed.closure_reason, reason)
            self.assertIs(closed.tls_client_hellos, first.tls_client_hellos)
            self.assertEqual(update.active_window.tls_client_hellos[0].client_hello.session_id, b'new')
            self.assertEqual(update.active_window.tls_handshake_statistics.forward.total_message_count, 1)

    def test_late_parser_failure_preserves_published_state_for_retry(self):
        instance = manager()
        first_data = wire(message(body(session=b'before')), 22)
        before = record(instance, first_data)
        calls = 0
        def analyze(source):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise MemoryError('second ClientHello')
            return analyze_tls_client_hello(source)
        data = wire(message(body(session=b'A')) + message(body(session=b'B')), 22)
        with patch.object(coordinator_module, 'analyze_tls_client_hello', side_effect=analyze):
            with self.assertRaises(MemoryError):
                record(instance, data, sequence=100 + len(first_data))
        self.assertEqual(calls, 2)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        after = record(instance, data, sequence=100 + len(first_data))
        duplicate = record(instance, data, sequence=100 + len(first_data))
        self.assertEqual(tuple(value.client_hello.session_id for value in after.tls_client_hellos), (b'A', b'B'))
        self.assertEqual(after.tls_handshake_statistics.forward.total_message_count, 3)
        self.assertEqual(duplicate.tls_client_hellos, ())

    def test_allocation_state_and_publication_failures_leave_bytes_retryable(self):
        for target in ('analysis.tls_client_hello._extension', 'analysis.tls_client_hello._build',
                       'analysis.flow_state_coordinator.CoordinatedFlowState',
                       'analysis.flow_observation_window.FlowObservationWindowUpdate'):
            instance = manager()
            data = message(selected_body())
            first = wire(data[:8], 22)
            before = record(instance, first)
            with patch(target, side_effect=MemoryError('candidate')):
                with self.assertRaises(MemoryError):
                    record(instance, wire(data[8:], 22), sequence=100 + len(first))
            self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
            after = record(instance, wire(data[8:], 22), sequence=100 + len(first))
            self.assertEqual(len(after.tls_client_hellos), 1)
            self.assertEqual(after.tls_handshake_statistics.forward.total_message_count, 1)

    def test_capture_failure_preserves_latest_published_batch_and_partial_suffix(self):
        source = MemoryPacketSource((packet(wire(message(body()) + b'\x01', 22)),), iteration_error=CaptureError('capture'))
        windows = []
        with self.assertRaises(CaptureError):
            run_flow_observation_session(source, capture_session_id='client-hello', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=windows.append)
        self.assertEqual(len(windows[0].tls_client_hellos), 1)
        self.assertEqual(windows[0].tls_handshake_state.forward.prefix, b'\x01')
        self.assertEqual(source.events[-1], 'stop')

    def test_next_packet_replaces_batch_and_releases_previous_result(self):
        instance = manager()
        first_data = wire(message(selected_body()), 22)
        first = record(instance, first_data)
        references = tuple(weakref.ref(value) for value in (first, first.coordinated_state, first.tls_client_hellos[0],
                                                           first.tls_client_hellos[0].client_hello))
        later = record(instance, wire(b'', 22), sequence=100 + len(first_data))
        self.assertEqual(later.tls_client_hellos, ())
        del first
        gc.collect()
        self.assertTrue(all(ref() is None for ref in references))

    def test_window_release_frees_messages_and_source_objects(self):
        instance = manager()
        source = packet(wire(message(selected_body()), 22))
        analyzed = analyze_packet(source)
        active = instance.record(analyzed).active_window
        value = active.tls_client_hellos[0].client_hello
        references = tuple(weakref.ref(item) for item in (source, analyzed, active, active.coordinated_state,
                                                         active.tls_handshake_state, active.tls_client_hellos[0]))
        instance.close(active.identity)
        del active, analyzed, source
        gc.collect()
        self.assertTrue(all(ref() is None for ref in references))
        self.assertEqual(value.extensions[0].supported_groups, (65535, 0, 29))

    def test_long_stream_retains_only_current_result_batch(self):
        instance = manager()
        data = wire(message(body(session=b'current', extensions=(extension(65000, b'x' * 1024),))), 22)
        references = []
        for index in range(160):
            active = record(instance, data, sequence=100 + index * len(data))
            references.append(weakref.ref(active.tls_client_hellos[0]))
            self.assertEqual(len(active.tls_client_hellos), 1)
        gc.collect()
        self.assertTrue(all(ref() is None for ref in references[:-1]))
        self.assertEqual(active.tls_handshake_statistics.forward.total_message_count, 160)
        self.assertGreater(active.tls_handshake_state.forward.stream.buffer_offset, 65536)

    def test_large_valid_client_hello_reclaims_lower_layer_buffers(self):
        raw_body = body(session=b's' * 255, suites=(65535,) * 32767, compression=(255,) * 255,
                        extensions=(extension(65535, b'x' * 65531),))
        data, instance, seq = message(raw_body), manager(), 100
        for start in range(0, len(data), 16000):
            raw_record = wire(data[start:start + 16000], 22)
            active = record(instance, raw_record, sequence=seq)
            seq += len(raw_record)
        self.assertEqual(active.tls_client_hellos[0].client_hello, parse(raw_body).client_hello)
        self.assertGreater(active.tls_handshake_state.forward.stream.buffer_offset, 65536)
        self.assertEqual(active.tls_handshake_state.forward.payload, b'')

    def test_generic_snapshot_projection_and_statistics_are_unchanged(self):
        sources = (packet(wire(message(selected_body()), 22)),
                   packet(wire(message(body()), 22), reverse=True, seconds=1, sequence=900))
        active, = run_packets(sources)
        with patch.object(coordinator_module, 'analyze_tls_client_hello', wraps=analyze_tls_client_hello):
            baseline, = run_packets(sources)
        clean = replace(baseline, coordinated_state=replace(baseline.coordinated_state, tls_client_hellos=()))
        left, right = extract_flow_feature_snapshot(active), extract_flow_feature_snapshot(clean)
        self.assertEqual(left.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
        self.assertEqual(snapshot_features(left), snapshot_features(right))
        self.assertEqual(project_flow_features(left), project_flow_features(right))
        self.assertEqual(len(project_flow_features(left).values), 49)
        self.assertEqual(active.tls_handshake_statistics, baseline.tls_handshake_statistics)
        self.assertEqual(active.tls_handshake_state, baseline.tls_handshake_state)
        self.assertEqual(active.tls_record_state, baseline.tls_record_state)

    def test_coordinated_state_validates_tuple_type_identity_and_tls_owner(self):
        state = FlowStateCoordinator().record(analyze_packet(packet(wire(message(body()), 22))))
        with self.assertRaises(TypeError):
            replace(state, tls_client_hellos=[])
        with self.assertRaises(TypeError):
            replace(state, tls_client_hellos=(None,))
        other = FlowStateCoordinator().record(analyze_packet(packet(wire(message(body()), 22), ipv6=True)))
        with self.assertRaises(FlowCoordinationError):
            replace(state, tls_client_hellos=other.tls_client_hellos)
        with self.assertRaises(FlowCoordinationError):
            replace(state, tls_handshake_state=None)
        legacy = tuple(getattr(state, member.name) for member in fields(state)
                       if member.name not in ('tls_client_hellos', 'tls_client_hello_statistics', 'tls_server_hellos', 'tls_server_hello_statistics'))
        self.assertEqual(type(state)(*legacy).tls_client_hellos, ())

    def test_session_four_classic_pcap_encodings_publish_identical_results(self):
        expected = None
        sources = traffic()
        original = FlowObservationWindowManager.record
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'client-hello.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    events, closed = [], []
                    def capture(instance, analysis):
                        update = original(instance, analysis)
                        events.extend(map(hello_observable, update.active_window.tls_client_hellos))
                        return update
                    path.write_bytes(pcap_bytes(tuple((i * 1000000, source.raw_bytes) for i, source in enumerate(sources)), order, nano))
                    with patch.object(FlowObservationWindowManager, 'record', capture):
                        run_flow_observation_session(PcapPacketSource(path), capture_session_id='client-hello',
                                                     inactivity_timeout=timedelta(seconds=60), closed_window_consumer=closed.append)
                    actual = tuple(events), tuple(map(observable, closed))
                    self.assertEqual(len(events), 15)
                    self.assertEqual(len(closed), 3)
                    self.assertEqual(sum(value[4] == 'complete' for value in events), 9)
                    if expected is None:
                        expected = actual
                    self.assertEqual(actual, expected)

    def test_replay_covers_failures_directions_capacity_and_release(self):
        events, released = replay()
        self.assertEqual((events, released), replay())
        self.assertEqual({value[1] for value in events}, {4, 6})
        self.assertTrue(any(value[3] == 'capacity' for value in events))
        self.assertTrue(any('gap' in value[5] for value in events))
        messages = tuple(message for event in events for message in event[4])
        self.assertEqual({value[2] for value in messages}, {FlowDirection.FORWARD.value, FlowDirection.REVERSE.value})
        self.assertEqual({value[4] for value in messages}, {'complete', 'malformed', 'incomplete'})
        self.assertTrue(all(released))

    def test_all_nine_seed_timezone_combinations(self):
        script = ('from tests.test_tls_client_hello_lifecycle import replay\n'
                  'import hashlib\nprint(hashlib.sha256(repr(replay()).encode()).hexdigest())\n')
        expected = hashlib.sha256(repr(replay()).encode()).hexdigest().encode() + b'\n'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                with self.subTest(seed=seed, zone=zone):
                    actual = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                    env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
                    self.assertEqual(actual, expected)
