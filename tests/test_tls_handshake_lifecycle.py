import gc
import hashlib
import os
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
import analysis.tls_handshake_framing as framing_module
from analysis import (
    FeatureContractVersion, FlowCoordinationError, FlowObservationWindowClosureReason,
    FlowObservationWindowError, FlowObservationWindowManager, FlowStateCoordinator,
    TLSHandshakeObservation, TLSHandshakeStatus, analyze_packet, extract_flow_feature_snapshot,
    update_tls_handshake_state,
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
from tests.test_tls_record_framing import packet, payloads, wire


def record(instance, data, **kwargs):
    return instance.record(analyze_packet(packet(data, **kwargs))).active_window


def collect(current, records, output):
    update = update_tls_handshake_state(current, records)
    output.extend(update.forward_messages + update.reverse_messages)
    return update


def traffic():
    values = []
    forward = message(b'\x00\xffforward', 255) + message(b'next')
    reverse = message(b'reverse') + message()
    forward_wire = wire(forward[:2], 22) + wire(b'ignored', 23) + wire(forward[2:], 22)
    reverse_wire = wire(reverse[:6], 22) + wire(b'', 22) + wire(reverse[6:], 22)
    for phase in range(4):
        for ipv6, port in ((False, 12345), (True, 12345), (True, 12346)):
            data, sequence, backward = ((forward_wire[:6], 100, False), (reverse_wire[:9], 900, True),
                                        (forward_wire[6:], 106, False), (reverse_wire[9:], 909, True))[phase]
            values.append(packet(data, sequence=sequence, seconds=len(values), reverse=backward,
                                 ipv6=ipv6, client_port=port, extensions=(0, 43, 60) if ipv6 else ()))
    return tuple(values)


def observable(window):
    state = window.tls_handshake_state
    directions = tuple(None if value is None else
                       (value.prefix, value.header, value.payload, value.status.value,
                        None if value.unavailable_reason is None else value.unavailable_reason.value,
                        value.consumed_offset, value.stream.buffer_offset)
                       for value in (state.forward, state.reverse))
    return (window.key.sequence_number, window.identity.ip_version, window.identity.source_port,
            None if window.closure_reason is None else window.closure_reason.value, directions)


def message_observable(value):
    return (value.identity.ip_version, value.identity.source_port, value.direction.value,
            value.header, value.payload, value.stream.last_sequence_number, value.consumed_offset)


def replay():
    instance = FlowObservationWindowManager('tls-handshake', timedelta(seconds=60), max_active_windows=3)
    output, windows, references = [], [], []
    sources = traffic() + (packet(b'gap', sequence=5000, seconds=12),
                           packet(wire(b'\x01', 22), client_port=12347, seconds=13))
    with patch.object(coordinator_module, 'update_tls_handshake_state',
                      side_effect=lambda current, records: collect(current, records, output)):
        for source in sources:
            update = instance.record(analyze_packet(source))
            references.append(weakref.ref(update.active_window.tls_handshake_state))
            windows.extend(observable(window) for window in (update.active_window,) + update.closed_windows)
        windows.extend(observable(window) for window in instance.end_capture_session())
    result = tuple(map(message_observable, output)), tuple(windows)
    del update, output, instance
    gc.collect()
    return result + (tuple(ref() is None for ref in references),)


class TLSHandshakeLifecycleTests(unittest.TestCase):
    def test_port_eligibility_and_ldap_dns_precedence(self):
        for port, data, name in ((389, ldap_message(), 'ldap_stream_state'), (53, framed(raw()), 'dns_stream_state')):
            for kwargs in ({'client_port': port}, {'client_port': 443, 'port': port}):
                state = FlowStateCoordinator().record(analyze_packet(packet(data, **kwargs)))
                self.assertIsNone(state.tls_handshake_state)
                self.assertIsNotNone(getattr(state, name))
        for port in (80, 8443, 853):
            state = FlowStateCoordinator().record(analyze_packet(packet(wire(message(b'A'), 22), port=port)))
            self.assertIsNone(state.tls_handshake_state)

    def test_real_session_interleaved_cross_record_and_directional_order(self):
        output, windows = [], []
        with patch.object(coordinator_module, 'update_tls_handshake_state',
                          side_effect=lambda current, records: collect(current, records, output)):
            run_flow_observation_session(MemoryPacketSource(traffic()), capture_session_id='tls-handshake',
                                         inactivity_timeout=timedelta(seconds=60), closed_window_consumer=windows.append)
        self.assertEqual(len(windows), 3)
        self.assertEqual(len({window.identity for window in windows}), 3)
        self.assertEqual(payloads(output), (b'\x00\xffforward', b'next') * 3 + (b'reverse', b'') * 3)
        for window in windows:
            self.assertIs(window.tls_handshake_state.forward.status, TLSHandshakeStatus.READY)
            self.assertIs(window.tls_handshake_state.reverse.status, TLSHandshakeStatus.READY)
            self.assertIs(window.tls_handshake_state.tls_record_state, window.tls_record_state)

    def test_no_parser_or_decryption_is_called_for_opaque_messages(self):
        with patch.object(coordinator_module, 'analyze_dns_message', side_effect=AssertionError('DNS')):
            with patch('analysis.ldap_stream_framing._message', side_effect=AssertionError('LDAP')):
                window, = run_packets((packet(wire(message(b'\x00opaque', 255), 22)),))
        self.assertIs(window.tls_handshake_state.forward.status, TLSHandshakeStatus.READY)
        self.assertIsNone(window.dns_stream_state)
        self.assertIsNone(window.coordinated_state.ldap_stream_state)

    def test_incomplete_header_and_body_at_closure(self):
        for data in (message(b'abc')[:2], message(b'abc')[:-1]):
            output = []
            with patch.object(coordinator_module, 'update_tls_handshake_state',
                              side_effect=lambda current, records: collect(current, records, output)):
                window, = run_packets((packet(wire(data, 22)),))
            self.assertEqual(output, [])
            self.assertIs(window.tls_handshake_state.forward.status, TLSHandshakeStatus.INCOMPLETE)

    def test_explicit_close_reopen_and_idempotent_finalization(self):
        instance = manager()
        first = record(instance, wire(message(b'A') + b'\x01', 22))
        closed = instance.close(first.identity)
        self.assertIs(closed.tls_handshake_state, first.tls_handshake_state)
        self.assertIs(closed.closure_reason, FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION)
        for _ in range(3):
            self.assertIs(replace(closed).tls_handshake_state, closed.tls_handshake_state)
        with self.assertRaises(FlowObservationWindowError):
            instance.close(first.identity)
        reopened = record(instance, wire(b'\x02', 22))
        self.assertEqual(reopened.tls_handshake_state.forward.prefix, b'\x02')
        self.assertEqual(len(instance.end_capture_session()), 1)
        self.assertEqual(instance.end_capture_session(), ())

    def test_inactivity_and_capacity_separate_partial_handshakes(self):
        for capacity, kwargs, reason in ((1, {'ipv6': True}, FlowObservationWindowClosureReason.CAPACITY),
                                         (2, {'seconds': 5}, FlowObservationWindowClosureReason.INACTIVITY)):
            instance = manager(capacity)
            first = record(instance, wire(b'\x01', 22))
            update = instance.record(analyze_packet(packet(wire(b'\x02', 22), sequence=106, **kwargs)))
            closed, = update.closed_windows
            self.assertIs(closed.closure_reason, reason)
            self.assertIs(closed.tls_handshake_state, first.tls_handshake_state)
            self.assertEqual(update.active_window.tls_handshake_state.forward.prefix, b'\x02')

    def test_fin_and_reset_preserve_complete_output_and_partial_suffix(self):
        for flags in (17, 20):
            output = []
            with patch.object(coordinator_module, 'update_tls_handshake_state',
                              side_effect=lambda current, records: collect(current, records, output)):
                window, = run_packets((packet(wire(message(b'A') + b'\x01', 22), flags=flags),))
            self.assertEqual(payloads(output), (b'A',))
            self.assertIs(window.tls_handshake_state.forward.status, TLSHandshakeStatus.INCOMPLETE)

    def test_failures_leave_candidate_consumption_retryable(self):
        targets = ('analysis.flow_state_coordinator.update_tls_record_state',
                   'analysis.tls_record_framing.consume_tcp_stream',
                   'analysis.flow_state_coordinator.update_tls_handshake_state',
                   'analysis.flow_observation_window.FlowObservationWindowUpdate',
                   'analysis.flow_state_coordinator.CoordinatedFlowState')
        for target in targets:
            with self.subTest(target=target):
                instance = manager()
                first = record(instance, wire(message(b'first')[:2], 22))
                data = wire(message(b'first')[2:] + message(b'second'), 22)
                with patch(target, side_effect=MemoryError('infrastructure')):
                    with self.assertRaises(MemoryError):
                        record(instance, data, sequence=107)
                self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
                output = []
                with patch.object(coordinator_module, 'update_tls_handshake_state',
                                  side_effect=lambda current, records: collect(current, records, output)):
                    record(instance, data, sequence=107)
                    record(instance, data, sequence=107)
                self.assertEqual(payloads(output), (b'first', b'second'))

    def test_late_message_allocation_failure_is_atomic(self):
        instance = manager()
        before = record(instance, wire(b'', 22))
        original, count = framing_module._build, 0
        def allocate(model, **values):
            nonlocal count
            if model is TLSHandshakeObservation and values.get('header') is not None:
                count += 1
                if count == 2:
                    raise MemoryError('second message')
            return original(model, **values)
        data = wire(message(b'A') + message(b'B'), 22)
        with patch.object(framing_module, '_build', side_effect=allocate):
            with self.assertRaises(MemoryError):
                record(instance, data, sequence=105)
        self.assertEqual(count, 2)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        output = []
        with patch.object(coordinator_module, 'update_tls_handshake_state',
                          side_effect=lambda current, records: collect(current, records, output)):
            record(instance, data, sequence=105)
        self.assertEqual(payloads(output), (b'A', b'B'))

    def test_capture_failure_preserves_published_prefix_and_partial_closure(self):
        source = MemoryPacketSource((packet(wire(message(b'A') + b'\x01', 22)),), iteration_error=CaptureError('capture'))
        output, closed = [], []
        with patch.object(coordinator_module, 'update_tls_handshake_state',
                          side_effect=lambda current, records: collect(current, records, output)):
            with self.assertRaises(CaptureError):
                run_flow_observation_session(source, capture_session_id='tls-handshake',
                                             inactivity_timeout=timedelta(seconds=5), closed_window_consumer=closed.append)
        self.assertEqual(payloads(output), (b'A',))
        self.assertEqual(closed[0].tls_handshake_state.forward.prefix, b'\x01')
        self.assertEqual(source.events[-1], 'stop')

    def test_owner_release_frees_old_windows_packets_and_messages(self):
        instance = manager()
        source = packet(wire(message(b'A'), 22))
        analyzed, output = analyze_packet(source), []
        with patch.object(coordinator_module, 'update_tls_handshake_state',
                          side_effect=lambda current, records: collect(current, records, output)):
            first = instance.record(analyzed).active_window
        refs = [weakref.ref(value) for value in (source, analyzed, first, first.coordinated_state,
                                                first.tls_handshake_state, output[0])]
        record(instance, wire(b'\x01', 22), sequence=110)
        del source, analyzed, first, output
        gc.collect()
        self.assertTrue(all(ref() is None for ref in refs))
        active = instance.active_windows()[0]
        ref = weakref.ref(active.tls_handshake_state)
        instance.close(active.identity)
        del active
        gc.collect()
        self.assertIsNone(ref())

    def test_generic_feature_contract_and_49_values_unchanged(self):
        inputs = (packet(wire(message(b'A'), 22)), packet(wire(message(b'B'), 22), sequence=900, reverse=True, seconds=1))
        window, = run_packets(inputs)
        original = coordinator_module.update_tls_handshake_state
        with patch.object(coordinator_module, 'update_tls_handshake_state', wraps=original) as updater:
            baseline, = run_packets(inputs)
        stripped = replace(baseline, coordinated_state=replace(baseline.coordinated_state, tls_handshake_state=None, tls_client_hellos=()))
        left, right = extract_flow_feature_snapshot(window), extract_flow_feature_snapshot(stripped)
        self.assertEqual(updater.call_count, 2)
        self.assertEqual(left.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
        self.assertEqual(snapshot_features(left), snapshot_features(right))
        self.assertEqual(project_flow_features(left), project_flow_features(right))
        self.assertEqual(len(project_flow_features(left).values), 49)

    def test_state_validation_and_legacy_constructor(self):
        state = FlowStateCoordinator().record(analyze_packet(packet(wire(b'\x01', 22))))
        self.assertIs(state.tls_handshake_state.tls_record_state, state.tls_record_state)
        with self.assertRaises(TypeError):
            replace(state, tls_handshake_state={})
        with self.assertRaises(FlowCoordinationError):
            replace(state, tls_record_state=None)
        values = tuple(getattr(state, field.name) for field in fields(state) if field.name not in ('tls_handshake_state', 'tls_handshake_statistics', 'tls_client_hellos', 'tls_client_hello_statistics', 'tls_server_hellos'))
        self.assertIsNone(type(state)(*values).tls_handshake_state)

    def test_four_pcap_encodings_through_capture_session(self):
        inputs, expected = traffic(), None
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'tls-handshake.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((i * 1000000, source.raw_bytes) for i, source in enumerate(inputs)), order, nano))
                        output, closed = [], []
                        with patch.object(coordinator_module, 'update_tls_handshake_state',
                                          side_effect=lambda current, records: collect(current, records, output)):
                            run_flow_observation_session(PcapPacketSource(path), capture_session_id='tls-handshake',
                                                         inactivity_timeout=timedelta(seconds=60), closed_window_consumer=closed.append)
                        actual = tuple(map(message_observable, output)), tuple(map(observable, closed))
                        self.assertEqual(len(output), 12)
                        self.assertEqual(len(closed), 3)
                        if expected is None:
                            expected = actual
                        self.assertEqual(actual, expected)

    def test_replay_includes_tcp_failure_capacity_and_release(self):
        output, windows, released = replay()
        self.assertEqual((output, windows, released), replay())
        self.assertEqual(len(output), 12)
        self.assertEqual({item[0] for item in output}, {4, 6})
        self.assertEqual(len({item[2] for item in output}), 2)
        self.assertTrue(any(row[3] == 'capacity' for row in windows))
        self.assertTrue(any(direction is not None and direction[4] == 'gap' for row in windows for direction in row[-1]))
        self.assertTrue(all(released))

    def test_all_nine_seed_timezone_combinations(self):
        script = ('from tests.test_tls_handshake_lifecycle import replay\n'
                  'import hashlib\nprint(hashlib.sha256(repr(replay()).encode()).hexdigest())\n')
        expected = hashlib.sha256(repr(replay()).encode()).hexdigest().encode() + b'\n'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                with self.subTest(seed=seed, zone=zone):
                    actual = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                    env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
                    self.assertEqual(actual, expected)
