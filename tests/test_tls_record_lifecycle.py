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
import analysis.tls_record_framing as framing_module
from analysis import (
    FeatureContractVersion, FlowCoordinationError, FlowObservationWindowClosureReason, FlowObservationWindowError,
    FlowStateCoordinator, TLSRecordObservation, TLSRecordStatus, TCPStreamStatus,
    analyze_packet, extract_flow_feature_snapshot, update_tls_record_state,
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
from tests.test_tls_record_framing import packet, payloads, wire


def record(instance, data, **kwargs):
    return instance.record(analyze_packet(packet(data, **kwargs))).active_window


def observe_records(current, streams, events):
    update = update_tls_record_state(current, streams)
    if update is not None:
        events.extend(update.forward_records + update.reverse_records)
    return update


def traffic():
    values = []
    for phase in range(4):
        for ipv6, port in ((False, 12345), (True, 12345), (True, 12346)):
            forward = wire(b'\x00\xffforward', 255, b'\x12\x34') + wire(b'next')
            reverse = wire(b'reverse') + wire()
            data, sequence, backward = ((forward[:2], 100, False), (reverse[:7], 900, True),
                                        (forward[2:], 102, False), (reverse[7:], 907, True))[phase]
            values.append(packet(data, sequence=sequence, seconds=len(values), reverse=backward,
                                 ipv6=ipv6, client_port=port, extensions=(0, 43, 60) if ipv6 else ()))
    return tuple(values)


def observable(window):
    state = window.tls_record_state
    directions = tuple(None if item is None else
                       (item.prefix, item.header, item.payload, item.status.value,
                        None if item.unavailable_reason is None else item.unavailable_reason.value,
                        item.consumed_offset, item.stream.status.value, item.stream.buffer_offset)
                       for item in (state.forward, state.reverse))
    return (window.key.sequence_number, window.identity.ip_version, window.identity.source_port,
            None if window.closure_reason is None else window.closure_reason.value, directions)


def record_observable(item):
    return (item.identity.ip_version, item.identity.source_port, item.direction.value,
            item.header, item.payload, item.stream.last_sequence_number, item.consumed_offset)


def replay():
    from analysis import FlowObservationWindowManager
    instance = FlowObservationWindowManager('tls', timedelta(seconds=60), max_active_windows=3)
    events, complete = [], []
    inputs = traffic() + (packet(b'gap', sequence=5000, seconds=12),
                          packet(b'\x17', client_port=12347, seconds=13))
    with patch.object(coordinator_module, 'update_tls_record_state',
                      side_effect=lambda current, streams: observe_records(current, streams, complete)):
        for source in inputs:
            update = instance.record(analyze_packet(source))
            events.extend(observable(window) for window in (update.active_window,) + update.closed_windows)
        events.extend(observable(window) for window in instance.end_capture_session())
    return tuple(map(record_observable, complete)), tuple(events)


class TLSRecordLifecycleTests(unittest.TestCase):
    def test_protocol_precedence_and_ineligible_ports(self):
        for port, data, attribute in ((389, ldap_message(), 'ldap_stream_state'), (53, framed(raw()), 'dns_stream_state')):
            for kwargs in ({'client_port': port}, {'port': port, 'client_port': 443}):
                state = FlowStateCoordinator().record(analyze_packet(packet(data, **kwargs)))
                self.assertIsNone(state.tls_record_state)
                self.assertIsNotNone(getattr(state, attribute))
        for port in (80, 8443, 853):
            state = FlowStateCoordinator().record(analyze_packet(packet(wire(b'x'), port=port)))
            self.assertIsNone(state.tls_record_state)

    def test_automatic_tls_never_invokes_dns_or_ldap_parser(self):
        with patch.object(coordinator_module, 'analyze_dns_message', side_effect=AssertionError('DNS')):
            with patch('analysis.ldap_stream_framing._message', side_effect=AssertionError('LDAP')):
                window, = run_packets((packet(wire(b'\x00opaque')),))
        self.assertIs(window.tls_record_state.forward.status, TLSRecordStatus.READY)
        self.assertIsNone(window.dns_stream_state)
        self.assertIsNone(window.coordinated_state.ldap_stream_state)

    def test_interleaved_ipv4_ipv6_and_client_ports(self):
        complete = []
        with patch.object(coordinator_module, 'update_tls_record_state',
                          side_effect=lambda current, streams: observe_records(current, streams, complete)):
            closed = []
            run_flow_observation_session(MemoryPacketSource(traffic()), capture_session_id='tls',
                                         inactivity_timeout=timedelta(seconds=60), closed_window_consumer=closed.append)
        self.assertEqual(len(closed), 3)
        self.assertEqual(len({window.identity for window in closed}), 3)
        self.assertEqual(payloads(complete), (b'\x00\xffforward', b'next') * 3 + (b'reverse', b'') * 3)
        for window in closed:
            self.assertIs(window.tls_record_state.forward.status, TLSRecordStatus.READY)
            self.assertIs(window.tls_record_state.reverse.status, TLSRecordStatus.READY)

    def test_incomplete_header_and_payload_at_session_closure(self):
        for data in (wire(b'abc')[:3], wire(b'abc')[:-1]):
            complete = []
            with patch.object(coordinator_module, 'update_tls_record_state',
                              side_effect=lambda current, streams: observe_records(current, streams, complete)):
                window, = run_packets((packet(data),))
            self.assertEqual(complete, [])
            self.assertIs(window.tls_record_state.forward.status, TLSRecordStatus.INCOMPLETE)
            self.assertEqual(window.tls_record_state.forward.consumed_offset, len(data))

    def test_explicit_close_and_repeated_finalization(self):
        instance = manager()
        active = record(instance, wire(b'complete') + b'\x17')
        closed = instance.close(active.identity)
        self.assertIs(closed.closure_reason, FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION)
        self.assertIs(closed.tls_record_state, active.tls_record_state)
        with self.assertRaises(FlowObservationWindowError):
            instance.close(active.identity)
        for _ in range(3):
            self.assertIs(replace(closed).tls_record_state, closed.tls_record_state)
        reopened = record(instance, b'\x03')
        self.assertEqual(reopened.tls_record_state.forward.prefix, b'\x03')
        self.assertEqual(len(instance.end_capture_session()), 1)
        self.assertEqual(instance.end_capture_session(), ())

    def test_inactivity_and_capacity_do_not_join_partial_records(self):
        for capacity, kwargs, reason in ((1, {'ipv6': True}, FlowObservationWindowClosureReason.CAPACITY),
                                         (2, {'seconds': 5}, FlowObservationWindowClosureReason.INACTIVITY)):
            instance = manager(capacity)
            before = record(instance, b'\x17')
            update = instance.record(analyze_packet(packet(b'\x03', sequence=101, **kwargs)))
            closed, = update.closed_windows
            self.assertIs(closed.closure_reason, reason)
            self.assertIs(closed.tls_record_state, before.tls_record_state)
            self.assertEqual(update.active_window.tls_record_state.forward.prefix, b'\x03')

    def test_infrastructure_failures_leave_published_state_retryable(self):
        targets = ('analysis.flow_state_coordinator.update_tcp_stream_state',
                   'analysis.tls_record_framing.consume_tcp_stream',
                   'analysis.flow_state_coordinator.update_tls_record_state',
                   'analysis.flow_observation_window.FlowObservationWindowUpdate')
        for target in targets:
            with self.subTest(target=target):
                instance = manager()
                data = wire(b'first') + wire(b'second')
                before = record(instance, data[:2])
                with patch(target, side_effect=MemoryError('infrastructure')):
                    with self.assertRaises(MemoryError):
                        record(instance, data[2:], sequence=102)
                self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
                complete = []
                with patch.object(coordinator_module, 'update_tls_record_state',
                                  side_effect=lambda current, streams: observe_records(current, streams, complete)):
                    after = record(instance, data[2:], sequence=102)
                    record(instance, data[2:], sequence=102)
                self.assertEqual(payloads(complete), (b'first', b'second'))
                self.assertEqual(after.tls_record_state.forward.consumed_offset, len(data))

    def test_late_record_allocation_failure_is_atomic(self):
        instance = manager()
        before = record(instance, b'')
        original = framing_module._build
        count = 0
        def allocate(model, **values):
            nonlocal count
            if model is TLSRecordObservation and values.get('header') is not None:
                count += 1
                if count == 2:
                    raise MemoryError('second complete record')
            return original(model, **values)
        data = wire(b'A') + wire(b'B')
        with patch.object(framing_module, '_build', side_effect=allocate):
            with self.assertRaises(MemoryError):
                record(instance, data)
        self.assertEqual(count, 2)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        complete = []
        with patch.object(coordinator_module, 'update_tls_record_state',
                          side_effect=lambda current, streams: observe_records(current, streams, complete)):
            record(instance, data)
        self.assertEqual(payloads(complete), (b'A', b'B'))

    def test_future_consumer_failure_at_prepare_boundary_keeps_candidate_unpublished(self):
        instance = manager()
        before = record(instance, b'\x17')
        data = wire(b'A') + wire(b'B')
        attempted = []
        def consume(current, streams):
            update = observe_records(current, streams, attempted)
            raise RuntimeError('future semantic consumer')
        with patch.object(coordinator_module, 'update_tls_record_state', side_effect=consume):
            with self.assertRaises(RuntimeError):
                record(instance, data[1:], sequence=101)
        self.assertEqual(payloads(attempted), (b'A', b'B'))
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        accepted = []
        with patch.object(coordinator_module, 'update_tls_record_state',
                          side_effect=lambda current, streams: observe_records(current, streams, accepted)):
            record(instance, data[1:], sequence=101)
            record(instance, data[1:], sequence=101)
        self.assertEqual(payloads(accepted), (b'A', b'B'))

    def test_failed_new_window_publication_does_not_create_state(self):
        instance = manager()
        with patch('analysis.flow_observation_window.FlowObservationWindowUpdate', side_effect=MemoryError('new window')):
            with self.assertRaises(MemoryError):
                record(instance, wire(b'A'))
        self.assertEqual(instance.active_windows(), ())
        after = record(instance, wire(b'A'))
        self.assertEqual(after.tls_record_state.forward.consumed_offset, 6)

    def test_capture_failure_preserves_completed_output_and_incomplete_suffix(self):
        source = MemoryPacketSource((packet(wire(b'A') + wire(b'B') + b'\x17'),), iteration_error=CaptureError('capture'))
        complete, closed = [], []
        with patch.object(coordinator_module, 'update_tls_record_state',
                          side_effect=lambda current, streams: observe_records(current, streams, complete)):
            with self.assertRaises(CaptureError):
                run_flow_observation_session(source, capture_session_id='tls', inactivity_timeout=timedelta(seconds=5),
                                             closed_window_consumer=closed.append)
        self.assertEqual(payloads(complete), (b'A', b'B'))
        self.assertEqual(closed[0].tls_record_state.forward.prefix, b'\x17')
        self.assertIs(closed[0].tls_record_state.forward.status, TLSRecordStatus.INCOMPLETE)
        self.assertEqual(source.events[-1], 'stop')

    def test_old_flow_window_and_completed_objects_are_released(self):
        instance = manager()
        complete = []
        with patch.object(coordinator_module, 'update_tls_record_state',
                          side_effect=lambda current, streams: observe_records(current, streams, complete)):
            first = record(instance, wire(b'A'))
        refs = [weakref.ref(value) for value in (first, first.coordinated_state, first.tls_record_state, complete[0])]
        record(instance, b'\x17', sequence=106)
        del first, complete
        gc.collect()
        self.assertTrue(all(ref() is None for ref in refs))
        active = instance.active_windows()[0]
        ref = weakref.ref(active.tls_record_state)
        instance.close(active.identity)
        del active
        gc.collect()
        self.assertIsNone(ref())

    def test_generic_snapshot_version_and_all_49_values_unchanged(self):
        inputs = (packet(wire(b'A')), packet(wire(b'B'), reverse=True, sequence=900, seconds=1))
        window, = run_packets(inputs)
        with patch.object(coordinator_module, 'update_tls_record_state', return_value=None):
            baseline, = run_packets(inputs)
        first, second = extract_flow_feature_snapshot(window), extract_flow_feature_snapshot(baseline)
        self.assertEqual(first.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
        self.assertEqual(snapshot_features(first), snapshot_features(second))
        self.assertEqual(project_flow_features(first), project_flow_features(second))
        self.assertEqual(len(project_flow_features(first).values), 49)

    def test_coordinator_type_reference_and_legacy_default(self):
        state = FlowStateCoordinator().record(analyze_packet(packet(b'\x17')))
        self.assertIs(state.tls_record_state.tcp_stream_state, state.tcp_stream_state)
        with self.assertRaises(TypeError):
            replace(state, tls_record_state={})
        with self.assertRaises(FlowCoordinationError):
            replace(state, tcp_stream_state=replace(state.tcp_stream_state))
        legacy = tuple(getattr(state, field.name) for field in fields(state) if field.name not in ('tls_record_state', 'tls_handshake_state', 'tls_handshake_statistics', 'tls_client_hellos', 'tls_client_hello_statistics'))
        self.assertIsNone(type(state)(*legacy).tls_record_state)

    def test_four_classic_pcap_encodings_through_real_capture_session(self):
        inputs = traffic()
        expected_records, expected_windows = None, None
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'tls.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes) for index, item in enumerate(inputs)), order, nano))
                        complete, closed = [], []
                        with patch.object(coordinator_module, 'update_tls_record_state',
                                          side_effect=lambda current, streams: observe_records(current, streams, complete)):
                            run_flow_observation_session(PcapPacketSource(path), capture_session_id='tls',
                                                         inactivity_timeout=timedelta(seconds=60), closed_window_consumer=closed.append)
                        records, windows = tuple(map(record_observable, complete)), tuple(map(observable, closed))
                        self.assertEqual(len(records), 12)
                        self.assertEqual(len(windows), 3)
                        if expected_records is None:
                            expected_records, expected_windows = records, windows
                        self.assertEqual((records, windows), (expected_records, expected_windows))

    def test_replay_covers_records_tcp_failure_and_capacity(self):
        complete, windows = replay()
        self.assertEqual((complete, windows), replay())
        self.assertEqual(len(complete), 12)
        self.assertEqual({row[0] for row in complete}, {4, 6})
        self.assertEqual(len({row[2] for row in complete}), 2)
        self.assertTrue(any(row[3] == 'capacity' for row in windows))
        self.assertTrue(any(direction is not None and direction[4] == 'gap' for row in windows for direction in row[-1]))

    def test_all_nine_hash_seed_timezone_combinations(self):
        script = ('from tests.test_tls_record_lifecycle import replay\n'
                  'import hashlib\nprint(hashlib.sha256(repr(replay()).encode()).hexdigest())\n')
        expected = hashlib.sha256(repr(replay()).encode()).hexdigest().encode() + b'\n'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                with self.subTest(seed=seed, zone=zone):
                    actual = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                    env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
                    self.assertEqual(actual, expected)
