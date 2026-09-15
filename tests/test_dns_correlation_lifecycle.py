import gc
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import asdict, fields, replace
from datetime import timedelta
from pathlib import Path
from struct import pack
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    DNSCorrelationReason, DNSCorrelationStatus, FlowCoordinationError, FlowObservationWindow,
    FlowObservationWindowClosureReason, FlowObservationWindowError, FlowObservationWindowManager,
    FlowStateCoordinator, analyze_packet,
)
from application import run_flow_observation_session
from capture import CaptureError, PcapPacketSource
from tests.pcap_scenarios import addresses, checksum, pcap_bytes
from tests.test_dns import header, name, question
from tests.test_dns_correlation import advance, full_state
from tests.test_dns_packet_analysis import dns_packet
from tests.test_flow_observation_session import MemoryPacketSource


def packet(identifier=1, response=False, seconds=0, ipv6=False, port=53, client_port=12345):
    raw = header(1, flags=0x8000 if response else 0, identifier=identifier) + question(name(b'example'))
    observation = dns_packet(raw, ipv6, response, seconds=seconds, port=port)
    if client_port == 12345:
        return observation
    wire = bytearray(observation.raw_bytes)
    start = 54 if ipv6 else 34
    port_offset = start + 2 if response else start
    wire[port_offset:port_offset + 2] = pack('!H', client_port)
    length = int.from_bytes(wire[start + 4:start + 6], 'big')
    wire[start + 6:start + 8] = b'\x00\x00'
    source, destination = addresses(ipv6, response)
    pseudo = source + destination + (pack('!I3xB', length, 17) if ipv6 else pack('!BBH', 0, 17, length))
    wire[start + 6:start + 8] = pack('!H', checksum(pseudo + bytes(wire[start:start + length])) or 65535)
    return replace(observation, raw_bytes=bytes(wire))


def manager(capacity=1024):
    return FlowObservationWindowManager('dns', timedelta(seconds=5), max_active_windows=capacity)


def record(window_manager, **kwargs):
    return window_manager.record(analyze_packet(packet(**kwargs))).active_window


def replay():
    instance = manager(2)
    events = []
    for ipv6 in (False, True):
        for identifier, response in ((1, False), (1, True), (1, True), (2, False), (2, False), (2, True)):
            active = record(instance, identifier=identifier, response=response, ipv6=ipv6)
            events.append(asdict(active.dns_correlation_state))
    events.append(asdict(advance(full_state(), 128)))
    for index in range(180):
        update = instance.record(analyze_packet(packet(index % 131, bool(index % 3), index, bool(index % 2),
                                                       53 if index % 7 else 12345)))
        if update.active_window.dns_correlation_state is not None:
            events.append(asdict(update.active_window.dns_correlation_state))
        events.extend(asdict(window.dns_correlation_state) for window in update.closed_windows
                      if window.dns_correlation_state is not None)
        assert len(instance.active_windows()) <= 2
    events.extend(asdict(window.dns_correlation_state) for window in instance.end_capture_session()
                  if window.dns_correlation_state is not None)
    return events


class DNSCorrelationLifecycleTests(unittest.TestCase):
    def test_real_ipv4_udp_request_response(self):
        instance = manager()
        request = record(instance)
        response = record(instance, response=True, seconds=1)
        event, = response.dns_correlation_state.observations
        self.assertIs(event.status, DNSCorrelationStatus.MATCHED)
        self.assertIs(event.request, request.dns_correlation_state.requests[0].message)
        self.assertEqual(event.duration, timedelta(seconds=1))

    def test_real_ipv6_udp_request_response(self):
        instance = manager()
        record(instance, ipv6=True)
        response = record(instance, response=True, seconds=1, ipv6=True)
        self.assertIs(response.dns_correlation_state.observations[0].status, DNSCorrelationStatus.MATCHED)
        self.assertEqual(response.identity.ip_version, 6)

    def test_interleaved_ip_versions_do_not_cross_match(self):
        instance = manager()
        record(instance)
        response = record(instance, ipv6=True, response=True)
        self.assertIs(response.dns_correlation_state.observations[0].status, DNSCorrelationStatus.UNMATCHED)
        self.assertIs(record(instance, response=True).dns_correlation_state.observations[0].status, DNSCorrelationStatus.MATCHED)

    def test_flow_and_session_scope(self):
        first, second = manager(), manager()
        record(first)
        self.assertIs(record(second, response=True).dns_correlation_state.observations[0].status, DNSCorrelationStatus.UNMATCHED)
        other = first.record(analyze_packet(dns_packet(header(1, flags=0x8000) + question(name(b'example')),
                                                         reverse=True, port=12345))).active_window
        self.assertIsNone(other.dns_correlation_state)
        self.assertEqual(len(first.active_windows()), 2)

    def test_same_id_across_client_ports_never_cross_matches(self):
        for ipv6 in (False, True):
            instance = manager()
            first = record(instance, ipv6=ipv6)
            other = record(instance, ipv6=ipv6, client_port=12346, response=True)
            self.assertNotEqual(first.identity, other.identity)
            self.assertIs(other.dns_correlation_state.observations[0].status, DNSCorrelationStatus.UNMATCHED)
            self.assertIs(record(instance, ipv6=ipv6, response=True).dns_correlation_state.observations[0].status,
                          DNSCorrelationStatus.MATCHED)

    def test_many_real_requests_saturate_without_unbounded_history(self):
        instance = manager()
        for index in range(400):
            state = record(instance, identifier=index).dns_correlation_state
            self.assertLessEqual(len(state.requests), 128)
            self.assertLessEqual(len(state.observations), 129)
        self.assertEqual(state.requests, ())
        self.assertIs(state.unavailable_reason, DNSCorrelationReason.LIMIT_EXCEEDED)
        state = record(instance, identifier=0, response=True).dns_correlation_state
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.UNMATCHED)
        self.assertIs(state.observations[0].reason, DNSCorrelationReason.LIMIT_EXCEEDED)

    def test_explicit_close_releases_pending_in_stored_state(self):
        instance = manager()
        before = record(instance)
        closed = instance.close(before.identity)
        self.assertIs(closed.closure_reason, FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION)
        self.assertTrue(closed.coordinated_state.dns_correlation_state.finalized)
        self.assertEqual(closed.coordinated_state.dns_correlation_state.requests, ())
        self.assertEqual(instance.active_windows(), ())
        self.assertEqual(len(before.dns_correlation_state.requests), 1)
        self.assertIs(closed.dns_correlation_state, closed.dns_correlation_state)

    def test_inactivity_closes_before_response_in_new_window(self):
        instance = manager()
        first = record(instance)
        update = instance.record(analyze_packet(packet(response=True, seconds=5)))
        self.assertIs(update.closed_windows[0].closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
        self.assertIs(update.closed_windows[0].dns_correlation_state.observations[0].status, DNSCorrelationStatus.UNRESOLVED)
        self.assertIs(update.active_window.dns_correlation_state.observations[0].status, DNSCorrelationStatus.UNMATCHED)
        self.assertNotEqual(first.key, update.active_window.key)

    def test_capture_end_finalizes_in_window_sequence_order(self):
        instance = manager()
        record(instance, ipv6=True)
        record(instance)
        closed = instance.end_capture_session()
        self.assertEqual([item.key.sequence_number for item in closed], [0, 1])
        for item in closed:
            self.assertEqual(item.dns_correlation_state.requests, ())
            self.assertIs(item.dns_correlation_state.observations[0].reason, DNSCorrelationReason.FLOW_CLOSED)
        self.assertEqual(instance.end_capture_session(), ())

    def test_capacity_closure_does_not_change_victim_policy(self):
        instance = manager(1)
        before = record(instance)
        update = instance.record(analyze_packet(packet(ipv6=True, seconds=1)))
        closed, = update.closed_windows
        self.assertEqual(closed.key, before.key)
        self.assertIs(closed.closure_reason, FlowObservationWindowClosureReason.CAPACITY)
        self.assertEqual(closed.dns_correlation_state.requests, ())
        self.assertIs(record(instance, response=True, seconds=2).dns_correlation_state.observations[0].status, DNSCorrelationStatus.UNMATCHED)

    def test_all_malformed_roles_leave_pending_unchanged(self):
        instance = manager()
        before = record(instance)
        for response in (False, True):
            for suffix in (b'\x80', b'\x40', b'\x01'):
                raw = header(1, flags=0x8000 if response else 0) + suffix
                update = instance.record(analyze_packet(dns_packet(raw, reverse=response)))
                state = update.active_window.dns_correlation_state
                self.assertEqual(state.requests, before.dns_correlation_state.requests)
                self.assertEqual(state.observations, ())

    def test_no_tcp_correlation_without_framing(self):
        raw = header(1) + question()
        for ipv6 in (False, True):
            state = FlowStateCoordinator().record(analyze_packet(dns_packet(raw, ipv6=ipv6, protocol=6)))
            self.assertIsNone(state.dns_correlation_state)

    def test_state_publication_failure_is_retryable(self):
        instance = manager()
        first = record(instance)
        failure = MemoryError('state publication')
        with patch('analysis.dns_correlation._build', side_effect=failure):
            with self.assertRaises(MemoryError) as caught:
                record(instance, response=True, seconds=2)
        self.assertIs(caught.exception, failure)
        self.assertIs(instance.active_windows()[0].dns_correlation_state, first.dns_correlation_state)
        self.assertIs(record(instance, response=True, seconds=1).dns_correlation_state.observations[0].status, DNSCorrelationStatus.MATCHED)

    def test_window_update_failure_does_not_consume_request(self):
        instance = manager()
        first = record(instance)
        with patch('analysis.flow_observation_window.FlowObservationWindowUpdate', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                record(instance, response=True, seconds=1)
        self.assertIs(instance.active_windows()[0].dns_correlation_state, first.dns_correlation_state)
        self.assertIs(record(instance, response=True, seconds=1).dns_correlation_state.observations[0].status, DNSCorrelationStatus.MATCHED)

    def test_finalization_failure_preserves_active_windows(self):
        instance = manager()
        before = record(instance)
        with patch('analysis.flow_observation_window.finalize_dns_correlation_state', side_effect=MemoryError('close')):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        self.assertIs(instance.active_windows()[0].dns_correlation_state, before.dns_correlation_state)
        self.assertEqual(instance.end_capture_session()[0].dns_correlation_state.requests, ())

    def test_failed_capacity_replacement_preserves_old_owner(self):
        instance = manager(1)
        first = record(instance)
        with patch('analysis.flow_state_coordinator.update_dns_correlation_state', side_effect=RuntimeError('admission')):
            with self.assertRaises(RuntimeError):
                record(instance, ipv6=True, seconds=1)
        self.assertIs(instance.active_windows()[0].dns_correlation_state, first.dns_correlation_state)
        self.assertIs(record(instance, response=True).dns_correlation_state.observations[0].status, DNSCorrelationStatus.MATCHED)

    def test_capture_failure_propagates_and_pending_becomes_unresolved(self):
        failure = CaptureError('capture failure')
        source = MemoryPacketSource((packet(),), iteration_error=failure)
        closed = []
        with self.assertRaises(CaptureError) as caught:
            run_flow_observation_session(source, capture_session_id='dns', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        self.assertIs(caught.exception, failure)
        self.assertEqual(source.events[-1], 'stop')
        self.assertIs(closed[0].dns_correlation_state.observations[0].status, DNSCorrelationStatus.UNRESOLVED)

    def test_downstream_failure_does_not_replay_closed_windows(self):
        source = MemoryPacketSource((packet(), packet(ipv6=True, seconds=1)))
        delivered = []
        failure = RuntimeError('consumer')
        def consume(window):
            delivered.append(window)
            raise failure
        with self.assertRaises(RuntimeError) as caught:
            run_flow_observation_session(source, capture_session_id='dns', inactivity_timeout=timedelta(seconds=5),
                                         max_active_windows=1, closed_window_consumer=consume)
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(delivered), 1)
        self.assertTrue(delivered[0].dns_correlation_state.finalized)
        self.assertEqual(source.events[-1], 'stop')

    def test_coordinator_requires_matching_identity_and_timestamp(self):
        first = FlowStateCoordinator().record(analyze_packet(packet()))
        other = FlowStateCoordinator().record(analyze_packet(packet(ipv6=True)))
        later = FlowStateCoordinator().record(analyze_packet(packet(seconds=1)))
        for replacement, exception in ((object(), TypeError), (other.dns_correlation_state, FlowCoordinationError),
                                       (later.dns_correlation_state, FlowCoordinationError)):
            with self.assertRaises(exception):
                replace(first, dns_correlation_state=replacement)

    def test_legacy_coordinator_constructor_remains_available(self):
        state = FlowStateCoordinator().record(analyze_packet(packet()))
        values = tuple(getattr(state, member.name) for member in fields(state)
                       if member.name not in ('dns_correlation_state', 'dns_transaction_statistics', 'dns_query_name_statistics', 'dns_resource_record_statistics'))
        self.assertIsNone(type(state)(*values).dns_correlation_state)

    def test_finalized_state_cannot_be_reopened_as_active_window(self):
        instance = manager()
        first = record(instance)
        closed = instance.close(first.identity)
        with self.assertRaises(FlowObservationWindowError):
            replace(closed, closure_reason=None)

    def test_udp_integration_parses_once_and_reuses_result(self):
        parsed = analyze_packet(packet())
        original = parsed.dns
        with patch('analysis.packet_analysis.analyze_dns_message', return_value=original) as parser:
            state = FlowStateCoordinator().record(parsed)
        parser.assert_called_once_with(parsed.udp.payload)
        self.assertIs(state.dns_correlation_state.requests[0].message, original)

    def test_all_classic_pcap_encodings_match_real_flow_execution(self):
        packets = (packet(), packet(ipv6=True), packet(response=True, seconds=1), packet(ipv6=True, response=True, seconds=1),
                   packet(identifier=2, seconds=2))
        expected = []
        kwargs = dict(capture_session_id='dns', inactivity_timeout=timedelta(seconds=5))
        run_flow_observation_session(MemoryPacketSource(packets), closed_window_consumer=expected.append, **kwargs)
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'dns.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    path.write_bytes(pcap_bytes(tuple((int(item.captured_at.timestamp()) * 1000000, item.raw_bytes)
                                                     for item in packets), order, nano))
                    actual = []
                    run_flow_observation_session(PcapPacketSource(path), closed_window_consumer=actual.append, **kwargs)
                    self.assertEqual([item.dns_correlation_state for item in actual], [item.dns_correlation_state for item in expected])

    def test_adversarial_flow_churn_is_bounded_and_deterministic(self):
        self.assertEqual(replay(), replay())
        for state in replay():
            self.assertLessEqual(len(state['requests']), 128)
            self.assertLessEqual(len(state['observations']), 129)
            if state['finalized']:
                self.assertEqual(state['requests'], ())

    def test_retained_dns_state_does_not_keep_packet_or_completed_history_alive(self):
        instance = manager()
        analysis = analyze_packet(packet())
        original_packet = weakref.ref(analysis.observation)
        original_analysis = weakref.ref(analysis)
        first = instance.record(analysis).active_window
        request = weakref.ref(first.dns_correlation_state.requests[0].message)
        matched = record(instance, response=True, seconds=1)
        result = weakref.ref(matched.dns_correlation_state.observations[0])
        record(instance, identifier=2, seconds=2)
        del analysis, first, matched
        gc.collect()
        self.assertIsNone(original_packet())
        self.assertIsNone(original_analysis())
        self.assertIsNone(request())
        self.assertIsNone(result())
        self.assertEqual(len(instance.active_windows()[0].dns_correlation_state.requests), 1)

    def test_hash_seed_and_timezone_replay(self):
        script = ('from tests.test_dns_correlation_lifecycle import replay\n'
                  'import hashlib\nprint(hashlib.sha256(repr(replay()).encode()).hexdigest())\n')
        outputs = []
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                outputs.append(subprocess.check_output([sys.executable, '-B', '-c', script],
                                                       env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone)))
        self.assertEqual(outputs, [outputs[0]] * 9)
