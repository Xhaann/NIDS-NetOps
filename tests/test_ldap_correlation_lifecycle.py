import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, asdict, fields, replace
from datetime import timedelta
from pathlib import Path
from struct import pack
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    FlowCoordinationError, FlowObservationWindow, FlowObservationWindowManager,
    FlowObservationWindowUpdate, LDAPCorrelationStatus, LDAPCorrelationUnavailableReason,
    analyze_packet, extract_flow_feature_snapshot, finalize_ldap_correlation_state,
)
from analysis import ldap_correlation
from application import GroundTruth, run_end_to_end_validation, run_flow_observation_session
from capture import CaptureSource, PcapPacketSource
from research import research_example_from_window
from tests.pcap_scenarios import checksum, pcap_bytes
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ldap_correlation import correlation_message, correlation_packets, correlation_states
from tests.test_ldap_flow_statistics import ldap_observation
from tests.test_ldap_stream_lifecycle import observe_framing


def alternate_client(packet):
    raw = bytearray(packet.raw_bytes)
    ipv6 = raw[14] >> 4 == 6
    start = 54 if ipv6 else 34
    source, destination = (bytes(raw[22:38]), bytes(raw[38:54])) if ipv6 else (bytes(raw[26:30]), bytes(raw[30:34]))
    port_offset = start if int.from_bytes(raw[start:start + 2], 'big') != 389 else start + 2
    raw[port_offset:port_offset + 2] = pack('!H', 12346)
    raw[start + 16:start + 18] = b'\x00\x00'
    length = len(raw) - start
    pseudo = source + destination + (pack('!I3xB', length, 6) if ipv6 else pack('!BBH', 0, 6, length))
    raw[start + 16:start + 18] = checksum(pseudo + bytes(raw[start:])).to_bytes(2, 'big')
    return replace(packet, raw_bytes=bytes(raw))


def correlation_results():
    events = ((False, correlation_message(0x60, 1) + correlation_message(0x63, 2)),
              (True, correlation_message(0x64, 2) + correlation_message(0x61, 1)),
              (False, correlation_message(0x60, 3)),
              (False, correlation_message(0x60, 3)),
              (True, correlation_message(0x65, 2) + correlation_message(0x61, 3) + correlation_message(0x61, 9)))
    packets = tuple(p for ipv6 in (False, True) for p in correlation_packets(events, ipv6))
    updates, closed = observe_framing(tuple(sorted(packets, key=lambda p: p.captured_at)))
    overflow = correlation_states(((False, b''.join(correlation_message(0x60, i) for i in range(1, 131))),))[-1]
    return (tuple(asdict(w) for w in updates), tuple(asdict(w) for w in closed),
            tuple(asdict(w.ldap_correlation_state) for w in closed), asdict(overflow.ldap_correlation_state))


class LDAPCorrelationLifecycleTests(unittest.TestCase):
    def test_ipv4_ipv6_and_identical_ids_across_distinct_ports_remain_flow_scoped(self):
        events = ((False, correlation_message(0x60)), (True, correlation_message(0x61)))
        groups = []
        for ipv6 in (False, True):
            packets = correlation_packets(events, ipv6)
            groups.extend((packets, tuple(alternate_client(p) for p in packets)))
        mixed = tuple(sorted((p for group in groups for p in group), key=lambda p: p.captured_at))
        _, closed = observe_framing(mixed)
        self.assertEqual(len(closed), 4)
        for group in groups:
            isolated = observe_framing(group)[1][0]
            actual = next(w for w in closed if w.identity == isolated.identity)
            self.assertEqual(actual.coordinated_state, isolated.coordinated_state)
            state = actual.ldap_correlation_state
            self.assertTrue(state.finalized)
            self.assertEqual(state.matched_response_count, 1)
            self.assertEqual(state.observations[0].identity, actual.identity)
            self.assertEqual(state.observations[0].message.message_id, 1)
            self.assertEqual(state.observations[0].request.message_id, 1)
        manager = FlowObservationWindowManager('isolated', timedelta(seconds=5))
        manager.record(analyze_packet(groups[0][0]))
        response = manager.record(analyze_packet(groups[1][1])).active_window
        self.assertIs(response.ldap_correlation_state.observations[0].status, LDAPCorrelationStatus.UNMATCHED)

    def test_final_window_projects_unresolved_requests_without_mutating_admitted_state(self):
        manager = FlowObservationWindowManager('final', timedelta(seconds=5))
        first = manager.record(analyze_packet(ldap_observation(correlation_message(0x60)))).active_window
        active = first.ldap_correlation_state
        closed = manager.end_capture_session()[0]
        self.assertIs(first.coordinated_state, closed.coordinated_state)
        self.assertIs(first.ldap_correlation_state, active)
        self.assertIs(active.requests[0].status, LDAPCorrelationStatus.PENDING)
        final = closed.ldap_correlation_state
        self.assertTrue(final.finalized)
        self.assertIs(final.requests[0].status, LDAPCorrelationStatus.UNRESOLVED)
        self.assertIs(final.observations[0].status, LDAPCorrelationStatus.UNRESOLVED)
        self.assertIs(final.requests[0].message, active.requests[0].message)
        self.assertEqual(closed.ldap_correlation_state, final)
        with self.assertRaises(FrozenInstanceError):
            final.requests[0].status = LDAPCorrelationStatus.MATCHED
        self.assertEqual(manager.end_capture_session(), ())

    def test_completed_and_unmatched_results_remain_explicit_after_finalization(self):
        packets = correlation_packets(((False, correlation_message(0x60)),
                                       (True, correlation_message(0x61) + correlation_message(0x61, 2))))
        updates, closed = observe_framing(packets)
        final = closed[0].ldap_correlation_state
        self.assertEqual([r.status for r in final.observations], [LDAPCorrelationStatus.MATCHED, LDAPCorrelationStatus.UNMATCHED])
        self.assertEqual((final.matched_response_count, final.unmatched_response_count), (1, 1))
        self.assertEqual(final.requests, ())
        self.assertIs(final.observations[0], updates[-1].ldap_correlation_state.observations[0])
        self.assertIsNone(final.observations[1].request)

    def test_explicit_segmentation_inactivity_and_new_capture_never_reuse_old_pending_requests(self):
        for close in (True, False):
            manager = FlowObservationWindowManager('windows', timedelta(seconds=5))
            first = manager.record(analyze_packet(ldap_observation(correlation_message(0x60)))).active_window
            if close:
                closed = manager.close(first.identity)
            update = manager.record(analyze_packet(ldap_observation(correlation_message(0x61), 6, reverse=True)))
            if not close:
                closed = update.closed_windows[0]
            self.assertIs(closed.ldap_correlation_state.requests[0].status, LDAPCorrelationStatus.UNRESOLVED)
            self.assertIs(update.active_window.ldap_correlation_state.observations[0].status, LDAPCorrelationStatus.UNMATCHED)
            self.assertNotEqual(closed.key, update.active_window.key)
        other = FlowObservationWindowManager('other', timedelta(seconds=5))
        new = other.record(analyze_packet(ldap_observation(correlation_message(0x61), reverse=True))).active_window
        self.assertIs(new.ldap_correlation_state.observations[0].status, LDAPCorrelationStatus.UNMATCHED)

    def test_window_publication_failure_preserves_pending_correlation_and_retry_order(self):
        for model in (FlowObservationWindow, FlowObservationWindowUpdate):
            manager = FlowObservationWindowManager('atomic', timedelta(seconds=5))
            first = manager.record(analyze_packet(ldap_observation(correlation_message(0x60)))).active_window
            for error in (MemoryError('allocation'), RuntimeError('publication')):
                with patch.object(model, '__post_init__', side_effect=error):
                    with self.assertRaises(type(error)):
                        manager.record(analyze_packet(ldap_observation(correlation_message(0x61), 2, reverse=True)))
                self.assertIs(manager.active_windows()[0].ldap_correlation_state, first.ldap_correlation_state)
            retry = manager.record(analyze_packet(ldap_observation(correlation_message(0x61), 1, reverse=True))).active_window
            self.assertEqual(retry.ldap_correlation_state.matched_response_count, 1)
            self.assertEqual(first.ldap_correlation_state.matched_response_count, 0)

    def test_correlation_failure_after_candidate_match_does_not_retire_published_request(self):
        manager = FlowObservationWindowManager('atomic', timedelta(seconds=5))
        first = manager.record(analyze_packet(ldap_observation(correlation_message(0x60)))).active_window
        with patch.object(ldap_correlation, '_state', side_effect=MemoryError('correlation publication')):
            with self.assertRaises(MemoryError):
                manager.record(analyze_packet(ldap_observation(correlation_message(0x61), 2, reverse=True)))
        self.assertIs(manager.active_windows()[0].ldap_correlation_state, first.ldap_correlation_state)
        retry = manager.record(analyze_packet(ldap_observation(correlation_message(0x61), 1, reverse=True))).active_window
        self.assertEqual(retry.ldap_correlation_state.matched_response_count, 1)
        self.assertIs(retry.ldap_correlation_state.observations[0].request, first.ldap_correlation_state.requests[0].message)

    def test_capture_failure_preserves_unresolved_requests_and_never_completes_partial_response(self):
        response = correlation_message(0x61)
        source = MemoryPacketSource(correlation_packets(((False, correlation_message(0x60)), (True, response[:5]))),
                                    iteration_error=RuntimeError('capture failure'))
        closed = []
        with self.assertRaisesRegex(RuntimeError, 'capture failure'):
            run_flow_observation_session(source, capture_session_id='failure', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        self.assertEqual(source.events[-1], 'stop')
        self.assertEqual(len(closed), 1)
        final = closed[0].ldap_correlation_state
        self.assertEqual(final.matched_response_count, 0)
        self.assertIs(final.requests[0].status, LDAPCorrelationStatus.UNRESOLVED)
        self.assertEqual(final.framing.reverse.retained_suffix, response[:5])

    def test_failed_close_preserves_active_pending_state_until_window_publication_succeeds(self):
        manager = FlowObservationWindowManager('close', timedelta(seconds=5))
        before = manager.record(analyze_packet(ldap_observation(correlation_message(0x60)))).active_window
        with patch.object(FlowObservationWindow, '__post_init__', side_effect=MemoryError('close publication')):
            with self.assertRaises(MemoryError):
                manager.close(before.identity)
        self.assertIs(manager.active_windows()[0].ldap_correlation_state, before.ldap_correlation_state)
        final = manager.close(before.identity)
        self.assertIs(final.ldap_correlation_state.requests[0].status, LDAPCorrelationStatus.UNRESOLVED)
        self.assertIs(before.ldap_correlation_state.requests[0].status, LDAPCorrelationStatus.PENDING)

    def test_pcap_correlation_and_detection_evaluation_research_projections_remain_compatible(self):
        packets = tuple(p for ipv6 in (False, True) for p in correlation_packets(
            ((False, correlation_message(0x60)), (True, correlation_message(0x61))), ipv6))
        packets = tuple(sorted(packets, key=lambda p: p.captured_at))
        expected = observe_framing(packets)[1]
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'correlation.pcap'
            path.write_bytes(pcap_bytes(tuple((int(p.captured_at.timestamp()) * 1000000, p.raw_bytes) for p in packets)))
            actual = []
            run_flow_observation_session(PcapPacketSource(path, source=CaptureSource('protocol-combinations')),
                                         capture_session_id='framing', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=actual.append)
        self.assertEqual(tuple(actual), expected)
        self.assertEqual([w.ldap_correlation_state for w in actual], [w.ldap_correlation_state for w in expected])
        config = settings()
        actual = run_end_to_end_validation(MemoryPacketSource(packets), configuration=config,
                                          capture_session_id='framing', ground_truth=GroundTruth((), ()))
        with patch('analysis.flow_state_coordinator.update_ldap_correlation_state', return_value=None):
            baseline = run_end_to_end_validation(MemoryPacketSource(packets), configuration=config,
                                                capture_session_id='framing', ground_truth=GroundTruth((), ()))
        self.assertEqual(actual.pipeline_result.packet_findings, baseline.pipeline_result.packet_findings)
        self.assertEqual(actual.report.metrics, baseline.report.metrics)
        self.assertEqual(len(actual.pipeline_result.flow_findings), 4)
        for finding, original in zip(actual.pipeline_result.flow_findings, baseline.pipeline_result.flow_findings):
            evidence, prior = finding.raw_evidence, original.raw_evidence
            window = evidence.snapshot.observation_window if hasattr(evidence, 'snapshot') else evidence.observation_window
            old_window = prior.snapshot.observation_window if hasattr(prior, 'snapshot') else prior.observation_window
            self.assertEqual(research_example_from_window(window).projection, research_example_from_window(old_window).projection)
            self.assertEqual(window.coordinated_state.ldap_stream_state, old_window.coordinated_state.ldap_stream_state)
            stripped = replace(window, coordinated_state=replace(window.coordinated_state, ldap_correlation_state=None))
            evidence = replace(evidence, **({'snapshot': extract_flow_feature_snapshot(stripped)} if hasattr(evidence, 'snapshot')
                                           else {'observation_window': stripped}))
            self.assertEqual(replace(finding, raw_evidence=evidence), original)

    def test_coordinator_requires_exact_active_framing_reference_and_preserves_old_constructor(self):
        state = correlation_states(((False, correlation_message(0x60)),))[0]
        for replacement, error in ((object(), TypeError), (finalize_ldap_correlation_state(state.ldap_correlation_state), FlowCoordinationError)):
            with self.assertRaises(error):
                replace(state, ldap_correlation_state=replacement)
        other = correlation_states(((False, correlation_message(0x60, 2)),))[0]
        with self.assertRaises(FlowCoordinationError):
            replace(state, ldap_correlation_state=other.ldap_correlation_state)
        previous = tuple(getattr(state, field.name) for field in fields(state)
                         if field.name not in ('ldap_correlation_state', 'dns_transaction_statistics', 'dns_query_name_statistics', 'dns_resource_record_statistics'))
        self.assertIsNone(type(state)(*previous).ldap_correlation_state)

    def test_repeated_hash_seed_timezone_results_are_byte_identical(self):
        self.assertEqual(correlation_results(), correlation_results())
        script = ('from tests.test_ldap_correlation_lifecycle import correlation_results\n'
                  'import sys\nsys.stdout.write(repr(correlation_results()))\n')
        outputs = []
        for seed, zone in (('0', 'UTC'), ('1', 'Asia/Kolkata'), ('9157', 'America/Los_Angeles'), ('0', 'UTC')):
            environment = dict(os.environ, PYTHONHASHSEED=seed, TZ=zone, PYTHONPATH='src', PYTHONDONTWRITEBYTECODE='1')
            outputs.append(subprocess.check_output([sys.executable, '-B', '-c', script], env=environment, timeout=15))
        self.assertTrue(all(output == outputs[0] for output in outputs))


if __name__ == '__main__':
    unittest.main()
