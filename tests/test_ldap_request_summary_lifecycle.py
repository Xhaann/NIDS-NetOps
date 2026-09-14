import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, asdict
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    FlowObservationWindow, FlowObservationWindowManager, FlowObservationWindowUpdate,
    LDAPCorrelationStatus, LDAPRequestSummaryStatus, analyze_packet, finalize_ldap_correlation_state,
)
from analysis import ldap_request_summary
from application import GroundTruth, run_end_to_end_validation, run_flow_observation_session
from capture import CaptureSource, PcapPacketSource
from research import research_example_from_window
from tests.pcap_scenarios import pcap_bytes
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ldap_correlation import correlation_message, correlation_packets, correlation_states
from tests.test_ldap_correlation_lifecycle import alternate_client
from tests.test_ldap_flow_statistics import ldap_observation
from tests.test_ldap_stream_lifecycle import observe_framing


def without_summaries(value):
    if isinstance(value, dict):
        return {key: without_summaries(item) for key, item in value.items() if key != 'request_summary'}
    if isinstance(value, (tuple, list)):
        return tuple(without_summaries(item) for item in value)
    return value


def summary_results():
    events = ((False, correlation_message(0x63, 10) + correlation_message(0x60, 2)),
              (True, correlation_message(0x64, 10) + correlation_message(0x73, 10) + correlation_message(0x61, 2)),
              (True, correlation_message(0x65, 10)),
              (False, correlation_message(0x63, 3)), (True, correlation_message(0x64, 3)),
              (False, correlation_message(0x63, 3)), (True, correlation_message(0x65, 3) + correlation_message(0x61, 9)))
    packets = tuple(p for ipv6 in (False, True) for p in correlation_packets(events, ipv6))
    updates, closed = observe_framing(tuple(sorted(packets, key=lambda p: p.captured_at)))
    unresolved = observe_framing(correlation_packets(((False, correlation_message(0x63)), (True, correlation_message(0x64)))))[1][0]
    limited = correlation_states(((False, b''.join(correlation_message(0x60, i) for i in range(1, 131))),))[-1]
    gap = observe_framing((ldap_observation(correlation_message(0x60)),
                           ldap_observation(correlation_message(0x61)[:5], 1, reverse=True),
                           ldap_observation(correlation_message(0x61)[5:], 2, reverse=True, sequence=106)))[1][0]
    return (tuple(asdict(w) for w in updates), tuple(asdict(w.ldap_correlation_state) for w in closed),
            asdict(unresolved.ldap_correlation_state), asdict(finalize_ldap_correlation_state(limited.ldap_correlation_state)),
            asdict(gap.ldap_correlation_state))


class LDAPRequestSummaryLifecycleTests(unittest.TestCase):
    def test_ipv4_ipv6_distinct_flows_preserve_exact_scoped_request_references(self):
        events = ((False, correlation_message(0x63)), (True, correlation_message(0x64)), (True, correlation_message(0x65)))
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
            self.assertEqual(actual.ldap_correlation_state, isolated.ldap_correlation_state)
            summary = actual.ldap_correlation_state.observations[0].request_summary
            self.assertEqual(summary.identity, actual.identity)
            self.assertIs(summary.request, actual.ldap_correlation_state.observations[0].request)
            self.assertEqual(summary.request.message_id, 1)
            self.assertEqual(summary.response_count, 2)
            self.assertIs(summary.status, LDAPRequestSummaryStatus.COMPLETED)

    def test_finalization_preserves_zero_or_nonterminal_counts_and_marks_pending_unresolved(self):
        for responses in (b'', correlation_message(0x64) + correlation_message(0x73)):
            updates, closed = observe_framing(correlation_packets(((False, correlation_message(0x63)), (True, responses))))
            active = updates[-1].ldap_correlation_state.requests[0].request_summary
            final = closed[0].ldap_correlation_state.requests[0].request_summary
            self.assertIs(active.status, LDAPRequestSummaryStatus.PENDING)
            self.assertIs(final.status, LDAPRequestSummaryStatus.UNRESOLVED)
            self.assertEqual(final.response_count, 2 if responses else 0)
            self.assertEqual(final.response_count, active.response_count)
            self.assertIs(final.request, active.request)
            self.assertIsNone(final.terminal_response)
            self.assertIs(updates[-1].coordinated_state, closed[0].coordinated_state)
            self.assertTrue(all(r.request_summary is None for r in closed[0].ldap_correlation_state.observations))
            with self.assertRaises(FrozenInstanceError):
                final.response_count = 100

    def test_completed_and_ambiguous_summaries_remain_unchanged_at_closure(self):
        events = ((False, correlation_message(0x63, 1) + correlation_message(0x60, 2)),
                  (True, correlation_message(0x64, 1)), (False, correlation_message(0x63, 1)),
                  (True, correlation_message(0x61, 2) + correlation_message(0x65, 1)))
        updates, closed = observe_framing(correlation_packets(events))
        active = updates[-1].ldap_correlation_state
        final = closed[0].ldap_correlation_state
        self.assertIs(final.requests[0].request_summary, active.requests[0].request_summary)
        self.assertIs(final.requests[0].request_summary.status, LDAPRequestSummaryStatus.AMBIGUOUS)
        self.assertEqual(final.requests[0].request_summary.response_count, 1)
        self.assertIsNone(final.requests[0].request_summary.terminal_response)
        self.assertIs(final.observations[0].request_summary, active.observations[0].request_summary)
        self.assertIs(final.observations[0].request_summary.status, LDAPRequestSummaryStatus.COMPLETED)
        self.assertIsNone(final.observations[1].request_summary)

    def test_one_batch_search_responses_expose_one_completed_summary_at_finalization(self):
        packets = correlation_packets(((False, correlation_message(0x63)),
                                       (True, correlation_message(0x64) + correlation_message(0x73) + correlation_message(0x65))))
        _, closed = observe_framing(packets)
        state = closed[0].ldap_correlation_state
        self.assertEqual(state.requests, ())
        self.assertEqual([r.request_summary is None for r in state.observations], [True, True, False])
        summary = state.observations[-1].request_summary
        self.assertEqual(summary.response_count, 3)
        self.assertIs(summary.status, LDAPRequestSummaryStatus.COMPLETED)
        self.assertIs(summary.terminal_response, state.observations[-1].message)

    def test_explicit_inactivity_and_capture_boundaries_never_continue_final_summaries(self):
        for explicit in (True, False):
            manager = FlowObservationWindowManager('summary', timedelta(seconds=5))
            first = manager.record(analyze_packet(ldap_observation(correlation_message(0x63)))).active_window
            manager.record(analyze_packet(ldap_observation(correlation_message(0x64), 1, reverse=True)))
            if explicit:
                closed = manager.close(first.identity)
            update = manager.record(analyze_packet(ldap_observation(correlation_message(0x65), 7, reverse=True)))
            if not explicit:
                closed = update.closed_windows[0]
            summary = closed.ldap_correlation_state.requests[0].request_summary
            self.assertIs(summary.status, LDAPRequestSummaryStatus.UNRESOLVED)
            self.assertEqual(summary.response_count, 1)
            self.assertIsNone(update.active_window.ldap_correlation_state.observations[0].request_summary)
            self.assertIs(update.active_window.ldap_correlation_state.observations[0].status, LDAPCorrelationStatus.UNMATCHED)
        fresh = FlowObservationWindowManager('another-capture', timedelta(seconds=5))
        state = fresh.record(analyze_packet(ldap_observation(correlation_message(0x65), reverse=True))).active_window
        self.assertIsNone(state.ldap_correlation_state.observations[0].request_summary)

    def test_failed_publication_does_not_count_nonterminal_or_terminal_response_before_retry(self):
        for tag in (0x64, 0x65):
            for model in (FlowObservationWindow, FlowObservationWindowUpdate):
                manager = FlowObservationWindowManager('atomic', timedelta(seconds=5))
                first = manager.record(analyze_packet(ldap_observation(correlation_message(0x63)))).active_window
                before = first.ldap_correlation_state.requests[0].request_summary
                with patch.object(model, '__post_init__', side_effect=MemoryError('publication')):
                    with self.assertRaises(MemoryError):
                        manager.record(analyze_packet(ldap_observation(correlation_message(tag), 2, reverse=True)))
                self.assertIs(manager.active_windows()[0].ldap_correlation_state.requests[0].request_summary, before)
                retry = manager.record(analyze_packet(ldap_observation(correlation_message(tag), 1, reverse=True))).active_window
                summary = (retry.ldap_correlation_state.requests if tag == 0x64 else retry.ldap_correlation_state.observations)[0].request_summary
                self.assertEqual(summary.response_count, 1)
                self.assertEqual(before.response_count, 0)
                self.assertIsNone(before.terminal_response)

    def test_summary_allocation_failure_does_not_publish_partial_batch_counts(self):
        manager = FlowObservationWindowManager('atomic', timedelta(seconds=5))
        first = manager.record(analyze_packet(ldap_observation(correlation_message(0x63)))).active_window
        original = ldap_request_summary._summary
        calls = []

        def build(values):
            calls.append(values['response_count'])
            if values['response_count'] == 2:
                raise MemoryError('summary allocation')
            return original(values)

        payload = correlation_message(0x64) + correlation_message(0x65)
        with patch.object(ldap_request_summary, '_summary', side_effect=build):
            with self.assertRaises(MemoryError):
                manager.record(analyze_packet(ldap_observation(payload, 2, reverse=True)))
        self.assertEqual(calls, [1, 2])
        self.assertIs(manager.active_windows()[0].ldap_correlation_state, first.ldap_correlation_state)
        retry = manager.record(analyze_packet(ldap_observation(payload, 1, reverse=True))).active_window
        summary = retry.ldap_correlation_state.observations[-1].request_summary
        self.assertEqual(summary.response_count, 2)
        self.assertIs(summary.status, LDAPRequestSummaryStatus.COMPLETED)

    def test_failed_finalized_projection_leaves_published_summary_unchanged(self):
        updates, closed = observe_framing(correlation_packets(((False, correlation_message(0x60)),)))
        before = updates[0].ldap_correlation_state.requests[0].request_summary
        with patch.object(ldap_request_summary, '_summary', side_effect=MemoryError('projection allocation')):
            with self.assertRaises(MemoryError):
                closed[0].ldap_correlation_state
        self.assertIs(updates[0].ldap_correlation_state.requests[0].request_summary, before)
        self.assertIs(before.status, LDAPRequestSummaryStatus.PENDING)
        self.assertIs(closed[0].ldap_correlation_state.requests[0].request_summary.status, LDAPRequestSummaryStatus.UNRESOLVED)

    def test_capture_failure_preserves_counts_and_does_not_complete_partial_terminal_response(self):
        done = correlation_message(0x65)
        source = MemoryPacketSource(correlation_packets(((False, correlation_message(0x63)),
                                    (True, correlation_message(0x64)), (True, done[:5]))),
                                    iteration_error=RuntimeError('capture failed'))
        closed = []
        with self.assertRaisesRegex(RuntimeError, 'capture failed'):
            run_flow_observation_session(source, capture_session_id='failed', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        self.assertEqual(source.events[-1], 'stop')
        self.assertEqual(len(closed), 1)
        summary = closed[0].ldap_correlation_state.requests[0].request_summary
        self.assertIs(summary.status, LDAPRequestSummaryStatus.UNRESOLVED)
        self.assertEqual(summary.response_count, 1)
        self.assertIsNone(summary.terminal_response)
        self.assertEqual(closed[0].ldap_correlation_state.framing.reverse.retained_suffix, done[:5])

    def test_pcap_summary_detection_evaluation_and_research_compatibility(self):
        packets = tuple(p for ipv6 in (False, True) for p in correlation_packets(
            ((False, correlation_message(0x63)), (True, correlation_message(0x64) + correlation_message(0x65))), ipv6))
        packets = tuple(sorted(packets, key=lambda p: p.captured_at))
        expected = observe_framing(packets)[1]
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'summaries.pcap'
            path.write_bytes(pcap_bytes(tuple((int(p.captured_at.timestamp()) * 1000000, p.raw_bytes) for p in packets)))
            actual = []
            run_flow_observation_session(PcapPacketSource(path, source=CaptureSource('protocol-combinations')),
                                         capture_session_id='framing', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=actual.append)
        self.assertEqual(tuple(actual), expected)
        self.assertEqual([w.ldap_correlation_state for w in actual], [w.ldap_correlation_state for w in expected])
        actual = run_end_to_end_validation(MemoryPacketSource(packets), configuration=settings(),
                                          capture_session_id='framing', ground_truth=GroundTruth((), ()))
        with patch('analysis.ldap_correlation._start_request_summary', return_value=None), \
                patch('analysis.ldap_correlation._summary_response', return_value=None), \
                patch('analysis.ldap_correlation._summary_status', return_value=None):
            baseline = run_end_to_end_validation(MemoryPacketSource(packets), configuration=settings(),
                                                capture_session_id='framing', ground_truth=GroundTruth((), ()))
        self.assertEqual(without_summaries(asdict(actual)), without_summaries(asdict(baseline)))
        self.assertEqual(actual.report.metrics, baseline.report.metrics)
        self.assertEqual(len(actual.pipeline_result.flow_findings), 4)
        for finding, prior in zip(actual.pipeline_result.flow_findings, baseline.pipeline_result.flow_findings):
            evidence, previous = finding.raw_evidence, prior.raw_evidence
            window = evidence.snapshot.observation_window if hasattr(evidence, 'snapshot') else evidence.observation_window
            old_window = previous.snapshot.observation_window if hasattr(previous, 'snapshot') else previous.observation_window
            self.assertEqual(research_example_from_window(window).projection, research_example_from_window(old_window).projection)

    def test_repeated_hash_seed_timezone_summary_outputs_are_byte_identical(self):
        self.assertEqual(summary_results(), summary_results())
        script = ('from tests.test_ldap_request_summary_lifecycle import summary_results\n'
                  'import sys\nsys.stdout.write(repr(summary_results()))\n')
        outputs = []
        for seed, zone in (('0', 'UTC'), ('1', 'Asia/Kolkata'), ('9157', 'America/Los_Angeles'), ('0', 'UTC')):
            environment = dict(os.environ, PYTHONHASHSEED=seed, TZ=zone, PYTHONPATH='src', PYTHONDONTWRITEBYTECODE='1')
            outputs.append(subprocess.check_output([sys.executable, '-B', '-c', script], env=environment, timeout=15))
        self.assertTrue(all(output == outputs[0] for output in outputs))


if __name__ == '__main__':
    unittest.main()
