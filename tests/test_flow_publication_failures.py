import unittest
from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch

from analysis import (
    FlowObservationWindow, FlowObservationWindowManager, FlowObservationWindowUpdate,
    analyze_packet, extract_flow_feature_snapshot,
)
from application import GroundTruth, run_end_to_end_validation
from application import detection_pipeline, end_to_end_validation
from research import research_example_from_window
from tests.pcap_scenarios import frame, transport
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_packet_analysis import UDP_BYTES, make_observation


def observation(seconds, ipv6=False, protocol=17):
    base = make_observation(17, UDP_BYTES)
    raw = frame(protocol, transport(protocol, b'body', ipv6), ipv6)
    return replace(base, captured_at=base.captured_at + timedelta(seconds=seconds),
                   raw_bytes=raw, captured_length=len(raw), original_length=len(raw))


class FlowPublicationFailureTests(unittest.TestCase):
    def test_failed_continuation_keeps_state_and_frontier_for_both_families_and_transports(self):
        for ipv6 in (False, True):
            for protocol in (6, 17):
                for model in (FlowObservationWindow, FlowObservationWindowUpdate):
                    for error in (RuntimeError('publication'), MemoryError('allocation'), KeyboardInterrupt('publication')):
                        with self.subTest(ipv6=ipv6, protocol=protocol, model=model, error=type(error)):
                            manager = FlowObservationWindowManager('publication', timedelta(seconds=5))
                            manager.record(analyze_packet(observation(0, ipv6, protocol)))
                            manager.record(analyze_packet(observation(1, ipv6, protocol)))
                            before = manager.active_windows()
                            with patch.object(model, '__post_init__', side_effect=error):
                                with self.assertRaises(type(error)) as failure:
                                    manager.record(analyze_packet(observation(3, ipv6, protocol)))
                            self.assertIs(failure.exception, error)
                            self.assertEqual(manager.active_windows(), before)
                            self.assertIs(manager.active_windows()[0].coordinated_state, before[0].coordinated_state)
                            accepted = manager.record(analyze_packet(observation(2, ipv6, protocol)))
                            self.assertEqual(accepted.active_window.coordinated_state.flow_statistics.packet_count, 3)
                            self.assertEqual(accepted.active_window.key, before[0].key)

    def test_failed_packet_does_not_change_other_flows_or_reopened_windows(self):
        manager = FlowObservationWindowManager('publication', timedelta(seconds=5))
        reference = FlowObservationWindowManager('publication', timedelta(seconds=5))
        for owner in (manager, reference):
            for ipv6, protocol in ((False, 6), (False, 17), (True, 6), (True, 17)):
                owner.record(analyze_packet(observation(0, ipv6, protocol)))
        identity = manager.active_windows()[0].identity
        closed = manager.close(identity)
        self.assertEqual(closed, reference.close(identity))
        before = manager.active_windows()
        with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                manager.record(analyze_packet(observation(3, True, 17)))
        self.assertEqual(manager.active_windows(), before)
        for owner in (manager, reference):
            reopened = owner.record(analyze_packet(observation(2, False, 6)))
            self.assertEqual(reopened.active_window.key.sequence_number, 4)
        final = manager.end_capture_session()
        self.assertEqual(final, reference.end_capture_session())
        self.assertEqual([window.key.sequence_number for window in final], [1, 2, 3, 4])
        self.assertEqual(closed.coordinated_state.flow_statistics.packet_count, 1)

    def test_retry_counts_rejected_packet_once_and_preserves_downstream_values(self):
        manager = FlowObservationWindowManager('publication', timedelta(seconds=5))
        reference = FlowObservationWindowManager('publication', timedelta(seconds=5))
        first, second = (analyze_packet(observation(seconds)) for seconds in (0, 1))
        for owner in (manager, reference):
            owner.record(first)
        with patch.object(FlowObservationWindow, '__post_init__', side_effect=ValueError('publication')):
            with self.assertRaises(ValueError):
                manager.record(second)
        self.assertEqual(manager.record(second), reference.record(second))
        actual = manager.end_capture_session()[0]
        expected = reference.end_capture_session()[0]
        self.assertEqual(extract_flow_feature_snapshot(actual), extract_flow_feature_snapshot(expected))
        self.assertEqual(research_example_from_window(actual), research_example_from_window(expected))
        self.assertEqual(actual.coordinated_state.flow_statistics.packet_count, 2)
        self.assertEqual(manager.end_capture_session(), ())

    def test_capture_failure_finalizes_only_previously_admitted_packets(self):
        for ipv6 in (False, True):
            for protocol in (6, 17):
                with self.subTest(ipv6=ipv6, protocol=protocol):
                    first, second = (observation(seconds, ipv6, protocol) for seconds in (0, 1))
                    source = MemoryPacketSource((first, second))
                    error = RuntimeError('continuation publication failed')
                    original = FlowObservationWindowUpdate.__post_init__
                    snapshots = []

                    def validate(update):
                        original(update)
                        if update.active_window.coordinated_state.flow_statistics.packet_count == 2:
                            raise error

                    def extract(window):
                        result = extract_flow_feature_snapshot(window)
                        snapshots.append(result)
                        return result

                    with patch.object(FlowObservationWindowUpdate, '__post_init__', validate), \
                            patch.object(detection_pipeline, 'extract_flow_feature_snapshot', extract), \
                            patch.object(end_to_end_validation, 'evaluate_detection_result') as evaluate:
                        with self.assertRaises(RuntimeError) as failure:
                            run_end_to_end_validation(source, configuration=settings(), capture_session_id='publication',
                                                      ground_truth=GroundTruth((), ()))
                    self.assertIs(failure.exception, error)
                    evaluate.assert_not_called()
                    self.assertEqual(source.events[-1], 'stop')
                    self.assertEqual(len(snapshots), 1)
                    reference = FlowObservationWindowManager('publication', timedelta(seconds=5))
                    reference.record(analyze_packet(first))
                    expected = reference.end_capture_session()[0]
                    self.assertEqual(snapshots[0], extract_flow_feature_snapshot(expected))
                    self.assertEqual(research_example_from_window(snapshots[0].observation_window),
                                     research_example_from_window(expected))


if __name__ == '__main__':
    unittest.main()
