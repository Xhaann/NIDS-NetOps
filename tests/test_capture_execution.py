import unittest
from contextlib import ExitStack
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, PropertyMock, patch

import application
from analysis import EthernetDecodeError, PacketAnalysisFailureClassification, analyze_packet, analyze_packet_outcome
from application import DetectionSession, run_capture_execution, run_detection_pipeline, run_flow_observation_session
from application import capture_execution, detection_pipeline, flow_observation_session
from capture import CaptureError, IterablePacketSource, LinkType, PcapPacketSource, consume
from detection import FlowVolumeMetric, PacketIntegrityConfiguration
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_flow_volume_threshold import configuration as volume_configuration
from tests.test_ipv6_flow import observation_at
from tests.test_packet_analysis import TCP_BYTES, UDP_BYTES, make_observation
from tests.test_pcap_packet_source import global_header, record
from tests.test_tcp_control_threshold import configuration as control_configuration


class CaptureExecutionTests(unittest.TestCase):
    def test_public_export_and_empty_source_delegate_lifecycle_without_analysis(self):
        self.assertIs(application.run_capture_execution, capture_execution.run_capture_execution)
        self.assertNotIn("_execute_capture", application.__all__)
        source = MemoryPacketSource(())
        consumer = Mock()
        with patch.object(capture_execution, "consume", wraps=consume) as ingestion, \
             patch.object(capture_execution, "analyze_packet_outcome") as analysis:
            self.assertIsNone(run_capture_execution(source, consumer))
        ingestion.assert_called_once()
        self.assertIs(ingestion.call_args.args[0], source)
        analysis.assert_not_called()
        consumer.assert_not_called()
        self.assertEqual(source.events, ["start", "stop"])

    def test_exact_observation_and_outcome_identity_once_in_source_order(self):
        first = observation_at(seconds=3)
        second = observation_at(17, seconds=1)
        observations = (first, second, first)
        before = [vars(o).copy() for o in observations]
        source = MemoryPacketSource(observations)
        expected = tuple(analyze_packet_outcome(o) for o in observations)
        received = []
        def receive(outcome):
            self.assertEqual(source.events[-1], "produce:" + str(len(received)))
            self.assertIs(outcome, expected[len(received)])
            received.append(outcome)
        with patch.object(capture_execution, "analyze_packet_outcome", side_effect=expected) as analysis:
            run_capture_execution(source, receive)
        self.assertEqual(analysis.call_count, 3)
        for index, call in enumerate(analysis.call_args_list):
            self.assertIs(call.args[0], observations[index])
            self.assertIs(received[index].observation, observations[index])
        self.assertEqual([vars(o) for o in observations], before)
        self.assertEqual(source.events, ["start", "produce:0", "produce:1", "produce:2", "stop"])
        self.assertTrue(source.stopped)

    def test_real_ipv4_and_ipv6_analysis_runs_once_without_execution_mutation(self):
        observations = (make_observation(6, TCP_BYTES), make_observation(17, UDP_BYTES),
                        observation_at(6, extensions=(0, 43, 60)), observation_at(17, extensions=(0, 60)))
        outcomes = []
        with patch.object(capture_execution, "analyze_packet_outcome", wraps=analyze_packet_outcome) as analysis, \
             patch("analysis.packet_analysis_outcome.analyze_packet", wraps=analyze_packet) as parser:
            run_capture_execution(MemoryPacketSource(observations), outcomes.append)
        self.assertEqual((analysis.call_count, parser.call_count), (4, 4))
        for index, outcome in enumerate(outcomes):
            self.assertIs(outcome.observation, observations[index])
            self.assertIs(outcome.analysis.observation, observations[index])
            self.assertTrue(outcome.succeeded)
        self.assertEqual(outcomes[0].analysis.tcp.source_port, 0x1234)
        self.assertEqual(outcomes[1].analysis.udp.destination_port, 0xABCD)
        self.assertEqual(outcomes[2].analysis.ipv6_tcp.destination_port, 443)
        self.assertEqual(outcomes[3].analysis.ipv6_udp.source_port, 12345)

    def test_all_failure_classifications_are_delivered_exactly_and_do_not_stop_execution(self):
        valid = observation_at(17)
        incomplete = replace(valid, raw_bytes=b"", captured_length=0)
        structural = replace(valid, raw_bytes=valid.raw_bytes[:14] + b"\x50" + valid.raw_bytes[15:])
        unsupported = replace(valid, link_type=LinkType(65001))
        integrity = make_observation(17, UDP_BYTES, ipv4_checksum=0)
        observations = (incomplete, structural, unsupported, integrity, valid)
        returned, delivered = [], []
        def analyze(observation):
            outcome = analyze_packet_outcome(observation)
            returned.append(outcome)
            return outcome
        with patch.object(capture_execution, "analyze_packet_outcome", side_effect=analyze) as operation:
            run_capture_execution(MemoryPacketSource(observations), delivered.append)
        self.assertEqual(operation.call_count, 5)
        self.assertEqual([o.failure_classification for o in delivered],
                         [PacketAnalysisFailureClassification.INCOMPLETE, PacketAnalysisFailureClassification.STRUCTURAL_FAILURE,
                          PacketAnalysisFailureClassification.UNSUPPORTED, PacketAnalysisFailureClassification.INTEGRITY_FAILURE, None])
        for actual, original in zip(delivered, returned):
            self.assertIs(actual, original)
        self.assertTrue(all(o.analysis is None for o in delivered[:-1]))
        self.assertTrue(delivered[-1].succeeded)

    def test_unexpected_analysis_failure_propagates_without_retry_or_next_observation(self):
        first = observation_at()
        source = MemoryPacketSource((first, observation_at(seconds=1), observation_at(seconds=2)))
        outcome = analyze_packet_outcome(first)
        error = ValueError("analysis sentinel")
        received = []
        with patch.object(capture_execution, "analyze_packet_outcome", side_effect=(outcome, error)) as analysis:
            with self.assertRaises(ValueError) as raised:
                run_capture_execution(source, received.append)
        self.assertIs(raised.exception, error)
        self.assertEqual(analysis.call_count, 2)
        self.assertEqual(received, [outcome])
        self.assertEqual(source.events, ["start", "produce:0", "produce:1", "stop"])

    def test_acquisition_errors_propagate_and_stop_once_without_retry(self):
        for stage in ("start", "iteration"):
            error = CaptureError(stage)
            source = MemoryPacketSource((observation_at(),), **{stage + "_error": error})
            received = []
            with patch.object(capture_execution, "analyze_packet_outcome", wraps=analyze_packet_outcome) as analysis:
                with self.assertRaises(CaptureError) as raised:
                    run_capture_execution(source, received.append)
            self.assertIs(raised.exception, error)
            self.assertEqual(analysis.call_count, 0 if stage == "start" else 1)
            self.assertEqual(len(received), analysis.call_count)
            self.assertEqual(source.events.count("start"), 1)
            self.assertEqual(source.events.count("stop"), 1)
            self.assertTrue(source.stopped)

    def test_downstream_failure_stops_before_next_acquisition_without_retry(self):
        source = MemoryPacketSource((observation_at(), observation_at(seconds=1)))
        error = RuntimeError("consumer sentinel")
        receive = Mock(side_effect=error)
        with patch.object(capture_execution, "analyze_packet_outcome", wraps=analyze_packet_outcome) as analysis:
            with self.assertRaises(RuntimeError) as raised:
                run_capture_execution(source, receive)
        self.assertIs(raised.exception, error)
        analysis.assert_called_once()
        receive.assert_called_once()
        self.assertEqual(source.events, ["start", "produce:0", "stop"])

    def test_cleanup_exception_precedence_matches_consume(self):
        for phase in ("analysis", "consumer", "acquisition", "normal"):
            primary, cleanup = ValueError("primary"), CaptureError("cleanup")
            options = {"stop_error": cleanup}
            if phase == "acquisition":
                primary = CaptureError("acquisition")
                options["iteration_error"] = primary
            source = MemoryPacketSource((observation_at(),), **options)
            consumer = Mock(side_effect=primary if phase == "consumer" else None)
            with patch.object(capture_execution, "analyze_packet_outcome", wraps=analyze_packet_outcome,
                              side_effect=primary if phase == "analysis" else None):
                with self.assertRaises(CaptureError) as raised:
                    run_capture_execution(source, consumer)
            self.assertIs(raised.exception, cleanup)
            self.assertIs(raised.exception.__context__, None if phase == "normal" else primary)
            self.assertEqual(source.events.count("stop"), 1)

    def test_iterable_source_preserves_acquired_metadata_and_is_detector_free(self):
        observation = observation_at(17)
        source = IterablePacketSource((observation.raw_bytes, b"", observation.raw_bytes), link_type=observation.link_type)
        received = []
        with patch.object(DetectionSession, "run_packets", side_effect=AssertionError("detector")), \
             patch.object(DetectionSession, "run_closed_flows", side_effect=AssertionError("detector")):
            run_capture_execution(source, received.append)
        self.assertEqual([o.succeeded for o in received], [True, False, True])
        for outcome, data in zip(received, (observation.raw_bytes, b"", observation.raw_bytes)):
            self.assertIs(outcome.observation.raw_bytes, data)
            self.assertIs(outcome.observation.link_type, observation.link_type)
            self.assertEqual((outcome.observation.captured_length, outcome.observation.original_length), (len(data), len(data)))
        self.assertEqual(list(source), [])
        with self.assertRaises(RuntimeError):
            source.start()

    def test_pcap_order_metadata_and_independent_repeated_execution(self):
        payload = observation_at(17).raw_bytes
        data = global_header(">", True) + b"".join(record(payload, ">", seconds=s, fraction=123456789, original=100)
                                                    for s in (3, 1, 3))
        with TemporaryDirectory() as directory:
            path = Path(directory) / "execution.pcap"
            path.write_bytes(data)
            results = []
            for _ in range(2):
                outcomes = []
                run_capture_execution(PcapPacketSource(path), outcomes.append)
                results.append(outcomes)
            self.assertEqual(path.read_bytes(), data)
        self.assertEqual(results[0], results[1])
        self.assertEqual([o.observation.captured_at.second for o in results[0]], [3, 1, 3])
        self.assertEqual([o.observation.captured_at.microsecond for o in results[0]], [123456] * 3)
        for outcome in results[0]:
            self.assertEqual(outcome.observation.raw_bytes, payload)
            self.assertEqual((outcome.observation.captured_length, outcome.observation.original_length), (62, 100))
        self.assertIsNot(results[0][0], results[0][2])
        self.assertIsNot(results[0][0].observation, results[0][2].observation)

    def test_pcap_corruption_and_consumer_failure_close_owned_file(self):
        for corrupt in (False, True):
            with TemporaryDirectory() as directory:
                path = Path(directory) / "execution.pcap"
                path.write_bytes(global_header() + record(observation_at().raw_bytes) + b"bad")
                source = PcapPacketSource(path)
                handle = path.open("rb")
                error = RuntimeError("consumer")
                consumer = Mock(side_effect=None if corrupt else error)
                with patch("capture.pcap_packet_source.io.open", return_value=handle):
                    with self.assertRaises(CaptureError if corrupt else RuntimeError):
                        run_capture_execution(source, consumer)
                consumer.assert_called_once()
                self.assertTrue(handle.closed)

    def test_execution_itself_never_reads_raw_data_or_reconstructs_semantics(self):
        observation = observation_at(6, extensions=(0, 60))
        outcome = analyze_packet_outcome(observation)
        received = []
        with ExitStack() as stack:
            operation = stack.enter_context(patch.object(capture_execution, "analyze_packet_outcome", return_value=outcome))
            for target in ("capture.packet_observation.PacketObservation.raw_bytes", "analysis.ipv6.IPv6Packet.payload"):
                stack.enter_context(patch(target, new_callable=PropertyMock, create=True, side_effect=AssertionError(target)))
            stack.enter_context(patch("analysis.packet_analysis_outcome.analyze_packet", side_effect=AssertionError("reanalysis")))
            run_capture_execution(MemoryPacketSource((observation,)), received.append)
        operation.assert_called_once_with(observation)
        self.assertIs(received[0], outcome)

    def test_pipeline_uses_public_execution_once_and_preserves_findings(self):
        observations = (observation_at(), observation_at(seconds=1, reverse=True), observation_at(seconds=6))
        session = DetectionSession(PacketIntegrityConfiguration("packet-integrity", "1"),
                                   volume_configuration(FlowVolumeMetric.PACKET_COUNT), control_configuration())
        with patch.object(detection_pipeline, "run_capture_execution", wraps=run_capture_execution) as execution, \
             patch.object(capture_execution, "consume", wraps=consume) as ingestion, \
             patch("analysis.packet_analysis_outcome.analyze_packet", wraps=analyze_packet) as parser, \
             patch.object(detection_pipeline, "extract_flow_feature_snapshot", wraps=detection_pipeline.extract_flow_feature_snapshot) as features:
            result = run_detection_pipeline(MemoryPacketSource(observations), detection_session=session,
                                            capture_session_id="execution", inactivity_timeout=timedelta(seconds=5))
        execution.assert_called_once()
        ingestion.assert_called_once()
        self.assertEqual(parser.call_count, 3)
        self.assertEqual(features.call_count, 2)
        self.assertEqual(len(result.packet_findings), 3)
        self.assertEqual([f.raw_evidence.total_packet_count for f in result.flow_findings], [2, 2, 1, 1])
        self.assertEqual([f.raw_evidence.observed_value for f in result.flow_findings], [2, 1, 1, 1])
        again = run_detection_pipeline(MemoryPacketSource(observations), detection_session=session,
                                       capture_session_id="execution", inactivity_timeout=timedelta(seconds=5))
        self.assertEqual(result, again)

    def test_flow_session_shares_execution_without_changing_raw_analysis_contract(self):
        valid = observation_at()
        bad = replace(valid, raw_bytes=b"", captured_length=0)
        source = MemoryPacketSource((valid, bad))
        windows = []
        with patch.object(flow_observation_session, "_execute_capture", wraps=capture_execution._execute_capture) as execution, \
             patch.object(capture_execution, "consume", wraps=consume) as ingestion, \
             patch.object(flow_observation_session, "analyze_packet", wraps=analyze_packet) as parser, \
             patch.object(capture_execution, "analyze_packet_outcome", side_effect=AssertionError("changed flow failure contract")):
            with self.assertRaises(EthernetDecodeError):
                run_flow_observation_session(source, capture_session_id="flow", inactivity_timeout=timedelta(seconds=5),
                                             closed_window_consumer=windows.append)
        execution.assert_called_once()
        ingestion.assert_called_once()
        self.assertEqual(parser.call_count, 2)
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0].coordinated_state.flow_statistics.packet_count, 1)
        self.assertEqual(source.events, ["start", "produce:0", "produce:1", "stop"])


if __name__ == "__main__":
    unittest.main()
