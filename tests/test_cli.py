import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import timedelta
from unittest.mock import Mock, PropertyMock, patch

from analysis import FlowObservationWindowError, analyze_packet
from application import DetectionPipelineResult, DetectionSession, run_detection_pipeline
from application import capture_execution, cli, detection_pipeline, flow_observation_session
from capture import CaptureError, PcapPacketSource
from detection import FlowVolumeMetric, PacketIntegrityConfiguration, TCPControlMetric
from tests.test_flow_volume_threshold import configuration as volume_configuration
from tests.test_ipv6_flow import observation_at
from tests.test_packet_analysis import TCP_BYTES, UDP_BYTES, make_observation
from tests.test_pcap_packet_source import global_header, record
from tests.test_tcp_control_threshold import configuration as control_configuration


class CLITests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "input.pcap"
        self.path.write_bytes(global_header())

    def arguments(self, **options):
        settings = {
            "capture-session-id": "cli-session",
            "inactivity-timeout-microseconds": "5000000",
            "packet-detector-id": "packet-integrity",
            "packet-detector-version": "1",
            "volume-detector-id": "flow-volume-threshold",
            "volume-detector-version": "1",
            "volume-metric": "packet_count",
            "volume-threshold": "0",
            "tcp-detector-id": "tcp-control-threshold",
            "tcp-detector-version": "1",
            "tcp-metric": "forward_syn_count",
            "tcp-threshold": "0",
        }
        settings.update(options)
        return [str(self.path)] + [value for name, value in settings.items() for value in ("--" + name, str(value))]

    def invoke(self, args=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = cli.main(self.arguments() if args is None else args)
        return status, stdout.getvalue(), stderr.getvalue()

    def packets(self, observations, seconds=None, network=1):
        if seconds is None:
            seconds = range(1, len(observations) + 1)
        self.path.write_bytes(global_header(network=network) + b"".join(
            record(o.raw_bytes, seconds=s, fraction=123456, original=o.original_length)
            for o, s in zip(observations, seconds)))

    def output(self, **options):
        status, stdout, stderr = self.invoke(self.arguments(**options))
        self.assertEqual((status, stderr), (0, ""))
        self.assertTrue(stdout.endswith("\n"))
        return json.loads(stdout)

    def assert_argument_error(self, args):
        with patch.object(cli, "PcapPacketSource") as source, patch.object(cli, "run_detection_pipeline") as pipeline:
            with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit) as raised:
                    cli.main(args)
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("nids-netops: error:", stderr.getvalue())
        source.assert_not_called()
        pipeline.assert_not_called()

    def test_cli_and_package_entrypoint_import_without_execution(self):
        with patch.object(cli, "run_detection_pipeline", side_effect=AssertionError("import execution")):
            entry = importlib.import_module("application.__main__")
        self.assertIs(entry.main, cli.main)
        self.assertTrue(callable(cli.main))

    def test_empty_capture_returns_exact_json_and_success(self):
        self.assertEqual(self.invoke(), (0, '{"packet_findings":[],"flow_findings":[]}\n', ""))

    def test_source_and_pipeline_called_once_with_explicit_configuration(self):
        source = Mock()
        with patch.object(cli, "PcapPacketSource", return_value=source) as create, \
             patch.object(cli, "run_detection_pipeline", return_value=DetectionPipelineResult((), ())) as pipeline:
            self.invoke(self.arguments(**{"volume-metric": "packets_per_second", "volume-threshold": "2.5",
                                         "tcp-metric": "reverse_ack_count", "tcp-threshold": "7"}))
        create.assert_called_once_with(str(self.path))
        pipeline.assert_called_once()
        self.assertIs(pipeline.call_args.args[0], source)
        source.start.assert_not_called()
        source.stop.assert_not_called()
        arguments = pipeline.call_args.kwargs
        self.assertEqual(arguments["capture_session_id"], "cli-session")
        self.assertEqual(arguments["inactivity_timeout"], timedelta(seconds=5))
        session = arguments["detection_session"]
        self.assertIs(type(session), DetectionSession)
        self.assertEqual(session.packet_configuration, PacketIntegrityConfiguration("packet-integrity", "1"))
        self.assertEqual(session.flow_volume_configuration.metric, FlowVolumeMetric.PACKETS_PER_SECOND)
        self.assertIs(type(session.flow_volume_configuration.threshold), float)
        self.assertEqual(session.flow_volume_configuration.threshold, 2.5)
        self.assertEqual(session.tcp_control_configuration.metric, TCPControlMetric.REVERSE_ACK)
        self.assertEqual(session.tcp_control_configuration.threshold, 7)

    def test_real_pipeline_analysis_flow_and_feature_execution_are_not_duplicated(self):
        self.packets((observation_at(), observation_at(reverse=True), observation_at()), seconds=(1, 2, 7))
        with patch.object(cli, "run_detection_pipeline", wraps=run_detection_pipeline) as pipeline, \
             patch.object(detection_pipeline, "run_capture_execution", wraps=capture_execution.run_capture_execution) as execution, \
             patch("analysis.packet_analysis_outcome.analyze_packet", wraps=analyze_packet) as parser, \
             patch.object(detection_pipeline, "_run_flow_observation_session", wraps=flow_observation_session._run_flow_observation_session) as flow, \
             patch.object(detection_pipeline, "extract_flow_feature_snapshot", wraps=detection_pipeline.extract_flow_feature_snapshot) as features:
            data = self.output()
        pipeline.assert_called_once()
        execution.assert_called_once()
        flow.assert_called_once()
        self.assertEqual((parser.call_count, features.call_count), (3, 2))
        self.assertEqual([f["raw_evidence"]["total_packet_count"] for f in data["flow_findings"]], [2, 2, 1, 1])

    def test_ipv4_tcp_detection(self):
        self.packets((make_observation(6, TCP_BYTES),))
        data = self.output()
        self.assertEqual(data["packet_findings"][0]["decision"], "no_match")
        self.assertEqual([f["raw_evidence"]["identity"]["ip_version"] for f in data["flow_findings"]], [4, 4])
        self.assertEqual(data["flow_findings"][0]["raw_evidence"]["identity"]["source_address"], "c0000201")

    def test_ipv4_udp_does_not_receive_tcp_detection(self):
        self.packets((make_observation(17, UDP_BYTES),))
        data = self.output()
        self.assertEqual(data["packet_findings"][0]["raw_evidence"]["protocol"], 17)
        self.assertEqual([f["detector_id"] for f in data["flow_findings"]], ["flow-volume-threshold"])

    def test_ipv6_tcp_extension_chain_uses_existing_detection(self):
        observation = observation_at(6, extensions=(0, 43, 60))
        self.packets((observation,))
        data = self.output()
        self.assertEqual([f["decision"] for f in data["flow_findings"]], ["match", "match"])
        evidence = data["flow_findings"][0]["raw_evidence"]
        self.assertEqual(evidence["identity"], {"ip_version": 6, "source_address": "20010db8000000000000000000000001",
                                              "destination_address": "20010db8000000000000000000000002",
                                              "source_port": 12345, "destination_port": 443, "protocol": 6})

    def test_ipv6_udp_extension_chain_has_volume_only(self):
        self.packets((observation_at(17, extensions=(0, 60)),))
        data = self.output()
        self.assertEqual(len(data["flow_findings"]), 1)
        self.assertEqual(data["flow_findings"][0]["raw_evidence"]["identity"]["protocol"], 17)
        self.assertEqual(data["flow_findings"][0]["decision"], "match")

    def test_unsupported_link_is_packet_outcome_not_capture_error(self):
        self.packets((observation_at(),), network=65001)
        data = self.output()
        self.assertEqual(data["flow_findings"], [])
        finding = data["packet_findings"][0]
        self.assertEqual((finding["decision"], finding["raw_evidence"]["failure_classification"]), ("not_evaluable", "unsupported"))
        self.assertEqual(finding["raw_evidence"]["link_type"], 65001)

    def test_incomplete_analysis_is_visible_in_successful_cli_result(self):
        self.path.write_bytes(global_header() + record(b""))
        data = self.output()
        self.assertEqual(data["flow_findings"], [])
        evidence = data["packet_findings"][0]["raw_evidence"]
        self.assertEqual(evidence["failure_classification"], "incomplete")
        self.assertEqual(evidence["failure_description"], "Ethernet frame is too short: expected at least 14 bytes, got 0")

    def test_structural_analysis_failure_preserves_match(self):
        raw = observation_at().raw_bytes
        self.path.write_bytes(global_header() + record(raw[:14] + b"\x50" + raw[15:]))
        finding = self.output()["packet_findings"][0]
        self.assertEqual((finding["decision"], finding["raw_evidence"]["failure_classification"]), ("match", "structural_failure"))

    def test_integrity_analysis_failure_is_not_process_failure(self):
        self.packets((make_observation(17, UDP_BYTES, ipv4_checksum=0),))
        data = self.output()
        self.assertEqual(data["flow_findings"], [])
        self.assertEqual(data["packet_findings"][0]["raw_evidence"]["failure_classification"], "integrity_failure")

    def test_duplicate_packets_and_findings_are_not_deduplicated(self):
        observation = observation_at(17)
        self.packets((observation, observation), seconds=(1, 1))
        data = self.output()
        self.assertEqual(len(data["packet_findings"]), 2)
        self.assertEqual(data["packet_findings"][0], data["packet_findings"][1])
        self.assertEqual(data["flow_findings"][0]["raw_evidence"]["observed_value"], 2)

    def test_independent_flow_and_detector_order_is_not_sorted(self):
        self.packets((observation_at(17, source_port=20000), observation_at(6, source_port=10000)))
        findings = self.output()["flow_findings"]
        self.assertEqual([f["raw_evidence"]["identity"]["source_port"] for f in findings], [20000, 10000, 10000])
        self.assertEqual([f["detector_id"] for f in findings], ["flow-volume-threshold", "flow-volume-threshold", "tcp-control-threshold"])

    def test_decreasing_packet_timestamps_remain_in_input_order_when_outcomes_are_unsupported(self):
        self.packets((observation_at(), observation_at(), observation_at()), seconds=(3, 1, 2), network=101)
        findings = self.output()["packet_findings"]
        self.assertEqual([f["raw_evidence"]["captured_at"] for f in findings],
                         ["1970-01-01T00:00:03.123456+00:00", "1970-01-01T00:00:01.123456+00:00", "1970-01-01T00:00:02.123456+00:00"])

    def test_decreasing_admitted_flow_timestamps_retain_existing_error(self):
        self.packets((observation_at(), observation_at()), seconds=(2, 1))
        with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(FlowObservationWindowError):
                cli.main(self.arguments())
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))

    def test_capture_error_is_normalized_without_exception_or_path_leakage(self):
        with patch.object(cli, "run_detection_pipeline", side_effect=CaptureError(str(self.path))) as pipeline:
            self.assertEqual(self.invoke(), (1, "", '{"error":"capture_error"}\n'))
        pipeline.assert_called_once()

    def test_missing_pcap_path_returns_capture_error(self):
        args = self.arguments()
        args[0] = str(self.path.parent / "missing.pcap")
        self.assertEqual(self.invoke(args), (1, "", '{"error":"capture_error"}\n'))

    def test_malformed_pcap_header_returns_capture_error(self):
        self.path.write_bytes(b"invalid")
        self.assertEqual(self.invoke(), (1, "", '{"error":"capture_error"}\n'))

    def test_corruption_after_valid_records_emits_no_partial_json(self):
        self.packets((observation_at(),))
        with self.path.open("ab") as handle:
            handle.write(b"bad")
        self.assertEqual(self.invoke(), (1, "", '{"error":"capture_error"}\n'))

    def test_all_configuration_arguments_are_explicitly_required(self):
        args = self.arguments()
        self.assert_argument_error(args[1:])
        for index in range(1, len(args), 2):
            with self.subTest(option=args[index]):
                self.assert_argument_error(args[:index] + args[index + 2:])

    def test_invalid_metric_choices_are_argparse_errors(self):
        for name in ("volume-metric", "tcp-metric"):
            self.assert_argument_error(self.arguments(**{name: "unknown"}))

    def test_count_threshold_requires_nonnegative_integer(self):
        for name in ("volume-threshold", "tcp-threshold"):
            for value in ("-1", "1.5", "NaN", "text"):
                self.assert_argument_error(self.arguments(**{name: value}))

    def test_rate_threshold_requires_finite_nonnegative_float(self):
        for value in ("-1", "nan", "inf", "-inf", "1e999", "text"):
            self.assert_argument_error(self.arguments(**{"volume-metric": "packets_per_second", "volume-threshold": value}))

    def test_timeout_requires_positive_representable_integer_microseconds(self):
        for value in ("0", "-1", "0.1", "text", str(10 ** 30)):
            self.assert_argument_error(self.arguments(**{"inactivity-timeout-microseconds": value}))

    def test_blank_identity_metadata_is_rejected_before_capture(self):
        for name in ("capture-session-id", "packet-detector-id", "packet-detector-version", "volume-detector-id",
                     "volume-detector-version", "tcp-detector-id", "tcp-detector-version"):
            self.assert_argument_error(self.arguments(**{name: "  "}))

    def test_unknown_and_abbreviated_options_are_not_accepted(self):
        self.assert_argument_error(self.arguments() + ["--unknown", "value"])
        args = self.arguments()
        args[args.index("--volume-threshold")] = "--volume-thresh"
        self.assert_argument_error(args)

    def test_help_exits_successfully_without_source_or_pipeline_execution(self):
        with patch.object(cli, "PcapPacketSource") as source, patch.object(cli, "run_detection_pipeline") as pipeline:
            with redirect_stdout(io.StringIO()) as stdout:
                with self.assertRaises(SystemExit) as raised:
                    cli.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("local classic PCAP", stdout.getvalue())
        source.assert_not_called()
        pipeline.assert_not_called()

    def test_unexpected_pipeline_error_propagates_exactly_without_retry(self):
        for error in (ValueError("detector"), RuntimeError("analysis"), OSError("internal")):
            with patch.object(cli, "run_detection_pipeline", side_effect=error) as pipeline:
                with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
                    with self.assertRaises(type(error)) as raised:
                        cli.main(self.arguments())
            self.assertIs(raised.exception, error)
            self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))
            pipeline.assert_called_once()

    def test_serialization_failure_propagates_without_partial_stdout(self):
        error = TypeError("serialization")
        with patch.object(cli, "_result_json", side_effect=error):
            with redirect_stdout(io.StringIO()) as stdout:
                with self.assertRaises(TypeError) as raised:
                    cli.main(self.arguments())
        self.assertIs(raised.exception, error)
        self.assertEqual(stdout.getvalue(), "")

    def test_packet_json_contains_only_documented_fields(self):
        self.packets((observation_at(17),))
        data = self.output()
        self.assertEqual(set(data), {"packet_findings", "flow_findings"})
        finding = data["packet_findings"][0]
        self.assertEqual(set(finding), {"detector_id", "detector_version", "decision", "raw_evidence", "security_interpretation"})
        self.assertEqual(finding["raw_evidence"], {"captured_at": "1970-01-01T00:00:01.123456+00:00",
                         "capture_source": "local-pcap", "link_type": 1, "captured_length": 62, "original_length": 62,
                         "protocol": 17, "failure_classification": None, "failure_description": None})
        self.assertEqual(finding["security_interpretation"], "No supported integrity or structural violation was observed.")

    def test_volume_json_has_exact_evidence_fields_and_values(self):
        self.packets((observation_at(17),))
        evidence = self.output()["flow_findings"][0]["raw_evidence"]
        self.assertEqual(set(evidence), {"capture_session_id", "sequence_number", "closure_reason", "identity",
                         "first_captured_at", "last_captured_at", "selected_metric", "threshold", "observed_value",
                         "comparison_operator", "total_packet_count", "forward_packet_count", "reverse_packet_count",
                         "captured_byte_total", "original_byte_total"})
        self.assertEqual((evidence["sequence_number"], evidence["closure_reason"], evidence["comparison_operator"],
                          evidence["observed_value"], evidence["threshold"]), (0, "capture_session_end", ">", 1, 0))

    def test_tcp_json_projects_existing_control_evidence_without_extra_byte_fields(self):
        self.packets((observation_at(), observation_at(reverse=True)))
        evidence = self.output()["flow_findings"][1]["raw_evidence"]
        self.assertEqual((evidence["selected_metric"], evidence["observed_value"], evidence["forward_packet_count"],
                          evidence["reverse_packet_count"]), ("forward_syn_count", 1, 1, 1))
        self.assertNotIn("captured_byte_total", evidence)
        self.assertNotIn("original_byte_total", evidence)

    def test_repeated_independent_executions_have_identical_output(self):
        self.packets((observation_at(), observation_at(17)))
        before = self.path.read_bytes()
        first = self.invoke()
        self.assertEqual(first, self.invoke())
        self.assertEqual(first, self.invoke())
        self.assertEqual(self.path.read_bytes(), before)

    def test_unicode_and_escaped_metadata_round_trip_without_object_representations(self):
        self.packets((observation_at(17),))
        data = self.output(**{"capture-session-id": 'session-\u03bb\n"', "volume-detector-id": "volume-\u03bb"})
        self.assertEqual(data["flow_findings"][0]["detector_id"], "volume-\u03bb")
        self.assertEqual(data["flow_findings"][0]["raw_evidence"]["capture_session_id"], 'session-\u03bb\n"')

    def test_output_has_no_machine_or_execution_metadata(self):
        self.packets((observation_at(17),))
        status, stdout, stderr = self.invoke()
        self.assertEqual((status, stderr), (0, ""))
        self.assertNotIn(str(self.path), stdout)
        self.assertNotIn(str(Path.cwd()), stdout)
        self.assertNotIn("object at", stdout)
        for key in ("pid", "hostname", "execution_timestamp", "finding_id", "severity", "confidence", "risk"):
            self.assertNotIn('"' + key + '"', stdout)

    def test_unavailable_rate_serializes_as_null_and_remains_not_evaluable(self):
        self.packets((observation_at(17),))
        finding = self.output(**{"volume-metric": "packets_per_second", "volume-threshold": "0.0"})["flow_findings"][0]
        self.assertEqual(finding["decision"], "not_evaluable")
        self.assertIsNone(finding["raw_evidence"]["observed_value"])
        self.assertIs(type(finding["raw_evidence"]["threshold"]), float)

    def test_threshold_boundaries_preserve_existing_volume_and_tcp_operators(self):
        self.packets((observation_at(), observation_at()), seconds=(1, 2))
        for threshold, expected in ((1, "match"), (2, "no_match"), (3, "no_match")):
            data = self.output(**{"volume-threshold": threshold, "tcp-threshold": threshold})
            self.assertEqual([f["decision"] for f in data["flow_findings"]], [expected, expected])
        finding = self.output(**{"volume-metric": "packets_per_second", "volume-threshold": "2.0"})["flow_findings"][0]
        self.assertEqual((finding["decision"], finding["raw_evidence"]["observed_value"]), ("no_match", 2.0))

    def test_capture_and_original_byte_lengths_are_not_normalized(self):
        payload = observation_at(17).raw_bytes
        self.path.write_bytes(global_header() + record(payload, original=200))
        data = self.output(**{"volume-metric": "original_bytes", "volume-threshold": "199"})
        packet = data["packet_findings"][0]["raw_evidence"]
        flow = data["flow_findings"][0]["raw_evidence"]
        self.assertEqual((packet["captured_length"], packet["original_length"]), (62, 200))
        self.assertEqual((flow["captured_byte_total"], flow["original_byte_total"], flow["observed_value"]), (62, 200, 200))

    def test_module_execution_in_subprocess_matches_main_output(self):
        self.packets((observation_at(17),))
        expected = self.invoke()
        environment = dict(os.environ, PYTHONPATH="src")
        completed = subprocess.run([sys.executable, "-B", "-m", "application"] + self.arguments(),
                                   capture_output=True, text=True, env=environment, check=False)
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr), expected)

    def test_adapter_only_reads_projected_evidence_after_pipeline_returns(self):
        self.packets((observation_at(),))
        session = DetectionSession(PacketIntegrityConfiguration("packet-integrity", "1"),
                                   volume_configuration(FlowVolumeMetric.PACKET_COUNT), control_configuration())
        result = run_detection_pipeline(PcapPacketSource(self.path), detection_session=session,
                                        capture_session_id="cli-session", inactivity_timeout=timedelta(seconds=5))
        expected = cli._result_json(result)
        before = repr(result)
        with ExitStack() as stack:
            pipeline = stack.enter_context(patch.object(cli, "run_detection_pipeline", return_value=result))
            for target in ("capture.packet_observation.PacketObservation.raw_bytes", "analysis.ipv6.IPv6Packet.payload",
                           "analysis.ethernet.EthernetFrame.payload"):
                stack.enter_context(patch(target, new_callable=PropertyMock, create=True, side_effect=AssertionError(target)))
            for target in ("application.capture_execution.analyze_packet_outcome", "analysis.packet_analysis.analyze_packet",
                           "application.detection_pipeline.extract_flow_feature_snapshot", "application.flow_observation_session.FlowObservationWindowManager",
                           "application.detection_session.run_packet_detectors", "application.detection_session.run_closed_flow_detectors"):
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            self.assertEqual(self.invoke(), (0, expected, ""))
        pipeline.assert_called_once()
        self.assertEqual(repr(result), before)


if __name__ == "__main__":
    unittest.main()
