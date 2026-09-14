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

from analysis import FlowIdentityError, FlowObservationWindowError, analyze_packet
from application import (DetectionPipelineResult, DetectionSession, OperationalErrorCategory,
                         PerformanceBenchmarkConfiguration, diagnose_error, run_detection_pipeline, run_performance_benchmark)
from application import capture_execution, cli, detection_pipeline, flow_observation_session
from capture import CaptureError, PcapPacketSource
from detection import FlowVolumeMetric, PacketIntegrityConfiguration, TCPControlMetric
from tests.test_flow_volume_threshold import configuration as volume_configuration
from tests.test_ipv6_flow import observation_at
from tests.test_packet_analysis import TCP_BYTES, UDP_BYTES, make_observation
from tests.test_pcap_packet_source import global_header, record
from tests.test_tcp_control_threshold import configuration as control_configuration


class CLITests(unittest.TestCase):
    def test_active_window_limit_default_and_override_reach_pipeline(self):
        for limit in (None, 1, 4096):
            arguments = self.arguments() if limit is None else self.arguments(**{'max-active-windows': limit})
            with patch.object(cli, 'run_detection_pipeline', return_value=DetectionPipelineResult((), ())) as execute:
                self.assertEqual(self.invoke(arguments)[0], 0)
            self.assertEqual(execute.call_args.kwargs['max_active_windows'], 1024 if limit is None else limit)

    def test_invalid_or_repeated_active_window_limit_fails_before_acquisition(self):
        for values in (['0'], ['-1'], ['1.5'], ['invalid'], ['1', '2']):
            arguments = self.arguments() + [part for value in values for part in ('--max-active-windows', value)]
            with patch.object(cli, 'PcapPacketSource') as source:
                self.argument_failure(arguments)
            source.assert_not_called()

    def test_capacity_closure_is_visible_in_cli_json(self):
        from tests.test_flow_capacity import capacity_packet

        packets = tuple(capacity_packet(i, i, ipv6=bool(i % 2)) for i in range(3))
        self.packets(packets, seconds=(0, 1, 2))
        status, stdout, stderr = self.invoke(self.arguments(**{'max-active-windows': 1}))
        self.assertEqual((status, stderr), (0, ''))
        findings = json.loads(stdout)['flow_findings']
        self.assertEqual([f['raw_evidence']['closure_reason'] for f in findings],
                         ['capacity', 'capacity', 'capture_session_end'])
        self.assertEqual([f['raw_evidence']['sequence_number'] for f in findings], [0, 1, 2])

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


    def argument_failure(self, args):
        with patch.object(cli, "PcapPacketSource") as source, patch.object(cli, "run_detection_pipeline") as pipeline:
            with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit) as raised:
                    cli.main(args)
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("Traceback", stderr.getvalue())
        source.assert_not_called()
        pipeline.assert_not_called()
        return stderr.getvalue()

    def process(self, args=None, **environment):
        env = dict(os.environ, PYTHONPATH="src", **environment)
        result = subprocess.run([sys.executable, "-B", "-m", "application"] +
                                (self.arguments() if args is None else args),
                                capture_output=True, text=True, env=env, check=False)
        return result.returncode, result.stdout, result.stderr

    def test_help_is_identical_across_terminal_widths(self):
        outputs = []
        for width in ("20", "80", "200"):
            with patch.dict(os.environ, COLUMNS=width), redirect_stdout(io.StringIO()) as stdout:
                with self.assertRaises(SystemExit) as raised:
                    cli.main(["--help"])
            self.assertEqual(raised.exception.code, 0)
            outputs.append(stdout.getvalue())
        self.assertEqual(outputs, [outputs[0]] * 3)

    def test_help_explains_units_domains_and_exit_contract(self):
        status, stdout, stderr = self.process(["--help"])
        self.assertEqual((status, stderr), (0, ""))
        for phrase in ("integer microseconds", "nonnegative integer", "UDP-only input", "Required settings must occur once",
                       "Exit 0:", "capture failure", "argument/configuration error", "No live capture"):
            self.assertIn(phrase, stdout)
        for option in self.arguments()[1::2]:
            self.assertIn(option, stdout)

    def test_argument_usage_is_identical_across_terminal_widths(self):
        outputs = []
        for width in ("24", "160"):
            with patch.dict(os.environ, COLUMNS=width):
                outputs.append(self.argument_failure([]))
        self.assertEqual(outputs[0], outputs[1])

    def test_duplicate_detector_identities_are_rejected_before_acquisition(self):
        for option in ("packet-detector-id", "volume-detector-version", "tcp-detector-id", "capture-session-id"):
            with self.subTest(option=option):
                error = self.argument_failure(self.arguments() + ["--" + option, "replacement"])
                self.assertIn("--" + option + ": must be supplied exactly once", error)
                self.assertNotIn("replacement", error)

    def test_duplicate_metric_selections_are_rejected(self):
        for option, value in (("volume-metric", "captured_bytes"), ("tcp-metric", "reverse_ack_count")):
            with self.subTest(option=option):
                self.assertIn("must be supplied exactly once", self.argument_failure(self.arguments() + ["--" + option, value]))

    def test_duplicate_numeric_settings_are_rejected_including_zero(self):
        for option in ("volume-threshold", "tcp-threshold", "inactivity-timeout-microseconds"):
            with self.subTest(option=option):
                self.assertIn("must be supplied exactly once", self.argument_failure(self.arguments() + ["--" + option, "10"]))

    def test_identical_duplicate_values_are_not_silently_accepted(self):
        args = self.arguments()
        for index in range(1, len(args), 2):
            with self.subTest(option=args[index]):
                self.assertIn("must be supplied exactly once", self.argument_failure(args + args[index:index + 2]))

    def test_duplicate_equals_form_cannot_override_separate_form(self):
        self.assertIn("must be supplied exactly once", self.argument_failure(self.arguments() + ["--volume-threshold=3"]))

    def test_equals_form_preserves_valid_settings(self):
        args = self.arguments()
        equals = [args[0]] + [args[i] + "=" + args[i + 1] for i in range(1, len(args), 2)]
        self.assertEqual(self.invoke(equals), self.invoke(args))

    def test_option_order_does_not_change_result(self):
        self.packets((observation_at(), observation_at(17)))
        args = self.arguments()
        reordered = [v for i in reversed(range(1, len(args), 2)) for v in args[i:i + 2]] + args[:1]
        self.assertEqual(self.invoke(reordered), self.invoke(args))

    def test_argument_list_is_preserved_on_success_and_duplicate_failure(self):
        for args in (self.arguments(), self.arguments() + ["--tcp-threshold", "2"]):
            before = list(args)
            if len(args) == len(self.arguments()):
                self.invoke(args)
            else:
                self.argument_failure(args)
            self.assertEqual(args, before)

    def test_blank_path_is_argument_error_without_acquisition(self):
        for value in ("", " ", "\t\n"):
            args = self.arguments()
            args[0] = value
            self.assertIn("nonblank path", self.argument_failure(args))

    def test_nul_path_is_argument_error_without_value_leakage(self):
        args = self.arguments()
        args[0] = "private-input\x00payload"
        error = self.argument_failure(args)
        self.assertIn("without NUL", error)
        self.assertNotIn("private-input", error)
        self.assertNotIn("payload", error)

    def test_nonblank_path_is_not_trimmed_or_rewritten(self):
        path = self.path.parent / " capture file .pcap "
        path.write_bytes(global_header())
        args = self.arguments()
        args[0] = str(path)
        before = path.read_bytes()
        self.assertEqual(self.invoke(args), (0, '{"packet_findings":[],"flow_findings":[]}\n', ""))
        self.assertEqual(path.read_bytes(), before)

    def test_integer_conversion_errors_do_not_echo_arbitrary_values(self):
        for option in ("tcp-threshold", "inactivity-timeout-microseconds"):
            error = self.argument_failure(self.arguments(**{option: "private-value\x1b[31m"}))
            self.assertIn("must be an integer", error)
            self.assertNotIn("private-value", error)
            self.assertNotIn("\x1b", error)

    def test_volume_conversion_errors_are_safe_for_count_and_rate_modes(self):
        for metric in ("packet_count", "packets_per_second"):
            error = self.argument_failure(self.arguments(**{"volume-metric": metric, "volume-threshold": "private-value\n"}))
            self.assertIn("--volume-threshold must be a number", error)
            self.assertNotIn("private-value", error)

    def test_directory_input_uses_existing_capture_failure(self):
        args = self.arguments()
        args[0] = str(self.path.parent)
        self.assertEqual(self.invoke(args), (1, "", '{"error":"capture_error"}\n'))

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'requires filesystem FIFO support')
    def test_fifo_and_symlink_subprocess_failures_have_repeatable_safe_output(self):
        fifo = self.path.parent / 'private-input.fifo'
        os.mkfifo(fifo)
        alias = self.path.parent / 'private-fifo-link'
        alias.symlink_to(fifo)
        for path in (fifo, alias):
            with self.subTest(path=path.name):
                args = self.arguments()
                args[0] = str(path)
                results = [subprocess.run([sys.executable, '-B', '-m', 'application'] + args,
                           capture_output=True, text=True, env=dict(os.environ, PYTHONPATH='src'),
                           check=False, timeout=10) for _ in range(2)]
                self.assertEqual([(result.returncode, result.stdout, result.stderr) for result in results],
                                 [(1, '', '{"error":"capture_error"}\n')] * 2)

    def test_unreadable_input_is_diagnosed_after_existing_cleanup(self):
        error = PermissionError("private-file-location")
        with patch("capture.pcap_packet_source.io.open", side_effect=error), \
             patch.object(PcapPacketSource, "stop", autospec=True, wraps=None) as stop, \
             patch.object(cli, "diagnose_error", wraps=diagnose_error) as diagnose:
            self.assertEqual(self.invoke(), (1, "", '{"error":"capture_error"}\n'))
        stop.assert_called_once()
        diagnosed = diagnose.call_args.args[0]
        self.assertIs(type(diagnosed), CaptureError)
        self.assertIs(diagnosed.__cause__, error)

    def test_zero_byte_file_is_distinct_from_empty_pcap(self):
        self.path.write_bytes(b"")
        self.assertEqual(self.invoke(), (1, "", '{"error":"capture_error"}\n'))
        self.path.write_bytes(global_header())
        self.assertEqual(self.invoke(), (0, '{"packet_findings":[],"flow_findings":[]}\n', ""))

    def test_pcapng_is_rejected_by_existing_capture_reader(self):
        self.path.write_bytes(bytes.fromhex("0a0d0d0a") + bytes(24))
        self.assertEqual(self.invoke(), (1, "", '{"error":"capture_error"}\n'))

    def test_capture_diagnostic_retains_original_exception_without_inspection(self):
        class UnprintableCaptureError(CaptureError):
            def __str__(self):
                raise AssertionError("exception text read")
        error = UnprintableCaptureError("private-content")
        diagnostics = []
        def diagnose(caught, **metadata):
            value = diagnose_error(caught, **metadata)
            diagnostics.append(value)
            return value
        with patch.object(cli, "run_detection_pipeline", side_effect=error) as pipeline, \
             patch.object(cli, "diagnose_error", side_effect=diagnose) as adapter:
            self.assertEqual(self.invoke(), (1, "", '{"error":"capture_error"}\n'))
        pipeline.assert_called_once()
        adapter.assert_called_once_with(error, operation_id="detection-pipeline", message="capture_error")
        self.assertEqual(diagnostics[0].category, OperationalErrorCategory.UNCLASSIFIED_FAILURE)
        self.assertEqual(diagnostics[0].context, ())

    def test_exact_capture_error_uses_existing_diagnostic_category(self):
        error = CaptureError("private-content")
        with patch.object(cli, "run_detection_pipeline", side_effect=error), \
             patch.object(cli, "diagnose_error", wraps=diagnose_error) as diagnose:
            self.invoke()
        value = diagnose_error(*diagnose.call_args.args, **diagnose.call_args.kwargs)
        self.assertEqual(value.category, OperationalErrorCategory.CAPTURE_FAILURE)
        self.assertEqual((value.operation_id, value.message), ("detection-pipeline", "capture_error"))

    def test_unexpected_errors_do_not_invoke_diagnostics(self):
        error = RuntimeError("internal")
        with patch.object(cli, "run_detection_pipeline", side_effect=error) as pipeline, \
             patch.object(cli, "diagnose_error") as diagnose:
            with self.assertRaises(RuntimeError) as raised:
                self.invoke()
        self.assertIs(raised.exception, error)
        pipeline.assert_called_once()
        diagnose.assert_not_called()

    def test_stdout_failure_propagates_once_without_diagnostic_or_retry(self):
        error = BrokenPipeError("closed output")
        output = Mock()
        output.write.side_effect = error
        with patch.object(sys, "stdout", output), patch.object(cli, "diagnose_error") as diagnose, \
             patch.object(cli, "run_detection_pipeline", return_value=DetectionPipelineResult((), ())) as pipeline:
            with self.assertRaises(BrokenPipeError) as raised:
                cli.main(self.arguments())
        self.assertIs(raised.exception, error)
        output.write.assert_called_once()
        pipeline.assert_called_once()
        diagnose.assert_not_called()

    def test_stderr_failure_propagates_without_reexecuting_capture(self):
        error = OSError("closed error stream")
        output = Mock()
        output.write.side_effect = error
        with patch.object(sys, "stderr", output), patch.object(cli, "run_detection_pipeline", side_effect=CaptureError("capture")) as pipeline:
            with self.assertRaises(OSError) as raised:
                cli.main(self.arguments())
        self.assertIs(raised.exception, error)
        pipeline.assert_called_once()
        output.write.assert_called_once()

    def test_pipeline_success_closes_source_before_presentation(self):
        sources = []
        def create(path):
            source = PcapPacketSource(path)
            sources.append(source)
            return source
        with patch.object(cli, "PcapPacketSource", side_effect=create):
            self.invoke()
        self.assertEqual(len(sources), 1)
        with self.assertRaises(RuntimeError):
            sources[0].start()
        self.assertEqual(list(sources[0]), [])

    def test_cli_does_not_execute_evaluation_reporting_or_benchmarks(self):
        self.packets((observation_at(17),))
        with ExitStack() as stack:
            for target in ("application.detection_evaluation.evaluate_detection_result", "application.detection_metrics.calculate_detection_metrics",
                           "application.evaluation_report.EvaluationReport.__post_init__", "application.end_to_end_validation.run_end_to_end_validation",
                           "application.detection_benchmark.run_detection_benchmark", "application.performance_benchmark.run_performance_benchmark"):
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            self.assertEqual(self.invoke()[0], 0)

    def test_performance_wrapper_executes_cli_only_configured_number_of_times(self):
        config = PerformanceBenchmarkConfiguration("cli", "1", 2, 1)
        clock = Mock(side_effect=(0.0, 1.0, 2.0, 4.0))
        operation = Mock(side_effect=self.invoke)
        result = run_performance_benchmark(operation, configuration=config, clock=clock)
        self.assertEqual(operation.call_count, 3)
        self.assertEqual(clock.call_count, 4)
        self.assertEqual(result.elapsed_seconds, (1.0, 2.0))
        self.assertIs(result.configuration, config)

    def test_subprocess_ipv4_tcp_preserves_packet_and_control_outputs(self):
        self.packets((make_observation(6, TCP_BYTES),))
        self.assertEqual(self.process(), self.invoke())
        self.assertEqual(len(json.loads(self.process()[1])["flow_findings"]), 2)

    def test_subprocess_ipv4_udp_preserves_volume_only_output(self):
        self.packets((make_observation(17, UDP_BYTES),))
        result = self.process()
        self.assertEqual(result, self.invoke())
        self.assertEqual(len(json.loads(result[1])["flow_findings"]), 1)

    def test_subprocess_ipv6_tcp_extensions_preserve_ordered_findings(self):
        self.packets((observation_at(6, extensions=(0, 43, 60)),))
        result = self.process()
        self.assertEqual(result, self.invoke())
        self.assertEqual([f["detector_id"] for f in json.loads(result[1])["flow_findings"]],
                         ["flow-volume-threshold", "tcp-control-threshold"])

    def test_subprocess_ipv6_udp_whole_fragment_preserves_existing_admission(self):
        self.packets((observation_at(17, fragment=(0, False)),))
        result = self.process()
        self.assertEqual(result, self.invoke())
        self.assertEqual(len(json.loads(result[1])["flow_findings"]), 1)

    def test_first_fragment_uses_existing_tcp_pipeline(self):
        self.packets((observation_at(6, fragment=(0, True)),))
        data = self.output()
        self.assertEqual(len(data["flow_findings"]), 2)
        self.assertEqual(self.process(), self.invoke())

    def test_nonfirst_ipv6_fragment_preserves_admission_exception(self):
        self.packets((observation_at(6, fragment=(1, False)),))
        with patch.object(cli, "diagnose_error") as diagnose:
            with self.assertRaises(FlowIdentityError):
                self.invoke()
        diagnose.assert_not_called()

    def test_subprocess_missing_input_has_usage_without_traceback(self):
        status, stdout, stderr = self.process([])
        self.assertEqual((status, stdout), (2, ""))
        self.assertIn("nids-netops: error:", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_subprocess_missing_file_preserves_capture_error_contract(self):
        args = self.arguments()
        args[0] = str(self.path.parent / "missing.pcap")
        self.assertEqual(self.process(args), (1, "", '{"error":"capture_error"}\n'))

    def test_subprocess_malformed_pcap_has_no_partial_output(self):
        self.path.write_bytes(b"malformed")
        self.assertEqual(self.process(), (1, "", '{"error":"capture_error"}\n'))

    def test_subprocess_duplicate_option_has_no_capture_or_result(self):
        args = self.arguments()
        args[0] = str(self.path.parent / "missing.pcap")
        status, stdout, stderr = self.process(args + ["--volume-threshold", "4"])
        self.assertEqual((status, stdout), (2, ""))
        self.assertIn("must be supplied exactly once", stderr)
        self.assertNotIn("capture_error", stderr)

    def test_subprocess_results_ignore_hash_seed_and_terminal_environment(self):
        self.packets((observation_at(17, source_port=20000), observation_at(6, source_port=10000)))
        before = self.path.read_bytes()
        first = self.process(PYTHONHASHSEED="1", COLUMNS="20", NIDS_PRIVATE_TEST="private-content")
        second = self.process(PYTHONHASHSEED="2", COLUMNS="200", NIDS_PRIVATE_TEST="different-content")
        self.assertEqual(first, second)
        self.assertEqual(first[0], 0)
        self.assertNotIn("private-content", first[1])
        self.assertEqual(self.path.read_bytes(), before)

    def test_failed_argument_parse_does_not_contaminate_next_invocation(self):
        self.argument_failure(self.arguments() + ["--tcp-threshold", "2"])
        self.assertEqual(self.invoke(), (0, '{"packet_findings":[],"flow_findings":[]}\n', ""))


if __name__ == "__main__":
    unittest.main()
