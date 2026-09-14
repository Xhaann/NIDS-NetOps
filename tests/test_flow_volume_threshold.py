import unittest
from builtins import open as builtin_open
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from math import inf, nan
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

from analysis import (
    FlowFeatureSnapshot,
    FlowObservationWindow,
    FlowObservationWindowClosureReason,
    FlowObservationWindowManager,
    IPv4Packet,
    PacketAnalysis,
    TCPPacket,
    UDPPacket,
    extract_flow_feature_snapshot,
)
from capture.packet_observation import CaptureSource, PacketObservation
from detection import (
    FlowVolumeMetric,
    FlowVolumeThresholdComparison,
    FlowVolumeThresholdConfiguration,
    FlowVolumeThresholdDecision,
    FlowVolumeThresholdError,
    FlowVolumeThresholdEvaluation,
    FlowVolumeThresholdEvidence,
    FlowVolumeThresholdInterpretation,
    evaluate_flow_volume_threshold,
)


TIMESTAMP = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
SOURCE_ADDRESS = b"\x0a\x00\x00\x01"
DESTINATION_ADDRESS = b"\x0a\x00\x00\x02"


def packet(
    protocol: int,
    seconds: float,
    *,
    reverse: bool = False,
    captured_length: int = 60,
    original_length: int = 100,
) -> PacketAnalysis:
    source_address = DESTINATION_ADDRESS if reverse else SOURCE_ADDRESS
    destination_address = SOURCE_ADDRESS if reverse else DESTINATION_ADDRESS
    source_port = 443 if reverse else 12345
    destination_port = 12345 if reverse else 443
    observation = PacketObservation(
        captured_at=TIMESTAMP + timedelta(seconds=seconds),
        link_type=None,
        captured_length=captured_length,
        original_length=original_length,
        raw_bytes=bytes(captured_length),
        source=CaptureSource("flow-volume-threshold-test"),
    )
    ipv4 = IPv4Packet(
        version=4,
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=40 if protocol == 6 else 28,
        identification=0,
        flags=0,
        fragment_offset=0,
        ttl=64,
        protocol=protocol,
        header_checksum=0,
        source_address=source_address,
        destination_address=destination_address,
        options=b"",
        payload=bytes(20 if protocol == 6 else 8),
    )
    if protocol == 6:
        return PacketAnalysis(
            observation,
            ipv4=ipv4,
            tcp=TCPPacket(
                source_port=source_port,
                destination_port=destination_port,
                sequence_number=0,
                acknowledgment_number=0,
                data_offset=5,
                reserved_bits=0,
                ns=False,
                cwr=False,
                ece=False,
                urg=False,
                ack=False,
                psh=False,
                rst=False,
                syn=False,
                fin=False,
                window_size=0,
                checksum=0,
                urgent_pointer=0,
                options=b"",
                payload=b"",
            ),
        )
    return PacketAnalysis(
        observation,
        ipv4=ipv4,
        udp=UDPPacket(source_port, destination_port, 8, 0, b""),
    )


def snapshot(
    protocol: int = 17,
    *,
    close_reason: FlowObservationWindowClosureReason = (
        FlowObservationWindowClosureReason.CAPTURE_SESSION_END
    ),
    packets: tuple[PacketAnalysis, ...] = (),
    capture_session_id: str = "detector-session",
) -> FlowFeatureSnapshot:
    observations = packets or (
        packet(protocol, 0, captured_length=60, original_length=100),
        packet(protocol, 2, reverse=True, captured_length=80, original_length=120),
        packet(protocol, 4, captured_length=100, original_length=140),
    )
    manager = FlowObservationWindowManager(capture_session_id, timedelta(seconds=5), max_active_windows=1)
    active = None
    for observation in observations:
        active = manager.record(observation).active_window
    if active is None:
        raise ValueError("packets must not be empty")
    if close_reason is FlowObservationWindowClosureReason.CAPTURE_SESSION_END:
        window = manager.end_capture_session()[0]
    elif close_reason is FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION:
        window = manager.close(active.identity)
    else:
        boundary = packet(
            (6 if protocol == 17 else 17) if close_reason is FlowObservationWindowClosureReason.CAPACITY else protocol,
            (observations[-1].observation.captured_at - TIMESTAMP).total_seconds() + 5,
        )
        window = manager.record(boundary).closed_windows[0]
    return extract_flow_feature_snapshot(window)


def configuration(
    metric: FlowVolumeMetric,
    threshold=None,
) -> FlowVolumeThresholdConfiguration:
    if threshold is None:
        threshold = 0.0 if metric in (
            FlowVolumeMetric.PACKETS_PER_SECOND,
            FlowVolumeMetric.CAPTURED_BYTES_PER_SECOND,
            FlowVolumeMetric.ORIGINAL_BYTES_PER_SECOND,
        ) else 0
    return FlowVolumeThresholdConfiguration(
        "flow-volume-threshold",
        "1.0.0",
        metric,
        threshold,
    )


class FlowVolumeThresholdTests(unittest.TestCase):
    def test_public_models_have_exact_frozen_field_contracts(self) -> None:
        self.assertEqual(
            tuple(field.name for field in fields(FlowVolumeThresholdConfiguration)),
            ("detector_id", "detector_version", "metric", "threshold"),
        )
        self.assertEqual(
            tuple(field.name for field in fields(FlowVolumeThresholdEvidence)),
            ("snapshot", "configuration", "observed_value", "comparison_operator"),
        )
        self.assertEqual(
            tuple(field.name for field in fields(FlowVolumeThresholdEvaluation)),
            ("decision", "raw_evidence", "security_interpretation"),
        )
        result = evaluate_flow_volume_threshold(
            snapshot(), configuration(FlowVolumeMetric.PACKET_COUNT)
        )
        with self.assertRaises(FrozenInstanceError):
            result.decision = FlowVolumeThresholdDecision.NO_MATCH
        with self.assertRaises(FrozenInstanceError):
            result.raw_evidence.observed_value = 0
        with self.assertRaises(FrozenInstanceError):
            result.raw_evidence.configuration.threshold = 1

    def test_metric_and_decision_enumerations_are_exact(self) -> None:
        self.assertEqual(
            tuple(metric.value for metric in FlowVolumeMetric),
            (
                "packet_count",
                "captured_bytes",
                "original_bytes",
                "forward_packet_count",
                "reverse_packet_count",
                "forward_captured_bytes",
                "reverse_captured_bytes",
                "forward_original_bytes",
                "reverse_original_bytes",
                "packets_per_second",
                "captured_bytes_per_second",
                "original_bytes_per_second",
            ),
        )
        self.assertEqual(
            tuple(FlowVolumeThresholdDecision),
            (
                FlowVolumeThresholdDecision.MATCH,
                FlowVolumeThresholdDecision.NO_MATCH,
                FlowVolumeThresholdDecision.NOT_EVALUABLE,
            ),
        )
        self.assertEqual(
            tuple(FlowVolumeThresholdComparison),
            (FlowVolumeThresholdComparison.GREATER_THAN,),
        )

    def test_configuration_requires_exact_nonblank_identity_and_version(self) -> None:
        for name in ("detector_id", "detector_version"):
            for value in (None, 1, True):
                values = {
                    "detector_id": "detector",
                    "detector_version": "1",
                    "metric": FlowVolumeMetric.PACKET_COUNT,
                    "threshold": 0,
                }
                values[name] = value
                with self.subTest(name=name, value=value):
                    with self.assertRaises(TypeError):
                        FlowVolumeThresholdConfiguration(**values)
            for value in ("", " ", "\t\n"):
                values = {
                    "detector_id": "detector",
                    "detector_version": "1",
                    "metric": FlowVolumeMetric.PACKET_COUNT,
                    "threshold": 0,
                }
                values[name] = value
                with self.subTest(name=name, value=value):
                    with self.assertRaises(FlowVolumeThresholdError):
                        FlowVolumeThresholdConfiguration(**values)

    def test_configuration_requires_exact_metric_and_threshold_types(self) -> None:
        with self.assertRaises(TypeError):
            FlowVolumeThresholdConfiguration("detector", "1", "packet_count", 0)
        for threshold in (True, 0.0, 1.0):
            with self.subTest(integer_threshold=threshold):
                with self.assertRaises(TypeError):
                    configuration(FlowVolumeMetric.PACKET_COUNT, threshold)
        with self.assertRaises(TypeError):
            FlowVolumeThresholdConfiguration(
                "detector", "1", FlowVolumeMetric.PACKET_COUNT, None
            )
        for threshold in (True, 0, 1):
            with self.subTest(rate_threshold=threshold):
                with self.assertRaises(TypeError):
                    configuration(FlowVolumeMetric.PACKETS_PER_SECOND, threshold)
        with self.assertRaises(TypeError):
            FlowVolumeThresholdConfiguration(
                "detector", "1", FlowVolumeMetric.PACKETS_PER_SECOND, None
            )

    def test_configuration_rejects_negative_and_nonfinite_thresholds(self) -> None:
        with self.assertRaises(FlowVolumeThresholdError):
            configuration(FlowVolumeMetric.PACKET_COUNT, -1)
        for threshold in (-0.1, nan, inf, -inf):
            with self.subTest(threshold=threshold):
                with self.assertRaises(FlowVolumeThresholdError):
                    configuration(FlowVolumeMetric.PACKETS_PER_SECOND, threshold)

    def test_exact_zero_thresholds_are_valid_and_match_positive_values(self) -> None:
        flow_snapshot = snapshot()
        for metric, threshold in (
            (FlowVolumeMetric.PACKET_COUNT, 0),
            (FlowVolumeMetric.CAPTURED_BYTES, 0),
            (FlowVolumeMetric.PACKETS_PER_SECOND, 0.0),
        ):
            with self.subTest(metric=metric):
                result = evaluate_flow_volume_threshold(
                    flow_snapshot, configuration(metric, threshold)
                )
                self.assertIs(result.decision, FlowVolumeThresholdDecision.MATCH)
                self.assertIs(type(result.raw_evidence.threshold), type(threshold))

    def test_all_integer_metrics_preserve_exact_values(self) -> None:
        flow_snapshot = snapshot()
        expected = {
            FlowVolumeMetric.PACKET_COUNT: 3,
            FlowVolumeMetric.CAPTURED_BYTES: 240,
            FlowVolumeMetric.ORIGINAL_BYTES: 360,
            FlowVolumeMetric.FORWARD_PACKET_COUNT: 2,
            FlowVolumeMetric.REVERSE_PACKET_COUNT: 1,
            FlowVolumeMetric.FORWARD_CAPTURED_BYTES: 160,
            FlowVolumeMetric.REVERSE_CAPTURED_BYTES: 80,
            FlowVolumeMetric.FORWARD_ORIGINAL_BYTES: 240,
            FlowVolumeMetric.REVERSE_ORIGINAL_BYTES: 120,
        }
        for metric, value in expected.items():
            with self.subTest(metric=metric):
                result = evaluate_flow_volume_threshold(
                    flow_snapshot, configuration(metric, value - 1)
                )
                self.assertIs(result.decision, FlowVolumeThresholdDecision.MATCH)
                self.assertEqual(result.raw_evidence.observed_value, value)
                self.assertIs(type(result.raw_evidence.observed_value), int)

    def test_all_rate_metrics_preserve_exact_values(self) -> None:
        flow_snapshot = snapshot()
        expected = {
            FlowVolumeMetric.PACKETS_PER_SECOND: 0.75,
            FlowVolumeMetric.CAPTURED_BYTES_PER_SECOND: 60.0,
            FlowVolumeMetric.ORIGINAL_BYTES_PER_SECOND: 90.0,
        }
        for metric, value in expected.items():
            with self.subTest(metric=metric):
                result = evaluate_flow_volume_threshold(
                    flow_snapshot, configuration(metric, value - 0.25)
                )
                self.assertIs(result.decision, FlowVolumeThresholdDecision.MATCH)
                self.assertEqual(result.raw_evidence.observed_value, value)
                self.assertIs(type(result.raw_evidence.observed_value), float)

    def test_threshold_comparison_is_strictly_greater_than(self) -> None:
        flow_snapshot = snapshot()
        for threshold, decision in (
            (2, FlowVolumeThresholdDecision.MATCH),
            (3, FlowVolumeThresholdDecision.NO_MATCH),
            (4, FlowVolumeThresholdDecision.NO_MATCH),
        ):
            with self.subTest(threshold=threshold):
                result = evaluate_flow_volume_threshold(
                    flow_snapshot,
                    configuration(FlowVolumeMetric.PACKET_COUNT, threshold),
                )
                self.assertIs(result.decision, decision)
                self.assertIs(
                    result.raw_evidence.comparison_operator,
                    FlowVolumeThresholdComparison.GREATER_THAN,
                )

    def test_zero_duration_rates_are_not_evaluable(self) -> None:
        flow_snapshot = snapshot(packets=(packet(17, 0),))
        self.assertIsNone(flow_snapshot.flow_rate_features)
        for metric in (
            FlowVolumeMetric.PACKETS_PER_SECOND,
            FlowVolumeMetric.CAPTURED_BYTES_PER_SECOND,
            FlowVolumeMetric.ORIGINAL_BYTES_PER_SECOND,
        ):
            with self.subTest(metric=metric):
                result = evaluate_flow_volume_threshold(
                    flow_snapshot, configuration(metric, 0.0)
                )
                self.assertIs(
                    result.decision, FlowVolumeThresholdDecision.NOT_EVALUABLE
                )
                self.assertIsNone(result.raw_evidence.observed_value)
                self.assertIs(
                    result.security_interpretation,
                    FlowVolumeThresholdInterpretation.METRIC_NOT_EVALUABLE,
                )

    def test_zero_duration_counts_and_bytes_remain_evaluable(self) -> None:
        flow_snapshot = snapshot(
            packets=(packet(17, 0, captured_length=60, original_length=100),)
        )
        for metric, value in (
            (FlowVolumeMetric.PACKET_COUNT, 1),
            (FlowVolumeMetric.CAPTURED_BYTES, 60),
            (FlowVolumeMetric.ORIGINAL_BYTES, 100),
        ):
            with self.subTest(metric=metric):
                result = evaluate_flow_volume_threshold(
                    flow_snapshot, configuration(metric, value)
                )
                self.assertIs(result.decision, FlowVolumeThresholdDecision.NO_MATCH)
                self.assertEqual(result.raw_evidence.observed_value, value)

    def test_tcp_and_udp_closed_snapshots_are_supported(self) -> None:
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                flow_snapshot = snapshot(protocol)
                result = evaluate_flow_volume_threshold(
                    flow_snapshot, configuration(FlowVolumeMetric.PACKET_COUNT, 2)
                )
                self.assertIs(result.decision, FlowVolumeThresholdDecision.MATCH)
                self.assertEqual(result.raw_evidence.protocol, protocol)
                self.assertIs(result.raw_evidence.identity, flow_snapshot.identity)

    def test_nonexact_snapshot_configuration_and_active_window_are_rejected(self) -> None:
        flow_snapshot = snapshot()

        class DerivedSnapshot(FlowFeatureSnapshot):
            pass

        class DerivedConfiguration(FlowVolumeThresholdConfiguration):
            pass

        derived_snapshot = object.__new__(DerivedSnapshot)
        for name, value in vars(flow_snapshot).items():
            object.__setattr__(derived_snapshot, name, value)
        derived_configuration = DerivedConfiguration(
            "detector", "1", FlowVolumeMetric.PACKET_COUNT, 0
        )
        for value in (None, object(), derived_snapshot):
            with self.subTest(snapshot=value):
                with self.assertRaises(TypeError):
                    evaluate_flow_volume_threshold(
                        value, configuration(FlowVolumeMetric.PACKET_COUNT)
                    )
        for value in (None, object(), derived_configuration):
            with self.subTest(configuration=value):
                with self.assertRaises(TypeError):
                    evaluate_flow_volume_threshold(flow_snapshot, value)
        manager = FlowObservationWindowManager("active", timedelta.max)
        active = manager.record(packet(17, 0)).active_window
        active_snapshot = extract_flow_feature_snapshot(active)
        with self.assertRaises(FlowVolumeThresholdError):
            evaluate_flow_volume_threshold(
                active_snapshot, configuration(FlowVolumeMetric.PACKET_COUNT)
            )

    def test_unsupported_protocol_is_rejected(self) -> None:
        flow_snapshot = snapshot()
        with patch.object(
            FlowFeatureSnapshot,
            "identity",
            new_callable=PropertyMock,
            return_value=SimpleNamespace(protocol=1),
        ):
            with self.assertRaises(FlowVolumeThresholdError):
                evaluate_flow_volume_threshold(
                    flow_snapshot, configuration(FlowVolumeMetric.PACKET_COUNT)
                )

    def test_raw_evidence_preserves_exact_window_provenance_and_context(self) -> None:
        flow_snapshot = snapshot(capture_session_id="capture-A")
        detector_configuration = configuration(FlowVolumeMetric.CAPTURED_BYTES, 200)
        result = evaluate_flow_volume_threshold(
            flow_snapshot, detector_configuration
        )
        evidence = result.raw_evidence
        window = flow_snapshot.observation_window
        self.assertIs(evidence.snapshot, flow_snapshot)
        self.assertIs(evidence.observation_window, window)
        self.assertIs(evidence.configuration, detector_configuration)
        self.assertEqual(evidence.capture_session_id, "capture-A")
        self.assertEqual(evidence.sequence_number, 0)
        self.assertIs(evidence.closure_reason, window.closure_reason)
        self.assertIs(evidence.identity, window.identity)
        self.assertIs(evidence.first_captured_at, window.first_captured_at)
        self.assertIs(evidence.last_captured_at, window.last_captured_at)
        self.assertIs(evidence.selected_metric, FlowVolumeMetric.CAPTURED_BYTES)
        self.assertEqual(evidence.observed_value, 240)
        self.assertEqual(evidence.threshold, 200)
        self.assertEqual(evidence.total_packet_count, 3)
        self.assertEqual(evidence.forward_packet_count, 2)
        self.assertEqual(evidence.reverse_packet_count, 1)
        self.assertEqual(evidence.captured_byte_total, 240)
        self.assertEqual(evidence.original_byte_total, 360)
        self.assertEqual(evidence.protocol, 17)

    def test_all_closure_reasons_are_preserved(self) -> None:
        for reason in FlowObservationWindowClosureReason:
            with self.subTest(reason=reason):
                flow_snapshot = snapshot(close_reason=reason)
                result = evaluate_flow_volume_threshold(
                    flow_snapshot, configuration(FlowVolumeMetric.PACKET_COUNT, 0)
                )
                self.assertIs(result.raw_evidence.closure_reason, reason)

    def test_security_interpretations_are_exact_and_separate_from_evidence(self) -> None:
        flow_snapshot = snapshot()
        cases = (
            (
                configuration(FlowVolumeMetric.PACKET_COUNT, 2),
                FlowVolumeThresholdDecision.MATCH,
                FlowVolumeThresholdInterpretation.THRESHOLD_EXCEEDED,
            ),
            (
                configuration(FlowVolumeMetric.PACKET_COUNT, 3),
                FlowVolumeThresholdDecision.NO_MATCH,
                FlowVolumeThresholdInterpretation.THRESHOLD_NOT_EXCEEDED,
            ),
        )
        for detector_configuration, decision, interpretation in cases:
            with self.subTest(decision=decision):
                result = evaluate_flow_volume_threshold(
                    flow_snapshot, detector_configuration
                )
                self.assertIs(result.decision, decision)
                self.assertIs(result.security_interpretation, interpretation)
                self.assertIs(type(result.raw_evidence), FlowVolumeThresholdEvidence)
                self.assertIs(type(result.security_interpretation), FlowVolumeThresholdInterpretation)
        zero_duration = snapshot(packets=(packet(17, 0),))
        result = evaluate_flow_volume_threshold(
            zero_duration, configuration(FlowVolumeMetric.PACKETS_PER_SECOND, 0.0)
        )
        self.assertIs(result.decision, FlowVolumeThresholdDecision.NOT_EVALUABLE)
        self.assertIs(
            result.security_interpretation,
            FlowVolumeThresholdInterpretation.METRIC_NOT_EVALUABLE,
        )

    def test_interpretations_make_no_attack_or_role_claims(self) -> None:
        forbidden = (
            "ddos",
            "dos",
            "flood",
            "scan",
            "brute",
            "exfiltration",
            "malware",
            "attacker",
            "malicious",
            "degradation",
            "exhaustion",
            "client",
            "server",
            "initiator",
            "responder",
            "victim",
        )
        for interpretation in FlowVolumeThresholdInterpretation:
            text = interpretation.value.lower()
            for term in forbidden:
                with self.subTest(interpretation=interpretation, term=term):
                    self.assertNotIn(term, text)

    def test_repeated_evaluation_is_deterministic_and_mutates_no_input(self) -> None:
        flow_snapshot = snapshot(6)
        detector_configuration = configuration(
            FlowVolumeMetric.ORIGINAL_BYTES_PER_SECOND, 80.0
        )
        window = flow_snapshot.observation_window
        state = flow_snapshot.coordinated_state
        before_snapshot = tuple(vars(flow_snapshot).items())
        before_window = replace(window)
        before_state = replace(state)
        before_configuration = replace(detector_configuration)
        first = evaluate_flow_volume_threshold(flow_snapshot, detector_configuration)
        second = evaluate_flow_volume_threshold(flow_snapshot, detector_configuration)
        self.assertEqual(first, second)
        self.assertIs(first.raw_evidence.snapshot, flow_snapshot)
        self.assertIs(second.raw_evidence.snapshot, flow_snapshot)
        self.assertEqual(tuple(vars(flow_snapshot).items()), before_snapshot)
        self.assertEqual(window, before_window)
        self.assertEqual(state, before_state)
        self.assertEqual(detector_configuration, before_configuration)

    def test_legitimate_high_volume_and_asymmetry_do_not_change_interpretation(self) -> None:
        flow_snapshot = snapshot(
            packets=(
                packet(17, 0, captured_length=1000, original_length=1000),
                packet(17, 1, captured_length=1000, original_length=1000),
            )
        )
        result = evaluate_flow_volume_threshold(
            flow_snapshot, configuration(FlowVolumeMetric.CAPTURED_BYTES, 1500)
        )
        self.assertIs(result.decision, FlowVolumeThresholdDecision.MATCH)
        self.assertIs(
            result.security_interpretation,
            FlowVolumeThresholdInterpretation.THRESHOLD_EXCEEDED,
        )
        self.assertEqual(result.raw_evidence.forward_packet_count, 2)
        self.assertEqual(result.raw_evidence.reverse_packet_count, 0)

    def test_short_window_high_rate_reports_only_the_raw_predicate(self) -> None:
        flow_snapshot = snapshot(
            packets=(
                packet(17, 0, captured_length=100, original_length=100),
                packet(17, 0.001, captured_length=100, original_length=100),
            )
        )
        result = evaluate_flow_volume_threshold(
            flow_snapshot,
            configuration(FlowVolumeMetric.CAPTURED_BYTES_PER_SECOND, 100000.0),
        )
        self.assertIs(result.decision, FlowVolumeThresholdDecision.MATCH)
        self.assertEqual(result.raw_evidence.observed_value, 200000.0)
        self.assertIs(
            result.security_interpretation,
            FlowVolumeThresholdInterpretation.THRESHOLD_EXCEEDED,
        )

    def test_capture_truncation_and_repeated_observations_preserve_raw_totals(self) -> None:
        repeated = packet(17, 0, captured_length=60, original_length=100)
        flow_snapshot = snapshot(
            packets=(repeated, replace(repeated, observation=replace(
                repeated.observation,
                captured_at=TIMESTAMP + timedelta(seconds=1),
            ))),
        )
        result = evaluate_flow_volume_threshold(
            flow_snapshot, configuration(FlowVolumeMetric.ORIGINAL_BYTES, 150)
        )
        self.assertIs(result.decision, FlowVolumeThresholdDecision.MATCH)
        self.assertEqual(result.raw_evidence.total_packet_count, 2)
        self.assertEqual(result.raw_evidence.captured_byte_total, 120)
        self.assertEqual(result.raw_evidence.original_byte_total, 200)
        self.assertIs(
            result.security_interpretation,
            FlowVolumeThresholdInterpretation.THRESHOLD_EXCEEDED,
        )

    def test_evaluation_retains_no_history_cross_flow_state_or_io_behavior(self) -> None:
        first_snapshot = snapshot(capture_session_id="first")
        second_snapshot = snapshot(6, capture_session_id="second")
        detector_configuration = configuration(FlowVolumeMetric.PACKET_COUNT, 2)
        with patch("builtins.open", wraps=builtin_open) as open_call, patch(
            "socket.socket"
        ) as socket_call:
            first = evaluate_flow_volume_threshold(
                first_snapshot, detector_configuration
            )
            second = evaluate_flow_volume_threshold(
                second_snapshot, detector_configuration
            )
        open_call.assert_not_called()
        socket_call.assert_not_called()
        self.assertIs(first.raw_evidence.snapshot, first_snapshot)
        self.assertIs(second.raw_evidence.snapshot, second_snapshot)
        self.assertNotEqual(first.raw_evidence.identity, second.raw_evidence.identity)
        for result in (first, second):
            for value in vars(result).values():
                self.assertNotIsInstance(value, (list, dict, set))
            for value in vars(result.raw_evidence).values():
                self.assertNotIsInstance(value, (list, dict, set))

    def test_result_models_reject_inconsistent_direct_construction(self) -> None:
        flow_snapshot = snapshot()
        detector_configuration = configuration(FlowVolumeMetric.PACKET_COUNT, 2)
        evidence = FlowVolumeThresholdEvidence(
            flow_snapshot,
            detector_configuration,
            3,
            FlowVolumeThresholdComparison.GREATER_THAN,
        )
        with self.assertRaises(FlowVolumeThresholdError):
            FlowVolumeThresholdEvidence(
                flow_snapshot,
                detector_configuration,
                2,
                FlowVolumeThresholdComparison.GREATER_THAN,
            )
        with self.assertRaises(FlowVolumeThresholdError):
            FlowVolumeThresholdEvaluation(
                FlowVolumeThresholdDecision.NO_MATCH,
                evidence,
                FlowVolumeThresholdInterpretation.THRESHOLD_NOT_EXCEEDED,
            )
        with self.assertRaises(FlowVolumeThresholdError):
            FlowVolumeThresholdEvaluation(
                FlowVolumeThresholdDecision.MATCH,
                evidence,
                FlowVolumeThresholdInterpretation.THRESHOLD_NOT_EXCEEDED,
            )


if __name__ == "__main__":
    unittest.main()
