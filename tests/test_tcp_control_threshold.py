import unittest
from builtins import open as builtin_open
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

from analysis import (
    FlowObservationWindow,
    FlowObservationWindowClosureReason,
    FlowObservationWindowManager,
    IPv4Packet,
    PacketAnalysis,
    TCPPacket,
    UDPPacket,
)
from capture.packet_observation import CaptureSource, PacketObservation
from detection import (
    TCPControlMetric,
    TCPControlThresholdComparison,
    TCPControlThresholdConfiguration,
    TCPControlThresholdDecision,
    TCPControlThresholdError,
    TCPControlThresholdEvaluation,
    TCPControlThresholdEvidence,
    TCPControlThresholdInterpretation,
    evaluate_tcp_control_threshold,
)


TIMESTAMP = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
SOURCE_ADDRESS = b"\x0a\x00\x00\x01"
DESTINATION_ADDRESS = b"\x0a\x00\x00\x02"
FLAG_NAMES = ("ns", "cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin")


def tcp_packet(seconds: float, *, reverse: bool = False, **flags) -> PacketAnalysis:
    source_address = DESTINATION_ADDRESS if reverse else SOURCE_ADDRESS
    destination_address = SOURCE_ADDRESS if reverse else DESTINATION_ADDRESS
    source_port = 443 if reverse else 12345
    destination_port = 12345 if reverse else 443
    observation = PacketObservation(
        captured_at=TIMESTAMP + timedelta(seconds=seconds),
        link_type=None,
        captured_length=60,
        original_length=100,
        raw_bytes=bytes(60),
        source=CaptureSource("tcp-control-threshold-test"),
    )
    ipv4 = IPv4Packet(
        version=4,
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=40,
        identification=0,
        flags=0,
        fragment_offset=0,
        ttl=64,
        protocol=6,
        header_checksum=0,
        source_address=source_address,
        destination_address=destination_address,
        options=b"",
        payload=bytes(20),
    )
    values = {name: False for name in FLAG_NAMES}
    values.update(flags)
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
            window_size=0,
            checksum=0,
            urgent_pointer=0,
            options=b"",
            payload=b"",
            **values,
        ),
    )


def udp_packet(seconds: float) -> PacketAnalysis:
    observation = PacketObservation(
        captured_at=TIMESTAMP + timedelta(seconds=seconds),
        link_type=None,
        captured_length=60,
        original_length=100,
        raw_bytes=bytes(60),
        source=CaptureSource("tcp-control-threshold-test"),
    )
    ipv4 = IPv4Packet(
        version=4,
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=28,
        identification=0,
        flags=0,
        fragment_offset=0,
        ttl=64,
        protocol=17,
        header_checksum=0,
        source_address=SOURCE_ADDRESS,
        destination_address=DESTINATION_ADDRESS,
        options=b"",
        payload=bytes(8),
    )
    return PacketAnalysis(
        observation,
        ipv4=ipv4,
        udp=UDPPacket(12345, 443, 8, 0, b""),
    )


def closed_window(
    *packets: PacketAnalysis,
    closure_reason: FlowObservationWindowClosureReason = (
        FlowObservationWindowClosureReason.CAPTURE_SESSION_END
    ),
    capture_session_id: str = "tcp-control-detector-session",
) -> FlowObservationWindow:
    manager = FlowObservationWindowManager(capture_session_id, timedelta(seconds=5))
    active = None
    for packet in packets:
        active = manager.record(packet).active_window
    if active is None:
        raise ValueError("at least one packet is required")
    if closure_reason is FlowObservationWindowClosureReason.CAPTURE_SESSION_END:
        return manager.end_capture_session()[0]
    if closure_reason is FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION:
        return manager.close(active.identity)
    seconds = (packets[-1].observation.captured_at - TIMESTAMP).total_seconds() + 5
    return manager.record(tcp_packet(seconds)).closed_windows[0]


def configuration(
    metric: TCPControlMetric = TCPControlMetric.FORWARD_SYN,
    threshold: int = 0,
) -> TCPControlThresholdConfiguration:
    return TCPControlThresholdConfiguration(
        "tcp-control-threshold",
        "1.0.0",
        metric,
        threshold,
    )


class TCPControlThresholdTests(unittest.TestCase):
    def test_public_models_have_exact_frozen_field_contracts(self) -> None:
        self.assertEqual(
            tuple(field.name for field in fields(TCPControlThresholdConfiguration)),
            ("detector_id", "detector_version", "metric", "threshold"),
        )
        self.assertEqual(
            tuple(field.name for field in fields(TCPControlThresholdEvidence)),
            (
                "observation_window",
                "configuration",
                "observed_value",
                "comparison_operator",
            ),
        )
        self.assertEqual(
            tuple(field.name for field in fields(TCPControlThresholdEvaluation)),
            ("decision", "raw_evidence", "security_interpretation"),
        )
        result = evaluate_tcp_control_threshold(
            closed_window(tcp_packet(0, syn=True)), configuration()
        )
        with self.assertRaises(FrozenInstanceError):
            result.decision = TCPControlThresholdDecision.NO_MATCH
        with self.assertRaises(FrozenInstanceError):
            result.raw_evidence.observed_value = 0
        with self.assertRaises(FrozenInstanceError):
            result.raw_evidence.configuration.threshold = 1

    def test_metric_decision_and_comparison_enumerations_are_exact(self) -> None:
        self.assertEqual(
            tuple(metric.name for metric in TCPControlMetric),
            (
                "FORWARD_NS",
                "FORWARD_CWR",
                "FORWARD_ECE",
                "FORWARD_URG",
                "FORWARD_ACK",
                "FORWARD_PSH",
                "FORWARD_RST",
                "FORWARD_SYN",
                "FORWARD_FIN",
                "FORWARD_SYN_ACK",
                "REVERSE_NS",
                "REVERSE_CWR",
                "REVERSE_ECE",
                "REVERSE_URG",
                "REVERSE_ACK",
                "REVERSE_PSH",
                "REVERSE_RST",
                "REVERSE_SYN",
                "REVERSE_FIN",
                "REVERSE_SYN_ACK",
            ),
        )
        self.assertEqual(
            tuple(TCPControlThresholdDecision),
            (
                TCPControlThresholdDecision.MATCH,
                TCPControlThresholdDecision.NO_MATCH,
                TCPControlThresholdDecision.NOT_EVALUABLE,
            ),
        )
        self.assertEqual(
            tuple(TCPControlThresholdComparison),
            (TCPControlThresholdComparison.GREATER_THAN,),
        )

    def test_configuration_requires_exact_nonblank_identity_and_version(self) -> None:
        class DerivedString(str):
            pass

        for name in ("detector_id", "detector_version"):
            for value in (None, True, 1, DerivedString("detector")):
                values = {
                    "detector_id": "detector",
                    "detector_version": "1",
                    "metric": TCPControlMetric.FORWARD_SYN,
                    "threshold": 0,
                }
                values[name] = value
                with self.subTest(name=name, value=value):
                    with self.assertRaises(TypeError):
                        TCPControlThresholdConfiguration(**values)
            for value in ("", " ", "\t\n"):
                values = {
                    "detector_id": "detector",
                    "detector_version": "1",
                    "metric": TCPControlMetric.FORWARD_SYN,
                    "threshold": 0,
                }
                values[name] = value
                with self.subTest(name=name, value=value):
                    with self.assertRaises(TCPControlThresholdError):
                        TCPControlThresholdConfiguration(**values)

    def test_configuration_requires_exact_metric_and_threshold_types(self) -> None:
        class DerivedInteger(int):
            pass

        with self.assertRaises(TypeError):
            TCPControlThresholdConfiguration("detector", "1", "forward_syn", 0)
        for threshold in (True, 0.0, "0", None, DerivedInteger(0)):
            with self.subTest(threshold=threshold):
                with self.assertRaises(TypeError):
                    TCPControlThresholdConfiguration(
                        "detector", "1", TCPControlMetric.FORWARD_SYN, threshold
                    )
        with self.assertRaises(TCPControlThresholdError):
            configuration(threshold=-1)

    def test_zero_threshold_and_strict_greater_than_semantics(self) -> None:
        with_syn = closed_window(tcp_packet(0, syn=True))
        without_syn = closed_window(tcp_packet(0))
        self.assertIs(
            evaluate_tcp_control_threshold(with_syn, configuration()).decision,
            TCPControlThresholdDecision.MATCH,
        )
        self.assertIs(
            evaluate_tcp_control_threshold(without_syn, configuration()).decision,
            TCPControlThresholdDecision.NO_MATCH,
        )
        two_syn = closed_window(tcp_packet(0, syn=True), tcp_packet(1, syn=True))
        for threshold, decision in (
            (1, TCPControlThresholdDecision.MATCH),
            (2, TCPControlThresholdDecision.NO_MATCH),
            (3, TCPControlThresholdDecision.NO_MATCH),
        ):
            with self.subTest(threshold=threshold):
                result = evaluate_tcp_control_threshold(
                    two_syn, configuration(threshold=threshold)
                )
                self.assertIs(result.decision, decision)
                self.assertIs(
                    result.raw_evidence.comparison_operator,
                    TCPControlThresholdComparison.GREATER_THAN,
                )

    def test_every_directional_tcp_control_counter_is_selectable(self) -> None:
        all_flags = {name: True for name in FLAG_NAMES}
        window = closed_window(
            tcp_packet(0, **all_flags),
            tcp_packet(1, reverse=True, **all_flags),
        )
        statistics = window.coordinated_state.tcp_control_statistics
        self.assertIsNotNone(statistics)
        for metric in TCPControlMetric:
            with self.subTest(metric=metric):
                result = evaluate_tcp_control_threshold(
                    window, configuration(metric)
                )
                self.assertIs(result.decision, TCPControlThresholdDecision.MATCH)
                self.assertEqual(result.raw_evidence.observed_value, 1)
                self.assertEqual(
                    result.raw_evidence.observed_value,
                    getattr(statistics, metric.value),
                )

    def test_forward_and_reverse_selection_remain_independent(self) -> None:
        window = closed_window(
            tcp_packet(0, syn=True),
            tcp_packet(1, reverse=True, ack=True),
        )
        expected = {
            TCPControlMetric.FORWARD_SYN: TCPControlThresholdDecision.MATCH,
            TCPControlMetric.REVERSE_SYN: TCPControlThresholdDecision.NO_MATCH,
            TCPControlMetric.FORWARD_ACK: TCPControlThresholdDecision.NO_MATCH,
            TCPControlMetric.REVERSE_ACK: TCPControlThresholdDecision.MATCH,
        }
        for metric, decision in expected.items():
            with self.subTest(metric=metric):
                result = evaluate_tcp_control_threshold(
                    window, configuration(metric)
                )
                self.assertIs(result.decision, decision)

    def test_syn_ack_is_an_independent_joint_observation(self) -> None:
        separate = closed_window(
            tcp_packet(0, syn=True),
            tcp_packet(1, ack=True),
        )
        joint = closed_window(tcp_packet(0, syn=True, ack=True))
        separate_statistics = separate.coordinated_state.tcp_control_statistics
        joint_statistics = joint.coordinated_state.tcp_control_statistics
        self.assertEqual(separate_statistics.forward_syn_count, 1)
        self.assertEqual(separate_statistics.forward_ack_count, 1)
        self.assertEqual(separate_statistics.forward_syn_ack_count, 0)
        self.assertEqual(joint_statistics.forward_syn_count, 1)
        self.assertEqual(joint_statistics.forward_ack_count, 1)
        self.assertEqual(joint_statistics.forward_syn_ack_count, 1)
        self.assertIs(
            evaluate_tcp_control_threshold(
                separate, configuration(TCPControlMetric.FORWARD_SYN_ACK)
            ).decision,
            TCPControlThresholdDecision.NO_MATCH,
        )
        self.assertIs(
            evaluate_tcp_control_threshold(
                joint, configuration(TCPControlMetric.FORWARD_SYN_ACK)
            ).decision,
            TCPControlThresholdDecision.MATCH,
        )

    def test_tcp_is_supported_and_udp_is_rejected(self) -> None:
        tcp_window = closed_window(tcp_packet(0, syn=True))
        result = evaluate_tcp_control_threshold(tcp_window, configuration())
        self.assertIs(result.decision, TCPControlThresholdDecision.MATCH)
        self.assertEqual(result.raw_evidence.protocol, 6)
        udp_window = closed_window(udp_packet(0))
        self.assertIsNone(udp_window.coordinated_state.tcp_control_statistics)
        with self.assertRaises(TCPControlThresholdError):
            evaluate_tcp_control_threshold(udp_window, configuration())

    def test_icmp_protocol_is_rejected(self) -> None:
        window = closed_window(tcp_packet(0, syn=True))
        with patch.object(
            FlowObservationWindow,
            "identity",
            new_callable=PropertyMock,
            return_value=SimpleNamespace(protocol=1),
        ):
            with self.assertRaises(TCPControlThresholdError):
                evaluate_tcp_control_threshold(window, configuration())

    def test_nonexact_window_configuration_and_active_window_are_rejected(self) -> None:
        window = closed_window(tcp_packet(0, syn=True))

        class DerivedWindow(FlowObservationWindow):
            pass

        class DerivedConfiguration(TCPControlThresholdConfiguration):
            pass

        derived_window = DerivedWindow(
            window.key, window.coordinated_state, window.closure_reason
        )
        derived_configuration = DerivedConfiguration(
            "detector", "1", TCPControlMetric.FORWARD_SYN, 0
        )
        for value in (None, object(), derived_window):
            with self.subTest(window=value):
                with self.assertRaises(TypeError):
                    evaluate_tcp_control_threshold(value, configuration())
        for value in (None, object(), derived_configuration):
            with self.subTest(configuration=value):
                with self.assertRaises(TypeError):
                    evaluate_tcp_control_threshold(window, value)
        manager = FlowObservationWindowManager("active", timedelta.max)
        active = manager.record(tcp_packet(0, syn=True)).active_window
        with self.assertRaises(TCPControlThresholdError):
            evaluate_tcp_control_threshold(active, configuration())

    def test_all_closure_reasons_are_supported_and_preserved(self) -> None:
        for reason in FlowObservationWindowClosureReason:
            with self.subTest(reason=reason):
                window = closed_window(
                    tcp_packet(0, syn=True), closure_reason=reason
                )
                result = evaluate_tcp_control_threshold(window, configuration())
                self.assertIs(result.decision, TCPControlThresholdDecision.MATCH)
                self.assertIs(result.raw_evidence.closure_reason, reason)

    def test_raw_evidence_preserves_exact_provenance_and_tcp_context(self) -> None:
        window = closed_window(
            tcp_packet(0, syn=True),
            tcp_packet(2, reverse=True, ack=True),
            capture_session_id="capture-C",
        )
        detector_configuration = configuration(TCPControlMetric.REVERSE_ACK, 0)
        result = evaluate_tcp_control_threshold(window, detector_configuration)
        evidence = result.raw_evidence
        statistics = window.coordinated_state.tcp_control_statistics
        self.assertIs(evidence.observation_window, window)
        self.assertIs(evidence.tcp_control_statistics, statistics)
        self.assertIs(evidence.configuration, detector_configuration)
        self.assertEqual(evidence.capture_session_id, "capture-C")
        self.assertEqual(evidence.sequence_number, 0)
        self.assertIs(evidence.closure_reason, window.closure_reason)
        self.assertIs(evidence.identity, window.identity)
        self.assertIs(evidence.first_captured_at, window.first_captured_at)
        self.assertIs(evidence.last_captured_at, window.last_captured_at)
        self.assertIs(evidence.selected_metric, TCPControlMetric.REVERSE_ACK)
        self.assertEqual(evidence.observed_value, 1)
        self.assertEqual(evidence.threshold, 0)
        self.assertEqual(evidence.protocol, 6)
        self.assertEqual(evidence.total_packet_count, 2)
        self.assertEqual(evidence.forward_packet_count, 1)
        self.assertEqual(evidence.reverse_packet_count, 1)

    def test_interpretations_are_exact_and_separate_from_raw_evidence(self) -> None:
        window = closed_window(tcp_packet(0, syn=True))
        cases = (
            (
                configuration(TCPControlMetric.FORWARD_SYN, 0),
                TCPControlThresholdDecision.MATCH,
                TCPControlThresholdInterpretation.THRESHOLD_EXCEEDED,
            ),
            (
                configuration(TCPControlMetric.FORWARD_SYN, 1),
                TCPControlThresholdDecision.NO_MATCH,
                TCPControlThresholdInterpretation.THRESHOLD_NOT_EXCEEDED,
            ),
        )
        for detector_configuration, decision, interpretation in cases:
            with self.subTest(decision=decision):
                result = evaluate_tcp_control_threshold(
                    window, detector_configuration
                )
                self.assertIs(result.decision, decision)
                self.assertIs(result.security_interpretation, interpretation)
                self.assertIs(type(result.raw_evidence), TCPControlThresholdEvidence)
                self.assertIs(
                    type(result.security_interpretation),
                    TCPControlThresholdInterpretation,
                )

    def test_interpretations_make_no_attack_state_or_role_claims(self) -> None:
        forbidden = (
            "syn flood",
            "flood",
            "dos",
            "scan",
            "attack",
            "attacker",
            "malicious",
            "brute",
            "handshake",
            "connection",
            "retransmission",
            "client",
            "server",
            "initiator",
            "responder",
            "victim",
        )
        for interpretation in TCPControlThresholdInterpretation:
            text = interpretation.value.lower()
            for term in forbidden:
                with self.subTest(interpretation=interpretation, term=term):
                    self.assertNotIn(term, text)

    def test_syn_rst_and_syn_ack_matches_remain_counter_predicates(self) -> None:
        cases = (
            (TCPControlMetric.FORWARD_SYN, tcp_packet(0, syn=True)),
            (TCPControlMetric.FORWARD_RST, tcp_packet(0, rst=True)),
            (TCPControlMetric.FORWARD_SYN_ACK, tcp_packet(0, syn=True, ack=True)),
        )
        for metric, packet in cases:
            with self.subTest(metric=metric):
                result = evaluate_tcp_control_threshold(
                    closed_window(packet), configuration(metric)
                )
                self.assertIs(result.decision, TCPControlThresholdDecision.MATCH)
                self.assertIs(
                    result.security_interpretation,
                    TCPControlThresholdInterpretation.THRESHOLD_EXCEEDED,
                )
                self.assertIs(result.raw_evidence.selected_metric, metric)

    def test_tcp_flags_do_not_control_window_lifecycle(self) -> None:
        manager = FlowObservationWindowManager("flags", timedelta.max)
        windows = tuple(
            manager.record(packet).active_window
            for packet in (
                tcp_packet(0, syn=True),
                tcp_packet(1, fin=True),
                tcp_packet(2, rst=True),
                tcp_packet(3, syn=True, ack=True),
            )
        )
        self.assertEqual(tuple(window.key for window in windows), (windows[0].key,) * 4)
        self.assertTrue(all(window.closure_reason is None for window in windows))
        closed = manager.end_capture_session()[0]
        result = evaluate_tcp_control_threshold(
            closed, configuration(TCPControlMetric.FORWARD_FIN)
        )
        self.assertIs(result.decision, TCPControlThresholdDecision.MATCH)

    def test_equal_aggregate_counters_ignore_packet_order(self) -> None:
        first = closed_window(
            tcp_packet(0, syn=True),
            tcp_packet(1, reverse=True, ack=True),
            tcp_packet(2, rst=True),
            capture_session_id="first-order",
        )
        second = closed_window(
            tcp_packet(0, rst=True),
            tcp_packet(1, reverse=True, ack=True),
            tcp_packet(2, syn=True),
            capture_session_id="second-order",
        )
        self.assertEqual(
            first.coordinated_state.tcp_control_statistics,
            second.coordinated_state.tcp_control_statistics,
        )
        first_result = evaluate_tcp_control_threshold(first, configuration())
        second_result = evaluate_tcp_control_threshold(second, configuration())
        self.assertIs(first_result.decision, second_result.decision)
        self.assertEqual(
            first_result.raw_evidence.observed_value,
            second_result.raw_evidence.observed_value,
        )
        self.assertIs(
            first_result.security_interpretation,
            second_result.security_interpretation,
        )

    def test_repeated_evaluation_is_deterministic_and_mutates_no_input(self) -> None:
        window = closed_window(
            tcp_packet(0, syn=True), tcp_packet(1, reverse=True, ack=True)
        )
        state = window.coordinated_state
        statistics = state.tcp_control_statistics
        detector_configuration = configuration(TCPControlMetric.REVERSE_ACK)
        before_window = replace(window)
        before_state = replace(state)
        before_statistics = replace(statistics)
        before_configuration = replace(detector_configuration)
        first = evaluate_tcp_control_threshold(window, detector_configuration)
        second = evaluate_tcp_control_threshold(window, detector_configuration)
        self.assertEqual(first, second)
        self.assertIs(first.raw_evidence.observation_window, window)
        self.assertIs(first.raw_evidence.tcp_control_statistics, statistics)
        self.assertEqual(window, before_window)
        self.assertEqual(state, before_state)
        self.assertEqual(statistics, before_statistics)
        self.assertEqual(detector_configuration, before_configuration)

    def test_evaluation_retains_no_history_cross_flow_state_or_io_behavior(self) -> None:
        first_window = closed_window(
            tcp_packet(0, syn=True), capture_session_id="first"
        )
        second_window = closed_window(
            tcp_packet(0, rst=True), capture_session_id="second"
        )
        detector_configuration = configuration(TCPControlMetric.FORWARD_SYN)
        with patch("builtins.open", wraps=builtin_open) as open_call, patch(
            "socket.socket"
        ) as socket_call:
            first = evaluate_tcp_control_threshold(
                first_window, detector_configuration
            )
            second = evaluate_tcp_control_threshold(
                second_window, detector_configuration
            )
        open_call.assert_not_called()
        socket_call.assert_not_called()
        self.assertIs(first.decision, TCPControlThresholdDecision.MATCH)
        self.assertIs(second.decision, TCPControlThresholdDecision.NO_MATCH)
        self.assertIs(first.raw_evidence.observation_window, first_window)
        self.assertIs(second.raw_evidence.observation_window, second_window)
        for result in (first, second):
            for value in vars(result).values():
                self.assertNotIsInstance(value, (list, dict, set))
            for value in vars(result.raw_evidence).values():
                self.assertNotIsInstance(value, (list, dict, set))

    def test_result_models_reject_inconsistent_direct_construction(self) -> None:
        window = closed_window(tcp_packet(0, syn=True))
        detector_configuration = configuration()
        evidence = TCPControlThresholdEvidence(
            window,
            detector_configuration,
            1,
            TCPControlThresholdComparison.GREATER_THAN,
        )
        with self.assertRaises(TCPControlThresholdError):
            TCPControlThresholdEvidence(
                window,
                detector_configuration,
                0,
                TCPControlThresholdComparison.GREATER_THAN,
            )
        with self.assertRaises(TCPControlThresholdError):
            TCPControlThresholdEvaluation(
                TCPControlThresholdDecision.NO_MATCH,
                evidence,
                TCPControlThresholdInterpretation.THRESHOLD_NOT_EXCEEDED,
            )
        with self.assertRaises(TCPControlThresholdError):
            TCPControlThresholdEvaluation(
                TCPControlThresholdDecision.MATCH,
                evidence,
                TCPControlThresholdInterpretation.THRESHOLD_NOT_EXCEEDED,
            )
        with self.assertRaises(TCPControlThresholdError):
            TCPControlThresholdEvaluation(
                TCPControlThresholdDecision.NOT_EVALUABLE,
                evidence,
                TCPControlThresholdInterpretation.THRESHOLD_EXCEEDED,
            )


if __name__ == "__main__":
    unittest.main()
