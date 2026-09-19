import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta, timezone
from unittest.mock import PropertyMock, patch

import application
from analysis import PacketAnalysisOutcome, PacketAnalysisFailureClassification, analyze_packet_outcome, extract_flow_feature_snapshot
from application import (
    DetectionClassification as C,
    DetectionEvaluationEntry,
    DetectionEvaluationResult,
    DetectionPipelineResult,
    ExpectedDetection,
    ExpectedDetectionResult,
    FlowDetectionIdentity,
    PacketDetectionIdentity,
    detection_identity,
    evaluate_detection_result,
)
from capture import CaptureSource, LinkType
from detection import (
    DetectionFinding,
    FlowVolumeMetric,
    FlowVolumeThresholdConfiguration,
    FlowVolumeThresholdDecision,
    FlowVolumeThresholdInterpretation,
    PacketIntegrityConfiguration,
    PacketIntegrityDecision,
    TCPControlMetric,
    detection_finding_from_evaluation,
    evaluate_flow_volume_threshold,
    evaluate_packet_integrity,
    evaluate_tcp_control_threshold,
)
from tests.test_detection_finding import flow_volume_evaluation
from tests.test_flow_volume_threshold import packet, snapshot
from tests.test_ipv6_detection import closed_snapshot
from tests.test_ipv6_flow import packet_at
from tests.test_packet_integrity import make_observation, TCP_BYTES
from tests.test_tcp_control_threshold import closed_window, configuration as control_configuration, tcp_packet


def packet_finding(decision=PacketIntegrityDecision.MATCH, *, configuration=None, **metadata):
    observation = replace(make_observation(6, TCP_BYTES), **metadata)
    if decision is PacketIntegrityDecision.NO_MATCH:
        outcome = analyze_packet_outcome(observation)
    else:
        classification = PacketAnalysisFailureClassification.STRUCTURAL_FAILURE if decision is PacketIntegrityDecision.MATCH else PacketAnalysisFailureClassification.INCOMPLETE
        outcome = PacketAnalysisOutcome(observation, None, classification, "explicit fixture outcome")
    return detection_finding_from_evaluation(evaluate_packet_integrity(
        outcome, configuration or PacketIntegrityConfiguration("packet-integrity", "1")))


def flow_finding(*, positive=True, protocol=17, ipv6=False, configuration=None, **snapshot_options):
    packets = tuple(packet_at(protocol) if ipv6 else packet(protocol, 0) for _ in range(2 if positive else 1))
    state = closed_snapshot(*packets) if ipv6 else snapshot(packets=packets, **snapshot_options)
    config = configuration or FlowVolumeThresholdConfiguration("volume", "1", FlowVolumeMetric.PACKET_COUNT, 1)
    return detection_finding_from_evaluation(evaluate_flow_volume_threshold(state, config))


def expected(finding, positive=True, index=None):
    return ExpectedDetection(detection_identity(finding, packet_index=index), positive)


def evaluate(packets=(), flows=(), packet_expectations=(), flow_expectations=()):
    return evaluate_detection_result(DetectionPipelineResult(packets, flows),
                                     ExpectedDetectionResult(packet_expectations, flow_expectations))


class UnhashableAddress(bytes):
    __hash__ = None


class UnindexableAddress(bytes):
    def __hash__(self):
        raise AssertionError("address must not be hashed by evaluation")


class AlternateHashAddress(bytes):
    def __hash__(self):
        return bytes.__hash__(self) ^ 65535


def flow_finding_with_address_type(finding, address_type, name="source_address"):
    window = finding.raw_evidence.observation_window
    identity = replace(window.identity, **{name: address_type(getattr(window.identity, name))})
    state = window.coordinated_state
    changes = {field.name: replace(getattr(state, field.name), identity=identity)
               for field in fields(state) if getattr(state, field.name) is not None
               and field.name not in ('dns_transaction_statistics', 'dns_query_name_statistics', 'dns_resource_record_statistics', 'dns_message_flag_statistics', 'dns_edns_statistics', 'tls_handshake_statistics', 'tls_client_hellos', 'tls_client_hello_statistics', 'tls_server_hellos', 'tls_server_hello_statistics')}
    window = replace(window, coordinated_state=replace(state, **changes))
    evidence = replace(finding.raw_evidence, snapshot=extract_flow_feature_snapshot(window))
    return replace(finding, raw_evidence=evidence)


class DetectionEvaluationTests(unittest.TestCase):
    def test_matching_phases_multiplicity_and_references_on_index_and_fallback(self):
        yes, no = flow_finding(), flow_finding(positive=False)
        unavailable = replace(yes, decision=FlowVolumeThresholdDecision.NOT_EVALUABLE,
                              security_interpretation=FlowVolumeThresholdInterpretation.METRIC_NOT_EVALUABLE)
        original = (unavailable, no, yes, yes, no, unavailable)
        packet_result = packet_finding()
        packet_expectation = expected(packet_result, index=0)
        identity = detection_identity(yes)
        missing_identity = replace(identity, window_key=replace(identity.window_key, sequence_number=10))
        missing_positive = ExpectedDetection(missing_identity, True)
        missing_negative = ExpectedDetection(replace(missing_identity, window_key=replace(identity.window_key, sequence_number=11)), False)
        for address_type in (bytes, UnhashableAddress, UnindexableAddress, AlternateHashAddress):
            for name in ("source_address", "destination_address"):
                findings = tuple(flow_finding_with_address_type(finding, address_type, name) if i % 2 == 0 else finding
                                 for i, finding in enumerate(original))
                for positive, priority, classifications in (
                    (True, (2, 3, 1, 4, 0, 5), (C.FALSE_NEGATIVE, C.FALSE_NEGATIVE, C.TRUE_POSITIVE)),
                    (False, (1, 4, 2, 3, 0, 5), (None, C.TRUE_NEGATIVE, C.FALSE_POSITIVE)),
                ):
                    for count in (0, 1, 2, 3, 5, 6, 7):
                        with self.subTest(address_type=address_type, name=name, positive=positive, count=count):
                            expectations = (missing_positive,) + tuple(ExpectedDetection(identity, positive) for _ in range(count)) + (missing_negative,)
                            result = evaluate(packets=(packet_result,), flows=findings,
                                              packet_expectations=(packet_expectation,), flow_expectations=expectations)
                            assignments = {actual_index: i + 1 for i, actual_index in enumerate(priority[:count])}
                            entries = result.flow_evaluations
                            self.assertEqual([e.actual_index for e in entries[:6]], list(range(6)))
                            for actual_index, entry in enumerate(entries[:6]):
                                expected_index = assignments.get(actual_index)
                                self.assertEqual(entry.expectation_index, expected_index)
                                self.assertIs(entry.finding, findings[actual_index])
                                self.assertIs(entry.expectation, None if expected_index is None else expectations[expected_index])
                                decision_index = ("not_evaluable", "no_match", "match").index(entry.finding.decision.value)
                                classification = classifications[decision_index] if expected_index is not None else (C.FALSE_POSITIVE if decision_index == 2 else None)
                                self.assertIs(entry.classification, classification)
                            missing_indices = [i for i in range(len(expectations)) if i not in assignments.values()]
                            self.assertEqual([e.expectation_index for e in entries[6:]], missing_indices)
                            for entry, i in zip(entries[6:], missing_indices):
                                self.assertIs(entry.expectation, expectations[i])
                                self.assertIsNone(entry.finding)
                                self.assertIsNone(entry.actual_index)
                                self.assertIs(entry.classification, C.FALSE_NEGATIVE if expectations[i].positive else None)
                            self.assertIs(result.packet_evaluations[0].finding, packet_result)
                            self.assertIs(result.packet_evaluations[0].expectation, packet_expectation)
                            self.assertIs(result.packet_evaluations[0].classification, C.TRUE_POSITIVE)
                            self.assertEqual(result, evaluate(packets=(packet_result,), flows=findings,
                                                             packet_expectations=(packet_expectation,), flow_expectations=expectations))

    def test_unhashable_and_unindexable_actual_identities_remain_accepted(self):
        normal = flow_finding()
        for address_type, error in ((UnhashableAddress, TypeError), (UnindexableAddress, AssertionError)):
            with self.subTest(address_type=address_type):
                finding = flow_finding_with_address_type(normal, address_type)
                with self.assertRaises(error):
                    hash(detection_identity(finding))
                entry = evaluate(flows=(finding,)).flow_evaluations[0]
                self.assertIs(entry.classification, C.FALSE_POSITIVE)
                self.assertIs(entry.finding, finding)
                entry = evaluate(flows=(finding,), flow_expectations=(expected(normal),)).flow_evaluations[0]
                self.assertIs(entry.classification, C.TRUE_POSITIVE)
                self.assertIs(entry.finding, finding)
                with self.assertRaises(error):
                    ExpectedDetectionResult((), (expected(finding),))

    def test_hashable_subclass_expectations_use_existing_equality_with_plain_findings(self):
        finding = flow_finding()
        custom = flow_finding_with_address_type(finding, AlternateHashAddress)
        expectation = expected(custom)
        self.assertEqual(expectation.identity, detection_identity(finding))
        self.assertNotEqual(hash(expectation.identity), hash(detection_identity(finding)))
        entries = evaluate(flows=(finding, finding), flow_expectations=(expectation, expected(finding), expectation)).flow_evaluations
        self.assertEqual([e.expectation_index for e in entries], [0, 1, 2])
        self.assertEqual([e.classification for e in entries], [C.TRUE_POSITIVE, C.TRUE_POSITIVE, C.FALSE_NEGATIVE])
        self.assertIs(entries[0].expectation, expectation)
        self.assertIs(entries[2].expectation, expectation)

    def test_identity_validation_precedes_indexing_in_finding_and_channel_order(self):
        class SourceText(str):
            pass

        malformed_packet = packet_finding(source=CaptureSource(SourceText("audit-source")))
        valid_packet, valid_flow = packet_finding(), flow_finding()
        window = valid_flow.raw_evidence.observation_window
        statistics = window.coordinated_state.flow_statistics
        statistics = replace(statistics, first_captured_at=statistics.first_captured_at.astimezone(timezone(timedelta(hours=1))),
                             last_captured_at=statistics.last_captured_at.astimezone(timezone(timedelta(hours=1))))
        window = replace(window, coordinated_state=replace(window.coordinated_state, flow_statistics=statistics))
        malformed_flow = replace(valid_flow, raw_evidence=replace(valid_flow.raw_evidence, snapshot=extract_flow_feature_snapshot(window)))
        for packets, flows, error, message in (
            ((malformed_packet, valid_flow), (), TypeError, "capture_source must be exactly a string"),
            ((valid_flow, malformed_packet), (), ValueError, "pipeline finding belongs to the other finding channel"),
            ((malformed_packet,), (malformed_flow,), TypeError, "capture_source must be exactly a string"),
            ((), (malformed_flow, valid_packet), ValueError, "timestamp must have zero UTC offset"),
            ((), (valid_packet, malformed_flow), ValueError, "pipeline finding belongs to the other finding channel"),
        ):
            with self.subTest(message=message, packets=len(packets), flows=len(flows)):
                with self.assertRaises(error) as raised:
                    evaluate(packets=packets, flows=flows)
                self.assertEqual(str(raised.exception), message)

    def test_ordinary_identity_search_work_is_linear_for_reversed_and_disjoint_inputs(self):
        for packet_channel, identity_type in ((True, PacketDetectionIdentity), (False, FlowDetectionIdentity)):
            finding = packet_finding() if packet_channel else flow_finding()
            for size in (64, 128):
                findings = (finding,) * size
                if not packet_channel:
                    window = finding.raw_evidence.observation_window
                    findings = tuple(replace(finding, raw_evidence=replace(finding.raw_evidence,
                                     snapshot=extract_flow_feature_snapshot(replace(window, key=replace(window.key, sequence_number=i)))))
                                     for i in range(size))
                identities = tuple(detection_identity(value, packet_index=i if packet_channel else None)
                                   for i, value in enumerate(findings))
                for disjoint in (False, True):
                    with self.subTest(packet=packet_channel, size=size, disjoint=disjoint):
                        targets = tuple(replace(identity, configuration=replace(identity.configuration, detector_version="other"))
                                        if disjoint else identity for identity in reversed(identities))
                        expectations = tuple(ExpectedDetection(identity, True) for identity in targets)
                        actual = DetectionPipelineResult(findings if packet_channel else (), () if packet_channel else findings)
                        expected_result = ExpectedDetectionResult(expectations if packet_channel else (), () if packet_channel else expectations)
                        calls = {"equality": 0, "hash": 0}
                        original_equality, original_hash = identity_type.__eq__, identity_type.__hash__

                        def counted_equality(left, right):
                            calls["equality"] += 1
                            return original_equality(left, right)

                        def counted_hash(value):
                            calls["hash"] += 1
                            return original_hash(value)

                        with patch.object(identity_type, "__eq__", counted_equality), patch.object(identity_type, "__hash__", counted_hash):
                            result = evaluate_detection_result(actual, expected_result)
                        entries = result.packet_evaluations if packet_channel else result.flow_evaluations
                        self.assertLessEqual(sum(calls.values()), 12 * size)
                        self.assertEqual(len(entries), size * (2 if disjoint else 1))
                        self.assertEqual([e.expectation_index for e in entries[:size]], [None] * size if disjoint else list(reversed(range(size))))
                        self.assertEqual([e.classification for e in entries[:size]], [C.FALSE_POSITIVE if disjoint else C.TRUE_POSITIVE] * size)

    def test_empty_result_has_no_inferred_negatives(self):
        self.assertEqual(evaluate(), DetectionEvaluationResult((), ()))

    def test_packet_positive_match_retains_exact_evidence(self):
        finding = packet_finding()
        expectation = expected(finding, index=0)
        result = evaluate(packets=(finding,), packet_expectations=(expectation,))
        entry = result.packet_evaluations[0]
        self.assertIs(entry.classification, C.TRUE_POSITIVE)
        self.assertEqual((entry.actual_index, entry.expectation_index), (0, 0))
        self.assertIs(entry.finding, finding)
        self.assertIs(entry.finding.raw_evidence, finding.raw_evidence)
        self.assertIs(entry.expectation, expectation)
        self.assertEqual(result.flow_evaluations, ())

    def test_positive_absence_is_false_negative(self):
        expectation = expected(packet_finding(), index=0)
        entry = evaluate(packet_expectations=(expectation,)).packet_evaluations[0]
        self.assertEqual((entry.classification, entry.actual_index, entry.finding), (C.FALSE_NEGATIVE, None, None))
        self.assertIs(entry.expectation, expectation)

    def test_unexpected_match_is_false_positive(self):
        finding = packet_finding()
        entry = evaluate(packets=(finding,)).packet_evaluations[0]
        self.assertEqual((entry.classification, entry.expectation, entry.expectation_index), (C.FALSE_POSITIVE, None, None))

    def test_negative_no_match_is_true_negative(self):
        finding = packet_finding(PacketIntegrityDecision.NO_MATCH)
        entry = evaluate(packets=(finding,), packet_expectations=(expected(finding, False, 0),)).packet_evaluations[0]
        self.assertIs(entry.classification, C.TRUE_NEGATIVE)
        self.assertIs(entry.finding.decision, PacketIntegrityDecision.NO_MATCH)

    def test_negative_absence_is_unresolved_not_true_negative(self):
        expectation = expected(packet_finding(), False, 0)
        entry = evaluate(packet_expectations=(expectation,)).packet_evaluations[0]
        self.assertEqual((entry.classification, entry.finding), (None, None))
        self.assertIs(entry.expectation, expectation)

    def test_negative_match_is_false_positive(self):
        finding = packet_finding()
        entry = evaluate(packets=(finding,), packet_expectations=(expected(finding, False, 0),)).packet_evaluations[0]
        self.assertIs(entry.classification, C.FALSE_POSITIVE)
        self.assertFalse(entry.expectation.positive)

    def test_positive_no_match_is_false_negative(self):
        finding = packet_finding(PacketIntegrityDecision.NO_MATCH)
        entry = evaluate(packets=(finding,), packet_expectations=(expected(finding, True, 0),)).packet_evaluations[0]
        self.assertIs(entry.classification, C.FALSE_NEGATIVE)
        self.assertIs(entry.finding, finding)

    def test_positive_not_evaluable_is_unsatisfied_with_distinct_decision(self):
        finding = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE)
        entry = evaluate(packets=(finding,), packet_expectations=(expected(finding, True, 0),)).packet_evaluations[0]
        self.assertIs(entry.classification, C.FALSE_NEGATIVE)
        self.assertIs(entry.finding.decision, PacketIntegrityDecision.NOT_EVALUABLE)

    def test_negative_not_evaluable_is_neither_true_negative_nor_false_positive(self):
        finding = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE)
        entry = evaluate(packets=(finding,), packet_expectations=(expected(finding, False, 0),)).packet_evaluations[0]
        self.assertIsNone(entry.classification)
        self.assertIs(entry.finding.decision, PacketIntegrityDecision.NOT_EVALUABLE)

    def test_unexpected_no_match_does_not_manufacture_negative_label(self):
        finding = packet_finding(PacketIntegrityDecision.NO_MATCH)
        entry = evaluate(packets=(finding,)).packet_evaluations[0]
        self.assertIsNone(entry.classification)
        self.assertIsNone(entry.expectation)
        self.assertIs(entry.finding, finding)

    def test_unexpected_not_evaluable_is_retained_without_binary_classification(self):
        finding = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE)
        entry = evaluate(packets=(finding,)).packet_evaluations[0]
        self.assertIsNone(entry.classification)
        self.assertIs(entry.finding, finding)

    def test_ipv4_udp_flow_matches_canonical_identity(self):
        finding = flow_finding()
        identity = detection_identity(finding)
        self.assertEqual((identity.flow_identity.ip_version, identity.flow_identity.protocol), (4, 17))
        self.assertEqual(identity.flow_identity.source_address, b'\x0a\x00\x00\x01')
        result = evaluate(flows=(finding,), flow_expectations=(ExpectedDetection(identity, True),))
        self.assertIs(result.flow_evaluations[0].classification, C.TRUE_POSITIVE)
        self.assertEqual(result.packet_evaluations, ())

    def test_ipv6_udp_flow_uses_packed_identity(self):
        finding = flow_finding(ipv6=True)
        identity = detection_identity(finding)
        self.assertEqual(identity.flow_identity.source_address, bytes.fromhex('20010db8000000000000000000000001'))
        self.assertEqual(identity.flow_identity.destination_address, bytes.fromhex('20010db8000000000000000000000002'))
        self.assertEqual(identity.flow_identity.protocol, 17)
        self.assertIs(evaluate(flows=(finding,), flow_expectations=(expected(finding),)).flow_evaluations[0].classification, C.TRUE_POSITIVE)

    def test_ipv6_tcp_volume_identity_remains_distinct_from_udp(self):
        tcp = flow_finding(protocol=6, ipv6=True)
        udp = flow_finding(protocol=17, ipv6=True)
        self.assertNotEqual(detection_identity(tcp), detection_identity(udp))
        result = evaluate(flows=(tcp, udp), flow_expectations=(expected(tcp), expected(udp)))
        self.assertEqual([e.classification for e in result.flow_evaluations], [C.TRUE_POSITIVE, C.TRUE_POSITIVE])

    def test_tcp_control_finding_uses_existing_configuration_and_window(self):
        window = closed_window(tcp_packet(0, syn=True))
        configuration = control_configuration()
        finding = detection_finding_from_evaluation(evaluate_tcp_control_threshold(window, configuration))
        identity = detection_identity(finding)
        self.assertIs(identity.configuration, configuration)
        self.assertIs(identity.window_key, window.key)
        self.assertIs(identity.flow_identity, window.identity)
        self.assertIs(evaluate(flows=(finding,), flow_expectations=(expected(finding),)).flow_evaluations[0].classification, C.TRUE_POSITIVE)

    def test_ipv6_control_finding_evaluates_without_protocol_specific_path(self):
        window = closed_snapshot(packet_at(flags=2)).observation_window
        finding = detection_finding_from_evaluation(evaluate_tcp_control_threshold(window, control_configuration()))
        entry = evaluate(flows=(finding,), flow_expectations=(expected(finding),)).flow_evaluations[0]
        self.assertIs(entry.classification, C.TRUE_POSITIVE)
        self.assertEqual(entry.expectation.identity.flow_identity.ip_version, 6)

    def test_detector_id_prevents_match(self):
        finding = packet_finding()
        identity = detection_identity(finding, packet_index=0)
        changed = replace(identity, configuration=replace(identity.configuration, detector_id='other'))
        result = evaluate(packets=(finding,), packet_expectations=(ExpectedDetection(changed, True),))
        self.assertEqual([e.classification for e in result.packet_evaluations], [C.FALSE_POSITIVE, C.FALSE_NEGATIVE])

    def test_detector_version_prevents_match(self):
        finding = flow_finding()
        identity = detection_identity(finding)
        changed = replace(identity, configuration=replace(identity.configuration, detector_version='2'))
        result = evaluate(flows=(finding,), flow_expectations=(ExpectedDetection(changed, True),))
        self.assertEqual([e.classification for e in result.flow_evaluations], [C.FALSE_POSITIVE, C.FALSE_NEGATIVE])

    def test_metric_and_threshold_participate_in_identity(self):
        finding = flow_finding()
        identity = detection_identity(finding)
        for config in (replace(identity.configuration, threshold=2), replace(identity.configuration, metric=FlowVolumeMetric.CAPTURED_BYTES)):
            result = evaluate(flows=(finding,), flow_expectations=(ExpectedDetection(replace(identity, configuration=config), True),))
            self.assertEqual([e.classification for e in result.flow_evaluations], [C.FALSE_POSITIVE, C.FALSE_NEGATIVE])

    def test_flow_session_sequence_addresses_and_times_prevent_unrelated_match(self):
        finding = flow_finding()
        identity = detection_identity(finding)
        alternatives = (
            replace(identity, window_key=replace(identity.window_key, capture_session_id='other')),
            replace(identity, window_key=replace(identity.window_key, sequence_number=1)),
            replace(identity, flow_identity=replace(identity.flow_identity, destination_port=444)),
            replace(identity, flow_identity=replace(identity.flow_identity, destination_address=b'\x0a\x00\x00\x03')),
            replace(identity, last_captured_at=identity.last_captured_at + timedelta(seconds=1)),
        )
        for alternative in alternatives:
            result = evaluate(flows=(finding,), flow_expectations=(ExpectedDetection(alternative, True),))
            self.assertEqual([e.classification for e in result.flow_evaluations], [C.FALSE_POSITIVE, C.FALSE_NEGATIVE])

    def test_packet_metadata_and_position_prevent_unrelated_match(self):
        finding = packet_finding()
        identity = detection_identity(finding, packet_index=0)
        for changes in ({'packet_index': 1}, {'capture_source': 'other'}, {'link_type': 101},
                        {'captured_at': identity.captured_at + timedelta(microseconds=1)},
                        {'captured_length': identity.captured_length - 1}, {'original_length': identity.original_length + 1}):
            result = evaluate(packets=(finding,), packet_expectations=(ExpectedDetection(replace(identity, **changes), True),))
            self.assertEqual([e.classification for e in result.packet_evaluations], [C.FALSE_POSITIVE, C.FALSE_NEGATIVE])

    def test_equivalent_independent_findings_match_without_object_identity(self):
        first, second = flow_finding(), flow_finding()
        self.assertIsNot(first.raw_evidence, second.raw_evidence)
        self.assertEqual(detection_identity(first), detection_identity(second))
        self.assertIs(evaluate(flows=(second,), flow_expectations=(expected(first),)).flow_evaluations[0].classification, C.TRUE_POSITIVE)

    def test_packet_identity_does_not_depend_on_decision_or_failure_description(self):
        positive = packet_finding()
        negative = packet_finding(PacketIntegrityDecision.NO_MATCH)
        unevaluable = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE)
        identities = [detection_identity(f, packet_index=0) for f in (positive, negative, unevaluable)]
        self.assertEqual(identities, [identities[0]] * 3)

    def test_duplicate_actual_flows_are_preserved_as_excess_false_positives(self):
        finding = flow_finding()
        entries = evaluate(flows=(finding, finding), flow_expectations=(expected(finding),)).flow_evaluations
        self.assertEqual([e.classification for e in entries], [C.TRUE_POSITIVE, C.FALSE_POSITIVE])
        self.assertEqual([e.actual_index for e in entries], [0, 1])
        self.assertTrue(all(e.finding is finding for e in entries))

    def test_duplicate_positive_expectations_require_multiple_findings(self):
        finding = flow_finding()
        expectation = expected(finding)
        entries = evaluate(flows=(finding,), flow_expectations=(expectation, expectation)).flow_evaluations
        self.assertEqual([e.classification for e in entries], [C.TRUE_POSITIVE, C.FALSE_NEGATIVE])
        self.assertEqual([e.expectation_index for e in entries], [0, 1])

    def test_equal_multiplicity_positives_all_match(self):
        finding = flow_finding()
        expectation = expected(finding)
        entries = evaluate(flows=(finding, finding), flow_expectations=(expectation, expectation)).flow_evaluations
        self.assertEqual([e.classification for e in entries], [C.TRUE_POSITIVE] * 2)
        self.assertEqual([e.expectation_index for e in entries], [0, 1])

    def test_duplicate_negatives_require_distinct_no_match_findings(self):
        finding = flow_finding(positive=False)
        expectation = expected(finding, False)
        entries = evaluate(flows=(finding,), flow_expectations=(expectation, expectation)).flow_evaluations
        self.assertEqual([e.classification for e in entries], [C.TRUE_NEGATIVE, None])
        self.assertIsNone(entries[1].finding)
        entries = evaluate(flows=(finding, finding), flow_expectations=(expectation, expectation)).flow_evaluations
        self.assertEqual([e.classification for e in entries], [C.TRUE_NEGATIVE] * 2)

    def test_duplicate_packet_values_have_distinct_result_positions(self):
        finding = packet_finding()
        expectations = tuple(expected(finding, index=i) for i in (0, 1))
        entries = evaluate(packets=(finding, finding), packet_expectations=expectations).packet_evaluations
        self.assertEqual([e.classification for e in entries], [C.TRUE_POSITIVE] * 2)
        self.assertNotEqual(expectations[0].identity, expectations[1].identity)

    def test_required_positive_decision_is_selected_before_opposite_without_reordering(self):
        yes, no = flow_finding(), flow_finding(positive=False)
        self.assertEqual(detection_identity(yes), detection_identity(no))
        entries = evaluate(flows=(no, yes), flow_expectations=(expected(yes),)).flow_evaluations
        self.assertEqual([e.classification for e in entries], [None, C.TRUE_POSITIVE])
        self.assertIs(entries[0].finding, no)
        self.assertIs(entries[1].finding, yes)

    def test_required_negative_decision_is_selected_before_match(self):
        yes, no = flow_finding(), flow_finding(positive=False)
        entries = evaluate(flows=(yes, no), flow_expectations=(expected(no, False),)).flow_evaluations
        self.assertEqual([e.classification for e in entries], [C.FALSE_POSITIVE, C.TRUE_NEGATIVE])
        self.assertIsNone(entries[0].expectation)

    def test_packet_order_and_missing_expectation_order_are_preserved(self):
        first = packet_finding()
        second = packet_finding(captured_at=first.raw_evidence.captured_at - timedelta(seconds=1))
        expectations = (expected(first, index=4), expected(second, index=3))
        entries = evaluate(packets=(first, second), packet_expectations=expectations).packet_evaluations
        self.assertEqual([e.actual_index for e in entries], [0, 1, None, None])
        self.assertEqual([e.expectation_index for e in entries], [None, None, 0, 1])
        self.assertIs(entries[0].finding, first)
        self.assertIs(entries[1].finding, second)

    def test_mixed_packet_flow_true_false_classifications_remain_separate(self):
        yes, no = packet_finding(), packet_finding(PacketIntegrityDecision.NO_MATCH)
        flow = flow_finding()
        missing = replace(detection_identity(flow), window_key=replace(detection_identity(flow).window_key, sequence_number=5))
        result = evaluate(packets=(yes, no), flows=(flow,), packet_expectations=(expected(yes, index=0), expected(no, False, 1)),
                          flow_expectations=(ExpectedDetection(missing, True),))
        self.assertEqual([e.classification for e in result.packet_evaluations], [C.TRUE_POSITIVE, C.TRUE_NEGATIVE])
        self.assertEqual([e.classification for e in result.flow_evaluations], [C.FALSE_POSITIVE, C.FALSE_NEGATIVE])

    def test_all_missing_expectations_do_not_infer_true_negatives(self):
        finding = packet_finding()
        entries = evaluate(packet_expectations=(expected(finding, index=0), expected(finding, False, 1))).packet_evaluations
        self.assertEqual([e.classification for e in entries], [C.FALSE_NEGATIVE, None])

    def test_flow_not_evaluable_keeps_typed_decision_and_evidence(self):
        finding = detection_finding_from_evaluation(flow_volume_evaluation(FlowVolumeThresholdDecision.NOT_EVALUABLE))
        for positive, classification in ((True, C.FALSE_NEGATIVE), (False, None)):
            entry = evaluate(flows=(finding,), flow_expectations=(expected(finding, positive),)).flow_evaluations[0]
            self.assertIs(entry.classification, classification)
            self.assertIs(entry.finding.decision, FlowVolumeThresholdDecision.NOT_EVALUABLE)
            self.assertIsNone(entry.finding.raw_evidence.observed_value)

    def test_packet_expectation_cannot_be_placed_in_flow_channel(self):
        with self.assertRaises(ValueError):
            ExpectedDetectionResult((), (expected(packet_finding(), index=0),))

    def test_flow_expectation_cannot_be_placed_in_packet_channel(self):
        with self.assertRaises(ValueError):
            ExpectedDetectionResult((expected(flow_finding()),), ())

    def test_misplaced_actual_evidence_is_rejected(self):
        for result in (DetectionPipelineResult((flow_finding(),), ()), DetectionPipelineResult((), (packet_finding(),))):
            with self.assertRaises(ValueError):
                evaluate_detection_result(result, ExpectedDetectionResult((), ()))

    def test_contradictory_labels_for_same_identity_are_rejected_in_either_order(self):
        finding = flow_finding()
        positive, negative = expected(finding), expected(finding, False)
        for expectations in ((positive, negative), (negative, positive)):
            with self.assertRaises(ValueError):
                ExpectedDetectionResult((), expectations)

    def test_expectation_collections_reject_mutability_without_mutating_lists(self):
        items = [expected(packet_finding(), index=0)]
        before = items[:]
        with self.assertRaises(TypeError):
            ExpectedDetectionResult(items, ())
        self.assertEqual(items, before)
        with self.assertRaises(TypeError):
            ExpectedDetectionResult((), [expected(flow_finding())])

    def test_expected_identity_and_result_contracts_are_frozen(self):
        expectation = expected(flow_finding())
        expected_result = ExpectedDetectionResult((), (expectation,))
        for obj, name, value in ((expectation, 'positive', False), (expectation.identity, 'window_key', None),
                                  (expected_result, 'flow_expectations', ())):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, name, value)

    def test_evaluation_result_and_entries_are_frozen(self):
        result = evaluate(packets=(packet_finding(),))
        with self.assertRaises(FrozenInstanceError):
            result.packet_evaluations = ()
        with self.assertRaises(FrozenInstanceError):
            result.packet_evaluations[0].classification = C.TRUE_NEGATIVE

    def test_repeated_independent_calls_do_not_retain_matching_state(self):
        finding = flow_finding()
        expectation = expected(finding)
        first = evaluate(flows=(finding, finding), flow_expectations=(expectation,))
        evaluate()
        evaluate(flows=(finding,), flow_expectations=(expectation, expectation))
        self.assertEqual(first, evaluate(flows=(flow_finding(), flow_finding()), flow_expectations=(expected(flow_finding()),)))

    def test_semantic_input_models_are_not_mutated(self):
        finding = packet_finding()
        result = DetectionPipelineResult((finding,), ())
        expectation = ExpectedDetectionResult((expected(finding, index=0),), ())
        original = (result, expectation, finding.raw_evidence.outcome, finding.raw_evidence.configuration)
        baseline = (DetectionPipelineResult((packet_finding(),), ()), ExpectedDetectionResult((expected(packet_finding(), index=0),), ()),
                    packet_finding().raw_evidence.outcome, PacketIntegrityConfiguration('packet-integrity', '1'))
        evaluated = evaluate_detection_result(result, expectation)
        self.assertEqual(original, baseline)
        self.assertIs(evaluated.packet_evaluations[0].finding, finding)
        self.assertEqual(tuple(f.name for f in fields(DetectionFinding)), ('detector_id', 'detector_version', 'decision', 'raw_evidence', 'security_interpretation'))

    def test_pure_boundary_does_not_execute_any_acquisition_analysis_features_or_detection(self):
        finding, flow = packet_finding(), flow_finding(ipv6=True)
        actual = DetectionPipelineResult((finding,), (flow,))
        expectation = ExpectedDetectionResult((expected(finding, index=0),), (expected(flow),))
        with ExitStack() as stack:
            mocks = []
            for target in ('application.detection_pipeline.run_detection_pipeline', 'application.capture_execution.run_capture_execution',
                           'application.flow_observation_session.run_flow_observation_session', 'application.detection_session.DetectionSession',
                           'application.cli.main', 'analysis.packet_analysis.analyze_packet', 'analysis.packet_analysis_outcome.analyze_packet_outcome',
                           'analysis.flow_feature_snapshot.extract_flow_feature_snapshot', 'application.detection_pipeline.extract_flow_feature_snapshot',
                           'analysis.ipv6.decode_ipv6', 'analysis.ipv6_extension_headers.validate_ipv6_extension_headers',
                           'analysis.ipv6_fragmentation.analyze_ipv6_fragmentation', 'capture.packet_ingestion.consume',
                           'capture.pcap_packet_source.PcapPacketSource.start', 'capture.iterable_packet_source.IterablePacketSource.start',
                           'detection.packet_integrity.evaluate_packet_integrity', 'detection.flow_volume_threshold.evaluate_flow_volume_threshold',
                           'detection.tcp_control_threshold.evaluate_tcp_control_threshold', 'builtins.open'):
                mocks.append(stack.enter_context(patch(target, side_effect=AssertionError(target))))
            for target in ('capture.packet_observation.PacketObservation.raw_bytes', 'analysis.ipv6.IPv6Packet.payload',
                           'analysis.ethernet.EthernetFrame.payload'):
                mocks.append(stack.enter_context(patch(target, new_callable=PropertyMock, create=True, side_effect=AssertionError(target))))
            result = evaluate_detection_result(actual, expectation)
            for mocked in mocks:
                mocked.assert_not_called()
        self.assertIs(result.packet_evaluations[0].classification, C.TRUE_POSITIVE)
        self.assertIs(result.flow_evaluations[0].classification, C.TRUE_POSITIVE)

    def test_public_exports_resolve(self):
        for value in (DetectionEvaluationResult, DetectionEvaluationEntry, ExpectedDetectionResult, ExpectedDetection,
                      FlowDetectionIdentity, PacketDetectionIdentity, evaluate_detection_result, detection_identity):
            self.assertIs(getattr(application, value.__name__), value)
            self.assertIn(value.__name__, application.__all__)
        self.assertIn('DetectionClassification', application.__all__)

    def test_entry_rejects_inconsistent_classification_and_missing_provenance(self):
        finding = packet_finding()
        for args in ((C.TRUE_NEGATIVE, None, None, 0, finding), (C.FALSE_POSITIVE, None, None, None, finding),
                     (None, None, None, None, None)):
            with self.assertRaises((TypeError, ValueError)):
                DetectionEvaluationEntry(*args)

    def test_result_rejects_wrong_channel_entries_and_mutable_collections(self):
        entry = evaluate(packets=(packet_finding(),)).packet_evaluations[0]
        with self.assertRaises(ValueError):
            DetectionEvaluationResult((), (entry,))
        with self.assertRaises(TypeError):
            DetectionEvaluationResult([entry], ())

    def test_evaluator_rejects_wrong_input_types(self):
        for actual, expectation in (((), ExpectedDetectionResult((), ())), (DetectionPipelineResult((), ()), ())):
            with self.assertRaises(TypeError):
                evaluate_detection_result(actual, expectation)

    def test_packet_identity_requires_explicit_valid_position(self):
        finding = packet_finding()
        with self.assertRaises(ValueError):
            detection_identity(finding)
        for value in (-1, True, 1.0):
            with self.assertRaises((TypeError, ValueError)):
                detection_identity(finding, packet_index=value)
        with self.assertRaises(ValueError):
            detection_identity(flow_finding(), packet_index=0)

    def test_packet_identity_validates_timestamp_and_capture_metadata(self):
        identity = detection_identity(packet_finding(), packet_index=0)
        for change in ({'captured_at': identity.captured_at.replace(tzinfo=None)},
                       {'captured_at': identity.captured_at.replace(tzinfo=timezone(timedelta(hours=1)))},
                       {'link_type': 65536}, {'capture_source': ''}, {'original_length': 0}, {'captured_length': True}):
            with self.assertRaises((TypeError, ValueError)):
                replace(identity, **change)

    def test_optional_capture_metadata_is_preserved(self):
        finding = packet_finding(link_type=None, original_length=None)
        identity = detection_identity(finding, packet_index=0)
        self.assertEqual((identity.link_type, identity.original_length), (None, None))
        self.assertIs(evaluate(packets=(finding,), packet_expectations=(ExpectedDetection(identity, True),)).packet_evaluations[0].classification, C.TRUE_POSITIVE)

    def test_flow_identity_validates_temporal_and_transport_context(self):
        identity = detection_identity(flow_finding())
        with self.assertRaises(ValueError):
            replace(identity, first_captured_at=identity.last_captured_at + timedelta(seconds=1))
        with self.assertRaises(ValueError):
            replace(identity, configuration=control_configuration(TCPControlMetric.FORWARD_SYN))

    def test_expectation_requires_explicit_boolean_label(self):
        identity = detection_identity(flow_finding())
        for value in (None, 1, 'positive'):
            with self.assertRaises(TypeError):
                ExpectedDetection(identity, value)


if __name__ == '__main__':
    unittest.main()
