import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from unittest.mock import PropertyMock, patch

import application
from analysis import FlowIdentity, FlowObservationWindowKey
from application import (
    DetectionPipelineResult,
    ExpectedDetection,
    ExpectedDetectionResult,
    FlowDetectionIdentity,
    GroundTruth,
    GroundTruthPolarity,
    GroundTruthRecord,
    PacketDetectionIdentity,
    evaluate_detection_result,
)
from detection import (
    FlowVolumeMetric,
    FlowVolumeThresholdConfiguration,
    PacketIntegrityConfiguration,
    PacketIntegrityDecision,
    TCPControlMetric,
    TCPControlThresholdConfiguration,
)
from tests.test_detection_evaluation import packet_finding
from tests.test_ipv6_flow import observation_at
from tests.test_packet_analysis import TCP_BYTES, make_observation


TIMESTAMP = datetime(2026, 9, 11, 0, 0, 1, 123456, tzinfo=timezone.utc)


def packet_target(**changes):
    target = PacketDetectionIdentity(
        PacketIntegrityConfiguration('integrity', '1'), 0, TIMESTAMP, 'external-capture', 1, 54, 100,
    )
    return replace(target, **changes)


def flow_target(protocol=17, ipv6=False, **changes):
    source = bytes.fromhex('20010db8000000000000000000000001') if ipv6 else b'\xc0\x00\x02\x01'
    destination = bytes.fromhex('20010db8000000000000000000000002') if ipv6 else b'\xc0\x00\x02\x02'
    target = FlowDetectionIdentity(
        FlowVolumeThresholdConfiguration('volume', '1', FlowVolumeMetric.PACKET_COUNT, 10),
        FlowObservationWindowKey('externally-defined-session', 0),
        FlowIdentity(source, destination, 12345, 443, protocol), TIMESTAMP, TIMESTAMP + timedelta(seconds=3),
    )
    return replace(target, **changes)


def positive(target):
    return GroundTruthRecord(target, GroundTruthPolarity.POSITIVE)


def negative(target):
    return GroundTruthRecord(target, GroundTruthPolarity.NEGATIVE)


class GroundTruthTests(unittest.TestCase):
    def test_explicit_positive_truth_retains_target_and_polarity(self):
        target = packet_target()
        record = positive(target)
        self.assertIs(record.target, target)
        self.assertIs(record.polarity, GroundTruthPolarity.POSITIVE)
        self.assertEqual(record.polarity.value, 'positive')

    def test_explicit_negative_truth_is_not_a_detector_decision(self):
        target = flow_target()
        record = negative(target)
        self.assertIs(record.target, target)
        self.assertIs(record.polarity, GroundTruthPolarity.NEGATIVE)
        self.assertEqual(record.polarity.value, 'negative')
        self.assertNotEqual(record.polarity, PacketIntegrityDecision.NO_MATCH)

    def test_empty_truth_means_unlabeled_not_explicitly_negative(self):
        empty = GroundTruth((), ())
        self.assertEqual((empty.packet_records, empty.flow_records), ((), ()))
        self.assertNotEqual(empty, GroundTruth((negative(packet_target()),), ()))
        self.assertEqual(tuple(GroundTruthPolarity), (GroundTruthPolarity.POSITIVE, GroundTruthPolarity.NEGATIVE))

    def test_partial_truth_does_not_fill_unspecified_targets(self):
        labeled = positive(packet_target(packet_index=5))
        unlabeled = packet_target(packet_index=0)
        truth = GroundTruth((labeled,), ())
        self.assertEqual(truth.packet_records, (labeled,))
        self.assertFalse(any(record.target == unlabeled for record in truth.packet_records))
        self.assertEqual(truth.flow_records, ())

    def test_record_polarity_and_target_cannot_be_reassigned(self):
        for record in (positive(packet_target()), negative(flow_target())):
            with self.assertRaises(FrozenInstanceError):
                record.polarity = GroundTruthPolarity.NEGATIVE
            with self.assertRaises(FrozenInstanceError):
                record.target = packet_target(packet_index=2)

    def test_nested_target_configuration_and_flow_identity_are_immutable(self):
        record = positive(flow_target())
        for obj, name, value in ((record.target, 'window_key', None),
                                  (record.target.configuration, 'threshold', 9),
                                  (record.target.window_key, 'sequence_number', 2),
                                  (record.target.flow_identity, 'source_port', 22)):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, name, value)

    def test_collection_and_record_tuples_are_immutable(self):
        truth = GroundTruth((positive(packet_target()),), (negative(flow_target()),))
        with self.assertRaises(FrozenInstanceError):
            truth.packet_records = ()
        with self.assertRaises(FrozenInstanceError):
            truth.flow_records = ()
        with self.assertRaises(TypeError):
            truth.packet_records[0] = negative(packet_target())

    def test_ipv4_packet_target_uses_external_capture_metadata(self):
        observation = make_observation(6, TCP_BYTES)
        target = packet_target(captured_at=observation.captured_at, capture_source=observation.source.identifier,
                               captured_length=observation.captured_length, original_length=observation.original_length)
        truth = GroundTruth((positive(target),), ())
        self.assertEqual(truth.packet_records[0].target.captured_length, 54)
        self.assertEqual(truth.packet_records[0].target.link_type, 1)
        self.assertIs(truth.packet_records[0].target.captured_at, observation.captured_at)

    def test_ipv6_packet_target_uses_same_family_neutral_contract(self):
        observation = observation_at()
        target = packet_target(captured_at=observation.captured_at, capture_source=observation.source.identifier,
                               captured_length=observation.captured_length, original_length=observation.original_length)
        record = negative(target)
        self.assertIs(type(record.target), PacketDetectionIdentity)
        self.assertEqual(record.target.captured_length, 74)
        self.assertEqual(record.target.original_length, 74)
        self.assertNotIn('ip_version', tuple(field.name for field in fields(record.target)))

    def test_optional_capture_metadata_remains_unspecified(self):
        record = positive(packet_target(link_type=None, original_length=None))
        self.assertIsNone(record.target.link_type)
        self.assertIsNone(record.target.original_length)
        self.assertEqual(record.target.captured_length, 54)

    def test_ipv4_flow_truth_reuses_exact_canonical_window_and_endpoints(self):
        target = flow_target()
        record = positive(target)
        self.assertIs(record.target.window_key, target.window_key)
        self.assertIs(record.target.flow_identity, target.flow_identity)
        self.assertEqual(record.target.flow_identity.source_address, b'\xc0\x00\x02\x01')
        self.assertEqual(record.target.flow_identity.destination_address, b'\xc0\x00\x02\x02')
        self.assertEqual(record.target.flow_identity.ip_version, 4)

    def test_ipv6_flow_truth_preserves_packed_addresses(self):
        record = negative(flow_target(ipv6=True))
        self.assertEqual(record.target.flow_identity.source_address, bytes.fromhex('20010db8000000000000000000000001'))
        self.assertEqual(record.target.flow_identity.destination_address, bytes.fromhex('20010db8000000000000000000000002'))
        self.assertEqual(record.target.flow_identity.ip_version, 6)

    def test_tcp_control_truth_uses_configuration_without_control_statistics(self):
        config = TCPControlThresholdConfiguration('tcp-control', '2', TCPControlMetric.FORWARD_SYN, 4)
        for ipv6 in (False, True):
            target = flow_target(6, ipv6=ipv6, configuration=config)
            record = positive(target)
            self.assertIs(record.target.configuration, config)
            self.assertEqual(record.target.flow_identity.protocol, 6)
            self.assertFalse(hasattr(record.target, 'tcp_control_statistics'))

    def test_udp_volume_truth_is_distinct_from_tcp_volume_truth(self):
        udp, tcp = flow_target(17), flow_target(6)
        records = (positive(udp), negative(tcp))
        truth = GroundTruth((), records)
        self.assertEqual([record.target.flow_identity.protocol for record in truth.flow_records], [17, 6])
        self.assertNotEqual(udp, tcp)

    def test_ipv4_and_ipv6_flow_targets_never_match(self):
        ipv4, ipv6 = flow_target(), flow_target(ipv6=True)
        truth = GroundTruth((), (positive(ipv4), negative(ipv6)))
        self.assertNotEqual(ipv4, ipv6)
        self.assertEqual(len(truth.flow_records), 2)

    def test_detector_id_scopes_truth_independently(self):
        first = packet_target()
        second = replace(first, configuration=replace(first.configuration, detector_id='other'))
        truth = GroundTruth((positive(first), negative(second)), ())
        self.assertNotEqual(first, second)
        self.assertEqual([r.target.configuration.detector_id for r in truth.packet_records], ['integrity', 'other'])

    def test_detector_version_scopes_truth_independently(self):
        first = flow_target()
        second = replace(first, configuration=replace(first.configuration, detector_version='2'))
        truth = GroundTruth((), (positive(first), negative(second)))
        self.assertNotEqual(first, second)
        self.assertEqual([r.target.configuration.detector_version for r in truth.flow_records], ['1', '2'])

    def test_flow_metric_and_threshold_remain_part_of_existing_target(self):
        first = flow_target()
        metric = replace(first, configuration=replace(first.configuration, metric=FlowVolumeMetric.CAPTURED_BYTES))
        threshold = replace(first, configuration=replace(first.configuration, threshold=11))
        truth = GroundTruth((), (positive(first), negative(metric), negative(threshold)))
        self.assertEqual([r.target.configuration.threshold for r in truth.flow_records], [10, 10, 11])
        self.assertEqual(truth.flow_records[1].target.configuration.metric, FlowVolumeMetric.CAPTURED_BYTES)

    def test_equivalent_independent_targets_produce_equal_truth(self):
        first = GroundTruth((positive(packet_target()),), (negative(flow_target(ipv6=True)),))
        second = GroundTruth((positive(packet_target()),), (negative(flow_target(ipv6=True)),))
        self.assertIsNot(first.packet_records[0].target, second.packet_records[0].target)
        self.assertIsNot(first.flow_records[0].target, second.flow_records[0].target)
        self.assertEqual(first, second)

    def test_packet_position_metadata_distinguish_unrelated_targets(self):
        first = packet_target()
        for changes in ({'packet_index': 1}, {'capture_source': 'other'}, {'link_type': 101},
                        {'captured_at': TIMESTAMP + timedelta(microseconds=1)}, {'captured_length': 53}, {'original_length': 101}):
            second = replace(first, **changes)
            truth = GroundTruth((positive(first), negative(second)), ())
            self.assertNotEqual(first, second)
            self.assertEqual(len(truth.packet_records), 2)

    def test_flow_window_endpoints_and_times_distinguish_unrelated_targets(self):
        first = flow_target()
        alternatives = (
            replace(first, window_key=replace(first.window_key, capture_session_id='other')),
            replace(first, window_key=replace(first.window_key, sequence_number=1)),
            replace(first, flow_identity=replace(first.flow_identity, destination_port=444)),
            replace(first, flow_identity=replace(first.flow_identity, destination_address=b'\xc0\x00\x02\x03')),
            replace(first, last_captured_at=first.last_captured_at + timedelta(microseconds=1)),
        )
        for second in alternatives:
            self.assertNotEqual(first, second)
            self.assertEqual(len(GroundTruth((), (positive(first), negative(second))).flow_records), 2)

    def test_reverse_endpoints_reuse_existing_identity_and_duplicate_rule(self):
        first = flow_target(6, ipv6=True)
        flow = first.flow_identity
        reverse = FlowIdentity(flow.destination_address, flow.source_address, flow.destination_port, flow.source_port, flow.protocol)
        second = replace(first, flow_identity=reverse)
        self.assertEqual(first, second)
        with self.assertRaisesRegex(ValueError, 'duplicate target'):
            GroundTruth((), (positive(first), positive(second)))

    def test_flow_target_is_rejected_in_packet_collection(self):
        with self.assertRaisesRegex(ValueError, 'packet_records.*other domain'):
            GroundTruth((positive(flow_target()),), ())

    def test_packet_target_is_rejected_in_flow_collection(self):
        with self.assertRaisesRegex(ValueError, 'flow_records.*other domain'):
            GroundTruth((), (positive(packet_target()),))

    def test_missing_and_wrong_target_types_are_rejected(self):
        for target in (None, (), {}, 'packet', ExpectedDetection(packet_target(), True)):
            with self.assertRaisesRegex(TypeError, 'target must be exactly'):
                positive(target)
        with self.assertRaises(TypeError):
            GroundTruthRecord(polarity=GroundTruthPolarity.POSITIVE)

    def test_missing_and_wrong_polarity_types_are_rejected(self):
        for polarity in (None, True, False, 1, 'positive', PacketIntegrityDecision.MATCH):
            with self.assertRaisesRegex(TypeError, 'polarity must be exactly'):
                GroundTruthRecord(packet_target(), polarity)
        with self.assertRaises(TypeError):
            GroundTruthRecord(packet_target())

    def test_malformed_packet_targets_fail_existing_identity_validation(self):
        for changes in ({'packet_index': -1}, {'packet_index': True}, {'captured_length': -1}, {'original_length': 53},
                        {'link_type': 65536}, {'capture_source': ''}, {'captured_at': TIMESTAMP.replace(tzinfo=None)}):
            with self.assertRaises((TypeError, ValueError)):
                positive(packet_target(**changes))

    def test_malformed_flow_targets_fail_existing_identity_validation(self):
        first = flow_target()
        for changes in ({'window_key': None}, {'flow_identity': None}, {'first_captured_at': first.last_captured_at + timedelta(seconds=1)},
                        {'configuration': PacketIntegrityConfiguration('packet', '1')},
                        {'configuration': TCPControlThresholdConfiguration('tcp', '1', TCPControlMetric.FORWARD_SYN, 0)}):
            with self.assertRaises((TypeError, ValueError)):
                positive(replace(first, **changes))

    def test_invalid_detector_id_and_version_use_existing_configuration_errors(self):
        configs = (packet_target().configuration, flow_target().configuration,
                   TCPControlThresholdConfiguration('tcp', '1', TCPControlMetric.FORWARD_SYN, 0))
        for config in configs:
            for name in ('detector_id', 'detector_version'):
                for value in ('', '  ', None, 1):
                    with self.assertRaises((TypeError, ValueError)):
                        replace(config, **{name: value})

    def test_permitted_metadata_values_are_not_normalized_or_overvalidated(self):
        config = PacketIntegrityConfiguration(' integrity ', ' version ')
        target = packet_target(configuration=config, capture_source=' external ', packet_index=100,
                               captured_length=0, original_length=0, link_type=65535)
        record = negative(target)
        self.assertIs(record.target.configuration, config)
        self.assertEqual(record.target.capture_source, ' external ')
        self.assertEqual(record.target.configuration.detector_id, ' integrity ')
        self.assertEqual((record.target.packet_index, record.target.link_type), (100, 65535))

    def test_duplicate_positive_targets_are_rejected_without_deduplication(self):
        records = (positive(packet_target()), positive(packet_target()))
        with self.assertRaisesRegex(ValueError, 'packet_records contains a duplicate target'):
            GroundTruth(records, ())
        self.assertEqual(len(records), 2)

    def test_duplicate_negative_targets_are_rejected_without_multiplicity(self):
        records = (negative(flow_target()), negative(flow_target()))
        with self.assertRaisesRegex(ValueError, 'flow_records contains a duplicate target'):
            GroundTruth((), records)
        self.assertEqual(len(records), 2)

    def test_contradictory_labels_rejected_in_both_orders_and_domains(self):
        for target in (packet_target(), flow_target()):
            for records in ((positive(target), negative(target)), (negative(target), positive(target))):
                with self.assertRaisesRegex(ValueError, 'contradictory labels'):
                    GroundTruth(records if type(target) is PacketDetectionIdentity else (),
                                records if type(target) is FlowDetectionIdentity else ())

    def test_caller_owned_mutable_collections_are_rejected_without_mutation(self):
        record = positive(packet_target())
        for container in ([record], {'record': record}):
            before = container.copy()
            with self.assertRaisesRegex(TypeError, 'packet_records must be exactly a tuple'):
                GroundTruth(container, ())
            self.assertEqual(container, before)
        flow_records = [negative(flow_target())]
        with self.assertRaisesRegex(TypeError, 'flow_records must be exactly a tuple'):
            GroundTruth((), flow_records)
        self.assertEqual(len(flow_records), 1)

    def test_record_type_validation_rejects_expectations_and_missing_values(self):
        for value in (None, packet_target(), ExpectedDetection(packet_target(), True), {'target': packet_target()}):
            with self.assertRaisesRegex(TypeError, 'GroundTruthRecord values'):
                GroundTruth((value,), ())

    def test_input_order_and_exact_record_references_are_preserved(self):
        packets = (positive(packet_target(packet_index=5)), negative(packet_target(packet_index=1)))
        flows = (negative(flow_target(window_key=FlowObservationWindowKey('session', 3))),
                 positive(flow_target(window_key=FlowObservationWindowKey('session', 0))))
        truth = GroundTruth(packets, flows)
        self.assertIs(truth.packet_records, packets)
        self.assertIs(truth.flow_records, flows)
        self.assertEqual([r.target.packet_index for r in truth.packet_records], [5, 1])
        self.assertEqual([r.target.window_key.sequence_number for r in truth.flow_records], [3, 0])
        self.assertIs(truth.packet_records[0], packets[0])
        self.assertIs(truth.flow_records[1], flows[1])

    def test_repeated_construction_has_no_hidden_state_even_after_validation_failure(self):
        first = GroundTruth((positive(packet_target()),), (negative(flow_target()),))
        with self.assertRaises(ValueError):
            GroundTruth((positive(packet_target()), negative(packet_target())), ())
        self.assertEqual(GroundTruth((), ()), GroundTruth((), ()))
        self.assertEqual(first, GroundTruth((positive(packet_target()),), (negative(flow_target()),)))

    def test_truth_contains_no_finding_result_or_implementation_state(self):
        record = positive(flow_target())
        self.assertEqual(tuple(field.name for field in fields(record)), ('target', 'polarity'))
        self.assertEqual(tuple(field.name for field in fields(GroundTruth)), ('packet_records', 'flow_records'))
        self.assertFalse(hasattr(record.target, 'finding'))
        self.assertFalse(hasattr(record.target, 'snapshot'))
        self.assertFalse(hasattr(record.target, 'observed_value'))
        self.assertFalse(hasattr(record.target, 'decision'))

    def test_existing_detection_result_and_evidence_are_unchanged(self):
        finding = packet_finding()
        result = DetectionPipelineResult((finding,), ())
        before = DetectionPipelineResult((packet_finding(),), ())
        truth = GroundTruth((negative(packet_target()),), ())
        self.assertEqual(result, before)
        self.assertIs(result.packet_findings[0], finding)
        self.assertIs(truth.packet_records[0].polarity, GroundTruthPolarity.NEGATIVE)
        with self.assertRaises(TypeError):
            GroundTruthRecord(finding, GroundTruthPolarity.POSITIVE)

    def test_truth_has_no_automatic_expectation_conversion(self):
        truth = GroundTruth((positive(packet_target()),), ())
        with self.assertRaisesRegex(TypeError, 'expected must be exactly an ExpectedDetectionResult'):
            evaluate_detection_result(DetectionPipelineResult((), ()), truth)
        with self.assertRaises(TypeError):
            ExpectedDetectionResult(truth.packet_records, ())

    def test_construction_is_pure_without_finding_inference_or_external_access(self):
        with ExitStack() as stack:
            mocks = []
            for target in ('application.detection_evaluation.detection_identity',
                           'application.detection_evaluation.evaluate_detection_result',
                           'application.detection_evaluation.ExpectedDetection',
                           'application.detection_evaluation.ExpectedDetectionResult',
                           'application.detection_pipeline.run_detection_pipeline',
                           'application.capture_execution.run_capture_execution',
                           'application.detection_session.DetectionSession', 'application.cli.main',
                           'analysis.packet_analysis.analyze_packet', 'analysis.packet_analysis_outcome.analyze_packet_outcome',
                           'analysis.flow_feature_snapshot.extract_flow_feature_snapshot',
                           'capture.packet_ingestion.consume', 'capture.pcap_packet_source.PcapPacketSource.start',
                           'detection.packet_integrity.evaluate_packet_integrity',
                           'detection.flow_volume_threshold.evaluate_flow_volume_threshold',
                           'detection.tcp_control_threshold.evaluate_tcp_control_threshold',
                           'detection.detection_finding.DetectionFinding', 'builtins.open', 'socket.socket'):
                mocks.append(stack.enter_context(patch(target, side_effect=AssertionError(target))))
            for target in ('capture.packet_observation.PacketObservation.raw_bytes', 'analysis.ipv6.IPv6Packet.payload'):
                mocks.append(stack.enter_context(patch(target, new_callable=PropertyMock, create=True, side_effect=AssertionError(target))))
            truth = GroundTruth((positive(packet_target()),), (negative(flow_target(ipv6=True)),))
            for mock in mocks:
                mock.assert_not_called()
        self.assertIs(truth.packet_records[0].polarity, GroundTruthPolarity.POSITIVE)
        self.assertEqual(truth.flow_records[0].target.flow_identity.ip_version, 6)

    def test_public_exports_resolve_to_ground_truth_contracts(self):
        for model in (GroundTruth, GroundTruthRecord, GroundTruthPolarity):
            self.assertIs(getattr(application, model.__name__), model)
            self.assertIn(model.__name__, application.__all__)


if __name__ == '__main__':
    unittest.main()
