import gc
import hashlib
import os
import random
import subprocess
import sys
import unittest
import weakref
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import PropertyMock, patch

from analysis import (
    DirectionalIPv6FlowLabelStatistics,
    FlowIdentityError,
    FlowStateCoordinator,
    IPV6_FLOW_LABEL_MAX_BINS,
    IPV6_FLOW_LABEL_VALUES,
    IPv6FlowLabelStatistics,
    IPv6Packet,
    analyze_packet,
    extract_flow_feature_snapshot,
    flow_identity_from_packet,
    update_directional_ipv6_flow_label_statistics,
)
from analysis.flow_direction import FlowDirectionError
from analysis.flow_observation_window import FlowObservationWindow, FlowObservationWindowUpdate
from analysis.flow_state_coordinator import CoordinatedFlowState
from application import GroundTruth, run_end_to_end_validation, run_flow_observation_session
from capture import PcapPacketSource
from tests.pcap_scenarios import frame, pcap_bytes, transport
from tests.protocol_scenarios import observation
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_icmp_flow_admission import icmp4, icmp6, manager
from tests.test_ipv4_header_statistics import ipv4

MAXIMUM = IPV6_FLOW_LABEL_VALUES - 1


def ipv6(protocol=17, flow_label=0, reverse=False, seconds=0, payload=b'data', traffic_class=None):
    if protocol == 58:
        raw = bytearray(icmp6(reverse=reverse).raw_bytes)
    else:
        raw = bytearray(frame(protocol, transport(protocol, payload, True, reverse), True, reverse))
    raw[15] = raw[15] & 0xF0 | flow_label >> 16
    raw[16] = flow_label >> 8 & 0xFF
    raw[17] = flow_label & 0xFF
    if traffic_class is not None:
        raw[14] = raw[14] & 0xF0 | traffic_class >> 4
        raw[15] = raw[15] & 0x0F | (traffic_class & 0x0F) << 4
    return observation(bytes(raw), seconds)


def update(current, analysis, identity=None):
    identity = flow_identity_from_packet(analysis) if identity is None else identity
    return update_directional_ipv6_flow_label_statistics(current, analysis, identity)


def record(sources):
    instance = manager()
    window = None
    for index, source in enumerate(sources):
        source = replace(source, captured_at=source.captured_at + timedelta(milliseconds=index))
        window = instance.record(analyze_packet(source)).active_window
    return window.ipv6_flow_label_statistics


def tampered(value, **changes):
    copy = replace(value)
    for name, item in changes.items():
        object.__setattr__(copy, name, item)
    return copy


def summarize(value):
    return asdict(value), (value.forward.packet_count, value.reverse.packet_count)


def replay_digest():
    instance = manager(capacity=3)
    events = []
    for source in (ipv6(flow_label=0xABCDE, seconds=0), ipv6(flow_label=3, reverse=True, seconds=1),
                   ipv4(dscp=46, seconds=2), ipv6(6, flow_label=MAXIMUM, seconds=3), icmp4(seconds=4),
                   ipv6(58, flow_label=1, seconds=5), ipv6(6, flow_label=0, reverse=True, seconds=6),
                   ipv6(flow_label=0xABCDE, seconds=7), ipv6(flow_label=77, seconds=20)):
        result = instance.record(analyze_packet(source))
        events.extend((window.key.sequence_number, window.closure_reason.value,
                       summarize(window.ipv6_flow_label_statistics)) for window in result.closed_windows)
        events.append((result.active_window.key.sequence_number, None,
                       summarize(result.active_window.ipv6_flow_label_statistics)))
    closed = instance.close(instance.active_windows()[0].identity)
    events.append((closed.key.sequence_number, closed.closure_reason.value, summarize(closed.ipv6_flow_label_statistics)))
    events.extend((window.key.sequence_number, window.closure_reason.value, summarize(window.ipv6_flow_label_statistics))
                  for window in instance.end_capture_session())
    return hashlib.sha256(repr(events).encode()).hexdigest()


class IPv6FlowLabelStatisticsTests(unittest.TestCase):
    def test_empty_aggregate_and_ipv4_flows(self):
        empty = IPv6FlowLabelStatistics()
        self.assertEqual((empty.flow_label_counts, empty.saturated_packet_count, empty.saturated, empty.packet_count), ((), 0, False, 0))
        self.assertEqual(DirectionalIPv6FlowLabelStatistics(), DirectionalIPv6FlowLabelStatistics(empty, empty))
        for source in (ipv4(dscp=46, ecn=2), icmp4()):
            analysis = analyze_packet(source)
            current = update(None, analysis)
            self.assertEqual(current, DirectionalIPv6FlowLabelStatistics())
            self.assertIs(update(current, analysis), current)
            self.assertEqual(manager().record(analysis).active_window.ipv6_flow_label_statistics,
                             DirectionalIPv6FlowLabelStatistics())

    def test_single_packet_for_each_admitted_ipv6_protocol(self):
        for protocol in (6, 17, 58):
            with self.subTest(protocol=protocol):
                value = record((ipv6(protocol, flow_label=0x12345),))
                self.assertEqual(value.forward.flow_label_counts, ((0x12345, 1),))
                self.assertEqual(value.reverse, IPv6FlowLabelStatistics())

    def test_zero_is_an_observed_value_distinct_from_empty(self):
        value = record((ipv6(flow_label=0),))
        self.assertEqual(value.forward.flow_label_counts, ((0, 1),))
        self.assertNotEqual(value.forward, IPv6FlowLabelStatistics())
        self.assertEqual((value.forward.packet_count, value.reverse.packet_count), (1, 0))

    def test_decoded_value_is_the_complete_twenty_bit_field(self):
        values = (0, 1, 2, 0xFFFF, 0x10000, 0x7FFFF, 0x80000, 0xFFFFE, MAXIMUM)
        for flow_label in values:
            for traffic_class in (0, 255):
                packet = analyze_packet(ipv6(flow_label=flow_label, traffic_class=traffic_class)).ipv6
                self.assertEqual((packet.flow_label, packet.traffic_class), (flow_label, traffic_class))
        value = record((ipv6(flow_label=MAXIMUM, traffic_class=255), ipv6(flow_label=0, traffic_class=255),
                        ipv6(flow_label=MAXIMUM), ipv6(flow_label=MAXIMUM - 1), ipv6(flow_label=1)))
        self.assertEqual(value.forward.flow_label_counts, ((0, 1), (1, 1), (MAXIMUM - 1, 1), (MAXIMUM, 2)))
        self.assertEqual(value.forward.packet_count, 5)

    def test_ordering_is_independent_of_arrival_order(self):
        values = (500000, 3, MAXIMUM, 0, 262144, 3, 1, 1048574)
        forward = record([ipv6(flow_label=item) for item in values]).forward
        backward = record([ipv6(flow_label=item) for item in reversed(values)]).forward
        self.assertEqual(forward, backward)
        self.assertEqual(forward.flow_label_counts, ((0, 1), (1, 1), (3, 2), (262144, 1), (500000, 1),
                                                     (1048574, 1), (MAXIMUM, 1)))

    def test_directions_accumulate_separately_and_repeats_count(self):
        for protocol in (6, 17, 58):
            with self.subTest(protocol=protocol):
                value = record((ipv6(protocol, flow_label=10), ipv6(protocol, flow_label=10, reverse=True),
                                ipv6(protocol, flow_label=10), ipv6(protocol, flow_label=12, reverse=True),
                                ipv6(protocol, flow_label=10, reverse=True)))
                self.assertEqual(value.forward.flow_label_counts, ((10, 2),))
                self.assertEqual(value.reverse.flow_label_counts, ((10, 2), (12, 1)))

    def test_traffic_class_and_ipv4_statistics_stay_separate(self):
        window = manager().record(analyze_packet(ipv6(flow_label=0xABCDE, traffic_class=0xFF))).active_window
        self.assertEqual(window.ipv6_flow_label_statistics.forward.flow_label_counts, ((0xABCDE, 1),))
        self.assertEqual(window.ipv6_traffic_class_statistics.forward.traffic_class_counts, ((255, 1),))
        window = manager().record(analyze_packet(ipv4(dscp=46, ecn=2))).active_window
        self.assertEqual(window.ipv6_flow_label_statistics, DirectionalIPv6FlowLabelStatistics())

    def test_construction_validates_domain_order_and_bound(self):
        valid = IPv6FlowLabelStatistics(((0, 3), (MAXIMUM, 2)))
        self.assertEqual(valid.packet_count, 5)
        huge = 10 ** 100
        self.assertEqual(IPv6FlowLabelStatistics(((MAXIMUM, huge),)).packet_count, huge)
        self.assertEqual(IPv6FlowLabelStatistics(((0, 1),), 0).packet_count, 1)
        for counts, error in (([], TypeError), (((IPV6_FLOW_LABEL_VALUES, 1),), ValueError), (((-1, 1),), ValueError),
                              (((5, 1), (4, 1)), ValueError), (((5, 1), (5, 1)), ValueError),
                              (((5, 0),), ValueError), (((5, -1),), ValueError), (((True, 1),), TypeError),
                              (((5.0, 1),), TypeError), (((5, True),), TypeError), (((5, 1.0),), TypeError),
                              ((('5', 1),), TypeError), (((5,),), TypeError), (([5, 1],), TypeError),
                              ((None,) * (IPV6_FLOW_LABEL_MAX_BINS + 1), ValueError)):
            with self.subTest(counts=counts), self.assertRaises(error):
                IPv6FlowLabelStatistics(counts)
        full = tuple((index, 1) for index in range(IPV6_FLOW_LABEL_MAX_BINS))
        self.assertFalse(IPv6FlowLabelStatistics(full).saturated)
        saturated = IPv6FlowLabelStatistics((), IPV6_FLOW_LABEL_MAX_BINS + 1)
        self.assertEqual((saturated.saturated, saturated.flow_label_counts, saturated.packet_count),
                         (True, (), IPV6_FLOW_LABEL_MAX_BINS + 1))
        self.assertEqual(IPv6FlowLabelStatistics((), huge).packet_count, huge)
        for counts, packets, error in ((full, 300, ValueError), (full[:1], 300, ValueError), ((), -1, ValueError),
                                       ((), 1, ValueError), ((), IPV6_FLOW_LABEL_MAX_BINS, ValueError),
                                       ((), True, TypeError), ((), 300.0, TypeError), ((), None, TypeError)):
            with self.subTest(counts=len(counts), packets=packets), self.assertRaises(error):
                IPv6FlowLabelStatistics(counts, packets)
        with self.assertRaises(TypeError):
            DirectionalIPv6FlowLabelStatistics(forward=None)
        with self.assertRaises(TypeError):
            DirectionalIPv6FlowLabelStatistics(reverse=asdict(valid))

    def test_malformed_sources_family_mixing_and_identities_cannot_publish(self):
        source = analyze_packet(ipv6(flow_label=46))
        identity = flow_identity_from_packet(source)
        for current, analysis, key in (([], source, identity), (IPv6FlowLabelStatistics(), source, identity),
                                       (None, None, identity), (None, source, None), (None, source, asdict(identity))):
            with self.assertRaises(TypeError):
                update_directional_ipv6_flow_label_statistics(current, analysis, key)
        with self.assertRaises(FlowDirectionError):
            update(None, source, replace(identity, source_port=1))
        cases = []
        for name, value, error in (('flow_label', IPV6_FLOW_LABEL_VALUES, ValueError), ('flow_label', -1, ValueError),
                                   ('version', 4, ValueError), ('flow_label', True, TypeError),
                                   ('flow_label', None, TypeError), ('flow_label', '5', TypeError),
                                   ('flow_label', 1.0, TypeError)):
            cases.append((tampered(source, ipv6=tampered(source.ipv6, **{name: value})), error))
        cases.append((tampered(source, ipv6=object()), TypeError))
        cases.append((tampered(source, ipv6=None), TypeError))
        cases.append((tampered(source, ipv4=analyze_packet(ipv4()).ipv4), ValueError))
        for index, (analysis, error) in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(error):
                update(None, analysis, identity)
        v4 = analyze_packet(ipv4())
        with self.assertRaisesRegex(ValueError, 'IPv4 flows'):
            update(None, tampered(v4, ipv6=source.ipv6), flow_identity_from_packet(v4))
        instance = manager()
        first = instance.record(source).active_window
        for analysis in (cases[0][0], cases[2][0]):
            with self.assertRaises(ValueError):
                instance.record(analysis)
            self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
        with self.assertRaises(FlowIdentityError):
            instance.record(analyze_packet(ipv6(143)))
        self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)

    def test_reducer_reads_no_bytes_parsers_or_payload(self):
        analysis = analyze_packet(ipv6(6, flow_label=0xABCDE, payload=bytes(200)))
        identity = flow_identity_from_packet(analysis)
        expected = update(None, analysis, identity)
        with patch.object(IPv6Packet, 'payload', new_callable=PropertyMock, create=True,
                          side_effect=AssertionError('payload')), \
                patch('analysis.ipv6.decode_ipv6', side_effect=AssertionError('decode')), \
                patch.object(IPv6Packet, '__post_init__', side_effect=AssertionError('rebuild')):
            self.assertEqual(update_directional_ipv6_flow_label_statistics(None, analysis, identity), expected)

    def test_failed_candidates_and_publication_retry_count_once(self):
        for target in (CoordinatedFlowState, FlowObservationWindowUpdate):
            with self.subTest(target=target.__name__):
                instance = manager()
                first = instance.record(analyze_packet(ipv6(flow_label=46))).active_window
                reply = analyze_packet(ipv6(flow_label=7, reverse=True, seconds=1))
                for _ in range(2):
                    with patch.object(target, '__post_init__', side_effect=MemoryError('publication')):
                        with self.assertRaises(MemoryError):
                            instance.record(reply)
                    self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
                accepted = instance.record(reply).active_window.ipv6_flow_label_statistics
                self.assertEqual(accepted.reverse.flow_label_counts, ((7, 1),))
                repeated = instance.record(reply).active_window.ipv6_flow_label_statistics
                self.assertEqual(repeated.reverse.flow_label_counts, ((7, 2),))
                self.assertEqual(first.ipv6_flow_label_statistics.reverse, IPv6FlowLabelStatistics())
        instance = manager()
        with patch('analysis.ipv6_flow_label_statistics._increment', side_effect=MemoryError('allocation')):
            with self.assertRaises(MemoryError):
                instance.record(analyze_packet(ipv6()))
        self.assertEqual(instance.active_windows(), ())
        retried = instance.record(analyze_packet(ipv6())).active_window
        self.assertEqual((retried.key.sequence_number, retried.ipv6_flow_label_statistics.forward.packet_count), (0, 1))

    def test_every_closure_reason_preserves_aggregate_and_replacement_starts_empty(self):
        for reason in ('explicit_segmentation', 'capture_session_end', 'inactivity', 'capacity'):
            with self.subTest(reason=reason):
                instance = manager(capacity=1)
                instance.record(analyze_packet(ipv6(flow_label=46)))
                published = instance.record(analyze_packet(ipv6(flow_label=46, reverse=True, seconds=1))).active_window
                if reason == 'explicit_segmentation':
                    closed = instance.close(published.identity)
                    replacement = instance.record(analyze_packet(ipv6(flow_label=8, seconds=2))).active_window
                elif reason == 'capture_session_end':
                    closed, = instance.end_capture_session()
                    replacement = None
                else:
                    later = ipv6(flow_label=8, seconds=7) if reason == 'inactivity' else ipv6(6, flow_label=8, seconds=2)
                    result = instance.record(analyze_packet(later))
                    closed, = result.closed_windows
                    replacement = result.active_window
                self.assertEqual(closed.closure_reason.value, reason)
                self.assertIs(closed.ipv6_flow_label_statistics, published.ipv6_flow_label_statistics)
                if replacement is not None:
                    self.assertEqual(replacement.ipv6_flow_label_statistics.forward.flow_label_counts, ((8, 1),))
                    self.assertEqual(replacement.ipv6_flow_label_statistics.reverse, IPv6FlowLabelStatistics())
        instance = manager()
        first = instance.record(analyze_packet(ipv6())).active_window
        with patch.object(FlowObservationWindow, '__post_init__', side_effect=MemoryError('closure')):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        closed, = instance.end_capture_session()
        self.assertIs(closed.ipv6_flow_label_statistics, first.ipv6_flow_label_statistics)

    def test_immutability_and_snapshot_stability(self):
        instance = manager()
        first = instance.record(analyze_packet(ipv6(flow_label=46))).active_window
        statistics = extract_flow_feature_snapshot(first).coordinated_state.ipv6_flow_label_statistics
        with self.assertRaises(FrozenInstanceError):
            statistics.forward = IPv6FlowLabelStatistics()
        with self.assertRaises(FrozenInstanceError):
            statistics.forward.flow_label_counts = ()
        with self.assertRaises(FrozenInstanceError):
            statistics.forward.saturated_packet_count = 300
        with self.assertRaises(TypeError):
            statistics.forward.flow_label_counts[0] = (46, 2)
        for index in range(1, 50):
            instance.record(analyze_packet(ipv6(flow_label=index, seconds=index / 1000)))
        self.assertEqual(statistics.forward.flow_label_counts, ((46, 1),))
        self.assertEqual(tuple(vars(statistics.forward)), ('flow_label_counts', 'saturated_packet_count'))

    def test_saturation_thresholds_and_transition(self):
        limit = IPV6_FLOW_LABEL_MAX_BINS
        labels = [(index * 4099) % IPV6_FLOW_LABEL_VALUES for index in range(limit + 1)]
        for distinct in (limit - 1, limit):
            value = record([ipv6(flow_label=item) for item in labels[:distinct]]).forward
            self.assertEqual((value.saturated, len(value.flow_label_counts), value.packet_count), (False, distinct, distinct))
            self.assertEqual(value.flow_label_counts, tuple(sorted((item, 1) for item in labels[:distinct])))
        value = record([ipv6(flow_label=item) for item in labels]).forward
        self.assertEqual((value.saturated, value.flow_label_counts, value.packet_count), (True, (), limit + 1))
        self.assertEqual(value, IPv6FlowLabelStatistics((), limit + 1))
        self.assertEqual(tuple(vars(value)), ('flow_label_counts', 'saturated_packet_count'))

    def test_saturation_is_permanent_and_counting_continues(self):
        limit = IPV6_FLOW_LABEL_MAX_BINS
        labels = list(range(limit + 1))
        instance = manager()
        window = None
        for index, item in enumerate(labels):
            window = instance.record(analyze_packet(ipv6(flow_label=item, seconds=index / 1000))).active_window
        self.assertTrue(window.ipv6_flow_label_statistics.forward.saturated)
        for index, item in enumerate((0, 0, 1048575, 5, limit + 500, 1)):
            window = instance.record(analyze_packet(ipv6(flow_label=item, seconds=1 + index / 1000))).active_window
            forward = window.ipv6_flow_label_statistics.forward
            self.assertEqual((forward.saturated, forward.flow_label_counts, forward.packet_count),
                             (True, (), limit + 2 + index))
        self.assertEqual(window.ipv6_flow_label_statistics.reverse, IPv6FlowLabelStatistics())

    def test_saturation_is_per_direction(self):
        limit = IPV6_FLOW_LABEL_MAX_BINS
        sources = [ipv6(flow_label=item) for item in range(limit + 1)] + [ipv6(flow_label=5, reverse=True),
                                                                          ipv6(flow_label=0, reverse=True)]
        value = record(sources)
        self.assertEqual((value.forward.saturated, value.forward.packet_count), (True, limit + 1))
        self.assertEqual((value.reverse.saturated, value.reverse.flow_label_counts), (False, ((0, 1), (5, 1))))

    def test_boundary_labels_participate_in_saturation(self):
        limit = IPV6_FLOW_LABEL_MAX_BINS
        middle = list(range(1000, 1000 + limit - 2))
        exact = record([ipv6(flow_label=item) for item in [0, MAXIMUM] + middle]).forward
        self.assertEqual((exact.saturated, exact.flow_label_counts[0], exact.flow_label_counts[-1]),
                         (False, (0, 1), (MAXIMUM, 1)))
        for extra in (0, MAXIMUM):
            labels = [item for item in (0, MAXIMUM) if item != extra] + middle + [extra, 5]
            self.assertTrue(record([ipv6(flow_label=item) for item in labels]).forward.saturated)

    def test_state_is_independent_of_arrival_order(self):
        limit = IPV6_FLOW_LABEL_MAX_BINS
        base = [(index * 4099) % IPV6_FLOW_LABEL_VALUES for index in range(limit + 1)]
        for distinct in (limit - 1, limit, limit + 1):
            population = base[:distinct] + base[:7] + [base[0]] * 3
            outcomes = set()
            for seed in range(6):
                shuffled = list(population)
                random.Random(seed).shuffle(shuffled)
                for ordering in (shuffled, sorted(shuffled), sorted(shuffled, reverse=True)):
                    outcomes.add(record([ipv6(flow_label=item) for item in ordering]).forward)
            with self.subTest(distinct=distinct):
                self.assertEqual(len(outcomes), 1)
                value, = outcomes
                self.assertEqual((value.saturated, value.packet_count), (distinct > limit, len(population)))
                if distinct > limit:
                    self.assertEqual(value.flow_label_counts, ())
                else:
                    self.assertEqual(sum(count for _, count in value.flow_label_counts), len(population))

    def test_reducer_is_independent_of_arrival_order_in_both_directions(self):
        limit = IPV6_FLOW_LABEL_MAX_BINS
        population = [(index * 7919) % IPV6_FLOW_LABEL_VALUES for index in range(limit + 40)]
        results = set()
        for seed in range(5):
            ordering = list(population)
            random.Random(seed).shuffle(ordering)
            current = None
            for item in ordering:
                analysis = analyze_packet(ipv6(flow_label=item))
                current = update(current, analysis)
            results.add(current)
        self.assertEqual(len(results), 1)
        self.assertTrue(next(iter(results)).forward.saturated)

    def test_failed_saturation_transition_is_atomic_and_retries_once(self):
        limit = IPV6_FLOW_LABEL_MAX_BINS
        for target in (CoordinatedFlowState, FlowObservationWindowUpdate):
            with self.subTest(target=target.__name__):
                instance = manager()
                for item in range(limit):
                    first = instance.record(analyze_packet(ipv6(flow_label=item, seconds=item / 1000))).active_window
                trigger = analyze_packet(ipv6(flow_label=limit, seconds=1))
                for _ in range(2):
                    with patch.object(target, '__post_init__', side_effect=MemoryError('publication')):
                        with self.assertRaises(MemoryError):
                            instance.record(trigger)
                    self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
                    self.assertEqual(len(first.ipv6_flow_label_statistics.forward.flow_label_counts), limit)
                with patch('analysis.ipv6_flow_label_statistics.IPv6FlowLabelStatistics',
                           side_effect=MemoryError('allocation')):
                    with self.assertRaises(MemoryError):
                        instance.record(trigger)
                self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
                accepted = instance.record(trigger).active_window.ipv6_flow_label_statistics.forward
                self.assertEqual((accepted.saturated, accepted.packet_count), (True, limit + 1))
                again = instance.record(trigger).active_window.ipv6_flow_label_statistics.forward
                self.assertEqual(again.packet_count, limit + 2)
                self.assertFalse(first.ipv6_flow_label_statistics.forward.saturated)

    def test_saturated_state_survives_snapshots_closure_and_replacement(self):
        limit = IPV6_FLOW_LABEL_MAX_BINS
        instance = manager()
        for item in range(limit + 1):
            window = instance.record(analyze_packet(ipv6(flow_label=item, seconds=item / 1000))).active_window
        snapshot = extract_flow_feature_snapshot(window).coordinated_state.ipv6_flow_label_statistics
        self.assertEqual(snapshot.forward, IPv6FlowLabelStatistics((), limit + 1))
        closed = instance.close(window.identity)
        self.assertIs(closed.ipv6_flow_label_statistics, window.ipv6_flow_label_statistics)
        replacement = instance.record(analyze_packet(ipv6(flow_label=1, seconds=3))).active_window
        self.assertEqual(replacement.ipv6_flow_label_statistics.forward, IPv6FlowLabelStatistics(((1, 1),)))
        self.assertEqual(snapshot.forward.packet_count, limit + 1)

    def test_published_statistics_release_packet_and_model_sources(self):
        source = analyze_packet(ipv6(6, flow_label=46))
        references = tuple(weakref.ref(item) for item in (source, source.ipv6, source.ethernet, source.observation))
        state = FlowStateCoordinator().record(source)
        del source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(state.ipv6_flow_label_statistics.forward.flow_label_counts, ((46, 1),))
        self.assertTrue(all(type(value) is int for item in state.ipv6_flow_label_statistics.forward.flow_label_counts
                            for value in item))

    def test_detection_and_other_flow_results_are_unchanged(self):
        sources = (ipv6(flow_label=184, seconds=1), ipv6(flow_label=3, reverse=True, seconds=2),
                   ipv6(6, flow_label=MAXIMUM, seconds=3), ipv6(58, flow_label=1, seconds=4),
                   ipv4(dscp=46, seconds=5))
        arguments = dict(configuration=settings(), capture_session_id='ipv6-flow-label', ground_truth=GroundTruth((), ()))
        actual = run_end_to_end_validation(MemoryPacketSource(sources), **arguments)
        with patch('analysis.flow_state_coordinator.update_directional_ipv6_flow_label_statistics',
                   return_value=DirectionalIPv6FlowLabelStatistics()):
            baseline = run_end_to_end_validation(MemoryPacketSource(sources), **arguments)
        self.assertEqual(actual.report.metrics, baseline.report.metrics)
        self.assertEqual(actual.pipeline_result.packet_findings, baseline.pipeline_result.packet_findings)
        self.assertEqual(len(actual.pipeline_result.flow_findings), len(baseline.pipeline_result.flow_findings))
        observed = []
        for left, right in zip(actual.pipeline_result.flow_findings, baseline.pipeline_result.flow_findings):
            self.assertEqual(left.decision, right.decision)
            if left.detector_id != 'volume':
                continue
            left_state, right_state = left.raw_evidence.snapshot.coordinated_state, right.raw_evidence.snapshot.coordinated_state
            self.assertEqual(replace(left_state, ipv6_flow_label_statistics=DirectionalIPv6FlowLabelStatistics()),
                             right_state)
            observed.append((left_state.identity.ip_version, left_state.identity.protocol,
                             left_state.ipv6_flow_label_statistics.forward.packet_count))
        self.assertTrue(observed)

    def test_capture_sessions_match_across_all_classic_pcap_encodings(self):
        sources = (ipv6(flow_label=184, seconds=0), ipv6(flow_label=3, reverse=True, seconds=1),
                   ipv6(6, flow_label=MAXIMUM, seconds=2), ipv6(58, flow_label=0, seconds=3),
                   ipv4(dscp=46, seconds=4))
        expected = []
        run_flow_observation_session(MemoryPacketSource(sources), capture_session_id='ipv6-flow-label',
                                     inactivity_timeout=timedelta(seconds=60), closed_window_consumer=expected.append)
        self.assertEqual([(window.identity.ip_version, window.identity.protocol,
                           window.ipv6_flow_label_statistics.forward.flow_label_counts,
                           window.ipv6_flow_label_statistics.reverse.flow_label_counts) for window in expected], [
            (6, 17, ((184, 1),), ((3, 1),)), (6, 6, ((MAXIMUM, 1),), ()), (6, 58, ((0, 1),), ()), (4, 17, (), ())])
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'ipv6-flow-label.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes)
                                                          for index, item in enumerate(sources)), order, nano))
                        source = PcapPacketSource(path)
                        actual = []
                        run_flow_observation_session(source, capture_session_id='ipv6-flow-label',
                                                     inactivity_timeout=timedelta(seconds=60),
                                                     closed_window_consumer=actual.append)
                        self.assertEqual(actual, expected)
                        self.assertIsNone(source._file)

    def test_established_seed_timezone_replay_matrix(self):
        expected = replay_digest()
        script = 'from tests.test_ipv6_flow_label_statistics import replay_digest; print(replay_digest())'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                actual = subprocess.check_output([sys.executable, '-B', '-c', script], cwd=Path(__file__).parents[1],
                                                 env=dict(os.environ, PYTHONHASHSEED=seed, TZ=zone, PYTHONPATH='src'),
                                                 text=True).strip()
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
