import gc
import hashlib
import os
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
    DirectionalIPv6TrafficClassStatistics,
    FlowIdentityError,
    FlowStateCoordinator,
    IPV6_TRAFFIC_CLASS_BINS,
    IPv6Packet,
    IPv6TrafficClassStatistics,
    analyze_packet,
    extract_flow_feature_snapshot,
    flow_identity_from_packet,
    update_directional_ipv6_traffic_class_statistics,
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


def ipv6(protocol=17, traffic_class=0, reverse=False, seconds=0, payload=b'data'):
    if protocol == 58:
        raw = bytearray(icmp6(reverse=reverse).raw_bytes)
    else:
        raw = bytearray(frame(protocol, transport(protocol, payload, True, reverse), True, reverse))
    raw[14] = raw[14] & 0xF0 | traffic_class >> 4
    raw[15] = raw[15] & 0x0F | (traffic_class & 0x0F) << 4
    return observation(bytes(raw), seconds)


def update(current, analysis, identity=None):
    identity = flow_identity_from_packet(analysis) if identity is None else identity
    return update_directional_ipv6_traffic_class_statistics(current, analysis, identity)


def record(sources):
    instance = manager()
    window = None
    for index, source in enumerate(sources):
        source = replace(source, captured_at=source.captured_at + timedelta(milliseconds=index))
        window = instance.record(analyze_packet(source)).active_window
    return window.ipv6_traffic_class_statistics


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
    for source in (ipv6(traffic_class=184, seconds=0), ipv6(traffic_class=3, reverse=True, seconds=1),
                   ipv4(dscp=46, seconds=2), ipv6(6, traffic_class=255, seconds=3), icmp4(seconds=4),
                   ipv6(58, traffic_class=1, seconds=5), ipv6(6, traffic_class=0, reverse=True, seconds=6),
                   ipv6(traffic_class=184, seconds=7), ipv6(traffic_class=77, seconds=20)):
        result = instance.record(analyze_packet(source))
        events.extend((window.key.sequence_number, window.closure_reason.value,
                       summarize(window.ipv6_traffic_class_statistics)) for window in result.closed_windows)
        events.append((result.active_window.key.sequence_number, None,
                       summarize(result.active_window.ipv6_traffic_class_statistics)))
    closed = instance.close(instance.active_windows()[0].identity)
    events.append((closed.key.sequence_number, closed.closure_reason.value, summarize(closed.ipv6_traffic_class_statistics)))
    events.extend((window.key.sequence_number, window.closure_reason.value, summarize(window.ipv6_traffic_class_statistics))
                  for window in instance.end_capture_session())
    return hashlib.sha256(repr(events).encode()).hexdigest()


class IPv6TrafficClassStatisticsTests(unittest.TestCase):
    def test_empty_aggregate_and_ipv4_flows(self):
        empty = IPv6TrafficClassStatistics()
        self.assertEqual((empty.traffic_class_counts, empty.packet_count), ((), 0))
        self.assertEqual(DirectionalIPv6TrafficClassStatistics(), DirectionalIPv6TrafficClassStatistics(empty, empty))
        for source in (ipv4(dscp=46, ecn=2), icmp4()):
            analysis = analyze_packet(source)
            current = update(None, analysis)
            self.assertEqual(current, DirectionalIPv6TrafficClassStatistics())
            self.assertIs(update(current, analysis), current)
            self.assertEqual(manager().record(analysis).active_window.ipv6_traffic_class_statistics,
                             DirectionalIPv6TrafficClassStatistics())

    def test_single_packet_for_each_admitted_ipv6_protocol(self):
        for protocol in (6, 17, 58):
            with self.subTest(protocol=protocol):
                value = record((ipv6(protocol, traffic_class=0xB8),))
                self.assertEqual(value.forward.traffic_class_counts, ((0xB8, 1),))
                self.assertEqual(value.reverse, IPv6TrafficClassStatistics())

    def test_decoded_value_is_the_complete_eight_bit_field(self):
        for traffic_class in (0, 1, 3, 4, 15, 16, 0x2E << 2 | 2, 0x80, 0xFC, 255):
            self.assertEqual(analyze_packet(ipv6(traffic_class=traffic_class)).ipv6.traffic_class, traffic_class)
        value = record((ipv6(traffic_class=0), ipv6(traffic_class=255), ipv6(traffic_class=0x2E << 2 | 2),
                        ipv6(traffic_class=0x2E << 2 | 2), ipv6(traffic_class=128)))
        self.assertEqual(value.forward.traffic_class_counts, ((0, 1), (128, 1), (186, 2), (255, 1)))
        self.assertEqual(value.forward.packet_count, 5)

    def test_all_values_are_bounded_by_the_wire_domain(self):
        sources = [ipv6(traffic_class=value) for value in range(255, -1, -1)] + [ipv6(traffic_class=0), ipv6(traffic_class=255)]
        value = record(sources).forward
        self.assertEqual(value.traffic_class_counts, tuple((item, 2 if item in (0, 255) else 1) for item in range(256)))
        self.assertEqual((len(value.traffic_class_counts), value.packet_count), (IPV6_TRAFFIC_CLASS_BINS, 258))
        repeated = record((ipv6(traffic_class=9), ipv6(traffic_class=9), ipv6(traffic_class=9)))
        self.assertEqual(repeated.forward.traffic_class_counts, ((9, 3),))

    def test_directions_accumulate_separately_and_repeats_count(self):
        for protocol in (6, 17, 58):
            with self.subTest(protocol=protocol):
                value = record((ipv6(protocol, traffic_class=10), ipv6(protocol, traffic_class=10, reverse=True),
                                ipv6(protocol, traffic_class=10), ipv6(protocol, traffic_class=12, reverse=True)))
                self.assertEqual(value.forward.traffic_class_counts, ((10, 2),))
                self.assertEqual(value.reverse.traffic_class_counts, ((10, 1), (12, 1)))

    def test_ipv4_dscp_statistics_stay_separate(self):
        instance = manager()
        instance.record(analyze_packet(ipv4(dscp=46, ecn=2)))
        window = instance.record(analyze_packet(ipv4(dscp=46, ecn=2, seconds=1))).active_window
        self.assertEqual(window.ipv4_header_statistics.forward.dscp_counts, ((46, 2),))
        self.assertEqual(window.ipv6_traffic_class_statistics, DirectionalIPv6TrafficClassStatistics())
        window = manager().record(analyze_packet(ipv6(traffic_class=46 << 2 | 2))).active_window
        self.assertEqual(window.ipv6_traffic_class_statistics.forward.traffic_class_counts, ((186, 1),))
        self.assertEqual(window.ipv4_header_statistics.forward.dscp_counts, ())

    def test_construction_validates_domain_and_order(self):
        valid = IPv6TrafficClassStatistics(((0, 3), (255, 2)))
        self.assertEqual(valid.packet_count, 5)
        huge = 10 ** 100
        self.assertEqual(IPv6TrafficClassStatistics(((255, huge),)).packet_count, huge)
        for counts, error in (([], TypeError), (((256, 1),), ValueError), (((-1, 1),), ValueError),
                              (((5, 1), (4, 1)), ValueError), (((5, 1), (5, 1)), ValueError),
                              (((5, 0),), ValueError), (((5, -1),), ValueError), (((True, 1),), TypeError),
                              (((5, 1.0),), TypeError), (((5,),), TypeError), (([5, 1],), TypeError),
                              ((None,) * 257, ValueError)):
            with self.subTest(counts=counts), self.assertRaises(error):
                IPv6TrafficClassStatistics(counts)
        with self.assertRaises(TypeError):
            DirectionalIPv6TrafficClassStatistics(forward=None)
        with self.assertRaises(TypeError):
            DirectionalIPv6TrafficClassStatistics(reverse=asdict(valid))

    def test_malformed_sources_family_mixing_and_identities_cannot_publish(self):
        source = analyze_packet(ipv6(traffic_class=46))
        identity = flow_identity_from_packet(source)
        for current, analysis, key in (([], source, identity), (IPv6TrafficClassStatistics(), source, identity),
                                       (None, None, identity), (None, source, None), (None, source, asdict(identity))):
            with self.assertRaises(TypeError):
                update_directional_ipv6_traffic_class_statistics(current, analysis, key)
        with self.assertRaises(FlowDirectionError):
            update(None, source, replace(identity, source_port=1))
        cases = []
        for name, value, error in (('traffic_class', 256, ValueError), ('traffic_class', -1, ValueError),
                                   ('version', 4, ValueError), ('traffic_class', True, TypeError),
                                   ('traffic_class', None, TypeError), ('traffic_class', '5', TypeError)):
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
        analysis = analyze_packet(ipv6(6, traffic_class=0xB8, payload=bytes(200)))
        identity = flow_identity_from_packet(analysis)
        expected = update(None, analysis, identity)
        with patch.object(IPv6Packet, 'payload', new_callable=PropertyMock, create=True,
                          side_effect=AssertionError('payload')), \
                patch('analysis.ipv6.decode_ipv6', side_effect=AssertionError('decode')), \
                patch.object(IPv6Packet, '__post_init__', side_effect=AssertionError('rebuild')):
            self.assertEqual(update_directional_ipv6_traffic_class_statistics(None, analysis, identity), expected)

    def test_failed_candidates_and_publication_retry_count_once(self):
        for target in (CoordinatedFlowState, FlowObservationWindowUpdate):
            with self.subTest(target=target.__name__):
                instance = manager()
                first = instance.record(analyze_packet(ipv6(traffic_class=46))).active_window
                reply = analyze_packet(ipv6(traffic_class=7, reverse=True, seconds=1))
                for _ in range(2):
                    with patch.object(target, '__post_init__', side_effect=MemoryError('publication')):
                        with self.assertRaises(MemoryError):
                            instance.record(reply)
                    self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
                accepted = instance.record(reply).active_window.ipv6_traffic_class_statistics
                self.assertEqual(accepted.reverse.traffic_class_counts, ((7, 1),))
                repeated = instance.record(reply).active_window.ipv6_traffic_class_statistics
                self.assertEqual(repeated.reverse.traffic_class_counts, ((7, 2),))
                self.assertEqual(first.ipv6_traffic_class_statistics.reverse, IPv6TrafficClassStatistics())
        instance = manager()
        with patch('analysis.ipv6_traffic_class_statistics._increment', side_effect=MemoryError('allocation')):
            with self.assertRaises(MemoryError):
                instance.record(analyze_packet(ipv6()))
        self.assertEqual(instance.active_windows(), ())
        retried = instance.record(analyze_packet(ipv6())).active_window
        self.assertEqual((retried.key.sequence_number, retried.ipv6_traffic_class_statistics.forward.packet_count), (0, 1))

    def test_every_closure_reason_preserves_aggregate_and_replacement_starts_empty(self):
        for reason in ('explicit_segmentation', 'capture_session_end', 'inactivity', 'capacity'):
            with self.subTest(reason=reason):
                instance = manager(capacity=1)
                instance.record(analyze_packet(ipv6(traffic_class=46)))
                published = instance.record(analyze_packet(ipv6(traffic_class=46, reverse=True, seconds=1))).active_window
                if reason == 'explicit_segmentation':
                    closed = instance.close(published.identity)
                    replacement = instance.record(analyze_packet(ipv6(traffic_class=8, seconds=2))).active_window
                elif reason == 'capture_session_end':
                    closed, = instance.end_capture_session()
                    replacement = None
                else:
                    later = ipv6(traffic_class=8, seconds=7) if reason == 'inactivity' else ipv6(6, traffic_class=8, seconds=2)
                    result = instance.record(analyze_packet(later))
                    closed, = result.closed_windows
                    replacement = result.active_window
                self.assertEqual(closed.closure_reason.value, reason)
                self.assertIs(closed.ipv6_traffic_class_statistics, published.ipv6_traffic_class_statistics)
                if replacement is not None:
                    self.assertEqual(replacement.ipv6_traffic_class_statistics.forward.traffic_class_counts, ((8, 1),))
                    self.assertEqual(replacement.ipv6_traffic_class_statistics.reverse, IPv6TrafficClassStatistics())
        instance = manager()
        first = instance.record(analyze_packet(ipv6())).active_window
        with patch.object(FlowObservationWindow, '__post_init__', side_effect=MemoryError('closure')):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        closed, = instance.end_capture_session()
        self.assertIs(closed.ipv6_traffic_class_statistics, first.ipv6_traffic_class_statistics)

    def test_immutability_snapshot_stability_and_bounded_state(self):
        instance = manager()
        first = instance.record(analyze_packet(ipv6(traffic_class=46))).active_window
        statistics = extract_flow_feature_snapshot(first).coordinated_state.ipv6_traffic_class_statistics
        with self.assertRaises(FrozenInstanceError):
            statistics.forward = IPv6TrafficClassStatistics()
        with self.assertRaises(FrozenInstanceError):
            statistics.forward.traffic_class_counts = ()
        with self.assertRaises(TypeError):
            statistics.forward.traffic_class_counts[0] = (46, 2)
        for index in range(1, 2049):
            window = instance.record(analyze_packet(ipv6(traffic_class=index % 256, seconds=index / 1000))).active_window
        self.assertEqual(statistics.forward.traffic_class_counts, ((46, 1),))
        current = window.ipv6_traffic_class_statistics.forward
        self.assertEqual((current.packet_count, len(current.traffic_class_counts)), (2049, 256))
        self.assertEqual(tuple(vars(current)), ('traffic_class_counts',))

    def test_published_statistics_release_packet_and_model_sources(self):
        source = analyze_packet(ipv6(6, traffic_class=46))
        references = tuple(weakref.ref(item) for item in (source, source.ipv6, source.ethernet, source.observation))
        state = FlowStateCoordinator().record(source)
        del source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(state.ipv6_traffic_class_statistics.forward.traffic_class_counts, ((46, 1),))
        self.assertTrue(all(type(value) is int for item in state.ipv6_traffic_class_statistics.forward.traffic_class_counts
                            for value in item))

    def test_detection_and_other_flow_results_are_unchanged(self):
        sources = (ipv6(traffic_class=184, seconds=1), ipv6(traffic_class=3, reverse=True, seconds=2),
                   ipv6(6, traffic_class=255, seconds=3), ipv6(58, traffic_class=1, seconds=4),
                   ipv4(dscp=46, seconds=5))
        arguments = dict(configuration=settings(), capture_session_id='ipv6-traffic-class', ground_truth=GroundTruth((), ()))
        actual = run_end_to_end_validation(MemoryPacketSource(sources), **arguments)
        with patch('analysis.flow_state_coordinator.update_directional_ipv6_traffic_class_statistics',
                   return_value=DirectionalIPv6TrafficClassStatistics()):
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
            self.assertEqual(replace(left_state, ipv6_traffic_class_statistics=DirectionalIPv6TrafficClassStatistics()),
                             right_state)
            observed.append((left_state.identity.ip_version, left_state.identity.protocol,
                             left_state.ipv6_traffic_class_statistics.forward.packet_count))
        self.assertTrue(observed)

    def test_capture_sessions_match_across_all_classic_pcap_encodings(self):
        sources = (ipv6(traffic_class=184, seconds=0), ipv6(traffic_class=3, reverse=True, seconds=1),
                   ipv6(6, traffic_class=255, seconds=2), ipv6(58, traffic_class=1, seconds=3),
                   ipv4(dscp=46, seconds=4))
        expected = []
        run_flow_observation_session(MemoryPacketSource(sources), capture_session_id='ipv6-traffic-class',
                                     inactivity_timeout=timedelta(seconds=60), closed_window_consumer=expected.append)
        self.assertEqual([(window.identity.ip_version, window.identity.protocol,
                           window.ipv6_traffic_class_statistics.forward.traffic_class_counts,
                           window.ipv6_traffic_class_statistics.reverse.traffic_class_counts) for window in expected], [
            (6, 17, ((184, 1),), ((3, 1),)), (6, 6, ((255, 1),), ()), (6, 58, ((1, 1),), ()), (4, 17, (), ())])
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'ipv6-traffic-class.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes)
                                                          for index, item in enumerate(sources)), order, nano))
                        source = PcapPacketSource(path)
                        actual = []
                        run_flow_observation_session(source, capture_session_id='ipv6-traffic-class',
                                                     inactivity_timeout=timedelta(seconds=60),
                                                     closed_window_consumer=actual.append)
                        self.assertEqual(actual, expected)
                        self.assertIsNone(source._file)

    def test_established_seed_timezone_replay_matrix(self):
        expected = replay_digest()
        script = 'from tests.test_ipv6_traffic_class_statistics import replay_digest; print(replay_digest())'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                actual = subprocess.check_output([sys.executable, '-B', '-c', script], cwd=Path(__file__).parents[1],
                                                 env=dict(os.environ, PYTHONHASHSEED=seed, TZ=zone, PYTHONPATH='src'),
                                                 text=True).strip()
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
