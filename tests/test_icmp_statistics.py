import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import FrozenInstanceError, asdict, fields, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import PropertyMock, patch

from analysis import (
    DirectionalICMPStatistics,
    FlowIdentityError,
    FlowStateCoordinator,
    ICMP_TYPE_CODE_BINS,
    ICMPMessage,
    ICMPStatistics,
    ICMPv6Packet,
    IPv4Packet,
    IPv6Packet,
    analyze_packet,
    extract_flow_feature_snapshot,
    flow_identity_from_packet,
    update_directional_icmp_statistics,
)
from analysis.flow_direction import FlowDirectionError
from analysis.flow_observation_window import FlowObservationWindow, FlowObservationWindowUpdate
from analysis.flow_state_coordinator import CoordinatedFlowState
from application import GroundTruth, run_end_to_end_validation, run_flow_observation_session
from capture import PcapPacketSource
from tests.pcap_scenarios import pcap_bytes
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_icmp_flow_admission import icmp4, icmp6, manager, tcp, udp
from tests.test_ipv6_transport import observation_for


def update(current, analysis, identity=None):
    identity = flow_identity_from_packet(analysis) if identity is None else identity
    return update_directional_icmp_statistics(current, analysis, identity)


def record(sources):
    instance = manager()
    window = None
    for index, source in enumerate(sources):
        source = replace(source, captured_at=source.captured_at + timedelta(milliseconds=index))
        window = instance.record(analyze_packet(source)).active_window
    return window.icmp_statistics


def tampered(value, **changes):
    copy = replace(value) if type(value) is not ICMPv6Packet else value.__class__.__new__(value.__class__)
    if type(value) is ICMPv6Packet:
        for member in fields(value):
            object.__setattr__(copy, member.name, getattr(value, member.name))
    for name, item in changes.items():
        object.__setattr__(copy, name, item)
    return copy


def summarize(value):
    return (asdict(value), tuple((side.packet_count, side.distinct_type_code_count, side.type_counts,
                                  side.distinct_type_count) for side in (value.forward, value.reverse)))


def replay_digest():
    instance = manager(capacity=3)
    events = []
    for source in (icmp4(seconds=0), icmp4(0, reverse=True, seconds=1), icmp6(seconds=2), udp(seconds=3),
                   icmp4(3, seconds=4, code=13), icmp6(129, reverse=True, seconds=5), icmp4(8, 7, seconds=6),
                   tcp(seconds=7), icmp6(1, bytes(4), seconds=8, code=4), icmp6(3, bytes(4), seconds=9, code=1),
                   icmp6(2, bytes(4), reverse=True, seconds=20)):
        result = instance.record(analyze_packet(source))
        events.extend((window.key.sequence_number, window.closure_reason.value, summarize(window.icmp_statistics))
                      for window in result.closed_windows)
        events.append((result.active_window.key.sequence_number, None, summarize(result.active_window.icmp_statistics)))
    closed = instance.close(instance.active_windows()[0].identity)
    events.append((closed.key.sequence_number, closed.closure_reason.value, summarize(closed.icmp_statistics)))
    events.extend((window.key.sequence_number, window.closure_reason.value, summarize(window.icmp_statistics))
                  for window in instance.end_capture_session())
    return hashlib.sha256(repr(events).encode()).hexdigest()


class ICMPStatisticsTests(unittest.TestCase):
    def test_empty_aggregate_and_non_icmp_flows(self):
        empty = ICMPStatistics()
        self.assertEqual((empty.type_code_counts, empty.packet_count, empty.distinct_type_code_count,
                          empty.type_counts, empty.distinct_type_count), ((), 0, 0, (), 0))
        self.assertEqual(DirectionalICMPStatistics(), DirectionalICMPStatistics(empty, empty, None))
        for source in (tcp(), udp(), tcp(ipv6=True), udp(ipv6=True)):
            current = update(None, analyze_packet(source))
            self.assertEqual(current, DirectionalICMPStatistics())
            self.assertIs(update(current, analyze_packet(source)), current)
            self.assertEqual(manager().record(analyze_packet(source)).active_window.icmp_statistics, DirectionalICMPStatistics())

    def test_icmpv4_echo_exchange_is_directional(self):
        value = record((icmp4(8), icmp4(0, reverse=True), icmp4(8, sequence=2), icmp4(0, sequence=2, reverse=True),
                        icmp4(8, sequence=3)))
        self.assertEqual(value.protocol, 1)
        self.assertEqual(value.forward.type_code_counts, ((8, 0, 3),))
        self.assertEqual(value.reverse.type_code_counts, ((0, 0, 2),))
        self.assertEqual((value.forward.packet_count, value.reverse.packet_count), (3, 2))

    def test_icmpv4_types_and_codes_form_a_type_scoped_distribution(self):
        sources = [icmp4(3, code=code, payload=bytes(28)) for code in (3, 0, 13, 1, 3)]
        sources += [icmp4(11, code=1), icmp4(11, code=0), icmp4(5, code=1), icmp4(3, code=3, reverse=True)]
        value = record(sources)
        self.assertEqual(value.protocol, 1)
        self.assertEqual(value.forward.type_code_counts,
                         ((3, 0, 1), (3, 1, 1), (3, 3, 2), (3, 13, 1), (5, 1, 1), (11, 0, 1), (11, 1, 1)))
        self.assertEqual(value.forward.type_counts, ((3, 5), (5, 1), (11, 2)))
        self.assertEqual((value.forward.packet_count, value.forward.distinct_type_code_count,
                          value.forward.distinct_type_count), (8, 7, 3))
        self.assertEqual(value.reverse.type_code_counts, ((3, 3, 1),))

    def test_icmpv6_types_and_codes_are_recorded(self):
        echo = record((icmp6(128), icmp6(129, reverse=True), icmp6(128)))
        self.assertEqual((echo.protocol, echo.forward.type_code_counts, echo.reverse.type_code_counts),
                         (58, ((128, 0, 2),), ((129, 0, 1),)))
        sources = [icmp6(1, bytes(4), code=code) for code in (4, 0, 6, 4)]
        sources += [icmp6(icmp_type, bytes(16)) for icmp_type in (136, 2, 135, 133, 3)]
        sources += [icmp6(3, bytes(4), code=1, reverse=True), icmp6(4, bytes(4), code=2, reverse=True)]
        value = record(sources)
        self.assertEqual(value.protocol, 58)
        self.assertEqual(value.forward.type_code_counts,
                         ((1, 0, 1), (1, 4, 2), (1, 6, 1), (2, 0, 1), (3, 0, 1), (133, 0, 1), (135, 0, 1), (136, 0, 1)))
        self.assertEqual(value.forward.type_counts, ((1, 4), (2, 1), (3, 1), (133, 1), (135, 1), (136, 1)))
        self.assertEqual(value.reverse.type_code_counts, ((3, 1, 1), (4, 2, 1)))

    def test_icmpv4_and_icmpv6_values_never_share_an_aggregate(self):
        v4 = record((icmp4(3, code=1),))
        v6 = record((icmp6(3, bytes(4), code=1),))
        self.assertEqual(v4.forward.type_code_counts, v6.forward.type_code_counts)
        self.assertNotEqual(v4, v6)
        self.assertEqual((v4.protocol, v6.protocol), (1, 58))
        source = analyze_packet(icmp4(3, code=1))
        with self.assertRaisesRegex(ValueError, 'protocol must match'):
            update(v6, source)
        with self.assertRaises(ValueError):
            update(record((icmp4(),)), analyze_packet(tcp()))
        instance = manager()
        for index, item in enumerate((icmp4(3, code=1), icmp6(3, bytes(4), code=1))):
            instance.record(analyze_packet(replace(item, captured_at=item.captured_at + timedelta(seconds=index))))
        self.assertEqual(sorted(window.icmp_statistics.protocol for window in instance.active_windows()), [1, 58])

    def test_type_and_code_boundaries_from_decoded_packets(self):
        value = record((icmp4(0, code=0, reverse=True), icmp4(0, code=255, reverse=True), icmp4(8, code=255)))
        self.assertEqual(value.forward.type_code_counts, ((8, 255, 1),))
        self.assertEqual(value.reverse.type_code_counts, ((0, 0, 1), (0, 255, 1)))
        value = record((icmp4(255, code=255), icmp4(255, code=0), icmp4(254, code=255)))
        self.assertEqual(value.forward.type_code_counts, ((254, 255, 1), (255, 0, 1), (255, 255, 1)))
        value = record((icmp6(0, bytes(4), code=255), icmp6(255, bytes(4), code=0), icmp6(255, bytes(4), code=255)))
        self.assertEqual(value.forward.type_code_counts, ((0, 255, 1), (255, 0, 1), (255, 255, 1)))

    def test_distribution_cardinality_is_bounded_and_saturates(self):
        sources = [icmp6(icmp_type, bytes(4), code=code) for icmp_type in (1, 255) for code in range(255, -1, -1)]
        value = None
        for source in sources:
            value = update(value, analyze_packet(source))
        self.assertEqual(value.forward.distinct_type_code_count, 512)
        self.assertEqual(value.forward.type_code_counts,
                         tuple((icmp_type, code, 1) for icmp_type in (1, 255) for code in range(256)))
        full = ICMPStatistics(tuple((icmp_type, code, 1) for icmp_type in range(256) for code in range(256)))
        self.assertEqual(full.distinct_type_code_count, ICMP_TYPE_CODE_BINS)
        self.assertEqual(full.type_counts, tuple((icmp_type, 256) for icmp_type in range(256)))
        saturated = update(DirectionalICMPStatistics(full, ICMPStatistics(), 58), analyze_packet(sources[0]))
        self.assertEqual(saturated.forward.distinct_type_code_count, ICMP_TYPE_CODE_BINS)
        self.assertEqual(saturated.forward.packet_count, ICMP_TYPE_CODE_BINS + 1)
        with self.assertRaisesRegex(ValueError, 'exceeds'):
            ICMPStatistics((None,) * (ICMP_TYPE_CODE_BINS + 1))

    def test_construction_validates_types_ordering_and_protocol(self):
        for bins, error in (
            ([], TypeError), (((1, 0, 1), [2, 0, 1]), TypeError), (((1, 0),), TypeError), (((1, 0, 1, 1),), TypeError),
            (((True, 0, 1),), TypeError), (((1, False, 1),), TypeError), (((1, 0, 1.0),), TypeError),
            (((256, 0, 1),), ValueError), (((0, 256, 1),), ValueError), (((-1, 0, 1),), ValueError),
            (((1, 0, 0),), ValueError), (((1, 0, -1),), ValueError), (((2, 0, 1), (1, 0, 1)), ValueError),
            (((1, 2, 1), (1, 1, 1)), ValueError), (((1, 1, 1), (1, 1, 2)), ValueError),
        ):
            with self.subTest(bins=bins), self.assertRaises(error):
                ICMPStatistics(bins)
        huge = ICMPStatistics(((3, 1, 10 ** 100),))
        self.assertEqual(huge.packet_count, 10 ** 100)
        occupied = ICMPStatistics(((8, 0, 1),))
        for arguments, error in (
            ((occupied, ICMPStatistics(), None), ValueError), ((ICMPStatistics(), ICMPStatistics(), 1), ValueError),
            ((occupied, ICMPStatistics(), 6), ValueError), ((occupied, ICMPStatistics(), True), ValueError),
            ((occupied, ICMPStatistics(), '1'), ValueError), ((None, ICMPStatistics(), None), TypeError),
            ((ICMPStatistics(), (), None), TypeError),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(error):
                DirectionalICMPStatistics(*arguments)

    def test_values_and_published_snapshots_are_immutable(self):
        instance = manager()
        first = instance.record(analyze_packet(icmp4())).active_window
        snapshot = extract_flow_feature_snapshot(first)
        statistics = snapshot.coordinated_state.icmp_statistics
        with self.assertRaises(FrozenInstanceError):
            statistics.protocol = 58
        with self.assertRaises(FrozenInstanceError):
            statistics.forward.type_code_counts = ()
        with self.assertRaises(TypeError):
            statistics.forward.type_code_counts[0] = (8, 0, 2)
        with self.assertRaises(TypeError):
            statistics.forward.type_counts[0] = (8, 2)
        later = instance.record(analyze_packet(icmp4(0, reverse=True, seconds=1))).active_window
        self.assertEqual(snapshot.coordinated_state.icmp_statistics.forward.type_code_counts, ((8, 0, 1),))
        self.assertEqual(snapshot.coordinated_state.icmp_statistics.reverse, ICMPStatistics())
        self.assertEqual(later.icmp_statistics.reverse.type_code_counts, ((0, 0, 1),))

    def test_malformed_sources_and_identities_are_rejected_without_publication(self):
        v4 = analyze_packet(icmp4())
        v6 = analyze_packet(icmp6())
        identity = flow_identity_from_packet(v4)
        for current, analysis, key in (([], v4, identity), (ICMPStatistics(), v4, identity), (None, None, identity),
                                       (None, v4, None), (None, v4, asdict(identity))):
            with self.assertRaises(TypeError):
                update_directional_icmp_statistics(current, analysis, key)
        for key in (replace(identity, icmp_echo_identifier=1), replace(identity, destination_address=b'\xff' * 4)):
            with self.assertRaises(FlowDirectionError):
                update(None, v4, key)
        with self.assertRaises(FlowDirectionError):
            update(None, analyze_packet(icmp4(3)), identity)
        cases = (
            (tampered(v4, icmp=tampered(v4.icmp, icmp_type=256)), ValueError),
            (tampered(v4, icmp=tampered(v4.icmp, code=-1)), ValueError),
            (tampered(v4, icmp=tampered(v4.icmp, icmp_type=True)), TypeError),
            (tampered(v4, icmp=tampered(v4.icmp, code='0')), TypeError),
            (tampered(v4, icmp=None), TypeError),
            (tampered(v4, icmp=v6.ipv6_icmpv6), TypeError),
            (tampered(v6, ipv6_icmpv6=tampered(v6.ipv6_icmpv6, icmp_type=256)), ValueError),
            (tampered(v6, ipv6_icmpv6=tampered(v6.ipv6_icmpv6, code=None)), TypeError),
            (tampered(v6, ipv6_icmpv6=v4.icmp), TypeError),
            (tampered(analyze_packet(udp()), icmp=v4.icmp), ValueError),
        )
        for index, (analysis, error) in enumerate(cases):
            key = identity if analysis.ipv4 is not None and analysis.udp is None else flow_identity_from_packet(
                analyze_packet(icmp6() if analysis.ipv6 is not None else udp()))
            with self.subTest(index=index), self.assertRaises(error):
                update(None, analysis, key)
        instance = manager()
        first = instance.record(v4).active_window
        with self.assertRaises(ValueError):
            instance.record(cases[0][0])
        self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
        unsupported = analyze_packet(observation_for(253, bytes(8)))
        with self.assertRaises(TypeError):
            update(None, unsupported, flow_identity_from_packet(v6))
        with self.assertRaises(FlowIdentityError):
            instance.record(unsupported)
        self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)

    def test_reducer_reads_no_raw_bytes_payload_or_parsers(self):
        for source in (icmp4(3, code=1, payload=bytes(range(200))), icmp6(1, bytes(64), code=4)):
            analysis = analyze_packet(source)
            identity = flow_identity_from_packet(analysis)
            expected = update(None, analysis, identity)
            with patch.object(ICMPMessage, 'payload', new_callable=PropertyMock, create=True,
                              side_effect=AssertionError('payload')), \
                    patch.object(ICMPv6Packet, 'raw_bytes', new_callable=PropertyMock, create=True,
                                 side_effect=AssertionError('raw bytes')), \
                    patch.object(IPv4Packet, 'payload', new_callable=PropertyMock, create=True,
                                 side_effect=AssertionError('IPv4 payload')), \
                    patch.object(IPv6Packet, 'payload', new_callable=PropertyMock, create=True,
                                 side_effect=AssertionError('IPv6 payload')), \
                    patch('analysis.icmp.decode_icmp', side_effect=AssertionError('decode')), \
                    patch('analysis.icmpv6.decode_icmpv6', side_effect=AssertionError('decode')), \
                    patch.object(ICMPMessage, '__post_init__', side_effect=AssertionError('rebuild')), \
                    patch.object(ICMPv6Packet, '__post_init__', side_effect=AssertionError('rebuild')):
                self.assertEqual(update_directional_icmp_statistics(None, analysis, identity), expected)
        sizes = [record((icmp4(3, code=1, payload=payload),)) for payload in (b'', bytes(512), bytes(60000))]
        self.assertEqual(sizes, [sizes[0]] * 3)

    def test_failed_candidates_and_publication_retry_count_once(self):
        for target in (CoordinatedFlowState, FlowObservationWindowUpdate):
            with self.subTest(target=target.__name__):
                instance = manager()
                first = instance.record(analyze_packet(icmp6())).active_window
                reply = analyze_packet(icmp6(129, reverse=True, seconds=1))
                for _ in range(2):
                    with patch.object(target, '__post_init__', side_effect=MemoryError('publication')):
                        with self.assertRaises(MemoryError):
                            instance.record(reply)
                    self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
                accepted = instance.record(reply).active_window.icmp_statistics
                self.assertEqual(accepted.reverse.type_code_counts, ((129, 0, 1),))
                repeated = instance.record(reply).active_window.icmp_statistics
                self.assertEqual(repeated.reverse.type_code_counts, ((129, 0, 2),))
                self.assertEqual(first.icmp_statistics.reverse, ICMPStatistics())
        instance = manager()
        with patch('analysis.icmp_statistics._increment', side_effect=MemoryError('allocation')):
            with self.assertRaises(MemoryError):
                instance.record(analyze_packet(icmp4()))
        self.assertEqual(instance.active_windows(), ())
        retried = instance.record(analyze_packet(icmp4())).active_window
        self.assertEqual((retried.key.sequence_number, retried.icmp_statistics.forward.packet_count), (0, 1))

    def test_every_closure_reason_preserves_aggregate_and_replacement_starts_empty(self):
        for reason in ('explicit_segmentation', 'capture_session_end', 'inactivity', 'capacity'):
            with self.subTest(reason=reason):
                instance = manager(capacity=1)
                instance.record(analyze_packet(icmp4(3, code=1)))
                published = instance.record(analyze_packet(icmp4(3, code=1, reverse=True, seconds=1))).active_window
                if reason == 'explicit_segmentation':
                    closed = instance.close(published.identity)
                    replacement = instance.record(analyze_packet(icmp4(3, code=2, seconds=2))).active_window
                elif reason == 'capture_session_end':
                    closed, = instance.end_capture_session()
                    replacement = None
                else:
                    later = icmp4(3, code=2, seconds=7) if reason == 'inactivity' else icmp6(1, bytes(4), seconds=2)
                    result = instance.record(analyze_packet(later))
                    closed, = result.closed_windows
                    replacement = result.active_window
                self.assertEqual(closed.closure_reason.value, reason)
                self.assertIs(closed.icmp_statistics, published.icmp_statistics)
                if replacement is not None:
                    self.assertEqual(replacement.icmp_statistics.forward.packet_count, 1)
                    self.assertEqual(replacement.icmp_statistics.reverse, ICMPStatistics())
        instance = manager()
        first = instance.record(analyze_packet(icmp6())).active_window
        with patch.object(FlowObservationWindow, '__post_init__', side_effect=MemoryError('closure')):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        closed, = instance.end_capture_session()
        self.assertIs(closed.icmp_statistics, first.icmp_statistics)

    def test_published_statistics_release_packet_and_model_sources(self):
        for factory in (icmp4, icmp6):
            source = analyze_packet(factory())
            model = source.icmp if source.icmp is not None else source.ipv6_icmpv6
            network = source.ipv4 if source.ipv4 is not None else source.ipv6
            references = tuple(weakref.ref(item) for item in (source, model, network, source.observation))
            state = FlowStateCoordinator().record(source)
            del source, model, network
            gc.collect()
            self.assertTrue(all(reference() is None for reference in references))
            self.assertEqual(state.icmp_statistics.forward.packet_count, 1)
            self.assertTrue(all(type(value) is int for item in state.icmp_statistics.forward.type_code_counts for value in item))

    def test_detection_and_transport_results_are_unchanged(self):
        sources = (tcp(seconds=1), udp(seconds=2), icmp4(seconds=3), icmp4(0, reverse=True, seconds=4),
                   icmp6(seconds=5), icmp6(1, bytes(4), seconds=6), udp(seconds=7, ipv6=True))
        arguments = dict(configuration=settings(), capture_session_id='icmp', ground_truth=GroundTruth((), ()))
        actual = run_end_to_end_validation(MemoryPacketSource(sources), **arguments)
        with patch('analysis.flow_state_coordinator.update_directional_icmp_statistics',
                   return_value=DirectionalICMPStatistics()):
            baseline = run_end_to_end_validation(MemoryPacketSource(sources), **arguments)
        self.assertEqual(actual.report.metrics, baseline.report.metrics)
        self.assertEqual(actual.pipeline_result.packet_findings, baseline.pipeline_result.packet_findings)
        self.assertEqual(len(actual.pipeline_result.flow_findings), len(baseline.pipeline_result.flow_findings))
        for left, right in zip(actual.pipeline_result.flow_findings, baseline.pipeline_result.flow_findings):
            self.assertEqual(left.decision, right.decision)
            if left.detector_id == 'volume':
                self.assertEqual(left.raw_evidence.snapshot.coordinated_state, right.raw_evidence.snapshot.coordinated_state)
                self.assertEqual(left.raw_evidence.snapshot.coordinated_state.icmp_statistics, DirectionalICMPStatistics())
        self.assertNotIn(1, [finding.raw_evidence.snapshot.identity.protocol for finding in actual.pipeline_result.flow_findings
                             if finding.detector_id == 'volume'])

    def test_capture_sessions_match_across_all_classic_pcap_encodings(self):
        sources = (icmp4(seconds=0), icmp4(0, reverse=True, seconds=1), icmp6(seconds=2), icmp6(129, reverse=True, seconds=3),
                   icmp4(3, code=3, seconds=4), icmp4(11, code=1, seconds=5), icmp6(1, bytes(4), code=4, seconds=6),
                   udp(seconds=7), tcp(seconds=8))
        expected = []
        run_flow_observation_session(MemoryPacketSource(sources), capture_session_id='icmp-statistics',
                                     inactivity_timeout=timedelta(seconds=60), closed_window_consumer=expected.append)
        self.assertEqual([(window.icmp_statistics.protocol, window.icmp_statistics.forward.type_code_counts,
                           window.icmp_statistics.reverse.type_code_counts) for window in expected], [
            (1, ((8, 0, 1),), ((0, 0, 1),)), (58, ((128, 0, 1),), ((129, 0, 1),)),
            (1, ((3, 3, 1), (11, 1, 1)), ()), (58, ((1, 4, 1),), ()), (None, (), ()), (None, (), ())])
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'icmp-statistics.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes)
                                                          for index, item in enumerate(sources)), order, nano))
                        source = PcapPacketSource(path)
                        actual = []
                        run_flow_observation_session(source, capture_session_id='icmp-statistics',
                                                     inactivity_timeout=timedelta(seconds=60),
                                                     closed_window_consumer=actual.append)
                        self.assertEqual(actual, expected)
                        self.assertIsNone(source._file)

    def test_established_seed_timezone_replay_matrix(self):
        expected = replay_digest()
        script = 'from tests.test_icmp_statistics import replay_digest; print(replay_digest())'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                actual = subprocess.check_output([sys.executable, '-B', '-c', script], cwd=Path(__file__).parents[1],
                                                 env=dict(os.environ, PYTHONHASHSEED=seed, TZ=zone), text=True).strip()
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
