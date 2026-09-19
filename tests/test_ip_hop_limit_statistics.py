import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import FrozenInstanceError, asdict, fields, replace
from datetime import timedelta
from fractions import Fraction
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import PropertyMock, patch

from analysis import (
    DirectionalIPHopLimitStatistics,
    FlowObservationWindowManager,
    FlowStateCoordinator,
    IP_HOP_LIMIT_BINS,
    IPHopLimitStatistics,
    analyze_packet,
    analyze_packet_outcome,
    extract_flow_feature_snapshot,
    flow_identity_from_packet,
    update_directional_ip_hop_limit_statistics,
)
from analysis.flow_observation_window import FlowObservationWindow, FlowObservationWindowUpdate
from analysis.flow_state_coordinator import CoordinatedFlowState
from application import GroundTruth, run_end_to_end_validation, run_flow_observation_session
from capture import PcapPacketSource
from tests.pcap_scenarios import checksum, frame, pcap_bytes, transport
from tests.protocol_scenarios import observation
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_packet_analysis import make_observation


def with_hop_limit(source, value):
    raw = bytearray(source.raw_bytes)
    if raw[12:14] == b'\x86\xdd':
        raw[21] = value
    else:
        raw[22] = value
        raw[24:26] = b'\x00\x00'
        end = 14 + (raw[14] & 15) * 4
        raw[24:26] = checksum(bytes(raw[14:end])).to_bytes(2, 'big')
    return replace(source, raw_bytes=bytes(raw))


def packet(value=64, ipv6=False, protocol=6, reverse=False, seconds=0, extensions=(), fragment=None):
    segment = transport(protocol, ipv6=ipv6, reverse=reverse)
    source = observation(frame(protocol, segment, ipv6, reverse, extensions, fragment), seconds)
    return analyze_packet(with_hop_limit(source, value))


def manager(timeout=5, capacity=1024):
    return FlowObservationWindowManager('ip-hop-limit-statistics', timedelta(seconds=timeout),
                                        max_active_windows=capacity)


def summarize(value):
    return (asdict(value), tuple((side.packet_count, side.distinct_hop_limit_count,
                                 side.min_hop_limit, side.max_hop_limit, side.total_hop_limit,
                                 str(side.mean_hop_limit), side.zero_hop_limit_packet_count)
                                for side in (value.forward, value.reverse)))


def replay_digest():
    instance = manager(capacity=2)
    events = []
    for index, (value, ipv6, protocol, reverse) in enumerate((
        (0, False, 6, False), (255, False, 6, True), (63, False, 6, False),
        (64, True, 17, False), (1, True, 17, True), (128, True, 6, False),
        (128, True, 6, False), (254, True, 17, False), (255, True, 6, True),
    )):
        update = instance.record(packet(value, ipv6, protocol, reverse, seconds=index if index < 8 else 13))
        events.extend((window.key.sequence_number, window.closure_reason.value, summarize(window.ip_hop_limit_statistics))
                      for window in update.closed_windows)
        events.append((update.active_window.key.sequence_number, None, summarize(update.active_window.ip_hop_limit_statistics)))
    closed = instance.close(instance.active_windows()[0].identity)
    events.append((closed.key.sequence_number, closed.closure_reason.value, summarize(closed.ip_hop_limit_statistics)))
    events.extend((window.key.sequence_number, window.closure_reason.value, summarize(window.ip_hop_limit_statistics))
                  for window in instance.end_capture_session())
    return hashlib.sha256(repr(events).encode()).hexdigest()


class IPHopLimitStatisticsTests(unittest.TestCase):
    def test_empty_and_first_observation(self):
        empty = IPHopLimitStatistics()
        self.assertEqual((empty.hop_limit_counts, empty.packet_count, empty.distinct_hop_limit_count,
                          empty.total_hop_limit, empty.zero_hop_limit_packet_count), ((), 0, 0, 0, 0))
        self.assertEqual((empty.min_hop_limit, empty.max_hop_limit, empty.mean_hop_limit), (None, None, None))
        self.assertEqual(manager().end_capture_session(), ())
        window = manager().record(packet()).active_window
        self.assertEqual(window.ip_hop_limit_statistics.forward.hop_limit_counts, ((64, 1),))
        self.assertEqual(window.ip_hop_limit_statistics.forward.mean_hop_limit, Fraction(64))
        self.assertEqual(window.ip_hop_limit_statistics.reverse, empty)

    def test_representative_values_are_directional_for_both_families_and_transports(self):
        for ipv6 in (False, True):
            for protocol in (6, 17):
                with self.subTest(ipv6=ipv6, protocol=protocol):
                    instance = manager()
                    for reverse, values in ((False, (64, 63, 64)), (True, (255, 254))):
                        for value in values:
                            window = instance.record(packet(value, ipv6, protocol, reverse)).active_window
                    forward, reverse = window.ip_hop_limit_statistics.forward, window.ip_hop_limit_statistics.reverse
                    self.assertEqual(forward.hop_limit_counts, ((63, 1), (64, 2)))
                    self.assertEqual((forward.packet_count, forward.distinct_hop_limit_count,
                                      forward.min_hop_limit, forward.max_hop_limit,
                                      forward.total_hop_limit, forward.mean_hop_limit),
                                     (3, 2, 63, 64, 191, Fraction(191, 3)))
                    self.assertEqual(reverse.hop_limit_counts, ((254, 1), (255, 1)))
                    self.assertEqual(reverse.mean_hop_limit, Fraction(509, 2))

    def test_zero_maximum_and_every_bin_remain_exact_and_bounded(self):
        for ipv6 in (False, True):
            value = None
            for wire_value in range(255, -1, -1):
                source = packet(wire_value, ipv6, protocol=17)
                outcome = analyze_packet_outcome(source.observation)
                self.assertTrue(outcome.succeeded)
                value = update_directional_ip_hop_limit_statistics(value, source, flow_identity_from_packet(source))
            self.assertEqual(len(value.forward.hop_limit_counts), IP_HOP_LIMIT_BINS)
            self.assertEqual(value.forward.hop_limit_counts, tuple((index, 1) for index in range(256)))
            self.assertEqual((value.forward.packet_count, value.forward.total_hop_limit,
                              value.forward.min_hop_limit, value.forward.max_hop_limit,
                              value.forward.mean_hop_limit, value.forward.zero_hop_limit_packet_count),
                             (256, 32640, 0, 255, Fraction(255, 2), 1))
            after = update_directional_ip_hop_limit_statistics(value, source, flow_identity_from_packet(source))
            self.assertEqual(len(after.forward.hop_limit_counts), 256)
            self.assertEqual(after.forward.zero_hop_limit_packet_count, 2)
            self.assertEqual(value.forward.zero_hop_limit_packet_count, 1)

    def test_observation_permutations_preserve_distributions_and_duplicates_count(self):
        results = []
        for sequence in ((1, 255, 0, 1, 64), (64, 1, 0, 255, 1)):
            instance = manager()
            for value in sequence:
                window = instance.record(packet(value)).active_window
            results.append(window.ip_hop_limit_statistics)
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0].forward.hop_limit_counts, ((0, 1), (1, 2), (64, 1), (255, 1)))

    def test_immutable_construction_validates_types_ordering_and_cardinality(self):
        for bins, error in (
            ([], TypeError), (((1, 1), [2, 1]), TypeError), (((1,),), TypeError),
            (((False, 1),), TypeError), (((1, True),), TypeError), (((1, 1.0),), TypeError),
            (((-1, 1),), ValueError), (((256, 1),), ValueError), (((1, 0),), ValueError),
            (((1, -1),), ValueError), (((2, 1), (1, 1)), ValueError),
            (((1, 1), (1, 2)), ValueError), ((None,) * 257, ValueError),
        ):
            with self.subTest(bins=bins), self.assertRaises(error):
                IPHopLimitStatistics(bins)
        value = IPHopLimitStatistics(((0, 10 ** 100), (255, 10 ** 100)))
        self.assertEqual(value.packet_count, 2 * 10 ** 100)
        self.assertEqual(value.mean_hop_limit, Fraction(255, 2))
        with self.assertRaises(FrozenInstanceError):
            value.hop_limit_counts = ()
        with self.assertRaises(TypeError):
            value.hop_limit_counts[0] = (0, 1)
        with self.assertRaises(TypeError):
            DirectionalIPHopLimitStatistics(forward=None)
        with self.assertRaises(TypeError):
            DirectionalIPHopLimitStatistics(reverse=())
        with self.assertRaises(FrozenInstanceError):
            DirectionalIPHopLimitStatistics().forward = value

    def test_invalid_public_inputs_and_identity_are_rejected(self):
        source = packet()
        identity = flow_identity_from_packet(source)
        for current, analysis, key in (([], source, identity), (None, None, identity), (None, source, None)):
            with self.assertRaises(TypeError):
                update_directional_ip_hop_limit_statistics(current, analysis, key)
        with self.assertRaises(ValueError):
            update_directional_ip_hop_limit_statistics(None, source, replace(identity, source_port=1))
        with self.assertRaises(TypeError):
            replace(FlowStateCoordinator().record(source), ip_hop_limit_statistics={})
        state = FlowStateCoordinator().record(source)
        legacy = tuple(getattr(state, member.name)
                       for member in fields(CoordinatedFlowState) if member.name != 'ip_hop_limit_statistics')
        self.assertEqual(CoordinatedFlowState(*legacy).ip_hop_limit_statistics, DirectionalIPHopLimitStatistics())

    def test_invalid_wire_values_and_network_metadata_cannot_publish(self):
        for ipv6 in (False, True):
            source = packet(ipv6=ipv6)
            field_name = 'ipv6' if ipv6 else 'ipv4'
            limit_name = 'hop_limit' if ipv6 else 'ttl'
            network = getattr(source, field_name)
            for changes, error in (({limit_name: True}, TypeError), ({limit_name: '64'}, TypeError),
                                   ({limit_name: -1}, ValueError), ({limit_name: 256}, ValueError),
                                   ({'version': 0}, ValueError), ({'version': True}, ValueError),
                                   ({'source_address': b'x'}, ValueError)):
                with self.subTest(ipv6=ipv6, changes=changes):
                    altered = replace(network)
                    for name, value in changes.items():
                        object.__setattr__(altered, name, value)
                    bad = replace(source)
                    object.__setattr__(bad, field_name, altered)
                    with self.assertRaises(error):
                        update_directional_ip_hop_limit_statistics(None, bad, flow_identity_from_packet(source))
            bad = replace(source)
            object.__setattr__(bad, field_name, object())
            with self.assertRaises(TypeError):
                update_directional_ip_hop_limit_statistics(None, bad, flow_identity_from_packet(source))
        source = packet()
        bad = replace(source)
        object.__setattr__(bad, 'ipv6', packet(ipv6=True).ipv6)
        with self.assertRaises(ValueError):
            update_directional_ip_hop_limit_statistics(None, bad, flow_identity_from_packet(source))
        instance = manager()
        first = instance.record(source).active_window
        bad = replace(source, ipv4=replace(source.ipv4))
        object.__setattr__(bad.ipv4, 'ttl', 256)
        with self.assertRaises(ValueError):
            instance.record(bad)
        self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)

    def test_payload_size_and_contents_do_not_change_the_measurement(self):
        for ipv6 in (False, True):
            results = []
            for payload in (b'', bytes(range(256)), bytes(65527 if ipv6 else 65507)):
                source = with_hop_limit(observation(frame(17, transport(17, payload, ipv6), ipv6), 0), 42)
                analysis = analyze_packet(source)
                results.append(update_directional_ip_hop_limit_statistics(None, analysis, flow_identity_from_packet(analysis)))
            self.assertEqual(results, [results[0]] * 3)
            self.assertEqual(results[0].forward.hop_limit_counts, ((42, 1),))
            network = analysis.ipv6 if ipv6 else analysis.ipv4
            with patch.object(type(network), 'payload', new_callable=PropertyMock, create=True,
                              side_effect=AssertionError('payload access')), patch.object(
                                  type(network), '__post_init__', side_effect=AssertionError('model revalidation')):
                result = update_directional_ip_hop_limit_statistics(None, analysis, flow_identity_from_packet(analysis))
            self.assertEqual(result, results[0])

    def test_extension_headers_options_and_fragments_keep_existing_admission(self):
        from tests.test_tcp_options import tcp_observation
        for ipv6 in (False, True):
            source = with_hop_limit(tcp_observation(ipv6, bytes.fromhex('020405b4'), fragment=(0, True)), 17)
            window = manager().record(analyze_packet(source)).active_window
            self.assertEqual(window.ip_hop_limit_statistics.forward.hop_limit_counts, ((17, 1),))
            self.assertEqual(window.tcp_option_statistics.forward.mss_value_counts, ((1460, 1),))
            if ipv6:
                self.assertGreater(window.ipv6_extension_header_statistics.forward.total_extension_header_count, 0)
            outcome = analyze_packet_outcome(tcp_observation(ipv6, fragment=(1, True)))
            if ipv6:
                with self.assertRaises(ValueError):
                    update_directional_ip_hop_limit_statistics(None, outcome.analysis, flow_identity_from_packet(packet(ipv6=True)))
            else:
                self.assertEqual(outcome.failure_classification.value, 'unsupported')

    def test_unsupported_icmp_and_missing_network_cannot_enter_statistics(self):
        from tests.test_ipv6_transport import observation_for
        for source in (make_observation(1, bytes.fromhex('0800000000000000')),
                       observation_for(58, bytes.fromhex('8000000000000000'))):
            analysis = analyze_packet(source)
            with self.assertRaises(ValueError):
                update_directional_ip_hop_limit_statistics(None, analysis, flow_identity_from_packet(packet()))
        source = packet()
        empty = replace(source, ipv4=None, tcp=None)
        with self.assertRaises(TypeError):
            update_directional_ip_hop_limit_statistics(None, empty, flow_identity_from_packet(source))

    def test_failed_packet_outcomes_do_not_refresh_or_count(self):
        from tests.test_tcp_options import tcp_observation
        first = packet(64).observation
        malformed = replace(tcp_observation(False, b'\x02\xff\x00\x00'), captured_at=first.captured_at + timedelta(seconds=1))
        raw = first.raw_bytes[:20]
        truncated = replace(first, raw_bytes=raw, captured_length=len(raw), captured_at=first.captured_at + timedelta(seconds=2))
        unsupported = replace(first, link_type=None, captured_at=first.captured_at + timedelta(seconds=3))
        raw = bytearray(first.raw_bytes)
        raw[22] = 1
        corrupt = replace(first, raw_bytes=bytes(raw), captured_at=first.captured_at + timedelta(seconds=4))
        inputs = (first, malformed, truncated, unsupported, corrupt, packet(63, seconds=5).observation)
        self.assertEqual([analyze_packet_outcome(item).failure_classification.value for item in inputs[1:-1]],
                         ['structural_failure', 'incomplete', 'unsupported', 'integrity_failure'])
        result = run_end_to_end_validation(MemoryPacketSource(inputs), configuration=settings(),
                                           capture_session_id='lifetime', ground_truth=GroundTruth((), ()))
        windows = [f.raw_evidence.snapshot.observation_window for f in result.pipeline_result.flow_findings if f.detector_id == 'volume']
        self.assertEqual([w.ip_hop_limit_statistics.forward.hop_limit_counts for w in windows], [((64, 1),), ((63, 1),)])
        self.assertEqual(windows[0].closure_reason.value, 'inactivity')

    def test_failed_candidate_publication_and_repeated_retries_are_atomic(self):
        for target in (CoordinatedFlowState, FlowObservationWindowUpdate):
            instance = manager()
            first = instance.record(packet(64)).active_window
            later = packet(63, seconds=1)
            for _ in range(2):
                with patch.object(target, '__post_init__', side_effect=MemoryError('publication')):
                    with self.assertRaises(MemoryError):
                        instance.record(later)
                self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
            accepted = instance.record(later).active_window
            self.assertEqual(accepted.ip_hop_limit_statistics.forward.hop_limit_counts, ((63, 1), (64, 1)))
            repeated = instance.record(later).active_window
            self.assertEqual(repeated.ip_hop_limit_statistics.forward.hop_limit_counts, ((63, 2), (64, 1)))
            self.assertEqual(first.ip_hop_limit_statistics.forward.hop_limit_counts, ((64, 1),))

    def test_initial_allocation_failure_and_clock_rejection_preserve_state(self):
        instance = manager()
        with patch('analysis.ip_hop_limit_statistics._increment', side_effect=MemoryError('allocation')):
            with self.assertRaises(MemoryError):
                instance.record(packet())
        self.assertEqual(instance.active_windows(), ())
        first = instance.record(packet(seconds=1)).active_window
        self.assertEqual(first.key.sequence_number, 0)
        with self.assertRaises(ValueError):
            instance.record(packet(63, seconds=0))
        self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)

    def test_closure_preserves_counts_and_new_windows_start_empty(self):
        for reason in ('explicit_segmentation', 'capture_session_end', 'inactivity', 'capacity'):
            with self.subTest(reason=reason):
                instance = manager(capacity=1)
                first = instance.record(packet(64)).active_window
                if reason == 'explicit_segmentation':
                    closed = instance.close(first.identity)
                    self.assertEqual(instance.record(packet(63)).active_window.ip_hop_limit_statistics.forward.hop_limit_counts, ((63, 1),))
                elif reason == 'capture_session_end':
                    closed, = instance.end_capture_session()
                    self.assertEqual(instance.end_capture_session(), ())
                    with self.assertRaises(ValueError):
                        instance.record(packet())
                else:
                    update = instance.record(packet(63, ipv6=reason == 'capacity', seconds=5))
                    closed, = update.closed_windows
                    self.assertEqual(update.active_window.ip_hop_limit_statistics.forward.hop_limit_counts, ((63, 1),))
                self.assertIs(closed.ip_hop_limit_statistics, first.ip_hop_limit_statistics)
                self.assertEqual(closed.closure_reason.value, reason)

    def test_replacement_and_finalization_failures_are_retryable(self):
        for capacity in (False, True):
            instance = manager(capacity=1)
            first = instance.record(packet()).active_window
            later = packet(63, ipv6=capacity, seconds=5)
            with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=MemoryError('replacement')):
                with self.assertRaises(MemoryError):
                    instance.record(later)
            self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
            update = instance.record(later)
            self.assertEqual(update.active_window.key.sequence_number, 1)
            self.assertEqual(update.active_window.ip_hop_limit_statistics.forward.packet_count, 1)
            with patch.object(FlowObservationWindow, '__post_init__', side_effect=MemoryError('closure')):
                with self.assertRaises(MemoryError):
                    instance.end_capture_session()
            closed, = instance.end_capture_session()
            self.assertIs(closed.ip_hop_limit_statistics, update.active_window.ip_hop_limit_statistics)
            self.assertEqual(instance.end_capture_session(), ())

    def test_published_statistics_release_sources_and_preserve_snapshots(self):
        source = packet(protocol=17)
        references = tuple(weakref.ref(item) for item in (source, source.ipv4, source.udp, source.observation, source.observation.source))
        instance = manager()
        first = instance.record(source).active_window
        snapshot = extract_flow_feature_snapshot(first)
        del source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertIs(snapshot.coordinated_state.ip_hop_limit_statistics, first.ip_hop_limit_statistics)
        instance.record(packet(63, protocol=17))
        self.assertEqual(snapshot.coordinated_state.ip_hop_limit_statistics.forward.hop_limit_counts, ((64, 1),))

    def test_real_capture_session_all_pcap_encodings_are_equivalent(self):
        sources = tuple(packet(value, ipv6, protocol, reverse, seconds=index).observation
                        for index, (value, ipv6, protocol, reverse) in enumerate(
                            (value, ipv6, protocol, reverse)
                            for ipv6 in (False, True) for protocol in (6, 17)
                            for reverse, value in ((False, 0), (True, 255), (False, 64))))
        expected = []
        run_flow_observation_session(MemoryPacketSource(sources), capture_session_id='lifetime',
                                     inactivity_timeout=timedelta(seconds=60), closed_window_consumer=expected.append)
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'hop-limits.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes) for index, item in enumerate(sources)), order, nano))
                    source = PcapPacketSource(path)
                    actual = []
                    run_flow_observation_session(source, capture_session_id='lifetime',
                                                 inactivity_timeout=timedelta(seconds=60), closed_window_consumer=actual.append)
                    self.assertEqual(actual, expected)
                    self.assertIsNone(source._file)

    def test_capture_and_consumer_failures_preserve_cleanup(self):
        failure = RuntimeError('capture')
        source = MemoryPacketSource((packet().observation,), iteration_error=failure)
        closed = []
        with self.assertRaises(RuntimeError) as caught:
            run_flow_observation_session(source, capture_session_id='lifetime', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        self.assertIs(caught.exception, failure)
        self.assertTrue(source.stopped)
        self.assertEqual(closed[0].ip_hop_limit_statistics.forward.hop_limit_counts, ((64, 1),))
        source = MemoryPacketSource((packet().observation, packet(ipv6=True, seconds=1).observation))
        delivered = []

        def fail(window):
            delivered.append(window)
            raise failure

        with self.assertRaises(RuntimeError):
            run_flow_observation_session(source, capture_session_id='lifetime', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=fail, max_active_windows=1)
        self.assertTrue(source.stopped)
        self.assertEqual(len(delivered), 1)

    def test_dns_ldap_tls_and_detection_contracts_coexist(self):
        from tests.test_dns_packet_analysis import dns_packet
        from tests.test_dns import header
        from tests.test_ldap_flow_statistics import ldap_observation
        from tests.test_ldap import message as ldap_message
        from tests.test_tls_server_hello import body
        from tests.test_tls_handshake_framing import message
        from tests.test_tls_record_framing import packet as tls_packet, wire
        sources = (dns_packet(header()), ldap_observation(ldap_message()), tls_packet(wire(message(body(), 2), 22)))
        instance = manager()
        windows = [instance.record(analyze_packet(with_hop_limit(item, 42))).active_window for item in sources]
        self.assertIsNotNone(windows[0].dns_correlation_state)
        self.assertEqual(windows[1].coordinated_state.ldap_statistics.complete_message_count, 1)
        self.assertEqual(windows[2].tls_server_hello_statistics.forward.total_server_hello_count, 1)
        for window in windows:
            self.assertEqual(window.ip_hop_limit_statistics.forward.hop_limit_counts, ((42, 1),))
        arguments = dict(configuration=settings(), capture_session_id='lifetime', ground_truth=GroundTruth((), ()))
        actual = run_end_to_end_validation(MemoryPacketSource(sources), **arguments)
        with patch('analysis.flow_state_coordinator.update_directional_ip_hop_limit_statistics', return_value=DirectionalIPHopLimitStatistics()):
            baseline = run_end_to_end_validation(MemoryPacketSource(sources), **arguments)
        self.assertEqual(actual.report.metrics, baseline.report.metrics)
        self.assertEqual(actual.pipeline_result.packet_findings, baseline.pipeline_result.packet_findings)
        self.assertEqual(len(actual.pipeline_result.flow_findings), len(baseline.pipeline_result.flow_findings))
        for left, right in zip(actual.pipeline_result.flow_findings, baseline.pipeline_result.flow_findings):
            self.assertEqual(left.decision, right.decision)
            if left.detector_id != 'volume':
                self.assertEqual(left.raw_evidence.tcp_control_statistics, right.raw_evidence.tcp_control_statistics)
                continue
            left_state, right_state = left.raw_evidence.snapshot.coordinated_state, right.raw_evidence.snapshot.coordinated_state
            self.assertEqual(replace(left_state, ip_hop_limit_statistics=DirectionalIPHopLimitStatistics()), right_state)

    def test_established_seed_timezone_replay_matrix(self):
        expected = replay_digest()
        script = 'from tests.test_ip_hop_limit_statistics import replay_digest; print(replay_digest())'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                actual = subprocess.check_output([sys.executable, '-B', '-c', script], cwd=Path(__file__).parents[1],
                                                 env=dict(os.environ, PYTHONHASHSEED=seed, TZ=zone), text=True).strip()
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
