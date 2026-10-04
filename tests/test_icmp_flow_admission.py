import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    FlowCoordinationError,
    FlowDirection,
    FlowIdentity,
    FlowIdentityError,
    FlowObservationWindowManager,
    FlowStateCoordinator,
    FlowTracker,
    ICMPMessage,
    analyze_packet,
    analyze_packet_outcome,
    extract_flow_feature_snapshot,
    flow_direction_from_packet,
    flow_identity_from_packet,
)
from analysis.flow_direction import FlowDirectionError
from analysis.flow_observation_window import FlowObservationWindow, FlowObservationWindowUpdate
from analysis.flow_state_coordinator import CoordinatedFlowState
from application import GroundTruth, run_end_to_end_validation, run_flow_observation_session
from application.detector_orchestration import run_closed_flow_detectors
from capture import PcapPacketSource
from detection import FlowVolumeThresholdError, TCPControlThresholdError
from detection.flow_volume_threshold import evaluate_flow_volume_threshold
from detection.tcp_control_threshold import evaluate_tcp_control_threshold
from tests.pcap_scenarios import checksum, frame, pcap_bytes, transport
from tests.protocol_scenarios import observation
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ipv6_transport import fragment_header, observation_for
from tests.test_packet_analysis import make_observation


def icmp_message(icmp_type, rest=bytes(4), payload=b'', code=0):
    message = bytes((icmp_type, code, 0, 0)) + rest + payload
    return message[:2] + checksum(message).to_bytes(2, 'big') + message[4:]


def echo(identifier, sequence=1):
    return identifier.to_bytes(2, 'big') + sequence.to_bytes(2, 'big')


def icmp4(icmp_type=8, identifier=0x1234, sequence=1, reverse=False, seconds=0, payload=b'ping', code=0):
    return observation(frame(1, icmp_message(icmp_type, echo(identifier, sequence), payload, code), False, reverse), seconds)


def icmp6(icmp_type=128, body=None, reverse=False, seconds=0, code=0):
    body = echo(0x1234) + b'ping' if body is None else body
    return observation(frame(58, bytes((icmp_type, code, 0, 0)) + body, True, reverse), seconds)


def tcp(reverse=False, seconds=0, ipv6=False):
    return observation(frame(6, transport(6, b'', ipv6, reverse), ipv6, reverse), seconds)


def udp(reverse=False, seconds=0, ipv6=False):
    return observation(frame(17, transport(17, b'data', ipv6, reverse), ipv6, reverse), seconds)


def identity_of(source):
    return flow_identity_from_packet(analyze_packet(source))


def manager(timeout=5, capacity=1024):
    return FlowObservationWindowManager('icmp-flow-admission', timedelta(seconds=timeout), max_active_windows=capacity)


def summarize(window):
    identity = window.identity
    directional = window.coordinated_state.directional_flow_statistics
    return (window.key.sequence_number, None if window.closure_reason is None else window.closure_reason.value,
            identity.source_address.hex(), identity.destination_address.hex(), identity.source_port,
            identity.destination_port, identity.protocol, identity.icmp_echo_identifier,
            directional.forward_packet_count, directional.reverse_packet_count,
            window.coordinated_state.tcp_control_statistics is None)


def replay_digest():
    instance = manager(capacity=3)
    events = []
    for source in (icmp4(seconds=0), icmp4(0, reverse=True, seconds=1), icmp6(seconds=2), udp(seconds=3),
                   icmp4(3, seconds=4), icmp6(129, reverse=True, seconds=5), icmp4(8, 7, seconds=6),
                   tcp(seconds=7), icmp6(1, bytes(4), seconds=8), icmp6(2, bytes(4), seconds=20)):
        update = instance.record(analyze_packet(source))
        events.extend(summarize(window) for window in update.closed_windows)
        events.append(summarize(update.active_window))
    events.append(summarize(instance.close(instance.active_windows()[0].identity)))
    events.extend(summarize(window) for window in instance.end_capture_session())
    return hashlib.sha256(repr(events).encode()).hexdigest()


class ICMPFlowAdmissionTests(unittest.TestCase):
    def test_icmpv4_and_icmpv6_echo_packets_are_admitted_without_ports(self):
        for source, protocol, version in ((icmp4(), 1, 4), (icmp6(), 58, 6)):
            with self.subTest(protocol=protocol):
                outcome = analyze_packet_outcome(source)
                self.assertTrue(outcome.succeeded)
                identity = flow_identity_from_packet(outcome.analysis)
                self.assertEqual((identity.protocol, identity.ip_version, identity.icmp_echo_identifier), (protocol, version, 0x1234))
                self.assertEqual((identity.source_port, identity.destination_port), (None, None))
                window = manager().record(outcome.analysis).active_window
                self.assertEqual(window.identity, identity)
                self.assertEqual(window.coordinated_state.flow_statistics.packet_count, 1)

    def test_echo_request_and_reply_share_one_flow_with_directional_membership(self):
        for request, reply in ((icmp4(8), icmp4(0, reverse=True, seconds=1)),
                               (icmp6(128), icmp6(129, reverse=True, seconds=1))):
            with self.subTest(protocol=identity_of(request).protocol):
                forward, backward = analyze_packet(request), analyze_packet(reply)
                identity = flow_identity_from_packet(forward)
                self.assertEqual(flow_identity_from_packet(backward), identity)
                self.assertEqual(hash(flow_identity_from_packet(backward)), hash(identity))
                self.assertIs(flow_direction_from_packet(forward, identity), FlowDirection.FORWARD)
                self.assertIs(flow_direction_from_packet(backward, identity), FlowDirection.REVERSE)
                instance = manager()
                instance.record(forward)
                window = instance.record(backward).active_window
                directional = window.coordinated_state.directional_flow_statistics
                self.assertEqual((directional.forward_packet_count, directional.reverse_packet_count), (1, 1))
                self.assertEqual(len(instance.active_windows()), 1)

    def test_sequence_numbers_payload_and_code_do_not_define_membership(self):
        base = identity_of(icmp4())
        for source in (icmp4(sequence=0), icmp4(sequence=65535), icmp4(payload=bytes(1000)), icmp4(payload=b''),
                       icmp4(code=255)):
            self.assertEqual(identity_of(source), base)
        base = identity_of(icmp6())
        for body in (echo(0x1234, 0), echo(0x1234, 65535), echo(0x1234) + bytes(1000)):
            self.assertEqual(identity_of(icmp6(body=body)), base)

    def test_echo_identifiers_partition_flows_between_the_same_addresses(self):
        identities = {identity_of(icmp4(identifier=value)) for value in (0, 1, 0x1234, 65535)}
        identities |= {identity_of(icmp6(body=echo(value))) for value in (0, 1, 0x1234, 65535)}
        self.assertEqual(len(identities), 8)
        self.assertEqual(sorted(identity.icmp_echo_identifier for identity in identities if identity.protocol == 1),
                         [0, 1, 0x1234, 65535])
        instance = manager()
        for index, value in enumerate((1, 2, 1, 2)):
            instance.record(analyze_packet(icmp4(identifier=value, seconds=index)))
        self.assertEqual([window.coordinated_state.flow_statistics.packet_count for window in instance.active_windows()], [2, 2])

    def test_messages_without_an_echo_identifier_share_one_non_echo_flow(self):
        cases = {
            1: [icmp4(icmp_type, payload=bytes(28)) for icmp_type in (3, 4, 5, 11, 12, 13, 14, 15, 16, 17, 18, 255)],
            58: [icmp6(icmp_type, bytes(8)) for icmp_type in (1, 2, 3, 4, 127, 130, 133, 135, 136, 255)]
            + [icmp6(128, b''), icmp6(129, b'\x12\x34\x00')],
        }
        for protocol, sources in cases.items():
            with self.subTest(protocol=protocol):
                identities = {identity_of(source) for source in sources}
                self.assertEqual(len(identities), 1)
                identity, = identities
                self.assertEqual((identity.protocol, identity.icmp_echo_identifier), (protocol, None))
                echo_zero = identity_of(icmp4(identifier=0) if protocol == 1 else icmp6(body=echo(0)))
                self.assertNotEqual(identity, echo_zero)
                instance = manager()
                for index, source in enumerate(sources):
                    window = instance.record(analyze_packet(replace(source, captured_at=source.captured_at + timedelta(milliseconds=index)))).active_window
                self.assertEqual(window.coordinated_state.flow_statistics.packet_count, len(sources))
                self.assertEqual(len(instance.active_windows()), 1)

    def test_protocols_and_ip_families_never_collapse(self):
        identities = [identity_of(source) for source in (icmp4(), icmp6(), icmp4(3), icmp6(1, bytes(4)),
                                                         tcp(), udp(), tcp(ipv6=True), udp(ipv6=True))]
        self.assertEqual(len(set(identities)), len(identities))
        self.assertEqual([identity.protocol for identity in identities], [1, 58, 1, 58, 6, 17, 6, 17])
        instance = manager()
        for index, source in enumerate((icmp4(), icmp6(), tcp(), udp(), tcp(ipv6=True), udp(ipv6=True))):
            instance.record(analyze_packet(replace(source, captured_at=source.captured_at + timedelta(seconds=index))))
        self.assertEqual(len(instance.active_windows()), 6)

    def test_identity_contract_validates_icmp_fields_before_construction(self):
        v4, v6 = b'\xc0\x00\x02\x01', bytes(15) + b'\x01'
        valid = FlowIdentity(v4, v4[:3] + b'\x02', None, None, 1, 0)
        self.assertEqual(FlowIdentity(v4[:3] + b'\x02', v4, None, None, 1, 0), valid)
        self.assertEqual(FlowIdentity(v4, v4, None, None, 1).source_address, v4)
        self.assertEqual(FlowIdentity(v6, v6, None, None, 58, 65535).icmp_echo_identifier, 65535)
        for arguments, error in (
            ((v4, v4, 1, None, 1), ValueError), ((v4, v4, None, 0, 1), ValueError), ((v6, v6, 1, 2, 58), ValueError),
            ((v6, v6, None, None, 1), ValueError), ((v4, v4, None, None, 58), ValueError),
            ((v4, v4, None, None, 1, -1), ValueError), ((v4, v4, None, None, 1, 65536), ValueError),
            ((v4, v4, None, None, 1, True), TypeError), ((v4, v4, None, None, 1, '1'), TypeError),
            ((v4, v4, None, None, 1, 1.0), TypeError), ((v4, v4, 1, 2, 6, 0), ValueError),
            ((v4, v4, 1, 2, 17, 7), ValueError), ((v4, v4, None, None, 2), TypeError),
            ((v4, v6, None, None, 1), ValueError), ((v4, v4, None, None, True), TypeError),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(error):
                FlowIdentity(*arguments)
        with self.assertRaises(FrozenInstanceError):
            valid.icmp_echo_identifier = 1
        self.assertNotEqual(valid, replace(valid, icmp_echo_identifier=None))

    def test_tcp_and_udp_identity_equality_hash_and_canonicalization_are_unchanged(self):
        for protocol in (6, 17):
            source, destination = b'\xc0\x00\x02\x02', b'\xc0\x00\x02\x01'
            identity = FlowIdentity(source, destination, 443, 12345, protocol)
            self.assertEqual((identity.source_address, identity.source_port), (destination, 12345))
            self.assertIsNone(identity.icmp_echo_identifier)
            self.assertEqual(hash(identity), hash((destination, source, 12345, 443, protocol)))
            self.assertEqual(identity, FlowIdentity(destination, source, 12345, 443, protocol))
            self.assertEqual(identity_of(tcp() if protocol == 6 else udp()),
                             identity_of(tcp(reverse=True) if protocol == 6 else udp(reverse=True)))

    def test_unadmittable_or_inconsistent_icmp_analyses_are_rejected_without_state_change(self):
        v4 = analyze_packet(icmp4())
        v6 = analyze_packet(icmp6())
        fragmented = analyze_packet(observation_for(58, echo(1) + b'data', fragment_header(58, more=True), 44))
        self.assertIsNone(fragmented.ipv6_icmpv6)
        invalid = (
            replace(v4, icmp=None), replace(v6, ipv6_icmpv6=None), fragmented,
            replace(v4, tcp=analyze_packet(tcp()).tcp), replace(v4, udp=analyze_packet(udp()).udp),
            replace(v4, ipv4=replace(v4.ipv4, protocol=58)),
        )
        for analysis in invalid:
            with self.subTest(analysis=analysis.observation.captured_length):
                instance = manager()
                first = instance.record(analyze_packet(udp())).active_window
                with self.assertRaises(FlowIdentityError):
                    flow_identity_from_packet(analysis)
                with self.assertRaises(FlowIdentityError):
                    instance.record(analysis)
                self.assertEqual(instance.active_windows(), (first,))
        forged = replace(v4)
        object.__setattr__(forged, 'icmp', replace(v6.ipv6_icmpv6))
        with self.assertRaises(FlowIdentityError):
            flow_identity_from_packet(forged)
        non_initial = analyze_packet_outcome(make_observation(1, icmp_message(8, echo(1)), fragment_field=1))
        self.assertEqual(non_initial.failure_classification.value, 'unsupported')
        first_fragment = analyze_packet(make_observation(1, icmp_message(8, echo(9)), fragment_field=1 << 13))
        self.assertEqual(flow_identity_from_packet(first_fragment).icmp_echo_identifier, 9)

    def test_direction_rejects_mismatched_protocol_identifier_and_endpoints(self):
        analysis = analyze_packet(icmp4())
        identity = flow_identity_from_packet(analysis)
        for other, message in ((replace(identity, icmp_echo_identifier=1), 'echo identifier'),
                               (replace(identity, icmp_echo_identifier=None), 'echo identifier'),
                               (identity_of(icmp6()), 'protocol'), (identity_of(tcp()), 'protocol'),
                               (replace(identity, destination_address=b'\xff' * 4), 'endpoints')):
            with self.subTest(message=message), self.assertRaisesRegex(FlowDirectionError, message):
                flow_direction_from_packet(analysis, other)
        with self.assertRaises(FlowDirectionError):
            flow_direction_from_packet(analyze_packet(tcp()), identity)

    def test_coordinated_icmp_state_keeps_transport_specific_state_absent(self):
        for source in (icmp4(), icmp6()):
            state = FlowStateCoordinator().record(analyze_packet(source))
            self.assertEqual((state.tcp_control_statistics, state.tcp_stream_state, state.ldap_statistics,
                              state.ldap_stream_state, state.dns_correlation_state, state.dns_stream_state,
                              state.tls_record_state, state.tls_handshake_state), (None,) * 8)
            self.assertEqual(state.tcp_option_statistics, type(state.tcp_option_statistics)())
            self.assertEqual(state.dns_transaction_statistics.total_transaction_count, 0)
            tcp_state = FlowStateCoordinator().record(analyze_packet(tcp(ipv6=state.identity.protocol == 58)))
            for name in ('tcp_control_statistics', 'tcp_stream_state'):
                with self.subTest(name=name), self.assertRaises(FlowCoordinationError):
                    replace(state, **{name: getattr(tcp_state, name)})
            snapshot = extract_flow_feature_snapshot(manager().record(analyze_packet(source)).active_window)
            self.assertEqual(snapshot.flow_volume_features.packet_count, 1)

    def test_detection_skips_flow_detectors_for_icmp_and_preserves_tcp_udp_findings(self):
        transport_sources = (tcp(seconds=1), udp(seconds=2), tcp(seconds=3, ipv6=True), udp(seconds=4, ipv6=True))
        mixed = transport_sources + (icmp4(seconds=5), icmp4(0, reverse=True, seconds=6), icmp6(seconds=7), icmp6(1, bytes(4), seconds=8))
        arguments = dict(configuration=settings(), capture_session_id='icmp', ground_truth=GroundTruth((), ()))
        with patch('application.detector_orchestration.evaluate_flow_volume_threshold',
                   wraps=evaluate_flow_volume_threshold) as volume, \
                patch('application.detector_orchestration.evaluate_tcp_control_threshold',
                      wraps=evaluate_tcp_control_threshold) as control:
            actual = run_end_to_end_validation(MemoryPacketSource(mixed), **arguments)
        self.assertEqual(sorted(call.args[0].identity.protocol for call in volume.call_args_list), [6, 6, 17, 17])
        self.assertEqual([call.args[0].identity.protocol for call in control.call_args_list], [6, 6])
        baseline = run_end_to_end_validation(MemoryPacketSource(transport_sources), **arguments)

        def project(result):
            return [(finding.detector_id, finding.decision, finding.raw_evidence.snapshot.identity
                     if finding.detector_id == 'volume' else finding.raw_evidence.identity)
                    for finding in result.pipeline_result.flow_findings]

        self.assertEqual(project(actual), project(baseline))
        self.assertEqual(actual.report.metrics.flow_metrics, baseline.report.metrics.flow_metrics)
        self.assertEqual(len(actual.pipeline_result.packet_findings), len(mixed))
        self.assertTrue(all(finding.raw_evidence.outcome.succeeded for finding in actual.pipeline_result.packet_findings))

    def test_orchestration_applicability_leaves_detector_semantics_unchanged(self):
        instance = manager()
        instance.record(analyze_packet(icmp4()))
        closed = extract_flow_feature_snapshot(instance.end_capture_session()[0])
        configuration = settings()
        volume = configuration.flow_volume_configuration
        tcp_configuration = configuration.tcp_control_configuration
        self.assertEqual(run_closed_flow_detectors(closed, flow_volume_configuration=volume,
                                                   tcp_control_configuration=tcp_configuration), ())
        self.assertEqual(run_closed_flow_detectors(closed, flow_volume_configuration=volume), ())
        with self.assertRaises(FlowVolumeThresholdError):
            evaluate_flow_volume_threshold(closed, volume)
        with self.assertRaises(TCPControlThresholdError):
            evaluate_tcp_control_threshold(closed.observation_window, tcp_configuration)
        active = extract_flow_feature_snapshot(manager().record(analyze_packet(icmp6())).active_window)
        with self.assertRaisesRegex(ValueError, 'must be closed'):
            run_closed_flow_detectors(active, flow_volume_configuration=volume)
        with self.assertRaises(TypeError):
            run_closed_flow_detectors(closed.observation_window, flow_volume_configuration=volume)

    def test_every_closure_reason_and_replacement_window(self):
        for reason in ('explicit_segmentation', 'capture_session_end', 'inactivity', 'capacity'):
            with self.subTest(reason=reason):
                instance = manager(capacity=1)
                first = instance.record(analyze_packet(icmp4())).active_window
                instance.record(analyze_packet(icmp4(0, reverse=True, seconds=1)))
                if reason == 'explicit_segmentation':
                    closed = instance.close(first.identity)
                    replacement = instance.record(analyze_packet(icmp4(seconds=2))).active_window
                elif reason == 'capture_session_end':
                    closed, = instance.end_capture_session()
                    replacement = None
                else:
                    later = icmp4(seconds=7) if reason == 'inactivity' else icmp6(seconds=2)
                    update = instance.record(analyze_packet(later))
                    closed, = update.closed_windows
                    replacement = update.active_window
                self.assertEqual(closed.closure_reason.value, reason)
                self.assertEqual(closed.identity, first.identity)
                self.assertEqual(closed.coordinated_state.flow_statistics.packet_count, 2)
                if replacement is not None:
                    self.assertNotEqual(replacement.key, closed.key)
                    self.assertEqual(replacement.coordinated_state.flow_statistics.packet_count, 1)

    def test_failed_publication_and_finalization_are_retryable_and_count_once(self):
        for target in (CoordinatedFlowState, FlowObservationWindowUpdate):
            with self.subTest(target=target.__name__):
                instance = manager()
                first = instance.record(analyze_packet(icmp6())).active_window
                reply = analyze_packet(icmp6(129, reverse=True, seconds=1))
                with patch.object(target, '__post_init__', side_effect=MemoryError('publication')):
                    with self.assertRaises(MemoryError):
                        instance.record(reply)
                self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
                accepted = instance.record(reply).active_window
                self.assertEqual(accepted.coordinated_state.flow_statistics.packet_count, 2)
        instance = manager()
        instance.record(analyze_packet(icmp4()))
        with patch.object(FlowObservationWindow, '__post_init__', side_effect=MemoryError('closure')):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        closed, = instance.end_capture_session()
        self.assertEqual(closed.coordinated_state.flow_statistics.packet_count, 1)
        self.assertEqual(instance.end_capture_session(), ())

    def test_many_distinct_identifiers_are_bounded_by_existing_capacity(self):
        instance = manager(capacity=8)
        closed = []
        for index in range(2048):
            update = instance.record(analyze_packet(icmp4(identifier=index, seconds=index / 1000)))
            closed.extend(update.closed_windows)
            self.assertLessEqual(len(instance.active_windows()), 8)
        self.assertEqual(len(closed), 2040)
        self.assertTrue(all(window.closure_reason.value == 'capacity' for window in closed))
        self.assertEqual(len({window.identity for window in closed + list(instance.end_capture_session())}), 2048)
        tracker = FlowTracker()
        for source in (icmp4(), icmp4(0, reverse=True), icmp4(3), icmp6()):
            tracker.record(analyze_packet(source))
        self.assertEqual(tracker.flow_count(), 3)

    def test_published_windows_release_packet_and_icmp_sources(self):
        source = analyze_packet(icmp4())
        references = tuple(weakref.ref(item) for item in (source, source.icmp, source.ipv4, source.observation))
        self.assertIs(type(source.icmp), ICMPMessage)
        instance = manager()
        window = instance.record(source).active_window
        snapshot = extract_flow_feature_snapshot(window)
        del source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        instance.record(analyze_packet(icmp4(0, reverse=True, seconds=1)))
        self.assertEqual(snapshot.coordinated_state.flow_statistics.packet_count, 1)
        self.assertEqual(snapshot.identity.icmp_echo_identifier, 0x1234)

    def test_capture_sessions_match_across_all_classic_pcap_encodings(self):
        sources = (icmp4(seconds=0), icmp4(0, reverse=True, seconds=1), icmp6(seconds=2), icmp6(129, reverse=True, seconds=3),
                   icmp4(3, seconds=4), icmp6(1, bytes(4), seconds=5), udp(seconds=6), tcp(seconds=7))
        expected = []
        run_flow_observation_session(MemoryPacketSource(sources), capture_session_id='icmp',
                                     inactivity_timeout=timedelta(seconds=60), closed_window_consumer=expected.append)
        self.assertEqual([(window.identity.protocol, window.identity.icmp_echo_identifier,
                           window.coordinated_state.flow_statistics.packet_count) for window in expected],
                         [(1, 0x1234, 2), (58, 0x1234, 2), (1, None, 1), (58, None, 1), (17, None, 1), (6, None, 1)])
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'icmp.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes)
                                                          for index, item in enumerate(sources)), order, nano))
                        source = PcapPacketSource(path)
                        actual = []
                        run_flow_observation_session(source, capture_session_id='icmp',
                                                     inactivity_timeout=timedelta(seconds=60),
                                                     closed_window_consumer=actual.append)
                        self.assertEqual(actual, expected)
                        self.assertIsNone(source._file)

    def test_established_seed_timezone_replay_matrix(self):
        expected = replay_digest()
        script = 'from tests.test_icmp_flow_admission import replay_digest; print(replay_digest())'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                actual = subprocess.check_output([sys.executable, '-B', '-c', script], cwd=Path(__file__).parents[1],
                                                 env=dict(os.environ, PYTHONHASHSEED=seed, TZ=zone), text=True).strip()
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
