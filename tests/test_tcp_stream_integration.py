import os
import subprocess
import sys
import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, asdict, fields, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import PropertyMock, patch

from analysis import (
    FlowCoordinationError, FlowObservationWindowManager, FlowObservationWindowUpdate,
    FlowStateCoordinator, LDAPMessageStatus, TCPStreamState, TCPStreamStatus,
    analyze_ldap_payload, analyze_packet, extract_flow_feature_snapshot,
)
from application import GroundTruth, run_end_to_end_validation, run_flow_observation_session
from capture import CaptureSource, PcapPacketSource
from research import research_example_from_window
from tests.pcap_scenarios import frame, pcap_bytes, transport
from tests.protocol_scenarios import observation
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ldap import RESULT, message
from tests.test_ldap_flow_statistics import ldap_observation
from tests.test_tcp_stream_observation import stream_observation, stream_packet, stream_states


def observe_streams(observations):
    manager = FlowObservationWindowManager('stream', timedelta(seconds=5))
    closed = []
    for observation in observations:
        closed.extend(manager.record(analyze_packet(observation)).closed_windows)
    closed.extend(manager.end_capture_session())
    return tuple(closed)


def deterministic_stream_results():
    sequences = (
        (stream_packet(b'ab', 0xFFFFFFFE), stream_packet(b'cd', 0), stream_packet(b'bc', 0xFFFFFFFF)),
        (stream_packet(b'ab', 10), stream_packet(b'ef', 14), stream_packet(b'cd', 12)),
        (stream_packet(b'abcd', 10), stream_packet(b'zz', 11)),
        (stream_packet(b'abcd', 10), stream_packet(b'cdef', 12)),
        (stream_packet(b'', 10, flags=2), stream_packet(b'ab', 11), stream_packet(b'', 13, flags=17)),
        (stream_packet(b'a' * 32768, 0), stream_packet(b'b' * 32768, 32768), stream_packet(b'x', 65536)),
    )
    raw = message(0x60, b'opaque')
    packets = tuple(ldap_observation(payload, seconds, ipv6, reverse, sequence=sequence)
                    for seconds, payload, sequence, reverse in ((0, raw[:5], 10, False),
                        (1, message(0x61, RESULT), 500, True), (2, raw[5:], 15, False))
                    for ipv6 in (False, True))
    windows = observe_streams(packets)
    return (tuple(tuple(asdict(state) for state in stream_states(*sequence)) for sequence in sequences),
            tuple(asdict(window) for window in windows),
            tuple(analyze_ldap_payload(window.coordinated_state.tcp_stream_state.forward.contiguous_payload) for window in windows))


class TCPStreamIntegrationTests(unittest.TestCase):
    def test_ipv4_ipv6_streams_preserve_controls_options_and_decoded_models(self):
        for ipv6 in (False, True):
            packets = (stream_packet(b'ab', 10, ipv6=ipv6, flags=2, options=b'\x01\x01\x00\x00'),
                       stream_packet(b'cd', 13, ipv6=ipv6, flags=17),
                       stream_packet(b'XY', 100, ipv6=ipv6, reverse=True, flags=20))
            snapshots = tuple(replace(packet) for packet in packets)
            coordinator = FlowStateCoordinator()
            for packet in packets:
                state = coordinator.record(packet)
            stream = state.tcp_stream_state
            self.assertEqual(stream.forward.contiguous_payload, b'abcd')
            self.assertEqual(stream.reverse.contiguous_payload, b'XY')
            self.assertEqual((stream.forward.start_sequence, stream.forward.end_sequence, stream.forward.next_sequence), (11, 15, 16))
            self.assertIs(stream.forward.status, TCPStreamStatus.FIN)
            self.assertIs(stream.reverse.status, TCPStreamStatus.RESET)
            control = state.tcp_control_statistics
            self.assertEqual((control.forward_syn_count, control.forward_fin_count, control.forward_ack_count,
                              control.reverse_rst_count, control.reverse_ack_count), (1, 1, 1, 1, 1))
            self.assertEqual(packets, snapshots)

    def test_mixed_flows_and_directions_equal_isolated_stream_results(self):
        groups = []
        for ipv6 in (False, True):
            groups.append(tuple(stream_observation(payload, sequence, second, ipv6, reverse)
                                for payload, sequence, second, reverse in ((b'ab', 10, 0, False),
                                    (b'XY', 900, 1, True), (b'cd', 12, 2, False))))
            groups.append(tuple(ldap_observation(payload, second, ipv6, sequence=sequence)
                                for payload, sequence, second in ((b'12', 300, 0), (b'34', 302, 2))))
            groups.append(tuple(observation(frame(17, transport(17, b'udp', ipv6), ipv6), second) for second in (0, 2)))
        combined = tuple(sorted((packet for group in groups for packet in group), key=lambda packet: packet.captured_at))
        actual = {window.identity: window.coordinated_state for window in observe_streams(combined)}
        self.assertEqual(len(actual), 6)
        for group in groups:
            expected = observe_streams(group)[0].coordinated_state
            self.assertEqual(actual[expected.identity], expected)
            if expected.identity.protocol == 17:
                self.assertIsNone(expected.tcp_stream_state)

    def test_gap_and_capacity_failure_leave_other_direction_and_flows_available(self):
        packets = (stream_observation(b'ab', 10), stream_observation(b'ef', 14, 1),
                   stream_observation(b'XY', 900, 2, reverse=True),
                   stream_observation(b'Z', 902, 3, reverse=True),
                   ldap_observation(b'a' * 32768, 3, sequence=0),
                   ldap_observation(b'b' * 32768, 3, sequence=32768),
                   ldap_observation(b'x', 4, sequence=65536),
                   stream_observation(b'v6', 400, 4, ipv6=True))
        windows = observe_streams(packets)
        self.assertEqual(windows[0].coordinated_state.tcp_stream_state.forward.status, TCPStreamStatus.GAP)
        self.assertEqual(windows[0].coordinated_state.tcp_stream_state.reverse.contiguous_payload, b'XYZ')
        self.assertEqual(windows[1].coordinated_state.tcp_stream_state.forward.status, TCPStreamStatus.LIMIT_EXCEEDED)
        self.assertEqual(windows[2].coordinated_state.tcp_stream_state.forward.contiguous_payload, b'v6')

    def test_finalization_expiration_and_reopening_create_independent_streams(self):
        manager = FlowObservationWindowManager('windows', timedelta(seconds=5))
        first = manager.record(stream_packet(b'ab', 10)).active_window
        manager.record(stream_packet(b'cd', 12, seconds=1))
        closed = manager.close(first.identity)
        self.assertEqual(closed.coordinated_state.tcp_stream_state.forward.payload, b'abcd')
        reopened = manager.record(stream_packet(b'XY', 900, seconds=2)).active_window
        expired = manager.record(stream_packet(b'Z', 1000, seconds=8))
        self.assertEqual(expired.closed_windows[0].coordinated_state.tcp_stream_state, reopened.coordinated_state.tcp_stream_state)
        final = manager.end_capture_session()[0]
        self.assertEqual(final.coordinated_state.tcp_stream_state.forward.payload, b'Z')
        self.assertEqual(first.coordinated_state.tcp_stream_state.forward.payload, b'ab')
        self.assertEqual(closed.coordinated_state.tcp_stream_state.forward.payload, b'abcd')
        with self.assertRaises(FrozenInstanceError):
            closed.coordinated_state.tcp_stream_state.forward.payload = b'changed'
        self.assertEqual(manager.end_capture_session(), ())

    def test_stream_and_window_publication_failures_do_not_advance_continuation(self):
        for model in (TCPStreamState, FlowObservationWindowUpdate):
            manager = FlowObservationWindowManager('atomic', timedelta(seconds=5))
            first = manager.record(stream_packet(b'ab', 10)).active_window
            with patch.object(model, '__post_init__', side_effect=MemoryError('publication')):
                with self.assertRaises(MemoryError):
                    manager.record(stream_packet(b'cd', 12, seconds=2))
            current = manager.active_windows()[0]
            self.assertIs(current.coordinated_state, first.coordinated_state)
            self.assertEqual(current.coordinated_state.tcp_stream_state.forward.next_sequence, 12)
            retry = manager.record(stream_packet(b'cd', 12, seconds=1)).active_window
            self.assertEqual(retry.coordinated_state.tcp_stream_state.forward.contiguous_payload, b'abcd')
            self.assertEqual(retry.coordinated_state.flow_statistics.packet_count, 2)

    def test_failed_first_publication_and_failed_expiration_do_not_replace_window(self):
        manager = FlowObservationWindowManager('atomic', timedelta(seconds=5))
        with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                manager.record(stream_packet(b'ab', 10))
        self.assertEqual(manager.active_windows(), ())
        first = manager.record(stream_packet(b'ab', 10)).active_window
        self.assertEqual(first.key.sequence_number, 0)
        with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                manager.record(stream_packet(b'XY', 900, seconds=6))
        self.assertEqual(manager.active_windows(), (first,))
        continuation = manager.record(stream_packet(b'cd', 12, seconds=1)).active_window
        self.assertEqual(continuation.coordinated_state.tcp_stream_state.forward.contiguous_payload, b'abcd')

    def test_capture_failure_finalizes_only_accepted_contiguous_prefix(self):
        raw = message(0x60, b'opaque')
        source = MemoryPacketSource((stream_observation(raw[:5], 10),), iteration_error=RuntimeError('capture failure'))
        windows = []
        with self.assertRaisesRegex(RuntimeError, 'capture failure'):
            run_flow_observation_session(source, capture_session_id='failure', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=windows.append)
        self.assertEqual(source.events[-1], 'stop')
        stream = windows[0].coordinated_state.tcp_stream_state.forward
        self.assertEqual((stream.contiguous_payload, stream.next_sequence), (raw[:5], 15))
        self.assertIs(analyze_ldap_payload(stream.contiguous_payload).messages[0].status, LDAPMessageStatus.INCOMPLETE)

    def test_ldap_single_payload_and_contiguous_split_have_identical_framing(self):
        raw = message(0x60, bytes.fromhex('02010304008000'))
        for ipv6 in (False, True):
            whole = analyze_packet(ldap_observation(raw, ipv6=ipv6, sequence=10))
            expected = whole.ldap
            manager = FlowObservationWindowManager('ldap', timedelta(seconds=5))
            first = manager.record(analyze_packet(ldap_observation(raw[:5], ipv6=ipv6, sequence=10))).active_window
            prefix = first.coordinated_state.tcp_stream_state.forward
            self.assertIs(analyze_ldap_payload(prefix.contiguous_payload).messages[0].status, LDAPMessageStatus.INCOMPLETE)
            manager.record(analyze_packet(ldap_observation(message(0x61, RESULT), 1, ipv6, True, sequence=500)))
            manager.record(analyze_packet(ldap_observation(raw[5:8], 2, ipv6, sequence=15)))
            manager.record(analyze_packet(ldap_observation(raw[8:], 3, ipv6, sequence=18)))
            final = manager.end_capture_session()[0]
            stream = final.coordinated_state.tcp_stream_state.forward
            self.assertEqual((stream.contiguous_payload, stream.start_sequence, stream.next_sequence), (raw, 10, 10 + len(raw)))
            self.assertEqual(analyze_ldap_payload(stream.contiguous_payload), expected)
            single_state = FlowStateCoordinator().record(whole)
            self.assertEqual(analyze_ldap_payload(single_state.tcp_stream_state.forward.contiguous_payload), expected)
            self.assertEqual(prefix.contiguous_payload, raw[:5])
            self.assertEqual(first.coordinated_state.ldap_statistics.incomplete_observation_count, 1)
            self.assertEqual(final.coordinated_state.ldap_statistics.request_count, 0)

    def test_ldap_gap_is_unavailable_and_retransmission_preserves_one_message(self):
        raw = message(0x60, b'opaque')
        gap = observe_streams((ldap_observation(raw[:5], sequence=10), ldap_observation(raw[5:], 1, sequence=16)))[0]
        stream = gap.coordinated_state.tcp_stream_state.forward
        self.assertIs(stream.status, TCPStreamStatus.GAP)
        self.assertIsNone(stream.contiguous_payload)
        self.assertEqual(stream.payload, raw[:5])
        self.assertIs(analyze_ldap_payload(stream.payload).messages[0].status, LDAPMessageStatus.INCOMPLETE)
        repeated = observe_streams((ldap_observation(raw[:5], sequence=10), ldap_observation(raw[:5], 1, sequence=10),
                                   ldap_observation(raw[5:], 2, sequence=15), ldap_observation(raw, 3, sequence=10)))[0]
        observed = analyze_ldap_payload(repeated.coordinated_state.tcp_stream_state.forward.contiguous_payload)
        self.assertEqual(observed, analyze_ldap_payload(raw))
        self.assertEqual(len(observed.messages), 1)

    def test_interleaved_ldap_stream_output_matches_isolated_flow(self):
        raw = message(0x60, b'opaque')
        packets = (ldap_observation(raw[:5], sequence=10), stream_observation(b'unrelated', 900, 1),
                   ldap_observation(raw[:4], 1, True, sequence=50),
                   ldap_observation(raw[5:], 2, sequence=15), ldap_observation(raw[4:], 3, True, sequence=54))
        windows = observe_streams(packets)
        for window in (windows[0], windows[2]):
            self.assertEqual(analyze_ldap_payload(window.coordinated_state.tcp_stream_state.forward.contiguous_payload),
                             analyze_ldap_payload(raw))
        self.assertEqual(windows[0].coordinated_state.tcp_stream_state,
                         observe_streams((packets[0], packets[3]))[0].coordinated_state.tcp_stream_state)

    def test_pcap_streams_detection_evaluation_and_research_projection_remain_compatible(self):
        packets = tuple(stream_observation(payload, sequence, second, ipv6)
                        for second, payload, sequence in ((0, b'ab', 10), (1, b'cd', 12)) for ipv6 in (False, True))
        expected = observe_streams(packets)
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'stream.pcap'
            path.write_bytes(pcap_bytes(tuple((int(packet.captured_at.timestamp()) * 1000000, packet.raw_bytes) for packet in packets)))
            windows = []
            run_flow_observation_session(PcapPacketSource(path, source=CaptureSource('protocol-combinations')),
                                         capture_session_id='stream', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=windows.append)
        self.assertEqual(tuple(windows), expected)
        for window in windows:
            legacy = replace(window, coordinated_state=replace(window.coordinated_state, tcp_stream_state=None))
            self.assertEqual(research_example_from_window(window).projection, research_example_from_window(legacy).projection)
            actual, previous = extract_flow_feature_snapshot(window), extract_flow_feature_snapshot(legacy)
            for field in fields(actual):
                if field.name != 'observation_window':
                    self.assertEqual(getattr(actual, field.name), getattr(previous, field.name))
        actual = run_end_to_end_validation(MemoryPacketSource(packets), configuration=settings(),
                                          capture_session_id='stream', ground_truth=GroundTruth((), ()))
        with patch('analysis.flow_state_coordinator.update_tcp_stream_state', return_value=None):
            previous = run_end_to_end_validation(MemoryPacketSource(packets), configuration=settings(),
                                                capture_session_id='stream', ground_truth=GroundTruth((), ()))
        self.assertEqual(actual.pipeline_result.packet_findings, previous.pipeline_result.packet_findings)
        self.assertEqual(actual.report.metrics, previous.report.metrics)
        self.assertEqual(len(actual.pipeline_result.flow_findings), len(previous.pipeline_result.flow_findings))
        for finding, reference in zip(actual.pipeline_result.flow_findings, previous.pipeline_result.flow_findings):
            evidence = finding.raw_evidence
            window = evidence.snapshot.observation_window if hasattr(evidence, 'snapshot') else evidence.observation_window
            stripped = replace(window, coordinated_state=replace(window.coordinated_state, tcp_stream_state=None))
            evidence = replace(evidence, **({'snapshot': extract_flow_feature_snapshot(stripped)} if hasattr(evidence, 'snapshot')
                                           else {'observation_window': stripped}))
            self.assertEqual(replace(finding, raw_evidence=evidence), reference)

    def test_coordinated_state_validates_extension_and_preserves_legacy_constructors(self):
        state = FlowStateCoordinator().record(stream_packet(b'ab'))
        with self.assertRaises(TypeError):
            replace(state, tcp_stream_state=object())
        other = FlowStateCoordinator().record(stream_packet(b'ab', ipv6=True))
        with self.assertRaises(FlowCoordinationError):
            replace(state, tcp_stream_state=other.tcp_stream_state)
        arguments = tuple(getattr(state, field.name) for field in fields(state) if field.name != 'tcp_stream_state')
        self.assertIsNone(type(state)(*arguments).tcp_stream_state)
        udp = analyze_packet(observation(frame(17, transport(17, b'udp')), 0))
        udp_state = FlowStateCoordinator().record(udp)
        with self.assertRaises(FlowCoordinationError):
            replace(udp_state, tcp_stream_state=state.tcp_stream_state)

    def test_stream_reads_existing_decoded_transport_without_reparsing_packet_bytes(self):
        for ipv6 in (False, True):
            packet = stream_packet(b'abc', 10, ipv6=ipv6)
            with ExitStack() as stack:
                for target in ('capture.packet_observation.PacketObservation.raw_bytes',
                               'analysis.ethernet.EthernetFrame.payload', 'analysis.ipv4.IPv4Packet.payload',
                               'analysis.ipv6.IPv6Packet.payload'):
                    stack.enter_context(patch(target, new_callable=PropertyMock, create=True,
                                              side_effect=AssertionError('packet bytes accessed')))
                stream = stream_states(packet)[0].forward
            self.assertEqual((stream.contiguous_payload, stream.start_sequence, stream.next_sequence), (b'abc', 10, 13))

    def test_failed_stream_publication_during_capture_finalizes_previous_prefix(self):
        packets = (stream_observation(b'ab', 10), stream_observation(b'cd', 12, 1))
        source = MemoryPacketSource(packets)
        windows = []
        original = TCPStreamState.__post_init__

        def validate(state):
            original(state)
            if state.forward.payload == b'abcd':
                raise RuntimeError('stream publication failed')

        with patch.object(TCPStreamState, '__post_init__', validate):
            with self.assertRaisesRegex(RuntimeError, 'stream publication failed'):
                run_flow_observation_session(source, capture_session_id='failure', inactivity_timeout=timedelta(seconds=5),
                                             closed_window_consumer=windows.append)
        self.assertEqual(len(windows), 1)
        state = windows[0].coordinated_state
        self.assertEqual((state.tcp_stream_state.forward.contiguous_payload, state.tcp_stream_state.forward.next_sequence), (b'ab', 12))
        self.assertEqual(state.flow_statistics.packet_count, 1)
        self.assertEqual(source.events[-1], 'stop')

    def test_structural_determinism_across_repeats_hash_seeds_and_timezones(self):
        expected = deterministic_stream_results()
        self.assertEqual(expected, deterministic_stream_results())
        script = ('from tests.test_tcp_stream_integration import deterministic_stream_results\n'
                  'import sys\nsys.stdout.write(repr(deterministic_stream_results()))\n')
        results = []
        for seed, zone in (('0', 'UTC'), ('1', 'Asia/Kolkata'), ('721', 'America/Los_Angeles'), ('0', 'UTC')):
            environment = dict(os.environ, PYTHONHASHSEED=seed, TZ=zone, PYTHONPATH='src', PYTHONDONTWRITEBYTECODE='1')
            results.append(subprocess.check_output([sys.executable, '-c', script], env=environment, timeout=15))
        self.assertTrue(all(result == results[0] for result in results))


if __name__ == '__main__':
    unittest.main()
