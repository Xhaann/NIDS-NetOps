import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, asdict, fields, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    FlowCoordinationError, FlowObservationWindowManager, FlowObservationWindowUpdate,
    LDAPMessageStatus, LDAPStreamStatus, TCPStreamState, analyze_packet,
    extract_flow_feature_snapshot,
)
from analysis import ldap_stream_framing
from application import GroundTruth, run_end_to_end_validation, run_flow_observation_session
from capture import CaptureSource, PcapPacketSource
from research import research_example_from_window
from tests.pcap_scenarios import frame, pcap_bytes, transport
from tests.protocol_scenarios import observation
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ldap import RESULT, message
from tests.test_ldap_flow_statistics import ldap_observation
from tests.test_ldap_stream_framing import framing_packet, framing_states
from tests.test_tcp_stream_observation import stream_observation


def observe_framing(observations):
    manager = FlowObservationWindowManager('framing', timedelta(seconds=5))
    updates = []
    closed = []
    for packet in observations:
        update = manager.record(analyze_packet(packet))
        updates.append(update.active_window)
        closed.extend(update.closed_windows)
    closed.extend(manager.end_capture_session())
    return tuple(updates), tuple(closed)


def deterministic_framing_results():
    raw = message(0x60, b'abcdefgh')
    response = message(0x61, RESULT)
    observations = tuple(ldap_observation(payload, second, ipv6, reverse, sequence=sequence)
                         for second, payload, sequence, reverse in ((0, message() + raw[:5], 100, False),
                             (1, response, 900, True), (2, raw[5:], 100 + len(message()) + 5, False),
                             (3, message(0x7A) + b'\x30\xff', 100 + len(message() + raw), False))
                         for ipv6 in (False, True))
    updates, closed = observe_framing(observations)
    gap = observe_framing((ldap_observation(raw[:5], sequence=100), ldap_observation(raw[5:], 1, sequence=106)))
    maximum = message(0x4A, b'x' * (65536 - 11))
    reclaimed = framing_states((maximum[:32768], maximum[32768:], message()))[-1]
    return (tuple(asdict(w) for w in updates), tuple(asdict(w) for w in closed),
            tuple(asdict(w) for w in gap[1]), asdict(reclaimed))


class LDAPStreamLifecycleTests(unittest.TestCase):
    def test_ipv4_ipv6_directional_messages_are_emitted_once_and_never_combined(self):
        request, response = message(0x60, b'abcdefgh'), message(0x61, RESULT)
        for ipv6 in (False, True):
            observations = (ldap_observation(request[:5], 0, ipv6, sequence=100),
                            ldap_observation(response, 1, ipv6, True, sequence=900),
                            ldap_observation(request[5:], 2, ipv6, sequence=105))
            updates, closed = observe_framing(observations)
            actual = [window.coordinated_state.ldap_stream_state for window in updates]
            self.assertEqual(actual[1].forward.messages, ())
            self.assertEqual(actual[1].forward.retained_suffix, request[:5])
            self.assertEqual([m.operation_tag for m in actual[1].reverse.messages], [0x61])
            self.assertEqual([m.operation_tag for m in actual[2].forward.messages], [0x60])
            self.assertEqual(actual[2].reverse.messages, ())
            self.assertEqual((actual[2].forward.consumed_offset, actual[2].reverse.consumed_offset), (len(request), len(response)))
            self.assertEqual((actual[2].forward.complete_message_count, actual[2].reverse.complete_message_count), (1, 1))
            self.assertIs(closed[0].coordinated_state, updates[-1].coordinated_state)
            self.assertEqual(closed[0].identity.ip_version, 6 if ipv6 else 4)

    def test_unrelated_ipv4_ipv6_tcp_udp_flows_do_not_change_framing(self):
        raw = message(0x60, b'abcdefgh')
        groups = []
        for ipv6 in (False, True):
            groups.append((ldap_observation(raw[:5], 0, ipv6, sequence=100), ldap_observation(raw[5:], 2, ipv6, sequence=105)))
            groups.append((stream_observation(b'HTTP', 900, 1, ipv6),))
            groups.append((observation(frame(17, transport(17, b'UDP', ipv6), ipv6), 1),))
        observations = tuple(sorted((p for group in groups for p in group), key=lambda p: p.captured_at))
        _, closed = observe_framing(observations)
        self.assertEqual(len(closed), 6)
        actual = {w.identity: w.coordinated_state for w in closed}
        for group in groups:
            expected = observe_framing(group)[1][0]
            self.assertEqual(actual[expected.identity], expected.coordinated_state)
            if expected.identity.protocol == 17 or expected.identity.destination_port != 389:
                self.assertIsNone(expected.coordinated_state.ldap_stream_state)

    def test_finalized_windows_and_new_windows_keep_independent_consumption_and_counts(self):
        raw = message(0x60, b'abcdefgh')
        manager = FlowObservationWindowManager('windows', timedelta(seconds=5))
        first = manager.record(framing_packet(message() + raw[:5])).active_window
        closed = manager.close(first.identity)
        restarted = manager.record(framing_packet(raw, 900, 1)).active_window
        expired = manager.record(framing_packet(raw[:5], 1000, 7))
        final = manager.end_capture_session()[0]
        self.assertEqual(closed.coordinated_state.ldap_stream_state.forward.retained_suffix, raw[:5])
        self.assertEqual(closed.coordinated_state.ldap_stream_state.forward.complete_message_count, 1)
        self.assertEqual(restarted.coordinated_state.ldap_stream_state.forward.messages[0].offset, 0)
        self.assertEqual(restarted.coordinated_state.ldap_stream_state.forward.consumed_offset, len(raw))
        self.assertEqual(expired.closed_windows[0].coordinated_state, restarted.coordinated_state)
        self.assertIs(final.coordinated_state.ldap_stream_state.forward.status, LDAPStreamStatus.INCOMPLETE)
        self.assertEqual(final.coordinated_state.ldap_stream_state.forward.complete_message_count, 0)
        with self.assertRaises(FrozenInstanceError):
            closed.coordinated_state.ldap_stream_state.forward.messages = ()
        self.assertEqual(manager.end_capture_session(), ())

    def test_failed_window_publication_preserves_pending_suffix_cursor_and_counts(self):
        first, second = message(), message(0x60, b'abcdefgh')
        manager = FlowObservationWindowManager('atomic', timedelta(seconds=5))
        before = manager.record(framing_packet(first + second[:5])).active_window
        with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=MemoryError('publication')):
            with self.assertRaises(MemoryError):
                manager.record(framing_packet(second[5:], 100 + len(first) + 5, 2))
        self.assertIs(manager.active_windows()[0].coordinated_state, before.coordinated_state)
        retry = manager.record(framing_packet(second[5:], 100 + len(first) + 5, 1)).active_window
        self.assertEqual(retry.coordinated_state.ldap_stream_state.forward.complete_message_count, 2)
        self.assertEqual([m.offset for m in retry.coordinated_state.ldap_stream_state.forward.messages], [len(first)])
        self.assertEqual(before.coordinated_state.ldap_stream_state.forward.retained_suffix, second[:5])

    def test_failed_publication_after_reclamation_does_not_discard_previous_tcp_history(self):
        raw = message()
        block = raw * 4681
        self.assertEqual(len(block), 32767)
        manager = FlowObservationWindowManager('atomic', timedelta(seconds=5))
        manager.record(framing_packet(block))
        before = manager.record(framing_packet(block, 100 + len(block), 1)).active_window
        with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                manager.record(framing_packet(raw, 100 + len(block) * 2, 3))
        self.assertIs(manager.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(before.coordinated_state.tcp_stream_state.forward.payload, block * 2)
        retry = manager.record(framing_packet(raw, 100 + len(block) * 2, 2)).active_window
        framed = retry.coordinated_state.ldap_stream_state.forward
        self.assertEqual(framed.stream.buffer_offset, len(block) * 2)
        self.assertEqual(framed.stream.payload, raw)
        self.assertEqual(framed.messages[0].offset, len(block) * 2)
        self.assertEqual(framed.complete_message_count, 9363)

    def test_parser_internal_failure_does_not_publish_consumed_earlier_candidate_frames(self):
        first, second = message(), message(identifier=b'\x02')
        manager = FlowObservationWindowManager('atomic', timedelta(seconds=5))
        before = manager.record(framing_packet(first[:2])).active_window
        original = ldap_stream_framing._message

        def parse(*args):
            result = original(*args)
            if result.message_id == 2:
                raise RuntimeError('framing publication failure')
            return result

        with patch.object(ldap_stream_framing, '_message', side_effect=parse):
            with self.assertRaises(RuntimeError):
                manager.record(framing_packet(first[2:] + second, 102, 2))
        self.assertIs(manager.active_windows()[0].coordinated_state, before.coordinated_state)
        retry = manager.record(framing_packet(first[2:] + second, 102, 1)).active_window
        self.assertEqual([m.message_id for m in retry.coordinated_state.ldap_stream_state.forward.messages], [1, 2])
        self.assertEqual(before.coordinated_state.ldap_stream_state.forward.consumed_offset, 0)

    def test_capture_failure_finalizes_complete_frames_and_preserves_incomplete_tail(self):
        first, second = message(), message(0x60, b'abcdefgh')
        source = MemoryPacketSource((ldap_observation(first + second[:5]),), iteration_error=RuntimeError('capture failure'))
        closed = []
        with self.assertRaisesRegex(RuntimeError, 'capture failure'):
            run_flow_observation_session(source, capture_session_id='failure', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        self.assertEqual(source.events[-1], 'stop')
        self.assertEqual(len(closed), 1)
        framed = closed[0].coordinated_state.ldap_stream_state.forward
        self.assertEqual([m.message_length for m in framed.messages], [len(first)])
        self.assertEqual(framed.retained_suffix, second[:5])
        self.assertIs(framed.pending_message.status, LDAPMessageStatus.INCOMPLETE)
        self.assertEqual(framed.complete_message_count, 1)

    def test_pcap_framing_and_existing_detection_evaluation_research_values_remain_compatible(self):
        raw = message(0x60, b'abcdefgh')
        packets = tuple(ldap_observation(payload, second, ipv6, sequence=sequence)
                        for second, payload, sequence in ((0, raw[:5], 100), (1, raw[5:], 105)) for ipv6 in (False, True))
        expected = observe_framing(packets)[1]
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'framing.pcap'
            path.write_bytes(pcap_bytes(tuple((int(p.captured_at.timestamp()) * 1000000, p.raw_bytes) for p in packets)))
            actual = []
            run_flow_observation_session(PcapPacketSource(path, source=CaptureSource('protocol-combinations')),
                                         capture_session_id='framing', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=actual.append)
        self.assertEqual(tuple(actual), expected)
        config = settings()
        config = replace(config, flow_volume_configuration=replace(config.flow_volume_configuration, threshold=100),
                         tcp_control_configuration=replace(config.tcp_control_configuration, threshold=100))
        actual = run_end_to_end_validation(MemoryPacketSource(packets), configuration=config,
                                          capture_session_id='framing', ground_truth=GroundTruth((), ()))
        with patch('analysis.flow_state_coordinator.update_ldap_stream_state', return_value=None):
            baseline = run_end_to_end_validation(MemoryPacketSource(packets), configuration=config,
                                                capture_session_id='framing', ground_truth=GroundTruth((), ()))
        self.assertEqual(actual.pipeline_result.packet_findings, baseline.pipeline_result.packet_findings)
        self.assertEqual(actual.report.metrics, baseline.report.metrics)
        self.assertEqual(len(actual.pipeline_result.flow_findings), 4)
        self.assertEqual(len(actual.pipeline_result.flow_findings), len(baseline.pipeline_result.flow_findings))
        for finding, original in zip(actual.pipeline_result.flow_findings, baseline.pipeline_result.flow_findings):
            evidence, prior = finding.raw_evidence, original.raw_evidence
            window = evidence.snapshot.observation_window if hasattr(evidence, 'snapshot') else evidence.observation_window
            old_window = prior.snapshot.observation_window if hasattr(prior, 'snapshot') else prior.observation_window
            self.assertEqual(research_example_from_window(window).projection, research_example_from_window(old_window).projection)
            current_stream = window.coordinated_state.tcp_stream_state.forward
            previous_stream = old_window.coordinated_state.tcp_stream_state.forward
            self.assertEqual({k: v for k, v in vars(current_stream).items() if k != 'consumed_length'},
                             {k: v for k, v in vars(previous_stream).items() if k != 'consumed_length'})
            stripped = replace(window, coordinated_state=replace(window.coordinated_state, ldap_stream_state=None, ldap_correlation_state=None,
                                                                 tcp_stream_state=old_window.coordinated_state.tcp_stream_state))
            evidence = replace(evidence, **({'snapshot': extract_flow_feature_snapshot(stripped)} if hasattr(evidence, 'snapshot')
                                           else {'observation_window': stripped}))
            self.assertEqual(replace(finding, raw_evidence=evidence), original)
            self.assertNotEqual(finding.decision.value, 'match')

    def test_coordinator_rejects_mismatched_stream_reference_and_preserves_old_constructor(self):
        state = framing_states((message(),))[0]
        with self.assertRaises(TypeError):
            replace(state, ldap_stream_state=object())
        with self.assertRaises(FlowCoordinationError):
            replace(state, tcp_stream_state=replace(state.tcp_stream_state))
        with self.assertRaises(FlowCoordinationError):
            replace(state, tcp_stream_state=TCPStreamState(state.identity))
        previous_arguments = tuple(getattr(state, field.name) for field in fields(state)
                                   if field.name not in ('ldap_stream_state', 'ldap_correlation_state', 'dns_transaction_statistics', 'dns_query_name_statistics', 'dns_resource_record_statistics', 'dns_message_flag_statistics', 'dns_edns_statistics', 'dns_stream_state', 'tls_record_state'))
        self.assertIsNone(type(state)(*previous_arguments).ldap_stream_state)

    def test_hash_seed_timezone_and_repeated_structural_determinism(self):
        self.assertEqual(deterministic_framing_results(), deterministic_framing_results())
        script = ('from tests.test_ldap_stream_lifecycle import deterministic_framing_results\n'
                  'import sys\nsys.stdout.write(repr(deterministic_framing_results()))\n')
        results = []
        for seed, zone in (('0', 'UTC'), ('1', 'Asia/Kolkata'), ('9157', 'America/Los_Angeles'), ('0', 'UTC')):
            environment = dict(os.environ, PYTHONHASHSEED=seed, TZ=zone, PYTHONPATH='src', PYTHONDONTWRITEBYTECODE='1')
            results.append(subprocess.check_output([sys.executable, '-c', script], env=environment, timeout=15))
        self.assertTrue(all(result == results[0] for result in results))


if __name__ == '__main__':
    unittest.main()
