import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import fields, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import analysis.flow_state_coordinator as coordinator_module
from analysis import (
    DNSCorrelationStatus, DNSMessageStatus, DNSStreamStatus, FeatureContractVersion, FlowCoordinationError,
    FlowDirection, FlowObservationWindowClosureReason, FlowStateCoordinator, TCPStreamStatus,
    analyze_dns_message, analyze_packet, extract_flow_feature_snapshot, finalize_dns_correlation_state, flow_identity_from_packet,
    update_dns_correlation_state, update_dns_edns_statistics, update_dns_message_flag_statistics,
    update_dns_query_name_statistics, update_dns_resource_record_statistics, update_dns_transaction_statistics,
)
from application import run_flow_observation_session
from capture import CaptureError, PcapPacketSource
from ml import project_flow_features
from tests.pcap_scenarios import pcap_bytes
from tests.test_dns import header, name, question, record as resource_record
from tests.test_dns_correlation_lifecycle import manager
from tests.test_dns_edns import message, opt, option
from tests.test_dns_stream_framing import framed, packet
from tests.test_dns_transaction_statistics_lifecycle import run_packets
from tests.test_flow_feature_snapshot import snapshot_features
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ldap import message as ldap_message


STATISTICS = ('dns_transaction_statistics', 'dns_query_name_statistics', 'dns_resource_record_statistics',
              'dns_message_flag_statistics', 'dns_edns_statistics')
REDUCERS = (update_dns_transaction_statistics, update_dns_query_name_statistics, update_dns_resource_record_statistics,
            update_dns_message_flag_statistics, update_dns_edns_statistics)


def raw(identifier=1, response=False, edns=True, **kwargs):
    extra = opt(**kwargs) if edns else b''
    answer = resource_record(data=b'opaque') if response else b''
    return (header(1, int(response), 0, int(edns), flags=0x87b3 if response else 0x07b0, identifier=identifier)
            + question(name(b'Example-1')) + answer + extra)


def record(instance, payload, **kwargs):
    return instance.record(analyze_packet(packet(payload, **kwargs))).active_window


def direct_statistics(events, identity):
    current, values = None, [None] * len(REDUCERS)
    for payload, reverse, timestamp in events:
        current = update_dns_correlation_state(current, analyze_dns_message(payload), identity,
                                              FlowDirection.REVERSE if reverse else FlowDirection.FORWARD, timestamp)
        if current is not None:
            for item in current.observations:
                if item.status is not DNSCorrelationStatus.PENDING:
                    values = [reducer(value, item) for reducer, value in zip(REDUCERS, values)]
    retained = sum(item.status is not DNSCorrelationStatus.PENDING for item in current.observations)
    final = finalize_dns_correlation_state(current)
    for item in final.observations[retained:]:
        values = [reducer(value, item) for reducer, value in zip(REDUCERS, values)]
    return tuple(values)


def traffic():
    values = []
    for phase in range(4):
        for ipv6, port in ((False, 12345), (True, 12345), (True, 12346)):
            request = framed(raw(data=option(port, b'abc') + option(65535), version=3, flags=0x8000))
            response = framed(raw(response=True, data=option(10, b'opaque'), extended=255, version=7))
            payload, sequence, reverse = ((request[:1], 100, False), (response[:6], 900, True),
                                           (request[1:], 101, False), (response[6:], 906, True))[phase]
            values.append(packet(payload, sequence=sequence, seconds=len(values) / 10,
                                 reverse=reverse, ipv6=ipv6, client_port=port, extensions=(0, 60) if ipv6 else ()))
    return tuple(values)


def observable(window):
    state = window.dns_stream_state
    directions = tuple(None if value is None else
                       (value.prefix, value.declared_length, value.payload, value.status.value,
                        None if value.unavailable_reason is None else value.unavailable_reason.value,
                        value.consumed_offset, value.stream.status.value, value.stream.buffer_offset)
                       for value in (state.forward, state.reverse))
    return (window.key.sequence_number, window.identity.ip_version, window.identity.source_port,
            None if window.closure_reason is None else window.closure_reason.value,
            directions, tuple(getattr(window, name) for name in STATISTICS))


def replay():
    instance = manager(3)
    events = []
    inputs = traffic() + (packet(b'gap', sequence=5000, seconds=2),
                          packet(b'\x00', client_port=12347, seconds=3),
                          packet(framed(raw(9, response=True)), client_port=12348, seconds=4))
    for item in inputs:
        update = instance.record(analyze_packet(item))
        events.extend(observable(window) for window in (update.active_window,) + update.closed_windows)
    events.extend(observable(window) for window in instance.end_capture_session())
    return tuple(events)


class DNSStreamLifecycleTests(unittest.TestCase):
    def test_real_tcp_no_opt_request_response_correlation(self):
        first, second = raw(edns=False), raw(response=True, edns=False)
        window, = run_packets((packet(framed(first)), packet(framed(second), reverse=True, sequence=900, seconds=1)))
        self.assertEqual(window.identity.protocol, 6)
        self.assertEqual(window.dns_transaction_statistics.matched_count, 1)
        self.assertEqual(window.dns_edns_statistics.edns_message_count, 0)
        item, = window.dns_correlation_state.observations
        self.assertEqual((item.request, item.message), (analyze_dns_message(first), analyze_dns_message(second)))

    def test_edns_and_all_existing_statistics_equal_delimited_tcp_path(self):
        first = raw(data=option(65535) + option(8, b'abc'), version=255, flags=0xffff)
        second = raw(response=True, data=option(10, b'xyz'), extended=255, flags=0x8000)
        inputs = (packet(framed(first), seconds=1), packet(framed(second), reverse=True, sequence=900, seconds=3))
        window, = run_packets(inputs)
        expected = direct_statistics(tuple((payload, reverse, source.captured_at)
                                           for payload, reverse, source in ((first, False, inputs[0]), (second, True, inputs[1]))), window.identity)
        self.assertEqual(tuple(getattr(window, name) for name in STATISTICS), expected)
        self.assertEqual(window.dns_transaction_statistics.mean_matched_latency_microseconds, 2000000)
        self.assertEqual(window.dns_query_name_statistics.query_name_count, 2)
        self.assertEqual(window.dns_resource_record_statistics.resource_record_count, 3)
        self.assertEqual(window.dns_message_flag_statistics.authenticated_data_count, 2)
        self.assertEqual(window.dns_edns_statistics.option_count, 3)
        self.assertEqual(window.dns_edns_statistics.unknown_option_count, 3)
        self.assertEqual(window.dns_edns_statistics.version_counts[255], 1)
        self.assertTrue(all(item.authoritative_answer and item.truncated and item.recursion_desired
                            and item.recursion_available and item.authenticated_data and item.checking_disabled
                            for item in (window.dns_correlation_state.observations[0].request.header,
                                         window.dns_correlation_state.observations[0].message.header)))

    def test_segmented_frames_use_completion_capture_timestamp(self):
        first, second = framed(raw()), framed(raw(response=True))
        inputs = (packet(first[:1]), packet(first[1:8], sequence=101, seconds=1),
                  packet(first[8:], sequence=108, seconds=2),
                  packet(second[:7], sequence=900, reverse=True, seconds=3),
                  packet(second[7:], sequence=907, reverse=True, seconds=4))
        window, = run_packets(inputs)
        item, = window.dns_correlation_state.observations
        self.assertEqual(item.request_captured_at, inputs[2].captured_at)
        self.assertEqual(item.captured_at, inputs[4].captured_at)
        self.assertEqual(window.dns_transaction_statistics.mean_matched_latency_microseconds, 2000000)

    def test_multiple_requests_and_responses_per_observation_are_all_reduced(self):
        requests = b''.join(framed(raw(index, data=option(index))) for index in range(5))
        responses = b''.join(framed(raw(index, True, data=option(index))) for index in reversed(range(5)))
        window, = run_packets((packet(requests), packet(responses, sequence=900, reverse=True)))
        self.assertEqual(window.dns_transaction_statistics.matched_count, 5)
        self.assertEqual(window.dns_edns_statistics.edns_message_count, 10)
        self.assertEqual(window.dns_edns_statistics.option_count, 10)
        self.assertEqual(window.dns_correlation_state.requests, ())
        self.assertEqual(len(window.dns_correlation_state.observations), 1)

    def test_sequential_id_reuse_preserves_multiplicity(self):
        instance = manager()
        first, second = framed(raw(data=option(7))), framed(raw(response=True, data=option(7)))
        for index in range(20):
            record(instance, first, sequence=100 + index * len(first))
            active = record(instance, second, sequence=900 + index * len(second), reverse=True)
        closed = instance.close(active.identity)
        self.assertEqual(closed.dns_transaction_statistics.matched_count, 20)
        self.assertEqual(closed.dns_edns_statistics.option_code_counts[0][7], 40)

    def test_ambiguous_ids_and_unresolved_original_keep_existing_accounting(self):
        first, second, response = raw(data=option(1)), raw(data=option(2)), raw(response=True, data=option(3))
        window, = run_packets((packet(framed(first) + framed(second)), packet(framed(response), sequence=900, reverse=True)))
        self.assertEqual((window.dns_transaction_statistics.ambiguous_count, window.dns_transaction_statistics.unresolved_count), (2, 1))
        self.assertEqual(window.dns_edns_statistics.option_code_counts[0][1:4], (1, 1, 1))

    def test_pending_capacity_with_many_framed_requests_remains_bounded(self):
        window, = run_packets((packet(b''.join(framed(raw(index)) for index in range(140))),))
        self.assertEqual(window.dns_transaction_statistics.unresolved_count, 140)
        self.assertEqual(window.dns_edns_statistics.edns_message_count, 140)
        self.assertEqual(window.dns_correlation_state.requests, ())

    def test_partial_edns_never_reaches_parser_before_frame_completion(self):
        data = framed(raw(data=option(65535, b'opaque')))
        instance = manager()
        with patch.object(coordinator_module, 'analyze_dns_message', wraps=analyze_dns_message) as parse:
            for index in range(len(data) - 1):
                active = record(instance, data[index:index + 1], sequence=100 + index)
            self.assertEqual(parse.call_count, 0)
            self.assertIsNone(active.dns_correlation_state)
            record(instance, data[-1:], sequence=100 + len(data) - 1)
            self.assertEqual(parse.call_args.args, (data[2:],))
            self.assertEqual(parse.call_count, 1)

    def test_malformed_incomplete_and_unsupported_dns_frames_keep_parser_statuses(self):
        raws = (header(1) + b'\x80', header(1) + b'\x01', header(1) + b'\x40', message(opt(data=b'\xff')))
        statuses = []
        def parse(payload):
            parsed = analyze_dns_message(payload)
            statuses.append(parsed.status)
            return parsed
        with patch.object(coordinator_module, 'analyze_dns_message', side_effect=parse):
            window, = run_packets((packet(b''.join(map(framed, raws)) + framed(raw(response=True))),))
        self.assertEqual(statuses, [DNSMessageStatus.MALFORMED, DNSMessageStatus.INCOMPLETE,
                                    DNSMessageStatus.UNSUPPORTED, DNSMessageStatus.MALFORMED, DNSMessageStatus.COMPLETE])
        self.assertEqual(window.dns_transaction_statistics.unmatched_count, 1)
        self.assertEqual(window.dns_edns_statistics.edns_message_count, 1)
        self.assertIs(window.dns_stream_state.forward.status, DNSStreamStatus.READY)

    def test_zero_length_frame_is_parsed_once_and_does_not_block_next_frame(self):
        with patch.object(coordinator_module, 'analyze_dns_message', wraps=analyze_dns_message) as parse:
            window, = run_packets((packet(b'\x00\x00' + framed(raw(response=True))),))
        self.assertEqual([call.args[0] for call in parse.call_args_list], [b'', raw(response=True)])
        self.assertEqual(window.dns_transaction_statistics.unmatched_count, 1)

    def test_incomplete_prefix_and_payload_at_closure_never_become_dns(self):
        for data in (b'\x00', framed(raw())[:-1]):
            with patch.object(coordinator_module, 'analyze_dns_message', side_effect=AssertionError('partial frame')):
                window, = run_packets((packet(data),))
            self.assertIs(window.dns_stream_state.forward.status, DNSStreamStatus.INCOMPLETE)
            self.assertIsNone(window.dns_correlation_state)
            self.assertEqual(window.dns_transaction_statistics.total_transaction_count, 0)

    def test_complete_then_partial_closure_and_repeated_finalization(self):
        window, = run_packets((packet(framed(raw(data=option(1))) + framed(raw(2))[:5]),))
        self.assertEqual(window.dns_transaction_statistics.unresolved_count, 1)
        self.assertEqual(window.dns_edns_statistics.option_count, 1)
        for _ in range(5):
            self.assertIs(replace(window).dns_edns_statistics, window.dns_edns_statistics)
            self.assertIs(replace(window).dns_stream_state, window.dns_stream_state)

    def test_ipv4_ipv6_client_ports_and_opposite_partial_frames_are_isolated(self):
        windows = run_packets(traffic())
        self.assertEqual(len(windows), 3)
        self.assertEqual(len({window.identity for window in windows}), 3)
        self.assertEqual([window.identity.ip_version for window in windows], [4, 6, 6])
        for window in windows:
            self.assertEqual(window.dns_transaction_statistics.matched_count, 1)
            self.assertEqual(window.dns_edns_statistics.edns_message_count, 2)
            self.assertEqual(window.dns_edns_statistics.option_count, 3)
            self.assertIs(window.dns_stream_state.forward.status, DNSStreamStatus.READY)
            self.assertIs(window.dns_stream_state.reverse.status, DNSStreamStatus.READY)

    def test_inactivity_does_not_join_partial_frames_across_windows(self):
        data = framed(raw())
        windows = run_packets((packet(data[:5]), packet(data[5:], sequence=105, seconds=5)))
        self.assertEqual(len(windows), 2)
        self.assertIs(windows[0].closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
        self.assertEqual(windows[0].dns_transaction_statistics.total_transaction_count, 0)
        self.assertIs(windows[0].dns_stream_state.forward.status, DNSStreamStatus.INCOMPLETE)
        self.assertEqual(windows[1].dns_stream_state.forward.consumed_offset, len(data) - 5)

    def test_capacity_and_explicit_closure_keep_independent_framing(self):
        instance = manager(1)
        first = record(instance, b'\x00')
        update = instance.record(analyze_packet(packet(framed(raw()), ipv6=True)))
        self.assertIs(update.closed_windows[0].closure_reason, FlowObservationWindowClosureReason.CAPACITY)
        self.assertIs(update.closed_windows[0].dns_stream_state, first.dns_stream_state)
        instance.close(update.active_window.identity)
        reopened = record(instance, b'\x00')
        self.assertEqual(reopened.dns_stream_state.forward.consumed_offset, 1)

    def test_stream_gap_preserves_previous_complete_messages_and_pending_transactions(self):
        instance = manager()
        before = record(instance, framed(raw(data=option(1))) + b'\x00')
        after = record(instance, framed(raw(2)), sequence=1000)
        self.assertIs(after.dns_stream_state.forward.unavailable_reason, TCPStreamStatus.GAP)
        self.assertIs(after.dns_correlation_state.requests[0], before.dns_correlation_state.requests[0])
        closed = instance.close(after.identity)
        self.assertEqual(closed.dns_transaction_statistics.unresolved_count, 1)
        self.assertEqual(closed.dns_edns_statistics.option_count, 1)

    def test_fin_and_reset_deliver_complete_frames_without_fabricating_partial_dns(self):
        for flags in (17, 20):
            window, = run_packets((packet(framed(raw(response=True)) + b'\x00', flags=flags),))
            self.assertEqual(window.dns_transaction_statistics.unmatched_count, 1)
            self.assertIs(window.dns_stream_state.forward.status, DNSStreamStatus.INCOMPLETE)

    def test_parser_failure_leaves_stream_consumption_and_aggregates_retryable(self):
        instance = manager()
        request = framed(raw())
        before = record(instance, request)
        good = raw(response=True)
        payload = framed(good) + framed(raw(2, True))
        with patch.object(coordinator_module, 'analyze_dns_message', side_effect=(analyze_dns_message(good), MemoryError('second frame'))):
            with self.assertRaises(MemoryError):
                record(instance, payload, sequence=900, reverse=True, seconds=2)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        after = record(instance, payload, sequence=900, reverse=True, seconds=1)
        self.assertEqual((after.dns_transaction_statistics.matched_count, after.dns_transaction_statistics.unmatched_count), (1, 1))

    def test_late_aggregation_failure_preserves_entire_multi_frame_candidate(self):
        instance = manager()
        before = record(instance, framed(raw()))
        calls = 0
        def reduce(current, observation):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise MemoryError('second EDNS aggregate')
            return update_dns_edns_statistics(current, observation)
        payload = framed(raw(response=True, data=option(1))) + framed(raw(2, True, data=option(2)))
        with patch.object(coordinator_module, 'update_dns_edns_statistics', side_effect=reduce):
            with self.assertRaises(MemoryError):
                record(instance, payload, sequence=900, reverse=True)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        after = record(instance, payload, sequence=900, reverse=True)
        self.assertEqual(after.dns_edns_statistics.option_count, 2)
        self.assertEqual(after.dns_edns_statistics.edns_message_count, 3)

    def test_failed_publication_does_not_consume_or_recount_on_retry(self):
        instance = manager()
        data = framed(raw(response=True, data=option(1)))
        before = record(instance, data[:1])
        with patch('analysis.flow_observation_window.FlowObservationWindowUpdate', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                record(instance, data[1:], sequence=101)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        after = record(instance, data[1:], sequence=101)
        self.assertEqual(after.dns_edns_statistics.option_count, 1)
        self.assertEqual(after.dns_stream_state.forward.consumed_offset, len(data))

    def test_failed_close_keeps_pending_dns_and_partial_next_frame_retryable(self):
        instance = manager()
        before = record(instance, framed(raw(data=option(1))) + b'\x00')
        with patch('analysis.flow_observation_window.update_dns_edns_statistics', side_effect=MemoryError('closure')):
            with self.assertRaises(MemoryError):
                instance.close(before.identity)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        closed = instance.close(before.identity)
        self.assertEqual(closed.dns_edns_statistics.option_count, 1)
        self.assertEqual(closed.dns_stream_state.forward.prefix, b'\x00')

    def test_stream_infrastructure_failure_propagates_without_publication(self):
        instance = manager()
        before = record(instance, b'\x00')
        with patch.object(coordinator_module, 'update_tcp_stream_state', side_effect=MemoryError('TCP')):
            with self.assertRaises(MemoryError):
                record(instance, b'\x0c' + header(), sequence=101)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)

    def test_capture_failure_publishes_prior_complete_frames_and_partial_closure(self):
        source = MemoryPacketSource((packet(framed(raw(response=True)) + framed(raw(2)) + b'\x00'),),
                                    iteration_error=CaptureError('capture'))
        closed = []
        with self.assertRaises(CaptureError):
            run_flow_observation_session(source, capture_session_id='dns-tcp', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        self.assertEqual((closed[0].dns_transaction_statistics.unmatched_count,
                          closed[0].dns_transaction_statistics.unresolved_count), (1, 1))
        self.assertIs(closed[0].dns_stream_state.forward.status, DNSStreamStatus.INCOMPLETE)
        self.assertEqual(source.events[-1], 'stop')

    def test_framing_state_does_not_retain_completed_dns_or_transaction_graph(self):
        instance = manager()
        first = record(instance, framed(raw(data=option(1, b'abc'))))
        matched = record(instance, framed(raw(response=True)), sequence=900, reverse=True)
        item = matched.dns_correlation_state.observations[0]
        references = [weakref.ref(value) for value in (first, matched, item, item.request, item.message,
                      item.request.header, item.request.questions[0].name, item.request.edns, item.request.edns.options[0])]
        framing = matched.dns_stream_state
        record(instance, b'', sequence=100 + len(framed(raw(data=option(1, b'abc')))))
        del first, matched, item
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual((framing.forward.payload, framing.reverse.payload), (b'', b''))

    def test_releasing_flow_owner_releases_framing_state(self):
        instance = manager()
        window = record(instance, b'\x00')
        reference = weakref.ref(window.dns_stream_state)
        instance.close(window.identity)
        del window
        gc.collect()
        self.assertIsNone(reference())

    def test_generic_version_and_all_49_values_are_identical_without_dns_ingestion(self):
        window, = run_packets((packet(framed(raw())), packet(framed(raw(response=True)), sequence=900, reverse=True, seconds=1)))
        with patch.object(coordinator_module, 'update_dns_stream_state', return_value=None):
            baseline, = run_packets((packet(framed(raw())), packet(framed(raw(response=True)), sequence=900, reverse=True, seconds=1)))
        first, second = extract_flow_feature_snapshot(window), extract_flow_feature_snapshot(baseline)
        self.assertEqual(first.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
        self.assertEqual(snapshot_features(first), snapshot_features(second))
        self.assertEqual(project_flow_features(first), project_flow_features(second))
        self.assertEqual(len(project_flow_features(first).values), 49)

    def test_packet_local_dns_and_delimited_api_remain_compatible(self):
        source = analyze_packet(packet(framed(raw())))
        self.assertIsNone(source.dns)
        self.assertIs(analyze_dns_message(raw()).status, DNSMessageStatus.COMPLETE)
        value = update_dns_correlation_state(None, analyze_dns_message(raw()), flow_identity_from_packet(source),
                                             FlowDirection.FORWARD, source.observation.captured_at)
        self.assertIs(value.observations[0].status, DNSCorrelationStatus.PENDING)

    def test_ldap_port_collision_retains_existing_consumer(self):
        state = FlowStateCoordinator().record(analyze_packet(packet(ldap_message(), client_port=389)))
        self.assertIsNone(state.dns_stream_state)
        self.assertIsNotNone(state.ldap_stream_state)
        self.assertEqual(len(state.ldap_stream_state.forward.messages), 1)

    def test_coordinator_default_type_and_exclusive_stream_reference_validation(self):
        state = FlowStateCoordinator().record(analyze_packet(packet(b'\x00')))
        self.assertIs(state.dns_stream_state.tcp_stream_state, state.tcp_stream_state)
        with self.assertRaises(TypeError):
            replace(state, dns_stream_state={})
        with self.assertRaises(FlowCoordinationError):
            replace(state, tcp_stream_state=replace(state.tcp_stream_state))
        legacy = tuple(getattr(state, member.name) for member in fields(state) if member.name not in ('dns_stream_state', 'tls_record_state', 'tls_handshake_state', 'tls_handshake_statistics', 'tls_client_hellos', 'tls_client_hello_statistics', 'tls_server_hellos'))
        self.assertIsNone(type(state)(*legacy).dns_stream_state)

    def test_four_pcap_encodings_use_real_segmented_tcp_session_path(self):
        inputs = traffic()
        expected = tuple(observable(window) for window in run_packets(inputs))
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'dns-tcp.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((index * 100000, item.raw_bytes) for index, item in enumerate(inputs)), order, nano))
                        windows = []
                        run_flow_observation_session(PcapPacketSource(path), capture_session_id='dns-tcp',
                                                     inactivity_timeout=timedelta(seconds=5), closed_window_consumer=windows.append)
                        self.assertEqual(tuple(observable(window) for window in windows), expected)

    def test_independent_replay_is_identical(self):
        result = replay()
        self.assertEqual(result, replay())
        self.assertTrue(any(event[-1][0].matched_count for event in result))
        self.assertTrue(any(direction is not None and direction[3] == 'unavailable'
                            for event in result for direction in event[-2]))

    def test_nine_hash_seed_timezone_combinations(self):
        script = ('from tests.test_dns_stream_lifecycle import replay\n'
                  'import hashlib\nprint(hashlib.sha256(repr(replay()).encode()).hexdigest())\n')
        expected = hashlib.sha256(repr(replay()).encode()).hexdigest().encode() + b'\n'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                with self.subTest(seed=seed, zone=zone):
                    actual = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                    env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
                    self.assertEqual(actual, expected)
