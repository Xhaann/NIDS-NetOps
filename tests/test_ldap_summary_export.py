import copy
import json
import os
import subprocess
import sys
import unittest
import weakref
from collections import deque
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, asdict, fields
from datetime import timedelta
from enum import Enum
from unittest.mock import patch

from analysis import FlowObservationWindowManager, FlowStateCoordinator, analyze_packet
from integrations import iter_ldap_summary_jsonl
from tests.test_ldap import envelope, message
from tests.test_ldap_correlation import correlation_message, correlation_packets, correlation_states
from tests.test_ldap_request_summary import summaries
from tests.test_ldap_stream_lifecycle import observe_framing


def bind_summaries(ipv6=False):
    return summaries(correlation_states(((False, correlation_message(0x60)), (True, correlation_message(0x61))), ipv6))


def message_metadata(observation):
    return {field.name: value.value if isinstance(value, Enum) else value
            for field in fields(observation) for value in (getattr(observation, field.name),)}


def export_scenarios():
    for ipv6 in (False, True):
        events = ((False, correlation_message(0x63, 10) + correlation_message(0x60, 2)),
                  (True, correlation_message(0x64, 10) + correlation_message(0x61, 2)),
                  (True, correlation_message(0x65, 10)), (False, correlation_message(0x60, 3)),
                  (False, correlation_message(0x60, 3)), (True, correlation_message(0x68, 4)))
        updates, closed = observe_framing(correlation_packets(events, ipv6))
        for window in updates:
            for observation in window.ldap_correlation_state.observations:
                if observation.request_summary is not None:
                    yield observation.request_summary
        for window in closed:
            for observation in window.ldap_correlation_state.requests:
                yield observation.request_summary


class LDAPSummaryExportTests(unittest.TestCase):
    def test_completed_bind_exact_utf8_json_line_and_field_order(self):
        summary = bind_summaries()[-1]
        expected = (
            b'{"identity":{"ip_version":4,"source_address":"c0000201","destination_address":"c6336402",'
            b'"source_port":12345,"destination_port":389,"protocol":6},"direction":"forward",'
            b'"request":{"offset":0,"status":"complete","reason":null,"message_length":14,'
            b'"envelope_complete":true,"message_id":1,"operation_tag":96,"operation":96,"operation_length":7,'
            b'"controls_present":false,"controls_length":null},"status":"completed","response_count":1,'
            b'"terminal_response":{"offset":0,"status":"complete","reason":null,"message_length":14,'
            b'"envelope_complete":true,"message_id":1,"operation_tag":97,"operation":97,"operation_length":7,'
            b'"controls_present":false,"controls_length":null}}\n'
        )
        self.assertEqual(tuple(iter_ldap_summary_jsonl((summary,))), (expected,))
        self.assertEqual(expected.decode('utf-8').encode('utf-8'), expected)
        record = json.loads(expected)
        self.assertEqual(tuple(record), ('identity', 'direction', 'request', 'status', 'response_count', 'terminal_response'))
        self.assertEqual(record['request'], message_metadata(summary.request))
        self.assertEqual(record['terminal_response'], message_metadata(summary.terminal_response))

    def test_pending_and_final_unresolved_preserve_count_and_absent_terminal(self):
        updates, closed = observe_framing(correlation_packets(((False, correlation_message(0x63)),
                                                              (True, correlation_message(0x64)))))
        active = updates[-1].ldap_correlation_state.requests[0].request_summary
        final = closed[0].ldap_correlation_state.requests[0].request_summary
        records = tuple(map(json.loads, iter_ldap_summary_jsonl((active, final))))
        self.assertEqual([r['status'] for r in records], ['pending', 'unresolved'])
        self.assertEqual([r['response_count'] for r in records], [1, 1])
        self.assertEqual([r['terminal_response'] for r in records], [None, None])
        self.assertEqual(records[0]['request'], records[1]['request'])
        self.assertEqual(active.status.value, 'pending')
        self.assertEqual(final.status.value, 'unresolved')

    def test_ambiguous_reuse_remains_ambiguous_with_only_established_count(self):
        states = correlation_states(((False, correlation_message(0x63)), (True, correlation_message(0x64)),
                                     (False, correlation_message(0x63)), (True, correlation_message(0x65))))
        summary = states[-1].ldap_correlation_state.requests[0].request_summary
        record = json.loads(next(iter_ldap_summary_jsonl((summary,))))
        self.assertEqual(record['status'], 'ambiguous')
        self.assertEqual(record['response_count'], 1)
        self.assertIsNone(record['terminal_response'])
        self.assertEqual(record['request'], message_metadata(summary.request))

    def test_search_terminal_reference_and_many_logical_responses_are_exact(self):
        entries = correlation_message(0x64, 10) * 1024 + correlation_message(0x73, 10)
        states = correlation_states(((False, correlation_message(0x63, 10)),
                                     (True, entries), (True, correlation_message(0x65, 10))))
        pending = states[1].ldap_correlation_state.requests[0].request_summary
        completed = states[2].ldap_correlation_state.observations[0].request_summary
        records = tuple(map(json.loads, iter_ldap_summary_jsonl((pending, completed))))
        self.assertEqual([r['response_count'] for r in records], [1025, 1026])
        self.assertEqual([r['status'] for r in records], ['pending', 'completed'])
        self.assertIsNone(records[0]['terminal_response'])
        self.assertEqual(records[1]['terminal_response'], message_metadata(completed.terminal_response))
        self.assertEqual(records[1]['terminal_response']['offset'], len(entries))
        self.assertEqual(records[1]['terminal_response']['operation'], 0x65)

    def test_non_fifo_completions_preserve_request_and_response_offsets(self):
        states = correlation_states(((False, b''.join(correlation_message(0x60, i) for i in (1, 2, 3))),
                                     (True, b''.join(correlation_message(0x61, i) for i in (2, 1, 3)))))
        records = tuple(map(json.loads, iter_ldap_summary_jsonl(summaries(states))))
        self.assertEqual([r['request']['message_id'] for r in records], [1, 2, 3, 2, 1, 3])
        self.assertEqual([r['request']['offset'] for r in records], [0, 14, 28, 14, 0, 28])
        self.assertEqual([r['terminal_response']['offset'] for r in records[3:]], [0, 14, 28])
        self.assertEqual([r['status'] for r in records], ['pending'] * 3 + ['completed'] * 3)

    def test_mixed_ipv4_ipv6_directions_and_identical_ids_preserve_supplied_order(self):
        ipv4 = bind_summaries()[-1]
        reverse = summaries(correlation_states(((True, correlation_message(0x68)),
                                                (False, correlation_message(0x69))), True))[-1]
        supplied = (reverse, ipv4, reverse)
        records = tuple(map(json.loads, iter_ldap_summary_jsonl(supplied)))
        self.assertEqual([r['identity']['ip_version'] for r in records], [6, 4, 6])
        self.assertEqual([r['direction'] for r in records], ['reverse', 'forward', 'reverse'])
        self.assertEqual([r['request']['message_id'] for r in records], [1, 1, 1])
        self.assertEqual([r['request']['operation'] for r in records], [0x68, 0x60, 0x68])
        for record, summary in zip(records, supplied):
            identity = record['identity']
            self.assertEqual(bytes.fromhex(identity['source_address']), summary.identity.source_address)
            self.assertEqual(bytes.fromhex(identity['destination_address']), summary.identity.destination_address)
            self.assertEqual((identity['source_port'], identity['destination_port'], identity['protocol']),
                             (summary.identity.source_port, summary.identity.destination_port, summary.identity.protocol))
        self.assertEqual(records[0], records[2])

    def test_controls_preserve_metadata_without_exporting_body_or_authentication_material(self):
        secret = b'private-bind-material-\xff\n'
        content = b'private-response-content'
        controls = envelope(0xA0, envelope(0x30, envelope(4, b'1.2.3')))
        request = message(0x60, envelope(2, b'\x03') + envelope(4, b'') + envelope(0x80, secret), controls=controls)
        response = message(0x61, envelope(0x0A, b'\x00') + envelope(4, b'') + envelope(4, content))
        summary = summaries(correlation_states(((False, request), (True, response))))[-1]
        output = next(iter_ldap_summary_jsonl((summary,)))
        record = json.loads(output)
        self.assertEqual(record['request'], message_metadata(summary.request))
        self.assertEqual(record['terminal_response'], message_metadata(summary.terminal_response))
        self.assertTrue(record['request']['controls_present'])
        self.assertEqual(record['request']['controls_length'], len(controls) - 2)
        self.assertEqual(output.count(b'\n'), 1)
        for value in (secret, secret.hex().encode('ascii'), content, request, response, b'1.2.3'):
            self.assertNotIn(value, output)

    def test_incomplete_unmatched_and_non_correlatable_observations_do_not_become_summaries(self):
        request = correlation_message(0x60)
        for events in (((True, correlation_message(0x61)),), ((False, request[:5]),),
                       ((False, b'\x30\xff' + request),), ((False, correlation_message(0x7A)),)):
            states = correlation_states(events)
            self.assertEqual(tuple(iter_ldap_summary_jsonl(summaries(states))), ())
        states = correlation_states(((False, request[:5]), (False, request[5:]), (True, correlation_message(0x61))))
        records = tuple(map(json.loads, iter_ldap_summary_jsonl(summaries(states))))
        self.assertEqual([r['status'] for r in records], ['pending', 'completed'])

    def test_retransmission_suppression_is_preserved_without_export_deduplication(self):
        packets = correlation_packets(((False, correlation_message(0x60)), (True, correlation_message(0x61))))
        coordinator = FlowStateCoordinator()
        states = tuple(coordinator.record(analyze_packet(p)) for p in (packets[0], packets[1], packets[1]))
        established = summaries(states)
        records = tuple(map(json.loads, iter_ldap_summary_jsonl(established)))
        self.assertEqual([r['response_count'] for r in records], [0, 1])
        self.assertEqual(states[-1].ldap_correlation_state.observations, ())
        repeated = tuple(iter_ldap_summary_jsonl((established[-1], established[-1])))
        self.assertEqual(len(repeated), 2)
        self.assertEqual(repeated[0], repeated[1])

    def test_export_leaves_active_flow_and_finalized_summaries_immutable(self):
        manager = FlowObservationWindowManager('export', timedelta(seconds=5))
        packets = correlation_packets(((False, correlation_message(0x60)), (True, correlation_message(0x61))))
        window = manager.record(analyze_packet(packets[0])).active_window
        active = window.ldap_correlation_state.requests[0].request_summary
        before = asdict(window)
        original = next(iter_ldap_summary_jsonl((active,)))
        self.assertEqual(asdict(manager.active_windows()[0]), before)
        self.assertIsNone(manager.active_windows()[0].closure_reason)
        manager.record(analyze_packet(packets[1]))
        closed = manager.end_capture_session()[0]
        completed = closed.ldap_correlation_state.observations[0].request_summary
        final_before = asdict(closed)
        self.assertEqual(next(iter_ldap_summary_jsonl((active,))), original)
        self.assertEqual(tuple(iter_ldap_summary_jsonl((completed,))), tuple(iter_ldap_summary_jsonl((completed,))))
        self.assertEqual(asdict(closed), final_before)
        for summary in (active, completed):
            with self.assertRaises(FrozenInstanceError):
                summary.response_count = 500
        self.assertEqual(active.response_count, 0)
        self.assertEqual(completed.response_count, 1)

    def test_export_only_reads_existing_observations_without_analysis_or_finalization(self):
        established = bind_summaries()
        before = tuple(asdict(s) for s in established)
        with ExitStack() as stack:
            for target in ('analysis.ldap_stream_framing._message',
                           'analysis.flow_state_coordinator.update_tcp_stream_state',
                           'analysis.flow_state_coordinator.update_ldap_stream_state',
                           'analysis.flow_state_coordinator.update_ldap_correlation_state',
                           'analysis.flow_observation_window.finalize_ldap_correlation_state',
                           'analysis.ldap_request_summary._summary'):
                stack.enter_context(patch(target, side_effect=AssertionError('export must only consume summaries')))
            self.assertEqual(len(tuple(iter_ldap_summary_jsonl(established))), 2)
        self.assertEqual(tuple(asdict(s) for s in established), before)

    def test_input_is_lazy_single_pass_without_lookahead(self):
        established = bind_summaries()
        events = []

        def source():
            events.append('start')
            yield established[0]
            events.append('second')
            yield established[1]
            events.append('end')

        output = iter_ldap_summary_jsonl(source())
        self.assertEqual(events, [])
        self.assertEqual(json.loads(next(output))['status'], 'pending')
        self.assertEqual(events, ['start'])
        self.assertEqual(json.loads(next(output))['status'], 'completed')
        self.assertEqual(events, ['start', 'second'])
        with self.assertRaises(StopIteration):
            next(output)
        self.assertEqual(events, ['start', 'second', 'end'])

    def test_large_iterable_releases_previous_summaries_and_yields_one_record_at_a_time(self):
        template = bind_summaries()[-1]
        expected = next(iter_ldap_summary_jsonl((template,)))
        recent = deque(maxlen=4)
        consumed = 0

        def source():
            nonlocal consumed
            for index in range(20000):
                if len(recent) == recent.maxlen:
                    self.assertIsNone(recent[0]())
                summary = copy.copy(template)
                recent.append(weakref.ref(summary))
                consumed += 1
                yield summary

        for count, record in enumerate(iter_ldap_summary_jsonl(source()), 1):
            self.assertEqual(consumed, count)
            self.assertEqual(record, expected)
        self.assertEqual(consumed, 20000)
        self.assertTrue(all(reference() is None for reference in recent))

    def test_empty_input_yields_nothing(self):
        self.assertEqual(tuple(iter_ldap_summary_jsonl(iter(()))), ())

    def test_invalid_member_raises_without_repr_fallback_or_consuming_later_input(self):
        class Unsupported:
            def __repr__(self):
                raise AssertionError('repr must not be called')

        summary = bind_summaries()[-1]
        for invalid in (None, {}, summary.request, Unsupported()):
            source = iter((summary, invalid, summary))
            output = iter_ldap_summary_jsonl(source)
            self.assertEqual(json.loads(next(output))['status'], 'completed')
            with self.assertRaisesRegex(TypeError, '^summaries must contain exactly LDAPRequestSummary values$'):
                next(output)
            with self.assertRaises(StopIteration):
                next(output)
            self.assertIs(next(source), summary)

    def test_invalid_iterable_and_iteration_start_failure_propagate(self):
        with self.assertRaises(TypeError):
            next(iter_ldap_summary_jsonl(None))
        error = OSError('input unavailable')

        class FailedIterable:
            def __iter__(self):
                raise error

        with self.assertRaises(OSError) as caught:
            next(iter_ldap_summary_jsonl(FailedIterable()))
        self.assertIs(caught.exception, error)

    def test_mid_iteration_failure_preserves_exception_and_valid_partial_output(self):
        summary = bind_summaries()[-1]
        error = RuntimeError('input interrupted')

        def source():
            yield summary
            raise error

        output = iter_ldap_summary_jsonl(source())
        self.assertEqual(json.loads(next(output))['response_count'], 1)
        with self.assertRaises(RuntimeError) as caught:
            next(output)
        self.assertIs(caught.exception, error)
        with self.assertRaises(StopIteration):
            next(output)

    def test_serialization_failure_yields_no_partial_record_or_replacement(self):
        source = iter(bind_summaries())
        output = iter_ldap_summary_jsonl(source)
        error = MemoryError('encoding unavailable')
        with patch('integrations.ldap_summary_export.json.dumps', side_effect=error):
            with self.assertRaises(MemoryError) as caught:
                next(output)
        self.assertIs(caught.exception, error)
        with self.assertRaises(StopIteration):
            next(output)
        self.assertEqual(next(source).status.value, 'completed')

    def test_caller_output_failure_propagates_without_consuming_next_summary(self):
        established = bind_summaries()
        source = iter(established)
        error = OSError('destination unavailable')

        class Destination:
            def write(self, record):
                self.record = record
                raise error

        destination = Destination()
        with self.assertRaises(OSError) as caught:
            for record in iter_ldap_summary_jsonl(source):
                destination.write(record)
        self.assertIs(caught.exception, error)
        self.assertEqual(json.loads(destination.record)['status'], 'pending')
        self.assertIs(next(source), established[1])

    def test_repeated_hash_seed_timezone_exports_are_byte_identical(self):
        expected = b''.join(iter_ldap_summary_jsonl(export_scenarios()))
        self.assertEqual(expected, b''.join(iter_ldap_summary_jsonl(export_scenarios())))
        records = tuple(map(json.loads, expected.splitlines()))
        self.assertEqual(len(records), 18)
        self.assertEqual({r['status'] for r in records}, {'pending', 'completed', 'ambiguous', 'unresolved'})
        script = ('from tests.test_ldap_summary_export import export_scenarios\n'
                  'from integrations import iter_ldap_summary_jsonl\n'
                  'import sys\n'
                  'for record in iter_ldap_summary_jsonl(export_scenarios()):\n'
                  '    sys.stdout.buffer.write(record)\n')
        for seed, zone in (('0', 'UTC'), ('1', 'Asia/Kolkata'), ('9157', 'America/Los_Angeles'), ('0', 'UTC')):
            environment = dict(os.environ, PYTHONHASHSEED=seed, TZ=zone, PYTHONPATH='src', PYTHONDONTWRITEBYTECODE='1')
            actual = subprocess.check_output([sys.executable, '-B', '-c', script], env=environment, timeout=15)
            self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
