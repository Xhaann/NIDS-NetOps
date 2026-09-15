import ast
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from analysis import (
    DNS_MAX_PENDING_REQUESTS, DNSCorrelationReason, DNSCorrelationState, DNSCorrelationStatus,
    DNSTransactionObservation, FlowDirection, analyze_dns_message, flow_identity_from_addresses,
    finalize_dns_correlation_state, update_dns_correlation_state,
)
from tests.test_dns import header, name, question


IDENTITY = flow_identity_from_addresses('192.0.2.1', '198.51.100.2', 12345, 53, 17)
EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


def message(identifier=1, response=False, labels=(b'example',), kind=1, cls=1, opcode=0):
    return analyze_dns_message(header(1, flags=(0x8000 if response else 0) | (opcode << 11), identifier=identifier)
                               + question(name(*labels), kind, cls))


def advance(current=None, identifier=1, response=False, seconds=0, direction=None, identity=IDENTITY, **kwargs):
    direction = direction or (FlowDirection.REVERSE if response else FlowDirection.FORWARD)
    return update_dns_correlation_state(current, message(identifier, response, **kwargs), identity,
                                        direction, EPOCH + timedelta(seconds=seconds))


def full_state():
    current = None
    for index in range(DNS_MAX_PENDING_REQUESTS):
        current = advance(current, index)
    return current


class DNSCorrelationTests(unittest.TestCase):
    def test_request_becomes_pending(self):
        state = advance()
        self.assertEqual(len(state.requests), 1)
        self.assertIs(state.requests[0], state.observations[0])
        self.assertIs(state.requests[0].status, DNSCorrelationStatus.PENDING)

    def test_match_preserves_exact_observations(self):
        state = advance()
        response = message(response=True)
        result = update_dns_correlation_state(state, response, IDENTITY, FlowDirection.REVERSE, EPOCH)
        item, = result.observations
        self.assertIs(item.request, state.requests[0].message)
        self.assertIs(item.message, response)
        self.assertIs(item.status, DNSCorrelationStatus.MATCHED)
        self.assertEqual(result.requests, ())

    def test_id_extremes_preserved(self):
        for identifier in (0, 65535):
            self.assertEqual(advance(advance(identifier=identifier), identifier, True).observations[0].transaction_id, identifier)

    def test_opposite_request_directions_have_independent_keys(self):
        state = advance(advance(), direction=FlowDirection.REVERSE)
        self.assertEqual(len(state.requests), 2)
        result = advance(state, response=True)
        self.assertIs(result.requests[0].direction, FlowDirection.REVERSE)
        self.assertIs(advance(result, response=True, direction=FlowDirection.FORWARD).observations[0].status, DNSCorrelationStatus.MATCHED)

    def test_same_direction_response_does_not_match(self):
        state = advance(advance(), response=True, direction=FlowDirection.FORWARD)
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.UNMATCHED)
        self.assertEqual(len(state.requests), 1)

    def test_unmatched_response_has_no_request_or_duration(self):
        item = advance(response=True).observations[0]
        self.assertIs(item.status, DNSCorrelationStatus.UNMATCHED)
        self.assertIsNone(item.request)
        self.assertIsNone(item.duration)

    def test_response_before_request_is_not_retroactively_matched(self):
        first = advance(response=True)
        later = advance(first, seconds=1)
        self.assertIs(later.observations[0].status, DNSCorrelationStatus.PENDING)
        self.assertEqual(len(later.observations), 1)

    def test_duplicate_response_remains_a_separate_unmatched_observation(self):
        state = advance(advance(), response=True)
        duplicate = advance(state, response=True)
        self.assertIs(duplicate.observations[0].status, DNSCorrelationStatus.UNMATCHED)
        self.assertIsNot(duplicate.observations[0], state.observations[0])

    def test_multiple_responses_do_not_accumulate_history(self):
        state = advance(advance(), response=True)
        for index in range(300):
            state = advance(state, response=True, seconds=index)
            self.assertEqual((len(state.requests), len(state.observations)), (0, 1))

    def test_sequential_reuse_matches_current_request(self):
        state = advance(advance(), response=True)
        second = advance(state, seconds=5)
        result = advance(second, response=True, seconds=7)
        self.assertIs(result.observations[0].request, second.requests[0].message)
        self.assertEqual(result.observations[0].duration, timedelta(seconds=2))

    def test_outstanding_reuse_is_ambiguous(self):
        original = advance()
        state = advance(original, seconds=1)
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.AMBIGUOUS)
        self.assertIs(state.requests[0].status, DNSCorrelationStatus.AMBIGUOUS)
        self.assertIs(state.requests[0].request, original.requests[0].request)
        self.assertEqual(len(state.requests), 1)

    def test_retransmission_is_not_deduplicated(self):
        state = advance()
        state = update_dns_correlation_state(state, state.requests[0].message, IDENTITY, FlowDirection.FORWARD, EPOCH)
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.AMBIGUOUS)

    def test_ambiguous_response_never_claims_a_match(self):
        state = advance(advance(advance()), response=True)
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.AMBIGUOUS)
        self.assertIsNone(state.observations[0].request)
        self.assertIsNone(state.observations[0].duration)
        self.assertEqual(len(state.requests), 1)

    def test_ambiguity_remains_until_context_closure(self):
        state = advance(advance())
        for index in range(300):
            state = advance(state, response=bool(index % 2))
            self.assertEqual(len(state.requests), 1)
            self.assertIs(state.observations[0].status, DNSCorrelationStatus.AMBIGUOUS)

    def test_opcode_mismatch_keeps_pending(self):
        state = advance(advance(), response=True, opcode=1)
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.UNMATCHED)
        self.assertEqual(len(state.requests), 1)

    def test_question_name_mismatch_keeps_pending(self):
        state = advance(advance(), response=True, labels=(b'other',))
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.UNMATCHED)
        self.assertIs(advance(state, response=True).observations[0].status, DNSCorrelationStatus.MATCHED)

    def test_question_type_and_class_must_match(self):
        for kwargs in ({'kind': 28}, {'cls': 3}):
            self.assertIs(advance(advance(), response=True, **kwargs).observations[0].status, DNSCorrelationStatus.UNMATCHED)

    def test_name_case_is_ascii_insensitive_without_mutating_messages(self):
        state = advance(labels=(b'EXAMPLE', b'\xff'))
        result = advance(state, response=True, labels=(b'example', b'\xff'))
        self.assertIs(result.observations[0].status, DNSCorrelationStatus.MATCHED)
        self.assertEqual(result.observations[0].request.questions[0].name.labels, (b'EXAMPLE', b'\xff'))

    def test_question_order_is_preserved(self):
        first = analyze_dns_message(header(2) + question(name(b'a')) + question(name(b'b')))
        second = analyze_dns_message(header(2, flags=0x8000) + question(name(b'b')) + question(name(b'a')))
        state = update_dns_correlation_state(None, first, IDENTITY, FlowDirection.FORWARD, EPOCH)
        state = update_dns_correlation_state(state, second, IDENTITY, FlowDirection.REVERSE, EPOCH)
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.UNMATCHED)

    def test_empty_question_sections_match_by_remaining_fields(self):
        request = analyze_dns_message(header(identifier=0))
        response = analyze_dns_message(header(identifier=0, flags=0x8000))
        state = update_dns_correlation_state(None, request, IDENTITY, FlowDirection.FORWARD, EPOCH)
        state = update_dns_correlation_state(state, response, IDENTITY, FlowDirection.REVERSE, EPOCH)
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.MATCHED)

    def test_exact_capacity_is_available(self):
        state = full_state()
        self.assertEqual(len(state.requests), DNS_MAX_PENDING_REQUESTS)
        self.assertIsNone(state.unavailable_reason)

    def test_capacity_closes_all_requests_in_admission_order(self):
        state = advance(full_state(), DNS_MAX_PENDING_REQUESTS)
        self.assertEqual(state.requests, ())
        self.assertEqual([item.transaction_id for item in state.observations], list(range(DNS_MAX_PENDING_REQUESTS + 1)))
        self.assertTrue(all(item.status is DNSCorrelationStatus.UNRESOLVED and item.reason is DNSCorrelationReason.LIMIT_EXCEEDED
                            for item in state.observations))

    def test_capacity_loss_is_sticky(self):
        state = advance(full_state(), DNS_MAX_PENDING_REQUESTS)
        for index in range(300):
            state = advance(state, index, bool(index % 2))
            self.assertEqual(state.requests, ())
            self.assertEqual(len(state.observations), 1)
            self.assertIs(state.unavailable_reason, DNSCorrelationReason.LIMIT_EXCEEDED)
            self.assertIsNot(state.observations[0].status, DNSCorrelationStatus.MATCHED)

    def test_response_releases_capacity(self):
        state = advance(full_state(), 0, True)
        self.assertEqual(len(state.requests), DNS_MAX_PENDING_REQUESTS - 1)
        state = advance(state, DNS_MAX_PENDING_REQUESTS)
        self.assertIsNone(state.unavailable_reason)
        self.assertEqual(len(state.requests), DNS_MAX_PENDING_REQUESTS)

    def test_duplicate_at_capacity_does_not_overflow(self):
        state = advance(full_state(), 0)
        self.assertIsNone(state.unavailable_reason)
        self.assertEqual(len(state.requests), DNS_MAX_PENDING_REQUESTS)

    def test_pending_closure_releases_requests(self):
        state = advance()
        result = finalize_dns_correlation_state(state)
        self.assertTrue(result.finalized)
        self.assertEqual(result.requests, ())
        self.assertEqual(len(result.observations), 1)
        self.assertIs(result.observations[0].status, DNSCorrelationStatus.UNRESOLVED)
        self.assertIs(result.observations[0].reason, DNSCorrelationReason.FLOW_CLOSED)
        self.assertIs(state.requests[0].status, DNSCorrelationStatus.PENDING)

    def test_closure_order_is_request_admission_order(self):
        state = advance(advance(advance(identifier=4), 2), 3)
        self.assertEqual([item.transaction_id for item in finalize_dns_correlation_state(state).observations], [4, 2, 3])

    def test_finalization_preserves_last_completed_output(self):
        state = advance(advance(), response=True)
        self.assertIs(finalize_dns_correlation_state(state).observations[0], state.observations[0])

    def test_repeated_finalization_returns_same_object(self):
        state = finalize_dns_correlation_state(advance())
        self.assertIs(finalize_dns_correlation_state(state), state)

    def test_finalized_state_rejects_recording(self):
        with self.assertRaises(ValueError):
            advance(finalize_dns_correlation_state(advance()))

    def test_invalid_finalization_input(self):
        for value in (None, object(), ()):
            with self.assertRaises(TypeError):
                finalize_dns_correlation_state(value)

    def test_malformed_incomplete_unsupported_input_never_creates_state(self):
        for flags in (0, 0x8000):
            for body in (b'\x80', b'\x01', b'\x40'):
                invalid = analyze_dns_message(header(1, flags=flags) + body)
                self.assertIsNone(update_dns_correlation_state(None, invalid, IDENTITY, FlowDirection.FORWARD, EPOCH))

    def test_invalid_response_does_not_consume_pending_request(self):
        state = advance()
        invalid = analyze_dns_message(header(1, flags=0x8000) + b'\x80')
        result = update_dns_correlation_state(state, invalid, IDENTITY, FlowDirection.REVERSE, EPOCH)
        self.assertIs(result.requests[0], state.requests[0])
        self.assertEqual(result.observations, ())

    def test_absent_message_clears_only_latest_output(self):
        state = advance()
        self.assertIsNone(update_dns_correlation_state(None, None, IDENTITY, FlowDirection.FORWARD, EPOCH))
        result = update_dns_correlation_state(state, None, IDENTITY, FlowDirection.FORWARD, EPOCH)
        self.assertEqual(result.observations, ())
        self.assertEqual(result.requests, state.requests)

    def test_duration_uses_capture_timestamps(self):
        state = advance(advance(), response=True, seconds=2.125)
        self.assertEqual(state.observations[0].duration, timedelta(seconds=2.125))

    def test_equal_timestamps_have_zero_duration(self):
        self.assertEqual(advance(advance(), response=True).observations[0].duration, timedelta(0))

    def test_earlier_response_timestamp_is_rejected(self):
        with self.assertRaises(ValueError):
            advance(advance(seconds=2), response=True, seconds=1)

    def test_timestamp_reference_is_preserved(self):
        state = advance()
        self.assertIs(state.observations[0].captured_at, state.last_captured_at)
        result = advance(state, response=True)
        self.assertIs(result.observations[0].request_captured_at, state.last_captured_at)

    def test_noncanonical_timestamps_rejected(self):
        for stamp in (EPOCH.replace(tzinfo=None), EPOCH.replace(tzinfo=timezone(timedelta(hours=1)))):
            with self.assertRaises(ValueError):
                update_dns_correlation_state(None, message(), IDENTITY, FlowDirection.FORWARD, stamp)

    def test_invalid_argument_types(self):
        arguments = [None, message(), IDENTITY, FlowDirection.FORWARD, EPOCH]
        for index in range(5):
            changed = arguments.copy()
            changed[index] = object()
            with self.assertRaises(TypeError):
                update_dns_correlation_state(*changed)

    def test_cross_flow_state_rejected(self):
        other = replace(IDENTITY, source_port=12346)
        with self.assertRaises(ValueError):
            advance(advance(), identity=other)

    def test_independent_states_do_not_cross_match(self):
        pending = advance()
        other = advance(response=True, identity=replace(IDENTITY, source_port=12346))
        self.assertIs(other.observations[0].status, DNSCorrelationStatus.UNMATCHED)
        self.assertEqual(len(pending.requests), 1)

    def test_already_delimited_tcp_message_uses_same_correlation(self):
        identity = replace(IDENTITY, protocol=6)
        state = advance(identity=identity)
        self.assertIs(advance(state, response=True, identity=identity).observations[0].status, DNSCorrelationStatus.MATCHED)

    def test_factory_only_immutable_state_and_observation(self):
        state = advance()
        for item in (state, state.observations[0]):
            with self.assertRaises(TypeError):
                type(item)()
            for member in fields(item):
                with self.assertRaises(FrozenInstanceError):
                    setattr(item, member.name, None)
            with self.assertRaises(TypeError):
                replace(item)
        self.assertIs(type(state.requests), tuple)
        self.assertIs(type(state.observations), tuple)

    def test_state_contains_no_packet_graph_or_history_chain(self):
        state = advance(advance(), response=True)
        self.assertEqual(set(vars(state)), {'identity', 'requests', 'observations', 'last_captured_at', 'unavailable_reason', 'finalized'})
        self.assertEqual(set(vars(state.observations[0])), {'identity', 'direction', 'message', 'captured_at', 'status',
                                                        'request', 'request_captured_at', 'reason'})

    def test_allocation_failure_does_not_mutate_previous_state(self):
        state = advance()
        failure = MemoryError('publication')
        with patch('analysis.dns_correlation._build', side_effect=failure):
            with self.assertRaises(MemoryError) as caught:
                advance(state, response=True)
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(state.requests), 1)
        self.assertIs(advance(state, response=True).observations[0].status, DNSCorrelationStatus.MATCHED)

    def test_source_dependencies_are_observation_only(self):
        tree = ast.parse(Path('src/analysis/dns_correlation.py').read_text())
        dependencies = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertEqual(dependencies, ['dataclasses', 'datetime', 'enum', 'typing', 'analysis.dns',
                                        'analysis.flow_direction', 'analysis.flow_identity'])
        self.assertFalse(any(isinstance(node, ast.Import) for node in ast.walk(tree)))

    def test_public_exports(self):
        import analysis
        for name in ('DNS_MAX_PENDING_REQUESTS', 'DNSCorrelationReason', 'DNSCorrelationStatus',
                     'DNSCorrelationState', 'DNSTransactionObservation', 'update_dns_correlation_state',
                     'finalize_dns_correlation_state'):
            self.assertIn(name, analysis.__all__)
            self.assertTrue(hasattr(analysis, name))

    def test_repeated_independent_sequences_are_equal(self):
        def run():
            state = None
            for identifier, response in ((1, False), (2, False), (1, True), (2, False), (2, True)):
                state = advance(state, identifier, response)
            return finalize_dns_correlation_state(state)
        self.assertEqual(run(), run())
