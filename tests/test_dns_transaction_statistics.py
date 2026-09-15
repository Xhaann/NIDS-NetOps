import ast
import unittest
from dataclasses import FrozenInstanceError, asdict, fields, replace
from datetime import datetime, timedelta, timezone
from fractions import Fraction
from pathlib import Path
from unittest.mock import patch

import analysis
from analysis import (
    DNSCorrelationStatus, DNSTransactionStatistics, FlowDirection, analyze_dns_message,
    finalize_dns_correlation_state, update_dns_correlation_state, update_dns_transaction_statistics,
)
from tests.test_dns import header, question, record
from tests.test_dns_correlation import EPOCH, IDENTITY, advance, full_state


def aggregate(observations, current=None):
    result = DNSTransactionStatistics() if current is None else current
    for observation in observations:
        if observation.status is not DNSCorrelationStatus.PENDING:
            result = update_dns_transaction_statistics(result, observation)
    return result


def matched(microseconds=0, opcode=0):
    request = advance(opcode=opcode)
    response = advance(response=True, opcode=opcode).observations[0].message
    return update_dns_correlation_state(request, response, IDENTITY, FlowDirection.REVERSE,
                                        EPOCH + timedelta(microseconds=microseconds)).observations[0]


def record_transaction(counts=(1, 2, 3, 4), response=True, opcode=0, response_code=0):
    questions, answers, authorities, additionals = counts
    payload = header(*counts, flags=(0x8000 if response else 0) | (opcode << 11) | response_code)
    payload += question() * questions + record() * (answers + authorities + additionals)
    message = analyze_dns_message(payload)
    state = update_dns_correlation_state(None, message, IDENTITY, FlowDirection.REVERSE if response else FlowDirection.FORWARD, EPOCH)
    return finalize_dns_correlation_state(state).observations[0]


class DNSTransactionStatisticsTests(unittest.TestCase):
    def test_empty_counters(self):
        value = DNSTransactionStatistics()
        self.assertEqual(value.total_transaction_count, 0)
        self.assertEqual((value.matched_count, value.unmatched_count, value.ambiguous_count, value.unresolved_count), (0, 0, 0, 0))
        self.assertEqual((value.question_count, value.answer_count, value.authority_count, value.additional_count), (0, 0, 0, 0))

    def test_empty_latency(self):
        value = DNSTransactionStatistics()
        self.assertEqual(value.total_matched_latency_microseconds, 0)
        self.assertIsNone(value.min_matched_latency_microseconds)
        self.assertIsNone(value.max_matched_latency_microseconds)
        self.assertIsNone(value.mean_matched_latency_microseconds)

    def test_empty_distributions(self):
        value = DNSTransactionStatistics()
        self.assertEqual(value.opcode_counts, (0,) * 16)
        self.assertEqual(value.response_code_counts, (0,) * 16)

    def test_one_match_accounts_for_two_messages_and_one_transaction(self):
        value = update_dns_transaction_statistics(None, matched(7))
        self.assertEqual((value.total_transaction_count, value.matched_count, value.question_count), (1, 1, 2))
        self.assertEqual((sum(value.opcode_counts), sum(value.response_code_counts)), (2, 1))

    def test_pending_is_rejected_without_changing_statistics(self):
        value = DNSTransactionStatistics()
        with self.assertRaises(ValueError):
            update_dns_transaction_statistics(value, advance().observations[0])
        self.assertEqual(value, DNSTransactionStatistics())

    def test_unanswered_request_is_unresolved_not_unmatched(self):
        value = aggregate(finalize_dns_correlation_state(advance()).observations)
        self.assertEqual((value.unresolved_count, value.unmatched_response_count, value.total_transaction_count), (1, 0, 1))
        self.assertEqual(sum(value.response_code_counts), 0)

    def test_only_unmatched_responses(self):
        value = aggregate(advance(response=True).observations * 20)
        self.assertEqual((value.unmatched_response_count, value.unmatched_count, value.total_transaction_count), (20, 20, 20))
        self.assertEqual(value.matched_count, 0)

    def test_ambiguous_request_counts_own_message_only(self):
        duplicate = advance(advance(), labels=(b'other',)).observations[0]
        self.assertIsNot(duplicate.request, duplicate.message)
        value = update_dns_transaction_statistics(None, duplicate)
        self.assertEqual((value.ambiguous_count, value.question_count, sum(value.opcode_counts)), (1, 1, 1))

    def test_ambiguous_response_counts_response_code(self):
        value = aggregate(advance(advance(advance()), response=True).observations)
        self.assertEqual((value.ambiguous_count, sum(value.response_code_counts)), (1, 1))
        self.assertIsNone(value.mean_matched_latency_microseconds)

    def test_capacity_unresolved_batch_is_fully_counted(self):
        value = aggregate(advance(full_state(), 128).observations)
        self.assertEqual((value.unresolved_count, value.total_transaction_count, value.question_count), (129, 129, 129))
        self.assertEqual(value.opcode_counts[0], 129)

    def test_mixed_status_accounting(self):
        observations = (matched(), advance(response=True).observations[0], advance(advance()).observations[0],
                        finalize_dns_correlation_state(advance()).observations[0])
        value = aggregate(observations)
        self.assertEqual((value.matched_count, value.unmatched_count, value.ambiguous_count, value.unresolved_count), (1, 1, 1, 1))
        self.assertEqual(value.total_transaction_count, 4)
        self.assertEqual(value.question_count, 5)

    def test_latency_extrema_total_and_exact_mean(self):
        value = aggregate(matched(duration) for duration in (9, 1, 7, 2))
        self.assertEqual((value.min_matched_latency_microseconds, value.max_matched_latency_microseconds,
                          value.total_matched_latency_microseconds), (1, 9, 19))
        self.assertEqual(value.mean_matched_latency_microseconds, Fraction(19, 4))

    def test_zero_latency_is_a_match(self):
        value = update_dns_transaction_statistics(None, matched())
        self.assertEqual((value.min_matched_latency_microseconds, value.max_matched_latency_microseconds,
                          value.total_matched_latency_microseconds, value.mean_matched_latency_microseconds), (0, 0, 0, Fraction(0)))
        self.assertEqual(value.matched_count, 1)

    def test_identical_latencies_preserve_exact_mean(self):
        value = aggregate(matched(13) for _ in range(71))
        self.assertEqual((value.min_matched_latency_microseconds, value.max_matched_latency_microseconds,
                          value.mean_matched_latency_microseconds), (13, 13, Fraction(13)))
        self.assertEqual(value.total_matched_latency_microseconds, 923)

    def test_nonmatches_do_not_affect_latency_denominator(self):
        value = aggregate((matched(1), matched(2), record_transaction(), record_transaction(response=False)))
        self.assertEqual(value.mean_matched_latency_microseconds, Fraction(3, 2))

    def test_capture_duration_beyond_float_integer_precision(self):
        first = datetime(1, 1, 1, tzinfo=timezone.utc)
        last = datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)
        request = advance().observations[0].message
        response = advance(response=True).observations[0].message
        state = update_dns_correlation_state(None, request, IDENTITY, FlowDirection.FORWARD, first)
        state = update_dns_correlation_state(state, response, IDENTITY, FlowDirection.REVERSE, last)
        value = aggregate(state.observations)
        self.assertEqual(value.total_matched_latency_microseconds, 315537897599999999)
        self.assertGreater(value.total_matched_latency_microseconds, 2 ** 53)

    def test_question_record_total(self):
        self.assertEqual(aggregate((record_transaction(),)).question_count, 1)

    def test_answer_record_total(self):
        self.assertEqual(aggregate((record_transaction(),)).answer_count, 2)

    def test_authority_record_total(self):
        self.assertEqual(aggregate((record_transaction(),)).authority_count, 3)

    def test_additional_record_total(self):
        self.assertEqual(aggregate((record_transaction(),)).additional_count, 4)

    def test_matched_request_and_response_record_sections(self):
        request = record_transaction((1, 2, 3, 4), response=False).message
        response = record_transaction((1, 5, 6, 7)).message
        state = update_dns_correlation_state(None, request, IDENTITY, FlowDirection.FORWARD, EPOCH)
        state = update_dns_correlation_state(state, response, IDENTITY, FlowDirection.REVERSE, EPOCH)
        value = aggregate(state.observations)
        self.assertEqual((value.question_count, value.answer_count, value.authority_count, value.additional_count), (2, 7, 9, 11))

    def test_maximum_supported_records_in_each_section(self):
        for index, field in enumerate(('question_count', 'answer_count', 'authority_count', 'additional_count')):
            counts = tuple(128 if position == index else 0 for position in range(4))
            value = aggregate((record_transaction(counts),))
            self.assertEqual(getattr(value, field), 128)

    def test_match_aggregates_two_maximum_record_messages(self):
        request = record_transaction((0, 128, 0, 0), response=False).message
        response = record_transaction((0, 128, 0, 0)).message
        state = update_dns_correlation_state(None, request, IDENTITY, FlowDirection.FORWARD, EPOCH)
        state = update_dns_correlation_state(state, response, IDENTITY, FlowDirection.REVERSE, EPOCH)
        value = aggregate(state.observations)
        self.assertEqual((value.matched_count, value.answer_count), (1, 256))

    def test_opcode_bins_cover_full_wire_domain_in_numeric_order(self):
        value = aggregate(record_transaction(opcode=code) for code in reversed(range(16)) for _ in range(code + 1))
        self.assertEqual(value.opcode_counts, tuple(range(1, 17)))

    def test_response_code_bins_cover_full_header_domain(self):
        value = aggregate(record_transaction(response_code=code) for code in reversed(range(16)) for _ in range(code + 1))
        self.assertEqual(value.response_code_counts, tuple(range(1, 17)))

    def test_request_response_code_bits_are_not_responses(self):
        value = aggregate((record_transaction(response=False, response_code=15),))
        self.assertEqual(value.response_code_counts, (0,) * 16)

    def test_empty_message_sections_still_count_transaction(self):
        value = aggregate((record_transaction((0, 0, 0, 0)),))
        self.assertEqual(value.total_transaction_count, 1)
        self.assertEqual((value.question_count, value.answer_count, value.authority_count, value.additional_count), (0, 0, 0, 0))

    def test_already_delimited_tcp_transaction_is_supported(self):
        identity = replace(IDENTITY, protocol=6)
        state = advance(advance(identity=identity), response=True, identity=identity, seconds=1)
        self.assertEqual(aggregate(state.observations).total_matched_latency_microseconds, 1000000)

    def test_frozen_result_and_public_sequences(self):
        value = aggregate((matched(),))
        for member in fields(value):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, member.name, None)
        with self.assertRaises(TypeError):
            value.opcode_counts[0] = 0
        with self.assertRaises(TypeError):
            value.response_code_counts[0] = 0

    def test_previous_result_is_not_mutated_by_later_update(self):
        first = aggregate((matched(1),))
        before = asdict(first)
        second = update_dns_transaction_statistics(first, matched(2))
        self.assertEqual(asdict(first), before)
        self.assertEqual(second.mean_matched_latency_microseconds, Fraction(3, 2))

    def test_mutating_caller_owned_export_does_not_change_result(self):
        value = aggregate((matched(),))
        exported = asdict(value)
        exported['matched_count'] = 400
        exported['opcode_counts'] = [400] * 16
        self.assertEqual(value.matched_count, 1)
        self.assertEqual(value.opcode_counts[0], 2)

    def test_mutating_caller_owned_constructor_arguments_cannot_change_recorded_result(self):
        arguments = asdict(aggregate((matched(1),)))
        before = DNSTransactionStatistics(**arguments)
        result = update_dns_transaction_statistics(before, matched(2))
        arguments.clear()
        arguments.update(matched_count=100, opcode_counts=[100] * 16)
        self.assertEqual(before.matched_count, 1)
        self.assertEqual(result.matched_count, 2)
        self.assertEqual(result.mean_matched_latency_microseconds, Fraction(3, 2))

    def test_mutable_distribution_inputs_are_rejected(self):
        for field in ('opcode_counts', 'response_code_counts'):
            for value in ([0] * 16, {0: 0}, iter((0,) * 16)):
                with self.assertRaises(TypeError):
                    DNSTransactionStatistics(**{field: value})

    def test_invalid_distribution_shapes_and_values(self):
        for field in ('opcode_counts', 'response_code_counts'):
            for value in ((), (0,) * 15, (0,) * 17, (-1,) + (0,) * 15):
                with self.assertRaises(ValueError):
                    DNSTransactionStatistics(**{field: value})
            for value in (True, 1.0, None):
                with self.assertRaises(TypeError):
                    DNSTransactionStatistics(**{field: (value,) + (0,) * 15})

    def test_exact_nonnegative_scalar_validation(self):
        for field in ('matched_count', 'unmatched_response_count', 'ambiguous_count', 'unresolved_count',
                      'question_count', 'answer_count', 'authority_count', 'additional_count',
                      'total_matched_latency_microseconds', 'min_matched_latency_microseconds', 'max_matched_latency_microseconds'):
            for value in (True, 1.0, '1'):
                with self.assertRaises(TypeError):
                    DNSTransactionStatistics(**{field: value})
            with self.assertRaises(ValueError):
                DNSTransactionStatistics(**{field: -1})

    def test_inconsistent_latency_and_distribution_aggregates_rejected(self):
        value = aggregate((matched(1),))
        for kwargs in ({'min_matched_latency_microseconds': None}, {'max_matched_latency_microseconds': 0},
                       {'total_matched_latency_microseconds': 3}, {'opcode_counts': (0,) * 16},
                       {'response_code_counts': (0,) * 16}, {'matched_count': 0}):
            with self.assertRaises(ValueError):
                replace(value, **kwargs)
        for kwargs in ({'total_matched_latency_microseconds': 1}, {'min_matched_latency_microseconds': 0},
                       {'question_count': 1}):
            with self.assertRaises(ValueError):
                DNSTransactionStatistics(**kwargs)

    def test_response_distribution_respects_terminal_roles(self):
        unmatched = aggregate((record_transaction(),))
        unresolved = aggregate((record_transaction(response=False),))
        with self.assertRaises(ValueError):
            replace(unmatched, response_code_counts=(0,) * 16)
        with self.assertRaises(ValueError):
            replace(unresolved, response_code_counts=(1,) + (0,) * 15)

    def test_noncanonical_capture_times_cannot_produce_feature_input(self):
        value = aggregate((matched(1),))
        request = advance().observations[0].message
        for timestamp in (EPOCH.replace(tzinfo=None), EPOCH.replace(tzinfo=timezone(timedelta(hours=5, minutes=30)))):
            with self.assertRaises(ValueError):
                update_dns_correlation_state(None, request, IDENTITY, FlowDirection.FORWARD, timestamp)
        self.assertEqual(value.total_transaction_count, 1)
        self.assertEqual(value.total_matched_latency_microseconds, 1)

    def test_only_established_transaction_objects_are_accepted(self):
        for value in (None, {}, [], advance(), advance().observations[0].message):
            with self.assertRaises(TypeError):
                update_dns_transaction_statistics(None, value)
        with self.assertRaises(TypeError):
            update_dns_transaction_statistics({}, matched())

    def test_large_counters_increment_without_float_conversion(self):
        count = 10 ** 400
        value = DNSTransactionStatistics(unmatched_response_count=count, question_count=count,
                                         opcode_counts=(count,) + (0,) * 15, response_code_counts=(count,) + (0,) * 15)
        updated = update_dns_transaction_statistics(value, advance(response=True).observations[0])
        self.assertEqual(updated.total_transaction_count, count + 1)
        self.assertEqual(updated.question_count, count + 1)
        self.assertEqual(updated.response_code_counts[0], count + 1)

    def test_large_latency_totals_and_exact_rational_mean(self):
        count = 10 ** 400
        value = DNSTransactionStatistics(matched_count=count, min_matched_latency_microseconds=1,
                                         max_matched_latency_microseconds=1, total_matched_latency_microseconds=count,
                                         opcode_counts=(count * 2,) + (0,) * 15, response_code_counts=(count,) + (0,) * 15)
        updated = update_dns_transaction_statistics(value, matched(2))
        self.assertEqual(updated.mean_matched_latency_microseconds, Fraction(count + 2, count + 1))
        self.assertEqual(updated.total_matched_latency_microseconds, count + 2)

    def test_feature_state_has_only_scalars_and_two_fixed_distributions(self):
        value = aggregate(matched(index) for index in range(300))
        self.assertEqual(len(fields(value)), 13)
        for member in fields(value):
            item = getattr(value, member.name)
            if type(item) is tuple:
                self.assertEqual(len(item), 16)
                self.assertTrue(all(type(count) is int for count in item))
            else:
                self.assertIs(type(item), int)

    def test_source_isolation_and_no_clock_or_float_arithmetic(self):
        tree = ast.parse(Path('src/analysis/dns_transaction_statistics.py').read_text())
        imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertEqual(imports, ['dataclasses', 'fractions', 'typing', 'analysis.dns_correlation'])
        self.assertFalse(any(isinstance(node, (ast.Import, ast.Div)) for node in ast.walk(tree)))
        calls = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertTrue(calls.isdisjoint({'now', 'utcnow', 'timestamp', 'total_seconds', 'monotonic'}))

    def test_public_exports(self):
        for name in ('DNSTransactionStatistics', 'update_dns_transaction_statistics'):
            self.assertIn(name, analysis.__all__)
            self.assertTrue(hasattr(analysis, name))

    def test_allocation_failure_leaves_existing_value_unchanged(self):
        value = aggregate((matched(),))
        observation = matched(1)
        with patch('analysis.dns_transaction_statistics.replace', side_effect=MemoryError('allocation')):
            with self.assertRaises(MemoryError):
                update_dns_transaction_statistics(value, observation)
        self.assertEqual(value, aggregate((matched(),)))
