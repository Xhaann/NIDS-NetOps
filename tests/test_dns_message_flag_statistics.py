import ast
import gc
import itertools
import unittest
import weakref
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, asdict, fields, replace
from pathlib import Path
from unittest.mock import PropertyMock, patch

import analysis
from analysis import (
    DNSCorrelationStatus, DNSHeader, DNSMessageFlagStatistics, DNSMessageObservation, DNSMessageStatus,
    FlowDirection, analyze_dns_message, finalize_dns_correlation_state, update_dns_correlation_state,
    update_dns_message_flag_statistics,
)
from tests.test_dns import header, question, record
from tests.test_dns_correlation import EPOCH, IDENTITY
from tests.test_dns_resource_record_statistics import altered_observation


FLAG_FIELDS = (('response_count', 'is_response', 0x8000), ('truncated_count', 'truncated', 0x0200),
               ('authoritative_answer_count', 'authoritative_answer', 0x0400),
               ('recursion_desired_count', 'recursion_desired', 0x0100),
               ('recursion_available_count', 'recursion_available', 0x0080),
               ('authenticated_data_count', 'authenticated_data', 0x0020),
               ('checking_disabled_count', 'checking_disabled', 0x0010))


def expected_statistics(*words):
    return DNSMessageFlagStatistics(message_count=len(words),
                                    **{field: sum(bool(word & mask) for word in words) for field, _, mask in FLAG_FIELDS})


def advance(current=None, flags=0, identifier=1, identity=IDENTITY):
    message = analyze_dns_message(header(flags=flags, identifier=identifier))
    direction = FlowDirection.REVERSE if message.header.is_response else FlowDirection.FORWARD
    return update_dns_correlation_state(current, message, identity, direction, EPOCH)


def terminal(flags=0):
    return finalize_dns_correlation_state(advance(flags=flags)).observations[0]


def statistics(flags=0):
    return update_dns_message_flag_statistics(None, terminal(flags))


class DNSMessageFlagStatisticsTests(unittest.TestCase):
    def test_empty_state_has_eight_zero_scalar_fields(self):
        value = DNSMessageFlagStatistics()
        self.assertEqual(asdict(value), dict(message_count=0, **{field: 0 for field, _, _ in FLAG_FIELDS}))
        self.assertEqual(value.query_count, 0)

    def test_all_supported_flags_clear(self):
        self.assertEqual(statistics(0), DNSMessageFlagStatistics(1, 0, 0))

    def test_all_supported_flags_set(self):
        self.assertEqual(statistics(0x87b0), DNSMessageFlagStatistics(1, 1, 1, 1, 1, 1, 1, 1))

    def test_qr_alone_counts_a_response(self):
        self.assertEqual(statistics(0x8000), DNSMessageFlagStatistics(1, 1, 0))
        self.assertEqual(statistics(0x8000).query_count, 0)

    def test_tc_alone_counts_a_truncated_query(self):
        self.assertEqual(statistics(0x0200), DNSMessageFlagStatistics(1, 0, 1))
        self.assertEqual(statistics(0x0200).query_count, 1)

    def test_mixed_messages_preserve_query_response_identity(self):
        value = None
        for flags in (0, 0x8000, 0x0200, 0x8200, 0):
            value = update_dns_message_flag_statistics(value, terminal(flags))
        self.assertEqual(value, DNSMessageFlagStatistics(5, 2, 2))
        self.assertEqual(value.query_count + value.response_count, value.message_count)

    def test_reserved_bit_does_not_create_a_counter(self):
        self.assertEqual(statistics(0x0040), statistics(0))
        self.assertEqual(statistics(0x87f0), statistics(0x87b0))
        self.assertEqual(tuple(member.name for member in fields(DNSMessageFlagStatistics)),
                         ('message_count',) + tuple(field for field, _, _ in FLAG_FIELDS))

    def test_opcode_and_response_codes_are_not_duplicated(self):
        for opcode in range(16):
            for code in range(16):
                self.assertEqual(statistics(0x8000 | opcode << 11 | code), statistics(0x8000))

    def test_matched_transaction_contributes_both_messages(self):
        observation = advance(advance(flags=0x0200), flags=0x8200).observations[0]
        self.assertIs(observation.status, DNSCorrelationStatus.MATCHED)
        self.assertEqual(update_dns_message_flag_statistics(None, observation), DNSMessageFlagStatistics(2, 1, 2))

    def test_unmatched_response_contributes_once(self):
        observation = terminal(0x8200)
        self.assertIs(observation.status, DNSCorrelationStatus.UNMATCHED)
        self.assertEqual(update_dns_message_flag_statistics(None, observation), DNSMessageFlagStatistics(1, 1, 1))

    def test_unresolved_query_contributes_once(self):
        observation = terminal(0x0200)
        self.assertIs(observation.status, DNSCorrelationStatus.UNRESOLVED)
        self.assertEqual(update_dns_message_flag_statistics(None, observation), DNSMessageFlagStatistics(1, 0, 1))

    def test_ambiguous_query_ignores_contextual_request(self):
        observation = advance(advance(flags=0x0200), flags=0).observations[0]
        self.assertIs(observation.status, DNSCorrelationStatus.AMBIGUOUS)
        self.assertEqual(update_dns_message_flag_statistics(None, observation), DNSMessageFlagStatistics(1, 0, 0))

    def test_ambiguous_response_uses_observed_header(self):
        state = advance(advance(flags=0x0200), flags=0)
        observation = advance(state, flags=0x8200).observations[0]
        self.assertIs(observation.status, DNSCorrelationStatus.AMBIGUOUS)
        self.assertEqual(update_dns_message_flag_statistics(None, observation), DNSMessageFlagStatistics(1, 1, 1))

    def test_qr_is_read_from_header_properties(self):
        observation = terminal(0x8000)
        with patch.object(DNSHeader, 'is_response', new_callable=PropertyMock, return_value=False) as response:
            value = update_dns_message_flag_statistics(None, observation)
        self.assertEqual(value, DNSMessageFlagStatistics(1, 0, 0))
        response.assert_called_once_with()

    def test_tc_is_read_from_header_properties(self):
        observation = terminal(0)
        with patch.object(DNSHeader, 'truncated', new_callable=PropertyMock, return_value=True) as truncated:
            value = update_dns_message_flag_statistics(None, observation)
        self.assertEqual(value, DNSMessageFlagStatistics(1, 0, 1))
        truncated.assert_called_once_with()

    def test_questions_and_records_do_not_multiply_message_counts(self):
        raw = header(64, 64, flags=0x8200) + question() * 64 + record() * 64
        message = analyze_dns_message(raw)
        state = update_dns_correlation_state(None, message, IDENTITY, FlowDirection.REVERSE, EPOCH)
        self.assertEqual(update_dns_message_flag_statistics(None, state.observations[0]), DNSMessageFlagStatistics(1, 1, 1))

    def test_pending_is_rejected(self):
        with self.assertRaises(ValueError):
            update_dns_message_flag_statistics(None, advance().observations[0])

    def test_invalid_statuses_are_rejected(self):
        for status in (None, 'matched', 1, object()):
            with self.assertRaises(ValueError):
                update_dns_message_flag_statistics(None, altered_observation(terminal(), status=status))

    def test_wrong_argument_types_are_rejected(self):
        for value in (None, {}, (), header(), terminal().message, advance()):
            with self.assertRaises(TypeError):
                update_dns_message_flag_statistics(None, value)
        for value in (False, 0, {}, (), terminal()):
            with self.assertRaises(TypeError):
                update_dns_message_flag_statistics(value, terminal())

    def test_invalid_contributing_message_statuses_are_rejected(self):
        for raw in (header(1) + b'\x80', header(1) + b'\x01', header(1) + b'\x40'):
            message = analyze_dns_message(raw)
            self.assertIsNot(message.status, DNSMessageStatus.COMPLETE)
            with self.assertRaises(ValueError):
                update_dns_message_flag_statistics(None, altered_observation(terminal(), message=message))

    def test_absent_or_wrong_message_is_rejected(self):
        for message in (None, {}, header()):
            with self.assertRaises(TypeError):
                update_dns_message_flag_statistics(None, altered_observation(terminal(), message=message))

    def test_absent_or_wrong_header_is_rejected(self):
        source = terminal()
        for value in (None, {}, header()):
            message = altered_observation(source.message, header=value)
            with self.assertRaises(TypeError):
                update_dns_message_flag_statistics(None, altered_observation(source, message=message))

    def test_non_boolean_semantic_properties_are_rejected(self):
        source = terminal()
        for _, attribute, _ in FLAG_FIELDS:
            for value in (1, None, 'true', []):
                with patch.object(DNSHeader, attribute, new_callable=PropertyMock, return_value=value):
                    with self.assertRaises(TypeError):
                        update_dns_message_flag_statistics(None, source)

    def test_matched_request_must_be_a_complete_message(self):
        source = advance(advance(), flags=0x8000).observations[0]
        with self.assertRaises(TypeError):
            update_dns_message_flag_statistics(None, altered_observation(source, request=None))
        with self.assertRaises(ValueError):
            update_dns_message_flag_statistics(None, altered_observation(source, request=analyze_dns_message(b'')))

    def test_negative_counters_are_rejected(self):
        for field in fields(DNSMessageFlagStatistics):
            with self.assertRaises(ValueError):
                DNSMessageFlagStatistics(**{field.name: -1})

    def test_non_integer_counters_are_rejected(self):
        for field in fields(DNSMessageFlagStatistics):
            for value in (True, False, 0.0, 1.5, None, [], {}, (), '1'):
                with self.assertRaises(TypeError):
                    DNSMessageFlagStatistics(**{field.name: value})

    def test_set_counts_cannot_exceed_message_count(self):
        for values in ((0, 1, 0), (0, 0, 1), (1, 2, 0), (1, 0, 2)):
            with self.assertRaises(ValueError):
                DNSMessageFlagStatistics(*values)
        self.assertEqual(DNSMessageFlagStatistics(2, 2, 2).query_count, 0)

    def test_result_is_immutable(self):
        value = statistics()
        for field in fields(value):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, field.name, 4)
        with self.assertRaises(FrozenInstanceError):
            value.query_count = 3

    def test_copy_on_update_and_caller_mapping_mutation(self):
        arguments = dict(message_count=1, response_count=0, truncated_count=0)
        previous = DNSMessageFlagStatistics(**arguments)
        updated = update_dns_message_flag_statistics(previous, terminal(0x8200))
        arguments.clear()
        self.assertEqual(previous, DNSMessageFlagStatistics(1, 0, 0))
        self.assertEqual(updated, DNSMessageFlagStatistics(2, 1, 1))
        exported = asdict(updated)
        exported['message_count'] = 50
        self.assertEqual(updated.message_count, 2)

    def test_large_integer_counts_preserve_exactness(self):
        huge = 10 ** 400
        current = DNSMessageFlagStatistics(huge, huge - 1, huge)
        updated = update_dns_message_flag_statistics(current, terminal(0x8200))
        self.assertEqual(updated, DNSMessageFlagStatistics(huge + 1, huge, huge + 1))
        self.assertEqual(updated.query_count, 1)

    def test_repeated_observations_remain_multiplicity_sensitive(self):
        source = terminal(0x8200)
        value = None
        for _ in range(10000):
            value = update_dns_message_flag_statistics(value, source)
        self.assertEqual(value, DNSMessageFlagStatistics(10000, 10000, 10000))
        self.assertEqual(len(vars(value)), 8)
        self.assertTrue(all(type(item) is int for item in vars(value).values()))

    def test_source_graph_is_released(self):
        source = terminal(0x8200)
        references = [weakref.ref(item) for item in (source, source.message, source.message.header)]
        value = update_dns_message_flag_statistics(None, source)
        del source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(value, DNSMessageFlagStatistics(1, 1, 1))

    def test_already_delimited_tcp_transaction(self):
        identity = replace(IDENTITY, protocol=6)
        state = advance(advance(flags=0x0200, identity=identity), flags=0x8000, identity=identity)
        self.assertEqual(update_dns_message_flag_statistics(None, state.observations[0]), DNSMessageFlagStatistics(2, 1, 1))

    def test_no_reparsing_or_section_access(self):
        source = terminal(0x8200)
        with patch('analysis.dns.analyze_dns_message', side_effect=AssertionError('reparse')):
            with patch.object(DNSMessageObservation, 'questions', new_callable=PropertyMock, create=True, side_effect=AssertionError('questions')):
                self.assertEqual(update_dns_message_flag_statistics(None, source), DNSMessageFlagStatistics(1, 1, 1))

    def test_source_isolation_uses_only_semantic_header_properties(self):
        tree = ast.parse(Path('src/analysis/dns_message_flag_statistics.py').read_text())
        self.assertEqual([node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)],
                         ['dataclasses', 'typing', 'analysis.dns', 'analysis.dns_correlation'])
        forbidden = {'flags', 'payload', 'raw_bytes', 'rdata', 'questions', 'labels', 'answers', 'authorities', 'additionals',
                     'name', 'duration', 'timestamp', 'captured_at', 'identity', 'opcode', 'response_code'}
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertTrue((attributes - {'name'}).isdisjoint(forbidden))
        self.assertTrue(all(isinstance(node.value, ast.Name) and node.value.id == 'member'
                            for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr == 'name'))
        self.assertFalse(any(isinstance(node, (ast.BitAnd, ast.BitOr, ast.LShift, ast.RShift, ast.Div, ast.Import)) for node in ast.walk(tree)))

    def test_public_exports(self):
        self.assertIs(analysis.DNSMessageFlagStatistics, DNSMessageFlagStatistics)
        self.assertIs(analysis.update_dns_message_flag_statistics, update_dns_message_flag_statistics)
        self.assertIn('DNSMessageFlagStatistics', analysis.__all__)
        self.assertIn('update_dns_message_flag_statistics', analysis.__all__)


class CompleteDNSMessageFlagStatisticsTests(unittest.TestCase):
    def test_authoritative_answer_only(self):
        self.assertEqual(statistics(0x0400), DNSMessageFlagStatistics(1, authoritative_answer_count=1))

    def test_recursion_desired_only(self):
        self.assertEqual(statistics(0x0100), DNSMessageFlagStatistics(1, recursion_desired_count=1))

    def test_recursion_available_only(self):
        self.assertEqual(statistics(0x0080), DNSMessageFlagStatistics(1, recursion_available_count=1))

    def test_authenticated_data_only(self):
        self.assertEqual(statistics(0x0020), DNSMessageFlagStatistics(1, authenticated_data_count=1))

    def test_checking_disabled_only(self):
        self.assertEqual(statistics(0x0010), DNSMessageFlagStatistics(1, checking_disabled_count=1))

    def test_every_pair_of_flags_contributes_independently(self):
        for first, second in itertools.combinations(FLAG_FIELDS, 2):
            word = first[2] | second[2]
            value = statistics(word)
            self.assertEqual(value, expected_statistics(word))
            self.assertEqual(sum(getattr(value, field) for field, _, _ in FLAG_FIELDS), 2)

    def test_all_128_combinations_preserve_independent_counts(self):
        aggregate = None
        for enabled in itertools.product((False, True), repeat=7):
            word = sum(mask for (_, _, mask), present in zip(FLAG_FIELDS, enabled) if present)
            value = statistics(word)
            self.assertEqual(value, expected_statistics(word))
            self.assertEqual(value.query_count + value.response_count, value.message_count)
            aggregate = update_dns_message_flag_statistics(aggregate, terminal(word))
        self.assertEqual(aggregate.message_count, 128)
        self.assertTrue(all(getattr(aggregate, field) == 64 for field, _, _ in FLAG_FIELDS))

    def test_request_rd_and_response_ra_are_separate_contributions(self):
        observation = advance(advance(flags=0x0100), flags=0x8080).observations[0]
        self.assertIs(observation.status, DNSCorrelationStatus.MATCHED)
        self.assertEqual(update_dns_message_flag_statistics(None, observation),
                         DNSMessageFlagStatistics(2, 1, recursion_desired_count=1, recursion_available_count=1))

    def test_unmatched_response_has_all_new_flag_counts(self):
        self.assertEqual(statistics(0x87b0), expected_statistics(0x87b0))

    def test_unresolved_request_has_all_new_flag_counts(self):
        self.assertEqual(statistics(0x07b0), expected_statistics(0x07b0))

    def test_ambiguous_request_does_not_recount_context_flags(self):
        observation = advance(advance(flags=0x07b0), flags=0x0100).observations[0]
        self.assertIs(observation.status, DNSCorrelationStatus.AMBIGUOUS)
        self.assertEqual(update_dns_message_flag_statistics(None, observation), expected_statistics(0x0100))

    def test_ambiguous_response_counts_only_observed_header(self):
        state = advance(advance(flags=0x07b0), flags=0x0100)
        observation = advance(state, flags=0x84a0).observations[0]
        self.assertIs(observation.status, DNSCorrelationStatus.AMBIGUOUS)
        self.assertEqual(update_dns_message_flag_statistics(None, observation), expected_statistics(0x84a0))

    def test_legacy_positional_and_keyword_construction_defaults(self):
        positional = DNSMessageFlagStatistics(3, 2, 1)
        keyword = DNSMessageFlagStatistics(message_count=3, response_count=2, truncated_count=1)
        self.assertEqual(positional, keyword)
        self.assertEqual(positional.query_count, 1)
        for field, _, _ in FLAG_FIELDS[2:]:
            self.assertEqual(getattr(positional, field), 0)
        value = update_dns_message_flag_statistics(positional, terminal(0x87b0))
        self.assertEqual((value.message_count, value.response_count, value.truncated_count, value.query_count), (4, 3, 2, 1))

    def test_all_new_counts_are_bounded_by_messages(self):
        for field, _, _ in FLAG_FIELDS:
            with self.assertRaises(ValueError):
                DNSMessageFlagStatistics(message_count=1, **{field: 2})
        value = DNSMessageFlagStatistics(5, 5, 5, 5, 5, 5, 5, 5)
        self.assertEqual(value.query_count, 0)

    def test_numeric_subclasses_and_numeric_objects_are_not_coerced(self):
        class IntegerSubclass(int):
            pass
        class Numeric:
            def __int__(self):
                return 1
        for field in fields(DNSMessageFlagStatistics):
            for invalid in (IntegerSubclass(1), Numeric()):
                with self.assertRaises(TypeError):
                    DNSMessageFlagStatistics(**{field.name: invalid})

    def test_all_large_counters_increment_exactly(self):
        huge = 10 ** 400
        current = DNSMessageFlagStatistics(*((huge,) * 8))
        value = update_dns_message_flag_statistics(current, terminal(0x87b0))
        self.assertEqual(value, DNSMessageFlagStatistics(*((huge + 1,) * 8)))
        self.assertEqual(current.message_count, huge)

    def test_every_semantic_property_is_delegated_and_raw_word_is_never_read(self):
        source = terminal(0)
        for chosen, _, _ in FLAG_FIELDS:
            with ExitStack() as stack:
                spies = [(field, stack.enter_context(patch.object(DNSHeader, attribute, new_callable=PropertyMock,
                                                                  return_value=field == chosen)))
                         for field, attribute, _ in FLAG_FIELDS]
                stack.enter_context(patch.object(DNSHeader, 'flags', new_callable=PropertyMock, create=True,
                                                 side_effect=AssertionError('raw flags read')))
                value = update_dns_message_flag_statistics(None, source)
            self.assertEqual(value, DNSMessageFlagStatistics(message_count=1, **{chosen: 1}))
            for _, spy in spies:
                spy.assert_called_once_with()

    def test_invalid_inputs_leave_nonempty_previous_result_intact(self):
        current = statistics(0x87b0)
        before = asdict(current)
        for observation in (None, advance().observations[0], altered_observation(terminal(), status='matched')):
            with self.assertRaises((TypeError, ValueError)):
                update_dns_message_flag_statistics(current, observation)
            self.assertEqual(asdict(current), before)

    def test_invalid_second_message_does_not_publish_partial_contributions(self):
        current = statistics(0x87b0)
        source = advance(advance(flags=0x07b0), flags=0x87b0).observations[0]
        invalid = analyze_dns_message(header(1, flags=0x87b0) + b'\x80')
        with self.assertRaises(ValueError):
            update_dns_message_flag_statistics(current, altered_observation(source, message=invalid))
        self.assertEqual(current, expected_statistics(0x87b0))
        self.assertEqual(update_dns_message_flag_statistics(current, source), expected_statistics(0x87b0, 0x07b0, 0x87b0))

    def test_late_property_failure_leaves_all_counters_intact(self):
        current = statistics(0x87b0)
        source = terminal(0x87b0)
        with patch.object(DNSHeader, 'checking_disabled', new_callable=PropertyMock, side_effect=MemoryError('last flag')):
            with self.assertRaises(MemoryError):
                update_dns_message_flag_statistics(current, source)
        self.assertEqual(current, expected_statistics(0x87b0))
        self.assertEqual(update_dns_message_flag_statistics(current, source), expected_statistics(0x87b0, 0x87b0))

    def test_many_full_flag_observations_retain_only_eight_integers(self):
        source = terminal(0x87b0)
        current = None
        for _ in range(10000):
            current = update_dns_message_flag_statistics(current, source)
        self.assertEqual(current, DNSMessageFlagStatistics(*((10000,) * 8)))
        self.assertEqual(len(vars(current)), 8)
        self.assertTrue(all(type(value) is int for value in vars(current).values()))

    def test_completed_tcp_transactions_use_the_same_reducer(self):
        identity = replace(IDENTITY, protocol=6)
        source = advance(advance(flags=0x0130, identity=identity), flags=0x87b0, identity=identity).observations[0]
        self.assertEqual(update_dns_message_flag_statistics(None, source), expected_statistics(0x0130, 0x87b0))
