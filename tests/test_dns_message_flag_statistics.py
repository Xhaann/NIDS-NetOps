import ast
import gc
import unittest
import weakref
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


def advance(current=None, flags=0, identifier=1, identity=IDENTITY):
    message = analyze_dns_message(header(flags=flags, identifier=identifier))
    direction = FlowDirection.REVERSE if message.header.is_response else FlowDirection.FORWARD
    return update_dns_correlation_state(current, message, identity, direction, EPOCH)


def terminal(flags=0):
    return finalize_dns_correlation_state(advance(flags=flags)).observations[0]


def statistics(flags=0):
    return update_dns_message_flag_statistics(None, terminal(flags))


class DNSMessageFlagStatisticsTests(unittest.TestCase):
    def test_empty_state_has_only_three_zero_scalar_fields(self):
        value = DNSMessageFlagStatistics()
        self.assertEqual(asdict(value), dict(message_count=0, response_count=0, truncated_count=0))
        self.assertEqual(value.query_count, 0)

    def test_all_supported_flags_clear(self):
        self.assertEqual(statistics(0), DNSMessageFlagStatistics(1, 0, 0))

    def test_all_supported_flags_set(self):
        self.assertEqual(statistics(0x8200), DNSMessageFlagStatistics(1, 1, 1))

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

    def test_unrepresented_flag_bits_do_not_create_counters(self):
        for bit in (0x0400, 0x0100, 0x0080, 0x0040, 0x0020, 0x0010):
            self.assertEqual(statistics(bit), statistics(0))
            self.assertEqual(statistics(bit | 0x8200), statistics(0x8200))
        self.assertEqual(tuple(member.name for member in fields(DNSMessageFlagStatistics)),
                         ('message_count', 'response_count', 'truncated_count'))

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
        for attribute in ('is_response', 'truncated'):
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
        self.assertEqual(len(vars(value)), 3)
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
