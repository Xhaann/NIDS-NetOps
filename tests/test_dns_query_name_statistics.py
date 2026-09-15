import ast
import gc
import unittest
import weakref
from dataclasses import FrozenInstanceError, asdict, fields, replace
from datetime import timedelta
from fractions import Fraction
from pathlib import Path
from unittest.mock import PropertyMock, patch

import analysis
from analysis import (
    DNSCorrelationStatus, DNSName, DNSQueryNameStatistics, FlowDirection, analyze_dns_message,
    finalize_dns_correlation_state, update_dns_correlation_state, update_dns_query_name_statistics,
)
from tests.test_dns import header, name, pointer, question, record
from tests.test_dns_correlation import EPOCH, IDENTITY


def message(query_names=((b'example',),), response=False, identifier=1):
    return analyze_dns_message(header(len(query_names), flags=0x8000 if response else 0, identifier=identifier)
                               + b''.join(question(name(*labels)) for labels in query_names))


def advance(current=None, query_names=((b'example',),), response=False, identifier=1, identity=IDENTITY, seconds=0):
    return update_dns_correlation_state(current, message(query_names, response, identifier), identity,
                                        FlowDirection.REVERSE if response else FlowDirection.FORWARD,
                                        EPOCH + timedelta(seconds=seconds))


def terminal(query_names=((b'example',),), response=True):
    return finalize_dns_correlation_state(advance(query_names=query_names, response=response)).observations[0]


def statistics(*query_names):
    return update_dns_query_name_statistics(None, terminal(query_names))


class DNSQueryNameStatisticsTests(unittest.TestCase):
    def test_empty_counters_are_zero(self):
        value = DNSQueryNameStatistics()
        for field in fields(value):
            if not field.name.startswith(('min_', 'max_')):
                self.assertEqual(getattr(value, field.name), 0)

    def test_empty_extrema_and_means_are_absent(self):
        value = DNSQueryNameStatistics()
        for field in fields(value):
            if field.name.startswith(('min_', 'max_')):
                self.assertIsNone(getattr(value, field.name))
        self.assertIsNone(value.mean_name_length_bytes)
        self.assertIsNone(value.mean_label_length_bytes)

    def test_root_is_one_expanded_octet_and_zero_labels(self):
        value = statistics(())
        self.assertEqual((value.query_name_count, value.root_name_count, value.label_count), (1, 1, 0))
        self.assertEqual((value.min_name_length_bytes, value.max_name_length_bytes, value.total_name_length_bytes), (1, 1, 1))
        self.assertEqual(value.mean_name_length_bytes, Fraction(1))
        self.assertEqual(value.max_labels_per_name, 0)
        self.assertIsNone(value.min_labels_per_non_root_name)
        self.assertIsNone(value.mean_label_length_bytes)

    def test_root_never_creates_an_empty_label_sample(self):
        value = statistics((), ())
        self.assertEqual(value.total_label_length_bytes, 0)
        self.assertIsNone(value.min_label_length_bytes)
        self.assertIsNone(value.max_label_length_bytes)
        self.assertNotEqual(value, DNSQueryNameStatistics())

    def test_single_label_uses_expanded_name_and_label_payload_octets(self):
        value = statistics((b'abc',))
        self.assertEqual((value.query_name_count, value.label_count, value.total_name_length_bytes), (1, 1, 5))
        self.assertEqual((value.total_label_length_bytes, value.min_label_length_bytes, value.max_label_length_bytes), (3, 3, 3))
        self.assertEqual((value.max_labels_per_name, value.min_labels_per_non_root_name), (1, 1))

    def test_multiple_labels_include_length_octets_and_one_root_octet(self):
        value = statistics((b'a', b'xyz'))
        self.assertEqual((value.label_count, value.total_name_length_bytes, value.total_label_length_bytes), (2, 7, 4))
        self.assertEqual((value.min_label_length_bytes, value.max_label_length_bytes), (1, 3))

    def test_multiple_questions_each_contribute_a_name(self):
        value = statistics((), (b'a',), (b'bb', b'ccc'))
        self.assertEqual((value.query_name_count, value.label_count, value.root_name_count), (3, 3, 1))

    def test_name_length_extrema_and_total(self):
        value = statistics((b'ab',), (b'abc', b'xy'), (b'a',))
        self.assertEqual((value.min_name_length_bytes, value.max_name_length_bytes, value.total_name_length_bytes), (3, 8, 15))

    def test_exact_fractional_mean_name_length(self):
        self.assertEqual(statistics((), (b'a',), (b'ab',)).mean_name_length_bytes, Fraction(8, 3))

    def test_label_length_extrema_and_total(self):
        value = statistics((b'ab',), (b'abc', b'xy'), (b'a',))
        self.assertEqual((value.min_label_length_bytes, value.max_label_length_bytes, value.total_label_length_bytes), (1, 3, 8))

    def test_exact_fractional_mean_label_length_excludes_roots(self):
        value = statistics((), (b'a', b'bc', b'de'))
        self.assertEqual(value.mean_label_length_bytes, Fraction(5, 3))

    def test_maximum_label_count_and_minimum_non_root_count(self):
        value = statistics((), (b'a', b'b', b'c'), (b'abc',), (b'x', b'y'))
        self.assertEqual((value.max_labels_per_name, value.min_labels_per_non_root_name), (3, 1))

    def test_root_transition_preserves_label_extrema(self):
        value = statistics((b'abc',))
        updated = update_dns_query_name_statistics(value, terminal(((),)))
        self.assertEqual(updated.min_name_length_bytes, 1)
        self.assertEqual(updated.min_label_length_bytes, 3)
        self.assertEqual(updated.max_label_length_bytes, 3)

    def test_ascii_digit_counts_names_not_digits_or_labels(self):
        value = statistics((b'123', b'45'), (b'a9',), (b'abc',))
        self.assertEqual(value.digit_name_count, 2)

    def test_hyphen_counts_names_not_hyphens(self):
        value = statistics((b'--', b'a-b'), (b'abc',))
        self.assertEqual(value.hyphen_name_count, 1)

    def test_underscore_counts_names_not_underscores(self):
        value = statistics((b'_srv', b'_tcp'), (b'a_b',), ())
        self.assertEqual(value.underscore_name_count, 2)

    def test_non_ascii_bytes_are_not_decoded_as_characters(self):
        value = statistics((b'\xff\x80',), (b'\xc3\xa9',), (b'ascii',))
        self.assertEqual(value.non_ascii_name_count, 2)
        self.assertEqual(value.total_label_length_bytes, 9)

    def test_byte_classifications_are_independent(self):
        value = statistics((b'1-_\x80',))
        self.assertEqual((value.digit_name_count, value.hyphen_name_count, value.underscore_name_count, value.non_ascii_name_count), (1, 1, 1, 1))

    def test_classification_boundaries_and_control_bytes(self):
        value = statistics((b'/0:9',), (b'\x7f\x80',), (b'\x00.\\',))
        self.assertEqual((value.digit_name_count, value.non_ascii_name_count), (1, 1))
        self.assertEqual(value.label_count, 3)
        self.assertEqual(value.total_label_length_bytes, 9)

    def test_unicode_digit_bytes_do_not_become_ascii_digits(self):
        value = statistics(('١'.encode('utf-8'),))
        self.assertEqual((value.digit_name_count, value.non_ascii_name_count), (0, 1))

    def test_case_is_preserved_and_no_normalization_is_applied(self):
        item = terminal(((b'AbC9', b'_X-'),))
        before = item.message.questions[0].name.labels
        first = update_dns_query_name_statistics(None, item)
        second = statistics((b'aBc9', b'_x-'))
        self.assertEqual(first, second)
        self.assertEqual(item.message.questions[0].name.labels, before)

    def test_maximum_label_length(self):
        value = statistics((b'x' * 63,))
        self.assertEqual((value.total_name_length_bytes, value.max_label_length_bytes), (65, 63))

    def test_maximum_expanded_name_length(self):
        value = statistics((b'a' * 63, b'b' * 63, b'c' * 63, b'd' * 61))
        self.assertEqual((value.total_name_length_bytes, value.total_label_length_bytes, value.label_count), (255, 250, 4))

    def test_maximum_number_of_nonempty_labels(self):
        value = statistics((b'a',) * 127)
        self.assertEqual((value.max_labels_per_name, value.total_name_length_bytes), (127, 255))

    def test_maximum_question_batch_in_both_matched_messages(self):
        query_names = ((b'x' * 63, b'y' * 63, b'z' * 63, b'w' * 61),) * 128
        state = advance(advance(query_names=query_names), query_names=query_names, response=True)
        value = update_dns_query_name_statistics(None, state.observations[0])
        self.assertEqual((value.query_name_count, value.label_count, value.total_name_length_bytes), (256, 1024, 65280))
        self.assertEqual(len(fields(value)), 15)

    def test_parser_expanded_length_is_used_instead_of_pointer_encoding(self):
        payload = header(2, flags=0x8000) + question(name(b'example')) + question(pointer(12))
        observed = analyze_dns_message(payload)
        state = update_dns_correlation_state(None, observed, IDENTITY, FlowDirection.REVERSE, EPOCH)
        first, second = observed.questions
        self.assertNotEqual(first.name.encoded_length, second.name.encoded_length)
        value = update_dns_query_name_statistics(None, state.observations[0])
        self.assertEqual((value.query_name_count, value.total_name_length_bytes), (2, 18))

    def test_only_questions_contribute_not_other_sections_or_rdata(self):
        payload = header(1, 1, 1, 1, flags=0x8000) + question(name(b'a'))
        payload += record(name(b'99-_\xff'), data=name(b'embedded')) * 3
        observed = analyze_dns_message(payload)
        state = update_dns_correlation_state(None, observed, IDENTITY, FlowDirection.REVERSE, EPOCH)
        self.assertEqual(update_dns_query_name_statistics(None, state.observations[0]), statistics((b'a',)))

    def test_message_without_questions_is_empty_even_with_records(self):
        payload = header(0, 1, flags=0x8000) + record(name(b'99-_\xff'))
        state = update_dns_correlation_state(None, analyze_dns_message(payload), IDENTITY, FlowDirection.REVERSE, EPOCH)
        self.assertEqual(update_dns_query_name_statistics(None, state.observations[0]), DNSQueryNameStatistics())

    def test_match_counts_request_and_response_as_established_messages(self):
        state = advance(advance(), response=True)
        self.assertEqual(update_dns_query_name_statistics(None, state.observations[0]), statistics((b'example',), (b'example',)))

    def test_unresolved_request_contributes_its_questions_once(self):
        self.assertEqual(update_dns_query_name_statistics(None, terminal(response=False)), statistics((b'example',)))

    def test_ambiguous_request_uses_observed_name_not_original_context(self):
        state = advance(advance(query_names=((b'old',),)), query_names=((b'new9',),))
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.AMBIGUOUS)
        self.assertEqual(update_dns_query_name_statistics(None, state.observations[0]), statistics((b'new9',)))

    def test_ambiguous_response_contributes_its_own_question(self):
        state = advance(advance(advance()), query_names=((b'different',),), response=True)
        self.assertEqual(update_dns_query_name_statistics(None, state.observations[0]), statistics((b'different',)))

    def test_pending_is_rejected(self):
        with self.assertRaises(ValueError):
            update_dns_query_name_statistics(None, advance().observations[0])

    def test_nontransaction_inputs_are_rejected(self):
        for value in (None, {}, [], message(), message().questions[0], message().questions[0].name, advance()):
            with self.assertRaises(TypeError):
                update_dns_query_name_statistics(None, value)
        with self.assertRaises(TypeError):
            update_dns_query_name_statistics({}, terminal())

    def test_frozen_result_exposes_no_mutable_container(self):
        value = statistics((b'a',))
        for field in fields(value):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, field.name, 9)
            self.assertTrue(getattr(value, field.name) is None or type(getattr(value, field.name)) is int)

    def test_caller_argument_mutation_does_not_change_recorded_result(self):
        arguments = asdict(statistics((b'a',)))
        before = DNSQueryNameStatistics(**arguments)
        result = update_dns_query_name_statistics(before, terminal(((b'bb',),)))
        arguments.clear()
        self.assertEqual(before.query_name_count, 1)
        self.assertEqual(result.mean_name_length_bytes, Fraction(7, 2))

    def test_replacing_source_observation_does_not_change_result(self):
        source = terminal(((b'a',),))
        value = update_dns_query_name_statistics(None, source)
        source = terminal(((b'changed',),))
        self.assertEqual(value.total_name_length_bytes, 3)
        self.assertNotEqual(value, update_dns_query_name_statistics(None, source))

    def test_result_does_not_retain_source_graph(self):
        source = terminal(((b'a',),))
        question_value = source.message.questions[0]
        references = tuple(weakref.ref(item) for item in (source, source.message, question_value, question_value.name, source.identity))
        result = update_dns_query_name_statistics(None, source)
        del source, question_value
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references[:-1]))
        self.assertEqual(result.query_name_count, 1)
        self.assertNotIn('identity', vars(result))

    def test_large_counts_and_fractional_totals_remain_exact(self):
        count = 10 ** 400
        value = DNSQueryNameStatistics(query_name_count=count, label_count=count, total_name_length_bytes=3 * count,
                                        min_name_length_bytes=3, max_name_length_bytes=3, total_label_length_bytes=count,
                                        min_label_length_bytes=1, max_label_length_bytes=1, max_labels_per_name=1,
                                        min_labels_per_non_root_name=1)
        result = update_dns_query_name_statistics(value, terminal(((b'bb',),)))
        self.assertEqual(result.query_name_count, count + 1)
        self.assertEqual(result.mean_name_length_bytes, Fraction(3 * count + 4, count + 1))
        self.assertEqual(result.mean_label_length_bytes, Fraction(count + 2, count + 1))

    def test_counter_and_extremum_types_are_exact(self):
        for field in fields(DNSQueryNameStatistics):
            for invalid in (True, 1.0, [], {}):
                with self.assertRaises(TypeError):
                    DNSQueryNameStatistics(**{field.name: invalid})
            with self.assertRaises(ValueError):
                DNSQueryNameStatistics(**{field.name: -1})

    def test_inconsistent_aggregate_contracts_are_rejected(self):
        value = statistics((b'a',))
        for changes in ({'total_name_length_bytes': 4}, {'root_name_count': 2}, {'digit_name_count': 2},
                        {'min_name_length_bytes': None}, {'max_label_length_bytes': 64},
                        {'max_labels_per_name': 128}, {'min_labels_per_non_root_name': 0},
                        {'label_count': 2}, {'max_name_length_bytes': 256}):
            with self.assertRaises(ValueError):
                replace(value, **changes)
        for changes in ({'max_labels_per_name': 0}, {'min_label_length_bytes': 0}, {'total_label_length_bytes': 1}):
            with self.assertRaises(ValueError):
                DNSQueryNameStatistics(**changes)

    def test_delimited_tcp_transactions_use_identical_structure(self):
        identity = replace(IDENTITY, protocol=6)
        state = advance(advance(identity=identity), response=True, identity=identity)
        self.assertEqual(update_dns_query_name_statistics(None, state.observations[0]), statistics((b'example',), (b'example',)))

    def test_structure_is_independent_of_capture_time_and_latency(self):
        early = advance(advance(), response=True)
        later = advance(advance(seconds=100), response=True, seconds=200)
        self.assertEqual(update_dns_query_name_statistics(None, early.observations[0]),
                         update_dns_query_name_statistics(None, later.observations[0]))

    def test_parser_delegation_and_canonical_expanded_length(self):
        source = terminal(((b'abc',),))
        with patch('analysis.dns.analyze_dns_message', side_effect=AssertionError('reparse')):
            with patch.object(DNSName, 'expanded_length', new_callable=PropertyMock, return_value=5) as expanded:
                value = update_dns_query_name_statistics(None, source)
        expanded.assert_called_once_with()
        self.assertEqual(value.total_name_length_bytes, 5)

    def test_source_isolation_no_clock_decode_float_or_entropy(self):
        tree = ast.parse(Path('src/analysis/dns_query_name_statistics.py').read_text())
        imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertEqual(imports, ['dataclasses', 'fractions', 'typing', 'analysis.dns', 'analysis.dns_correlation'])
        self.assertFalse(any(isinstance(node, (ast.Import, ast.Div)) for node in ast.walk(tree)))
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertTrue(attributes.isdisjoint({'decode', 'lower', 'upper', 'raw_bytes', 'payload', 'encoded_length',
                                             'now', 'timestamp', 'duration', 'identity', 'answers', 'authorities', 'additionals'}))

    def test_public_exports(self):
        for name in ('DNSQueryNameStatistics', 'update_dns_query_name_statistics'):
            self.assertIn(name, analysis.__all__)
            self.assertTrue(hasattr(analysis, name))
