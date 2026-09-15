import ast
import gc
import unittest
import weakref
from dataclasses import FrozenInstanceError, fields, replace
from fractions import Fraction
from pathlib import Path
from unittest.mock import PropertyMock, patch

import analysis
from analysis import (
    DNSCorrelationStatus, DNSMessageStatus, DNSResourceRecord, DNSResourceRecordStatistics, FlowDirection,
    analyze_dns_message, finalize_dns_correlation_state, update_dns_correlation_state,
    update_dns_resource_record_statistics,
)
from tests.test_dns import header, name, question, record
from tests.test_dns_correlation import EPOCH, IDENTITY


def payload(answers=(), authorities=(), additionals=(), response=True, identifier=1, questions=()):
    return (header(len(questions), len(answers), len(authorities), len(additionals),
                   flags=0x8000 if response else 0, identifier=identifier)
            + b''.join(questions) + b''.join(answers) + b''.join(authorities) + b''.join(additionals))


def advance(current=None, identity=IDENTITY, **kwargs):
    message = analyze_dns_message(payload(**kwargs))
    return update_dns_correlation_state(current, message, identity,
                                        FlowDirection.REVERSE if kwargs.get('response', True) else FlowDirection.FORWARD, EPOCH)


def terminal(**kwargs):
    return finalize_dns_correlation_state(advance(**kwargs)).observations[0]


def statistics(**kwargs):
    return update_dns_resource_record_statistics(None, terminal(**kwargs))


def counts_at(code, count):
    blocks = list(DNSResourceRecordStatistics().type_counts)
    block = list(blocks[code >> 8])
    block[code & 255] = count
    blocks[code >> 8] = tuple(block)
    return tuple(blocks)


def altered_observation(original, **changes):
    result = object.__new__(type(original))
    for name, value in dict(vars(original), **changes).items():
        object.__setattr__(result, name, value)
    return result


class DNSResourceRecordStatisticsTests(unittest.TestCase):
    def test_empty_counts_and_totals(self):
        value = DNSResourceRecordStatistics()
        self.assertEqual((value.resource_record_count, value.answer_count, value.authority_count,
                          value.additional_count, value.total_rdata_length_bytes), (0, 0, 0, 0, 0))

    def test_empty_extrema_and_mean_are_none(self):
        value = DNSResourceRecordStatistics()
        self.assertIsNone(value.min_rdata_length_bytes)
        self.assertIsNone(value.max_rdata_length_bytes)
        self.assertIsNone(value.mean_rdata_length_bytes)

    def test_empty_distributions_have_all_unsigned_16_bit_bins(self):
        value = DNSResourceRecordStatistics()
        for distribution in (value.type_counts, value.class_counts):
            self.assertEqual(len(distribution), 256)
            self.assertTrue(all(type(block) is tuple and len(block) == 256 for block in distribution))
            self.assertEqual(sum(sum(block) for block in distribution), 0)

    def test_single_answer(self):
        value = statistics(answers=(record(data=b'ab'),))
        self.assertEqual((value.answer_count, value.resource_record_count, value.total_rdata_length_bytes), (1, 1, 2))

    def test_multiple_answers(self):
        value = statistics(answers=(record(), record(data=b'a'), record(data=b'bc')))
        self.assertEqual((value.answer_count, value.resource_record_count), (3, 3))

    def test_authority_section(self):
        value = statistics(authorities=(record(), record()))
        self.assertEqual((value.answer_count, value.authority_count, value.additional_count, value.resource_record_count), (0, 2, 0, 2))

    def test_additional_section(self):
        value = statistics(additionals=(record(), record(), record()))
        self.assertEqual((value.answer_count, value.authority_count, value.additional_count, value.resource_record_count), (0, 0, 3, 3))

    def test_mixed_section_accounting(self):
        value = statistics(answers=(record(),), authorities=(record(),) * 2, additionals=(record(),) * 3)
        self.assertEqual((value.answer_count, value.authority_count, value.additional_count, value.resource_record_count), (1, 2, 3, 6))
        self.assertEqual(sum(sum(block) for block in value.type_counts), 6)
        self.assertEqual(sum(sum(block) for block in value.class_counts), 6)

    def test_question_entries_do_not_count_as_records(self):
        value = statistics(questions=(question(name(b'example'), kind=65535, cls=65535),))
        self.assertEqual(value, DNSResourceRecordStatistics())

    def test_zero_length_rdata_is_an_observation(self):
        value = statistics(answers=(record(),))
        self.assertEqual((value.min_rdata_length_bytes, value.max_rdata_length_bytes,
                          value.total_rdata_length_bytes, value.mean_rdata_length_bytes), (0, 0, 0, Fraction(0)))
        self.assertEqual(value.resource_record_count, 1)
        self.assertNotEqual(value, DNSResourceRecordStatistics())

    def test_rdata_extrema_total_and_fractional_mean(self):
        value = statistics(answers=tuple(record(data=b'x' * length) for length in (2, 0, 3)))
        self.assertEqual((value.min_rdata_length_bytes, value.max_rdata_length_bytes, value.total_rdata_length_bytes), (0, 3, 5))
        self.assertEqual(value.mean_rdata_length_bytes, Fraction(5, 3))

    def test_largest_rdata_that_fits_a_complete_parser_message(self):
        wire = record(data=b'x' * 65512)
        self.assertEqual(len(payload(answers=(wire,))), 65535)
        value = statistics(answers=(wire,))
        self.assertEqual((value.min_rdata_length_bytes, value.max_rdata_length_bytes, value.total_rdata_length_bytes), (65512, 65512, 65512))

    def test_type_distribution_includes_boundaries_and_unknown_codes(self):
        codes = (0, 1, 255, 256, 257, 4096, 65000, 65535)
        value = statistics(answers=tuple(record(kind=code) for code in reversed(codes)))
        for code in codes:
            self.assertEqual(value.type_counts[code >> 8][code & 255], 1)
        self.assertEqual(sum(sum(block) for block in value.type_counts), len(codes))

    def test_class_distribution_includes_full_wire_domain(self):
        codes = (0, 1, 3, 255, 256, 32768, 65535)
        value = statistics(answers=tuple(record(cls=code) for code in codes))
        for code in codes:
            self.assertEqual(value.class_counts[code >> 8][code & 255], 1)
        self.assertEqual(sum(sum(block) for block in value.class_counts), len(codes))

    def test_unknown_record_types_keep_opaque_payloads_in_accounting(self):
        value = statistics(answers=(record(kind=65432, cls=65535, data=b'\xff\x00\xc0\x0c'),))
        self.assertEqual((value.resource_record_count, value.total_rdata_length_bytes), (1, 4))
        self.assertEqual(value.type_counts[65432 >> 8][65432 & 255], 1)

    def test_edns_class_and_type_remain_structural_wire_values(self):
        value = statistics(additionals=(record(kind=41, cls=4096, ttl=0xffffffff, data=b'\x00\xff\x00\x02\x00\xff'),))
        self.assertEqual(value.type_counts[0][41], 1)
        self.assertEqual(value.class_counts[16][0], 1)
        self.assertEqual(value.total_rdata_length_bytes, 6)

    def test_duplicates_within_a_message_preserve_multiplicity(self):
        value = statistics(answers=(record(data=b'ab'),) * 10)
        self.assertEqual((value.resource_record_count, value.total_rdata_length_bytes, value.type_counts[0][1]), (10, 20, 10))

    def test_repeated_transaction_observations_preserve_multiplicity(self):
        observation = terminal(answers=(record(data=b'ab'),))
        current = None
        for _ in range(10):
            current = update_dns_resource_record_statistics(current, observation)
        self.assertEqual((current.resource_record_count, current.total_rdata_length_bytes), (10, 20))

    def test_matched_request_and_response_sections_both_contribute(self):
        state = advance(response=False, additionals=(record(kind=41),))
        state = advance(state, answers=(record(data=b'ab'),), authorities=(record(),), additionals=(record(),))
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.MATCHED)
        value = update_dns_resource_record_statistics(None, state.observations[0])
        self.assertEqual((value.answer_count, value.authority_count, value.additional_count, value.resource_record_count), (1, 1, 2, 4))

    def test_unmatched_response_counts_its_observed_records(self):
        observation = terminal(answers=(record(),))
        self.assertIs(observation.status, DNSCorrelationStatus.UNMATCHED)
        self.assertEqual(update_dns_resource_record_statistics(None, observation).resource_record_count, 1)

    def test_unresolved_request_counts_its_observed_records(self):
        observation = terminal(response=False, additionals=(record(),))
        self.assertIs(observation.status, DNSCorrelationStatus.UNRESOLVED)
        self.assertEqual(update_dns_resource_record_statistics(None, observation).additional_count, 1)

    def test_ambiguous_request_ignores_original_context_records(self):
        state = advance(response=False, additionals=(record(),) * 5)
        state = advance(state, response=False, additionals=(record(),) * 2)
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.AMBIGUOUS)
        self.assertEqual(update_dns_resource_record_statistics(None, state.observations[0]).resource_record_count, 2)

    def test_ambiguous_response_counts_only_its_records(self):
        state = advance(advance(response=False), response=False)
        state = advance(state, answers=(record(),) * 3)
        self.assertIs(state.observations[0].status, DNSCorrelationStatus.AMBIGUOUS)
        self.assertEqual(update_dns_resource_record_statistics(None, state.observations[0]).answer_count, 3)

    def test_pending_observations_are_rejected(self):
        with self.assertRaises(ValueError):
            update_dns_resource_record_statistics(None, advance(response=False).observations[0])

    def test_wrong_argument_types_are_rejected(self):
        source = terminal()
        for value in (None, {}, [], payload(), source.message, advance()):
            with self.assertRaises(TypeError):
                update_dns_resource_record_statistics(None, value)
        with self.assertRaises(TypeError):
            update_dns_resource_record_statistics({}, source)

    def test_invalid_terminal_status_cannot_create_state(self):
        for status in (None, 'matched', object()):
            with self.assertRaises(ValueError):
                update_dns_resource_record_statistics(None, altered_observation(terminal(), status=status))

    def test_invalid_terminal_messages_cannot_create_state(self):
        for raw in (header(0, 1) + b'\x80', header(0, 1) + b'\x01', header(0, 1) + b'\x40'):
            invalid = analyze_dns_message(raw)
            self.assertIsNot(invalid.status, DNSMessageStatus.COMPLETE)
            with self.assertRaises(ValueError):
                update_dns_resource_record_statistics(None, altered_observation(terminal(), message=invalid))

    def test_matched_observation_requires_both_established_messages(self):
        observation = advance(advance(response=False)).observations[0]
        with self.assertRaises(TypeError):
            update_dns_resource_record_statistics(None, altered_observation(observation, request=None))
        invalid = analyze_dns_message(b'')
        with self.assertRaises(ValueError):
            update_dns_resource_record_statistics(None, altered_observation(observation, request=invalid))

    def test_rdata_and_owner_names_are_never_accessed_or_decoded(self):
        observation = terminal(answers=(record(name(b'owner'), kind=1, data=b'\x00\xff\xc0\x0c'),))
        with patch.object(DNSResourceRecord, 'rdata', new_callable=PropertyMock, create=True, side_effect=AssertionError('RDATA read')):
            with patch.object(DNSResourceRecord, 'name', new_callable=PropertyMock, create=True, side_effect=AssertionError('name read')):
                value = update_dns_resource_record_statistics(None, observation)
        self.assertEqual(value.total_rdata_length_bytes, 4)

    def test_established_parser_result_is_consumed_without_reparsing(self):
        observation = terminal(answers=(record(),))
        with patch('analysis.dns.analyze_dns_message', side_effect=AssertionError('reparse')):
            value = update_dns_resource_record_statistics(None, observation)
        self.assertEqual(value.resource_record_count, 1)

    def test_empty_record_observation_preserves_previous_value(self):
        current = statistics(answers=(record(),))
        self.assertIs(update_dns_resource_record_statistics(current, terminal()), current)

    def test_immutable_scalar_fields_and_nested_distributions(self):
        value = statistics(answers=(record(),))
        for field in fields(value):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, field.name, None)
        with self.assertRaises(TypeError):
            value.type_counts[0] = ()
        with self.assertRaises(TypeError):
            value.class_counts[0][1] = 4

    def test_copy_on_update_leaves_previous_bins_unchanged(self):
        before = statistics(answers=(record(),))
        after = update_dns_resource_record_statistics(before, terminal(answers=(record(kind=257, cls=513),)))
        self.assertEqual(before.type_counts[1][1], 0)
        self.assertEqual(after.type_counts[1][1], 1)
        self.assertIs(after.type_counts[0], before.type_counts[0])
        self.assertIs(after.class_counts[0], before.class_counts[0])

    def test_mutable_distribution_inputs_are_rejected(self):
        empty = DNSResourceRecordStatistics()
        for field in ('type_counts', 'class_counts'):
            for invalid in (list(empty.type_counts), (list(empty.type_counts[0]),) * 256, {}, ()):
                with self.assertRaises(TypeError):
                    replace(empty, **{field: invalid})

    def test_invalid_bins_and_distribution_totals_are_rejected(self):
        for count, error in ((True, TypeError), (1.0, TypeError), (-1, ValueError), (1, ValueError)):
            with self.assertRaises(error):
                DNSResourceRecordStatistics(type_counts=counts_at(65535, count))
        with self.assertRaises(TypeError):
            DNSResourceRecordStatistics(class_counts=((0,) * 255,) * 256)

    def test_scalar_types_and_empty_rdata_contract_are_validated(self):
        for field in ('answer_count', 'authority_count', 'additional_count', 'total_rdata_length_bytes',
                      'min_rdata_length_bytes', 'max_rdata_length_bytes'):
            for invalid in (True, 1.0, [], {}):
                with self.assertRaises(TypeError):
                    DNSResourceRecordStatistics(**{field: invalid})
            with self.assertRaises(ValueError):
                DNSResourceRecordStatistics(**{field: -1})
        for change in ({'min_rdata_length_bytes': 0}, {'max_rdata_length_bytes': 0}, {'total_rdata_length_bytes': 1}):
            with self.assertRaises(ValueError):
                DNSResourceRecordStatistics(**change)

    def test_inconsistent_record_extrema_and_totals_are_rejected(self):
        value = statistics(answers=(record(data=b'ab'),))
        for change in ({'min_rdata_length_bytes': None}, {'max_rdata_length_bytes': 1},
                       {'max_rdata_length_bytes': 65536}, {'total_rdata_length_bytes': 3}, {'answer_count': 2}):
            with self.assertRaises(ValueError):
                replace(value, **change)

    def test_large_integer_totals_and_fraction_mean_are_exact(self):
        count = 10 ** 400
        value = DNSResourceRecordStatistics(answer_count=count, total_rdata_length_bytes=count,
                                             min_rdata_length_bytes=1, max_rdata_length_bytes=1,
                                             type_counts=counts_at(1, count), class_counts=counts_at(1, count))
        updated = update_dns_resource_record_statistics(value, terminal(answers=(record(data=b'ab'),)))
        self.assertEqual(updated.resource_record_count, count + 1)
        self.assertEqual(updated.total_rdata_length_bytes, count + 2)
        self.assertEqual(updated.mean_rdata_length_bytes, Fraction(count + 2, count + 1))
        self.assertEqual(updated.type_counts[0][1], count + 1)

    def test_constructor_mapping_mutation_cannot_alter_recorded_result(self):
        arguments = dict(vars(statistics(answers=(record(data=b'a'),))))
        value = DNSResourceRecordStatistics(**arguments)
        result = update_dns_resource_record_statistics(value, terminal(answers=(record(data=b'bc'),)))
        arguments.clear()
        self.assertEqual(value.resource_record_count, 1)
        self.assertEqual(result.mean_rdata_length_bytes, Fraction(3, 2))

    def test_result_does_not_retain_transaction_message_or_records(self):
        source = terminal(answers=(record(),))
        references = [weakref.ref(item) for item in (source, source.message, source.message.answers[0], source.message.answers[0].name)]
        value = update_dns_resource_record_statistics(None, source)
        del source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(value.resource_record_count, 1)

    def test_already_delimited_tcp_transaction_is_supported(self):
        identity = replace(IDENTITY, protocol=6)
        state = advance(advance(response=False, identity=identity), identity=identity, answers=(record(data=b'ab'),))
        self.assertEqual(update_dns_resource_record_statistics(None, state.observations[0]), statistics(answers=(record(data=b'ab'),)))

    def test_source_dependencies_and_attribute_access_are_structural_only(self):
        tree = ast.parse(Path('src/analysis/dns_resource_record_statistics.py').read_text())
        self.assertEqual([node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)],
                         ['dataclasses', 'fractions', 'typing', 'analysis.dns', 'analysis.dns_correlation'])
        self.assertFalse(any(isinstance(node, (ast.Import, ast.Div)) for node in ast.walk(tree)))
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertTrue(attributes.isdisjoint({'rdata', 'payload', 'raw_bytes', 'decode', 'labels', 'questions',
                                             'identity', 'duration', 'now', 'timestamp', 'ttl'}))

    def test_public_exports(self):
        for name in ('DNSResourceRecordStatistics', 'update_dns_resource_record_statistics'):
            self.assertIn(name, analysis.__all__)
            self.assertTrue(hasattr(analysis, name))
