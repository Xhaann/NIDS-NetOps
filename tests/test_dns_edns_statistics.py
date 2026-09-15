import ast
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from fractions import Fraction
from pathlib import Path
from unittest.mock import PropertyMock, patch

import analysis
from analysis import (
    DNSEDNS, DNSEDNSOption, DNSEDNSStatistics, DNSCorrelationStatus, DNSMessageStatus,
    DNS_MAX_EDNS_OPTIONS, DNS_MAX_EDNS_OPTION_DATA_BYTES, FlowDirection,
    analyze_dns_message, finalize_dns_correlation_state, update_dns_correlation_state,
    update_dns_edns_statistics,
)
from tests.test_dns import header
from tests.test_dns_correlation import EPOCH, IDENTITY
from tests.test_dns_edns import message, opt, option
from tests.test_dns_resource_record_statistics import altered_observation, counts_at


SCALARS = ('edns_message_count', 'option_count', 'min_option_data_length', 'max_option_data_length',
           'total_option_data_length_bytes', 'zero_length_option_count', 'max_options_in_message',
           'min_options_in_message', 'udp_payload_size_min', 'udp_payload_size_max',
           'udp_payload_size_total', 'dnssec_ok_count')
DISTRIBUTIONS = ('extended_rcode_counts', 'version_counts', 'option_code_counts')


def advance(current=None, raw=None, identity=IDENTITY):
    parsed = analyze_dns_message(message(opt()) if raw is None else raw)
    return update_dns_correlation_state(current, parsed, identity,
                                        FlowDirection.REVERSE if parsed.header.is_response else FlowDirection.FORWARD, EPOCH)


def terminal(raw=None):
    return finalize_dns_correlation_state(advance(raw=raw)).observations[0]


def statistics(**kwargs):
    return update_dns_edns_statistics(None, terminal(message(opt(**kwargs))))


def bins_at(index, count=1):
    return (0,) * index + (count,) + (0,) * (255 - index)


class DNSEDNSStatisticsTests(unittest.TestCase):
    def test_public_exports_and_exact_fields(self):
        self.assertIs(analysis.DNSEDNSStatistics, DNSEDNSStatistics)
        self.assertIs(analysis.update_dns_edns_statistics, update_dns_edns_statistics)
        self.assertEqual({member.name for member in fields(DNSEDNSStatistics)}, set(SCALARS + DISTRIBUTIONS))
        self.assertEqual(len(SCALARS), 12)

    def test_empty_state_and_fixed_domains(self):
        value = DNSEDNSStatistics()
        for name in SCALARS:
            expected = None if name.startswith(('min_', 'max_')) or name.endswith(('_min', '_max')) else 0
            self.assertEqual(getattr(value, name), expected)
        self.assertIsNone(value.mean_option_data_length)
        self.assertEqual((value.unknown_option_count, value.non_dnssec_ok_count), (0, 0))
        for name in DISTRIBUTIONS[:2]:
            self.assertEqual(getattr(value, name), (0,) * 256)
        self.assertEqual(len(value.option_code_counts), 256)
        self.assertTrue(all(type(block) is tuple and block == (0,) * 256 for block in value.option_code_counts))

    def test_absent_opt_is_identity_update(self):
        value = statistics(data=option(7, b'ab'))
        self.assertIs(update_dns_edns_statistics(value, terminal(header())), value)
        self.assertEqual(update_dns_edns_statistics(None, terminal(header())), DNSEDNSStatistics())

    def test_empty_opt_is_distinct_from_zero_length_option(self):
        empty, zero = statistics(), statistics(data=option())
        self.assertEqual((empty.edns_message_count, empty.option_count, empty.min_options_in_message), (1, 0, 0))
        self.assertIsNone(empty.mean_option_data_length)
        self.assertEqual((zero.option_count, zero.zero_length_option_count, zero.min_option_data_length,
                          zero.max_option_data_length, zero.mean_option_data_length), (1, 1, 0, 0, Fraction(0)))

    def test_duplicate_codes_and_exact_length_statistics(self):
        value = statistics(data=option(7) + option(7, b'ab') + option(65535, b'abc'), size=4096, flags=0x8000)
        self.assertEqual((value.option_count, value.unknown_option_count, value.zero_length_option_count), (3, 3, 1))
        self.assertEqual((value.min_option_data_length, value.max_option_data_length,
                          value.total_option_data_length_bytes, value.mean_option_data_length), (0, 3, 5, Fraction(5, 3)))
        self.assertEqual((value.min_options_in_message, value.max_options_in_message), (3, 3))
        self.assertEqual((value.udp_payload_size_min, value.udp_payload_size_max, value.udp_payload_size_total), (4096, 4096, 4096))
        self.assertEqual((value.option_code_counts[0][7], value.option_code_counts[255][255]), (2, 1))
        self.assertEqual((value.dnssec_ok_count, value.non_dnssec_ok_count), (1, 0))

    def test_all_options_are_opaque_including_familiar_codes(self):
        value = statistics(data=b''.join(option(code, b'opaque') for code in (0, 3, 8, 10, 12, 15, 65535)))
        self.assertEqual(value.unknown_option_count, 7)
        self.assertEqual(value.unknown_option_count, value.option_count)

    def test_full_version_and_extended_rcode_domains(self):
        value = None
        for index in range(256):
            value = update_dns_edns_statistics(value, terminal(message(opt(version=index, extended=255 - index))))
        self.assertEqual(value.version_counts, (1,) * 256)
        self.assertEqual(value.extended_rcode_counts, (1,) * 256)

    def test_code_block_boundaries_preserve_unsigned_codes(self):
        codes = (0, 1, 255, 256, 257, 32767, 32768, 65279, 65280, 65535)
        value = statistics(data=b''.join(option(code) for code in codes))
        for code in codes:
            self.assertEqual(value.option_code_counts[code // 256][code % 256], 1)
        self.assertEqual(sum(map(sum, value.option_code_counts)), len(codes))

    def test_reserved_edns_flags_do_not_change_statistics(self):
        self.assertEqual(statistics(flags=0x7fff), statistics(flags=0))
        self.assertEqual(statistics(flags=0xffff), statistics(flags=0x8000))

    def test_do_and_header_ad_are_independent(self):
        values = [update_dns_edns_statistics(None, terminal(message(opt(flags=edns), flags=flags)))
                  for edns, flags in ((0, 0x20), (0, 0), (0x8000, 0x20), (0x8000, 0))]
        self.assertEqual(values[0], values[1])
        self.assertEqual(values[2], values[3])
        self.assertEqual([value.dnssec_ok_count for value in values], [0, 0, 1, 1])

    def test_matched_request_and_response_count_independently(self):
        state = advance(raw=message(opt(size=0, data=option(1))))
        state = advance(state, message(opt(size=65535, version=255, extended=255, data=option(2, b'ab')), flags=0x8000))
        observed, = state.observations
        self.assertIs(observed.status, DNSCorrelationStatus.MATCHED)
        value = update_dns_edns_statistics(None, observed)
        self.assertEqual((value.edns_message_count, value.option_count, value.udp_payload_size_min,
                          value.udp_payload_size_max, value.udp_payload_size_total), (2, 2, 0, 65535, 65535))
        self.assertEqual(value.mean_option_data_length, Fraction(1))

    def test_matched_message_without_edns_does_not_contribute(self):
        for first, second in ((message(opt()), header(flags=0x8000)), (header(), message(opt(), flags=0x8000))):
            observed, = advance(advance(raw=first), second).observations
            self.assertEqual(update_dns_edns_statistics(None, observed), statistics())

    def test_unmatched_and_unresolved_terminal_observations(self):
        for flags, status in ((0, DNSCorrelationStatus.UNRESOLVED), (0x8000, DNSCorrelationStatus.UNMATCHED)):
            observed = terminal(message(opt(data=option()), flags=flags))
            self.assertIs(observed.status, status)
            self.assertEqual(update_dns_edns_statistics(None, observed), statistics(data=option()))

    def test_pending_and_invalid_types_are_rejected(self):
        observed = terminal()
        for current, observation in (({}, observed), (False, observed), (None, None), (None, observed.message)):
            with self.assertRaises(TypeError):
                update_dns_edns_statistics(current, observation)
        with self.assertRaises(ValueError):
            update_dns_edns_statistics(None, advance().observations[0])

    def test_forged_noncomplete_terminal_message_is_rejected(self):
        observed = terminal()
        for status in (DNSMessageStatus.MALFORMED, DNSMessageStatus.INCOMPLETE, DNSMessageStatus.UNSUPPORTED):
            forged = altered_observation(observed, message=altered_observation(observed.message, status=status))
            with self.assertRaises(ValueError):
                update_dns_edns_statistics(None, forged)

    def test_scalar_constructor_types_and_negatives(self):
        for name in SCALARS:
            for invalid in (True, 1.0, '1', [], {}):
                with self.subTest(name=name, invalid=invalid), self.assertRaises(TypeError):
                    DNSEDNSStatistics(**{name: invalid})
            with self.assertRaises(ValueError):
                DNSEDNSStatistics(**{name: -1})

    def test_distribution_shape_type_and_count_validation(self):
        for name in DISTRIBUTIONS:
            for invalid in ([], (), (0,) * 255, (0,) * 257):
                with self.subTest(name=name), self.assertRaises(TypeError):
                    DNSEDNSStatistics(**{name: invalid})
        for count in (True, 1.0, -1):
            for name in DISTRIBUTIONS:
                bins = bins_at(0, count)
                value = (bins,) + ((0,) * 256,) * 255 if name == 'option_code_counts' else bins
                with self.subTest(name=name, count=count), self.assertRaises((TypeError, ValueError)):
                    DNSEDNSStatistics(**{name: value})
        for name in DISTRIBUTIONS:
            value = counts_at(0, 1) if name == 'option_code_counts' else bins_at(0)
            with self.assertRaises(ValueError):
                DNSEDNSStatistics(**{name: value})

    def test_constructor_extrema_and_aggregate_invariants(self):
        value = statistics(data=option(1) + option(2, b'ab') + option(2, b'abc'))
        for changes in ({'min_option_data_length': None}, {'max_option_data_length': 65509},
                        {'max_options_in_message': 129}, {'udp_payload_size_max': 65536},
                        {'dnssec_ok_count': 2}, {'zero_length_option_count': 4},
                        {'zero_length_option_count': 0}, {'min_options_in_message': 2},
                        {'total_option_data_length_bytes': 2}, {'udp_payload_size_total': 1},
                        {'option_code_counts': counts_at(1, 2)}, {'version_counts': (0,) * 256}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(value, **changes)

    def test_positive_options_must_fit_total_after_observed_maximum(self):
        value = statistics(data=option(1) + option(1, b'a') + option(1, b'0123456789'))
        with self.assertRaises(ValueError):
            replace(value, total_option_data_length_bytes=10)

    def test_constructor_enforces_combined_envelope_byte_bound(self):
        value = statistics(data=option(1, b'x' * 32752) + option(1, b'x' * 32752))
        with self.assertRaises(ValueError):
            replace(value, min_option_data_length=32753, max_option_data_length=32753,
                    total_option_data_length_bytes=65506)

    def test_parser_maximum_option_count_and_length(self):
        value = statistics(data=option(65535) * DNS_MAX_EDNS_OPTIONS)
        self.assertEqual((value.option_count, value.zero_length_option_count), (128, 128))
        value = statistics(data=option(65535, b'x' * DNS_MAX_EDNS_OPTION_DATA_BYTES))
        self.assertEqual(value.max_option_data_length, 65508)
        self.assertEqual(value.mean_option_data_length, Fraction(65508))

    def test_exact_arithmetic_beyond_float_range(self):
        scale = 10 ** 400
        base = statistics(data=option(9, b'ab') + option(9, b'abc'))
        value = replace(base, edns_message_count=scale, option_count=2 * scale,
                        total_option_data_length_bytes=5 * scale, udp_payload_size_total=1232 * scale,
                        version_counts=bins_at(0, scale), extended_rcode_counts=bins_at(0, scale),
                        option_code_counts=counts_at(9, 2 * scale))
        self.assertEqual(value.mean_option_data_length, Fraction(5, 2))
        updated = update_dns_edns_statistics(value, terminal(message(opt(data=option(9, b'a')))))
        self.assertEqual(updated.mean_option_data_length, Fraction(5 * scale + 1, 2 * scale + 1))
        self.assertEqual(updated.edns_message_count, scale + 1)

    def test_frozen_state_and_immutable_distribution_snapshots(self):
        before = statistics(data=option(1))
        after = update_dns_edns_statistics(before, terminal(message(opt(data=option(1)))))
        with self.assertRaises(FrozenInstanceError):
            before.option_count = 9
        with self.assertRaises(FrozenInstanceError):
            del before.option_count
        with self.assertRaises(TypeError):
            before.option_code_counts[0][1] = 9
        self.assertEqual(before.option_count, 1)
        self.assertEqual(after.option_code_counts[0][1], 2)
        self.assertIs(before.option_code_counts[1], after.option_code_counts[1])

    def test_semantic_reducer_does_not_reparse_source_bytes(self):
        observed = terminal(message(opt(data=option(8, b'opaque'))))
        with patch('analysis.dns.analyze_dns_message', side_effect=AssertionError('reparse')):
            with patch.object(DNSEDNSOption, 'data_length', new_callable=PropertyMock, return_value=2):
                value = update_dns_edns_statistics(None, observed)
        self.assertEqual(value.total_option_data_length_bytes, 2)
        with patch.object(DNSEDNS, 'dnssec_ok', new_callable=PropertyMock, return_value=True):
            self.assertEqual(update_dns_edns_statistics(None, observed).dnssec_ok_count, 1)

    def test_semantic_bounds_fail_without_mutating_previous_state(self):
        before = statistics(data=option(1))
        observed = terminal(message(opt(data=option(1))))
        for length in (True, -1, 65509):
            with patch.object(DNSEDNSOption, 'data_length', new_callable=PropertyMock, return_value=length):
                with self.assertRaises((TypeError, ValueError)):
                    update_dns_edns_statistics(before, observed)
        self.assertEqual(before, statistics(data=option(1)))

    def test_source_access_is_limited_to_semantic_fields(self):
        tree = ast.parse(Path('src/analysis/dns_edns_statistics.py').read_text())
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse(attributes & {'data', 'rdata', 'raw_bytes', 'payload', 'labels', 'flags', 'captured_at', 'duration'})
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imports, {'dataclasses', 'fractions', 'typing', 'analysis.dns', 'analysis.dns_correlation'})
