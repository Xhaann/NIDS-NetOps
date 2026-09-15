import gc
import random
import unittest
import weakref
from dataclasses import FrozenInstanceError, asdict, fields, replace
from struct import pack
from unittest.mock import patch

import analysis
from analysis import (
    DNSEDNS, DNSEDNSOption, DNSMessageStatus, DNS_MAX_EDNS_OPTIONS,
    DNS_MAX_EDNS_OPTION_BYTES, DNS_MAX_EDNS_OPTION_DATA_BYTES, DNS_MAX_MESSAGE_BYTES,
    analyze_dns_message,
)
from tests.test_dns import header, name, pointer, question, record


def option(code=65001, data=b''):
    return pack('!HH', code, len(data)) + data


def opt(size=1232, extended=0, version=0, flags=0, data=b'', owner=b'\x00'):
    return record(owner, kind=41, cls=size, ttl=(extended << 24) | (version << 16) | flags, data=data)


def message(*records, flags=0, questions=()):
    return header(questions=len(questions), additionals=len(records), flags=flags) + b''.join(questions) + b''.join(records)


def edns(**kwargs):
    return analyze_dns_message(message(opt(**kwargs))).edns


def adversarial_edns_payloads():
    base = message(opt(data=option(1, b'ab') + option(65535, b'\xff\xc0\x00')))
    values = [base[:end] for end in range(len(base) + 1)]
    values.extend(base[:offset] + bytes((byte,)) + base[offset + 1:]
                  for offset in range(len(base)) for byte in (0, 1, 41, 63, 128, 255))
    generator = random.Random(20)
    values.extend(message(opt(data=bytes(generator.randrange(256) for _ in range(generator.randrange(300)))))
                  for _ in range(300))
    return tuple(values)


class DNSEDNSTests(unittest.TestCase):
    def assert_status(self, raw, status, reason=None):
        result = analyze_dns_message(raw)
        self.assertIs(result.status, status, result)
        self.assertEqual(result.parsed_length + result.remaining_bytes, len(raw))
        if reason is not None:
            self.assertEqual(result.reason, reason)
        if status is not DNSMessageStatus.COMPLETE:
            self.assertIsNone(result.edns)
            self.assertTrue(all(item.edns is None for section in (result.answers, result.authorities, result.additionals) for item in section))
        return result

    def test_no_opt_has_no_edns(self):
        self.assertIsNone(analyze_dns_message(header()).edns)
        result = analyze_dns_message(message(record(kind=65000, data=b'opaque')))
        self.assertIsNone(result.edns)
        self.assertIsNone(result.additionals[0].edns)

    def test_one_opt_attaches_to_existing_record(self):
        result = self.assert_status(message(opt()), DNSMessageStatus.COMPLETE)
        self.assertIs(result.edns, result.additionals[0].edns)
        self.assertEqual(result.additionals[0].record_type, 41)
        self.assertEqual(result.header.additional_count, 1)

    def test_root_uses_existing_empty_label_tuple(self):
        root = analyze_dns_message(message(opt())).additionals[0].name
        self.assertEqual(root.labels, ())
        self.assertEqual(root.expanded_length, 1)

    def test_compressed_root_uses_existing_name_decoder(self):
        result = self.assert_status(message(opt(owner=pointer(12)), questions=(question(),)), DNSMessageStatus.COMPLETE)
        self.assertEqual(result.additionals[0].name.pointer_hops, 1)
        self.assertEqual(result.additionals[0].name.labels, ())
        self.assertIsNotNone(result.edns)

    def test_udp_payload_size_preserves_raw_values_without_clamping(self):
        for size in (0, 1, 511, 512, 1232, 4096, 65535):
            self.assertEqual(edns(size=size).udp_payload_size, size)

    def test_extended_rcode_all_eight_bit_values(self):
        for value in range(256):
            self.assertEqual(edns(extended=value).extended_rcode, value)

    def test_header_and_extended_rcode_remain_distinct(self):
        for value in range(16):
            result = analyze_dns_message(message(opt(extended=255), flags=0x8000 | value))
            self.assertEqual(result.header.response_code, value)
            self.assertEqual(result.edns.extended_rcode, 255)

    def test_version_zero(self):
        self.assertEqual(edns().version, 0)

    def test_all_nonzero_versions_are_structurally_supported(self):
        for version in range(1, 256):
            result = self.assert_status(message(opt(version=version, data=option(65535))), DNSMessageStatus.COMPLETE)
            self.assertEqual(result.edns.version, version)

    def test_do_clear(self):
        self.assertIs(edns().dnssec_ok, False)

    def test_do_set(self):
        self.assertIs(edns(flags=0x8000).dnssec_ok, True)

    def test_ad_and_do_are_independent(self):
        for ad in (False, True):
            for do in (False, True):
                result = analyze_dns_message(message(opt(flags=0x8000 if do else 0), flags=0x0020 if ad else 0))
                self.assertIs(result.header.authenticated_data, ad)
                self.assertIs(result.edns.dnssec_ok, do)

    def test_reserved_flags_are_preserved_without_interpretation(self):
        for flag in (1 << bit for bit in range(15)):
            value = edns(flags=flag)
            self.assertEqual(value.flags, flag)
            self.assertIs(value.dnssec_ok, False)
        self.assertEqual(edns(flags=65535).flags, 65535)

    def test_ttl_components_decode_independently(self):
        value = edns(extended=203, version=42, flags=0x9123)
        self.assertEqual((value.extended_rcode, value.version, value.flags, value.dnssec_ok), (203, 42, 0x9123, True))

    def test_zero_options_is_an_empty_tuple(self):
        self.assertEqual(edns().options, ())
        self.assertIs(type(edns().options), tuple)

    def test_one_option(self):
        item, = edns(data=option(10, b'abc')).options
        self.assertEqual((item.code, item.data_length, item.data), (10, 3, b'abc'))

    def test_multiple_options_preserve_wire_order(self):
        codes = (65535, 1, 20, 0)
        value = edns(data=b''.join(option(code, bytes((index,))) for index, code in enumerate(codes)))
        self.assertEqual(tuple(item.code for item in value.options), codes)
        self.assertEqual(tuple(item.data for item in value.options), (b'\x00', b'\x01', b'\x02', b'\x03'))

    def test_duplicate_option_codes_preserve_multiplicity(self):
        value = edns(data=option(7, b'a') + option(7, b'b') + option(7, b'a'))
        self.assertEqual(tuple(item.data for item in value.options), (b'a', b'b', b'a'))

    def test_unknown_option_codes_are_preserved(self):
        for code in (0, 32768, 65000, 65535):
            self.assertEqual(edns(data=option(code)).options[0].code, code)

    def test_zero_length_option_data_is_not_absent_option(self):
        value = edns(data=option())
        self.assertEqual(len(value.options), 1)
        self.assertEqual((value.options[0].data, value.options[0].data_length), (b'', 0))

    def test_binary_option_data_remains_opaque(self):
        data = bytes(range(256)) + b'\xc0\x0c\x40\xff\x00'
        self.assertEqual(edns(data=option(8, data)).options[0].data, data)

    def test_no_individual_option_semantics_are_imposed(self):
        for code in (3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15):
            self.assertEqual(edns(data=option(code, b'\xff')).options[0].data, b'\xff')

    def test_raw_record_fields_remain_exact(self):
        data = option(65000, b'\x00\xff')
        item = analyze_dns_message(message(opt(4096, 1, 2, 0x8001, data))).additionals[0]
        self.assertEqual((item.record_class, item.ttl, item.rdlength, item.rdata), (4096, 0x01028001, 6, data))

    def test_exact_option_count_bound(self):
        data = option() * DNS_MAX_EDNS_OPTIONS
        self.assertEqual(len(edns(data=data).options), 128)

    def test_excess_option_count_is_unsupported_without_prefix_edns(self):
        result = self.assert_status(message(opt(data=option() * 129)), DNSMessageStatus.UNSUPPORTED, 'EDNS option count limit')
        self.assertTrue(result.limit_reached)
        self.assertEqual(result.failure_offset, 23 + 4 * 128)
        self.assertEqual(result.additionals, ())

    def test_exact_option_byte_and_individual_data_bounds(self):
        data = bytes((255,)) * DNS_MAX_EDNS_OPTION_DATA_BYTES
        raw = message(opt(data=option(65535, data)))
        self.assertEqual(len(raw), DNS_MAX_MESSAGE_BYTES)
        value = self.assert_status(raw, DNSMessageStatus.COMPLETE).edns
        self.assertEqual(value.options[0].data_length, 65508)
        self.assertEqual(DNS_MAX_EDNS_OPTION_BYTES, 65512)
        self.assertEqual(value.options[0].data, data)

    def test_combined_options_can_reach_total_byte_bound(self):
        data = option(1) * 127 + option(2, b'a' * (DNS_MAX_EDNS_OPTION_BYTES - 128 * 4))
        value = edns(data=data)
        self.assertEqual(len(value.options), 128)
        self.assertEqual(sum(4 + item.data_length for item in value.options), DNS_MAX_EDNS_OPTION_BYTES)

    def test_excess_option_bytes_hit_existing_message_limit(self):
        result = self.assert_status(message(opt(data=option(1, b'a' * (DNS_MAX_EDNS_OPTION_DATA_BYTES + 1)))), DNSMessageStatus.UNSUPPORTED)
        self.assertTrue(result.limit_reached)
        self.assertIsNone(result.header)

    def test_maximum_wire_rdlength_with_missing_data_is_incomplete(self):
        raw = header(additionals=1) + b'\x00' + pack('!HHIH', 41, 1232, 0, 65535)
        self.assert_status(raw, DNSMessageStatus.INCOMPLETE)

    def test_each_truncated_opt_envelope_is_incomplete(self):
        raw = message(opt(data=option()))
        for end in range(12, 23):
            self.assert_status(raw[:end], DNSMessageStatus.INCOMPLETE)

    def test_truncated_rdata_is_incomplete(self):
        raw = message(opt(data=option(1, b'abcdef')))
        for end in range(23, len(raw)):
            self.assert_status(raw[:end], DNSMessageStatus.INCOMPLETE)

    def test_short_option_header_inside_complete_rdata_is_malformed(self):
        for size in (1, 2, 3):
            result = self.assert_status(message(opt(data=bytes(size))), DNSMessageStatus.MALFORMED, 'EDNS option header exceeds RDATA')
            self.assertEqual(result.failure_offset, 23)
            self.assertFalse(result.limit_reached)

    def test_declared_option_data_exceeding_rdata_is_malformed(self):
        raw = message(opt(data=pack('!HH', 1, 2) + b'x'))
        self.assert_status(raw, DNSMessageStatus.MALFORMED, 'EDNS option data exceeds RDATA')

    def test_maximum_option_length_cannot_escape_message(self):
        self.assert_status(message(opt(data=pack('!HH', 1, 65535))), DNSMessageStatus.MALFORMED)

    def test_next_record_bytes_cannot_satisfy_option_length(self):
        raw = message(opt(data=pack('!HH', 1, 5)), record(data=b'abcde'))
        result = self.assert_status(raw, DNSMessageStatus.MALFORMED)
        self.assertEqual(result.parsed_length, 12)
        self.assertEqual(result.additionals, ())

    def test_zero_rdata_does_not_consume_following_record(self):
        result = self.assert_status(message(opt(), record(kind=65000, data=option())), DNSMessageStatus.COMPLETE)
        self.assertEqual(result.edns.options, ())
        self.assertEqual(result.additionals[1].rdata, option())
        self.assertIsNone(result.additionals[1].edns)

    def test_opt_may_follow_and_precede_ordinary_additionals(self):
        result = self.assert_status(message(record(data=b'\xff'), opt(data=option(1, b'x')), record(data=b'\x00')), DNSMessageStatus.COMPLETE)
        self.assertEqual(result.edns.options[0].data, b'x')
        self.assertIs(result.edns, result.additionals[1].edns)

    def test_valid_option_prefix_is_not_published_on_later_bad_option(self):
        self.assert_status(message(opt(data=option(1, b'valid') + b'\xff')), DNSMessageStatus.MALFORMED)

    def test_multiple_opts_are_malformed_and_no_edns_is_published(self):
        result = self.assert_status(message(opt(), opt()), DNSMessageStatus.MALFORMED, 'multiple OPT records')
        self.assertEqual(len(result.additionals), 1)
        self.assertEqual(result.additionals[0].record_type, 41)
        self.assertEqual(result.failure_offset, 23)

    def test_nonroot_owner_is_malformed_without_normalization(self):
        self.assert_status(message(opt(owner=name(b'example'))), DNSMessageStatus.MALFORMED, 'OPT requires root owner')

    def test_compressed_nonroot_owner_is_malformed(self):
        self.assert_status(message(opt(owner=pointer(12)), questions=(question(name(b'a')),)), DNSMessageStatus.MALFORMED)

    def test_opt_in_answer_or_authority_is_malformed(self):
        for section in ('answers', 'authorities'):
            self.assert_status(header(**{section: 1}) + opt(), DNSMessageStatus.MALFORMED, 'OPT requires additional section')

    def test_question_type_41_does_not_create_edns(self):
        result = self.assert_status(header(1) + question(kind=41), DNSMessageStatus.COMPLETE)
        self.assertIsNone(result.edns)

    def test_later_malformed_record_suppresses_semantic_edns(self):
        self.assert_status(header(additionals=2) + opt() + b'\x80', DNSMessageStatus.MALFORMED)

    def test_later_incomplete_record_suppresses_semantic_edns(self):
        self.assert_status(header(additionals=2) + opt(), DNSMessageStatus.INCOMPLETE)

    def test_later_unsupported_record_suppresses_semantic_edns(self):
        self.assert_status(header(additionals=2) + opt() + b'\x40', DNSMessageStatus.UNSUPPORTED)

    def test_trailing_bytes_suppress_semantic_edns(self):
        self.assert_status(message(opt()) + b'\x00', DNSMessageStatus.MALFORMED)

    def test_factory_only_construction_rejects_invalid_and_unvalidated_values(self):
        for model in (DNSEDNS, DNSEDNSOption):
            with self.assertRaises(TypeError):
                model()
            for invalid in (True, -1, 65536, 1.0, '1', None, bytearray(), memoryview(b''), object()):
                with self.assertRaises(TypeError):
                    model(invalid)
                for member in fields(model):
                    with self.assertRaises(TypeError):
                        model(**{member.name: invalid})
        with self.assertRaises(TypeError):
            DNSEDNSOption(code=1, data=b'valid')

    def test_parsed_field_types_are_exact(self):
        value = edns(size=65535, extended=255, version=255, flags=65535, data=option(65535, b'x'))
        self.assertTrue(all(type(getattr(value, key)) is int for key in ('udp_payload_size', 'extended_rcode', 'version', 'flags')))
        self.assertIs(type(value.dnssec_ok), bool)
        self.assertIs(type(value.options), tuple)
        self.assertIs(type(value.options[0].code), int)
        self.assertIs(type(value.options[0].data_length), int)
        self.assertIs(type(value.options[0].data), bytes)

    def test_frozen_objects_and_option_collections(self):
        value = edns(data=option(1, b'abc'))
        for item in (value, value.options[0]):
            for member in fields(item):
                with self.assertRaises(FrozenInstanceError):
                    setattr(item, member.name, None)
                with self.assertRaises(FrozenInstanceError):
                    delattr(item, member.name)
            with self.assertRaises(TypeError):
                replace(item)
        with self.assertRaises(TypeError):
            value.options[0] = None
        with self.assertRaises(TypeError):
            value.options[0].data[0] = 0

    def test_exported_copy_mutation_cannot_change_source(self):
        value = edns(data=option(1, b'abc'))
        exported = asdict(value)
        exported['options'][0]['code'] = 2
        self.assertEqual(value.options[0].code, 1)

    def test_repeated_parsing_equality_and_hash(self):
        raw = message(opt(data=option(1, b'abc')))
        first = analyze_dns_message(raw)
        for _ in range(20):
            self.assertEqual(first, analyze_dns_message(raw))
            self.assertEqual(hash(first), hash(analyze_dns_message(raw)))

    def test_semantic_access_never_reparses(self):
        result = analyze_dns_message(message(opt(flags=0x8000, data=option(1, b'a'))))
        with patch('analysis.dns.unpack_from', side_effect=AssertionError('reparse')):
            self.assertIs(result.edns, result.additionals[0].edns)
            self.assertTrue(result.edns.dnssec_ok)
            self.assertEqual(result.edns.options[0].data_length, 1)

    def test_option_bytes_never_enter_name_decoder(self):
        import analysis.dns as dns
        with patch('analysis.dns._name', wraps=dns._name) as decoder:
            result = analyze_dns_message(message(opt(data=option(1, b'\xc0\x0c\x40'))))
        self.assertEqual(decoder.call_count, 1)
        self.assertEqual(result.edns.options[0].data, b'\xc0\x0c\x40')

    def test_option_name_compression_targets_stay_opaque(self):
        raw = header(additionals=2) + opt(data=option(1, b'\x00')) + record(owner=pointer(27))
        self.assert_status(raw, DNSMessageStatus.UNSUPPORTED, 'compression target in opaque RDATA')

    def test_option_payload_is_absent_from_repr_and_failure_reasons(self):
        data = b'private-option-payload'
        result = analyze_dns_message(message(opt(data=option(1, data))))
        self.assertNotIn(data.decode(), repr(result))
        failure = analyze_dns_message(message(opt(data=option(1, data) + b'\xff')))
        self.assertNotIn(data.decode(), failure.reason)

    def test_retained_edns_releases_record_message_and_header(self):
        source = analyze_dns_message(message(opt(data=option(1, b'abc'))))
        references = [weakref.ref(item) for item in (source, source.header, source.additionals[0], source.additionals[0].name)]
        value = source.edns
        del source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(value.options[0].data, b'abc')

    def test_retained_option_releases_edns_owner(self):
        value = edns(data=option(1, b'abc'))
        reference = weakref.ref(value)
        item = value.options[0]
        del value
        gc.collect()
        self.assertIsNone(reference())
        self.assertEqual(item.data, b'abc')

    def test_infrastructure_failure_during_options_propagates(self):
        import analysis.dns as dns
        build = dns._observation
        def fail(model, **values):
            if model is DNSEDNSOption:
                raise MemoryError('option allocation')
            return build(model, **values)
        with patch('analysis.dns._observation', side_effect=fail):
            with self.assertRaises(MemoryError):
                analyze_dns_message(message(opt(data=option())))

    def test_deterministic_adversarial_inputs_are_bounded(self):
        for raw in adversarial_edns_payloads():
            value = analyze_dns_message(raw)
            self.assertEqual(value, analyze_dns_message(raw))
            self.assertEqual(value.parsed_length + value.remaining_bytes, len(raw))
            if value.edns is not None:
                self.assertIs(value.status, DNSMessageStatus.COMPLETE)
                self.assertLessEqual(len(value.edns.options), DNS_MAX_EDNS_OPTIONS)
                self.assertLessEqual(sum(4 + item.data_length for item in value.edns.options), DNS_MAX_EDNS_OPTION_BYTES)
            else:
                self.assertTrue(all(item.edns is None for item in value.additionals))

    def test_public_exports(self):
        for value in (DNSEDNS, DNSEDNSOption):
            self.assertIs(getattr(analysis, value.__name__), value)
            self.assertIn(value.__name__, analysis.__all__)
        for key in ('DNS_MAX_EDNS_OPTIONS', 'DNS_MAX_EDNS_OPTION_BYTES', 'DNS_MAX_EDNS_OPTION_DATA_BYTES'):
            self.assertIn(key, analysis.__all__)
