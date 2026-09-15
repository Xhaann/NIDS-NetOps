import random
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from struct import pack
from unittest.mock import patch

import analysis
from analysis import (
    DNSHeader, DNSName, DNSQuestion, DNSResourceRecord, DNSMessageObservation,
    DNSMessageStatus, DNS_MAX_ENTRIES, DNS_MAX_MESSAGE_BYTES, DNS_MAX_POINTER_HOPS,
    analyze_dns_message,
)


def header(questions=0, answers=0, authorities=0, additionals=0, flags=0x0100, identifier=123):
    return pack('!6H', identifier, flags, questions, answers, authorities, additionals)


def name(*labels):
    return b''.join(bytes((len(label),)) + label for label in labels) + b'\x00'


def question(owner=b'\x00', kind=1, cls=1):
    return owner + pack('!HH', kind, cls)


def record(owner=b'\x00', kind=1, cls=1, ttl=60, data=b''):
    return owner + pack('!HHIH', kind, cls, ttl, len(data)) + data


def pointer(offset):
    return pack('!H', 0xC000 | offset)


def chain(hops):
    body = question()
    previous = 12
    for _ in range(hops):
        offset = 12 + len(body)
        body += question(pointer(previous))
        previous = offset
    return header(questions=hops + 1) + body


def adversarial_payloads():
    base = header(questions=1, answers=1) + question(name(b'example', b'org')) + record(pointer(12), data=b'ABCD')
    cases = [base[:end] for end in range(len(base) + 1)]
    cases.extend(base[:offset] + bytes((value,)) + base[offset + 1:]
                 for offset in range(len(base)) for value in (0, 1, 63, 64, 128, 192, 255))
    cases.extend(header(questions=1) + bytes((value,)) + suffix
                 for value in range(256) for suffix in (b'', b'\x00', b'\xff' * 64))
    generator = random.Random(53)
    cases.extend(bytes(generator.randrange(256) for _ in range(generator.randrange(257))) for _ in range(1024))
    return tuple(cases)


class DNSMessageTests(unittest.TestCase):
    def parsed(self, payload, status=DNSMessageStatus.COMPLETE):
        result = analyze_dns_message(payload)
        self.assertIs(result.status, status, result)
        self.assertEqual(result.parsed_length + result.remaining_bytes, len(payload))
        self.assertLessEqual(result.parsed_length, len(payload))
        if status is DNSMessageStatus.COMPLETE:
            self.assertIsNone(result.reason)
            self.assertIsNone(result.failure_offset)
            self.assertEqual(result.remaining_bytes, 0)
        return result

    def test_fixed_header(self):
        result = self.parsed(header(identifier=65535, flags=65535))
        self.assertEqual((result.header.transaction_id, result.header.flags), (65535, 65535))
        self.assertEqual(result.parsed_length, 12)

    def test_request_response_direction(self):
        self.assertFalse(self.parsed(header()).header.is_response)
        self.assertTrue(self.parsed(header(flags=0x8000)).header.is_response)

    def test_opcode_extraction_preserves_unknown_values(self):
        for opcode in range(16):
            self.assertEqual(self.parsed(header(flags=opcode << 11)).header.opcode, opcode)

    def test_response_code_is_header_low_bits(self):
        for code in range(16):
            self.assertEqual(self.parsed(header(flags=0xFFF0 | code)).header.response_code, code)

    def test_tc_flag_does_not_mean_structural_incompleteness(self):
        self.assertTrue(self.parsed(header(flags=0x8200)).header.truncated)
        self.assertFalse(self.parsed(header()).header.truncated)

    def test_declared_counts_and_section_order(self):
        raw = header(2, 2, 1, 1) + question(kind=1) + question(kind=28)
        raw += record(ttl=1) + record(ttl=2) + record(ttl=3) + record(ttl=4)
        result = self.parsed(raw)
        self.assertEqual((result.header.question_count, result.header.answer_count,
                          result.header.authority_count, result.header.additional_count), (2, 2, 1, 1))
        self.assertEqual([entry.ttl for group in (result.answers, result.authorities, result.additionals)
                          for entry in group], [1, 2, 3, 4])

    def test_root_question(self):
        item = self.parsed(header(1) + question()).questions[0]
        self.assertEqual(item.name.labels, ())
        self.assertEqual((item.name.offset, item.name.encoded_length, item.name.expanded_length), (12, 1, 1))

    def test_multilabel_name_preserves_case_and_binary_octets(self):
        labels = (b'WWW', b'ExAmPlE', b'\xff\x00')
        self.assertEqual(self.parsed(header(1) + question(name(*labels))).questions[0].name.labels, labels)

    def test_maximum_label(self):
        self.assertEqual(self.parsed(header(1) + question(name(b'a' * 63))).questions[0].name.labels, (b'a' * 63,))

    def test_extended_label_is_unsupported(self):
        self.parsed(header(1) + b'\x40', DNSMessageStatus.UNSUPPORTED)

    def test_reserved_label_is_malformed(self):
        self.parsed(header(1) + b'\x80', DNSMessageStatus.MALFORMED)

    def test_truncated_label(self):
        self.parsed(header(1) + b'\x03ab', DNSMessageStatus.INCOMPLETE)

    def test_missing_name_terminator(self):
        self.parsed(header(1) + b'\x01a', DNSMessageStatus.INCOMPLETE)

    def test_maximum_expanded_name(self):
        item = self.parsed(header(1) + question(name(*([b'a' * 63] * 3 + [b'b' * 61])))).questions[0]
        self.assertEqual(item.name.expanded_length, 255)

    def test_oversized_expanded_name(self):
        self.parsed(header(1) + question(name(*([b'a' * 63] * 3 + [b'b' * 62]))), DNSMessageStatus.MALFORMED)

    def test_maximum_label_count(self):
        self.assertEqual(len(self.parsed(header(1) + question(name(*([b'a'] * 127)))).questions[0].name.labels), 127)

    def test_compressed_owner(self):
        result = self.parsed(header(1, 1) + question(name(b'example')) + record(pointer(12)))
        self.assertEqual(result.answers[0].name.labels, result.questions[0].name.labels)
        self.assertEqual((result.answers[0].name.encoded_length, result.answers[0].name.pointer_hops), (2, 1))

    def test_mixed_literal_and_pointer(self):
        result = self.parsed(header(2) + question(name(b'org')) + question(b'\x03www' + pointer(12)))
        self.assertEqual(result.questions[1].name.labels, (b'www', b'org'))
        self.assertEqual(result.questions[1].name.encoded_length, 6)

    def test_pointer_to_suffix(self):
        result = self.parsed(header(2) + question(name(b'www', b'org')) + question(pointer(16)))
        self.assertEqual(result.questions[1].name.labels, (b'org',))

    def test_pointer_to_root(self):
        self.assertEqual(self.parsed(header(2) + question() + question(pointer(12))).questions[1].name.labels, ())

    def test_pointer_to_pointer(self):
        self.assertEqual(self.parsed(chain(2)).questions[-1].name.pointer_hops, 2)

    def test_pointer_at_message_boundary(self):
        self.parsed(header(1) + question(pointer(18)), DNSMessageStatus.MALFORMED)

    def test_pointer_outside_message(self):
        self.parsed(header(1) + question(pointer(16383)), DNSMessageStatus.MALFORMED)

    def test_pointer_into_header(self):
        self.parsed(header(1) + question(pointer(0)), DNSMessageStatus.MALFORMED)

    def test_pointer_into_label_body(self):
        self.parsed(header(2) + question(name(b'\x00a')) + question(pointer(13)), DNSMessageStatus.MALFORMED)

    def test_pointer_into_question_metadata(self):
        self.parsed(header(2) + question() + question(pointer(13)), DNSMessageStatus.MALFORMED)

    def test_pointer_into_record_metadata(self):
        self.parsed(header(answers=2) + record() + record(pointer(13)), DNSMessageStatus.MALFORMED)

    def test_pointer_into_opaque_rdata_is_not_guessed(self):
        result = self.parsed(header(answers=2) + record(kind=5, data=name(b'alias')) + record(pointer(23)),
                             DNSMessageStatus.UNSUPPORTED)
        self.assertEqual(len(result.answers), 1)
        self.assertFalse(result.limit_reached)

    def test_self_pointer_loop(self):
        self.parsed(header(1) + question(pointer(12)), DNSMessageStatus.MALFORMED)

    def test_backward_pointer_loop_through_literal(self):
        self.parsed(header(1) + question(b'\x01a' + pointer(12)), DNSMessageStatus.MALFORMED)

    def test_forward_pointer_and_cycle(self):
        self.parsed(header(1) + pointer(14) + pointer(12), DNSMessageStatus.MALFORMED)

    def test_truncated_pointer(self):
        self.parsed(header(1) + b'\xc0', DNSMessageStatus.INCOMPLETE)

    def test_exact_pointer_hop_limit(self):
        self.assertEqual(self.parsed(chain(DNS_MAX_POINTER_HOPS)).questions[-1].name.pointer_hops, DNS_MAX_POINTER_HOPS)

    def test_excessive_pointer_traversal(self):
        result = self.parsed(chain(DNS_MAX_POINTER_HOPS + 1), DNSMessageStatus.UNSUPPORTED)
        self.assertTrue(result.limit_reached)
        self.assertEqual(len(result.questions), DNS_MAX_POINTER_HOPS + 1)

    def test_expanded_bound_includes_compressed_suffix(self):
        suffix = name(*([b'a' * 63] * 3 + [b'b' * 61]))
        self.parsed(header(2) + question(suffix) + question(b'\x01x' + pointer(12)), DNSMessageStatus.MALFORMED)

    def test_question_type_and_class_are_unsigned_raw_values(self):
        item = self.parsed(header(1) + question(kind=65535, cls=65535)).questions[0]
        self.assertEqual((item.question_type, item.question_class), (65535, 65535))

    def test_duplicate_questions_preserved(self):
        result = self.parsed(header(2) + question() * 2)
        self.assertEqual(len(result.questions), 2)
        self.assertEqual([item.name.offset for item in result.questions], [12, 17])

    def test_record_envelope_unsigned_values(self):
        item = self.parsed(header(answers=1) + record(kind=65535, cls=65535, ttl=4294967295, data=b'xyz')).answers[0]
        self.assertEqual((item.record_type, item.record_class, item.ttl, item.rdlength, item.rdata),
                         (65535, 65535, 4294967295, 3, b'xyz'))

    def test_unknown_record_preserves_next_boundary(self):
        result = self.parsed(header(answers=2) + record(kind=65000, data=b'\xff\xc0\x00') + record(ttl=99))
        self.assertEqual(result.answers[0].rdata, b'\xff\xc0\x00')
        self.assertEqual(result.answers[1].ttl, 99)

    def test_zero_length_rdata_is_structural_only(self):
        self.assertEqual(self.parsed(header(answers=1) + record(kind=1)).answers[0].rdata, b'')

    def test_edns_envelope_preserves_raw_fields(self):
        data = b'\xff\xff\x00\x01\xff'
        item = self.parsed(header(additionals=1) + record(kind=41, cls=4096, ttl=0x01008000, data=data)).additionals[0]
        self.assertEqual((item.record_type, item.record_class, item.ttl, item.rdata), (41, 4096, 0x01008000, data))

    def test_empty_payload(self):
        result = self.parsed(b'', DNSMessageStatus.INCOMPLETE)
        self.assertIsNone(result.header)
        self.assertEqual(result.failure_offset, 0)

    def test_every_short_header(self):
        for length in range(1, 12):
            self.assertIsNone(self.parsed(header()[:length], DNSMessageStatus.INCOMPLETE).header)

    def test_missing_declared_question(self):
        result = self.parsed(header(65535), DNSMessageStatus.INCOMPLETE)
        self.assertEqual(result.questions, ())
        self.assertFalse(result.limit_reached)

    def test_question_envelope_truncations(self):
        for length in range(4):
            self.parsed(header(1) + b'\x00' + bytes(length), DNSMessageStatus.INCOMPLETE)

    def test_each_record_section_envelope_truncations(self):
        for section in ('answers', 'authorities', 'additionals'):
            for length in range(10):
                result = self.parsed(header(**{section: 1}) + b'\x00' + bytes(length), DNSMessageStatus.INCOMPLETE)
                self.assertEqual(getattr(result, section), ())

    def test_rdlength_exceeds_available_bytes(self):
        self.parsed(header(answers=1) + record(data=b'abcd')[:-1], DNSMessageStatus.INCOMPLETE)

    def test_maximum_declared_rdlength_missing(self):
        self.parsed(header(answers=1) + b'\x00' + pack('!HHIH', 1, 1, 0, 65535), DNSMessageStatus.INCOMPLETE)

    def test_first_failure_stops_later_sections(self):
        result = self.parsed(header(1, 1, 1, 1) + question() + b'\x80' * 33, DNSMessageStatus.MALFORMED)
        self.assertEqual(result.parsed_length, 17)
        self.assertEqual(len(result.questions), 1)
        self.assertEqual((result.answers, result.authorities, result.additionals), ((), (), ()))

    def test_complete_prefix_excludes_partial_record(self):
        result = self.parsed(header(answers=2) + record(data=b'first') + record(data=b'second')[:-1], DNSMessageStatus.INCOMPLETE)
        self.assertEqual([item.rdata for item in result.answers], [b'first'])
        self.assertEqual(result.parsed_length, 28)

    def test_trailing_bytes_are_not_another_message(self):
        result = self.parsed(header() * 2, DNSMessageStatus.MALFORMED)
        self.assertEqual((result.parsed_length, result.remaining_bytes), (12, 12))

    def test_exact_entry_limit(self):
        self.assertEqual(len(self.parsed(header(DNS_MAX_ENTRIES) + question() * DNS_MAX_ENTRIES).questions), DNS_MAX_ENTRIES)

    def test_entry_limit_is_shared_across_sections(self):
        result = self.parsed(header(64, 64, 1) + question() * 64 + record() * 65, DNSMessageStatus.UNSUPPORTED)
        self.assertTrue(result.limit_reached)
        self.assertEqual((len(result.questions), len(result.answers), len(result.authorities)), (64, 64, 0))

    def test_exact_message_size_and_rdata_retention_bound(self):
        raw = header(answers=1) + record(data=b'x' * (DNS_MAX_MESSAGE_BYTES - 23))
        result = self.parsed(raw)
        self.assertEqual(len(result.answers[0].rdata), DNS_MAX_MESSAGE_BYTES - 23)

    def test_oversized_message_is_not_clipped(self):
        result = self.parsed(bytes(DNS_MAX_MESSAGE_BYTES + 1), DNSMessageStatus.UNSUPPORTED)
        self.assertTrue(result.limit_reached)
        self.assertEqual(result.parsed_length, 0)
        self.assertIsNone(result.header)

    def test_invalid_api_input(self):
        class BytesSubclass(bytes):
            pass
        for value in (None, '', bytearray(), memoryview(b''), 12, BytesSubclass()):
            with self.assertRaises(TypeError):
                analyze_dns_message(value)

    def test_factory_only_immutable_contract(self):
        result = self.parsed(header(1, 1) + question() + record())
        for item in (result, result.header, result.questions[0], result.questions[0].name, result.answers[0]):
            with self.assertRaises(TypeError):
                type(item)()
            with self.assertRaises(TypeError):
                replace(item)
            for member in fields(item):
                with self.assertRaises(FrozenInstanceError):
                    setattr(item, member.name, None)
        self.assertIsInstance(hash(result), int)

    def test_sensitive_bytes_absent_from_repr_and_reasons(self):
        result = self.parsed(header(1, 1) + question(name(b'private-name')) + record(data=b'private-data'))
        self.assertNotIn('private-name', repr(result))
        self.assertNotIn('private-data', repr(result))

    def test_parser_preserves_input_and_repeated_equality(self):
        raw = header(1) + question(name(b'EXAMPLE'))
        before = bytes(bytearray(raw))
        first = self.parsed(raw)
        self.assertEqual(first, self.parsed(raw))
        self.assertEqual(raw, before)

    def test_infrastructure_failure_propagates(self):
        failure = MemoryError('allocation')
        with patch('analysis.dns._observation', side_effect=failure):
            with self.assertRaises(MemoryError) as caught:
                analyze_dns_message(header())
        self.assertIs(caught.exception, failure)

    def test_parser_has_only_standard_library_dependencies(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path(analysis.__file__).with_name('dns.py').read_text())
        imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertEqual(imports, ['dataclasses', 'enum', 'struct', 'typing'])
        self.assertFalse(any(isinstance(node, ast.Import) for node in ast.walk(tree)))
        with patch('socket.getaddrinfo', side_effect=AssertionError('external resolution')):
            self.parsed(header(1) + question(name(b'example')))

    def test_public_exports(self):
        for model in (DNSHeader, DNSName, DNSQuestion, DNSResourceRecord, DNSMessageObservation, DNSMessageStatus):
            self.assertIn(model.__name__, analysis.__all__)
            self.assertIs(getattr(analysis, model.__name__), model)
        self.assertEqual(analyze_dns_message.__annotations__, {'payload': bytes, 'return': DNSMessageObservation})

    def test_bounded_adversarial_corpus(self):
        for raw in adversarial_payloads():
            result = analyze_dns_message(raw)
            self.assertEqual(result, analyze_dns_message(raw))
            self.assertEqual(result.parsed_length + result.remaining_bytes, len(raw))
            self.assertLessEqual(sum(len(section) for section in (result.questions, result.answers,
                                                                  result.authorities, result.additionals)), DNS_MAX_ENTRIES)
            for section in (result.questions, result.answers, result.authorities, result.additionals):
                for entry in section:
                    self.assertLessEqual(entry.name.expanded_length, 255)
                    self.assertLessEqual(entry.name.pointer_hops, DNS_MAX_POINTER_HOPS)
                    self.assertLessEqual(entry.name.offset + entry.name.encoded_length, len(raw))
