import unittest
from dataclasses import FrozenInstanceError, fields

import analysis
from analysis import (
    LDAP_MAX_MESSAGES, LDAP_MAX_PAYLOAD_BYTES, LDAPMessageObservation,
    LDAPMessageStatus, LDAPOperation, LDAPPayloadObservation, analyze_ldap_payload,
)


def envelope(tag, body):
    size = len(body)
    length = bytes((size,)) if size < 128 else bytes((0x82,)) + size.to_bytes(2, 'big')
    return bytes((tag,)) + length + body


def message(tag=0x42, body=b'', identifier=b'\x01', controls=b''):
    return envelope(0x30, envelope(2, identifier) + envelope(tag, body) + controls)


RESULT = bytes.fromhex('0a010004000400')
OPERATIONS = (
    (0x60, 'BIND_REQUEST', bytes.fromhex('02010304008000')),
    (0x61, 'BIND_RESPONSE', RESULT),
    (0x42, 'UNBIND_REQUEST', b''),
    (0x63, 'SEARCH_REQUEST', bytes.fromhex('04000a01020a01000201000201000101008702636e3000')),
    (0x64, 'SEARCH_RESULT_ENTRY', bytes.fromhex('04003000')),
    (0x65, 'SEARCH_RESULT_DONE', RESULT),
    (0x66, 'MODIFY_REQUEST', envelope(4, b'cn=example') + envelope(0x30, envelope(0x30, bytes.fromhex('0a0100') + envelope(0x30, envelope(4, b'cn') + envelope(0x31, envelope(4, b'x')))))),
    (0x67, 'MODIFY_RESPONSE', RESULT),
    (0x68, 'ADD_REQUEST', bytes.fromhex('04003000')),
    (0x69, 'ADD_RESPONSE', RESULT),
    (0x4A, 'DELETE_REQUEST', b'cn=example'),
    (0x6B, 'DELETE_RESPONSE', RESULT),
    (0x6C, 'MODIFY_DN_REQUEST', bytes.fromhex('04000404636e3d780101ff')),
    (0x6D, 'MODIFY_DN_RESPONSE', RESULT),
    (0x6E, 'COMPARE_REQUEST', bytes.fromhex('040030070402636e040178')),
    (0x6F, 'COMPARE_RESPONSE', RESULT),
    (0x50, 'ABANDON_REQUEST', b'\x02'),
    (0x73, 'SEARCH_RESULT_REFERENCE', envelope(4, b'ldap://example.invalid')),
    (0x77, 'EXTENDED_REQUEST', envelope(0x80, b'1.3.6.1.4.1.1466.20037')),
    (0x78, 'EXTENDED_RESPONSE', RESULT),
    (0x79, 'INTERMEDIATE_RESPONSE', envelope(0x80, b'1.2.3')),
)


class LDAPTests(unittest.TestCase):
    def parse(self, payload):
        return analyze_ldap_payload(payload).messages[0]

    def test_minimal_message_and_operation_tags(self):
        for tag, name, body in OPERATIONS:
            with self.subTest(operation=name):
                raw = message(tag, body)
                observed = self.parse(raw)
                self.assertEqual(observed.status, LDAPMessageStatus.COMPLETE)
                self.assertEqual(observed.message_id, 1)
                self.assertEqual(observed.operation, LDAPOperation[name])
                self.assertEqual(observed.operation_tag, tag)
                self.assertEqual(observed.operation_length, len(body))
                self.assertEqual(observed.message_length, len(raw))
                self.assertTrue(observed.envelope_complete)
                self.assertIs(observed.controls_present, False)
                self.assertIsNone(observed.reason)
                self.assertEqual(analyze_ldap_payload(raw).remaining_bytes, 0)
        self.assertEqual(len(OPERATIONS), len(LDAPOperation))

    def test_operation_body_is_opaque_without_semantic_claims(self):
        observed = self.parse(message(0x60, b'\xff\x80'))
        self.assertEqual(observed.status, LDAPMessageStatus.COMPLETE)
        self.assertEqual(observed.operation, LDAPOperation.BIND_REQUEST)

    def test_unknown_operation_retains_tag_and_length(self):
        observed = self.parse(message(0x7A, b'x'))
        self.assertEqual(observed.status, LDAPMessageStatus.UNSUPPORTED)
        self.assertIsNone(observed.operation)
        self.assertEqual((observed.operation_tag, observed.operation_length), (0x7A, 1))
        self.assertTrue(observed.envelope_complete)

    def test_truncated_tag_length_identifier_and_body_do_not_fabricate_fields(self):
        raw = message(0x60, OPERATIONS[0][2])
        for size in range(len(raw)):
            with self.subTest(size=size):
                observed = self.parse(raw[:size])
                self.assertEqual(observed.status, LDAPMessageStatus.INCOMPLETE)
                self.assertFalse(observed.envelope_complete)
                self.assertEqual(observed.message_length, None if size < 2 else len(raw))
                self.assertEqual(observed.message_id, None if size < 5 else 1)
                self.assertEqual(observed.operation_tag, None if size < 6 else 0x60)
                self.assertEqual(observed.operation_length, None if size < 7 else 7)

    def test_definite_long_lengths_include_legal_nonminimal_ber(self):
        body = message()[2:]
        for encoding in (b'\x81\x05', b'\x82\x00\x05', b'\x84\x00\x00\x00\x05'):
            observed = self.parse(b'\x30' + encoding + body)
            self.assertEqual(observed.status, LDAPMessageStatus.COMPLETE)
        large = message(0x4A, b'x' * 256)
        self.assertEqual(self.parse(large).operation_length, 256)
        for size in (2, 3):
            self.assertEqual(self.parse(large[:size]).status, LDAPMessageStatus.INCOMPLETE)
        self.assertEqual(self.parse(large[:-1]).status, LDAPMessageStatus.INCOMPLETE)

    def test_invalid_and_unsupported_length_encodings(self):
        for raw, status in ((b'\x30\xff', LDAPMessageStatus.MALFORMED),
                            (b'\x30\x80', LDAPMessageStatus.UNSUPPORTED),
                            (b'\x30\x85', LDAPMessageStatus.UNSUPPORTED),
                            (b'\x30\x84\xff\xff\xff\xff', LDAPMessageStatus.UNSUPPORTED)):
            self.assertEqual(self.parse(raw).status, status)
        self.assertEqual(self.parse(b'\x30\x84\xff').status, LDAPMessageStatus.INCOMPLETE)

    def test_nested_bounds_missing_required_fields_and_reserved_lengths(self):
        bodies = (b'', b'\x02', b'\x02\x01', b'\x02\x01\x01',
                  b'\x02\x01\x01\x60', b'\x02\x01\x01\x60\x08',
                  b'\x02\xff', b'\x02\x01\x01\x60\xff',
                  b'\x04\x01\x01\x42\x00')
        for body in bodies:
            with self.subTest(body=body):
                self.assertEqual(self.parse(envelope(0x30, body)).status, LDAPMessageStatus.MALFORMED)
        self.assertEqual(self.parse(b'\x30\x05\x02\x01\x01\x60\x08').status,
                         LDAPMessageStatus.MALFORMED)

    def test_message_identifier_integer_constraints(self):
        for identifier in (b'', b'\xff', b'\x80', b'\x00\x01', b'\x00' * 5):
            observed = self.parse(message(identifier=identifier))
            self.assertEqual(observed.status, LDAPMessageStatus.MALFORMED)
            self.assertIsNone(observed.message_id)
        for identifier, value in ((b'\x00', 0), (b'\x00\x80', 128), (b'\x7f\xff\xff\xff', 2147483647)):
            self.assertEqual(self.parse(message(identifier=identifier)).message_id, value)

    def test_high_tag_number_and_trailing_components_are_unsupported(self):
        for raw in (message(0x7F), message(controls=envelope(0xA1, b'')),
                    message(controls=envelope(0xA0, b'') + b'\x00')):
            self.assertEqual(self.parse(raw).status, LDAPMessageStatus.UNSUPPORTED)

    def test_controls_presence_length_truncation_and_parent_bounds(self):
        controls = envelope(0xA0, envelope(0x30, envelope(4, b'1.2.3')))
        raw = message(controls=controls)
        observed = self.parse(raw)
        self.assertEqual(observed.status, LDAPMessageStatus.COMPLETE)
        self.assertIs(observed.controls_present, True)
        self.assertEqual(observed.controls_length, len(controls) - 2)
        self.assertIsNone(self.parse(raw[:7]).controls_present)
        partial = self.parse(raw[:8])
        self.assertIs(partial.controls_present, True)
        self.assertIsNone(partial.controls_length)
        self.assertEqual(partial.status, LDAPMessageStatus.INCOMPLETE)
        self.assertEqual(self.parse(raw[:-1]).status, LDAPMessageStatus.INCOMPLETE)
        for suffix in (b'\xa0\x7f', b'\xa0\xff'):
            self.assertEqual(self.parse(message(controls=suffix)).status, LDAPMessageStatus.MALFORMED)
        self.assertEqual(self.parse(message(controls=b'\xa0\x80')).status, LDAPMessageStatus.UNSUPPORTED)

    def test_multiple_messages_and_truncated_tail_use_ber_boundaries(self):
        first, second = message(), message(0x61, RESULT)
        observed = analyze_ldap_payload(first + second + b'\x30')
        self.assertEqual([m.offset for m in observed.messages], [0, len(first), len(first + second)])
        self.assertEqual([m.status for m in observed.messages],
                         [LDAPMessageStatus.COMPLETE, LDAPMessageStatus.COMPLETE, LDAPMessageStatus.INCOMPLETE])
        self.assertEqual(observed.remaining_bytes, 1)

    def test_malformed_then_valid_only_recovers_at_known_outer_boundary(self):
        observed = analyze_ldap_payload(b'\x30\x02\x02\x00' + message())
        self.assertEqual([m.status for m in observed.messages],
                         [LDAPMessageStatus.MALFORMED, LDAPMessageStatus.COMPLETE])
        for prefix in (b'\x30\xff', b'\xff', b'\x30\x80'):
            self.assertEqual(len(analyze_ldap_payload(prefix + message()).messages), 1)
        observed = analyze_ldap_payload(message(0x7A) + message())
        self.assertEqual(observed.messages[1].status, LDAPMessageStatus.COMPLETE)

    def test_resource_limits_are_visible_and_do_not_allocate_declared_lengths(self):
        raw = message() * (LDAP_MAX_MESSAGES + 1)
        observed = analyze_ldap_payload(raw)
        self.assertEqual(len(observed.messages), LDAP_MAX_MESSAGES)
        self.assertEqual(observed.remaining_bytes, len(message()))
        self.assertTrue(observed.limit_reached)
        observed = analyze_ldap_payload(b'\x30\x84\xff\xff\xff\xff')
        self.assertEqual(observed.messages[0].message_length, 4294967301)
        self.assertEqual(observed.messages[0].status, LDAPMessageStatus.UNSUPPORTED)
        self.assertTrue(analyze_ldap_payload(b'x' * (LDAP_MAX_PAYLOAD_BYTES + 1)).limit_reached)

    def test_bounded_malformed_corpus_and_repeated_execution(self):
        corpus = [bytes((tag, length)) + b'\x02\x01\x01\x42\x00'
                  for tag in (0x30, 0x3F, 0xFF) for length in range(256)]
        corpus += [message(0x60, bytes(range(256)))[:size] for size in range(270)]
        first = tuple(analyze_ldap_payload(raw) for raw in corpus)
        self.assertEqual(first, tuple(analyze_ldap_payload(raw) for raw in corpus))
        for raw, observed in zip(corpus, first):
            self.assertLessEqual(len(observed.messages), LDAP_MAX_MESSAGES)
            self.assertGreaterEqual(observed.remaining_bytes, 0)
            for item in observed.messages:
                self.assertLessEqual(item.offset, len(raw))
                if item.envelope_complete:
                    self.assertLessEqual(item.offset + item.message_length, len(raw))

    def test_public_contracts_are_immutable_and_exports_resolve(self):
        observed = analyze_ldap_payload(message())
        for value in (observed, observed.messages[0]):
            hash(value)
            for field in fields(value):
                with self.assertRaises(FrozenInstanceError):
                    setattr(value, field.name, None)
        for model in (LDAPMessageObservation, LDAPPayloadObservation):
            with self.assertRaises(TypeError):
                model()
        for value in (None, bytearray(), '', 1):
            with self.assertRaises(TypeError):
                analyze_ldap_payload(value)
        self.assertEqual(len(analysis.__all__), len(set(analysis.__all__)))
        for name in analysis.__all__:
            self.assertIsNotNone(getattr(analysis, name))


if __name__ == '__main__':
    unittest.main()
