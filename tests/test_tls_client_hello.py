import ast
import gc
import unittest
import weakref
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

import analysis
import analysis.tls_client_hello as hello_module
from analysis import (
    TLS_CLIENT_HELLO_MAX_BODY_BYTES, TLS_CLIENT_HELLO_MAX_EXTENSIONS,
    TLSClientHello, TLSClientHelloExtension, TLSClientHelloObservation, TLSClientHelloStatus,
    TLSHandshakeStatus, analyze_tls_client_hello,
)
from tests.test_tls_handshake_framing import advance, fragments, message
from tests.test_tls_handshake_statistics import altered, observed


def extension(kind, data=b''):
    return kind.to_bytes(2, 'big') + len(data).to_bytes(2, 'big') + data


def identifiers(*values):
    data = b''.join(value.to_bytes(2, 'big') for value in values)
    return len(data).to_bytes(2, 'big') + data


def alpn(*names):
    data = b''.join(bytes((len(name),)) + name for name in names)
    return len(data).to_bytes(2, 'big') + data


def body(version=b'\x03\x03', random=bytes(range(32)), session=b'', suites=(0x1301,), compression=(0,), extensions=None):
    ciphers = b''.join(value.to_bytes(2, 'big') for value in suites)
    data = (version + random + bytes((len(session),)) + session + len(ciphers).to_bytes(2, 'big') + ciphers
            + bytes((len(compression),)) + bytes(compression))
    if extensions is not None:
        block = b''.join(extensions)
        data += len(block).to_bytes(2, 'big') + block
    return data


def selected_body():
    return body(suites=(65535, 0, 0x1301, 65535), compression=(0, 255, 0), extensions=(
        extension(10, identifiers(65535, 0, 29)), extension(13, identifiers(0x0804, 0, 65535)),
        extension(16, alpn(b'h2', b'\x00\xff', b'H2')), extension(65000, b'\x00opaque\xff'),
        extension(10, identifiers(23)), extension(13, identifiers(0x0403)), extension(16, alpn(b'other')),
    ))


def source(data, kind=1):
    raw = message(data, kind)
    state, values = fragments(tuple(raw[i:i + 16000] for i in range(0, len(raw), 16000)))
    return values[0]


def parse(data):
    return analyze_tls_client_hello(source(data))


class TLSClientHelloTests(unittest.TestCase):
    def assert_status(self, data, status):
        value = parse(data)
        self.assertIs(value.status, status)
        if status is not TLSClientHelloStatus.COMPLETE:
            self.assertIsNone(value.client_hello)
            self.assertIsNotNone(value.reason)
        return value

    def test_minimal_client_hello_and_absent_extensions(self):
        value = self.assert_status(body(), TLSClientHelloStatus.COMPLETE).client_hello
        self.assertEqual((value.legacy_version, value.random, value.session_id), (b'\x03\x03', bytes(range(32)), b''))
        self.assertEqual((value.cipher_suites, value.compression_methods, value.extensions), ((0x1301,), (0,), ()))
        self.assertFalse(value.extensions_present)

    def test_version_and_random_remain_exact_opaque_bytes(self):
        random = b'\x00\xff' * 16
        value = parse(body(version=b'\xff\x00', random=random)).client_hello
        self.assertEqual(value.legacy_version, b'\xff\x00')
        self.assertEqual(value.random, random)
        self.assertIs(type(value.random), bytes)

    def test_empty_and_maximum_wire_session_id(self):
        for session in (b'', bytes(range(255))):
            value = self.assert_status(body(session=session), TLSClientHelloStatus.COMPLETE).client_hello
            self.assertEqual(value.session_id, session)
        self.assertEqual(hello_module.TLS_CLIENT_HELLO_MAX_SESSION_ID_BYTES, 255)

    def test_every_required_prefix_truncation_is_incomplete(self):
        data = body(session=b'session', suites=(1, 2), compression=(0, 255))
        for cut in range(len(data)):
            with self.subTest(cut=cut):
                self.assert_status(data[:cut], TLSClientHelloStatus.INCOMPLETE)

    def test_cipher_suite_empty_and_odd_lengths_are_malformed(self):
        self.assert_status(body(suites=()), TLSClientHelloStatus.MALFORMED)
        for length in (1, 3, 65535):
            self.assert_status(body()[:35] + length.to_bytes(2, 'big'), TLSClientHelloStatus.MALFORMED)

    def test_cipher_order_duplicates_and_maximum_even_vector(self):
        for suites in ((1,), (65535, 0, 1, 65535), (0x1301,) * 32767):
            value = self.assert_status(body(suites=suites), TLSClientHelloStatus.COMPLETE).client_hello
            self.assertEqual(value.cipher_suites, suites)

    def test_compression_empty_is_malformed_and_maximum_is_preserved(self):
        self.assert_status(body(compression=()), TLSClientHelloStatus.MALFORMED)
        compression = tuple(reversed(range(255)))
        value = parse(body(compression=compression)).client_hello
        self.assertEqual(value.compression_methods, compression)

    def test_empty_extensions_are_distinct_from_absent_extensions(self):
        left, right = parse(body()).client_hello, parse(body(extensions=())).client_hello
        self.assertEqual(left.extensions, right.extensions)
        self.assertFalse(left.extensions_present)
        self.assertTrue(right.extensions_present)

    def test_single_unknown_extension_is_opaque(self):
        value = parse(body(extensions=(extension(65535, b'\x00\xffopaque'),))).client_hello.extensions[0]
        self.assertEqual((value.extension_type, value.data), (65535, b'\x00\xffopaque'))
        self.assertEqual((value.supported_groups, value.signature_algorithms, value.alpn_protocols), (None, None, None))

    def test_all_unselected_types_remain_opaque_without_registry(self):
        for kind in (0, 1, 11, 21, 43, 51, 257, 65000, 65535):
            value = self.assert_status(body(extensions=(extension(kind, b'\xff'),)), TLSClientHelloStatus.COMPLETE)
            self.assertEqual(value.client_hello.extensions[0].data, b'\xff')

    def test_order_and_duplicate_selected_occurrences_are_preserved(self):
        values = parse(selected_body()).client_hello.extensions
        self.assertEqual(tuple(value.extension_type for value in values), (10, 13, 16, 65000, 10, 13, 16))
        self.assertEqual((values[0].supported_groups, values[4].supported_groups), ((65535, 0, 29), (23,)))
        self.assertEqual((values[1].signature_algorithms, values[5].signature_algorithms), ((0x0804, 0, 65535), (0x0403,)))
        self.assertEqual((values[2].alpn_protocols, values[6].alpn_protocols), ((b'h2', b'\x00\xff', b'H2'), (b'other',)))
        self.assertEqual(values[0].data, identifiers(65535, 0, 29))

    def test_duplicate_opaque_extensions_are_not_deduplicated(self):
        values = parse(body(extensions=(extension(65000, b'a'), extension(65000, b'b')))).client_hello.extensions
        self.assertEqual(tuple(value.data for value in values), (b'a', b'b'))

    def test_incomplete_outer_extension_length_and_block(self):
        data = body(extensions=(extension(65000, b'abcd'),))
        for cut in range(len(body()) + 1, len(data)):
            self.assert_status(data[:cut], TLSClientHelloStatus.INCOMPLETE)

    def test_extension_header_and_data_cannot_cross_complete_block(self):
        for block in (b'\x01', b'\x01\x00\x00', b'\x01\x00\x00\x02x'):
            self.assert_status(body(extensions=(block,)), TLSClientHelloStatus.MALFORMED)

    def test_trailing_bytes_outside_declared_block_are_rejected(self):
        for data in (body(extensions=()) + b'x', body(extensions=(extension(0),)) + b'\x00\x00'):
            self.assert_status(data, TLSClientHelloStatus.MALFORMED)

    def test_selected_identifier_vectors_preserve_empty_and_ordered_values(self):
        for kind, name in ((10, 'supported_groups'), (13, 'signature_algorithms')):
            for values in ((), (0, 65535, 0, 29)):
                extension_value = parse(body(extensions=(extension(kind, identifiers(*values)),))).client_hello.extensions[0]
                self.assertEqual(getattr(extension_value, name), values)

    def test_selected_identifier_odd_lengths_are_malformed(self):
        for kind in (10, 13):
            self.assert_status(body(extensions=(extension(kind, b'\x00\x03abc'),)), TLSClientHelloStatus.MALFORMED)

    def test_selected_vector_length_must_fill_extension_exactly(self):
        for kind in (10, 13, 16):
            for data in (b'', b'\x00', b'\x00\x04ab', b'\x00\x00ab', b'\xff\xff'):
                with self.subTest(kind=kind, data=data):
                    self.assert_status(body(extensions=(extension(kind, data),)), TLSClientHelloStatus.MALFORMED)

    def test_alpn_exact_binary_names_and_wire_order(self):
        names = (b'\x00', b'\xff' * 255, b'H2', b'h2', b'\x00')
        value = parse(body(extensions=(extension(16, alpn(*names)),))).client_hello.extensions[0]
        self.assertEqual(value.alpn_protocols, names)

    def test_alpn_empty_name_and_empty_list_are_malformed(self):
        for names in ((), (b'',), (b'a', b'')):
            self.assert_status(body(extensions=(extension(16, alpn(*names)),)), TLSClientHelloStatus.MALFORMED)

    def test_alpn_name_cannot_cross_list_boundary(self):
        self.assert_status(body(extensions=(extension(16, b'\x00\x02\x02a'),)), TLSClientHelloStatus.MALFORMED)

    def test_large_selected_vectors_fit_containing_extensions(self):
        for kind, name in ((10, 'supported_groups'), (13, 'signature_algorithms')):
            data = identifiers(*((65535,) * 32764))
            value = parse(body(extensions=(extension(kind, data),))).client_hello.extensions[0]
            self.assertEqual(len(getattr(value, name)), 32764)
        names = (b'x',) * 32764
        self.assertEqual(parse(body(extensions=(extension(16, alpn(*names)),))).client_hello.extensions[0].alpn_protocols, names)

    def test_extension_count_bound_and_unsupported_next_occurrence(self):
        self.assertEqual(TLS_CLIENT_HELLO_MAX_EXTENSIONS, 1024)
        block = (extension(65535),) * TLS_CLIENT_HELLO_MAX_EXTENSIONS
        self.assertEqual(len(parse(body(extensions=block)).client_hello.extensions), 1024)
        self.assert_status(body(extensions=block + (extension(65535),)), TLSClientHelloStatus.UNSUPPORTED)

    def test_largest_extension_data_and_block(self):
        data = bytes(range(256)) * 255 + b'x' * 251
        self.assertEqual(len(data), 65531)
        value = self.assert_status(body(extensions=(extension(65535, data),)), TLSClientHelloStatus.COMPLETE)
        self.assertEqual(value.client_hello.extensions[0].data, data)
        self.assertEqual(hello_module.TLS_CLIENT_HELLO_MAX_EXTENSION_DATA_BYTES, 65531)
        with self.assertRaises(OverflowError):
            body(extensions=(extension(65535, data + b'x'),))

    def test_maximum_structurally_representable_body(self):
        data = body(session=b's' * 255, suites=(65535,) * 32767, compression=(255,) * 255,
                    extensions=(extension(65535, b'x' * 65531),))
        self.assertEqual(len(data), 131619)
        self.assert_status(data, TLSClientHelloStatus.COMPLETE)

    def test_exact_outer_ceiling_cannot_be_a_valid_client_hello_structure(self):
        self.assertEqual(TLS_CLIENT_HELLO_MAX_BODY_BYTES, 262144)
        data = body(extensions=())
        value = self.assert_status(data + b'x' * (262144 - len(data)), TLSClientHelloStatus.MALFORMED)
        self.assertEqual(value.failure_offset, len(data))

    def test_non_client_hello_is_explicitly_unsupported_without_body_parsing(self):
        for kind in (0, 2, 11, 255):
            with patch.object(hello_module, '_parse', side_effect=AssertionError('must not parse')):
                value = analyze_tls_client_hello(observed(body(), kind))
            self.assertIs(value.status, TLSClientHelloStatus.UNSUPPORTED)
            self.assertIsNone(value.client_hello)

    def test_immutable_factory_only_public_types_and_exports(self):
        value = parse(selected_body())
        for model in (TLSClientHello, TLSClientHelloExtension, TLSClientHelloObservation):
            self.assertIs(getattr(analysis, model.__name__), model)
            with self.assertRaises(TypeError):
                model()
        for item, name in ((value, 'status'), (value.client_hello, 'session_id'), (value.client_hello.extensions[0], 'data')):
            with self.assertRaises(FrozenInstanceError):
                setattr(item, name, None)
        hello = value.client_hello
        for values in (hello.cipher_suites, hello.compression_methods, hello.extensions, hello.extensions[0].supported_groups,
                       hello.extensions[1].signature_algorithms, hello.extensions[2].alpn_protocols):
            self.assertIs(type(values), tuple)
            with self.assertRaises(TypeError):
                values[0] = None

    def test_input_type_and_completed_observation_invariants(self):
        original = observed(body())
        for invalid in (None, body(), bytearray(body())):
            with self.assertRaises(TypeError):
                analyze_tls_client_hello(invalid)
        for changes in ({'payload': bytearray(body())}, {'stream': None}, {'header': None}, {'prefix': []}):
            with self.assertRaises(TypeError):
                analyze_tls_client_hello(altered(original, **changes))
        for changes in ({'payload': b'bad'}, {'status': TLSHandshakeStatus.INCOMPLETE}, {'prefix': b'x'},
                        {'unavailable_reason': 'failure'}):
            with self.assertRaises(ValueError):
                analyze_tls_client_hello(altered(original, **changes))
        for changes in ({'declared_length': 262145}, {'handshake_type': 256}):
            with self.assertRaises(ValueError):
                analyze_tls_client_hello(altered(original, header=altered(original.header, **changes)))
        with self.assertRaises(TypeError):
            analyze_tls_client_hello(altered(original, header=altered(original.header, handshake_type=True)))

    def test_incomplete_handshake_is_not_client_hello_parser_input(self):
        value = advance(data=message(body())[:-1]).state.forward
        with self.assertRaises(ValueError):
            analyze_tls_client_hello(value)

    def test_completing_stream_ownership_and_direction_are_delegated(self):
        for reverse in (False, True):
            source_value = observed(body(), reverse=reverse)
            value = analyze_tls_client_hello(source_value)
            self.assertIs(value.stream, source_value.stream)
            self.assertIs(value.identity, source_value.identity)
            self.assertIs(value.direction, source_value.direction)
            self.assertEqual(value.consumed_offset, source_value.consumed_offset)

    def test_parsed_structure_does_not_retain_handshake_or_stream(self):
        source_value = source(selected_body())
        value = analyze_tls_client_hello(source_value)
        references = tuple(weakref.ref(item) for item in (source_value, source_value.header, source_value.stream, value))
        hello = value.client_hello
        del source_value, value
        gc.collect()
        self.assertTrue(all(ref() is None for ref in references))
        self.assertEqual(hello.extensions[0].supported_groups, (65535, 0, 29))

    def test_repeated_independent_parsing_is_identical_and_has_no_history(self):
        first = parse(selected_body())
        for _ in range(30):
            self.assertEqual(parse(selected_body()), first)
        self.assertEqual(set(vars(first)), {'stream', 'status', 'reason', 'client_hello', 'failure_offset'})

    def test_parser_infrastructure_failure_propagates(self):
        value = source(selected_body())
        for target in ('_extension', '_build'):
            with patch.object(hello_module, target, side_effect=MemoryError('allocation')):
                with self.assertRaises(MemoryError):
                    analyze_tls_client_hello(value)
        self.assertIs(analyze_tls_client_hello(value).status, TLSClientHelloStatus.COMPLETE)

    def test_untrusted_length_does_not_allocate_declared_payload(self):
        value = source(body()[:35] + b'\xff\xfe')
        with patch.object(hello_module, '_build', wraps=hello_module._build) as build:
            result = analyze_tls_client_hello(value)
        self.assertIs(result.status, TLSClientHelloStatus.INCOMPLETE)
        self.assertEqual(build.call_count, 1)
        self.assertIsNone(result.client_hello)

    def test_parser_source_is_scoped_to_body_structure(self):
        tree = ast.parse(Path(hello_module.__file__).read_text())
        imports = tuple(node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom))
        self.assertEqual(imports, ('dataclasses', 'enum', 'typing', 'analysis.flow_direction', 'analysis.flow_identity',
                                   'analysis.tcp_stream_observation', 'analysis.tls_handshake_framing'))
        calls = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertFalse(calls & {'hash', 'float', 'open', 'eval', 'exec', 'analyze_dns_message', 'decode_tcp'})
