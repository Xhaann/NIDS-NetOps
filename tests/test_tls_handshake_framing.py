import ast
import gc
import random
import unittest
import weakref
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

import analysis
from analysis import (
    TLS_HANDSHAKE_MAX_MESSAGE_LENGTH, TLSHandshakeHeader, TLSHandshakeObservation, TLSHandshakeState,
    TLSHandshakeStatus, TLSHandshakeUpdate, TCPStreamState, TCPStreamStatus, analyze_packet,
    flow_identity_from_packet, update_tls_record_state, update_tls_handshake_state,
)
from tests.test_tls_record_framing import advance as record_advance, packet, wire, payloads


def message(payload=b'', kind=1):
    return bytes((kind,)) + len(payload).to_bytes(3, 'big') + payload


def advance(current=None, data=b'', sequence=100, content_type=22, **kwargs):
    update = record_advance(None if current is None else current.tls_record_state,
                            wire(data, content_type), sequence, **kwargs)
    return None if update is None else update_tls_handshake_state(current, update)


def fragments(parts, **kwargs):
    state, messages, sequence = None, [], 100
    for part in parts:
        update = advance(state, part, sequence, **kwargs)
        state = update.state
        messages.extend(update.forward_messages)
        sequence += 5 + len(part)
    return state, tuple(messages)


class TLSHandshakeFramingTests(unittest.TestCase):
    def test_empty_eligible_stream_and_empty_handshake_record(self):
        identity = flow_identity_from_packet(analyze_packet(packet()))
        records = update_tls_record_state(None, TCPStreamState(identity))
        update = update_tls_handshake_state(None, records)
        self.assertEqual((update.state.forward, update.state.reverse, update.forward_messages), (None, None, ()))
        observed = advance()
        self.assertIs(observed.state.forward.status, TLSHandshakeStatus.READY)
        self.assertEqual(observed.forward_messages, ())

    def test_exact_four_byte_network_order_header(self):
        update = advance(data=b'\xfe\x01\x02\x03')
        value = update.state.forward
        self.assertEqual((value.header.handshake_type, value.declared_length), (254, 66051))
        self.assertEqual((value.prefix, value.payload, update.forward_messages), (b'', b'', ()))
        self.assertIs(value.status, TLSHandshakeStatus.INCOMPLETE)

    def test_every_header_and_body_split_across_records(self):
        raw = bytes(range(256))
        data = message(raw)
        for cut in range(len(data) + 1):
            with self.subTest(cut=cut):
                state, values = fragments((data[:cut], data[cut:]))
                self.assertEqual(payloads(values), (raw,))
                self.assertEqual((state.forward.prefix, state.forward.header, state.forward.payload), (b'', None, b''))

    def test_partial_header_at_each_record_boundary(self):
        data = message(b'abc')
        for cut in range(1, 4):
            first = advance(data=data[:cut])
            self.assertEqual(first.state.forward.prefix, data[:cut])
            self.assertIsNone(first.state.forward.declared_length)
            self.assertEqual(first.forward_messages, ())
            final = advance(first.state, data[cut:], 105 + cut)
            self.assertEqual(payloads(final.forward_messages), (b'abc',))

    def test_one_byte_record_payloads(self):
        raws = (b'\x00\xff', b'', b'body')
        data = b''.join(map(message, raws))
        state, values = fragments(tuple(data[i:i + 1] for i in range(len(data))))
        self.assertEqual(payloads(values), raws)
        self.assertIs(state.forward.status, TLSHandshakeStatus.READY)

    def test_seeded_arbitrary_record_and_tcp_segmentation(self):
        raws = tuple(bytes((i,)) * i for i in range(40))
        data = b''.join(map(message, raws))
        rng = random.Random(24)
        for _ in range(8):
            cuts = sorted({0, len(data)} | {rng.randrange(len(data)) for _ in range(60)})
            stream = b''.join(wire(data[a:b], 22) for a, b in zip(cuts, cuts[1:]))
            tcp_cuts = sorted({0, len(stream)} | {rng.randrange(len(stream)) for _ in range(80)})
            current, values = None, []
            for left, right in zip(tcp_cuts, tcp_cuts[1:]):
                records = record_advance(None if current is None else current.tls_record_state,
                                         stream[left:right], 100 + left)
                update = update_tls_handshake_state(current, records)
                current = update.state
                values.extend(update.forward_messages)
            self.assertEqual(payloads(values), raws)

    def test_multiple_messages_and_partial_next_header_or_body(self):
        data = message(b'last')
        for cut in (1, 3, 4, 6):
            first_data = message(b'A') + message(b'B') + data[:cut]
            first = advance(data=first_data)
            self.assertEqual(payloads(first.forward_messages), (b'A', b'B'))
            self.assertIs(first.state.forward.status, TLSHandshakeStatus.INCOMPLETE)
            final = advance(first.state, data[cut:], 105 + len(first_data))
            self.assertEqual(payloads(final.forward_messages), (b'last',))

    def test_record_contains_end_of_one_and_start_of_next_message(self):
        data = message(b'first') + message(b'second') + message(b'third')
        state, values = fragments((data[:7], data[7:12], data[12:]))
        self.assertEqual(payloads(values), (b'first', b'second', b'third'))
        self.assertIs(state.forward.status, TLSHandshakeStatus.READY)

    def test_zero_length_message_is_complete_at_exact_header_boundary(self):
        update = advance(data=message())
        value, = update.forward_messages
        self.assertEqual((value.header.handshake_type, value.declared_length, value.payload), (1, 0, b''))
        self.assertIs(value.status, TLSHandshakeStatus.READY)

    def test_maximum_message_spans_records_and_tcp_buffer_reclamation(self):
        self.assertEqual(TLS_HANDSHAKE_MAX_MESSAGE_LENGTH, 262144)
        raw = bytes(range(256)) * 1024
        first = advance(data=message(raw)[:4])
        self.assertEqual(first.state.forward.payload, b'')
        self.assertEqual(first.state.forward.declared_length, 262144)
        state, sequence, values = first.state, 109, []
        for offset in range(0, len(raw), 16384):
            update = advance(state, raw[offset:offset + 16384], sequence)
            state, sequence = update.state, sequence + 16389
            values.extend(update.forward_messages)
            self.assertLessEqual(len(state.forward.payload), 262143)
            self.assertLessEqual(state.forward.stream.payload_length, 65536)
            self.assertEqual(state.tls_record_state.forward.payload, b'')
        self.assertEqual(payloads(values), (raw,))
        self.assertGreater(state.forward.stream.buffer_offset, 65536)

    def test_representable_oversized_and_impossible_lengths(self):
        for size in (262145, 16777215):
            data = message(b'A') + b'\x01' + size.to_bytes(3, 'big') + b'unconsumed body'
            update = advance(data=data)
            value = update.state.forward
            self.assertEqual(payloads(update.forward_messages), (b'A',))
            self.assertEqual((value.declared_length, value.payload), (size, b''))
            self.assertIs(value.status, TLSHandshakeStatus.UNAVAILABLE)
            self.assertIs(value.unavailable_reason, TCPStreamStatus.LIMIT_EXCEEDED)
            after = advance(update.state, message(b'ignored'), 105 + len(data))
            self.assertEqual(after.forward_messages, ())
            self.assertIs(after.state.forward.unavailable_reason, TCPStreamStatus.LIMIT_EXCEEDED)
        with self.assertRaises(OverflowError):
            (16777216).to_bytes(3, 'big')

    def test_all_handshake_types_and_binary_payload_preserved(self):
        raw = bytes(range(256)) + b'\x00'
        state, values = fragments(tuple(message(raw, kind) for kind in range(256)))
        self.assertEqual(tuple(v.header.handshake_type for v in values), tuple(range(256)))
        self.assertEqual(payloads(values), (raw,) * 256)
        self.assertTrue(all(v.declared_length == len(raw) for v in values))
        self.assertIs(state.forward.status, TLSHandshakeStatus.READY)

    def test_non_handshake_content_never_enters_message_framing(self):
        state, sequence = None, 100
        for content_type in range(256):
            if content_type == 22:
                continue
            data = message(b'ignored')
            update = advance(state, data, sequence, content_type=content_type)
            state, sequence = update.state, sequence + 5 + len(data)
            self.assertEqual(update.forward_messages, ())
            self.assertIs(state.forward.status, TLSHandshakeStatus.READY)

    def test_non_handshake_and_empty_records_preserve_incomplete_message(self):
        for cut in (2, 6):
            data = message(b'abcdef')
            first = advance(data=data[:cut])
            second = advance(first.state, b'\xff' * 20, 105 + cut, content_type=23)
            empty = advance(second.state, b'', 130 + cut)
            for value in (second.state.forward, empty.state.forward):
                self.assertEqual((value.prefix, value.header, value.payload),
                                 (first.state.forward.prefix, first.state.forward.header, first.state.forward.payload))
            final = advance(empty.state, data[cut:], 135 + cut)
            self.assertEqual(payloads(final.forward_messages), (b'abcdef',))

    def test_simultaneous_partial_directions_ipv4_ipv6(self):
        for ipv6 in (False, True):
            forward, reverse = message(b'forward'), message(b'reverse')
            first = advance(data=forward[:2], ipv6=ipv6)
            second = advance(first.state, reverse[:6], 900, reverse=True, ipv6=ipv6)
            self.assertEqual((second.state.forward.prefix, second.state.reverse.payload), (forward[:2], b're'))
            third = advance(second.state, forward[2:], 107, ipv6=ipv6)
            self.assertEqual((payloads(third.forward_messages), third.reverse_messages), ((b'forward',), ()))
            final = advance(third.state, reverse[6:], 911, reverse=True, ipv6=ipv6)
            self.assertEqual((final.forward_messages, payloads(final.reverse_messages)), ((), (b'reverse',)))

    def test_completion_stream_is_exact_record_source(self):
        first = advance(data=message(b'abc')[:5])
        records = record_advance(first.state.tls_record_state, wire(b'bc' + message(b'next'), 22), 110, seconds=7)
        update = update_tls_handshake_state(first.state, records)
        for item in update.forward_messages:
            self.assertIs(item.stream, records.forward_records[0].stream)
            self.assertEqual(item.identity, update.state.identity)
            self.assertEqual(item.direction, update.state.forward.direction)
            self.assertEqual(item.consumed_offset, records.state.forward.consumed_offset)
        self.assertIs(update.state.tls_record_state, records.state)

    def test_retransmission_and_replayed_updates_do_not_reemit(self):
        data = wire(message(b'once'), 22)
        records = record_advance(payload=data)
        first = update_tls_handshake_state(None, records)
        repeated = update_tls_handshake_state(first.state, records)
        duplicate_records = record_advance(repeated.state.tls_record_state, data)
        duplicate = update_tls_handshake_state(repeated.state, duplicate_records)
        self.assertEqual(payloads(first.forward_messages), (b'once',))
        self.assertEqual((repeated.forward_messages, duplicate.forward_messages), ((), ()))

    def test_gap_overlap_conflict_and_first_failure_are_inherited(self):
        data = wire(message(b'abc')[:5], 22)
        first_records = record_advance(payload=data)
        first = update_tls_handshake_state(None, first_records)
        for sequence, raw, reason in ((200, b'gap', TCPStreamStatus.GAP),
                                      (105, b'xxx', TCPStreamStatus.CONFLICT),
                                      (108, data[8:] + b'extra', TCPStreamStatus.OVERLAP)):
            records = record_advance(first.state.tls_record_state, raw, sequence)
            failed = update_tls_handshake_state(first.state, records)
            self.assertIs(failed.state.forward.unavailable_reason, reason)
            self.assertEqual(failed.state.forward.payload, b'a')
            later = advance(failed.state, message(b'ignored'), 1000)
            self.assertIs(later.state.forward.unavailable_reason, reason)
            self.assertEqual(later.forward_messages, ())

    def test_tls_record_limit_failure_preserves_prior_messages(self):
        raw = wire(message(b'A') + b'\x01', 22) + b'\x16\x03\x03\xff\xff'
        records = record_advance(payload=raw)
        update = update_tls_handshake_state(None, records)
        self.assertEqual(payloads(update.forward_messages), (b'A',))
        self.assertEqual(update.state.forward.prefix, b'\x01')
        self.assertIs(update.state.forward.unavailable_reason, TCPStreamStatus.LIMIT_EXCEEDED)

    def test_handshake_limit_precedes_later_tcp_failure(self):
        first = advance(data=b'\x01\xff\xff\xff')
        after = advance(first.state, b'gap', 1000)
        self.assertIs(after.state.forward.unavailable_reason, TCPStreamStatus.LIMIT_EXCEEDED)

    def test_fin_reset_partial_suffix_and_after_close(self):
        for flags, reason in ((17, TCPStreamStatus.FIN), (20, TCPStreamStatus.RESET)):
            data = message(b'A') + b'\x01'
            first = advance(data=data, flags=flags)
            self.assertEqual(payloads(first.forward_messages), (b'A',))
            self.assertIs(first.state.forward.status, TLSHandshakeStatus.INCOMPLETE)
            self.assertIs(first.state.forward.stream.status, reason)
            later = advance(first.state, b'\x00', 111)
            self.assertIs(later.state.forward.unavailable_reason, TCPStreamStatus.AFTER_CLOSE)

    def test_syn_sequence_wraparound(self):
        raw = wire(message(b'abc'), 22)
        first_records = record_advance(payload=raw[:5], sequence=0xfffffffc, flags=2)
        first = update_tls_handshake_state(None, first_records)
        records = record_advance(first.state.tls_record_state, raw[5:], 2)
        final = update_tls_handshake_state(first.state, records)
        self.assertEqual(payloads(final.forward_messages), (b'abc',))

    def test_ipv6_extensions_and_fragment_failure(self):
        for extensions in ((), (0,), (60,), (0, 43, 60), (0, 60)):
            update = advance(data=message(b'opaque'), ipv6=True, extensions=extensions)
            self.assertEqual(payloads(update.forward_messages), (b'opaque',))
        failed = advance(data=message(b'opaque'), ipv6=True, fragment=(0, True, 24))
        self.assertIs(failed.state.forward.unavailable_reason, TCPStreamStatus.FRAGMENTED)

    def test_no_scanning_or_resynchronization_of_unproven_midstream_data(self):
        update = advance(data=b'\xff\xff\xff\xff' + message(b'plausible'))
        self.assertEqual(update.forward_messages, ())
        self.assertIs(update.state.forward.status, TLSHandshakeStatus.UNAVAILABLE)
        self.assertIsNone(update.state.forward.stream.syn_sequence)
        aligned = advance(data=message(b'opaque'))
        self.assertIsNone(aligned.state.forward.stream.syn_sequence)
        self.assertEqual(payloads(aligned.forward_messages), (b'opaque',))

    def test_partial_tls_record_is_never_presented_as_handshake_bytes(self):
        raw = wire(message(b'abc'), 22)
        for length in range(len(raw)):
            records = record_advance(payload=raw[:length])
            update = update_tls_handshake_state(None, records)
            self.assertEqual(update.forward_messages, ())
            self.assertEqual((update.state.forward.prefix, update.state.forward.payload), (b'', b''))

    def test_long_stream_retains_only_incomplete_state(self):
        state, sequence = None, 100
        for index in range(180):
            data = message(bytes((index,)) * 2000)
            update = advance(state, data, sequence)
            state, sequence = update.state, sequence + 5 + len(data)
            self.assertEqual(len(update.forward_messages), 1)
            self.assertEqual((state.forward.prefix, state.forward.header, state.forward.payload), (b'', None, b''))
            self.assertLessEqual(state.forward.stream.payload_length, 65536)
            self.assertEqual(set(vars(state)), {'tls_record_state', 'forward', 'reverse'})
        self.assertGreater(state.forward.stream.buffer_offset, 65536)

    def test_completed_record_and_handshake_objects_are_released(self):
        records = record_advance(payload=wire(message(b'complete') + b'\x01', 22))
        update = update_tls_handshake_state(None, records)
        refs = [weakref.ref(value) for value in (records, records.forward_records[0], records.forward_records[0].header,
                                                update, update.forward_messages[0], update.forward_messages[0].header)]
        state = update.state
        del records, update
        gc.collect()
        self.assertTrue(all(ref() is None for ref in refs))
        self.assertEqual(state.forward.prefix, b'\x01')

    def test_public_values_are_frozen_factory_only(self):
        update = advance(data=message(b'A'))
        for model in (TLSHandshakeHeader, TLSHandshakeObservation, TLSHandshakeState, TLSHandshakeUpdate):
            self.assertIs(getattr(analysis, model.__name__), model)
            with self.assertRaises(TypeError):
                model()
        for value, name in ((update, 'state'), (update.state, 'forward'), (update.state.forward, 'prefix'),
                            (update.forward_messages[0].header, 'handshake_type')):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, name, None)
        self.assertIs(type(update.forward_messages), tuple)
        self.assertIs(type(update.forward_messages[0].payload), bytes)

    def test_type_identity_and_stale_input_validation(self):
        records = record_advance(payload=wire(message(b'A'), 22))
        first = update_tls_handshake_state(None, records)
        for current, batch in (({}, records), (None, None), (None, records.state)):
            with self.assertRaises(TypeError):
                update_tls_handshake_state(current, batch)
        other = record_advance(payload=wire(), client_port=12346)
        with self.assertRaises(ValueError):
            update_tls_handshake_state(first.state, other)
        newer = advance(first.state, message(b'B'), 110)
        with self.assertRaises(ValueError):
            update_tls_handshake_state(newer.state, records)
        empty = update_tls_record_state(None, TCPStreamState(first.state.identity))
        with self.assertRaises(ValueError):
            update_tls_handshake_state(first.state, empty)

    def test_port_orientation_and_precedence_are_lower_layer_owned(self):
        for port in (80, 8443, 853):
            self.assertIsNone(advance(port=port))
        for port in (389, 53):
            self.assertIsNone(advance(client_port=port))
        self.assertEqual(payloads(advance(data=message(b'A'), reverse=True).reverse_messages), (b'A',))
        self.assertIsNotNone(advance(port=12345, client_port=443))

    def test_source_boundary_has_no_raw_transport_or_semantic_dependencies(self):
        tree = ast.parse(Path('src/analysis/tls_handshake_framing.py').read_text())
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imports, {'dataclasses', 'enum', 'typing', 'analysis.flow_direction', 'analysis.flow_identity',
                                  'analysis.tcp_stream_observation', 'analysis.tls_record_framing'})
        names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse(names & {'unconsumed_payload', 'contiguous_payload', 'sequence_number', 'raw_bytes', 'protocol_version'})
        with patch('analysis.dns.analyze_dns_message', side_effect=AssertionError('DNS')):
            with patch('analysis.ldap_stream_framing._message', side_effect=AssertionError('LDAP')):
                self.assertEqual(payloads(advance(data=message(b'opaque')).forward_messages), (b'opaque',))
