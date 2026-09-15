import gc
import random
import unittest
import weakref
from dataclasses import FrozenInstanceError, replace
from unittest.mock import patch

import analysis
from analysis import (
    TLS_RECORD_MAX_PAYLOAD_BYTES, TLSRecordHeader, TLSRecordObservation, TLSRecordState,
    TLSRecordStatus, TLSRecordUpdate, TCPStreamState, TCPStreamStatus, analyze_packet,
    consume_tcp_stream, flow_identity_from_packet, update_tcp_stream_state, update_tls_record_state,
)
from tests.test_dns_stream_framing import packet as tcp_packet


def packet(payload=b'', sequence=100, **kwargs):
    kwargs.setdefault('port', 443)
    return tcp_packet(payload, sequence, **kwargs)


def wire(payload=b'', content_type=23, version=b'\x03\x03'):
    return bytes((content_type,)) + version + len(payload).to_bytes(2, 'big') + payload


def advance(current=None, payload=b'', sequence=100, **kwargs):
    analyzed = analyze_packet(packet(payload, sequence, **kwargs))
    streams = update_tcp_stream_state(None if current is None else current.tcp_stream_state,
                                      analyzed, flow_identity_from_packet(analyzed))
    return update_tls_record_state(current, streams)


def chunks(parts, **kwargs):
    state, records, sequence = None, [], 100
    for part in parts:
        update = advance(state, part, sequence, **kwargs)
        state = update.state
        records.extend(update.forward_records)
        sequence += len(part)
    return state, tuple(records)


def payloads(records):
    return tuple(record.payload for record in records)


class TLSRecordFramingTests(unittest.TestCase):
    def test_empty_eligible_state_and_observation(self):
        identity = flow_identity_from_packet(analyze_packet(packet()))
        update = update_tls_record_state(None, TCPStreamState(identity))
        self.assertEqual((update.state.forward, update.state.reverse, update.forward_records, update.reverse_records),
                         (None, None, (), ()))
        value = advance().state.forward
        self.assertEqual((value.prefix, value.header, value.payload, value.status), (b'', None, b'', TLSRecordStatus.READY))

    def test_exact_header_and_network_order(self):
        update = advance(payload=b'\xfe\x91\x02\x01\x02')
        value = update.state.forward
        self.assertEqual((value.header.content_type, value.header.protocol_version, value.declared_length), (254, b'\x91\x02', 258))
        self.assertEqual((value.prefix, value.payload, update.forward_records), (b'', b'', ()))
        self.assertIs(value.status, TLSRecordStatus.INCOMPLETE)

    def test_every_header_and_payload_split(self):
        raw = bytes(range(256))
        data = wire(raw)
        for cut in range(len(data) + 1):
            with self.subTest(cut=cut):
                state, records = chunks((data[:cut], data[cut:]))
                self.assertEqual(payloads(records), (raw,))
                self.assertEqual(state.forward.consumed_offset, len(data))
                self.assertEqual((state.forward.prefix, state.forward.header, state.forward.payload), (b'', None, b''))

    def test_partial_header_never_emits(self):
        data = wire(b'abc')
        for size in range(1, 5):
            update = advance(payload=data[:size])
            self.assertEqual(update.state.forward.prefix, data[:size])
            self.assertIsNone(update.state.forward.header)
            self.assertIs(update.state.forward.status, TLSRecordStatus.INCOMPLETE)
            self.assertEqual(update.forward_records, ())

    def test_one_byte_observations_and_multiple_records(self):
        raws = (b'', b'\x00\xff', b'arbitrary')
        data = b''.join(map(wire, raws))
        state, records = chunks(tuple(data[i:i + 1] for i in range(len(data))))
        self.assertEqual(payloads(records), raws)
        self.assertIs(state.forward.status, TLSRecordStatus.READY)

    def test_seeded_arbitrary_fragmentation(self):
        raws = tuple(bytes((i,)) * i for i in range(60))
        data = b''.join(map(wire, raws))
        rng = random.Random(23)
        for _ in range(10):
            cuts = sorted({0, len(data)} | {rng.randrange(len(data)) for _ in range(100)})
            state, records = chunks(tuple(data[a:b] for a, b in zip(cuts, cuts[1:])))
            self.assertEqual(payloads(records), raws)
            self.assertEqual(state.forward.payload, b'')

    def test_coalesced_records_and_partial_next_header_or_body(self):
        for cut in (1, 4, 5, 7):
            last = wire(b'final')
            data = wire(b'A') + wire(b'B') + last[:cut]
            first = advance(payload=data)
            self.assertEqual(payloads(first.forward_records), (b'A', b'B'))
            self.assertIs(first.state.forward.status, TLSRecordStatus.INCOMPLETE)
            final = advance(first.state, last[cut:], 100 + len(data))
            self.assertEqual(payloads(final.forward_records), (b'final',))

    def test_exact_record_and_next_header_boundaries(self):
        state, records = chunks((wire(b'A'), wire(b'B')[:5], b'B', wire()))
        self.assertEqual(payloads(records), (b'A', b'B', b''))
        self.assertIs(state.forward.status, TLSRecordStatus.READY)

    def test_zero_length_at_exact_header_boundary(self):
        update = advance(payload=wire())
        record, = update.forward_records
        self.assertEqual(record.declared_length, 0)
        self.assertEqual(record.payload, b'')
        self.assertIs(record.status, TLSRecordStatus.READY)

    def test_maximum_bounded_record_without_preallocation(self):
        self.assertEqual(TLS_RECORD_MAX_PAYLOAD_BYTES, 18432)
        raw = bytes(range(256)) * 72
        first = advance(payload=wire(raw)[:5])
        self.assertEqual(first.state.forward.payload, b'')
        self.assertEqual(first.state.forward.declared_length, 18432)
        final = advance(first.state, raw, 105)
        self.assertEqual(payloads(final.forward_records), (raw,))
        self.assertIs(final.state.forward.status, TLSRecordStatus.READY)

    def test_representable_oversized_lengths_stop_before_body(self):
        for size in (18433, 65535):
            data = wire(b'A') + b'\x17\x03\x03' + size.to_bytes(2, 'big') + b'body'
            update = advance(payload=data)
            value = update.state.forward
            self.assertEqual(payloads(update.forward_records), (b'A',))
            self.assertEqual((value.declared_length, value.payload, value.consumed_offset), (size, b'', 11))
            self.assertEqual(value.stream.unconsumed_payload, b'body')
            self.assertIs(value.unavailable_reason, TCPStreamStatus.LIMIT_EXCEEDED)
            self.assertIs(value.status, TLSRecordStatus.UNAVAILABLE)
            later = advance(update.state, b'gap', 1000)
            self.assertIs(later.state.forward.unavailable_reason, TCPStreamStatus.LIMIT_EXCEEDED)
            self.assertEqual(later.forward_records, ())
        with self.assertRaises(OverflowError):
            (65536).to_bytes(2, 'big')

    def test_all_content_types_versions_and_opaque_payloads(self):
        raws = tuple(bytes(range(256)) + b'\x00' for _ in range(256))
        parts = tuple(wire(raw, i, bytes((i, 255 - i))) for i, raw in enumerate(raws))
        state, records = chunks(parts)
        self.assertEqual(payloads(records), raws)
        self.assertEqual(tuple(r.header.content_type for r in records), tuple(range(256)))
        self.assertEqual(tuple(r.header.protocol_version for r in records), tuple(bytes((i, 255 - i)) for i in range(256)))
        self.assertTrue(all(r.declared_length == 257 for r in records))
        self.assertIs(state.forward.status, TLSRecordStatus.READY)

    def test_completion_observation_is_shared_without_packet_or_timestamp_copy(self):
        first = advance(payload=wire(b'abc')[:6])
        final = advance(first.state, b'bc' + wire(b'd'), 106, seconds=7)
        for value in final.forward_records:
            self.assertIs(value.stream, final.state.tcp_stream_state.forward)
            self.assertEqual(value.stream.last_sequence_number, 106)
            self.assertEqual(value.identity, final.state.identity)
            self.assertEqual(value.direction, final.state.forward.direction)
            self.assertEqual(value.consumed_offset, final.state.forward.consumed_offset)
        self.assertEqual(first.state.forward.payload, b'a')

    def test_opposite_partial_directions_ipv4_ipv6(self):
        for ipv6 in (False, True):
            first = advance(payload=wire(b'forward')[:2], ipv6=ipv6)
            second = advance(first.state, wire(b'reverse')[:6], 900, reverse=True, ipv6=ipv6)
            self.assertEqual((second.state.forward.prefix, second.state.reverse.payload), (b'\x17\x03', b'r'))
            third = advance(second.state, wire(b'forward')[2:], 102, ipv6=ipv6)
            self.assertEqual((payloads(third.forward_records), third.reverse_records), ((b'forward',), ()))
            final = advance(third.state, b'everse', 906, reverse=True, ipv6=ipv6)
            self.assertEqual((final.forward_records, payloads(final.reverse_records)), ((), (b'reverse',)))

    def test_retransmissions_empty_and_repeated_updates_emit_once(self):
        data = wire(b'once')
        first = advance(payload=data)
        duplicate = advance(first.state, data)
        empty = advance(duplicate.state, b'', 100 + len(data))
        repeated = update_tls_record_state(empty.state, empty.state.tcp_stream_state)
        self.assertEqual(payloads(first.forward_records), (b'once',))
        self.assertEqual((duplicate.forward_records, empty.forward_records, repeated.forward_records), ((), (), ()))

    def test_gap_is_sticky_with_prior_records_preserved(self):
        first = advance(payload=wire(b'A') + b'\x17')
        failed = advance(first.state, b'gap', 200)
        retry = advance(failed.state, wire(b'B')[1:], 107)
        self.assertEqual(payloads(first.forward_records), (b'A',))
        for value in (failed, retry):
            self.assertIs(value.state.forward.unavailable_reason, TCPStreamStatus.GAP)
            self.assertEqual(value.state.forward.prefix, b'\x17')
            self.assertEqual(value.forward_records, ())

    def test_conflict_and_overlap_inherit_tcp_reason(self):
        first = advance(payload=wire(b'abcdef')[:8])
        conflict = advance(first.state, b'xxx', 105)
        overlap = advance(first.state, b'bcdef', 106)
        self.assertIs(conflict.state.forward.unavailable_reason, TCPStreamStatus.CONFLICT)
        self.assertIs(overlap.state.forward.unavailable_reason, TCPStreamStatus.OVERLAP)

    def test_fin_reset_and_after_close(self):
        for flags, status in ((17, TCPStreamStatus.FIN), (20, TCPStreamStatus.RESET)):
            first = advance(payload=wire(b'A') + b'\x17', flags=flags)
            self.assertEqual(payloads(first.forward_records), (b'A',))
            self.assertIs(first.state.forward.stream.status, status)
            self.assertIs(first.state.forward.status, TLSRecordStatus.INCOMPLETE)
            after = advance(first.state, b'\x03', 108)
            self.assertIs(after.state.forward.unavailable_reason, TCPStreamStatus.AFTER_CLOSE)

    def test_syn_sequence_wraparound(self):
        data = wire(b'abc')
        first = advance(payload=data[:5], sequence=0xfffffffc, flags=2)
        final = advance(first.state, data[5:], 2)
        self.assertEqual(payloads(final.forward_records), (b'abc',))

    def test_ipv6_extensions_and_fragment_failure(self):
        for extensions in ((), (0,), (60,), (0, 43, 60), (0, 60)):
            update = advance(payload=wire(b'opaque'), ipv6=True, extensions=extensions)
            self.assertEqual(payloads(update.forward_records), (b'opaque',))
        failed = advance(payload=wire(b'opaque'), ipv6=True, fragment=(0, True, 23))
        self.assertIs(failed.state.forward.unavailable_reason, TCPStreamStatus.FRAGMENTED)
        self.assertEqual(failed.forward_records, ())

    def test_large_record_reclaims_tcp_consumed_prefix(self):
        state = None
        sequence = 100
        for _ in range(50):
            data = wire(b'x' * 1024)
            update = advance(state, data, sequence)
            state, sequence = update.state, sequence + len(data)
        raw = b'\x00' * 18432
        records = []
        data = wire(raw)
        for offset in range(0, len(data), 257):
            update = advance(state, data[offset:offset + 257], sequence)
            state, sequence = update.state, sequence + len(data[offset:offset + 257])
            records.extend(update.forward_records)
            self.assertLessEqual(len(state.forward.payload), 18431)
            self.assertLessEqual(state.forward.stream.payload_length, 65536)
        self.assertEqual(payloads(records), (raw,))
        self.assertGreater(state.forward.stream.buffer_offset, 0)

    def test_long_stream_retains_no_completed_record_history(self):
        state = None
        for index in range(200):
            update = advance(state, wire(b'x' * 1024), 100 + index * 1029)
            self.assertEqual(payloads(update.forward_records), (b'x' * 1024,))
            state = update.state
            self.assertEqual((state.forward.prefix, state.forward.header, state.forward.payload), (b'', None, b''))
            self.assertEqual(set(vars(state)), {'tcp_stream_state', 'forward', 'reverse'})
            self.assertLessEqual(state.forward.stream.payload_length, 65536)
        self.assertGreater(state.forward.stream.buffer_offset, 65536)

    def test_retained_state_releases_completed_records_and_source_objects(self):
        source = packet(wire(b'complete') + b'\x17')
        analyzed = analyze_packet(source)
        streams = update_tcp_stream_state(None, analyzed, flow_identity_from_packet(analyzed))
        update = update_tls_record_state(None, streams)
        refs = [weakref.ref(value) for value in (source, analyzed, streams, update, update.forward_records[0], update.forward_records[0].header)]
        state = update.state
        del source, analyzed, streams, update
        gc.collect()
        self.assertTrue(all(ref() is None for ref in refs))
        self.assertEqual(state.forward.prefix, b'\x17')

    def test_factory_only_frozen_public_representation(self):
        update = advance(payload=wire(b'A'))
        for model in (TLSRecordHeader, TLSRecordObservation, TLSRecordState, TLSRecordUpdate):
            self.assertIs(getattr(analysis, model.__name__), model)
            with self.assertRaises(TypeError):
                model()
        for value, attribute in ((update, 'state'), (update.state, 'forward'), (update.state.forward, 'prefix'),
                                 (update.forward_records[0].header, 'content_type')):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, attribute, None)
        self.assertIs(type(update.forward_records), tuple)
        self.assertIs(type(update.forward_records[0].payload), bytes)

    def test_invalid_types_identity_and_consumption(self):
        first = advance(payload=b'\x17')
        for current, streams in (({}, first.state.tcp_stream_state), (None, None)):
            with self.assertRaises(TypeError):
                update_tls_record_state(current, streams)
        with self.assertRaises(ValueError):
            update_tls_record_state(None, first.state.tcp_stream_state)
        other = advance(client_port=12346)
        with self.assertRaises(ValueError):
            update_tls_record_state(first.state, other.state.tcp_stream_state)
        with self.assertRaises(ValueError):
            update_tls_record_state(first.state, replace(first.state.tcp_stream_state, forward=None))
        analyzed = analyze_packet(packet(b'\x03', 101))
        streams = update_tcp_stream_state(first.state.tcp_stream_state, analyzed, first.state.identity)
        with self.assertRaises(ValueError):
            update_tls_record_state(first.state, replace(streams, forward=consume_tcp_stream(streams.forward, 1)))

    def test_eligibility_and_both_service_orientations(self):
        for port in (80, 8443, 853):
            self.assertIsNone(advance(port=port))
        for port in (389, 53):
            self.assertIsNone(advance(client_port=port))
            self.assertIsNone(advance(port=port, client_port=443))
        self.assertIsNotNone(advance(reverse=True))
        self.assertIsNotNone(advance(port=12345, client_port=443))

    def test_framer_never_invokes_dns_or_ldap_parser(self):
        with patch('analysis.dns.analyze_dns_message', side_effect=AssertionError('DNS parser')):
            with patch('analysis.ldap_stream_framing._message', side_effect=AssertionError('LDAP parser')):
                update = advance(payload=wire(b'\x00\xffarbitrary'))
        self.assertEqual(payloads(update.forward_records), (b'\x00\xffarbitrary',))
