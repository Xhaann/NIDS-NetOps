import ast
import gc
import random
import unittest
import weakref
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from struct import pack
from unittest.mock import patch

import analysis
from analysis import (
    DNS_MAX_MESSAGE_BYTES, DNSMessageStatus, DNSStreamObservation, DNSStreamState, DNSStreamStatus,
    DNSStreamUpdate, FlowDirection, TCPStreamState, TCPStreamStatus, analyze_dns_message, analyze_packet,
    consume_tcp_stream, flow_identity_from_packet, update_dns_stream_state, update_tcp_stream_state,
)
from tests.pcap_scenarios import addresses, checksum, frame, transport
from tests.protocol_scenarios import observation
from tests.test_dns import header
from tests.test_dns_edns import message, opt, option


def framed(raw):
    return len(raw).to_bytes(2, 'big') + raw


def packet(payload=b'', sequence=100, seconds=0, ipv6=False, reverse=False, flags=16,
           client_port=12345, port=53, extensions=(), fragment=None):
    segment = transport(6, payload, ipv6, reverse, sequence=sequence, flags=flags)
    ports = (port, client_port) if reverse else (client_port, port)
    segment = pack('!HH', *ports) + segment[4:16] + b'\x00\x00' + segment[18:]
    source, destination = addresses(ipv6, reverse)
    pseudo = source + destination + (pack('!I3xB', len(segment), 6) if ipv6 else pack('!BBH', 0, 6, len(segment)))
    segment = segment[:16] + pack('!H', checksum(pseudo + segment)) + segment[18:]
    return observation(frame(6, segment, ipv6, reverse, extensions, fragment), seconds)


def advance(current=None, payload=b'', sequence=100, **kwargs):
    analyzed = analyze_packet(packet(payload, sequence, **kwargs))
    streams = update_tcp_stream_state(None if current is None else current.tcp_stream_state,
                                      analyzed, flow_identity_from_packet(analyzed))
    return update_dns_stream_state(current, streams)


def run_chunks(chunks, **kwargs):
    state, frames, sequence = None, [], 100
    for chunk in chunks:
        update = advance(state, chunk, sequence, **kwargs)
        state = update.state
        frames.extend(update.forward_frames)
        sequence += len(chunk)
    return state, tuple(frames)


class DNSStreamFramingTests(unittest.TestCase):
    def test_empty_stream_state(self):
        identity = flow_identity_from_packet(analyze_packet(packet()))
        update = update_dns_stream_state(None, TCPStreamState(identity))
        self.assertIsNone(update.state.forward)
        self.assertIsNone(update.state.reverse)
        self.assertEqual((update.forward_frames, update.reverse_frames), ((), ()))

    def test_empty_observation_is_ready_without_a_dns_message(self):
        update = advance()
        value = update.state.forward
        self.assertIs(value.status, DNSStreamStatus.READY)
        self.assertEqual((value.prefix, value.payload, value.declared_length), (b'', b'', None))
        self.assertEqual(update.forward_frames, ())

    def test_single_frame_excludes_prefix_and_consumes_exact_bytes(self):
        raw = header()
        update = advance(payload=framed(raw))
        self.assertEqual(update.forward_frames, (raw,))
        self.assertEqual(update.state.forward.consumed_offset, len(raw) + 2)
        self.assertEqual(update.state.forward.stream.unconsumed_payload, b'')
        self.assertIs(update.state.forward.stream, update.state.tcp_stream_state.forward)
        self.assertIs(update.state.forward.status, DNSStreamStatus.READY)

    def test_partial_prefix_is_bounded_and_not_emitted(self):
        update = advance(payload=b'\xff')
        self.assertEqual(update.forward_frames, ())
        self.assertEqual(update.state.forward.prefix, b'\xff')
        self.assertIsNone(update.state.forward.declared_length)
        self.assertIs(update.state.forward.status, DNSStreamStatus.INCOMPLETE)
        self.assertEqual(update.state.forward.consumed_offset, 1)

    def test_prefix_split_one_plus_one(self):
        raw = header()
        state, frames = run_chunks((framed(raw)[:1], framed(raw)[1:2], raw))
        self.assertEqual(frames, (raw,))
        self.assertIs(state.forward.status, DNSStreamStatus.READY)

    def test_network_order_prefix_is_exact(self):
        update = advance(payload=b'\x01\x02' + b'x' * 7)
        self.assertEqual(update.state.forward.declared_length, 258)
        self.assertEqual(update.state.forward.payload, b'x' * 7)
        self.assertEqual(update.forward_frames, ())

    def test_complete_prefix_with_partial_payload(self):
        raw = header()
        first = advance(payload=framed(raw)[:6])
        self.assertEqual((first.state.forward.prefix, first.state.forward.declared_length,
                          first.state.forward.payload), (b'', len(raw), raw[:4]))
        self.assertEqual(first.forward_frames, ())
        second = advance(first.state, raw[4:], 106)
        self.assertEqual(second.forward_frames, (raw,))
        self.assertEqual(first.state.forward.payload, raw[:4])

    def test_every_split_position_preserves_one_message(self):
        raw = message(opt(data=option(65535, b'opaque')))
        data = framed(raw)
        for split in range(len(data) + 1):
            with self.subTest(split=split):
                state, frames = run_chunks((data[:split], data[split:]))
                self.assertEqual(frames, (raw,))
                self.assertEqual(state.forward.payload, b'')

    def test_one_byte_segmentation_preserves_multiple_frames(self):
        raws = (header(), b'', message(opt(data=option(1, b'abc'))))
        data = b''.join(map(framed, raws))
        state, frames = run_chunks(tuple(data[index:index + 1] for index in range(len(data))))
        self.assertEqual(frames, raws)
        self.assertEqual(state.forward.consumed_offset, len(data))

    def test_multiple_frames_in_one_observation(self):
        raws = (header(), header(flags=0x8000), b'opaque')
        update = advance(payload=b''.join(map(framed, raws)))
        self.assertEqual(update.forward_frames, raws)

    def test_complete_frames_then_partial_next_prefix(self):
        first, second = header(), message(opt())
        update = advance(payload=framed(first) + framed(second)[:1])
        self.assertEqual(update.forward_frames, (first,))
        self.assertEqual(update.state.forward.prefix, framed(second)[:1])
        final = advance(update.state, framed(second)[1:], 100 + len(framed(first)) + 1)
        self.assertEqual(final.forward_frames, (second,))

    def test_complete_frames_then_partial_next_payload(self):
        raws = (header(), message(opt()), message(opt(data=option(1))))
        data = b''.join(map(framed, raws))
        boundary = len(framed(raws[0])) + len(framed(raws[1])) + 7
        update = advance(payload=data[:boundary])
        self.assertEqual(update.forward_frames, raws[:2])
        self.assertEqual(update.state.forward.payload, raws[2][:5])
        self.assertEqual(advance(update.state, data[boundary:], 100 + boundary).forward_frames, raws[2:])

    def test_arbitrary_segmentation_matches_unsplit_frames(self):
        raws = tuple(bytes((index,)) * index for index in range(60))
        data = b''.join(map(framed, raws))
        generator = random.Random(22)
        for _ in range(12):
            cuts = sorted({0, len(data)} | {generator.randrange(len(data)) for _ in range(80)})
            state, frames = run_chunks(tuple(data[left:right] for left, right in zip(cuts, cuts[1:])))
            self.assertEqual(frames, raws)
            self.assertIs(state.forward.status, DNSStreamStatus.READY)

    def test_exact_observation_boundaries_and_next_prefix(self):
        raw = header()
        state, frames = run_chunks((framed(raw), framed(raw)[:2], raw))
        self.assertEqual(frames, (raw, raw))
        self.assertEqual(state.forward.consumed_offset, 2 * len(framed(raw)))

    def test_zero_length_is_an_empty_complete_frame(self):
        update = advance(payload=b'\x00\x00' + framed(header()))
        self.assertEqual(update.forward_frames, (b'', header()))
        self.assertIs(analyze_dns_message(update.forward_frames[0]).status, DNSMessageStatus.INCOMPLETE)
        self.assertIs(update.state.forward.status, DNSStreamStatus.READY)

    def test_maximum_legal_frame_spans_stream_reclamation(self):
        raw = message(opt(data=option(65535, b'x' * 65508)))
        self.assertEqual(len(raw), DNS_MAX_MESSAGE_BYTES)
        data = framed(raw)
        first = advance(payload=data[:32768])
        second = advance(first.state, data[32768:65536], 32868)
        self.assertEqual(len(second.state.forward.payload), 65534)
        self.assertEqual(second.state.forward.declared_length, 65535)
        self.assertEqual(second.forward_frames, ())
        final = advance(second.state, data[65536:], 65636)
        self.assertEqual(final.forward_frames, (raw,))
        self.assertGreater(final.state.forward.stream.buffer_offset, 0)
        self.assertLessEqual(final.state.forward.stream.payload_length, 65536)
        self.assertIs(analyze_dns_message(final.forward_frames[0]).status, DNSMessageStatus.COMPLETE)

    def test_one_above_parser_limit_is_not_encodable_in_two_bytes(self):
        self.assertEqual(DNS_MAX_MESSAGE_BYTES, 65535)
        with self.assertRaises(OverflowError):
            (DNS_MAX_MESSAGE_BYTES + 1).to_bytes(2, 'big')
        update = advance(payload=b'\xff\xff')
        self.assertEqual(update.state.forward.declared_length, DNS_MAX_MESSAGE_BYTES)
        self.assertEqual(update.state.forward.payload, b'')
        self.assertIs(update.state.forward.status, DNSStreamStatus.INCOMPLETE)

    def test_defensive_limit_guard_stops_before_body_under_injected_lower_limit(self):
        with patch('analysis.dns_stream_framing.DNS_MAX_MESSAGE_BYTES', 4):
            update = advance(payload=framed(b'ok') + b'\x00\x05' + b'x' * 100)
        value = update.state.forward
        self.assertEqual(update.forward_frames, (b'ok',))
        self.assertIs(value.status, DNSStreamStatus.UNAVAILABLE)
        self.assertIs(value.unavailable_reason, TCPStreamStatus.LIMIT_EXCEEDED)
        self.assertEqual((value.payload, value.consumed_offset), (b'', 6))
        after = advance(update.state, framed(b'ok'), 206)
        self.assertEqual(after.forward_frames, ())
        self.assertIs(after.state.forward.status, DNSStreamStatus.UNAVAILABLE)

    def test_payload_bytes_are_never_interpreted_by_framer(self):
        raws = (b'', b'\xff', header(1) + b'\x80', message(opt(data=b'\xff')))
        with patch('analysis.dns.analyze_dns_message', side_effect=AssertionError('framer parsed DNS')):
            update = advance(payload=b''.join(map(framed, raws)))
        self.assertEqual(update.forward_frames, raws)
        self.assertIs(update.state.forward.status, DNSStreamStatus.READY)

    def test_opposite_directions_keep_partial_frames_independent(self):
        for ipv6 in (False, True):
            request, response = framed(header()), framed(header(flags=0x8000))
            first = advance(payload=request[:1], ipv6=ipv6)
            second = advance(first.state, response[:5], 900, reverse=True, ipv6=ipv6)
            self.assertEqual((second.state.forward.prefix, second.state.reverse.payload), (request[:1], response[2:5]))
            third = advance(second.state, request[1:], 101, ipv6=ipv6)
            self.assertEqual((third.forward_frames, third.reverse_frames), ((header(),), ()))
            final = advance(third.state, response[5:], 905, reverse=True, ipv6=ipv6)
            self.assertEqual((final.forward_frames, final.reverse_frames), ((), (header(flags=0x8000),)))

    def test_empty_updates_and_retransmissions_do_not_reemit(self):
        raw = framed(header())
        first = advance(payload=raw)
        duplicate = advance(first.state, raw)
        self.assertEqual(duplicate.forward_frames, ())
        empty = advance(duplicate.state, b'', 100 + len(raw))
        self.assertEqual(empty.forward_frames, ())
        repeated = update_dns_stream_state(empty.state, empty.state.tcp_stream_state)
        self.assertEqual(repeated.forward_frames, ())

    def test_gap_is_sticky_and_preserves_previously_emitted_frames(self):
        first = advance(payload=framed(header()) + b'\x00')
        failed = advance(first.state, b'\x0c' + header(), 200)
        self.assertEqual(first.forward_frames, (header(),))
        self.assertIs(failed.state.forward.unavailable_reason, TCPStreamStatus.GAP)
        self.assertEqual(failed.forward_frames, ())
        self.assertEqual(failed.state.forward.prefix, b'\x00')
        retry = advance(failed.state, b'\x0c' + header(), 115)
        self.assertIs(retry.state.forward.status, DNSStreamStatus.UNAVAILABLE)
        self.assertEqual(retry.forward_frames, ())

    def test_conflict_and_partial_overlap_follow_existing_stream_failures(self):
        first = advance(payload=b'\x00\x0cabc')
        conflict = advance(first.state, b'xyz', 102)
        self.assertIs(conflict.state.forward.unavailable_reason, TCPStreamStatus.CONFLICT)
        overlap = advance(first.state, b'bcdef', 103)
        self.assertIs(overlap.state.forward.unavailable_reason, TCPStreamStatus.OVERLAP)

    def test_fin_and_reset_emit_complete_prefix_and_keep_incomplete_suffix(self):
        for flags, status in ((17, TCPStreamStatus.FIN), (20, TCPStreamStatus.RESET)):
            update = advance(payload=framed(header()) + b'\x00', flags=flags)
            self.assertEqual(update.forward_frames, (header(),))
            self.assertIs(update.state.forward.stream.status, status)
            self.assertIs(update.state.forward.status, DNSStreamStatus.INCOMPLETE)
            after = advance(update.state, b'\x0c' + header(), 115)
            self.assertIs(after.state.forward.unavailable_reason, TCPStreamStatus.AFTER_CLOSE)

    def test_syn_and_sequence_wraparound_use_existing_stream_coordinates(self):
        raw = framed(header())
        first = advance(payload=raw[:5], sequence=0xfffffffc, flags=2)
        final = advance(first.state, raw[5:], 2)
        self.assertEqual(final.forward_frames, (header(),))
        self.assertEqual(final.state.forward.consumed_offset, len(raw))

    def test_ipv6_fragment_failure_is_not_parsed_as_dns(self):
        update = advance(payload=framed(header()), ipv6=True, fragment=(0, True, 22))
        self.assertIs(update.state.forward.unavailable_reason, TCPStreamStatus.FRAGMENTED)
        self.assertEqual(update.forward_frames, ())

    def test_long_stream_consumption_has_no_complete_frame_history(self):
        raw = framed(b'x' * 1024)
        state = None
        for index in range(160):
            update = advance(state, raw, 100 + index * len(raw))
            self.assertEqual(update.forward_frames, (raw[2:],))
            state = update.state
            self.assertEqual(state.forward.payload, b'')
            self.assertLessEqual(state.forward.stream.payload_length, 65536)
            self.assertEqual(len(vars(state.forward)), 6)
        self.assertGreater(state.forward.stream.buffer_offset, 65536)

    def test_retained_framing_state_releases_source_packets_and_prior_updates(self):
        source = packet(framed(header()) + b'\x00')
        analyzed = analyze_packet(source)
        streams = update_tcp_stream_state(None, analyzed, flow_identity_from_packet(analyzed))
        update = update_dns_stream_state(None, streams)
        references = [weakref.ref(item) for item in (source, analyzed, streams, update)]
        state = update.state
        del source, analyzed, streams, update
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(state.forward.prefix, b'\x00')
        self.assertEqual(set(vars(state)), {'tcp_stream_state', 'forward', 'reverse'})

    def test_factory_only_frozen_public_values_and_exports(self):
        update = advance(payload=b'\x00')
        for model in (DNSStreamObservation, DNSStreamState, DNSStreamUpdate):
            self.assertIs(getattr(analysis, model.__name__), model)
            with self.assertRaises(TypeError):
                model()
        for value, name in ((update, 'state'), (update.state, 'forward'), (update.state.forward, 'prefix')):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, name, None)
        self.assertEqual(tuple(member.name for member in fields(update)), ('state', 'forward_frames', 'reverse_frames'))

    def test_invalid_types_identities_and_consumption_are_rejected(self):
        update = advance(payload=b'\x00')
        for current, streams in (({}, update.state.tcp_stream_state), (None, None)):
            with self.assertRaises(TypeError):
                update_dns_stream_state(current, streams)
        with self.assertRaises(ValueError):
            update_dns_stream_state(None, update.state.tcp_stream_state)
        other = advance(payload=b'\x00', client_port=12346)
        with self.assertRaises(ValueError):
            update_dns_stream_state(update.state, other.state.tcp_stream_state)
        with self.assertRaises(ValueError):
            update_dns_stream_state(update.state, replace(update.state.tcp_stream_state, forward=None))
        original = analyze_packet(packet(b'\x0c', sequence=101))
        streams = update_tcp_stream_state(update.state.tcp_stream_state, original, update.state.identity)
        stolen = replace(streams, forward=consume_tcp_stream(streams.forward, 1))
        with self.assertRaises(ValueError):
            update_dns_stream_state(update.state, stolen)

    def test_port_dispatch_preserves_existing_ldap_precedence(self):
        self.assertIsNone(advance(port=5353))
        self.assertIsNone(advance(client_port=389))
        self.assertIsNotNone(advance(client_port=636))

    def test_source_isolation_has_no_dns_parser_or_transport_reassembly(self):
        tree = ast.parse(Path('src/analysis/dns_stream_framing.py').read_text())
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imports, {'dataclasses', 'enum', 'typing', 'analysis.dns', 'analysis.flow_direction',
                                  'analysis.flow_identity', 'analysis.tcp_stream_observation'})
        dns_import, = [node for node in tree.body if isinstance(node, ast.ImportFrom) and node.module == 'analysis.dns']
        self.assertEqual([item.name for item in dns_import.names], ['DNS_MAX_MESSAGE_BYTES'])
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse(attributes & {'header', 'edns', 'questions', 'sequence_number', 'raw_bytes'})
