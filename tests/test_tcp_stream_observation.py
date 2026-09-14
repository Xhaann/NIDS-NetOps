import unittest
from dataclasses import FrozenInstanceError, fields, replace

import analysis
from analysis import (
    FlowDirection, FlowDirectionError, FlowIdentityError, TCP_STREAM_MAX_BYTES,
    TCPPayloadRelation, TCPStreamObservation, TCPStreamState, TCPStreamStatus,
    analyze_packet, flow_identity_from_packet, update_tcp_stream_state,
)
from tests.pcap_scenarios import frame, transport
from tests.protocol_scenarios import observation
from tests.test_packet_analysis import make_observation


def stream_observation(payload=b'', sequence=100, seconds=0, ipv6=False, reverse=False, flags=16,
                       options=b'', fragment=None):
    segment = transport(6, payload, ipv6, reverse, sequence=sequence, flags=flags, options=options)
    if fragment is not None and not ipv6:
        raw = make_observation(6, segment, fragment_field=0x2000).raw_bytes
    else:
        raw = frame(6, segment, ipv6, reverse, fragment=fragment)
    return observation(raw, seconds)


def stream_packet(*args, **kwargs):
    return analyze_packet(stream_observation(*args, **kwargs))


def stream_states(*packets):
    state = None
    results = []
    for packet in packets:
        state = update_tcp_stream_state(state, packet, flow_identity_from_packet(packet))
        results.append(state)
    return tuple(results)


class TCPStreamObservationTests(unittest.TestCase):
    def test_first_payload_retains_exact_identity_range_and_bytes(self):
        packet = stream_packet(b'abc', 100)
        identity = flow_identity_from_packet(packet)
        state = update_tcp_stream_state(None, packet, identity)
        stream = state.forward
        self.assertIs(state.identity, identity)
        self.assertIs(stream.identity, identity)
        self.assertIs(stream.direction, FlowDirection.FORWARD)
        self.assertEqual(stream.payload, b'abc')
        self.assertEqual(stream.contiguous_payload, b'abc')
        self.assertEqual((stream.start_sequence, stream.end_sequence, stream.next_sequence), (100, 103, 103))
        self.assertEqual((stream.last_sequence_number, stream.last_payload_sequence, stream.last_payload_length), (100, 100, 3))
        self.assertIsNone(stream.last_sequence_delta)
        self.assertIsNone(stream.syn_sequence)
        self.assertIs(stream.last_relation, TCPPayloadRelation.FIRST)
        self.assertIs(stream.status, TCPStreamStatus.OPEN)
        self.assertIsNone(state.reverse)

    def test_multiple_contiguous_observations_preserve_byte_order_and_previous_states(self):
        states = stream_states(stream_packet(b'ab', 10), stream_packet(b'cde', 12), stream_packet(b'fg', 15))
        self.assertEqual(tuple(s.forward.payload for s in states), (b'ab', b'abcde', b'abcdefg'))
        self.assertEqual(tuple(s.forward.next_sequence for s in states), (12, 15, 17))
        self.assertEqual(tuple(s.forward.last_sequence_delta for s in states), (None, 0, 0))
        self.assertEqual(tuple(s.forward.last_relation for s in states),
                         (TCPPayloadRelation.FIRST, TCPPayloadRelation.CONTIGUOUS, TCPPayloadRelation.CONTIGUOUS))
        self.assertTrue(all(s.forward.start_sequence == 10 for s in states))
        self.assertIs(states[2].identity, states[0].identity)

    def test_opposite_directions_have_independent_sequence_spaces_and_buffers(self):
        states = stream_states(stream_packet(b'ab', 10), stream_packet(b'XY', 900, reverse=True),
                               stream_packet(b'cd', 12), stream_packet(b'Z', 902, reverse=True))
        final = states[-1]
        self.assertEqual((final.forward.payload, final.reverse.payload), (b'abcd', b'XYZ'))
        self.assertEqual((final.forward.next_sequence, final.reverse.next_sequence), (14, 903))
        self.assertIs(final.reverse.direction, FlowDirection.REVERSE)
        self.assertIs(states[1].forward, states[0].forward)
        self.assertIs(states[2].reverse, states[1].reverse)

    def test_gap_is_sticky_even_when_missing_bytes_arrive_later(self):
        states = stream_states(stream_packet(b'ab', 10), stream_packet(b'ef', 14),
                               stream_packet(b'cd', 12), stream_packet(b'gh', 16))
        self.assertIs(states[1].forward.last_relation, TCPPayloadRelation.GAP)
        self.assertEqual(states[1].forward.last_sequence_delta, 2)
        for state in states[1:]:
            self.assertIs(state.forward.status, TCPStreamStatus.GAP)
            self.assertEqual((state.forward.payload, state.forward.next_sequence), (b'ab', 12))
            self.assertIsNone(state.forward.contiguous_payload)
        self.assertIs(states[-1].forward.last_relation, TCPPayloadRelation.UNAVAILABLE)
        self.assertEqual(states[-1].forward.last_payload_sequence, 16)

    def test_exact_and_contained_retransmissions_never_duplicate_payload(self):
        states = stream_states(stream_packet(b'ab', 10), stream_packet(b'cd', 12),
                               stream_packet(b'abcd', 10), stream_packet(b'bc', 11), stream_packet(b'ef', 14))
        for state, delta in zip(states[2:4], (-4, -3)):
            self.assertIs(state.forward.last_relation, TCPPayloadRelation.DUPLICATE)
            self.assertIs(state.forward.status, TCPStreamStatus.OPEN)
            self.assertEqual(state.forward.last_sequence_delta, delta)
            self.assertIs(state.forward.payload, states[1].forward.payload)
            self.assertEqual(state.forward.next_sequence, 14)
        self.assertEqual(states[-1].forward.payload, b'abcdef')

    def test_matching_partial_overlap_is_unavailable_without_appending_suffix(self):
        first, overlap, later = stream_states(stream_packet(b'abcd', 10), stream_packet(b'cdef', 12), stream_packet(b'ef', 14))
        self.assertIs(overlap.forward.last_relation, TCPPayloadRelation.OVERLAP)
        self.assertIs(overlap.forward.status, TCPStreamStatus.OVERLAP)
        self.assertEqual(overlap.forward.last_sequence_delta, -2)
        self.assertIs(overlap.forward.payload, first.forward.payload)
        self.assertIsNone(overlap.forward.contiguous_payload)
        self.assertEqual(later.forward.payload, b'abcd')
        self.assertIs(later.forward.status, TCPStreamStatus.OVERLAP)

    def test_conflicting_contained_and_partial_overlaps_do_not_choose_bytes(self):
        for payload, sequence in ((b'zz', 11), (b'zdef', 12), (b'zbcd', 10)):
            first, conflict = stream_states(stream_packet(b'abcd', 10), stream_packet(payload, sequence))
            self.assertIs(conflict.forward.status, TCPStreamStatus.CONFLICT)
            self.assertIs(conflict.forward.last_relation, TCPPayloadRelation.OVERLAP)
            self.assertIs(conflict.forward.payload, first.forward.payload)
            self.assertIsNone(conflict.forward.contiguous_payload)
            self.assertEqual(conflict.forward.next_sequence, 14)

    def test_ranges_before_capture_prefix_are_not_prepended(self):
        for payload, sequence in ((b'xyab', 8), (b'xy', 5)):
            state = stream_states(stream_packet(b'abcd', 10), stream_packet(payload, sequence))[-1]
            self.assertIs(state.forward.status, TCPStreamStatus.OVERLAP)
            self.assertEqual((state.forward.start_sequence, state.forward.payload, state.forward.next_sequence), (10, b'abcd', 14))
            self.assertIsNone(state.forward.contiguous_payload)

    def test_sequence_wraparound_preserves_contiguity_and_duplicate_ranges(self):
        states = stream_states(stream_packet(b'ab', 0xFFFFFFFE), stream_packet(b'cd', 0),
                               stream_packet(b'bc', 0xFFFFFFFF), stream_packet(b'ef', 2))
        self.assertEqual(tuple(s.forward.next_sequence for s in states), (0, 2, 2, 4))
        self.assertIs(states[2].forward.last_relation, TCPPayloadRelation.DUPLICATE)
        self.assertEqual(states[2].forward.last_sequence_delta, -3)
        self.assertEqual(states[-1].forward.payload, b'abcdef')
        self.assertEqual(states[-1].forward.end_sequence, 4)

    def test_half_sequence_space_jump_is_explicitly_ambiguous(self):
        states = stream_states(stream_packet(b'ab', 10), stream_packet(b'c', 12 + (1 << 31)), stream_packet(b'c', 12))
        self.assertIs(states[1].forward.status, TCPStreamStatus.AMBIGUOUS)
        self.assertIs(states[1].forward.last_relation, TCPPayloadRelation.AMBIGUOUS)
        self.assertIsNone(states[1].forward.last_sequence_delta)
        self.assertIsNone(states[-1].forward.contiguous_payload)
        self.assertEqual(states[-1].forward.payload, b'ab')

    def test_empty_ack_does_not_anchor_or_advance_application_sequence(self):
        states = stream_states(stream_packet(b'', 500), stream_packet(b'ab', 10),
                               stream_packet(b'', 900), stream_packet(b'cd', 12))
        self.assertEqual(states[0].forward.payload, b'')
        self.assertIsNone(states[0].forward.start_sequence)
        self.assertIsNone(states[0].forward.next_sequence)
        self.assertIs(states[0].forward.last_relation, TCPPayloadRelation.EMPTY)
        self.assertIs(states[2].forward.last_relation, TCPPayloadRelation.EMPTY)
        self.assertEqual(states[2].forward.next_sequence, 12)
        self.assertEqual(states[-1].forward.payload, b'abcd')

    def test_syn_only_anchors_next_payload_and_consumes_one_sequence_number(self):
        states = stream_states(stream_packet(b'', 0xFFFFFFFF, flags=2),
                               stream_packet(b'', 0xFFFFFFFF, flags=2), stream_packet(b'ab', 0))
        for state in states[:2]:
            self.assertEqual((state.forward.payload, state.forward.next_sequence, state.forward.syn_sequence), (b'', 0, 0xFFFFFFFF))
            self.assertIsNone(state.forward.start_sequence)
            self.assertIs(state.forward.last_relation, TCPPayloadRelation.EMPTY)
        self.assertIs(states[-1].forward.last_relation, TCPPayloadRelation.FIRST)
        self.assertEqual(states[-1].forward.last_sequence_delta, 0)
        self.assertEqual(states[-1].forward.payload, b'ab')
        gap = stream_states(stream_packet(b'', 10, flags=2), stream_packet(b'ab', 12))[-1]
        self.assertIs(gap.forward.status, TCPStreamStatus.GAP)
        self.assertEqual(gap.forward.payload, b'')

    def test_syn_payload_retransmission_and_unexpected_syn_are_distinct(self):
        states = stream_states(stream_packet(b'ab', 10, flags=2), stream_packet(b'ab', 10, flags=2), stream_packet(b'cd', 13))
        self.assertEqual((states[0].forward.start_sequence, states[0].forward.next_sequence), (11, 13))
        self.assertIs(states[1].forward.last_relation, TCPPayloadRelation.DUPLICATE)
        self.assertEqual(states[-1].forward.payload, b'abcd')
        for packet in (stream_packet(b'', 50, flags=2), stream_packet(b'xx', 50, flags=2)):
            state = stream_states(stream_packet(b'ab', 10), packet)[-1]
            self.assertIs(state.forward.status, TCPStreamStatus.RESTART)
            self.assertEqual(state.forward.payload, b'ab')
            self.assertIsNone(state.forward.contiguous_payload)

    def test_fin_only_closes_direction_without_application_bytes(self):
        states = stream_states(stream_packet(b'ab', 10), stream_packet(b'', 12, flags=17), stream_packet(b'cd', 13))
        self.assertIs(states[1].forward.status, TCPStreamStatus.FIN)
        self.assertIs(states[1].forward.last_relation, TCPPayloadRelation.EMPTY)
        self.assertEqual((states[1].forward.payload, states[1].forward.end_sequence, states[1].forward.next_sequence), (b'ab', 12, 13))
        self.assertIsNone(states[-1].forward.contiguous_payload)
        self.assertIs(states[-1].forward.status, TCPStreamStatus.AFTER_CLOSE)
        self.assertIs(states[-1].forward.last_relation, TCPPayloadRelation.UNAVAILABLE)
        first = stream_states(stream_packet(b'', 10, flags=1))[0].forward
        self.assertEqual((first.payload, first.next_sequence), (b'', 11))
        self.assertIsNone(first.start_sequence)

    def test_payload_after_fin_or_reset_cannot_reopen_or_silently_resolve_conflicts(self):
        for flags in (17, 20):
            for payload in (b'ab', b'zz'):
                states = stream_states(stream_packet(b'ab', 10, flags=flags),
                                       stream_packet(payload, 10), stream_packet(b'', 12))
                self.assertEqual(states[0].forward.contiguous_payload, b'ab')
                for state in states[1:]:
                    self.assertIs(state.forward.status, TCPStreamStatus.AFTER_CLOSE)
                    self.assertEqual(state.forward.payload, b'ab')
                    self.assertIsNone(state.forward.contiguous_payload)

    def test_fin_at_unobserved_frontier_cannot_imply_missing_bytes(self):
        for sequence, status in ((14, TCPStreamStatus.GAP), (11, TCPStreamStatus.OVERLAP)):
            state = stream_states(stream_packet(b'ab', 10), stream_packet(b'', sequence, flags=1))[-1].forward
            self.assertIs(state.status, status)
            self.assertEqual((state.payload, state.next_sequence), (b'ab', 12))
            self.assertIsNone(state.contiguous_payload)

    def test_rst_only_freezes_direction_without_consuming_sequence_space(self):
        states = stream_states(stream_packet(b'ab', 10), stream_packet(b'', 12, flags=4), stream_packet(b'cd', 12))
        self.assertIs(states[1].forward.status, TCPStreamStatus.RESET)
        self.assertIs(states[1].forward.last_relation, TCPPayloadRelation.EMPTY)
        self.assertEqual((states[-1].forward.payload, states[-1].forward.next_sequence), (b'ab', 12))
        first = stream_states(stream_packet(b'', 10, flags=4))[0].forward
        self.assertEqual(first.payload, b'')
        self.assertIsNone(first.next_sequence)

    def test_payload_with_fin_rst_or_ack_retains_exact_data_and_control_offsets(self):
        for flags, status, next_sequence in ((17, TCPStreamStatus.FIN, 13), (20, TCPStreamStatus.RESET, 12), (16, TCPStreamStatus.OPEN, 12)):
            stream = stream_states(stream_packet(b'ab', 10, flags=flags))[0].forward
            self.assertEqual((stream.payload, stream.start_sequence, stream.end_sequence, stream.next_sequence), (b'ab', 10, 12, next_sequence))
            self.assertIs(stream.status, status)
            self.assertIs(stream.last_relation, TCPPayloadRelation.FIRST)

    def test_exact_capacity_duplicate_and_overflow_are_bounded_and_sticky(self):
        chunks = (b'a' * 32768, b'b' * 32768)
        states = stream_states(stream_packet(chunks[0], 0), stream_packet(chunks[1], 32768),
                               stream_packet(chunks[1], 32768), stream_packet(b'x', TCP_STREAM_MAX_BYTES),
                               stream_packet(b'y' * 30000, TCP_STREAM_MAX_BYTES))
        self.assertEqual(states[1].forward.payload, chunks[0] + chunks[1])
        self.assertEqual(states[1].forward.payload_length, TCP_STREAM_MAX_BYTES)
        self.assertIs(states[1].forward.status, TCPStreamStatus.OPEN)
        self.assertIs(states[2].forward.last_relation, TCPPayloadRelation.DUPLICATE)
        for state in states[3:]:
            self.assertIs(state.forward.status, TCPStreamStatus.LIMIT_EXCEEDED)
            self.assertIs(state.forward.payload, states[1].forward.payload)
            self.assertEqual(state.forward.next_sequence, TCP_STREAM_MAX_BYTES)
            self.assertIsNone(state.forward.contiguous_payload)

    def test_oversized_supplied_tcp_model_does_not_copy_or_truncate_to_valid_stream(self):
        packet = stream_packet()
        packet = replace(packet, tcp=replace(packet.tcp, payload=b'x' * (TCP_STREAM_MAX_BYTES + 1)))
        state = stream_states(packet)[0].forward
        self.assertIs(state.status, TCPStreamStatus.LIMIT_EXCEEDED)
        self.assertEqual(state.last_payload_length, TCP_STREAM_MAX_BYTES + 1)
        self.assertEqual(state.payload, b'')
        self.assertIsNone(state.next_sequence)
        self.assertIsNone(state.contiguous_payload)

    def test_initial_ip_fragments_cannot_supply_stream_continuity(self):
        for ipv6 in (False, True):
            packets = (stream_packet(b'ab', 10, ipv6=ipv6),
                       stream_packet(b'cd', 12, ipv6=ipv6, fragment=(0, True)),
                       stream_packet(b'ef', 14, ipv6=ipv6))
            states = stream_states(*packets)
            self.assertIs(states[1].forward.status, TCPStreamStatus.FRAGMENTED)
            self.assertEqual(states[-1].forward.payload, b'ab')
            self.assertIsNone(states[-1].forward.contiguous_payload)
        atomic = stream_states(stream_packet(b'ab', 10, ipv6=True, fragment=(0, False)))[0]
        self.assertEqual(atomic.forward.contiguous_payload, b'ab')

    def test_public_contracts_are_immutable_and_validate_identity_direction_and_types(self):
        packet = stream_packet(b'ab')
        state = stream_states(packet)[0]
        for value in (state, state.forward):
            hash(value)
            for field in fields(value):
                with self.assertRaises(FrozenInstanceError):
                    setattr(value, field.name, None)
        with self.assertRaises(TypeError):
            TCPStreamObservation()
        for changes, error in (({'identity': None}, TypeError), ({'forward': object()}, TypeError),
                               ({'reverse': state.forward}, ValueError),
                               ({'identity': replace(state.identity, source_port=12346)}, ValueError),
                               ({'identity': replace(state.identity, protocol=17)}, ValueError)):
            with self.assertRaises(error):
                replace(state, **changes)
        for args, error in (((None, None, state.identity), TypeError), ((None, packet, None), TypeError),
                            ((object(), packet, state.identity), TypeError),
                            ((None, packet, replace(state.identity, protocol=17)), ValueError),
                            ((None, packet, replace(state.identity, source_port=12346)), FlowDirectionError),
                            ((state, stream_packet(ipv6=True), flow_identity_from_packet(stream_packet(ipv6=True))), ValueError),
                            ((None, replace(packet, tcp=None), state.identity), FlowIdentityError)):
            with self.assertRaises(error):
                update_tcp_stream_state(*args)
        for name in ('TCP_STREAM_MAX_BYTES', 'TCPStreamObservation', 'TCPStreamState', 'TCPStreamStatus',
                     'TCPPayloadRelation', 'update_tcp_stream_state'):
            self.assertIn(name, analysis.__all__)
            self.assertIsNotNone(getattr(analysis, name))


if __name__ == '__main__':
    unittest.main()
