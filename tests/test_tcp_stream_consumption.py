import unittest
from dataclasses import replace

from analysis import (
    TCP_STREAM_MAX_BYTES, TCPPayloadRelation, TCPStreamStatus, consume_tcp_stream,
    flow_identity_from_packet, update_tcp_stream_state,
)
from tests.test_tcp_stream_observation import stream_packet, stream_states


class TCPStreamConsumptionTests(unittest.TestCase):
    def test_consumption_advances_only_cursor_and_preserves_sequence_and_published_bytes(self):
        stream = stream_states(stream_packet(b'abcdef', 100))[0].forward
        consumed = consume_tcp_stream(stream, 4)
        self.assertIs(consumed.payload, stream.payload)
        self.assertEqual(consumed.unconsumed_payload, b'ef')
        self.assertEqual((consumed.buffer_offset, consumed.consumed_length, consumed.consumed_offset), (0, 4, 4))
        self.assertEqual((consumed.start_sequence, consumed.end_sequence, consumed.next_sequence), (100, 106, 106))
        self.assertEqual(stream.unconsumed_payload, b'abcdef')
        self.assertIs(consume_tcp_stream(consumed, 0), consumed)
        self.assertEqual(consume_tcp_stream(consumed, 2).unconsumed_payload, b'')

    def test_retransmission_before_reclamation_uses_existing_byte_comparison(self):
        state = stream_states(stream_packet(b'abcdef', 100))[0]
        state = replace(state, forward=consume_tcp_stream(state.forward, 4))
        packet = stream_packet(b'abcdef', 100)
        repeated = update_tcp_stream_state(state, packet, state.identity)
        self.assertIs(repeated.forward.last_relation, TCPPayloadRelation.DUPLICATE)
        self.assertEqual(repeated.forward.unconsumed_payload, b'ef')
        self.assertEqual(repeated.forward.consumed_offset, 4)
        conflict = update_tcp_stream_state(state, stream_packet(b'xbcdef', 100), state.identity)
        self.assertIs(conflict.forward.status, TCPStreamStatus.CONFLICT)
        self.assertIsNone(conflict.forward.unconsumed_payload)

    def test_capacity_reclaims_only_consumed_bytes_and_preserves_pending_suffix(self):
        first = stream_packet(b'a' * 32768, 0)
        second = stream_packet(b'b' * 32768, 32768)
        state = stream_states(first, second)[-1]
        before = state.forward
        state = replace(state, forward=consume_tcp_stream(before, 32768))
        updated = update_tcp_stream_state(state, stream_packet(b'c' * 32768, 65536), state.identity)
        stream = updated.forward
        self.assertEqual(stream.payload, b'b' * 32768 + b'c' * 32768)
        self.assertEqual((stream.buffer_offset, stream.consumed_length, stream.consumed_offset), (32768, 0, 32768))
        self.assertEqual((stream.start_sequence, stream.next_sequence), (32768, 98304))
        self.assertEqual(len(before.payload), TCP_STREAM_MAX_BYTES)
        self.assertEqual(before.payload[:32768], b'a' * 32768)

    def test_evicted_retransmission_is_unavailable_without_reconstruction(self):
        state = stream_states(stream_packet(b'a' * 32768, 0), stream_packet(b'b' * 32768, 32768))[-1]
        state = replace(state, forward=consume_tcp_stream(state.forward, 65536))
        updated = update_tcp_stream_state(state, stream_packet(b'new', 65536), state.identity)
        old = update_tcp_stream_state(updated, stream_packet(b'old', 0), state.identity)
        self.assertIs(old.forward.status, TCPStreamStatus.OVERLAP)
        self.assertIsNone(old.forward.unconsumed_payload)
        self.assertEqual(old.forward.payload, b'new')

    def test_unconsumed_bytes_cannot_be_evicted_to_accept_oversized_append(self):
        state = stream_states(stream_packet(b'a' * 32768, 0), stream_packet(b'b' * 32768, 32768))[-1]
        state = replace(state, forward=consume_tcp_stream(state.forward, 1))
        result = update_tcp_stream_state(state, stream_packet(b'cc', 65536), state.identity).forward
        self.assertIs(result.status, TCPStreamStatus.LIMIT_EXCEEDED)
        self.assertEqual(result.consumed_offset, 1)
        self.assertEqual(result.payload, b'a' * 32767 + b'b' * 32768)
        self.assertEqual(result.next_sequence, 65536)
        self.assertIsNone(result.unconsumed_payload)

    def test_consumption_and_reclamation_preserve_wraparound_and_syn_fin_offsets(self):
        packet = stream_packet(b'ab', 0xFFFFFFFD, flags=2)
        state = stream_states(packet)[0]
        state = replace(state, forward=consume_tcp_stream(state.forward, 2))
        next_packet = stream_packet(b'cd', 0, flags=17)
        state = update_tcp_stream_state(state, next_packet, flow_identity_from_packet(next_packet))
        stream = consume_tcp_stream(state.forward, 2)
        self.assertEqual((stream.start_sequence, stream.end_sequence, stream.next_sequence), (0xFFFFFFFE, 2, 3))
        self.assertEqual(stream.consumed_offset, 4)
        self.assertEqual(stream.unconsumed_payload, b'')
        self.assertIs(stream.status, TCPStreamStatus.FIN)

    def test_invalid_consumption_is_rejected_without_mutation(self):
        stream = stream_states(stream_packet(b'ab', 100))[0].forward
        for count, error in ((True, TypeError), ('1', TypeError), (-1, ValueError), (3, ValueError)):
            with self.assertRaises(error):
                consume_tcp_stream(stream, count)
        with self.assertRaises(TypeError):
            consume_tcp_stream(None, 0)
        unavailable = stream_states(stream_packet(b'ab', 100), stream_packet(b'cd', 104))[-1].forward
        with self.assertRaises(ValueError):
            consume_tcp_stream(unavailable, 0)
        self.assertEqual(stream.unconsumed_payload, b'ab')


if __name__ == '__main__':
    unittest.main()
