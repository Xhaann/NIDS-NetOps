import unittest
from dataclasses import FrozenInstanceError, fields
from unittest.mock import patch

import analysis
from analysis import (
    FlowStateCoordinator, LDAPMessageStatus, LDAPStreamObservation, LDAPStreamState,
    LDAPStreamStatus, TCP_STREAM_MAX_BYTES, TCPStreamState, TCPStreamStatus,
    analyze_ldap_payload, analyze_packet, update_ldap_stream_state,
)
from analysis import ldap_stream_framing
from tests.test_ldap import OPERATIONS, envelope, message
from tests.test_ldap_flow_statistics import ldap_observation


def framing_packet(payload, sequence=100, seconds=0, ipv6=False, reverse=False):
    return analyze_packet(ldap_observation(payload, seconds, ipv6, reverse, sequence=sequence))


def framing_states(payloads, ipv6=False):
    coordinator = FlowStateCoordinator()
    sequence = 100
    states = []
    for index, payload in enumerate(payloads):
        states.append(coordinator.record(framing_packet(payload, sequence, index, ipv6)))
        sequence += len(payload)
    return tuple(states)


class LDAPStreamFramingTests(unittest.TestCase):
    def test_single_message_preserves_packet_parser_metadata_and_consumes_exact_boundary(self):
        raw = message(0x60, OPERATIONS[0][2])
        packet = framing_packet(raw)
        state = FlowStateCoordinator().record(packet)
        framed = state.ldap_stream_state.forward
        self.assertEqual(framed.messages, packet.ldap.messages)
        self.assertEqual(framed.messages[0].offset, 0)
        self.assertEqual(framed.messages[0].message_length, len(raw))
        self.assertEqual(framed.consumed_offset, len(raw))
        self.assertEqual(framed.retained_suffix, b'')
        self.assertIsNone(framed.pending_message)
        self.assertIs(framed.status, LDAPStreamStatus.READY)
        self.assertEqual(framed.complete_message_count, 1)
        self.assertIs(state.ldap_stream_state.tcp_stream_state, state.tcp_stream_state)
        self.assertIs(framed.stream, state.tcp_stream_state.forward)

    def test_multiple_messages_preserve_order_offsets_lengths_and_repeated_identifiers(self):
        packets = (message(0x60, b'opaque'), message(0x63), message(0x4A, b'cn=x'))
        framed = framing_states((b''.join(packets),))[0].ldap_stream_state.forward
        self.assertEqual([m.operation_tag for m in framed.messages], [0x60, 0x63, 0x4A])
        self.assertEqual([m.offset for m in framed.messages], [0, len(packets[0]), len(packets[0] + packets[1])])
        self.assertEqual([m.message_length for m in framed.messages], [len(p) for p in packets])
        self.assertEqual([m.message_id for m in framed.messages], [1, 1, 1])
        self.assertEqual(framed.consumed_offset, sum(map(len, packets)))
        self.assertEqual(framed.retained_suffix, b'')

    def test_all_existing_operation_identification_and_controls_remain_equivalent(self):
        controls = envelope(0xA0, envelope(0x30, envelope(4, b'1.2.3')))
        raw = b''.join(message(tag, body, controls=controls) for tag, _, body in OPERATIONS)
        framed = framing_states((raw,))[0].ldap_stream_state.forward
        self.assertEqual(framed.messages, analyze_ldap_payload(raw).messages)
        self.assertTrue(all(m.controls_present for m in framed.messages))
        self.assertEqual(framed.complete_message_count, len(OPERATIONS))

    def test_message_split_across_two_or_many_observations_retains_suffix_until_complete(self):
        raw = message(0x60, OPERATIONS[0][2])
        for chunks in ((raw[:6], raw[6:]), (raw[:1], raw[1:2], raw[2:5], raw[5:8], raw[8:])):
            states = framing_states(chunks)
            prefix = b''
            for chunk, state in zip(chunks[:-1], states[:-1]):
                prefix += chunk
                framed = state.ldap_stream_state.forward
                self.assertEqual(framed.retained_suffix, prefix)
                self.assertEqual(framed.consumed_offset, 0)
                self.assertEqual(framed.messages, ())
                self.assertIs(framed.status, LDAPStreamStatus.INCOMPLETE)
                self.assertIs(framed.pending_message.status, LDAPMessageStatus.INCOMPLETE)
            final = states[-1].ldap_stream_state.forward
            self.assertEqual(final.messages, analyze_ldap_payload(raw).messages)
            self.assertEqual(final.retained_suffix, b'')
            self.assertEqual(final.complete_message_count, 1)

    def test_complete_messages_then_partial_suffix_emit_only_new_boundaries_on_completion(self):
        first, second, third = message(), message(0x63), message(0x60, b'abcdefgh')
        states = framing_states((first + second + third[:5], third[5:8], third[8:]))
        initial = states[0].ldap_stream_state.forward
        self.assertEqual([m.offset for m in initial.messages], [0, len(first)])
        self.assertEqual(initial.consumed_offset, len(first + second))
        self.assertEqual(initial.retained_suffix, third[:5])
        self.assertEqual(initial.pending_message.offset, len(first + second))
        self.assertEqual(states[1].ldap_stream_state.forward.messages, ())
        final = states[-1].ldap_stream_state.forward
        self.assertEqual([m.offset for m in final.messages], [len(first + second)])
        self.assertEqual(final.messages[0].message_length, len(third))
        self.assertEqual(final.consumed_offset, len(first + second + third))
        self.assertEqual(final.complete_message_count, 3)
        self.assertEqual(initial.retained_suffix, third[:5])

    def test_long_declared_length_remains_incomplete_without_allocation_or_reparsing_body(self):
        raw = message(0x4A, b'x' * 1000)
        with patch.object(ldap_stream_framing, '_message', wraps=ldap_stream_framing._message) as parse:
            states = framing_states((raw[:11],) + tuple(raw[i:i + 1] for i in range(11, len(raw))))
        self.assertEqual(parse.call_count, 2)
        self.assertIs(states[0].ldap_stream_state.forward.status, LDAPStreamStatus.INCOMPLETE)
        self.assertEqual(states[0].ldap_stream_state.forward.pending_message.message_length, len(raw))
        self.assertEqual(states[-1].ldap_stream_state.forward.complete_message_count, 1)

    def test_newly_available_malformed_nested_length_is_not_hidden_by_partial_outer_body(self):
        raw = b'\x30\x20\x02\x01\x01\x60\xff'
        states = framing_states((raw[:2], raw[2:]))
        self.assertIs(states[0].ldap_stream_state.forward.status, LDAPStreamStatus.INCOMPLETE)
        final = states[-1].ldap_stream_state.forward
        self.assertIs(final.status, LDAPStreamStatus.MALFORMED)
        self.assertEqual(final.pending_message, analyze_ldap_payload(raw).messages[0])
        self.assertEqual(final.retained_suffix, raw)

    def test_consumed_messages_are_not_reparsed_on_later_payload_or_empty_observations(self):
        raws = tuple(message(tag) for tag in (0x60, 0x63, 0x42))
        with patch.object(ldap_stream_framing, '_message', wraps=ldap_stream_framing._message) as parse:
            states = framing_states((raws[0], b'', raws[1], b'', raws[2], b''))
        self.assertEqual(parse.call_count, 3)
        self.assertEqual([call.args[1] + call.args[3] for call in parse.call_args_list],
                         [0, len(raws[0]), len(raws[0] + raws[1])])
        self.assertEqual([len(s.ldap_stream_state.forward.messages) for s in states], [1, 0, 1, 0, 1, 0])
        self.assertEqual(states[-1].ldap_stream_state.forward.complete_message_count, 3)

    def test_malformed_length_and_inner_structure_stop_without_any_resynchronization(self):
        for malformed in (b'\x30\xff', b'\x30\x02\x02\x00', message(controls=b'\xa0\x7f')):
            raw = malformed + message()
            states = framing_states((raw, message()))
            for state in states:
                framed = state.ldap_stream_state.forward
                self.assertIs(framed.status, LDAPStreamStatus.MALFORMED)
                self.assertEqual(framed.messages, ())
                self.assertEqual(framed.consumed_offset, 0)
                self.assertEqual(framed.malformed_message_count, 1)
                self.assertIs(framed.pending_message.status, LDAPMessageStatus.MALFORMED)
            self.assertEqual(states[0].ldap_stream_state.forward.retained_suffix, raw)
            self.assertEqual(states[-1].ldap_stream_state.forward.retained_suffix, raw + message())

    def test_complete_unsupported_and_malformed_boundaries_preserve_exact_stop_offset(self):
        first, unknown, malformed = message(), message(0x7A, b'opaque'), b'\x30\xff'
        state = framing_states((first + unknown + malformed + message(),))[0].ldap_stream_state.forward
        self.assertEqual([m.status for m in state.messages], [LDAPMessageStatus.COMPLETE, LDAPMessageStatus.UNSUPPORTED])
        self.assertEqual([m.offset for m in state.messages], [0, len(first)])
        self.assertEqual(state.pending_message.offset, len(first + unknown))
        self.assertEqual(state.retained_suffix, malformed + message())
        self.assertEqual((state.complete_message_count, state.unsupported_message_count, state.malformed_message_count), (1, 1, 1))

    def test_unsupported_bounded_frames_allow_next_message_and_unbounded_encodings_stop(self):
        unknown = message(0x7A, b'opaque')
        framed = framing_states((unknown + message(),))[0].ldap_stream_state.forward
        self.assertEqual([m.status for m in framed.messages], [LDAPMessageStatus.UNSUPPORTED, LDAPMessageStatus.COMPLETE])
        self.assertEqual(framed.messages[1].offset, len(unknown))
        self.assertEqual(framed.retained_suffix, b'')
        for raw in (b'\x30\x80', b'\x30\x85', b'\x30\x84\xff\xff\xff\xff'):
            states = framing_states((raw, message()))
            for state in states:
                current = state.ldap_stream_state.forward
                self.assertIs(current.status, LDAPStreamStatus.UNSUPPORTED)
                self.assertEqual(current.consumed_offset, 0)
                self.assertEqual(current.messages, ())
                self.assertEqual(current.unsupported_message_count, 1)

    def test_wrong_tag_after_established_boundary_is_not_skipped(self):
        raw = message()
        state = framing_states((raw, b'not-ldap' + raw))[-1].ldap_stream_state.forward
        self.assertIs(state.status, LDAPStreamStatus.MALFORMED)
        self.assertEqual(state.consumed_offset, len(raw))
        self.assertEqual(state.pending_message.offset, len(raw))
        self.assertEqual(state.complete_message_count, 1)
        self.assertEqual(state.retained_suffix, b'not-ldap' + raw)

    def test_partial_unsupported_inner_structure_waits_for_its_known_outer_boundary(self):
        unsupported = envelope(0x30, b'\x02\x01\x01\x7f\x01\x00opaque')
        with patch.object(ldap_stream_framing, '_message', wraps=ldap_stream_framing._message) as parse:
            states = framing_states((unsupported[:6], unsupported[6:8], unsupported[8:] + message()))
        self.assertEqual(parse.call_count, 3)
        for state in states[:-1]:
            current = state.ldap_stream_state.forward
            self.assertIs(current.status, LDAPStreamStatus.INCOMPLETE)
            self.assertIs(current.pending_message.status, LDAPMessageStatus.UNSUPPORTED)
            self.assertEqual(current.pending_message.message_length, len(unsupported))
            self.assertEqual(current.consumed_offset, 0)
            self.assertEqual(current.unsupported_message_count, 0)
        final = states[-1].ldap_stream_state.forward
        self.assertEqual([m.status for m in final.messages], [LDAPMessageStatus.UNSUPPORTED, LDAPMessageStatus.COMPLETE])
        self.assertEqual([m.offset for m in final.messages], [0, len(unsupported)])
        self.assertEqual(final.unsupported_message_count, 1)
        self.assertEqual(final.consumed_offset, len(unsupported + message()))
        self.assertEqual(final.retained_suffix, b'')

    def test_many_small_messages_reclaim_consumed_storage_and_keep_absolute_offsets(self):
        raw = message()
        block = raw * 512
        coordinator = FlowStateCoordinator()
        count = 0
        reclaimed = False
        for index in range(80):
            state = coordinator.record(framing_packet(block, 100 + index * len(block), index))
            framed = state.ldap_stream_state.forward
            self.assertEqual([m.offset for m in framed.messages], list(range(count * len(raw), (count + 512) * len(raw), len(raw))))
            self.assertTrue(all(m.message_length == len(raw) for m in framed.messages))
            count += 512
            self.assertEqual(framed.complete_message_count, count)
            self.assertEqual(framed.consumed_offset, count * len(raw))
            self.assertEqual(framed.retained_suffix, b'')
            self.assertLessEqual(len(framed.stream.payload), TCP_STREAM_MAX_BYTES)
            self.assertIs(framed.stream.status, TCPStreamStatus.OPEN)
            reclaimed = reclaimed or framed.stream.buffer_offset > 0
        self.assertTrue(reclaimed)
        self.assertEqual(len(framed.messages), 512)
        self.assertGreater(framed.consumed_offset, TCP_STREAM_MAX_BYTES * 4)

    def test_maximum_sized_message_completes_and_leaves_room_for_later_message(self):
        raw = message(0x4A, b'x' * (TCP_STREAM_MAX_BYTES - 11))
        self.assertEqual(len(raw), TCP_STREAM_MAX_BYTES)
        states = framing_states((raw[:32768], raw[32768:], message()))
        self.assertIs(states[0].ldap_stream_state.forward.status, LDAPStreamStatus.INCOMPLETE)
        self.assertEqual(states[1].ldap_stream_state.forward.messages[0].message_length, TCP_STREAM_MAX_BYTES)
        final = states[-1].ldap_stream_state.forward
        self.assertEqual(final.messages[0].offset, TCP_STREAM_MAX_BYTES)
        self.assertEqual(final.consumed_offset, TCP_STREAM_MAX_BYTES + len(message()))
        self.assertEqual(final.stream.payload, message())
        self.assertEqual(final.retained_suffix, b'')
        self.assertEqual(final.complete_message_count, 2)

    def test_reclamation_preserves_partial_message_bytes_and_absolute_boundary(self):
        first = message() * 4681
        pending = message(0x4A, b'x' * 40000)
        states = framing_states((first, pending[:32768], pending[32768:]))
        before = states[1].ldap_stream_state.forward
        self.assertEqual(before.retained_suffix, pending[:32768])
        self.assertEqual(before.pending_message.offset, len(first))
        final = states[2].ldap_stream_state.forward
        self.assertEqual(final.stream.buffer_offset, len(first))
        self.assertEqual(final.stream.payload, pending)
        self.assertEqual([(m.offset, m.message_length) for m in final.messages], [(len(first), len(pending))])
        self.assertEqual(final.consumed_offset, len(first + pending))
        self.assertEqual(final.complete_message_count, 4682)
        self.assertEqual(final.retained_suffix, b'')
        self.assertEqual(before.retained_suffix, pending[:32768])

    def test_empty_and_non_ldap_streams_do_not_create_framing_or_consume_bytes(self):
        for payload in (b'', b'HTTP', b'\x16\x03\x03'):
            state = FlowStateCoordinator().record(framing_packet(payload))
            self.assertIsNone(state.ldap_stream_state)
            self.assertEqual(state.tcp_stream_state.forward.consumed_offset, 0)
        state = framing_states((b'', message(), b''))[-1].ldap_stream_state.forward
        self.assertEqual(state.complete_message_count, 1)
        self.assertEqual(state.messages, ())
        self.assertEqual(state.retained_suffix, b'')
        self.assertIs(state.status, LDAPStreamStatus.READY)

    def test_gap_and_conflicting_overlap_stop_without_parsing_unavailable_prefix(self):
        raw = message(0x60, b'abcdefgh')
        for next_payload, sequence, expected in ((raw[5:], 106, TCPStreamStatus.GAP), (b'zz', 102, TCPStreamStatus.CONFLICT)):
            coordinator = FlowStateCoordinator()
            before = coordinator.record(framing_packet(raw[:5]))
            with patch.object(ldap_stream_framing, '_message', side_effect=AssertionError('unavailable bytes parsed')):
                state = coordinator.record(framing_packet(next_payload, sequence, 1))
                later = coordinator.record(framing_packet(raw[5:], 105, 2))
            for current in (state, later):
                framed = current.ldap_stream_state.forward
                self.assertIs(framed.status, LDAPStreamStatus.UNAVAILABLE)
                self.assertIs(framed.stream.status, expected)
                self.assertEqual(framed.consumed_offset, 0)
                self.assertEqual(framed.complete_message_count, 0)
                self.assertEqual(framed.messages, ())
            self.assertIs(state.ldap_stream_state.forward.pending_message, before.ldap_stream_state.forward.pending_message)

    def test_retransmission_never_reemits_message_or_corrupts_incomplete_suffix(self):
        first, second = message(), message(0x60, b'abcdefgh')
        coordinator = FlowStateCoordinator()
        initial = coordinator.record(framing_packet(first + second[:5]))
        repeated = coordinator.record(framing_packet(first + second[:5], 100, 1))
        self.assertEqual(repeated.ldap_stream_state.forward.messages, ())
        self.assertEqual(repeated.ldap_stream_state.forward.retained_suffix, second[:5])
        self.assertEqual(repeated.ldap_stream_state.forward.complete_message_count, 1)
        final = coordinator.record(framing_packet(second[5:], 100 + len(first) + 5, 2))
        self.assertEqual([m.offset for m in final.ldap_stream_state.forward.messages], [len(first)])
        duplicate = coordinator.record(framing_packet(first + second, 100, 3))
        self.assertEqual(duplicate.ldap_stream_state.forward.messages, ())
        self.assertEqual(duplicate.ldap_stream_state.forward.complete_message_count, 2)
        self.assertEqual(initial.ldap_stream_state.forward.retained_suffix, second[:5])

    def test_public_contracts_reject_wrong_types_and_stale_consumption_and_are_immutable(self):
        state = framing_states((message(),))[0]
        framing = state.ldap_stream_state
        for value in (framing, framing.forward, framing.forward.messages[0]):
            hash(value)
            for field in fields(value):
                with self.assertRaises(FrozenInstanceError):
                    setattr(value, field.name, None)
        for model in (LDAPStreamState, LDAPStreamObservation):
            with self.assertRaises(TypeError):
                model()
        for args in ((object(), state.tcp_stream_state), (None, None)):
            with self.assertRaises(TypeError):
                update_ldap_stream_state(*args)
        other = framing_states((message(),), True)[0]
        with self.assertRaises(ValueError):
            update_ldap_stream_state(framing, other.tcp_stream_state)
        with self.assertRaises(ValueError):
            update_ldap_stream_state(None, state.tcp_stream_state)
        origin = FlowStateCoordinator()
        with patch('analysis.flow_state_coordinator.update_ldap_stream_state', return_value=None):
            stale = origin.record(framing_packet(message())).tcp_stream_state
        with self.assertRaises(ValueError):
            update_ldap_stream_state(framing, stale)
        with self.assertRaises(ValueError):
            update_ldap_stream_state(framing, TCPStreamState(state.identity))
        for name in ('LDAPStreamObservation', 'LDAPStreamState', 'LDAPStreamStatus', 'update_ldap_stream_state', 'consume_tcp_stream'):
            self.assertIn(name, analysis.__all__)
            self.assertIsNotNone(getattr(analysis, name))


if __name__ == '__main__':
    unittest.main()
