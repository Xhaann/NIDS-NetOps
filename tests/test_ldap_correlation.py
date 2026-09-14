import unittest
from dataclasses import FrozenInstanceError, fields

from analysis import (
    FlowDirection, FlowStateCoordinator, LDAP_MAX_PENDING_REQUESTS, LDAPCorrelationObservation,
    LDAPCorrelationState, LDAPCorrelationStatus, LDAPCorrelationUnavailableReason,
    LDAPMessageStatus, LDAPOperation, analyze_packet, finalize_ldap_correlation_state,
    flow_identity_from_packet, update_ldap_correlation_state,
)
from tests.test_ldap import OPERATIONS, envelope, message
from tests.test_ldap_flow_statistics import ldap_observation


BODIES = {tag: body for tag, _, body in OPERATIONS}


def correlation_message(tag, identifier=1, controls=b''):
    size = max(1, (identifier.bit_length() + 8) // 8)
    return message(tag, BODIES.get(tag, b''), identifier.to_bytes(size, 'big'), controls)


def correlation_packets(events, ipv6=False):
    sequences = {False: 100, True: 900}
    packets = []
    for index, (reverse, payload) in enumerate(events):
        packets.append(ldap_observation(payload, index, ipv6, reverse, sequence=sequences[reverse]))
        sequences[reverse] += len(payload)
    return tuple(packets)


def correlation_states(events, ipv6=False):
    coordinator = FlowStateCoordinator()
    return tuple(coordinator.record(analyze_packet(p)) for p in correlation_packets(events, ipv6))


class LDAPCorrelationTests(unittest.TestCase):
    def test_bind_pair_preserves_exact_identity_direction_and_observation_references(self):
        events = ((False, correlation_message(0x60)), (True, correlation_message(0x61)))
        states = correlation_states(events)
        first, final = (s.ldap_correlation_state for s in states)
        request = states[0].ldap_stream_state.forward.messages[0]
        response = states[1].ldap_stream_state.reverse.messages[0]
        self.assertIs(first.requests[0].message, request)
        self.assertIs(first.requests[0].status, LDAPCorrelationStatus.PENDING)
        self.assertEqual(final.identity, flow_identity_from_packet(analyze_packet(correlation_packets(events)[0])))
        match = final.observations[0]
        self.assertIs(match.identity, final.identity)
        self.assertIs(match.request, request)
        self.assertIs(match.message, response)
        self.assertIs(match.direction, FlowDirection.REVERSE)
        self.assertIs(match.request_direction, FlowDirection.FORWARD)
        self.assertIs(match.status, LDAPCorrelationStatus.MATCHED)
        self.assertEqual((match.request.message_id, match.message.message_id), (1, 1))
        self.assertEqual((match.request.offset, match.message.offset), (0, 0))
        self.assertEqual(final.requests, ())
        self.assertEqual((final.matched_response_count, final.unmatched_response_count), (1, 0))

    def test_existing_response_families_require_compatible_request_operations(self):
        for request, response in ((0x60, 0x61), (0x63, 0x65), (0x66, 0x67), (0x68, 0x69),
                                  (0x4A, 0x6B), (0x6C, 0x6D), (0x6E, 0x6F), (0x77, 0x78)):
            state = correlation_states(((False, correlation_message(request)), (True, correlation_message(response))))[-1]
            match = state.ldap_correlation_state.observations[0]
            self.assertIs(match.status, LDAPCorrelationStatus.MATCHED)
            self.assertIs(match.request.operation, LDAPOperation(request))
            self.assertIs(match.message.operation, LDAPOperation(response))

    def test_multiple_outstanding_non_fifo_responses_preserve_observed_order(self):
        requests = b''.join(correlation_message(0x60, i) for i in (1, 2, 3))
        responses = b''.join(correlation_message(0x61, i) for i in (2, 1, 3))
        states = correlation_states(((False, requests), (True, responses)))
        first, final = (s.ldap_correlation_state for s in states)
        self.assertEqual([r.message.message_id for r in first.requests], [1, 2, 3])
        self.assertEqual([r.message.message_id for r in final.observations], [2, 1, 3])
        self.assertEqual([r.request.message_id for r in final.observations], [2, 1, 3])
        self.assertEqual([r.message.offset for r in final.observations], [0, len(correlation_message(0x61)), 2 * len(correlation_message(0x61))])
        self.assertEqual(final.matched_response_count, 3)
        self.assertEqual(final.requests, ())

    def test_search_entries_and_references_match_without_retiring_request_until_done(self):
        responses = b''.join(correlation_message(tag) for tag in (0x64, 0x73, 0x64))
        states = correlation_states(((False, correlation_message(0x63)), (True, responses), (True, correlation_message(0x65))))
        middle, final = (s.ldap_correlation_state for s in states[1:])
        self.assertEqual(len(middle.requests), 1)
        self.assertEqual(middle.matched_response_count, 3)
        self.assertTrue(all(r.request is middle.requests[0].message for r in middle.observations))
        self.assertEqual(final.requests, ())
        self.assertEqual(final.matched_response_count, 4)
        self.assertIs(final.observations[0].message.operation, LDAPOperation.SEARCH_RESULT_DONE)

    def test_unmatched_response_is_not_retroactively_associated_with_later_request(self):
        states = correlation_states(((True, correlation_message(0x61)), (False, correlation_message(0x60))))
        first, final = (s.ldap_correlation_state for s in states)
        self.assertIs(first.observations[0].status, LDAPCorrelationStatus.UNMATCHED)
        self.assertIsNone(first.observations[0].request)
        self.assertEqual(final.unmatched_response_count, 1)
        self.assertEqual(final.matched_response_count, 0)
        self.assertIs(final.requests[0].status, LDAPCorrelationStatus.PENDING)

    def test_different_ids_same_direction_and_incompatible_response_types_do_not_match(self):
        events = ((False, correlation_message(0x60)), (True, correlation_message(0x61, 2)),
                  (False, correlation_message(0x61)), (True, correlation_message(0x67)))
        final = correlation_states(events)[-1].ldap_correlation_state
        self.assertEqual(final.matched_response_count, 0)
        self.assertEqual(final.unmatched_response_count, 3)
        self.assertEqual(len(final.requests), 1)
        self.assertIs(final.requests[0].message.operation, LDAPOperation.BIND_REQUEST)

    def test_same_id_requests_in_opposite_directions_are_independent(self):
        events = ((False, correlation_message(0x60)), (True, correlation_message(0x68)),
                  (False, correlation_message(0x69)), (True, correlation_message(0x61)))
        states = correlation_states(events)
        self.assertEqual([r.direction for r in states[1].ldap_correlation_state.requests], [FlowDirection.FORWARD, FlowDirection.REVERSE])
        matches = [s.ldap_correlation_state.observations[0] for s in states[2:]]
        self.assertEqual([r.request.operation for r in matches], [LDAPOperation.ADD_REQUEST, LDAPOperation.BIND_REQUEST])
        self.assertEqual([r.request_direction for r in matches], [FlowDirection.REVERSE, FlowDirection.FORWARD])
        self.assertEqual(states[-1].ldap_correlation_state.matched_response_count, 2)

    def test_request_id_reuse_before_resolution_remains_ambiguous_after_responses(self):
        events = ((False, correlation_message(0x60)), (False, correlation_message(0x68)),
                  (True, correlation_message(0x61)), (True, correlation_message(0x69)),
                  (False, correlation_message(0x60)), (True, correlation_message(0x61)))
        states = correlation_states(events)
        original = states[0].ldap_correlation_state.requests[0].message
        for state in states[1:]:
            current = state.ldap_correlation_state
            self.assertIs(current.requests[0].status, LDAPCorrelationStatus.AMBIGUOUS)
            self.assertIs(current.requests[0].message, original)
            self.assertIs(current.observations[0].status, LDAPCorrelationStatus.AMBIGUOUS)
            self.assertEqual(current.matched_response_count, 0)
        self.assertEqual(states[-1].ldap_correlation_state.ambiguous_observation_count, 5)
        self.assertIsNone(states[2].ldap_correlation_state.observations[0].request)

    def test_id_reuse_after_terminal_response_starts_new_observed_request(self):
        events = tuple((reverse, correlation_message(0x61 if reverse else 0x60)) for reverse in (False, True, False, True))
        states = correlation_states(events)
        final = states[-1].ldap_correlation_state
        self.assertEqual(final.matched_response_count, 2)
        self.assertIs(final.observations[0].request, states[2].ldap_stream_state.forward.messages[0])
        self.assertEqual(final.observations[0].request.offset, len(correlation_message(0x60)))

    def test_incomplete_request_waits_for_framing_and_does_not_match_early_response(self):
        raw = correlation_message(0x60)
        states = correlation_states(((False, raw[:5]), (True, correlation_message(0x61)),
                                     (False, raw[5:]), (True, correlation_message(0x61))))
        self.assertEqual(states[0].ldap_correlation_state.requests, ())
        self.assertEqual(states[0].ldap_correlation_state.observations, ())
        self.assertIs(states[1].ldap_correlation_state.observations[0].status, LDAPCorrelationStatus.UNMATCHED)
        self.assertIs(states[2].ldap_correlation_state.requests[0].status, LDAPCorrelationStatus.PENDING)
        final = states[3].ldap_correlation_state
        self.assertEqual((final.matched_response_count, final.unmatched_response_count), (1, 1))
        self.assertIs(final.observations[0].request.status, LDAPMessageStatus.COMPLETE)

    def test_malformed_request_or_response_stops_association_without_resynchronization(self):
        for events in (((False, b'\x30\xff' + correlation_message(0x60)), (True, correlation_message(0x61))),
                       ((False, correlation_message(0x60)), (True, b'\x30\xff' + correlation_message(0x61)))):
            states = correlation_states(events)
            final = states[-1].ldap_correlation_state
            self.assertIs(final.unavailable_reason, LDAPCorrelationUnavailableReason.STREAM_UNAVAILABLE)
            self.assertEqual(final.matched_response_count, 0)
            self.assertTrue(all(r.status is LDAPCorrelationStatus.UNRESOLVED for r in final.requests))

    def test_complete_response_before_malformed_suffix_remains_observed_match(self):
        events = ((False, correlation_message(0x60)), (True, correlation_message(0x61) + b'\x30\xff'))
        final = correlation_states(events)[-1].ldap_correlation_state
        self.assertIs(final.observations[0].status, LDAPCorrelationStatus.MATCHED)
        self.assertEqual(final.matched_response_count, 1)
        self.assertIs(final.unavailable_reason, LDAPCorrelationUnavailableReason.STREAM_UNAVAILABLE)

    def test_unsupported_known_and_unknown_operations_are_non_correlatable(self):
        unsupported = message(0x60, BODIES[0x60], controls=envelope(4, b'unknown'))
        unknown = correlation_message(0x7A, 2)
        states = correlation_states(((False, unsupported + unknown), (True, correlation_message(0x61))))
        initial, final = (s.ldap_correlation_state for s in states)
        self.assertEqual([r.status for r in initial.observations], [LDAPCorrelationStatus.NON_CORRELATABLE] * 2)
        self.assertIs(initial.observations[0].message.operation, LDAPOperation.BIND_REQUEST)
        self.assertIsNone(initial.observations[1].message.operation)
        self.assertEqual(initial.requests, ())
        self.assertEqual(final.non_correlatable_count, 2)
        self.assertEqual(final.unmatched_response_count, 1)

    def test_unsupported_reuse_cannot_leave_a_false_unique_pending_request(self):
        states = correlation_states(((False, correlation_message(0x60)), (False, correlation_message(0x7A)),
                                     (True, correlation_message(0x61))))
        self.assertIs(states[1].ldap_correlation_state.observations[0].status, LDAPCorrelationStatus.NON_CORRELATABLE)
        self.assertIs(states[-1].ldap_correlation_state.observations[0].status, LDAPCorrelationStatus.AMBIGUOUS)
        self.assertEqual(states[-1].ldap_correlation_state.matched_response_count, 0)

    def test_zero_identifier_and_operations_without_supported_response_pairing_are_non_correlatable(self):
        packets = ((False, correlation_message(0x60, 0)), (True, correlation_message(0x78, 0)),
                   (False, correlation_message(0x42) + correlation_message(0x50)), (True, correlation_message(0x79)))
        final = correlation_states(packets)[-1].ldap_correlation_state
        self.assertEqual(final.non_correlatable_count, 5)
        self.assertEqual(final.requests, ())
        self.assertEqual(final.matched_response_count, 0)
        for identifier in (128, 2147483647):
            state = correlation_states(((False, correlation_message(0x60, identifier)),
                                        (True, correlation_message(0x61, identifier))))[-1]
            self.assertEqual(state.ldap_correlation_state.observations[0].message.message_id, identifier)
            self.assertEqual(state.ldap_correlation_state.matched_response_count, 1)

    def test_controls_are_retained_but_do_not_form_correlation_keys(self):
        control = envelope(0xA0, envelope(0x30, envelope(4, b'1.2.3')))
        states = correlation_states(((False, correlation_message(0x60, controls=control)),
                                     (True, correlation_message(0x61))))
        match = states[-1].ldap_correlation_state.observations[0]
        self.assertIs(match.request.controls_present, True)
        self.assertIs(match.message.controls_present, False)
        self.assertIs(match.status, LDAPCorrelationStatus.MATCHED)
        self.assertEqual(match.request.message_length, len(correlation_message(0x60, controls=control)))

    def test_sequence_gap_freezes_pending_requests_and_prevents_later_matching(self):
        coordinator = FlowStateCoordinator()
        raw = correlation_message(0x60)
        coordinator.record(analyze_packet(ldap_observation(raw)))
        gap = coordinator.record(analyze_packet(ldap_observation(raw, 1, sequence=101 + len(raw))))
        final = coordinator.record(analyze_packet(ldap_observation(correlation_message(0x61), 2, reverse=True)))
        for state in (gap, final):
            current = state.ldap_correlation_state
            self.assertIs(current.unavailable_reason, LDAPCorrelationUnavailableReason.STREAM_UNAVAILABLE)
            self.assertEqual(current.matched_response_count, 0)
            self.assertIs(current.requests[0].status, LDAPCorrelationStatus.UNRESOLVED)
        self.assertIs(final.ldap_correlation_state.observations[0].status, LDAPCorrelationStatus.UNMATCHED)

    def test_retransmissions_and_empty_packets_do_not_duplicate_correlation_observations(self):
        coordinator = FlowStateCoordinator()
        request, response = correlation_message(0x60), correlation_message(0x61)
        packets = (ldap_observation(request), ldap_observation(request, 1),
                   ldap_observation(b'', 2, sequence=100 + len(request)),
                   ldap_observation(response, 3, reverse=True), ldap_observation(response, 4, reverse=True))
        states = tuple(coordinator.record(analyze_packet(p)) for p in packets)
        for index in (1, 2, 4):
            self.assertEqual(states[index].ldap_correlation_state.observations, ())
        self.assertEqual(states[-1].ldap_correlation_state.matched_response_count, 1)
        self.assertEqual(states[-1].ldap_correlation_state.ambiguous_observation_count, 0)

    def test_pending_capacity_is_sticky_and_cannot_create_matches_after_forgetting_requests(self):
        coordinator = FlowStateCoordinator()
        sequence = 100
        for batch in range(5):
            raw = b''.join(correlation_message(0x60, i) for i in range(batch * 100 + 1, batch * 100 + 101))
            state = coordinator.record(analyze_packet(ldap_observation(raw, batch, sequence=sequence)))
            sequence += len(raw)
            current = state.ldap_correlation_state
            self.assertLessEqual(len(current.requests), LDAP_MAX_PENDING_REQUESTS)
            self.assertEqual(len(current.observations), 100)
        self.assertIs(current.unavailable_reason, LDAPCorrelationUnavailableReason.LIMIT_EXCEEDED)
        self.assertEqual([r.message.message_id for r in current.requests], list(range(1, 129)))
        self.assertTrue(all(r.status is LDAPCorrelationStatus.UNRESOLVED for r in current.requests))
        response = coordinator.record(analyze_packet(ldap_observation(correlation_message(0x61), 5, reverse=True)))
        self.assertEqual(response.ldap_correlation_state.matched_response_count, 0)
        self.assertIs(response.ldap_correlation_state.observations[0].status, LDAPCorrelationStatus.UNMATCHED)

    def test_resolved_requests_release_capacity_without_accumulating_history(self):
        events = []
        for batch in range(5):
            events.extend(((False, b''.join(correlation_message(0x60, i) for i in range(1, 101))),
                           (True, b''.join(correlation_message(0x61, i) for i in range(100, 0, -1)))))
        final = correlation_states(events)[-1].ldap_correlation_state
        self.assertEqual(final.matched_response_count, 500)
        self.assertEqual(final.requests, ())
        self.assertEqual(len(final.observations), 100)
        self.assertIsNone(final.unavailable_reason)

    def test_exact_capacity_allows_response_and_one_replacement_before_exhaustion(self):
        raw = b''.join(correlation_message(0x60, i) for i in range(1, LDAP_MAX_PENDING_REQUESTS + 1))
        states = correlation_states(((False, raw), (True, correlation_message(0x61, 2)),
                                     (False, correlation_message(0x60, 129)), (False, correlation_message(0x60, 130))))
        self.assertEqual(len(states[0].ldap_correlation_state.requests), 128)
        self.assertIsNone(states[0].ldap_correlation_state.unavailable_reason)
        replacement = states[2].ldap_correlation_state
        self.assertEqual([r.message.message_id for r in replacement.requests], [1] + list(range(3, 130)))
        self.assertEqual(replacement.matched_response_count, 1)
        self.assertIsNone(replacement.unavailable_reason)
        self.assertIs(states[3].ldap_correlation_state.unavailable_reason, LDAPCorrelationUnavailableReason.LIMIT_EXCEEDED)

    def test_empty_and_non_ldap_streams_create_no_correlation_state(self):
        for payload in (b'', b'HTTP', b'\x16\x03\x03'):
            state = correlation_states(((False, payload),))[0]
            self.assertIsNone(state.ldap_correlation_state)

    def test_public_contracts_are_immutable_factory_only_and_validate_input_context(self):
        state = correlation_states(((False, correlation_message(0x60)),))[0]
        current = state.ldap_correlation_state
        for value in (current, current.observations[0]):
            hash(value)
            for field in fields(value):
                with self.assertRaises(FrozenInstanceError):
                    setattr(value, field.name, None)
        for model in (LDAPCorrelationState, LDAPCorrelationObservation):
            with self.assertRaises(TypeError):
                model()
        for args in ((object(), current.framing), (None, object())):
            with self.assertRaises(TypeError):
                update_ldap_correlation_state(*args)
        other = correlation_states(((False, correlation_message(0x60)),), True)[0]
        with self.assertRaises(ValueError):
            update_ldap_correlation_state(current, other.ldap_stream_state)
        self.assertIs(update_ldap_correlation_state(current, current.framing), current)
        final = finalize_ldap_correlation_state(current)
        self.assertIs(finalize_ldap_correlation_state(final), final)
        self.assertIs(final.requests[0].status, LDAPCorrelationStatus.UNRESOLVED)
        with self.assertRaises(ValueError):
            update_ldap_correlation_state(final, current.framing)
        with self.assertRaises(TypeError):
            finalize_ldap_correlation_state(None)


if __name__ == '__main__':
    unittest.main()
