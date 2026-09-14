import unittest
from dataclasses import FrozenInstanceError, fields
from unittest.mock import patch

from analysis import (
    FlowDirection, FlowStateCoordinator, LDAP_MAX_PENDING_REQUESTS, LDAPCorrelationStatus,
    LDAPCorrelationUnavailableReason, LDAPOperation, LDAPRequestSummary, LDAPRequestSummaryStatus,
    analyze_packet, finalize_ldap_correlation_state, update_ldap_correlation_state,
)
from analysis import ldap_request_summary
from tests.test_ldap import envelope, message
from tests.test_ldap_correlation import BODIES, correlation_message, correlation_packets, correlation_states
from tests.test_ldap_flow_statistics import ldap_observation


def summaries(states):
    return tuple(record.request_summary for state in states for record in state.ldap_correlation_state.observations
                 if record.request_summary is not None)


class LDAPRequestSummaryTests(unittest.TestCase):
    def test_terminal_response_updates_exact_request_reference_count_and_status(self):
        states = correlation_states(((False, correlation_message(0x60)), (True, correlation_message(0x61))))
        initial, final = summaries(states)
        self.assertEqual(tuple(f.name for f in fields(final)), ('identity', 'direction', 'request', 'status', 'response_count', 'terminal_response'))
        self.assertIs(initial.identity, states[0].identity)
        self.assertIs(initial.direction, FlowDirection.FORWARD)
        self.assertIs(initial.request, states[0].ldap_stream_state.forward.messages[0])
        self.assertEqual(initial.request.message_id, 1)
        self.assertIs(initial.request.operation, LDAPOperation.BIND_REQUEST)
        self.assertEqual(initial.response_count, 0)
        self.assertIs(initial.status, LDAPRequestSummaryStatus.PENDING)
        self.assertIsNone(initial.terminal_response)
        self.assertIs(final.request, initial.request)
        self.assertEqual(final.response_count, 1)
        self.assertIs(final.status, LDAPRequestSummaryStatus.COMPLETED)
        self.assertIs(final.terminal_response, states[1].ldap_stream_state.reverse.messages[0])
        self.assertEqual(states[1].ldap_correlation_state.requests, ())

    def test_existing_non_search_terminal_pairs_preserve_identifiers_and_operations(self):
        for request, response in ((0x60, 0x61), (0x66, 0x67), (0x68, 0x69), (0x4A, 0x6B),
                                  (0x6C, 0x6D), (0x6E, 0x6F), (0x77, 0x78)):
            states = correlation_states(((False, correlation_message(request, 128)), (True, correlation_message(response, 128))))
            final = summaries(states)[-1]
            self.assertEqual(final.request.message_id, 128)
            self.assertEqual(final.terminal_response.message_id, 128)
            self.assertIs(final.request.operation, LDAPOperation(request))
            self.assertIs(final.terminal_response.operation, LDAPOperation(response))
            self.assertEqual(final.response_count, 1)
            self.assertIs(final.status, LDAPRequestSummaryStatus.COMPLETED)

    def test_search_counts_and_terminal_reference_preserve_response_order(self):
        events = ((False, correlation_message(0x63, 10)),
                  (True, correlation_message(0x64, 10) + correlation_message(0x73, 10)),
                  (True, correlation_message(0x64, 10)), (True, correlation_message(0x65, 10)))
        states = correlation_states(events)
        progress = tuple(state.ldap_correlation_state.requests[0].request_summary for state in states[:-1]) + (summaries(states)[-1],)
        self.assertEqual([s.response_count for s in progress], [0, 2, 3, 4])
        self.assertEqual([s.status for s in progress], [LDAPRequestSummaryStatus.PENDING] * 3 + [LDAPRequestSummaryStatus.COMPLETED])
        self.assertTrue(all(s.request is progress[0].request for s in progress))
        for index, count in ((1, 2), (2, 3)):
            current = states[index].ldap_correlation_state
            self.assertEqual(current.requests[0].request_summary.response_count, count)
            self.assertTrue(all(r.request_summary is None for r in current.observations))
            self.assertIsNone(current.requests[0].request_summary.terminal_response)
        responses = tuple(r for state in states[1:] for r in state.ldap_correlation_state.observations)
        self.assertEqual([r.message.operation for r in responses], [LDAPOperation.SEARCH_RESULT_ENTRY, LDAPOperation.SEARCH_RESULT_REFERENCE,
                                                                   LDAPOperation.SEARCH_RESULT_ENTRY, LDAPOperation.SEARCH_RESULT_DONE])
        self.assertEqual([r.message.offset for r in responses], [0, len(events[1][1]) - len(correlation_message(0x73, 10)),
                                                               len(events[1][1]), len(events[1][1] + events[2][1])])
        self.assertIs(progress[-1].terminal_response, responses[-1].message)

    def test_search_done_without_entries_is_one_observed_terminal_response(self):
        final = summaries(correlation_states(((False, correlation_message(0x63)), (True, correlation_message(0x65)))))[-1]
        self.assertEqual(final.response_count, 1)
        self.assertIs(final.status, LDAPRequestSummaryStatus.COMPLETED)
        self.assertIs(final.terminal_response.operation, LDAPOperation.SEARCH_RESULT_DONE)

    def test_multiple_outstanding_non_fifo_responses_update_only_selected_summary(self):
        states = correlation_states(((False, b''.join(correlation_message(0x60, i) for i in (1, 2, 3))),
                                     (True, b''.join(correlation_message(0x61, i) for i in (2, 1, 3)))))
        first = states[0].ldap_correlation_state.requests
        final = states[1].ldap_correlation_state.observations
        self.assertEqual([r.request_summary.request.message_id for r in first], [1, 2, 3])
        self.assertEqual([r.request_summary.request.message_id for r in final], [2, 1, 3])
        self.assertEqual([r.request_summary.response_count for r in final], [1, 1, 1])
        self.assertIs(final[0].request_summary.request, first[1].message)
        self.assertEqual([r.request_summary.response_count for r in first], [0, 0, 0])

    def test_same_id_opposite_direction_requests_have_independent_summaries(self):
        events = ((False, correlation_message(0x60)), (True, correlation_message(0x68)),
                  (False, correlation_message(0x69)), (True, correlation_message(0x61)))
        states = correlation_states(events)
        progress = summaries(states)
        self.assertEqual([s.direction for s in progress], [FlowDirection.FORWARD, FlowDirection.REVERSE,
                                                          FlowDirection.REVERSE, FlowDirection.FORWARD])
        self.assertEqual([s.response_count for s in progress], [0, 0, 1, 1])
        self.assertIs(progress[2].request, progress[1].request)
        self.assertIs(progress[3].request, progress[0].request)

    def test_unmatched_wrong_id_wrong_operation_and_early_responses_have_no_summary(self):
        states = correlation_states(((True, correlation_message(0x61)), (False, correlation_message(0x60)),
                                     (True, correlation_message(0x61, 2)), (True, correlation_message(0x67))))
        for index in (0, 2, 3):
            self.assertIsNone(states[index].ldap_correlation_state.observations[0].request_summary)
        pending = states[-1].ldap_correlation_state.requests[0].request_summary
        self.assertEqual(pending.response_count, 0)
        self.assertIsNone(pending.terminal_response)
        self.assertEqual(states[-1].ldap_correlation_state.unmatched_response_count, 3)

    def test_retransmitted_request_and_responses_do_not_change_summary_count_or_terminal_reference(self):
        request, entry, done = (correlation_message(tag) for tag in (0x63, 0x64, 0x65))
        packets = (ldap_observation(request), ldap_observation(request, 1),
                   ldap_observation(entry, 2, reverse=True), ldap_observation(entry, 3, reverse=True),
                   ldap_observation(done, 4, reverse=True, sequence=100 + len(entry)),
                   ldap_observation(done, 5, reverse=True, sequence=100 + len(entry)))
        coordinator = FlowStateCoordinator()
        states = tuple(coordinator.record(analyze_packet(p)) for p in packets)
        self.assertEqual([s.response_count for s in summaries(states)], [0, 2])
        for index in (1, 3, 5):
            self.assertEqual(states[index].ldap_correlation_state.observations, ())
        self.assertIs(states[2].ldap_correlation_state.requests[0].request_summary,
                      states[3].ldap_correlation_state.requests[0].request_summary)
        final = states[4].ldap_correlation_state.observations[0].request_summary
        self.assertEqual(final.response_count, 2)
        self.assertIs(final.terminal_response, states[4].ldap_stream_state.reverse.messages[0])

    def test_ambiguous_reuse_preserves_only_previously_safe_response_count(self):
        events = ((False, correlation_message(0x63)), (True, correlation_message(0x64)),
                  (False, correlation_message(0x63)), (True, correlation_message(0x65)))
        states = correlation_states(events)
        first = states[0].ldap_correlation_state.requests[0].request_summary
        for state in states[2:]:
            summary = state.ldap_correlation_state.requests[0].request_summary
            self.assertIs(summary.status, LDAPRequestSummaryStatus.AMBIGUOUS)
            self.assertIs(summary.request, first.request)
            self.assertEqual(summary.response_count, 1)
            self.assertIsNone(summary.terminal_response)
        self.assertIsNone(states[3].ldap_correlation_state.observations[0].request_summary)
        final = finalize_ldap_correlation_state(states[3].ldap_correlation_state)
        self.assertIs(final.requests[0].request_summary, states[3].ldap_correlation_state.requests[0].request_summary)

    def test_resolved_id_reuse_starts_a_new_summary_without_inheriting_response_counts(self):
        events = ((False, correlation_message(0x63)), (True, correlation_message(0x64) + correlation_message(0x65)),
                  (False, correlation_message(0x60)), (True, correlation_message(0x61)))
        progress = summaries(correlation_states(events))
        self.assertEqual([s.response_count for s in progress], [0, 2, 0, 1])
        self.assertNotEqual(progress[0].request.offset, progress[2].request.offset)
        self.assertIs(progress[3].request, progress[2].request)

    def test_incomplete_request_enters_summary_only_after_complete_framing(self):
        raw = correlation_message(0x60)
        states = correlation_states(((False, raw[:1]), (False, raw[1:5]), (False, raw[5:]), (True, correlation_message(0x61))))
        for state in states[:2]:
            self.assertEqual(state.ldap_correlation_state.requests, ())
            self.assertEqual(state.ldap_correlation_state.observations, ())
        self.assertEqual([s.response_count for s in summaries(states)], [0, 1])
        self.assertIs(summaries(states)[0].request, states[2].ldap_stream_state.forward.messages[0])

    def test_malformed_request_or_response_cannot_create_completed_summary(self):
        for events in (((False, b'\x30\xff' + correlation_message(0x60)), (True, correlation_message(0x61))),
                       ((False, correlation_message(0x60)), (True, b'\x30\xff' + correlation_message(0x61)))):
            states = correlation_states(events)
            current = states[-1].ldap_correlation_state
            self.assertIs(current.unavailable_reason, LDAPCorrelationUnavailableReason.STREAM_UNAVAILABLE)
            self.assertFalse(any(s.status is LDAPRequestSummaryStatus.COMPLETED for s in summaries(states)))
            for record in current.requests:
                self.assertIs(record.request_summary.status, LDAPRequestSummaryStatus.UNRESOLVED)
                self.assertEqual(record.request_summary.response_count, 0)

    def test_non_correlatable_metadata_never_creates_request_summaries(self):
        unsupported = message(0x60, BODIES[0x60], controls=envelope(4, b'unsupported'))
        events = ((False, unsupported + correlation_message(0x7A) + correlation_message(0x42) + correlation_message(0x50)),
                  (True, correlation_message(0x79)), (False, correlation_message(0x60, 0)))
        states = correlation_states(events)
        self.assertEqual(summaries(states), ())
        self.assertEqual(states[-1].ldap_correlation_state.requests, ())
        self.assertEqual(states[-1].ldap_correlation_state.non_correlatable_count, 6)

    def test_unsupported_id_collision_marks_existing_summary_ambiguous_without_response(self):
        states = correlation_states(((False, correlation_message(0x63)), (True, correlation_message(0x64)),
                                     (False, correlation_message(0x7A)), (True, correlation_message(0x65))))
        current = states[-1].ldap_correlation_state
        self.assertIs(current.requests[0].request_summary.status, LDAPRequestSummaryStatus.AMBIGUOUS)
        self.assertEqual(current.requests[0].request_summary.response_count, 1)
        self.assertIsNone(states[2].ldap_correlation_state.observations[0].request_summary)
        self.assertIsNone(current.observations[0].request_summary)

    def test_gap_preserves_observed_response_count_and_cannot_fabricate_termination(self):
        request, entry, done = (correlation_message(tag) for tag in (0x63, 0x64, 0x65))
        coordinator = FlowStateCoordinator()
        packets = (ldap_observation(request), ldap_observation(entry, 1, reverse=True),
                   ldap_observation(done, 2, reverse=True, sequence=101 + len(entry)),
                   ldap_observation(done, 3, reverse=True, sequence=100 + len(entry)))
        states = tuple(coordinator.record(analyze_packet(p)) for p in packets)
        for state in states[2:]:
            summary = state.ldap_correlation_state.requests[0].request_summary
            self.assertIs(summary.status, LDAPRequestSummaryStatus.UNRESOLVED)
            self.assertEqual(summary.response_count, 1)
            self.assertIsNone(summary.terminal_response)
        self.assertEqual(len(summaries(states)), 1)

    def test_controls_remain_original_metadata_and_do_not_change_summary_keys(self):
        controls = envelope(0xA0, envelope(0x30, envelope(4, b'1.2.3')))
        states = correlation_states(((False, correlation_message(0x60, controls=controls)), (True, correlation_message(0x61))))
        summary = summaries(states)[-1]
        self.assertIs(summary.request.controls_present, True)
        self.assertIs(summary.terminal_response.controls_present, False)
        self.assertEqual(summary.response_count, 1)
        self.assertEqual(summary.request.message_length, len(correlation_message(0x60, controls=controls)))

    def test_empty_and_non_ldap_streams_have_no_summary_state(self):
        for payload in (b'', b'HTTP', b'\x16\x03\x03'):
            state = correlation_states(((False, payload),))[0]
            self.assertIsNone(state.ldap_correlation_state)

    def test_many_search_responses_keep_exact_count_without_a_response_history(self):
        coordinator = FlowStateCoordinator()
        coordinator.record(analyze_packet(ldap_observation(correlation_message(0x63))))
        response = correlation_message(0x64)
        sequence = 900
        for index in range(20):
            block = response * 512
            state = coordinator.record(analyze_packet(ldap_observation(block, index + 1, reverse=True, sequence=sequence)))
            sequence += len(block)
            summary = state.ldap_correlation_state.requests[0].request_summary
            self.assertEqual(summary.response_count, (index + 1) * 512)
            self.assertIsNone(summary.terminal_response)
            self.assertEqual(len(vars(summary)), 6)
            self.assertFalse(any(isinstance(value, (tuple, list, dict)) for value in vars(summary).values()))
            self.assertEqual(len(state.ldap_correlation_state.requests), 1)
            self.assertEqual(len(state.ldap_correlation_state.observations), 512)
        self.assertGreater(sequence - 900, 65536)
        final = coordinator.record(analyze_packet(ldap_observation(correlation_message(0x65), 21, reverse=True, sequence=sequence)))
        self.assertEqual(final.ldap_correlation_state.observations[0].request_summary.response_count, 10241)
        self.assertIs(final.ldap_correlation_state.observations[0].request_summary.status, LDAPRequestSummaryStatus.COMPLETED)

    def test_pending_limit_and_unmatched_request_growth_retain_only_bounded_summaries(self):
        coordinator = FlowStateCoordinator()
        sequence = 100
        for index in range(10):
            block = b''.join(correlation_message(0x60, i) for i in range(index * 100 + 1, index * 100 + 101))
            state = coordinator.record(analyze_packet(ldap_observation(block, index, sequence=sequence)))
            sequence += len(block)
            self.assertLessEqual(len(state.ldap_correlation_state.requests), LDAP_MAX_PENDING_REQUESTS)
            self.assertEqual(len(state.ldap_correlation_state.observations), 100)
        current = state.ldap_correlation_state
        self.assertIs(current.unavailable_reason, LDAPCorrelationUnavailableReason.LIMIT_EXCEEDED)
        self.assertEqual(len(current.requests), 128)
        for record in current.requests + current.observations:
            self.assertIs(record.request_summary.status, LDAPRequestSummaryStatus.UNRESOLVED)
            self.assertEqual(record.request_summary.response_count, 0)
            self.assertIsNone(record.request_summary.terminal_response)

    def test_completed_summaries_leave_active_storage_with_the_existing_event_batch(self):
        events = []
        for index in range(10):
            events.extend(((False, b''.join(correlation_message(0x60, i) for i in range(1, 101))),
                           (True, b''.join(correlation_message(0x61, i) for i in range(100, 0, -1)))))
        current = correlation_states(events)[-1].ldap_correlation_state
        self.assertEqual(current.matched_response_count, 1000)
        self.assertEqual(current.requests, ())
        self.assertEqual(len(current.observations), 100)
        self.assertTrue(all(r.request_summary.response_count == 1 for r in current.observations))

    def test_only_new_matches_update_summary_and_no_previous_history_is_recomputed(self):
        coordinator = FlowStateCoordinator()
        packets = correlation_packets(((False, correlation_message(0x63)), (True, correlation_message(0x64)),
                                       (True, b''), (True, correlation_message(0x65)), (False, b'')))
        with patch.object(ldap_request_summary, '_summary', wraps=ldap_request_summary._summary) as build:
            states = tuple(coordinator.record(analyze_packet(p)) for p in packets)
            self.assertEqual(build.call_count, 3)
            current = states[-1].ldap_correlation_state
            self.assertIs(update_ldap_correlation_state(current, current.framing), current)
            self.assertEqual(build.call_count, 3)
        self.assertIs(states[1].ldap_correlation_state.requests[0].request_summary,
                      states[2].ldap_correlation_state.requests[0].request_summary)
        self.assertEqual(states[3].ldap_correlation_state.observations[0].request_summary.response_count, 2)

    def test_summaries_are_factory_only_immutable_and_do_not_retain_predecessors(self):
        states = correlation_states(((False, correlation_message(0x60)), (True, correlation_message(0x61))))
        initial, completed = summaries(states)
        for summary in (initial, completed):
            hash(summary)
            for field in fields(summary):
                with self.assertRaises(FrozenInstanceError):
                    setattr(summary, field.name, None)
            self.assertFalse(any(isinstance(value, LDAPRequestSummary) for value in vars(summary).values()))
        with self.assertRaises(TypeError):
            LDAPRequestSummary()
        self.assertEqual(initial.response_count, 0)
        self.assertEqual(completed.response_count, 1)


if __name__ == '__main__':
    unittest.main()
