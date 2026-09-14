import gc
import unittest
import weakref
from datetime import timedelta
from struct import pack
from unittest.mock import patch

from analysis import (
    DEFAULT_MAX_ACTIVE_WINDOWS, FlowObservationWindow, FlowObservationWindowClosureReason,
    FlowObservationWindowError, FlowObservationWindowManager, FlowObservationWindowUpdate,
    FlowStateCoordinator, LDAPCorrelationStatus, LDAPRequestSummaryStatus, analyze_packet,
)
from tests.pcap_scenarios import addresses, checksum, frame, transport
from tests.protocol_scenarios import observation
from tests.test_ldap_correlation import correlation_message
from tests.test_ldap_flow_statistics import ldap_observation


def capacity_packet(index, seconds=0, ipv6=False, protocol=17, reverse=False, payload=b''):
    segment = transport(protocol, payload, ipv6, reverse, flags=24)
    ports = (443, 12000 + index) if reverse else (12000 + index, 443)
    offset = 16 if protocol == 6 else 6
    segment = pack('!HH', *ports) + segment[4:offset] + b'\x00\x00' + segment[offset + 2:]
    source, destination = addresses(ipv6, reverse)
    pseudo = source + destination + (
        pack('!I3xB', len(segment), protocol) if ipv6 else pack('!BBH', 0, protocol, len(segment))
    )
    value = checksum(pseudo + segment) or 65535
    segment = segment[:offset] + value.to_bytes(2, 'big') + segment[offset + 2:]
    return observation(frame(protocol, segment, ipv6, reverse), seconds)


def manager(limit=2):
    return FlowObservationWindowManager('capacity', timedelta(seconds=5), max_active_windows=limit)


def record(owner, index, seconds=0, **options):
    return owner.record(analyze_packet(capacity_packet(index, seconds, **options)))


class FlowCapacityTests(unittest.TestCase):
    def test_limit_is_positive_exact_integer_and_default_is_finite(self):
        self.assertEqual(DEFAULT_MAX_ACTIVE_WINDOWS, 1024)
        for invalid in (True, False, None, 1.0, '1', object()):
            with self.subTest(invalid=type(invalid)), self.assertRaises(TypeError):
                manager(invalid)
        for invalid in (0, -1):
            with self.assertRaises(FlowObservationWindowError):
                manager(invalid)
        owner = FlowObservationWindowManager('capacity', timedelta(seconds=5))
        for index in range(DEFAULT_MAX_ACTIVE_WINDOWS):
            self.assertEqual(record(owner, index).closed_windows, ())
        update = record(owner, DEFAULT_MAX_ACTIVE_WINDOWS)
        self.assertEqual(len(owner.active_windows()), DEFAULT_MAX_ACTIVE_WINDOWS)
        self.assertEqual(update.closed_windows[0].key.sequence_number, 0)
        self.assertIs(update.closed_windows[0].closure_reason, FlowObservationWindowClosureReason.CAPACITY)

    def test_boundary_eviction_preserves_exact_state_for_each_family_and_transport(self):
        for ipv6 in (False, True):
            for protocol in (6, 17):
                with self.subTest(ipv6=ipv6, protocol=protocol):
                    owner = manager()
                    first = record(owner, 0, ipv6=ipv6, protocol=protocol).active_window
                    second = record(owner, 1, 1, ipv6=ipv6, protocol=protocol)
                    self.assertEqual(second.closed_windows, ())
                    update = record(owner, 2, 2, ipv6=ipv6, protocol=protocol)
                    closed, = update.closed_windows
                    self.assertEqual(closed.key, first.key)
                    self.assertIs(closed.coordinated_state, first.coordinated_state)
                    self.assertEqual(closed.last_captured_at, first.last_captured_at)
                    self.assertIsNone(first.closure_reason)
                    self.assertIs(closed.closure_reason, FlowObservationWindowClosureReason.CAPACITY)
                    self.assertEqual(update.active_window.key.sequence_number, 2)
                    self.assertEqual([w.key.sequence_number for w in owner.active_windows()], [1, 2])

    def test_recent_reverse_observation_changes_victim_without_creation_reordering(self):
        for ipv6 in (False, True):
            owner = manager()
            record(owner, 0, ipv6=ipv6)
            record(owner, 1, 1, ipv6=ipv6)
            updated = record(owner, 0, 2, ipv6=ipv6, reverse=True)
            self.assertEqual(updated.closed_windows, ())
            self.assertEqual(updated.active_window.coordinated_state.flow_statistics.packet_count, 2)
            self.assertEqual([w.key.sequence_number for w in owner.active_windows()], [0, 1])
            update = record(owner, 2, 3, ipv6=ipv6)
            self.assertEqual(update.closed_windows[0].key.sequence_number, 1)
            self.assertEqual([w.key.sequence_number for w in owner.end_capture_session()], [0, 2])

    def test_equal_timestamp_ties_follow_creation_even_after_repeated_observations(self):
        owner = manager()
        record(owner, 0)
        record(owner, 1)
        record(owner, 0)
        update = record(owner, 2)
        self.assertEqual(update.closed_windows[0].key.sequence_number, 0)
        self.assertEqual(update.closed_windows[0].coordinated_state.flow_statistics.packet_count, 2)

    def test_inactivity_at_capacity_replaces_only_the_same_identity(self):
        owner = manager()
        first = record(owner, 0).active_window
        record(owner, 1, 1)
        update = record(owner, 1, 6)
        self.assertEqual(len(update.closed_windows), 1)
        self.assertIs(update.closed_windows[0].closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
        self.assertEqual(owner.active_windows()[0], first)
        self.assertEqual([w.key.sequence_number for w in owner.active_windows()], [0, 2])

    def test_explicit_close_frees_capacity_and_evicted_identity_restarts_fresh(self):
        owner = manager(1)
        old = record(owner, 0, protocol=6, payload=b'prefix').active_window
        record(owner, 1, 1)
        reopened = record(owner, 0, 2, protocol=6, payload=b'fresh').active_window
        self.assertEqual(reopened.key.sequence_number, 2)
        self.assertEqual(reopened.coordinated_state.flow_statistics.packet_count, 1)
        self.assertEqual(reopened.coordinated_state.tcp_stream_state.forward.contiguous_payload, b'fresh')
        self.assertEqual(old.coordinated_state.tcp_stream_state.forward.contiguous_payload, b'prefix')
        self.assertIs(owner.close(reopened.identity).closure_reason, FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION)
        self.assertEqual(record(owner, 2, 3).closed_windows, ())

    def test_mixed_identity_churn_retains_only_limit_and_releases_evicted_state(self):
        owner = manager(3)
        references = []
        for index in range(80):
            active = record(owner, index, ipv6=bool(index % 2), protocol=6 if index % 3 else 17,
                            payload=b'x' * 512).active_window
            references.append(weakref.ref(active.coordinated_state))
            self.assertLessEqual(len(owner.active_windows()), 3)
        del active
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references[:-3]))
        self.assertTrue(all(reference() is not None for reference in references[-3:]))
        self.assertEqual([w.key.sequence_number for w in owner.end_capture_session()], [77, 78, 79])
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))

    def test_invalid_and_out_of_order_input_cannot_evict_or_advance_sequence(self):
        owner = manager(1)
        original = record(owner, 0, 2).active_window
        for invalid, error in ((None, TypeError), (object(), TypeError),
                               (analyze_packet(capacity_packet(1, 1)), FlowObservationWindowError)):
            with self.assertRaises(error):
                owner.record(invalid)
            self.assertEqual(owner.active_windows(), (original,))
        update = record(owner, 1, 2)
        self.assertEqual(update.active_window.key.sequence_number, 1)

    def test_publication_and_candidate_failures_preserve_victim_frontier_and_retry(self):
        for ipv6 in (False, True):
            for model, method in ((FlowObservationWindow, '__post_init__'),
                                  (FlowObservationWindowUpdate, '__post_init__'),
                                  (FlowStateCoordinator, 'record')):
                for error in (MemoryError('allocation'), RuntimeError('publication'), KeyboardInterrupt()):
                    with self.subTest(ipv6=ipv6, model=model, error=type(error)):
                        owner = manager(1)
                        original = record(owner, 0, ipv6=ipv6, protocol=6).active_window
                        with patch.object(model, method, side_effect=error):
                            with self.assertRaises(type(error)) as raised:
                                record(owner, 1, 3, ipv6=ipv6, protocol=6)
                        self.assertIs(raised.exception, error)
                        self.assertEqual(owner.active_windows(), (original,))
                        update = record(owner, 1, 2, ipv6=ipv6, protocol=6)
                        self.assertEqual(update.active_window.key.sequence_number, 1)
                        self.assertIs(update.closed_windows[0].coordinated_state, original.coordinated_state)

    def test_failure_building_new_active_window_after_victim_leaves_table_unchanged(self):
        owner = manager(1)
        original = record(owner, 0).active_window
        validate = FlowObservationWindow.__post_init__

        def fail_active(window):
            if window.closure_reason is None:
                raise MemoryError('active publication')
            validate(window)

        with patch.object(FlowObservationWindow, '__post_init__', fail_active):
            with self.assertRaises(MemoryError):
                record(owner, 1, 2)
        self.assertEqual(owner.active_windows(), (original,))
        self.assertEqual(record(owner, 1, 1).active_window.key.sequence_number, 1)

    def test_table_copy_and_insertion_failure_do_not_remove_victim(self):
        class FailedInsert(dict):
            def __setitem__(self, key, value):
                raise MemoryError('table insertion')

        class FailedCopy(dict):
            def copy(self):
                raise MemoryError('table copy')

        class CopyWithFailedInsert(dict):
            def copy(self):
                return FailedInsert(self)

        for table in (FailedCopy, CopyWithFailedInsert):
            owner = manager(1)
            original = record(owner, 0).active_window
            owner._active = table(owner._active)
            with self.assertRaises(MemoryError):
                record(owner, 1, 3)
            self.assertEqual(owner.active_windows(), (original,))
            owner._active = dict(owner._active)
            retry = record(owner, 1, 2)
            self.assertEqual(retry.active_window.key.sequence_number, 1)
            self.assertEqual(retry.closed_windows[0].key, original.key)

    def test_failed_continuation_does_not_change_capacity_victim(self):
        owner = manager()
        record(owner, 0)
        record(owner, 1, 1)
        before = owner.active_windows()
        with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=MemoryError()):
            with self.assertRaises(MemoryError):
                record(owner, 0, 3)
        self.assertEqual(owner.active_windows(), before)
        self.assertEqual(record(owner, 2, 2).closed_windows[0].key.sequence_number, 0)

    def test_empty_repeated_finalization_and_failed_final_publication(self):
        empty = manager(1)
        self.assertEqual(empty.active_windows(), ())
        self.assertEqual(empty.end_capture_session(), ())
        self.assertEqual(empty.end_capture_session(), ())
        with self.assertRaises(FlowObservationWindowError):
            record(empty, 0)
        owner = manager(1)
        record(owner, 0)
        update = record(owner, 1, 1)
        with patch.object(FlowObservationWindow, '__post_init__', side_effect=MemoryError()):
            with self.assertRaises(MemoryError):
                owner.end_capture_session()
        self.assertEqual(owner.active_windows(), (update.active_window,))
        final, = owner.end_capture_session()
        self.assertEqual(final.key.sequence_number, 1)
        self.assertIs(final.closure_reason, FlowObservationWindowClosureReason.CAPTURE_SESSION_END)
        self.assertEqual(owner.end_capture_session(), ())

    def test_capacity_finalizes_pending_ldap_without_cross_window_response_association(self):
        for ipv6 in (False, True):
            owner = manager(1)
            request = correlation_message(0x63)
            first = owner.record(analyze_packet(ldap_observation(request, ipv6=ipv6))).active_window
            closed, = record(owner, 0, 1, ipv6=ipv6).closed_windows
            self.assertIs(closed.coordinated_state, first.coordinated_state)
            self.assertIs(first.ldap_correlation_state.requests[0].request_summary.status, LDAPRequestSummaryStatus.PENDING)
            summary = closed.ldap_correlation_state.requests[0].request_summary
            self.assertIs(summary.status, LDAPRequestSummaryStatus.UNRESOLVED)
            self.assertEqual(summary.response_count, 0)
            self.assertIsNone(summary.terminal_response)
            response = ldap_observation(correlation_message(0x65), 2, ipv6, reverse=True)
            reopened = owner.record(analyze_packet(response)).active_window
            self.assertEqual(reopened.key.sequence_number, 2)
            event, = reopened.ldap_correlation_state.observations
            self.assertIs(event.status, LDAPCorrelationStatus.UNMATCHED)
            self.assertIsNone(event.request_summary)

    def test_capacity_preserves_incomplete_malformed_and_unavailable_ldap_state(self):
        for ipv6 in (False, True):
            for payloads in ((b'\x30\x20',), (b'\x30\x80',), (b'\x30\x20', b'gap')):
                owner = manager(1)
                for index, payload in enumerate(payloads):
                    first = owner.record(analyze_packet(ldap_observation(
                        payload, index, ipv6, sequence=100 + index * 100,
                    ))).active_window
                closed, = record(owner, 0, 3, ipv6=ipv6).closed_windows
                self.assertIs(closed.coordinated_state, first.coordinated_state)
                self.assertEqual(closed.ldap_correlation_state.requests, ())
                self.assertTrue(closed.ldap_correlation_state.finalized)
