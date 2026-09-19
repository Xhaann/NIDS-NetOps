import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    DirectionalIPv6ExtensionHeaderStatistics,
    FlowObservationWindowManager,
    IPv6ExtensionHeader,
    IPv6ExtensionHeaderStatistics,
    IPV6_EXTENSION_HEADER_MAX_COUNT,
    analyze_packet,
    flow_identity_from_packet,
    update_directional_ipv6_extension_header_statistics,
    update_ipv6_extension_header_statistics,
)
from analysis.flow_observation_window import FlowObservationWindowUpdate
from application import run_flow_observation_session
from capture import PcapPacketSource
from tests.pcap_scenarios import pcap_bytes
from tests.test_ipv6_flow import observation_at, packet_at
from tests.test_packet_analysis import TCP_BYTES, make_observation


def manager(timeout=5, capacity=1024):
    return FlowObservationWindowManager(
        'ipv6-extension-statistics',
        timedelta(seconds=timeout),
        max_active_windows=capacity,
    )


def replay_digest():
    instance = manager(capacity=2)
    events = []
    for index, (reverse, extensions) in enumerate(
        ((False, ()), (False, (0,)), (True, (43, 60)), (False, (0, 43, 0, 60)))
    ):
        window = instance.record(packet_at(6, seconds=index, reverse=reverse, extensions=extensions)).active_window
        value = window.ipv6_extension_header_statistics
        events.append((window.key.sequence_number, asdict(value)))
    events.extend((window.key.sequence_number, asdict(window.ipv6_extension_header_statistics))
                  for window in instance.end_capture_session())
    return hashlib.sha256(repr(events).encode()).hexdigest()


class IPv6ExtensionHeaderStatisticsTests(unittest.TestCase):
    def test_empty_value_is_bounded_immutable_and_directional(self):
        value = IPv6ExtensionHeaderStatistics()
        self.assertEqual(value.extension_header_type_counts, ())
        self.assertEqual(value.terminal_next_header_counts, ())
        self.assertEqual(value.extension_header_absent_packet_count, 0)
        with self.assertRaises(FrozenInstanceError):
            value.total_ipv6_packet_count = 1
        self.assertEqual(DirectionalIPv6ExtensionHeaderStatistics().forward, value)

    def test_single_packet_records_chain_shape_and_terminal_protocol(self):
        packet = packet_at(6, extensions=(0, 43, 60))
        identity = flow_identity_from_packet(packet)
        value = update_ipv6_extension_header_statistics(None, packet, identity)
        self.assertEqual(value.total_ipv6_packet_count, 1)
        self.assertEqual(value.packets_with_extension_headers, 1)
        self.assertEqual((value.min_extension_header_count, value.max_extension_header_count), (3, 3))
        self.assertEqual(value.total_extension_header_count, 3)
        self.assertEqual(value.extension_header_type_counts, ((0, 1), (43, 1), (60, 1)))
        self.assertEqual(value.terminal_next_header_counts, ((6, 1),))
        self.assertEqual(value.duplicate_extension_header_count, 0)
        self.assertEqual(value.extension_header_absent_packet_count, 0)

    def test_empty_and_duplicate_ordered_chains_are_preserved_as_structure(self):
        identity = flow_identity_from_packet(packet_at(17))
        value = update_ipv6_extension_header_statistics(None, packet_at(17), identity)
        value = update_ipv6_extension_header_statistics(value, packet_at(17, extensions=(0, 43, 0)), identity)
        self.assertEqual(value.total_ipv6_packet_count, 2)
        self.assertEqual(value.packets_with_extension_headers, 1)
        self.assertEqual((value.min_extension_header_count, value.max_extension_header_count), (0, 3))
        self.assertEqual(value.total_extension_header_count, 3)
        self.assertEqual(value.extension_header_type_counts, ((0, 2), (43, 1)))
        self.assertEqual(value.terminal_next_header_counts, ((17, 2),))
        self.assertEqual(value.duplicate_extension_header_count, 1)
        self.assertEqual(value.extension_header_absent_packet_count, 1)

    def test_direction_isolated_and_ipv4_is_explicitly_empty(self):
        forward = packet_at(17, extensions=(0,))
        reverse = packet_at(17, reverse=True, extensions=(43, 60))
        identity = flow_identity_from_packet(forward)
        value = update_directional_ipv6_extension_header_statistics(None, forward, identity)
        value = update_directional_ipv6_extension_header_statistics(value, reverse, identity)
        self.assertEqual(value.forward.extension_header_type_counts, ((0, 1),))
        self.assertEqual(value.reverse.extension_header_type_counts, ((43, 1), (60, 1)))
        ipv4 = analyze_packet(make_observation(6, TCP_BYTES))
        ipv4_identity = flow_identity_from_packet(ipv4)
        empty = update_directional_ipv6_extension_header_statistics(value, ipv4, ipv4_identity)
        self.assertEqual(empty, value)

    def test_direct_construction_enforces_domains_and_aggregate_invariants(self):
        maximum = IPv6ExtensionHeaderStatistics(
            total_ipv6_packet_count=1,
            packets_with_extension_headers=1,
            min_extension_header_count=IPV6_EXTENSION_HEADER_MAX_COUNT,
            max_extension_header_count=IPV6_EXTENSION_HEADER_MAX_COUNT,
            total_extension_header_count=IPV6_EXTENSION_HEADER_MAX_COUNT,
            extension_header_type_counts=((0, IPV6_EXTENSION_HEADER_MAX_COUNT),),
            terminal_next_header_counts=((6, 1),),
        )
        self.assertEqual(maximum.max_extension_header_count, IPV6_EXTENSION_HEADER_MAX_COUNT)
        for changes in (
            {'extension_header_type_counts': ((256, 1),)},
            {'terminal_next_header_counts': ((6, 2),)},
            {'min_extension_header_count': IPV6_EXTENSION_HEADER_MAX_COUNT + 1},
            {'packets_with_extension_headers': 2},
            {'total_extension_header_count': 0},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises((TypeError, ValueError)):
                    replace(maximum, **changes)

    def test_input_chain_bound_and_malformed_metadata_are_rejected(self):
        packet = packet_at(6, extensions=(0,))
        headers = tuple(
            IPv6ExtensionHeader(
                header_type=0,
                offset=40 + index * 8,
                declared_length=8,
                raw_bytes=bytes((0 if index < IPV6_EXTENSION_HEADER_MAX_COUNT else 6, 0)) + bytes(6),
                next_header=0 if index < IPV6_EXTENSION_HEADER_MAX_COUNT else 6,
            )
            for index in range(IPV6_EXTENSION_HEADER_MAX_COUNT + 1)
        )
        oversized = replace(
            packet,
            ipv6_extension_headers=replace(packet.ipv6_extension_headers, headers=headers),
        )
        identity = flow_identity_from_packet(packet)
        with self.assertRaises(ValueError):
            update_directional_ipv6_extension_header_statistics(None, oversized, identity)
        malformed_header = replace(packet.ipv6_extension_headers.headers[0], declared_length=7)
        malformed = replace(
            packet,
            ipv6_extension_headers=replace(packet.ipv6_extension_headers, headers=(malformed_header,)),
        )
        with self.assertRaises(ValueError):
            update_directional_ipv6_extension_header_statistics(None, malformed, identity)

    def test_wrong_types_and_identity_are_rejected_without_state_change(self):
        packet = packet_at(6)
        identity = flow_identity_from_packet(packet)
        value = update_directional_ipv6_extension_header_statistics(None, packet, identity)
        for current, analysis, supplied_identity in (
            (IPv6ExtensionHeaderStatistics(), packet, identity),
            (value, None, identity),
            (value, packet, None),
        ):
            with self.subTest(current=type(current), analysis=type(analysis), identity=type(supplied_identity)):
                with self.assertRaises(TypeError):
                    update_directional_ipv6_extension_header_statistics(current, analysis, supplied_identity)
        with self.assertRaises(TypeError):
            update_ipv6_extension_header_statistics([], packet, identity)

    def test_lifecycle_repeated_packets_closure_capacity_and_inactivity_are_bounded(self):
        instance = manager()
        first = instance.record(packet_at(6, extensions=(0,))).active_window
        second = instance.record(packet_at(6, seconds=1, extensions=(0,))).active_window
        self.assertEqual(second.ipv6_extension_header_statistics.forward.total_ipv6_packet_count, 2)
        closed = instance.close(first.identity)
        self.assertEqual(closed.ipv6_extension_header_statistics, second.ipv6_extension_header_statistics)
        instance = manager()
        instance.record(packet_at(17, extensions=(43,)))
        update = instance.record(packet_at(17, seconds=5, extensions=(60,)))
        self.assertEqual(update.closed_windows[0].ipv6_extension_header_statistics.forward.extension_header_type_counts,
                         ((43, 1),))
        self.assertEqual(update.active_window.ipv6_extension_header_statistics.forward.extension_header_type_counts,
                         ((60, 1),))
        instance = manager(capacity=1)
        instance.record(packet_at(6, extensions=(0,)))
        update = instance.record(packet_at(6, source_port=12346, extensions=(43,)))
        self.assertEqual(update.closed_windows[0].closure_reason.value, 'capacity')
        self.assertEqual(update.closed_windows[0].ipv6_extension_header_statistics.forward.extension_header_type_counts,
                         ((0, 1),))

    def test_publication_failure_retry_does_not_duplicate_statistics(self):
        instance = manager()
        first = instance.record(packet_at(6, extensions=(0,))).active_window
        packet = packet_at(6, seconds=1, extensions=(43,))
        with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                instance.record(packet)
        self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
        after = instance.record(packet).active_window
        retry = instance.record(packet).active_window
        self.assertEqual(after.ipv6_extension_header_statistics.forward.total_ipv6_packet_count, 2)
        self.assertEqual(retry.ipv6_extension_header_statistics.forward.total_ipv6_packet_count, 3)

    def test_source_objects_are_not_retained_by_the_aggregate(self):
        packet = packet_at(6, extensions=(0, 43))
        identity = flow_identity_from_packet(packet)
        value = update_directional_ipv6_extension_header_statistics(None, packet, identity)
        packet_reference = weakref.ref(packet)
        chain_reference = weakref.ref(packet.ipv6_extension_headers)
        del packet, identity
        gc.collect()
        self.assertIsNone(packet_reference())
        self.assertIsNone(chain_reference())
        self.assertEqual(value.forward.total_extension_header_count, 2)

    def test_real_capture_session_four_pcap_encodings_are_equivalent(self):
        sources = (
            observation_at(6, extensions=(0, 43)),
            observation_at(6, seconds=1, reverse=True, extensions=(60,)),
        )
        expected = None
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'ipv6-extension-statistics.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes)
                                                       for index, item in enumerate(sources)), order, nano))
                    closed = []
                    run_flow_observation_session(
                        PcapPacketSource(path),
                        capture_session_id='ipv6-extension-statistics',
                        inactivity_timeout=timedelta(seconds=60),
                        closed_window_consumer=closed.append,
                    )
                    actual = tuple((window.identity.ip_version,
                                    window.ipv6_extension_header_statistics.forward.extension_header_type_counts,
                                    window.ipv6_extension_header_statistics.reverse.extension_header_type_counts)
                                   for window in closed)
                    if expected is None:
                        expected = actual
                    self.assertEqual(actual, expected)

    def test_deterministic_replay_across_seed_and_timezone(self):
        expected = replay_digest()
        script = 'from tests.test_ipv6_extension_header_statistics import replay_digest; print(replay_digest())'
        for seed in ('1', '29', '503'):
            for timezone_name in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                environment = os.environ.copy()
                environment['PYTHONHASHSEED'] = seed
                environment['TZ'] = timezone_name
                actual = subprocess.check_output(
                    [sys.executable, '-B', '-c', script],
                    cwd=Path(__file__).parents[1],
                    env=environment,
                    text=True,
                ).strip()
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
