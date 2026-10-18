import unittest
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    IPv4FragmentationStatistics, PacketAnalysisFailureClassification, analyze_packet_outcome,
    update_ipv4_fragmentation_statistics,
)
from application.capture_fragmentation import run_capture_fragmentation_statistics
from capture import CaptureError, CaptureSource, PcapPacketSource
from capture.iterable_packet_source import IterablePacketSource
from capture.packet_observation import LinkType
from tests.pcap_scenarios import pcap_bytes, tcp_exchange, udp_exchange
from tests.test_ethernet_vlan import observation, tagged
from tests.test_packet_analysis import PROTOCOLS, TCP_BYTES, UDP_BYTES, make_observation

DF = 0x4000
MF = 0x2000
RESERVED = 0x8000


def outcome_for(protocol, payload, fragment_field, **options):
    return analyze_packet_outcome(make_observation(protocol, payload, fragment_field=fragment_field, **options))


def fold(outcomes):
    statistics = None
    for outcome in outcomes:
        statistics = update_ipv4_fragmentation_statistics(statistics, outcome)
    return statistics if statistics is not None else IPv4FragmentationStatistics()


class IPv4FragmentationStatisticsTests(unittest.TestCase):
    def test_empty_aggregate_is_all_zero(self):
        empty = IPv4FragmentationStatistics()
        self.assertTrue(all(getattr(empty, member.name) == 0 for member in fields(empty)))
        self.assertEqual((empty.packet_count, empty.fragment_packet_count, empty.non_initial_fragment_packet_count,
                          empty.more_fragments_packet_count, empty.dont_fragment_packet_count), (0, 0, 0, 0, 0))

    def test_categories_follow_offset_and_more_fragments(self):
        cases = (
            (0, 'unfragmented_packet_count'),
            (MF, 'initial_fragment_packet_count'),
            (MF | 185, 'intermediate_fragment_packet_count'),
            (185, 'final_fragment_packet_count'),
            (MF | 1, 'intermediate_fragment_packet_count'),
            (8191, 'final_fragment_packet_count'),
            (MF | 8191, 'intermediate_fragment_packet_count'),
        )
        for field, name in cases:
            for protocol, _, payload in PROTOCOLS:
                with self.subTest(field=field, protocol=protocol):
                    result = fold((outcome_for(protocol, payload, field),))
                    self.assertEqual(getattr(result, name), 1)
                    self.assertEqual(result.packet_count, 1)
                    self.assertEqual(result.dont_fragment_packet_count, 0)

    def test_non_initial_fragments_are_counted_although_transport_rejects_them(self):
        for protocol, _, payload in PROTOCOLS:
            for field in (MF | 185, 185):
                with self.subTest(protocol=protocol, field=field):
                    outcome = outcome_for(protocol, payload, field)
                    self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.UNSUPPORTED)
                    self.assertEqual(fold((outcome,)).non_initial_fragment_packet_count, 1)

    def test_recognition_does_not_depend_on_failure_wording(self):
        outcome = outcome_for(17, UDP_BYTES, MF | 5)
        reworded = replace(outcome, failure_description='unrelated wording')
        self.assertEqual(fold((reworded,)), fold((outcome,)))
        self.assertEqual(fold((reworded,)).intermediate_fragment_packet_count, 1)

    def test_unsupported_outcomes_that_are_not_transport_fragments_are_not_counted(self):
        arp = analyze_packet_outcome(observation(bytes.fromhex('00112233445566778899aabb0806') + bytes(28)))
        self.assertIs(arp.failure_classification, PacketAnalysisFailureClassification.UNSUPPORTED)
        unfragmented = outcome_for(17, UDP_BYTES, 0)
        forged = replace(unfragmented, analysis=None,
                         failure_classification=PacketAnalysisFailureClassification.UNSUPPORTED,
                         failure_description='forged')
        self.assertEqual(fold((arp, forged)).packet_count, 0)

    def test_other_ip_protocol_fragments_are_counted_once_from_the_analysis(self):
        for field, name in ((0, 'unfragmented_packet_count'), (MF, 'initial_fragment_packet_count'),
                            (185, 'final_fragment_packet_count')):
            outcome = outcome_for(47, b'opaque', field)
            self.assertTrue(outcome.succeeded)
            self.assertEqual(getattr(fold((outcome,)), name), 1)

    def test_flag_combinations_are_counted_independently(self):
        for df in (0, DF):
            for mf in (0, MF):
                for reserved in (0, RESERVED):
                    for offset in (0, 185):
                        with self.subTest(df=df, mf=mf, reserved=reserved, offset=offset):
                            result = fold((outcome_for(17, UDP_BYTES, df | mf | reserved | offset),))
                            self.assertEqual(result.dont_fragment_packet_count, int(bool(df)))
                            self.assertEqual(result.more_fragments_packet_count, int(bool(mf)))
                            self.assertEqual(result.reserved_flag_packet_count, int(bool(reserved)))
                            self.assertEqual(result.packet_count, 1)
                            self.assertEqual(result.fragment_packet_count, int(bool(mf or offset)))

    def test_df_is_tracked_per_category(self):
        result = fold((
            outcome_for(17, UDP_BYTES, DF),
            outcome_for(17, UDP_BYTES, DF | MF),
            outcome_for(17, UDP_BYTES, DF | MF | 10),
            outcome_for(17, UDP_BYTES, DF | 10),
            outcome_for(17, UDP_BYTES, 10),
        ))
        self.assertEqual((result.unfragmented_df_packet_count, result.initial_fragment_df_packet_count,
                          result.intermediate_fragment_df_packet_count, result.final_fragment_df_packet_count), (1, 1, 1, 1))
        self.assertEqual(result.final_fragment_packet_count, 2)
        self.assertEqual(result.dont_fragment_packet_count, 4)

    def test_counts_are_consistent_across_a_mixed_sequence(self):
        outcomes = tuple(outcome_for(protocol, payload, field)
                         for protocol, _, payload in PROTOCOLS for field in (0, MF, MF | 5, 5, DF | 5, DF))
        result = fold(outcomes)
        self.assertEqual(result.packet_count, len(outcomes))
        self.assertEqual(result.fragment_packet_count + result.unfragmented_packet_count, result.packet_count)
        self.assertEqual(result.non_initial_fragment_packet_count + result.initial_fragment_packet_count,
                         result.fragment_packet_count)
        self.assertEqual(result, fold(outcomes))

    def test_malformed_incomplete_and_corrupt_packets_are_not_counted(self):
        good = make_observation(17, UDP_BYTES, fragment_field=185)
        raw = good.raw_bytes
        corrupt = replace(good, raw_bytes=raw[:24] + bytes((raw[24] ^ 1,)) + raw[25:])
        truncated = replace(good, raw_bytes=raw[:20], captured_length=20, original_length=20)
        short = replace(good, raw_bytes=raw[:14] + raw[14:30], captured_length=30, original_length=30)
        ethernet_only = replace(good, raw_bytes=raw[:14], captured_length=14, original_length=14)
        bad_version = replace(good, raw_bytes=raw[:14] + bytes((0x55,)) + raw[15:])
        for candidate in (corrupt, truncated, short, ethernet_only, bad_version):
            with self.subTest(length=len(candidate.raw_bytes)):
                outcome = analyze_packet_outcome(candidate)
                self.assertFalse(outcome.succeeded)
                self.assertEqual(fold((outcome,)).packet_count, 0)

    def test_corrupt_checksum_on_a_non_initial_fragment_is_not_trusted(self):
        outcome = outcome_for(17, UDP_BYTES, 185, ipv4_checksum=1)
        self.assertEqual(fold((outcome,)).packet_count, 0)

    def test_non_ipv4_traffic_is_not_counted(self):
        for _, raw in tcp_exchange(True)[:2] + udp_exchange(True)[:2]:
            self.assertEqual(fold((analyze_packet_outcome(observation(raw)),)).packet_count, 0)
        arp = observation(bytes.fromhex('00112233445566778899aabb0806') + bytes(28))
        self.assertEqual(fold((analyze_packet_outcome(arp),)).packet_count, 0)

    def test_vlan_tagged_fragments_are_counted_like_untagged(self):
        raw = make_observation(17, UDP_BYTES, fragment_field=MF | 5).raw_bytes
        for tags in (((0x8100, 1, 0, 7),), ((0x88A8, 0, 0, 4095), (0x8100, 7, 1, 0))):
            wrapped = analyze_packet_outcome(observation(tagged(raw, *tags)))
            plain = analyze_packet_outcome(observation(raw))
            self.assertEqual(fold((wrapped,)), fold((plain,)))
            self.assertEqual(fold((wrapped,)).intermediate_fragment_packet_count, 1)

    def test_snapshots_are_immutable_and_updates_do_not_mutate_inputs(self):
        before = IPv4FragmentationStatistics()
        after = update_ipv4_fragmentation_statistics(before, outcome_for(6, TCP_BYTES, MF))
        self.assertEqual(before, IPv4FragmentationStatistics())
        self.assertEqual(after.initial_fragment_packet_count, 1)
        with self.assertRaises(FrozenInstanceError):
            after.initial_fragment_packet_count = 5

    def test_invalid_aggregate_construction_is_rejected(self):
        for arguments in ({'unfragmented_packet_count': -1}, {'unfragmented_df_packet_count': 1},
                          {'initial_fragment_packet_count': 1, 'initial_fragment_df_packet_count': 2},
                          {'final_fragment_df_packet_count': 1}, {'reserved_flag_packet_count': 1}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                IPv4FragmentationStatistics(**arguments)
        for name in ('unfragmented_packet_count', 'reserved_flag_packet_count', 'final_fragment_df_packet_count'):
            for value in (1.0, True, '1', None):
                with self.subTest(name=name, value=value), self.assertRaises(TypeError):
                    IPv4FragmentationStatistics(**{name: value})

    def test_update_validates_argument_types(self):
        outcome = outcome_for(6, TCP_BYTES, 0)
        for current in (object(), 1, ()):
            with self.assertRaises(TypeError):
                update_ipv4_fragmentation_statistics(current, outcome)
        for bad in (None, outcome.observation, outcome.analysis):
            with self.assertRaises(TypeError):
                update_ipv4_fragmentation_statistics(None, bad)

    def test_state_is_bounded_by_fixed_counters(self):
        count = len(fields(IPv4FragmentationStatistics))
        result = IPv4FragmentationStatistics()
        for index in range(2000):
            result = update_ipv4_fragmentation_statistics(
                result, outcome_for(17, UDP_BYTES, (MF if index % 2 else 0) | (index * 7) % 8192))
        self.assertEqual(len(fields(result)), count)
        self.assertEqual(result.packet_count, 2000)
        self.assertTrue(all(type(value) is int for value in vars(result).values()))

    def test_no_payload_or_packet_is_retained(self):
        result = fold((outcome_for(17, UDP_BYTES, MF), outcome_for(17, UDP_BYTES, 5)))
        self.assertTrue(all(type(getattr(result, member.name)) is int for member in fields(result)))


class CaptureFragmentationRunnerTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def packets(self):
        fields_ = (0, MF, MF | 5, 5, DF | MF | 9, DF, 3)
        return tuple((1000000 + index, make_observation(PROTOCOLS[index % 3][0], PROTOCOLS[index % 3][2],
                                                        fragment_field=field).raw_bytes)
                     for index, field in enumerate(fields_))

    def pcap_source(self, packets, order='<', nano=False):
        path = self.directory / 'capture.pcap'
        path.write_bytes(pcap_bytes(packets, order, nano))
        return PcapPacketSource(path, source=CaptureSource('fragments'))

    def run_source(self, source):
        with patch.object(source, 'stop', wraps=source.stop) as stop:
            try:
                return run_capture_fragmentation_statistics(source)
            finally:
                stop.assert_called_once()
                self.assertEqual(list(source), [])

    def expected(self):
        return fold(tuple(analyze_packet_outcome(observation(raw)) for _, raw in self.packets()))

    def test_empty_capture_yields_empty_statistics(self):
        self.assertEqual(self.run_source(self.pcap_source(())), IPv4FragmentationStatistics())
        self.assertEqual(run_capture_fragmentation_statistics(IterablePacketSource(())), IPv4FragmentationStatistics())

    def test_in_memory_and_pcap_paths_agree_for_all_encodings(self):
        expected = self.expected()
        self.assertEqual(expected.packet_count, 7)
        self.assertEqual(expected.non_initial_fragment_packet_count, 4)
        in_memory = run_capture_fragmentation_statistics(IterablePacketSource([raw for _, raw in self.packets()], link_type=LinkType(1)))
        self.assertEqual(in_memory, expected)
        for order in ('<', '>'):
            for nano in (False, True):
                with self.subTest(order=order, nano=nano):
                    self.assertEqual(self.run_source(self.pcap_source(self.packets(), order, nano)), expected)

    def test_each_run_starts_from_empty_state(self):
        first = self.run_source(self.pcap_source(self.packets()))
        second = self.run_source(self.pcap_source(self.packets()[:2]))
        self.assertEqual(first, self.expected())
        self.assertEqual(second.packet_count, 2)
        self.assertEqual(self.run_source(self.pcap_source(())), IPv4FragmentationStatistics())

    def test_source_is_released_and_repeated_close_is_safe(self):
        source = self.pcap_source(self.packets())
        self.run_source(source)
        source.stop()
        source.stop()

    def test_capture_failure_propagates_and_releases_source(self):
        path = self.directory / 'broken.pcap'
        path.write_bytes(pcap_bytes(self.packets())[:-5])
        source = PcapPacketSource(path, source=CaptureSource('broken'))
        with patch.object(source, 'stop', wraps=source.stop) as stop:
            with self.assertRaises(CaptureError):
                run_capture_fragmentation_statistics(source)
            stop.assert_called_once()

    def test_mixed_traffic_does_not_change_other_family_results(self):
        mixed = self.packets() + tuple((2000000 + time, raw) for time, raw in tcp_exchange(True) + udp_exchange(False))
        result = self.run_source(self.pcap_source(mixed))
        extra = fold(tuple(analyze_packet_outcome(observation(raw)) for _, raw in udp_exchange(False)))
        self.assertEqual(result.packet_count, self.expected().packet_count + extra.packet_count)


if __name__ == '__main__':
    unittest.main()
