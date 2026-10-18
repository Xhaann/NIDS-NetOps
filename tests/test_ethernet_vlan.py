import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    EthernetDecodeError, EthernetFrame, PacketAnalysisFailureClassification,
    VLANTag, analyze_packet, analyze_packet_outcome, decode_ethernet,
)
from application import GroundTruth, run_end_to_end_validation
from capture import CaptureSource, PcapPacketSource
from capture.packet_observation import LinkType, PacketObservation
from tests.pcap_scenarios import pcap_bytes, tcp_exchange, udp_exchange
from tests.test_end_to_end_validation import settings

MACS = bytes.fromhex("00112233445566778899aabb")
SOURCE = CaptureSource("vlan-test")


def tag_bytes(pcp=0, dei=0, vid=0):
    return ((pcp << 13) | (dei << 12) | vid).to_bytes(2, "big")


def tagged(raw, *tags):
    prefix = b""
    for tpid, pcp, dei, vid in tags:
        prefix += tpid.to_bytes(2, "big") + tag_bytes(pcp, dei, vid)
    return raw[:12] + prefix + raw[12:]


def observation(raw):
    return PacketObservation(
        captured_at=datetime(2026, 9, 6, tzinfo=timezone.utc), link_type=LinkType(1),
        captured_length=len(raw), original_length=len(raw), raw_bytes=raw, source=SOURCE)


class VLANDecodeTests(unittest.TestCase):
    def test_untagged_frame_has_no_tags(self):
        result = decode_ethernet(observation(MACS + b"\x08\x00payload"))
        self.assertEqual(result.vlan_tags, ())
        self.assertEqual(result.ether_type, 0x0800)
        self.assertEqual(result.payload, b"payload")

    def test_single_tag_exposes_effective_ether_type_and_metadata(self):
        for tpid in (0x8100, 0x88A8):
            for pcp in range(8):
                for dei in (0, 1):
                    for vid in (0, 1, 100, 2048, 4094, 4095):
                        with self.subTest(tpid=tpid, pcp=pcp, dei=dei, vid=vid):
                            raw = MACS + tpid.to_bytes(2, "big") + tag_bytes(pcp, dei, vid) + b"\x86\xdd" + b"xy"
                            result = decode_ethernet(observation(raw))
                            self.assertEqual(result.vlan_tags, (VLANTag(tpid, pcp, dei, vid),))
                            self.assertEqual(result.ether_type, 0x86DD)
                            self.assertEqual(result.payload, b"xy")

    def test_double_tags_in_every_supported_order(self):
        for outer in (0x8100, 0x88A8):
            for inner in (0x8100, 0x88A8):
                with self.subTest(outer=outer, inner=inner):
                    raw = MACS + outer.to_bytes(2, "big") + tag_bytes(7, 1, 4095) + inner.to_bytes(2, "big")
                    raw += tag_bytes(3, 0, 5) + b"\x08\x00" + b"z"
                    result = decode_ethernet(observation(raw))
                    self.assertEqual(result.vlan_tags, (VLANTag(outer, 7, 1, 4095), VLANTag(inner, 3, 0, 5)))
                    self.assertEqual(result.ether_type, 0x0800)
                    self.assertEqual(result.payload, b"z")

    def test_exact_minimum_lengths_decode_with_empty_payload(self):
        single = decode_ethernet(observation(MACS + b"\x81\x00" + tag_bytes(1, 0, 2) + b"\x08\x00"))
        double = decode_ethernet(observation(
            MACS + b"\x88\xa8" + tag_bytes() + b"\x81\x00" + tag_bytes() + b"\x08\x00"))
        self.assertEqual((len(single.vlan_tags), single.payload), (1, b""))
        self.assertEqual((len(double.vlan_tags), double.payload), (2, b""))

    def test_truncation_at_every_tag_boundary_is_never_a_valid_frame(self):
        full = MACS + b"\x88\xa8" + tag_bytes(1, 0, 2) + b"\x81\x00" + tag_bytes(2, 1, 3) + b"\x08\x00"
        for length in range(14, len(full)):
            with self.subTest(length=length):
                with self.assertRaisesRegex(EthernetDecodeError, "VLAN tag is too short"):
                    decode_ethernet(observation(full[:length]))
                outcome = analyze_packet_outcome(observation(full[:length]))
                self.assertEqual(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
        for length in range(14):
            with self.assertRaisesRegex(EthernetDecodeError, "frame is too short"):
                decode_ethernet(observation(full[:length]))

    def test_third_tag_is_rejected_without_further_parsing(self):
        raw = MACS
        for _ in range(3):
            raw += b"\x81\x00" + tag_bytes(0, 0, 7)
        raw += b"\x08\x00" + b"x"
        for candidate in (raw, raw + bytes(100)):
            with self.assertRaisesRegex(EthernetDecodeError, "supported VLAN tag depth"):
                decode_ethernet(observation(candidate))
            outcome = analyze_packet_outcome(observation(candidate))
            self.assertEqual(outcome.failure_classification, PacketAnalysisFailureClassification.UNSUPPORTED)

    def test_unsupported_inner_ether_type_is_unsupported(self):
        raw = MACS + b"\x81\x00" + tag_bytes(0, 0, 9) + b"\x08\x06" + bytes(28)
        outcome = analyze_packet_outcome(observation(raw))
        self.assertEqual(outcome.failure_classification, PacketAnalysisFailureClassification.UNSUPPORTED)
        self.assertEqual(decode_ethernet(observation(raw)).ether_type, 0x0806)

    def test_vlan_tag_validation_and_immutability(self):
        tag = VLANTag(0x8100, 1, 0, 2)
        with self.assertRaises(FrozenInstanceError):
            tag.vid = 3
        for arguments in ((0x0800, 0, 0, 0), (0x8100, 8, 0, 0), (0x8100, -1, 0, 0), (0x8100, 0, 2, 0),
                          (0x8100, 0, 0, 4096), (0x8100, 0, 0, -1)):
            with self.assertRaises(ValueError):
                VLANTag(*arguments)
        for arguments in ((True, 0, 0, 0), (0x8100, 0.0, 0, 0), (0x8100, 0, None, 0), (0x8100, 0, 0, "1")):
            with self.assertRaises(TypeError):
                VLANTag(*arguments)

    def test_frame_vlan_tags_validation_and_positional_compatibility(self):
        tag = VLANTag(0x8100, 0, 0, 1)
        self.assertEqual(EthernetFrame(bytes(6), bytes(6), 0, b"").vlan_tags, ())
        self.assertEqual(EthernetFrame(bytes(6), bytes(6), 0, b"", (tag, tag)).vlan_tags, (tag, tag))
        with self.assertRaises(TypeError):
            EthernetFrame(bytes(6), bytes(6), 0, b"", [tag])
        with self.assertRaises(TypeError):
            EthernetFrame(bytes(6), bytes(6), 0, b"", (tag, 1))
        with self.assertRaises(ValueError):
            EthernetFrame(bytes(6), bytes(6), 0, b"", (tag, tag, tag))

    def test_input_observation_is_not_modified(self):
        raw = MACS + b"\x81\x00" + tag_bytes(1, 1, 1) + b"\x08\x00" + b"p"
        source = observation(raw)
        before = replace(source)
        decode_ethernet(source)
        self.assertEqual(source, before)
        self.assertIs(source.raw_bytes, raw)


class VLANPacketAnalysisTests(unittest.TestCase):
    def test_tagged_frames_match_untagged_analysis_except_metadata(self):
        for ipv6 in (False, True):
            for time, raw in tcp_exchange(ipv6)[:2] + udp_exchange(ipv6)[:2]:
                for tags in (((0x8100, 5, 1, 100),), ((0x88A8, 0, 0, 4095), (0x8100, 7, 0, 0))):
                    with self.subTest(ipv6=ipv6, tags=len(tags)):
                        plain = analyze_packet(observation(raw))
                        wrapped = analyze_packet(observation(tagged(raw, *tags)))
                        self.assertEqual(len(wrapped.ethernet.vlan_tags), len(tags))
                        self.assertEqual(wrapped.ethernet.ether_type, plain.ethernet.ether_type)
                        self.assertEqual(wrapped.ethernet.payload, plain.ethernet.payload)
                        for name in ("ipv4", "ipv6", "tcp", "udp", "ipv6_tcp", "ipv6_udp",
                                     "ipv4_checksum_valid", "tcp_checksum_valid", "udp_checksum_valid"):
                            self.assertEqual(getattr(wrapped, name), getattr(plain, name), name)

    def test_decoded_tags_are_deterministically_ordered(self):
        raw = tagged(tcp_exchange()[0][1], (0x88A8, 1, 0, 10), (0x8100, 2, 1, 20))
        first = analyze_packet(observation(raw)).ethernet.vlan_tags
        self.assertEqual(first, analyze_packet(observation(raw)).ethernet.vlan_tags)
        self.assertEqual([tag.vid for tag in first], [10, 20])


class VLANPcapTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.configuration = settings()

    def run_packets(self, packets, order="<", nano=False):
        path = self.directory / "capture.pcap"
        path.write_bytes(pcap_bytes(packets, order, nano))
        source = PcapPacketSource(path, source=SOURCE)
        with patch.object(source, "stop", wraps=source.stop) as stop:
            try:
                return run_end_to_end_validation(
                    source, configuration=self.configuration, capture_session_id="vlan",
                    ground_truth=GroundTruth((), ()))
            finally:
                stop.assert_called_once()
                self.assertEqual(list(source), [])

    def flow_summary(self, result):
        return [(finding.detector_id, finding.decision, finding.raw_evidence.identity,
                 finding.raw_evidence.first_captured_at, finding.raw_evidence.last_captured_at)
                for finding in result.pipeline_result.flow_findings]

    def packet_summary(self, result):
        return [(finding.detector_id, finding.decision, finding.raw_evidence.outcome.failure_classification)
                for finding in result.pipeline_result.packet_findings]

    def test_tagged_replay_matches_untagged_for_all_pcap_encodings(self):
        base = tcp_exchange(False) + tuple((time + 10000000, raw) for time, raw in tcp_exchange(True))
        variants = (
            ((0x8100, 1, 0, 10),),
            ((0x88A8, 2, 1, 4095), (0x8100, 3, 0, 0)),
        )
        for order in ("<", ">"):
            for nano in (False, True):
                plain = self.run_packets(base, order, nano)
                for tags in variants:
                    with self.subTest(order=order, nano=nano, tags=len(tags)):
                        packets = tuple((time, tagged(raw, *tags)) for time, raw in base)
                        result = self.run_packets(packets, order, nano)
                        self.assertTrue(plain.pipeline_result.flow_findings)
                        self.assertEqual(self.flow_summary(result), self.flow_summary(plain))
                        self.assertEqual(self.packet_summary(result), self.packet_summary(plain))
                        self.assertTrue(all(
                            len(f.raw_evidence.outcome.analysis.ethernet.vlan_tags) == len(tags)
                            for f in result.pipeline_result.packet_findings))

    def test_mixed_tagged_and_untagged_packets_share_one_flow(self):
        base = tcp_exchange(False)
        mixed = tuple((time, tagged(raw, (0x8100, 0, 0, index)) if index % 2 else raw)
                      for index, (time, raw) in enumerate(base))
        plain = self.run_packets(base)
        result = self.run_packets(mixed)
        self.assertTrue(plain.pipeline_result.flow_findings)
        self.assertEqual(self.flow_summary(result), self.flow_summary(plain))
        self.assertEqual(self.packet_summary(result), self.packet_summary(plain))

    def test_malformed_tagged_frames_are_non_evaluable_and_release_source(self):
        good = tcp_exchange(False)[0][1]
        truncated = good[:12] + b"\x81\x00\x00"
        three = good[:12] + (b"\x81\x00" + tag_bytes()) * 3 + good[12:]
        packets = ((1000000, truncated), (1000001, three), (1000002, good))
        result = self.run_packets(packets)
        self.assertEqual(
            [item[2] for item in self.packet_summary(result)],
            [PacketAnalysisFailureClassification.INCOMPLETE, PacketAnalysisFailureClassification.UNSUPPORTED, None])
        alone = self.run_packets(((1000002, good),))
        self.assertEqual(self.flow_summary(result), self.flow_summary(alone))


if __name__ == "__main__":
    unittest.main()
