import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    LinkLayerDecodeError, LinkLayerFrame, PacketAnalysisFailureClassification, analyze_packet,
    analyze_packet_outcome, decode_link_layer, update_ipv4_fragmentation_statistics,
)
from application import GroundTruth, run_end_to_end_validation
from application.capture_fragmentation import run_capture_fragmentation_statistics
from capture import CaptureSource, PcapPacketSource
from capture.packet_observation import LinkType, PacketObservation
from tests.pcap_scenarios import tcp_exchange, udp_exchange
from tests.test_end_to_end_validation import settings
from tests.test_packet_analysis import UDP_BYTES, make_observation
from tests.test_pcap_packet_source import global_header, record

SOURCE = CaptureSource("link-layer-test")
COOKED_ADDRESS = bytes.fromhex("0011223344550000")


def observation_on(link_type, raw):
    return PacketObservation(
        captured_at=datetime(2026, 9, 6, tzinfo=timezone.utc), link_type=LinkType(link_type),
        captured_length=len(raw), original_length=len(raw), raw_bytes=raw, source=SOURCE)


def cooked(raw, protocol=None, packet_type=0, hardware_type=1):
    protocol = int.from_bytes(raw[12:14], "big") if protocol is None else protocol
    return (packet_type.to_bytes(2, "big") + hardware_type.to_bytes(2, "big") + (6).to_bytes(2, "big")
            + COOKED_ADDRESS + protocol.to_bytes(2, "big") + raw[14:])


def pcap_on(link_type, packets):
    return global_header(network=link_type) + b"".join(
        record(raw, seconds=time // 1000000, fraction=time % 1000000) for time, raw in packets)


class LinkLayerDecodeTests(unittest.TestCase):
    def test_raw_ip_dispatches_on_version_and_keeps_all_bytes(self):
        for version, ether_type in ((4, 0x0800), (6, 0x86DD)):
            for tail in (b"", b"\x00\xff"):
                raw = bytes((version << 4 | 5,)) + tail
                frame = decode_link_layer(observation_on(101, raw))
                self.assertEqual((frame.link_type, frame.ether_type, frame.payload), (101, ether_type, raw))
                self.assertEqual((frame.packet_type, frame.hardware_type), (None, None))

    def test_raw_ip_rejects_other_versions_and_empty_input(self):
        for version in (0, 1, 3, 5, 7, 15):
            with self.subTest(version=version):
                raw = bytes((version << 4,)) + bytes(30)
                with self.assertRaisesRegex(LinkLayerDecodeError, "version must be 4 or 6"):
                    decode_link_layer(observation_on(101, raw))
                outcome = analyze_packet_outcome(observation_on(101, raw))
                self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.UNSUPPORTED)
        with self.assertRaisesRegex(LinkLayerDecodeError, "too short"):
            decode_link_layer(observation_on(101, b""))
        self.assertIs(analyze_packet_outcome(observation_on(101, b"")).failure_classification,
                      PacketAnalysisFailureClassification.INCOMPLETE)

    def test_linux_cooked_header_fields_and_boundaries(self):
        header = bytes.fromhex("0004 0304 0006 aabbccddeeff0000 86dd")
        frame = decode_link_layer(observation_on(113, header))
        self.assertEqual((frame.link_type, frame.packet_type, frame.hardware_type, frame.ether_type, frame.payload),
                         (113, 4, 0x0304, 0x86DD, b""))
        longer = decode_link_layer(observation_on(113, header + b"payload"))
        self.assertEqual(longer.payload, b"payload")
        for length in range(16):
            with self.subTest(length=length):
                with self.assertRaisesRegex(LinkLayerDecodeError, "too short"):
                    decode_link_layer(observation_on(113, header[:length]))
                self.assertIs(analyze_packet_outcome(observation_on(113, header[:length])).failure_classification,
                              PacketAnalysisFailureClassification.INCOMPLETE)

    def test_unsupported_link_types_are_rejected_before_decoding(self):
        raw = make_observation(17, UDP_BYTES).raw_bytes
        for code in (0, 2, 12, 65001):
            with self.subTest(code=code):
                with self.assertRaisesRegex(LinkLayerDecodeError, "requires LinkType"):
                    decode_link_layer(observation_on(code, raw))
                outcome = analyze_packet_outcome(observation_on(code, raw))
                self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.UNSUPPORTED)

    def test_non_ip_cooked_protocols_are_unsupported(self):
        raw = cooked(make_observation(17, UDP_BYTES).raw_bytes, protocol=0x0806)
        outcome = analyze_packet_outcome(observation_on(113, raw))
        self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.UNSUPPORTED)
        tagged = cooked(make_observation(17, UDP_BYTES).raw_bytes, protocol=0x8100)
        self.assertFalse(analyze_packet_outcome(observation_on(113, tagged)).succeeded)

    def test_decoder_requires_a_packet_observation(self):
        for value in (None, b"\x45", object()):
            with self.assertRaises(TypeError):
                decode_link_layer(value)

    def test_frame_validation_and_immutability(self):
        frame = LinkLayerFrame(113, 0x0800, b"x", 1, 2)
        with self.assertRaises(FrozenInstanceError):
            frame.payload = b"y"
        for arguments in ((1, 0x0800, b"x"), (101, 70000, b"x"), (101, 0x0800, b"x", 1, None),
                          (113, 0x0800, b"x"), (113, 0x0800, b"x", 65536, 1), (113, 0x0800, b"x", 1, -1)):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                LinkLayerFrame(*arguments)
        for arguments in ((True, 0x0800, b"x"), (101, "x", b"x"), (101, 0x0800, bytearray(b"x")),
                          (113, 0x0800, b"x", 1.0, 1)):
            with self.subTest(arguments=arguments), self.assertRaises(TypeError):
                LinkLayerFrame(*arguments)


class LinkLayerAnalysisTests(unittest.TestCase):
    def frames(self):
        for ipv6 in (False, True):
            for _, raw in tcp_exchange(ipv6)[:2] + udp_exchange(ipv6)[:2]:
                yield raw

    def test_raw_ip_and_cooked_match_ethernet_analysis(self):
        names = ("ipv4", "ipv6", "ipv6_extension_headers", "tcp", "udp", "icmp", "ipv6_tcp", "ipv6_udp",
                 "ipv4_checksum_valid", "tcp_checksum_valid", "udp_checksum_valid", "icmp_checksum_valid")
        for raw in self.frames():
            plain = analyze_packet(observation_on(1, raw))
            for code, wrapped_raw in ((101, raw[14:]), (113, cooked(raw))):
                with self.subTest(code=code):
                    wrapped = analyze_packet(observation_on(code, wrapped_raw))
                    self.assertIsNone(wrapped.ethernet)
                    self.assertEqual(wrapped.link_layer.link_type, code)
                    self.assertEqual(wrapped.link_layer.ether_type, plain.ethernet.ether_type)
                    for name in names:
                        self.assertEqual(getattr(wrapped, name), getattr(plain, name), name)
        self.assertIsNone(analyze_packet(observation_on(1, next(iter(self.frames())))).link_layer)

    def test_analysis_rejects_both_frame_models(self):
        analysis = analyze_packet(observation_on(1, next(iter(self.frames()))))
        with self.assertRaises(Exception):
            replace(analysis, link_layer=LinkLayerFrame(101, 0x0800, b""))
        with self.assertRaises(TypeError):
            replace(analysis, link_layer=object())

    def test_integrity_and_fragment_failures_match_ethernet(self):
        for fragment_field in (0, 185, 0x2000 | 185):
            for protocol, payload in ((17, UDP_BYTES),):
                good = make_observation(protocol, payload, fragment_field=fragment_field).raw_bytes
                bad = make_observation(protocol, payload, fragment_field=fragment_field, ipv4_checksum=1).raw_bytes
                for raw in (good, bad):
                    plain = analyze_packet_outcome(observation_on(1, raw))
                    for code, wrapped in ((101, raw[14:]), (113, cooked(raw))):
                        outcome = analyze_packet_outcome(observation_on(code, wrapped))
                        self.assertEqual(outcome.failure_classification, plain.failure_classification)
                        self.assertEqual(outcome.failure_description, plain.failure_description)

    def test_fragment_statistics_count_non_initial_fragments_on_every_link_type(self):
        raws = [make_observation(17, UDP_BYTES, fragment_field=field).raw_bytes for field in (0, 0x2000, 0x2000 | 5, 5)]
        for code, convert in ((1, lambda raw: raw), (101, lambda raw: raw[14:]), (113, cooked)):
            with self.subTest(code=code):
                statistics = None
                for raw in raws:
                    statistics = update_ipv4_fragmentation_statistics(
                        statistics, analyze_packet_outcome(observation_on(code, convert(raw))))
                self.assertEqual((statistics.packet_count, statistics.non_initial_fragment_packet_count), (4, 2))


class LinkLayerPcapTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.configuration = settings()

    def run_pcap(self, link_type, packets, runner=None):
        path = self.directory / "capture.pcap"
        path.write_bytes(pcap_on(link_type, packets))
        source = PcapPacketSource(path, source=SOURCE)
        with patch.object(source, "stop", wraps=source.stop) as stop:
            try:
                if runner is not None:
                    return runner(source)
                return run_end_to_end_validation(
                    source, configuration=self.configuration, capture_session_id="link",
                    ground_truth=GroundTruth((), ()))
            finally:
                stop.assert_called_once()
                self.assertEqual(list(source), [])

    def summaries(self, result):
        flows = [(f.detector_id, f.decision, f.raw_evidence.identity, f.raw_evidence.first_captured_at,
                  f.raw_evidence.last_captured_at) for f in result.pipeline_result.flow_findings]
        packets = [(f.detector_id, f.decision, f.raw_evidence.outcome.failure_classification)
                   for f in result.pipeline_result.packet_findings]
        return flows, packets

    def test_replay_matches_ethernet_for_raw_ip_and_cooked(self):
        base = tcp_exchange(False) + tuple((time + 10000000, raw) for time, raw in tcp_exchange(True)) + tuple(
            (time + 20000000, raw) for time, raw in udp_exchange(False))
        expected = self.summaries(self.run_pcap(1, base))
        self.assertTrue(expected[0])
        for code, convert in ((101, lambda raw: raw[14:]), (113, cooked)):
            with self.subTest(code=code):
                result = self.run_pcap(code, tuple((time, convert(raw)) for time, raw in base))
                self.assertEqual(self.summaries(result), expected)
                self.assertTrue(all(f.raw_evidence.outcome.analysis.link_layer.link_type == code
                                    for f in result.pipeline_result.packet_findings))

    def test_malformed_packets_are_non_evaluable_and_release_source(self):
        good = tcp_exchange(False)[0][1]
        packets = ((1000000, b""), (1000001, b"\x55" + bytes(40)), (1000002, good[14:]))
        result = self.run_pcap(101, packets)
        classes = [item[2] for item in self.summaries(result)[1]]
        self.assertEqual(classes, [PacketAnalysisFailureClassification.INCOMPLETE,
                                   PacketAnalysisFailureClassification.UNSUPPORTED, None])

    def test_fragment_runner_agrees_across_link_types(self):
        raws = tuple((1000000 + index, make_observation(17, UDP_BYTES, fragment_field=field).raw_bytes)
                     for index, field in enumerate((0, 0x2000, 0x2000 | 5, 5)))
        expected = self.run_pcap(1, raws, run_capture_fragmentation_statistics)
        self.assertEqual(expected.packet_count, 4)
        for code, convert in ((101, lambda raw: raw[14:]), (113, cooked)):
            self.assertEqual(self.run_pcap(code, tuple((t, convert(raw)) for t, raw in raws),
                                           run_capture_fragmentation_statistics), expected)


if __name__ == "__main__":
    unittest.main()
