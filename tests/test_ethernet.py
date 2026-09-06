import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from typing import cast

from analysis import EthernetDecodeError, EthernetFrame, decode_ethernet
from capture.packet_observation import CaptureSource, LinkType, PacketObservation
from capture.packet_source import CaptureError


class EthernetDecoderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.header = bytes.fromhex("00112233445566778899aabb1234")
        self.observation = PacketObservation(
            captured_at=datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc),
            link_type=LinkType(1),
            captured_length=len(self.header),
            original_length=len(self.header),
            raw_bytes=self.header,
            source=CaptureSource("ethernet-test"),
        )

    def test_complete_header_decodes_with_empty_payload(self) -> None:
        frame = decode_ethernet(self.observation)
        self.assertEqual(frame.destination_mac, b"\x00\x11\x22\x33\x44\x55")
        self.assertEqual(frame.source_mac, b"\x66\x77\x88\x99\xaa\xbb")
        self.assertEqual(frame.ether_type, 0x1234)
        self.assertEqual(frame.payload, b"")

    def test_binary_payload_and_capture_observation_are_preserved(self) -> None:
        payload = b"\x00\xff\x80\n\r\x00"
        raw_bytes = self.header + payload
        observation = replace(
            self.observation,
            raw_bytes=raw_bytes,
            captured_length=len(raw_bytes),
            original_length=len(raw_bytes) + 10,
        )
        before = replace(observation)
        frame = decode_ethernet(observation)
        self.assertIsInstance(frame.payload, bytes)
        self.assertEqual(frame.payload, payload)
        self.assertEqual(observation, before)
        self.assertIs(observation.raw_bytes, raw_bytes)
        self.assertEqual(raw_bytes, self.header + payload)
        self.assertIs(observation.source, before.source)
        self.assertIs(observation.link_type, before.link_type)
        self.assertIs(observation.captured_at, before.captured_at)

    def test_short_headers_raise_decoding_errors(self) -> None:
        for length in (0, 1, 13):
            with self.subTest(length=length):
                observation = replace(
                    self.observation,
                    raw_bytes=bytes(length),
                    captured_length=length,
                    original_length=length,
                )
                with self.assertRaisesRegex(EthernetDecodeError, "too short") as failure:
                    decode_ethernet(observation)
                self.assertIn("14 bytes", str(failure.exception))
                self.assertNotIsInstance(failure.exception, CaptureError)

    def test_non_ethernet_link_types_are_rejected(self) -> None:
        for value in (0, 101, 65535):
            with self.subTest(value=value):
                observation = replace(self.observation, link_type=LinkType(value))
                with self.assertRaisesRegex(EthernetDecodeError, r"LinkType\(1\)"):
                    decode_ethernet(observation)

    def test_unknown_link_type_is_rejected(self) -> None:
        observation = replace(self.observation, link_type=None)
        with self.assertRaisesRegex(EthernetDecodeError, r"LinkType\(1\)"):
            decode_ethernet(observation)

    def test_independent_frames_preserve_unsigned_type_values(self) -> None:
        first_bytes = bytes.fromhex("00112233445566778899aabb0000") + b"first"
        second_bytes = bytes.fromhex("ffeeddccbbaa998877665544ffff") + b"second"
        frames = []
        for raw_bytes in (first_bytes, second_bytes):
            observation = replace(
                self.observation,
                raw_bytes=raw_bytes,
                captured_length=len(raw_bytes),
                original_length=len(raw_bytes),
            )
            frames.append(decode_ethernet(observation))
        self.assertEqual(
            frames,
            [
                EthernetFrame(first_bytes[:6], first_bytes[6:12], 0, b"first"),
                EthernetFrame(second_bytes[:6], second_bytes[6:12], 65535, b"second"),
            ],
        )
        self.assertIsNot(frames[0], frames[1])

    def test_decoder_requires_packet_observation(self) -> None:
        with self.assertRaises(TypeError):
            decode_ethernet(cast(PacketObservation, self.header))


class EthernetFrameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.frame = EthernetFrame(
            destination_mac=b"\x00\x11\x22\x33\x44\x55",
            source_mac=b"\x66\x77\x88\x99\xaa\xbb",
            ether_type=0x1234,
            payload=b"\x00\xff\x80",
        )

    def test_mac_addresses_require_exactly_six_immutable_bytes(self) -> None:
        for name in ("destination_mac", "source_mac"):
            for value in (b"", b"12345", b"1234567"):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(ValueError):
                        replace(self.frame, **{name: value})
            for value in (bytearray(6), memoryview(bytes(6)), "001122334455", None):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.frame, **{name: value})

    def test_ether_type_requires_unsigned_sixteen_bit_integer(self) -> None:
        for value in (-1, 65536):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    replace(self.frame, ether_type=value)
        for value in (True, False, 4660.0, "4660", None):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    replace(self.frame, ether_type=value)

    def test_payload_requires_immutable_bytes(self) -> None:
        for value in (bytearray(b"data"), memoryview(b"data"), "data", None):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    replace(self.frame, payload=value)

    def test_frame_is_immutable(self) -> None:
        for name, value in (
            ("destination_mac", bytes(6)),
            ("source_mac", bytes(6)),
            ("ether_type", 0),
            ("payload", b""),
        ):
            with self.subTest(field=name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(self.frame, name, value)
                with self.assertRaises(FrozenInstanceError):
                    delattr(self.frame, name)
