import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Optional, cast

from capture import CaptureSource, LinkType, PacketObservation


class UnknownOffset(tzinfo):
    def utcoffset(self, dt: Optional[datetime]) -> Optional[timedelta]:
        return None


class EquivalentUTC(tzinfo):
    def utcoffset(self, dt: Optional[datetime]) -> timedelta:
        return timedelta(0)


class MalformedOffset(tzinfo):
    def utcoffset(self, dt: Optional[datetime]) -> str:
        return "zero"


class RaisingOffset(tzinfo):
    def utcoffset(self, dt: Optional[datetime]) -> timedelta:
        raise RuntimeError("offset must not be evaluated")


class PacketObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw_bytes = b"\x00\xff\x80\x01"
        self.source = CaptureSource("sensor-a:input-1")
        self.timestamp = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)
        self.observation = PacketObservation(
            captured_at=self.timestamp,
            link_type=LinkType(1),
            captured_length=4,
            original_length=4,
            raw_bytes=self.raw_bytes,
            source=self.source,
        )

    def test_valid_observation_preserves_supplied_values(self) -> None:
        self.assertEqual(self.observation.captured_at, self.timestamp)
        self.assertEqual(self.observation.link_type, LinkType(1))
        self.assertEqual(self.observation.captured_length, 4)
        self.assertEqual(self.observation.original_length, 4)
        self.assertEqual(self.observation.raw_bytes, b"\x00\xff\x80\x01")
        self.assertIs(self.observation.raw_bytes, self.raw_bytes)
        self.assertIs(self.observation.source, self.source)

    def test_truncated_observation_preserves_original_length(self) -> None:
        observation = replace(self.observation, original_length=100)
        self.assertEqual(observation.original_length, 100)
        self.assertIs(observation.raw_bytes, self.raw_bytes)

    def test_unknown_metadata_remains_unknown(self) -> None:
        observation = replace(self.observation, link_type=None, original_length=None)
        self.assertIsNone(observation.link_type)
        self.assertIsNone(observation.original_length)

    def test_empty_observation_is_valid(self) -> None:
        observation = replace(
            self.observation, raw_bytes=b"", captured_length=0, original_length=0
        )
        self.assertEqual(observation.raw_bytes, b"")
        self.assertEqual(observation.captured_length, 0)

    def test_captured_length_must_match_bytes(self) -> None:
        for length in (0, 3, 5):
            with self.subTest(length=length):
                with self.assertRaisesRegex(ValueError, "captured_length must equal"):
                    replace(self.observation, captured_length=length)

    def test_original_length_must_cover_captured_bytes(self) -> None:
        with self.assertRaisesRegex(ValueError, "original_length must not be smaller"):
            replace(self.observation, original_length=3)

    def test_negative_lengths_are_rejected(self) -> None:
        for name in ("captured_length", "original_length"):
            with self.subTest(field=name):
                with self.assertRaisesRegex(ValueError, f"{name} must not be negative"):
                    replace(self.observation, **{name: -1})

    def test_lengths_require_integers_without_coercion(self) -> None:
        for name in ("captured_length", "original_length"):
            for value in (True, False, 4.0, "4"):
                with self.subTest(field=name, value=value):
                    with self.assertRaisesRegex(TypeError, f"{name} must be an integer"):
                        replace(self.observation, **{name: value})
        with self.assertRaisesRegex(TypeError, "captured_length must be an integer"):
            replace(self.observation, captured_length=None)

    def test_naive_timestamps_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone-aware UTC"):
            replace(self.observation, captured_at=datetime(2026, 9, 6))

    def test_positive_and_negative_non_utc_offsets_are_rejected_without_conversion(self) -> None:
        before = vars(self.observation).copy()
        for offset in (timedelta(hours=5, minutes=30), timedelta(hours=-7),
                       timedelta(microseconds=1), timedelta(microseconds=-1)):
            timestamp = self.timestamp.astimezone(timezone(offset))
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(ValueError, "zero UTC offset"):
                    replace(self.observation, captured_at=timestamp)
            self.assertEqual(timestamp.utcoffset(), offset)
        self.assertEqual(vars(self.observation), before)

    def test_builtin_utc_and_distinct_named_zero_offsets_preserve_exact_timestamp(self) -> None:
        named_utc = timezone(timedelta(0), "UTC alias")
        self.assertIsNot(named_utc, timezone.utc)
        for zone in (timezone.utc, named_utc):
            for microsecond in (0, 1, 500000, 999999):
                timestamp = self.timestamp.replace(tzinfo=zone, microsecond=microsecond)
                observation = replace(self.observation, captured_at=timestamp)
                self.assertIs(observation.captured_at, timestamp)
                self.assertIs(observation.captured_at.tzinfo, zone)
                self.assertEqual(observation.captured_at.utcoffset(), timedelta(0))

    def test_custom_unknown_and_malformed_timezone_behaviors_are_rejected(self) -> None:
        for zone in (EquivalentUTC(), UnknownOffset(), MalformedOffset(), RaisingOffset()):
            timestamp = self.timestamp.replace(tzinfo=zone)
            with self.subTest(kind=type(zone)):
                with self.assertRaisesRegex(ValueError, "fixed UTC datetime.timezone"):
                    replace(self.observation, captured_at=timestamp)

    def test_datetime_subclasses_cannot_override_elapsed_time_arithmetic(self) -> None:
        class AlternateArithmetic(datetime):
            def __sub__(self, other):
                return timedelta(0)

        timestamp = AlternateArithmetic(2026, 9, 6, 12, tzinfo=timezone.utc)
        with self.assertRaisesRegex(TypeError, "exact built-in type"):
            replace(self.observation, captured_at=timestamp)

    def test_caller_must_explicitly_convert_non_utc_timestamps(self) -> None:
        local = self.timestamp.astimezone(timezone(timedelta(hours=-4)))
        with self.assertRaises(ValueError):
            replace(self.observation, captured_at=local)
        converted = local.astimezone(timezone.utc)
        observation = replace(self.observation, captured_at=converted)
        self.assertIs(observation.captured_at, converted)
        self.assertEqual(observation.captured_at, self.timestamp)

    def test_timestamp_requires_datetime(self) -> None:
        for value in (None, 0, "2026-09-06T12:00:00Z"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "captured_at must be a datetime"):
                    replace(self.observation, captured_at=value)

    def test_raw_data_requires_immutable_bytes(self) -> None:
        for value in (bytearray(self.raw_bytes), memoryview(self.raw_bytes), "data", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "raw_bytes must be immutable bytes"):
                    replace(self.observation, raw_bytes=value)

    def test_source_requires_explicit_identity(self) -> None:
        for value in ("sensor-a:input-1", {"identifier": "sensor-a:input-1"}, None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "source must be a CaptureSource"):
                    replace(self.observation, source=value)

    def test_link_type_requires_explicit_value(self) -> None:
        for value in (1, "ethernet"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "link_type must be a LinkType"):
                    replace(self.observation, link_type=value)

    def test_observation_and_metadata_are_immutable(self) -> None:
        for value, name, replacement in (
            (self.observation, "captured_length", 0),
            (self.observation, "raw_bytes", b""),
            (self.source, "identifier", "another-source"),
            (self.observation.link_type, "value", 2),
        ):
            with self.subTest(field=name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(value, name, replacement)
                with self.assertRaises(FrozenInstanceError):
                    delattr(value, name)


class CaptureSourceTests(unittest.TestCase):
    def test_identity_is_preserved_and_compared_by_value(self) -> None:
        source = CaptureSource(" sensor-a:input-1 ")
        self.assertEqual(source.identifier, " sensor-a:input-1 ")
        self.assertEqual(source, CaptureSource(" sensor-a:input-1 "))
        self.assertNotEqual(source, CaptureSource("sensor-a:input-1"))

    def test_blank_identity_is_rejected(self) -> None:
        for identifier in ("", " ", "\t\n"):
            with self.subTest(identifier=identifier):
                with self.assertRaises(ValueError):
                    CaptureSource(identifier)

    def test_identity_requires_string(self) -> None:
        for value in (None, 1, b"sensor-a"):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    CaptureSource(cast(str, value))


class LinkTypeTests(unittest.TestCase):
    def test_link_type_preserves_codes_including_unrecognized_values(self) -> None:
        for value in (0, 1, 65001, 65535):
            with self.subTest(value=value):
                self.assertEqual(LinkType(value).value, value)
                self.assertEqual(LinkType(value), LinkType(value))

    def test_link_type_rejects_out_of_range_codes(self) -> None:
        for value in (-1, 65536):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    LinkType(value)

    def test_link_type_rejects_non_integer_codes(self) -> None:
        for value in (True, False, 1.0, "1", None):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    LinkType(cast(int, value))
