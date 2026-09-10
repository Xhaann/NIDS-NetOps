import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path
from struct import pack
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

import capture
from analysis import PacketAnalysisFailureClassification, analyze_packet_outcome
from application import DetectionSession, run_detection_pipeline
from capture import CaptureError, CaptureSource, LinkType, PacketSource, PcapPacketSource, consume
from detection import FlowVolumeMetric, PacketIntegrityConfiguration
from tests.test_flow_volume_threshold import configuration as volume_configuration
from tests.test_ipv6_flow import observation_at
from tests.test_packet_analysis import TCP_BYTES, UDP_BYTES, make_observation
from tests.test_tcp_control_threshold import configuration as control_configuration


def global_header(order="<", nano=False, version=(2, 4), zone=0, sigfigs=0, snaplen=65535, network=1):
    return pack(order + "IHHiIII", 0xA1B23C4D if nano else 0xA1B2C3D4,
                *version, zone, sigfigs, snaplen, network)


def record(payload=b"packet", order="<", seconds=1, fraction=0, captured=None, original=None):
    size = len(payload) if captured is None else captured
    return pack(order + "IIII", seconds, fraction, size, size if original is None else original) + payload


class PcapPacketSourceTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "capture.pcap"

    def write(self, data):
        self.path.write_bytes(data)
        return PcapPacketSource(self.path)

    def collect(self, data):
        source = self.write(data)
        observations = []
        consume(source, observations.append)
        self.assertEqual(list(source), [])
        return observations

    def test_all_four_magic_variants_preserve_metadata_bytes_and_utc_precision(self):
        for order in ("<", ">"):
            for nano in (False, True):
                with self.subTest(order=order, nano=nano):
                    payload = bytes.fromhex("00ff80deadbeef")
                    fraction = 123456789 if nano else 123456
                    data = global_header(order, nano, zone=-19800, sigfigs=0xFFFFFFFF)
                    data += record(payload, order, seconds=0xFFFFFFFF, fraction=fraction, original=9000)
                    source = self.write(data)
                    identity = CaptureSource("capture-evidence")
                    source = PcapPacketSource(self.path, source=identity)
                    observations = []
                    consume(source, observations.append)
                    self.assertEqual(len(observations), 1)
                    value = observations[0]
                    self.assertEqual(value.captured_at, datetime(2106, 2, 7, 6, 28, 15, 123456, tzinfo=timezone.utc))
                    self.assertIs(value.captured_at.tzinfo, timezone.utc)
                    self.assertEqual((value.raw_bytes, value.captured_length, value.original_length), (payload, 7, 9000))
                    self.assertEqual(value.link_type, LinkType(1))
                    self.assertIs(value.source, identity)
                    self.assertEqual(self.path.read_bytes(), data)
                    with self.assertRaises(FrozenInstanceError):
                        value.raw_bytes = b"changed"

    def test_epoch_fraction_boundaries_and_nanosecond_truncation_without_rounding(self):
        for nano, fractions, expected in (
            (False, (0, 1, 999999), (0, 1, 999999)),
            (True, (0, 1, 999, 1000, 1999, 999999999), (0, 0, 0, 1, 1, 999999)),
        ):
            data = global_header(nano=nano) + b"".join(record(seconds=0, fraction=f) for f in fractions)
            observations = self.collect(data)
            self.assertEqual([o.captured_at for o in observations],
                             [datetime(1970, 1, 1, 0, 0, 0, f, tzinfo=timezone.utc) for f in expected])

    def test_reserved_timezone_and_sigfigs_do_not_change_timestamp(self):
        for zone in (-2147483648, -19800, 19800, 2147483647):
            values = self.collect(global_header(zone=zone, sigfigs=0xFFFFFFFF) + record(seconds=0))
            self.assertEqual(values[0].captured_at, datetime(1970, 1, 1, tzinfo=timezone.utc))

    def test_zero_packet_captures_have_normal_lifecycle_in_all_formats(self):
        for order in ("<", ">"):
            for nano in (False, True):
                self.assertEqual(self.collect(global_header(order, nano)), [])

    def test_zero_byte_packets_and_capture_truncation_preserve_both_lengths(self):
        values = self.collect(global_header(snaplen=3) + record(b"", original=5) + record(b"abc", original=100)
                              + record(b"xyz") + record(b""))
        self.assertEqual([(o.raw_bytes, o.captured_length, o.original_length) for o in values],
                         [(b"", 0, 5), (b"abc", 3, 100), (b"xyz", 3, 3), (b"", 0, 0)])

    def test_order_duplicates_and_decreasing_timestamps_are_not_normalized(self):
        data = global_header() + record(b"third", seconds=3) + record(b"first", seconds=1) + record(b"third", seconds=3)
        values = self.collect(data)
        self.assertEqual([o.raw_bytes for o in values], [b"third", b"first", b"third"])
        self.assertEqual([o.captured_at.second for o in values], [3, 1, 3])
        self.assertEqual(values[0], values[2])
        self.assertIsNot(values[0], values[2])

    def test_all_portable_link_codes_propagate_without_protocol_decoding(self):
        for code in (0, 1, 101, 65001, 65535):
            observation = self.collect(global_header(network=code) + record(b"unparsed"))[0]
            self.assertEqual(observation.link_type, LinkType(code))
            self.assertEqual(observation.raw_bytes, b"unparsed")
            if code != 1:
                outcome = analyze_packet_outcome(observation)
                self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.UNSUPPORTED)

    def test_global_header_truncation_at_every_boundary_is_rejected_before_delivery(self):
        header = global_header()
        for length in range(24):
            source = self.write(header[:length])
            delivered = []
            with self.assertRaisesRegex(CaptureError, "truncated PCAP global header"):
                consume(source, delivered.append)
            self.assertEqual(delivered, [])
            self.assertEqual(list(source), [])

    def test_invalid_magic_including_pcapng_is_rejected(self):
        for magic in (b"\x00" * 4, b"\x0a\x0d\x0d\x0a", b"\x34\xcd\xb2\xa1"):
            with self.assertRaisesRegex(CaptureError, "unsupported PCAP magic number"):
                self.collect(magic + global_header()[4:])

    def test_invalid_versions_snaplen_and_unrepresentable_network_metadata_are_rejected(self):
        cases = [(global_header(version=v), "version must be 2.4") for v in ((0, 0), (2, 3), (2, 5), (3, 4))]
        cases.append((global_header(snaplen=0), "snaplen must be positive"))
        cases.extend((global_header(network=n), "additional link-type information is unsupported")
                     for n in (0x10001, 0x04000001, 0x08000001, 0x24000001, 0xFFFFFFFF))
        for data, message in cases:
            with self.subTest(message=message, header=data):
                with self.assertRaisesRegex(CaptureError, message):
                    self.collect(data + record())

    def test_record_header_truncation_at_every_boundary_is_not_eof(self):
        for length in range(1, 16):
            with self.assertRaisesRegex(CaptureError, "truncated PCAP record header"):
                self.collect(global_header() + record()[:length])

    def test_invalid_fraction_limits_in_both_byte_orders_and_resolutions(self):
        for order in ("<", ">"):
            for nano, limit in ((False, 1000000), (True, 1000000000)):
                for fraction in (limit, 0xFFFFFFFF):
                    with self.assertRaisesRegex(CaptureError, "timestamp fraction exceeds its resolution"):
                        self.collect(global_header(order, nano) + record(order=order, fraction=fraction))

    def test_invalid_record_lengths_are_rejected_without_padding_or_correction(self):
        cases = ((global_header(snaplen=5) + record(b"abcdef"), "captured length exceeds snaplen"),
                 (global_header() + record(b"abc", original=2), "original length is smaller"),
                 (global_header() + record(b"abc", captured=4), "truncated PCAP packet payload"),
                 (global_header(snaplen=0xFFFFFFFF) + record(b"", captured=0xFFFFFFFF), "truncated PCAP packet payload"))
        for data, message in cases:
            with self.assertRaisesRegex(CaptureError, message):
                self.collect(data)

    def test_every_payload_truncation_is_rejected(self):
        data = global_header() + record(b"abcdef")
        for removed in range(1, 7):
            with self.assertRaisesRegex(CaptureError, "truncated PCAP packet payload"):
                self.collect(data[:-removed])

    def test_corruption_after_valid_records_raises_without_skipping_or_rollback(self):
        data = global_header() + record(b"first") + record(b"second") + b"bad"
        for _ in range(2):
            source = self.write(data)
            values = []
            with self.assertRaisesRegex(CaptureError, "truncated PCAP record header"):
                consume(source, values.append)
            self.assertEqual([v.raw_bytes for v in values], [b"first", b"second"])
            self.assertEqual(list(source), [])

    def test_public_export_and_construction_do_not_open_file(self):
        self.assertIs(capture.PcapPacketSource, PcapPacketSource)
        self.assertIn("PcapPacketSource", capture.__all__)
        with patch.object(Path, "open", side_effect=AssertionError("construction must not open")):
            source: PacketSource = PcapPacketSource(str(self.path))
            with self.assertRaises(RuntimeError):
                iter(source)
            with self.assertRaises(RuntimeError):
                next(source)
            source.stop()
        with self.assertRaises(TypeError):
            PcapPacketSource(self.path, source="invalid")
        with self.assertRaises(TypeError):
            PcapPacketSource(3)

    def test_start_and_stop_once_through_consume_and_close_owned_handle(self):
        source = self.write(global_header() + record())
        handle = self.path.open("rb")
        tracked = Mock(wraps=handle)
        with patch.object(Path, "open", return_value=tracked) as opened, \
             patch.object(source, "start", wraps=source.start) as start, \
             patch.object(source, "stop", wraps=source.stop) as stop:
            consume(source, lambda value: None)
        opened.assert_called_once_with("rb")
        start.assert_called_once()
        stop.assert_called_once()
        tracked.close.assert_called_once()
        self.assertTrue(handle.closed)
        source.stop()
        tracked.close.assert_called_once()

    def test_iteration_resumes_and_exhaustion_is_permanent(self):
        source = self.write(global_header() + record(b"first") + record(b"last"))
        try:
            source.start()
            self.assertEqual(next(iter(source)).raw_bytes, b"first")
            with self.assertRaises(RuntimeError):
                source.start()
            self.assertEqual([v.raw_bytes for v in source], [b"last"])
            with self.path.open("ab") as output:
                output.write(record(b"later"))
            self.assertEqual(list(source), [])
            with self.assertRaises(StopIteration):
                next(source)
        finally:
            source.stop()
        with self.assertRaises(RuntimeError):
            source.start()

    def test_stop_before_start_and_early_stop_are_terminal(self):
        for started in (False, True):
            source = self.write(global_header() + record(b"first") + record(b"last"))
            if started:
                source.start()
                self.assertEqual(next(source).raw_bytes, b"first")
            source.stop()
            source.stop()
            self.assertEqual(list(source), [])
            with self.assertRaises(RuntimeError):
                source.start()

    def test_failed_start_and_failed_record_require_stop_not_retry(self):
        for data, startup in ((b"bad", True), (global_header() + b"bad", False)):
            source = self.write(data)
            try:
                if not startup:
                    source.start()
                with self.assertRaises(CaptureError):
                    source.start() if startup else next(source)
                for operation in (source.start, lambda: iter(source), lambda: next(source)):
                    with self.assertRaises(RuntimeError):
                        operation()
            finally:
                source.stop()
            self.assertEqual(list(source), [])

    def test_global_and_record_parse_failures_close_file_through_consumer(self):
        for data in (b"bad", global_header() + b"bad", global_header() + record(captured=100)):
            source = self.write(data)
            handle = self.path.open("rb")
            tracked = Mock(wraps=handle)
            with patch.object(Path, "open", return_value=tracked), patch.object(source, "stop", wraps=source.stop) as stop:
                with self.assertRaises(CaptureError):
                    consume(source, lambda value: None)
            stop.assert_called_once()
            tracked.close.assert_called_once()
            self.assertTrue(handle.closed)

    def test_open_read_and_close_os_errors_use_capture_error_with_exact_cause(self):
        source = PcapPacketSource(self.path)
        with self.assertRaises(CaptureError) as raised:
            consume(source, lambda value: None)
        self.assertIsInstance(raised.exception.__cause__, FileNotFoundError)
        for phase in ("read", "close"):
            source = self.write(global_header() + record())
            handle = self.path.open("rb")
            tracked = Mock(wraps=handle)
            error = OSError(phase)
            def close():
                handle.close()
                raise error
            if phase == "read":
                tracked.read.side_effect = (global_header(), error)
            else:
                tracked.close.side_effect = close
            with patch.object(Path, "open", return_value=tracked):
                with self.assertRaises(CaptureError) as raised:
                    consume(source, lambda value: None)
            self.assertIs(raised.exception.__cause__, error)
            self.assertTrue(handle.closed)

    def test_short_read_after_initial_size_check_is_an_explicit_failure(self):
        source = self.write(global_header() + record())
        handle = self.path.open("rb")
        tracked = Mock(wraps=handle)
        tracked.read.side_effect = (global_header(), record()[:16], b"short")
        with patch.object(Path, "open", return_value=tracked):
            with self.assertRaisesRegex(CaptureError, "truncated PCAP packet payload"):
                consume(source, lambda value: None)
        self.assertTrue(handle.closed)

    def test_downstream_errors_propagate_without_retry_or_read_ahead(self):
        source = self.write(global_header() + record(b"first") + record(b"second"))
        handle = self.path.open("rb")
        tracked = Mock(wraps=handle)
        error = ValueError("downstream sentinel")
        consumer = Mock(side_effect=error)
        with patch.object(Path, "open", return_value=tracked):
            with self.assertRaises(ValueError) as raised:
                consume(source, consumer)
        self.assertIs(raised.exception, error)
        consumer.assert_called_once()
        self.assertEqual([call.args for call in tracked.read.call_args_list], [(24,), (16,), (5,)])
        self.assertTrue(handle.closed)

    def test_incremental_reads_are_bounded_to_header_and_current_payload(self):
        source = self.write(global_header() + b"".join(record(b"abcdefgh") for _ in range(100)))
        handle = self.path.open("rb")
        tracked = Mock(wraps=handle)
        with patch.object(Path, "open", return_value=tracked):
            try:
                source.start()
                self.assertEqual([call.args for call in tracked.read.call_args_list], [(24,)])
                next(source)
                self.assertEqual([call.args for call in tracked.read.call_args_list], [(24,), (16,), (8,)])
                self.assertEqual(len(list(source)), 99)
            finally:
                source.stop()
        self.assertEqual([call.args for call in tracked.read.call_args_list], [(24,)] + [(16,), (8,)] * 100)
        self.assertTrue(handle.closed)

    def test_untrusted_huge_length_is_rejected_before_payload_allocation(self):
        source = self.write(global_header(snaplen=0xFFFFFFFF) + record(b"", captured=0xFFFFFFFF))
        handle = self.path.open("rb")
        tracked = Mock(wraps=handle)
        with patch.object(Path, "open", return_value=tracked):
            with self.assertRaisesRegex(CaptureError, "truncated PCAP packet payload"):
                consume(source, lambda value: None)
        self.assertEqual([call.args for call in tracked.read.call_args_list], [(24,), (16,)])
        self.assertTrue(handle.closed)

    def test_independent_sources_and_repeated_reads_have_no_stale_state(self):
        data = global_header() + record(b"first") + record(b"last")
        self.path.write_bytes(data)
        first, second = PcapPacketSource(self.path), PcapPacketSource(self.path)
        try:
            first.start()
            second.start()
            one = next(first)
            self.assertEqual(one, next(second))
            first.stop()
            self.assertEqual(next(second).raw_bytes, b"last")
        finally:
            first.stop()
            second.stop()
        self.assertEqual(self.collect(data), self.collect(data))
        self.assertEqual(self.collect(global_header(">", True, network=101) + record(b"new", ">", fraction=999))[0].link_type,
                         LinkType(101))

    def test_pcap_source_composes_with_unchanged_detection_pipeline_for_ipv4_and_ipv6(self):
        packets = (make_observation(6, TCP_BYTES), make_observation(17, UDP_BYTES), observation_at(6), observation_at(17))
        data = global_header(">", True)
        data += b"".join(record(p.raw_bytes, ">", seconds=i + 1, fraction=123456789, original=p.original_length)
                         for i, p in enumerate(packets))
        session = DetectionSession(PacketIntegrityConfiguration("packet-integrity", "1"),
                                   volume_configuration(FlowVolumeMetric.PACKET_COUNT), control_configuration())
        source = self.write(data)
        result = run_detection_pipeline(source, detection_session=session, capture_session_id="pcap-integration",
                                        inactivity_timeout=timedelta(seconds=5))
        self.assertEqual(len(result.packet_findings), 4)
        self.assertEqual([f.raw_evidence.protocol for f in result.flow_findings], [6, 6, 17, 6, 6, 17])
        self.assertEqual([f.raw_evidence.identity.ip_version for f in result.flow_findings], [4, 4, 4, 6, 6, 6])
        for finding, packet in zip(result.packet_findings, packets):
            self.assertEqual(finding.raw_evidence.outcome.observation.raw_bytes, packet.raw_bytes)
            self.assertEqual(finding.raw_evidence.outcome.observation.captured_at.microsecond, 123456)
            self.assertIs(finding.raw_evidence.configuration, session.packet_configuration)
        self.assertEqual(list(source), [])
        self.assertEqual(self.path.read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
