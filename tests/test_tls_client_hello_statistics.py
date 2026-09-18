import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import FrozenInstanceError
from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import timedelta
from unittest.mock import patch

from analysis import (
    DirectionalTLSClientHelloStatistics,
    FlowDirection,
    TLSClientHelloStatistics,
    TLSClientHelloStatus,
    update_directional_tls_client_hello_statistics,
    update_tls_client_hello_statistics,
)
from tests.test_tls_client_hello import body, extension, identifiers, alpn, parse, selected_body
from tests.test_tls_handshake_statistics import altered
from tests.test_tls_client_hello_lifecycle import manager, packet, record, run_packets, wire, message
from tests.test_tls_client_hello_lifecycle import traffic
from tests.pcap_scenarios import pcap_bytes
from application import run_flow_observation_session
from capture import PcapPacketSource
from analysis.flow_observation_window import FlowObservationWindowUpdate


class TLSClientHelloStatisticsTests(unittest.TestCase):
    def test_empty_statistics_are_immutable_and_bounded(self):
        value = TLSClientHelloStatistics()
        self.assertEqual(value.total_client_hello_count, 0)
        self.assertEqual(len(value.legacy_version_counts), 65536)
        self.assertEqual(len(value.cipher_suite_counts), 65536)
        self.assertEqual(len(value.extension_type_counts), 65536)
        self.assertEqual(len(value.compression_method_counts), 256)
        with self.assertRaises(FrozenInstanceError):
            value.total_client_hello_count = 1
        with self.assertRaises(TypeError):
            value.legacy_version_counts[0] = 1

    def test_single_observation_updates_all_structural_fields(self):
        observation = parse(selected_body())
        value = update_tls_client_hello_statistics(None, observation)
        hello = observation.client_hello
        self.assertEqual(value.total_client_hello_count, 1)
        self.assertEqual(value.legacy_version_counts[0x0303], 1)
        self.assertEqual((value.min_legacy_version, value.max_legacy_version), (0x0303, 0x0303))
        self.assertEqual((value.min_session_id_length, value.max_session_id_length, value.total_session_id_bytes),
                         (0, 0, 0))
        self.assertEqual((value.min_cipher_suite_count, value.max_cipher_suite_count,
                          value.total_cipher_suite_count), (4, 4, 4))
        self.assertEqual((value.min_compression_method_count, value.max_compression_method_count,
                          value.total_compression_method_count), (3, 3, 3))
        self.assertEqual((value.min_extension_count, value.max_extension_count, value.total_extension_count), (7, 7, 7))
        self.assertEqual(value.cipher_suite_counts[65535], 2)
        self.assertEqual(value.cipher_suite_counts[0x1301], 1)
        self.assertEqual(value.compression_method_counts[0], 2)
        self.assertEqual(value.compression_method_counts[255], 1)
        self.assertEqual(value.extension_type_counts[10], 2)
        self.assertEqual(value.extension_type_counts[65000], 1)
        self.assertEqual(value.unknown_extension_count, 1)
        self.assertEqual(value.duplicate_extension_count, 3)
        self.assertEqual((value.supported_groups_extension_count, value.total_supported_groups_count,
                          value.min_supported_groups_count, value.max_supported_groups_count), (2, 4, 1, 3))
        self.assertEqual((value.signature_algorithms_extension_count, value.total_signature_algorithms_count,
                          value.min_signature_algorithms_count, value.max_signature_algorithms_count), (2, 4, 1, 3))
        self.assertEqual((value.alpn_extension_count, value.total_alpn_protocol_count,
                          value.min_alpn_protocol_count, value.max_alpn_protocol_count), (2, 4, 1, 3))
        self.assertEqual(len(hello.extensions), value.total_extension_count)

    def test_multiple_and_repeated_observations_count_independently(self):
        first = parse(body(version=b'\x03\x01', session=b'a', suites=(1, 2), compression=(0,)))
        second = parse(body(version=b'\x03\x04', session=b'ab', suites=(2,), compression=(255, 1), extensions=()))
        value = update_tls_client_hello_statistics(first.client_hello and None, first)
        value = update_tls_client_hello_statistics(value, second)
        value = update_tls_client_hello_statistics(value, first)
        self.assertEqual(value.total_client_hello_count, 3)
        self.assertEqual((value.min_legacy_version, value.max_legacy_version), (0x0301, 0x0304))
        self.assertEqual((value.min_session_id_length, value.max_session_id_length, value.total_session_id_bytes), (1, 2, 4))
        self.assertEqual(value.cipher_suite_counts[2], 3)
        self.assertEqual(value.extension_type_counts, (0,) * 65536)
        self.assertEqual(value.total_extension_count, 0)

    def test_directional_updates_remain_isolated(self):
        forward = parse(body(version=b'\x03\x03'))
        reverse = altered(forward, stream=altered(forward.stream, direction=FlowDirection.REVERSE))
        value = update_directional_tls_client_hello_statistics(None, forward)
        value = update_directional_tls_client_hello_statistics(value, reverse)
        self.assertEqual(value.forward.total_client_hello_count, 1)
        self.assertEqual(value.reverse.total_client_hello_count, 1)
        self.assertEqual(value.forward, value.reverse)

    def test_noncomplete_statuses_are_excluded_by_lifecycle_and_rejected_standalone(self):
        source = parse(body())
        for status in (TLSClientHelloStatus.INCOMPLETE, TLSClientHelloStatus.MALFORMED, TLSClientHelloStatus.UNSUPPORTED):
            failed = altered(source, status=status, client_hello=None)
            with self.assertRaises(ValueError):
                update_tls_client_hello_statistics(None, failed)
        window, = run_packets((packet(wire(message(body()), 22)),))
        self.assertEqual(window.tls_client_hello_statistics.forward.total_client_hello_count, 1)
        self.assertEqual(window.tls_client_hello_statistics.reverse.total_client_hello_count, 0)

    def test_duplicate_and_unknown_extensions_are_structural_only(self):
        observation = parse(body(extensions=(extension(65000, b'a'), extension(65000, b'b'), extension(10, identifiers()))))
        value = update_tls_client_hello_statistics(None, observation)
        self.assertEqual(value.total_extension_count, 3)
        self.assertEqual(value.unknown_extension_count, 2)
        self.assertEqual(value.duplicate_extension_count, 1)
        self.assertEqual(value.extension_type_counts[65000], 2)
        self.assertEqual(value.supported_groups_extension_count, 1)
        self.assertEqual(value.total_supported_groups_count, 0)

    def test_selected_empty_and_malformed_structures(self):
        empty = parse(body(extensions=(extension(10, identifiers()), extension(13, identifiers()))))
        value = update_tls_client_hello_statistics(None, empty)
        self.assertEqual((value.min_supported_groups_count, value.max_supported_groups_count), (0, 0))
        self.assertEqual((value.min_signature_algorithms_count, value.max_signature_algorithms_count), (0, 0))
        malformed = parse(body(extensions=(extension(10, b'\x00\x01x'),)))
        self.assertIs(malformed.status, TLSClientHelloStatus.MALFORMED)
        with self.assertRaises(ValueError):
            update_tls_client_hello_statistics(None, malformed)

    def test_lifecycle_retries_and_closure_preserve_aggregate(self):
        instance = manager()
        data = wire(message(body(session=b'a')) + message(body(session=b'b')), 22)
        active = record(instance, data)
        self.assertEqual(active.tls_client_hello_statistics.forward.total_client_hello_count, 2)
        closed = instance.close(active.identity)
        self.assertEqual(closed.tls_client_hello_statistics.forward.total_client_hello_count, 2)
        self.assertEqual(instance.end_capture_session(), ())

    def test_publication_failure_keeps_statistics_retryable_without_duplication(self):
        instance = manager()
        first = record(instance, wire(message(body(session=b'a')), 22))
        data = wire(message(body(session=b'b')), 22)
        with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                record(instance, data, sequence=100 + len(data))
        self.assertEqual(instance.active_windows()[0].coordinated_state.tls_client_hello_statistics,
                         first.tls_client_hello_statistics)
        after = record(instance, data, sequence=100 + len(data))
        self.assertEqual(after.tls_client_hello_statistics.forward.total_client_hello_count, 2)

    def test_four_classic_pcap_encodings_publish_identical_statistics(self):
        expected = None
        sources = traffic()
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'client-hello-statistics.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    closed = []
                    path.write_bytes(pcap_bytes(tuple((i * 1000000, source.raw_bytes)
                                                       for i, source in enumerate(sources)), order, nano))
                    run_flow_observation_session(
                        PcapPacketSource(path), capture_session_id='client-hello-statistics',
                        inactivity_timeout=timedelta(seconds=60), closed_window_consumer=closed.append,
                    )
                    actual = tuple((window.identity.ip_version, window.identity.source_port,
                                    window.tls_client_hello_statistics.forward.total_client_hello_count,
                                    window.tls_client_hello_statistics.reverse.total_client_hello_count,
                                    window.tls_client_hello_statistics.forward.total_extension_count,
                                    window.tls_client_hello_statistics.reverse.unknown_extension_count)
                                   for window in closed)
                    self.assertEqual(len(actual), 3)
                    if expected is None:
                        expected = actual
                    self.assertEqual(actual, expected)

    def test_statistics_do_not_retain_client_hello_sources(self):
        observation = parse(selected_body())
        value = update_tls_client_hello_statistics(None, observation)
        reference = weakref.ref(observation)
        hello_reference = weakref.ref(observation.client_hello)
        del observation
        gc.collect()
        self.assertIsNone(reference())
        self.assertIsNone(hello_reference())
        self.assertEqual(value.total_client_hello_count, 1)

    def test_large_counts_use_exact_integers(self):
        observation = parse(body())
        value = None
        for _ in range(5):
            value = update_tls_client_hello_statistics(value, observation)
        self.assertEqual(value.total_client_hello_count, 5)
        self.assertEqual(value.total_session_id_bytes, 0)
        self.assertEqual(value.cipher_suite_counts[0x1301], 5)

    def test_hash_seed_and_timezone_replay_digest_is_stable(self):
        script = 'from tests.test_tls_client_hello_statistics import replay_digest; print(replay_digest())'
        expected = replay_digest()
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                env = dict(os.environ, PYTHONHASHSEED=seed, TZ=zone, PYTHONPATH='src')
                result = subprocess.run([sys.executable, '-B', '-c', script], cwd=Path(__file__).parents[1],
                                        env=env, check=True, capture_output=True, text=True)
                self.assertEqual(result.stdout.strip(), expected)


def replay_digest():
    first = parse(selected_body())
    second = parse(body(version=b'\x03\x01', extensions=(extension(65000, b'x'),)))
    value = update_directional_tls_client_hello_statistics(None, first)
    value = update_directional_tls_client_hello_statistics(
        value, altered(second, stream=altered(second.stream, direction=FlowDirection.REVERSE)),
    )
    return hashlib.sha256(repr((value.forward.total_client_hello_count, value.reverse.total_client_hello_count,
                                value.forward.legacy_version_counts[0x0303], value.reverse.extension_type_counts[65000])).encode()).hexdigest()


if __name__ == '__main__':
    unittest.main()
