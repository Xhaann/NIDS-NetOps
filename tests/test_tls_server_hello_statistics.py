import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    DirectionalTLSServerHelloStatistics,
    FlowDirection,
    TLSServerHelloStatistics,
    analyze_tls_server_hello,
    analyze_packet,
    update_directional_tls_server_hello_statistics,
    update_tls_server_hello_statistics,
)
from application import run_flow_observation_session
from capture import PcapPacketSource
from tests.pcap_scenarios import pcap_bytes
from tests.test_dns_transaction_statistics_lifecycle import run_packets
from tests.test_tls_client_hello_lifecycle import manager, record, wire
from tests.test_tls_server_hello import body, extension, parse, server_packet, source
from tests.test_tls_handshake_framing import message
from tests.test_tls_record_framing import packet
from analysis.flow_observation_window import FlowObservationWindowUpdate


def clone(value, **changes):
    result = object.__new__(type(value))
    for name, current in vars(value).items():
        object.__setattr__(result, name, changes.get(name, current))
    return result


class TLSServerHelloStatisticsTests(unittest.TestCase):
    def test_empty_statistics_are_immutable_and_bounded(self):
        value = TLSServerHelloStatistics()
        self.assertEqual(value.total_server_hello_count, 0)
        self.assertEqual(value.legacy_version_counts, ())
        self.assertEqual(value.cipher_suite_counts, ())
        self.assertEqual(value.extension_type_counts, ())
        self.assertEqual(value.compression_method_counts, ())
        self.assertEqual(value.extensions_absent_count, 0)
        with self.assertRaises(FrozenInstanceError):
            value.total_server_hello_count = 1
        with self.assertRaises(FrozenInstanceError):
            value.legacy_version_counts += ((1, 1),)

    def test_single_observation_updates_all_structural_fields(self):
        observation = parse(body(version=b'\x03\x01', session=b'abc', cipher=65535, compression=255,
                                  extensions=(extension(23, b'ab'), extension(65000, b'opaque'), extension(23, b'c'))))
        value = update_tls_server_hello_statistics(None, observation)
        self.assertEqual(value.total_server_hello_count, 1)
        self.assertEqual(value.legacy_version_counts, ((0x0301, 1),))
        self.assertEqual((value.min_legacy_version, value.max_legacy_version), (0x0301, 0x0301))
        self.assertEqual((value.min_session_id_length, value.max_session_id_length, value.total_session_id_bytes),
                         (3, 3, 3))
        self.assertEqual(value.cipher_suite_counts, ((65535, 1),))
        self.assertEqual(value.compression_method_counts, ((255, 1),))
        self.assertEqual(value.extensions_present_count, 1)
        self.assertEqual(value.extensions_absent_count, 0)
        self.assertEqual((value.min_extension_count, value.max_extension_count, value.total_extension_count), (3, 3, 3))
        self.assertEqual((value.min_extension_data_length, value.max_extension_data_length,
                          value.total_extension_data_bytes), (1, 6, 9))
        self.assertEqual(value.extension_type_counts, ((23, 2), (65000, 1)))
        self.assertEqual(value.duplicate_extension_count, 1)

    def test_multiple_observations_preserve_presence_and_order_independent_counts(self):
        first = parse(body(extensions=None))
        second = parse(body(extensions=()))
        third = parse(body(version=b'\x03\x04', session=b'ab', cipher=1, compression=1,
                           extensions=(extension(1, b'long'),)))
        value = update_tls_server_hello_statistics(None, first)
        value = update_tls_server_hello_statistics(value, second)
        value = update_tls_server_hello_statistics(value, third)
        self.assertEqual(value.total_server_hello_count, 3)
        self.assertEqual((value.extensions_present_count, value.extensions_absent_count), (2, 1))
        self.assertEqual((value.min_session_id_length, value.max_session_id_length, value.total_session_id_bytes), (0, 2, 2))
        self.assertEqual((value.min_extension_count, value.max_extension_count, value.total_extension_count), (0, 1, 1))
        self.assertEqual((value.min_extension_data_length, value.max_extension_data_length,
                          value.total_extension_data_bytes), (4, 4, 4))
        self.assertEqual(value.extension_type_counts, ((1, 1),))

    def test_directional_updates_isolate_forward_and_reverse(self):
        forward = parse(body(cipher=1, extensions=(extension(2, b'f'),)))
        reverse = clone(parse(body(cipher=2, extensions=(extension(3, b'r'),))), direction=FlowDirection.REVERSE)
        value = update_directional_tls_server_hello_statistics(None, forward)
        value = update_directional_tls_server_hello_statistics(value, reverse)
        self.assertEqual(value.forward.total_server_hello_count, 1)
        self.assertEqual(value.forward.cipher_suite_counts, ((1, 1),))
        self.assertEqual(value.reverse.total_server_hello_count, 1)
        self.assertEqual(value.reverse.cipher_suite_counts, ((2, 1),))
        self.assertEqual(value.reverse.extension_type_counts, ((3, 1),))

    def test_noncomplete_observations_are_excluded_by_lifecycle_and_rejected_directly(self):
        incomplete = parse(body()[:34])
        unsupported = analyze_tls_server_hello(source(body(), kind=1))
        for observation in (incomplete, unsupported):
            with self.assertRaises(ValueError):
                update_tls_server_hello_statistics(None, observation)
        incomplete_window, = run_packets((server_packet(body()[:34]),))
        self.assertEqual(incomplete_window.tls_server_hello_statistics.forward.total_server_hello_count, 0)
        window, = run_packets((server_packet(body()),))
        self.assertEqual(window.tls_server_hello_statistics.forward.total_server_hello_count, 1)

    def test_boundaries_and_invalid_aggregate_values_are_rejected(self):
        maximum = update_tls_server_hello_statistics(
            None, parse(body(session=b's' * 32, extensions=(extension(65535, b'x' * 65531),))),
        )
        self.assertEqual((maximum.min_session_id_length, maximum.max_session_id_length), (32, 32))
        self.assertEqual((maximum.min_extension_data_length, maximum.max_extension_data_length), (65531, 65531))
        with self.assertRaises(ValueError):
            replace(maximum, extensions_present_count=2)
        with self.assertRaises(ValueError):
            replace(maximum, total_extension_data_bytes=0)
        with self.assertRaises(ValueError):
            replace(maximum, min_extension_data_length=65532)
        with self.assertRaises(TypeError):
            replace(maximum, cipher_suite_counts=[])

    def test_invalid_observation_values_do_not_enter_the_reducer(self):
        observation = parse(body())
        invalid = clone(observation, identity=None)
        with self.assertRaises(TypeError):
            update_tls_server_hello_statistics(None, invalid)
        invalid_hello = clone(observation.server_hello, extensions=(None,), extensions_length=4,
                              extensions_present=True)
        invalid = clone(observation, server_hello=invalid_hello)
        with self.assertRaises(TypeError):
            update_tls_server_hello_statistics(None, invalid)

    def test_lifecycle_counts_repeated_complete_messages_once_and_preserves_closure(self):
        instance = manager()
        data = wire(message(body(), 2) + message(body(session=b'a'), 2), 22)
        first = record(instance, data)
        self.assertEqual(first.tls_server_hello_statistics.forward.total_server_hello_count, 2)
        duplicate = record(instance, data, sequence=100)
        self.assertEqual(duplicate.tls_server_hello_statistics.forward.total_server_hello_count, 2)
        self.assertEqual(duplicate.tls_server_hellos, ())
        closed = instance.close(first.identity)
        self.assertEqual(closed.tls_server_hello_statistics, first.tls_server_hello_statistics)

    def test_publication_failure_retry_does_not_duplicate_statistics(self):
        instance = manager()
        first_data = wire(message(body(), 2), 22)
        first = record(instance, first_data)
        data = wire(message(body(session=b'retry'), 2), 22)
        with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                record(instance, data, sequence=100 + len(first_data))
        self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
        after = record(instance, data, sequence=100 + len(first_data))
        self.assertEqual(after.tls_server_hello_statistics.forward.total_server_hello_count, 2)
        retry = record(instance, data, sequence=100 + len(first_data))
        self.assertEqual(retry.tls_server_hello_statistics.forward.total_server_hello_count, 2)

    def test_inactivity_and_capacity_closure_preserve_statistics(self):
        instance = manager()
        first = record(instance, wire(message(body(), 2), 22), seconds=0)
        update = instance.record(analyze_packet(server_packet(body(session=b'inactive'), seconds=10)))
        self.assertEqual(update.closed_windows[0].tls_server_hello_statistics.forward.total_server_hello_count, 1)
        self.assertEqual(update.active_window.tls_server_hello_statistics.forward.total_server_hello_count, 1)
        limited = manager(1)
        original = record(limited, wire(message(body(), 2), 22))
        update = limited.record(analyze_packet(server_packet(body(session=b'capacity'), ipv6=True, seconds=1)))
        self.assertEqual(update.closed_windows[0].tls_server_hello_statistics.forward.total_server_hello_count, 1)
        self.assertEqual(update.active_window.tls_server_hello_statistics.forward.total_server_hello_count, 1)

    def test_ipv4_ipv6_and_direction_metadata_are_preserved_by_statistics(self):
        for ipv6, reverse in ((False, False), (False, True), (True, False), (True, True)):
            window, = run_packets((server_packet(body(), ipv6=ipv6, reverse=reverse),))
            statistics = window.tls_server_hello_statistics
            selected = statistics.reverse if reverse else statistics.forward
            other = statistics.forward if reverse else statistics.reverse
            self.assertEqual(selected.total_server_hello_count, 1)
            self.assertEqual(other.total_server_hello_count, 0)
            self.assertEqual(window.tls_server_hellos[0].identity.ip_version, 6 if ipv6 else 4)

    def test_source_objects_are_not_retained_by_statistics(self):
        input_observation = source(body(), kind=2)
        observation = analyze_tls_server_hello(input_observation)
        value = update_tls_server_hello_statistics(None, observation)
        source_reference = weakref.ref(observation)
        stream_reference = weakref.ref(input_observation.stream)
        del input_observation, observation
        gc.collect()
        self.assertIsNone(source_reference())
        self.assertIsNone(stream_reference())
        self.assertEqual(value.total_server_hello_count, 1)

    def test_real_capture_session_four_pcap_encodings_are_equivalent(self):
        sources = (server_packet(body(), seconds=0), server_packet(body(extensions=()), ipv6=True,
                                                                     seconds=1, sequence=900))
        expected = None
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'server-hello-statistics.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    closed = []
                    path.write_bytes(pcap_bytes(tuple((i * 1000000, item.raw_bytes) for i, item in enumerate(sources)),
                                                order, nano))
                    run_flow_observation_session(PcapPacketSource(path), capture_session_id='server-hello-statistics',
                                                 inactivity_timeout=timedelta(seconds=60),
                                                 closed_window_consumer=closed.append)
                    actual = tuple((window.identity.ip_version,
                                    window.tls_server_hello_statistics.forward.total_server_hello_count,
                                    window.tls_server_hello_statistics.forward.extensions_present_count)
                                   for window in closed)
                    if expected is None:
                        expected = actual
                    self.assertEqual(actual, expected)

    def test_deterministic_replay_across_seed_and_timezone(self):
        expected = replay_digest()
        script = 'from tests.test_tls_server_hello_statistics import replay_digest; print(replay_digest())'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                env = dict(os.environ, PYTHONHASHSEED=seed, TZ=zone, PYTHONPATH='src')
                result = subprocess.run([sys.executable, '-B', '-c', script], cwd=Path(__file__).parents[1],
                                        env=env, check=True, capture_output=True, text=True)
                self.assertEqual(result.stdout.strip(), expected)


def replay_digest():
    values = []
    for ipv6, reverse, session, extensions in (
        (False, False, b'', (extension(65000, b'x'),)),
        (True, True, b's', (extension(1), extension(1))),
    ):
        window, = run_packets((server_packet(body(session=session, extensions=extensions), ipv6=ipv6, reverse=reverse),))
        statistics = window.tls_server_hello_statistics
        values.append((statistics.forward, statistics.reverse))
    return hashlib.sha256(repr(tuple(values)).encode()).hexdigest()


if __name__ == '__main__':
    unittest.main()
