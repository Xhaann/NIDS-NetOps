import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import FrozenInstanceError
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    FlowDirection,
    FlowObservationWindowClosureReason,
    FlowObservationWindowUpdate,
    TLSServerHelloStatus,
    analyze_packet,
    analyze_tls_server_hello,
)
from application import run_flow_observation_session
from capture import PcapPacketSource
from tests.pcap_scenarios import pcap_bytes
from tests.test_dns_transaction_statistics_lifecycle import run_packets
from tests.test_tls_client_hello_lifecycle import manager, record, wire
from tests.test_tls_client_hello import source
from tests.test_tls_handshake_framing import message
from tests.test_tls_record_framing import packet


def extension(kind, data=b''):
    return kind.to_bytes(2, 'big') + len(data).to_bytes(2, 'big') + data


def body(version=b'\x03\x03', random=bytes(range(32)), session=b'', cipher=0x1301,
         compression=0, extensions=None):
    data = version + random + bytes((len(session),)) + session
    data += cipher.to_bytes(2, 'big') + bytes((compression,))
    if extensions is not None:
        block = b''.join(extensions)
        data += len(block).to_bytes(2, 'big') + block
    return data


def parse(data):
    return analyze_tls_server_hello(source(data, kind=2))


def server_packet(data, ipv6=False, reverse=False, seconds=0, sequence=100, flags=0):
    return packet(wire(message(data, 2), 22), ipv6=ipv6, reverse=reverse,
                  seconds=seconds, sequence=sequence, flags=flags)


def observable(value):
    hello = value.server_hello
    representation = None if hello is None else (
        hello.legacy_version, hello.random, hello.session_id, hello.cipher_suite,
        hello.compression_method, hello.extensions_length, hello.extensions_present,
        tuple((item.extension_type, item.data) for item in hello.extensions),
    )
    return (value.identity.ip_version, value.direction.value, value.consumed_offset,
            value.status.value, value.reason, value.failure_offset, representation)


class TLSServerHelloTests(unittest.TestCase):
    def test_minimal_server_hello_and_opaque_fields(self):
        value = parse(body())
        self.assertIs(value.status, TLSServerHelloStatus.COMPLETE)
        hello = value.server_hello
        self.assertEqual((hello.legacy_version, hello.random, hello.session_id),
                         (b'\x03\x03', bytes(range(32)), b''))
        self.assertEqual((hello.cipher_suite, hello.compression_method), (0x1301, 0))
        self.assertEqual((hello.extensions_length, hello.extension_count, hello.extensions_present), (None, 0, False))
        self.assertEqual(hello.session_id_length, 0)

    def test_session_id_extensions_duplicates_unknown_and_order(self):
        data = body(session=bytes(range(32)), extensions=(extension(23, b'ab'), extension(65000, b'opaque'), extension(23, b'c')))
        value = parse(data)
        hello = value.server_hello
        self.assertEqual(hello.session_id_length, 32)
        self.assertEqual(hello.extensions_length, 4 + 2 + 4 + 6 + 4 + 1)
        self.assertEqual(tuple(item.extension_type for item in hello.extensions), (23, 65000, 23))
        self.assertEqual(tuple(item.data for item in hello.extensions), (b'ab', b'opaque', b'c'))
        self.assertEqual(tuple(item.data_length for item in hello.extensions), (2, 6, 1))
        self.assertEqual(hello.extensions[0], hello.extensions[0])

    def test_empty_extension_vector_is_present(self):
        hello = parse(body(extensions=())).server_hello
        self.assertEqual((hello.extensions_length, hello.extensions, hello.extensions_present), (0, (), True))

    def test_maximum_bounded_session_and_extension_data(self):
        opaque = b'x' * 65531
        hello = parse(body(session=b's' * 32, extensions=(extension(65535, opaque),))).server_hello
        self.assertEqual(hello.session_id_length, 32)
        self.assertEqual(hello.extensions[0].data_length, 65531)
        self.assertEqual(hello.extensions[0].data, opaque)

    def test_extension_count_bound_is_unsupported(self):
        valid = parse(body(extensions=(extension(1),) * 1024))
        self.assertIs(valid.status, TLSServerHelloStatus.COMPLETE)
        failed = parse(body(extensions=(extension(1),) * 1025))
        self.assertIs(failed.status, TLSServerHelloStatus.UNSUPPORTED)
        self.assertIsNone(failed.server_hello)

    def test_truncation_statuses(self):
        complete = body(session=b'session', extensions=(extension(1, b'abcd'),))
        cuts = (
            body()[:34],
            body()[:35],
            body(session=b'session')[:35 + 7],
            body(session=b'session')[:35 + 7 + 1],
            body(session=b'session')[:35 + 7 + 2],
            complete[:-1],
        )
        for data in cuts:
            with self.subTest(length=len(data)):
                self.assertIs(parse(data).status, TLSServerHelloStatus.INCOMPLETE)

    def test_malformed_lengths_and_trailing_bytes(self):
        oversized_session = body()[:34] + b'\xff' + body()[35:]
        self.assertIs(parse(oversized_session).status, TLSServerHelloStatus.MALFORMED)
        malformed_vectors = (
            body(extensions=()) + b'x',
            body(extensions=(b'\x00',)),
            body(extensions=(b'\x00\x01\x00\x02x',)),
            body(extensions=(extension(1, b'ab')[:-1],)),
        )
        for data in malformed_vectors:
            with self.subTest(length=len(data)):
                self.assertIs(parse(data).status, TLSServerHelloStatus.MALFORMED)

    def test_non_server_messages_are_unsupported(self):
        value = analyze_tls_server_hello(source(body(), kind=1))
        self.assertIs(value.status, TLSServerHelloStatus.UNSUPPORTED)
        self.assertIsNone(value.server_hello)

    def test_factory_and_public_result_are_immutable(self):
        value = parse(body(extensions=(extension(1, b'x'),)))
        with self.assertRaises(FrozenInstanceError):
            value.server_hello.cipher_suite = 1
        with self.assertRaises(TypeError):
            value.server_hello.extensions[0] = None
        with self.assertRaises(FrozenInstanceError):
            value.server_hello.extensions[0].data = b'x'

    def test_direction_and_ipv4_ipv6_identity_metadata(self):
        for ipv6 in (False, True):
            for reverse in (False, True):
                window, = run_packets((server_packet(body(), ipv6=ipv6, reverse=reverse),))
                value, = window.tls_server_hellos
                self.assertEqual(value.identity.ip_version, 6 if ipv6 else 4)
                self.assertIs(value.direction, FlowDirection.REVERSE if reverse else FlowDirection.FORWARD)

    def test_current_batch_coexists_with_client_hello_and_handshake_statistics(self):
        from tests.test_tls_client_hello import body as client_body
        data = wire(message(client_body(), 1) + message(body(), 2), 22)
        window, = run_packets((packet(data),))
        self.assertEqual(len(window.tls_client_hellos), 1)
        self.assertEqual(len(window.tls_server_hellos), 1)
        self.assertEqual(window.tls_handshake_statistics.forward.total_message_count, 2)

    def test_repeated_server_hellos_are_independent_and_not_republished(self):
        instance = manager()
        data = wire(message(body(), 2) + message(body(session=b'a'), 2), 22)
        first = record(instance, data)
        self.assertEqual(len(first.tls_server_hellos), 2)
        duplicate = record(instance, data, sequence=100)
        self.assertEqual(duplicate.tls_server_hellos, ())

    def test_publication_failure_retry_is_atomic(self):
        instance = manager()
        first_data = wire(message(body(), 2), 22)
        first = record(instance, first_data)
        data = wire(message(body(session=b'retry'), 2), 22)
        with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                record(instance, data, sequence=100 + len(first_data))
        self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
        after = record(instance, data, sequence=100 + len(first_data))
        self.assertEqual(len(after.tls_server_hellos), 1)
        duplicate = record(instance, data, sequence=100 + len(first_data))
        self.assertEqual(duplicate.tls_server_hellos, ())

    def test_closure_fin_rst_inactivity_capacity_and_explicit_close(self):
        for flags in (17, 20):
            window, = run_packets((server_packet(body(), seconds=0, flags=flags),))
            self.assertEqual(len(window.tls_server_hellos), 1)
            self.assertIsNotNone(window.tls_server_hellos[0].server_hello)
        instance = manager()
        active = record(instance, wire(message(body(), 2), 22))
        closed = instance.close(active.identity)
        self.assertEqual(len(closed.tls_server_hellos), 1)
        self.assertEqual(instance.end_capture_session(), ())

    def test_inactivity_and_capacity_close_preserve_server_hello_batches(self):
        instance = manager()
        first = record(instance, wire(message(body(), 2), 22), seconds=0)
        update = instance.record(analyze_packet(server_packet(body(session=b'inactive'), seconds=10)))
        self.assertEqual(update.closed_windows[0].closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
        self.assertEqual(len(update.closed_windows[0].tls_server_hellos), 1)
        self.assertEqual(len(update.active_window.tls_server_hellos), 1)
        limited = manager(1)
        original = record(limited, wire(message(body(), 2), 22), ipv6=False)
        update = limited.record(analyze_packet(server_packet(body(session=b'capacity'), ipv6=True, seconds=1)))
        self.assertEqual(update.closed_windows[0].closure_reason, FlowObservationWindowClosureReason.CAPACITY)
        self.assertEqual(len(update.closed_windows[0].tls_server_hellos), 1)
        self.assertEqual(len(update.active_window.tls_server_hellos), 1)

    def test_source_observation_is_released_after_analysis(self):
        source_observation = source(body(), kind=2)
        stream_reference = weakref.ref(source_observation.stream)
        observation_reference = weakref.ref(source_observation)
        value = analyze_tls_server_hello(source_observation)
        del source_observation
        gc.collect()
        self.assertIsNone(observation_reference())
        self.assertIsNone(stream_reference())
        self.assertEqual(value.server_hello.random, bytes(range(32)))

    def test_real_capture_session_four_pcap_encodings(self):
        sources = (server_packet(body(), ipv6=False, seconds=0),
                   server_packet(body(extensions=()), ipv6=True, seconds=1, sequence=900))
        expected = None
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'server-hello.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    closed = []
                    path.write_bytes(pcap_bytes(tuple((i * 1000000, item.raw_bytes) for i, item in enumerate(sources)), order, nano))
                    run_flow_observation_session(PcapPacketSource(path), capture_session_id='server-hello',
                                                 inactivity_timeout=timedelta(seconds=60), closed_window_consumer=closed.append)
                    actual = tuple((window.identity.ip_version,
                                    tuple(map(observable, window.tls_server_hellos))) for window in closed)
                    self.assertEqual(len(actual), 2)
                    if expected is None:
                        expected = actual
                    self.assertEqual(actual, expected)

    def test_lower_layer_non_handshake_records_do_not_publish(self):
        window, = run_packets((packet(wire(b'ignored', 23)),))
        self.assertEqual(window.tls_server_hellos, ())

    def test_replay_digest_is_hash_seed_and_timezone_independent(self):
        expected = replay_digest()
        script = 'from tests.test_tls_server_hello import replay_digest; print(replay_digest())'
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
        values.extend(map(observable, window.tls_server_hellos))
    return hashlib.sha256(repr(tuple(values)).encode()).hexdigest()


if __name__ == '__main__':
    unittest.main()
