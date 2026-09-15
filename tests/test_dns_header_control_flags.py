import ast
import gc
import hashlib
import itertools
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import FrozenInstanceError, asdict, fields, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    DNSCorrelationStatus, DNSHeader, DNSMessageFlagStatistics, DNSMessageStatus,
    analyze_dns_message, analyze_packet, update_dns_message_flag_statistics,
)
from application import run_flow_observation_session
from capture import PcapPacketSource
from tests.pcap_scenarios import pcap_bytes
from tests.test_dns import adversarial_payloads, header
from tests.test_dns_correlation import IDENTITY
from tests.test_dns_correlation_lifecycle import manager
from tests.test_dns_message_flag_statistics import advance, terminal
from tests.test_dns_message_flag_statistics_lifecycle import packet
from tests.test_dns_packet_analysis import dns_packet
from tests.test_dns_transaction_statistics_lifecycle import run_packets


FLAGS = (('is_response', 0x8000), ('authoritative_answer', 0x0400), ('truncated', 0x0200),
         ('recursion_desired', 0x0100), ('recursion_available', 0x0080),
         ('authenticated_data', 0x0020), ('checking_disabled', 0x0010))


def semantic_values(value):
    return tuple(getattr(value, name) for name, _ in FLAGS)


def parsed(flags):
    return analyze_dns_message(header(flags=flags)).header


def replay_packets():
    return (packet(flags=0x0130), packet(flags=0x0400, ipv6=True),
            packet(flags=0x87b0), packet(flags=0x80c0, ipv6=True),
            packet(flags=0x0010, client_port=12346), packet(flags=0x8020, client_port=12346))


def replay():
    packets = replay_packets()
    headers = tuple(analyze_packet(item).dns.header for item in packets)
    messages = tuple((value.flags, semantic_values(value)) for value in headers)
    windows = run_packets(packets)
    transactions = tuple(tuple((item.status.value, semantic_values(item.message.header),
                                 None if item.request is None else semantic_values(item.request.header))
                                for item in window.dns_correlation_state.observations) for window in windows)
    return messages, transactions


class DNSHeaderControlFlagTests(unittest.TestCase):
    def assert_single(self, bit, expected_name):
        result = parsed(bit)
        self.assertEqual(semantic_values(result), tuple(name == expected_name for name, _ in FLAGS))
        self.assertEqual(result.flags, bit)
        self.assertTrue(all(type(value) is bool for value in semantic_values(result)))

    def test_all_flags_clear(self):
        self.assertEqual(semantic_values(parsed(0)), (False,) * 7)

    def test_qr_only(self):
        self.assert_single(0x8000, 'is_response')

    def test_aa_only(self):
        self.assert_single(0x0400, 'authoritative_answer')

    def test_tc_only(self):
        self.assert_single(0x0200, 'truncated')

    def test_rd_only(self):
        self.assert_single(0x0100, 'recursion_desired')

    def test_ra_only(self):
        self.assert_single(0x0080, 'recursion_available')

    def test_ad_only(self):
        self.assert_single(0x0020, 'authenticated_data')

    def test_cd_only(self):
        self.assert_single(0x0010, 'checking_disabled')

    def test_all_supported_flags_set(self):
        self.assertEqual(semantic_values(parsed(0x87b0)), (True,) * 7)

    def test_all_128_supported_flag_combinations(self):
        for values in itertools.product((False, True), repeat=7):
            word = sum(mask for (_, mask), enabled in zip(FLAGS, values) if enabled)
            result = parsed(word)
            self.assertEqual(semantic_values(result), values)
            self.assertTrue(all(type(value) is bool for value in semantic_values(result)))
            self.assertEqual(result.flags, word)

    def test_changing_one_flag_leaves_all_others_unchanged(self):
        for word in (0, 0xffff, 0x1234, 0x87b0, 0x784f):
            original = semantic_values(parsed(word))
            for index, (_, mask) in enumerate(FLAGS):
                expected = tuple(not value if offset == index else value for offset, value in enumerate(original))
                self.assertEqual(semantic_values(parsed(word ^ mask)), expected)

    def test_all_65536_raw_words_preserve_legacy_and_new_semantics(self):
        for word in range(65536):
            result = parsed(word)
            self.assertEqual(result.flags, word)
            self.assertIs(result.is_response, bool(word & 0x8000))
            self.assertIs(result.truncated, bool(word & 0x0200))
            self.assertEqual(result.opcode, (word >> 11) & 15)
            self.assertEqual(result.response_code, word & 15)
            self.assertEqual(semantic_values(result), tuple(bool(word & mask) for _, mask in FLAGS))

    def test_historical_z_positions_are_preserved_independently(self):
        for bits in range(8):
            word = bits << 4
            result = parsed(word)
            self.assertEqual(result.flags, word)
            self.assertIs(result.authenticated_data, bool(bits & 2))
            self.assertIs(result.checking_disabled, bool(bits & 1))
            self.assertFalse(result.is_response)
        self.assertEqual(semantic_values(parsed(0x0040)), (False,) * 7)
        self.assertNotEqual(parsed(0), parsed(0x0040))

    def test_flags_are_not_normalized_by_query_or_response_role(self):
        query = parsed(0x05b0)
        response = parsed(0x85b0)
        self.assertFalse(query.is_response)
        self.assertTrue(response.is_response)
        self.assertEqual(semantic_values(query)[1:], semantic_values(response)[1:])
        self.assertTrue(query.authoritative_answer)
        self.assertTrue(query.authenticated_data)

    def test_tc_does_not_change_complete_message_status(self):
        result = analyze_dns_message(header(flags=0x87b0))
        self.assertIs(result.status, DNSMessageStatus.COMPLETE)
        self.assertTrue(result.header.truncated)
        self.assertEqual(result.remaining_bytes, 0)

    def test_header_stored_fields_hash_equality_and_repr_remain_unchanged(self):
        value = parsed(0x87b0)
        expected = dict(transaction_id=123, flags=0x87b0, question_count=0, answer_count=0, authority_count=0, additional_count=0)
        self.assertEqual(asdict(value), expected)
        self.assertEqual(tuple(member.name for member in fields(value)), tuple(expected))
        self.assertEqual(hash(value), hash(tuple(expected.values())))
        self.assertEqual(value, parsed(0x87b0))
        self.assertEqual(repr(value), 'DNSHeader(transaction_id=123, flags=34736, question_count=0, answer_count=0, authority_count=0, additional_count=0)')
        before = vars(value).copy()
        semantic_values(value)
        self.assertEqual(vars(value), before)

    def test_properties_and_stored_fields_remain_frozen(self):
        value = parsed(0)
        for name in tuple(name for name, _ in FLAGS) + tuple(vars(value)):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, name, True)
            with self.assertRaises(FrozenInstanceError):
                delattr(value, name)

    def test_factory_only_construction_remains_closed(self):
        with self.assertRaises(TypeError):
            DNSHeader()
        with self.assertRaises(TypeError):
            DNSHeader(123, 0, 0, 0, 0, 0)
        with self.assertRaises(TypeError):
            DNSHeader(**asdict(parsed(0)))
        with self.assertRaises(TypeError):
            replace(parsed(0))

    def test_semantic_constructor_values_cannot_be_coerced(self):
        for name, _ in FLAGS:
            for value in (True, False, 0, 1, 'true', 1.0, None, [], {}, object()):
                with self.assertRaises(TypeError):
                    DNSHeader(**{name: value})

    def test_invalid_parser_inputs_still_raise_type_error(self):
        for raw in (True, 1, 1.0, None, 'dns', bytearray(header()), memoryview(header())):
            with self.assertRaises(TypeError):
                analyze_dns_message(raw)

    def test_properties_use_existing_header_without_reparsing(self):
        value = parsed(0x87b0)
        with patch('analysis.dns.unpack_from', side_effect=AssertionError('wire reparse')):
            with patch('analysis.dns.analyze_dns_message', side_effect=AssertionError('message reparse')):
                self.assertEqual(semantic_values(value), (True,) * 7)

    def test_existing_adversarial_parser_outputs_match_initial_head(self):
        outputs = tuple(asdict(analyze_dns_message(raw)) for raw in adversarial_payloads())
        self.assertEqual(len(outputs), 2153)
        self.assertEqual(hashlib.sha256(repr(outputs).encode()).hexdigest(),
                         '8185ed7a57c444c5c4bad68dd1f924611697cf23d7d63023ce7078266316bdac')

    def test_malformed_message_preserves_header_without_becoming_valid(self):
        self.assert_invalid_message(header(1, flags=0x87b0) + b'\x80', DNSMessageStatus.MALFORMED)

    def test_incomplete_message_preserves_header_without_becoming_valid(self):
        self.assert_invalid_message(header(1, flags=0x87b0) + b'\x01', DNSMessageStatus.INCOMPLETE)

    def test_unsupported_message_preserves_header_without_becoming_valid(self):
        self.assert_invalid_message(header(1, flags=0x87b0) + b'\x40', DNSMessageStatus.UNSUPPORTED)

    def assert_invalid_message(self, raw, status):
        for ipv6 in (False, True):
            analyzed = analyze_packet(dns_packet(raw, ipv6=ipv6))
            self.assertIs(analyzed.dns.status, status)
            self.assertEqual(semantic_values(analyzed.dns.header), (True,) * 7)
            window, = run_packets((dns_packet(raw, ipv6=ipv6),))
            self.assertIsNone(window.dns_correlation_state)
            self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics())

    def test_short_headers_still_have_no_header(self):
        for length in range(12):
            value = analyze_dns_message(header(flags=0x87b0)[:length])
            self.assertIs(value.status, DNSMessageStatus.INCOMPLETE)
            self.assertIsNone(value.header)

    def test_parser_infrastructure_failures_still_propagate(self):
        with patch('analysis.dns._observation', side_effect=MemoryError('header')):
            with self.assertRaises(MemoryError):
                analyze_packet(packet(flags=0x87b0)).dns

    def test_ipv4_udp_header_properties(self):
        result = analyze_packet(packet(flags=0x87b0))
        self.assertEqual(semantic_values(result.dns.header), (True,) * 7)
        self.assertIs(result.dns.status, DNSMessageStatus.COMPLETE)

    def test_ipv6_udp_header_properties(self):
        result = analyze_packet(packet(flags=0x87b0, ipv6=True, extensions=(0, 60)))
        self.assertEqual(semantic_values(result.dns.header), (True,) * 7)
        self.assertIs(result.dns.status, DNSMessageStatus.COMPLETE)

    def test_packet_analysis_delegates_once_to_existing_parser(self):
        observed = packet(flags=0x87b0)
        with patch('analysis.packet_analysis.analyze_dns_message', wraps=analyze_dns_message) as parser:
            result = analyze_packet(observed)
            self.assertEqual(semantic_values(result.dns.header), (True,) * 7)
        parser.assert_called_once()

    def test_delimited_tcp_transactions_retain_both_semantic_headers(self):
        identity = replace(IDENTITY, protocol=6)
        state = advance(advance(flags=0x0130, identity=identity), flags=0x87b0, identity=identity)
        value = state.observations[0]
        self.assertIs(value.status, DNSCorrelationStatus.MATCHED)
        self.assertEqual(semantic_values(value.request.header), (False, False, False, True, False, True, True))
        self.assertEqual(semantic_values(value.message.header), (True,) * 7)

    def test_automatic_tcp_framing_remains_unavailable(self):
        for ipv6 in (False, True):
            self.assertIsNone(analyze_packet(packet(flags=0x87b0, protocol=6, ipv6=ipv6)).dns)

    def test_interleaved_flows_and_repeated_ids_keep_headers_independent(self):
        windows = run_packets(replay_packets())
        self.assertEqual(len(windows), 3)
        observations = [window.dns_correlation_state.observations[0] for window in windows]
        self.assertTrue(all(value.status is DNSCorrelationStatus.MATCHED for value in observations))
        self.assertEqual([value.message.header.flags for value in observations], [0x87b0, 0x80c0, 0x8020])
        self.assertEqual([value.request.header.flags for value in observations], [0x0130, 0x0400, 0x0010])
        self.assertEqual(len({window.identity for window in windows}), 3)
        self.assertTrue(all(value.transaction_id == 1 for value in observations))

    def test_retained_header_releases_packet_message_transaction_and_flow(self):
        instance = manager()
        analyzed = analyze_packet(packet(flags=0x87b0))
        window = instance.record(analyzed).active_window
        transaction = window.dns_correlation_state.observations[0]
        references = [weakref.ref(item) for item in (analyzed, analyzed.observation, analyzed.dns, window,
                      window.coordinated_state, window.dns_correlation_state, transaction, window.identity)]
        value = analyzed.dns.header
        instance.close(window.identity)
        del analyzed, window, transaction
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(semantic_values(value), (True,) * 7)
        self.assertTrue(all(type(item) is int for item in vars(value).values()))

    def test_feature_seventeen_values_remain_identical_for_all_combinations(self):
        for values in itertools.product((False, True), repeat=7):
            word = sum(mask for (_, mask), enabled in zip(FLAGS, values) if enabled)
            value = update_dns_message_flag_statistics(None, terminal(word))
            self.assertEqual(value, DNSMessageFlagStatistics(1, int(values[0]), int(values[2])))
            self.assertEqual(tuple(asdict(value)), ('message_count', 'response_count', 'truncated_count'))

    def test_feature_seventeen_matched_counts_do_not_expand(self):
        window, = run_packets((packet(flags=0x0130), packet(flags=0x87b0)))
        self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics(2, 1, 1))

    def test_downstream_modules_never_read_raw_dns_flag_words(self):
        for filename in ('dns_message_flag_statistics.py', 'dns_transaction_statistics.py', 'dns_query_name_statistics.py',
                         'dns_resource_record_statistics.py', 'dns_correlation.py', 'flow_state_coordinator.py', 'flow_observation_window.py'):
            tree = ast.parse(Path('src/analysis', filename).read_text())
            self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr == 'flags' for node in ast.walk(tree)), filename)

    def test_pcap_semantic_headers_match_all_four_encodings(self):
        packets = replay_packets()
        expected = tuple(semantic_values(analyze_packet(item).dns.header) for item in packets)
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'header-flags.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes) for index, item in enumerate(packets)), order, nano))
                    source = PcapPacketSource(path)
                    source.start()
                    try:
                        actual = tuple(semantic_values(analyze_packet(item).dns.header) for item in source)
                    finally:
                        source.stop()
                    self.assertEqual(actual, expected)
                    windows = []
                    run_flow_observation_session(PcapPacketSource(path), capture_session_id="headers",
                                                 inactivity_timeout=timedelta(seconds=5), closed_window_consumer=windows.append)
                    self.assertEqual(tuple(semantic_values(window.dns_correlation_state.observations[0].message.header)
                                           for window in windows), (expected[2], expected[3], expected[5]))

    def test_repeated_independent_replay(self):
        self.assertEqual(replay(), replay())

    def test_nine_hash_seed_timezone_combinations(self):
        script = ('from tests.test_dns_header_control_flags import replay\n'
                  'import hashlib\nprint(hashlib.sha256(repr(replay()).encode()).hexdigest())\n')
        expected = hashlib.sha256(repr(replay()).encode()).hexdigest().encode() + b'\n'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                result = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
                self.assertEqual(result, expected)
