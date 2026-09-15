import ast
import gc
import unittest
import weakref
from dataclasses import FrozenInstanceError, fields, replace
from fractions import Fraction
from pathlib import Path
from unittest.mock import PropertyMock, patch

import analysis
from analysis import (
    DirectionalTLSHandshakeStatistics, FlowDirection, TLSHandshakeStatistics, TLSHandshakeStatus,
    TCPStreamStatus, update_directional_tls_handshake_statistics, update_tls_handshake_statistics,
)
from tests.test_tls_handshake_framing import advance, fragments, message


def observed(payload=b'', kind=1, **kwargs):
    update = advance(data=message(payload, kind), **kwargs)
    return (update.reverse_messages if kwargs.get('reverse') else update.forward_messages)[0]


def bins(kind, count=1):
    return (0,) * kind + (count,) + (0,) * (255 - kind)


def altered(value, **changes):
    result = object.__new__(type(value))
    for name, item in dict(vars(value), **changes).items():
        object.__setattr__(result, name, item)
    return result


class TLSHandshakeStatisticsTests(unittest.TestCase):
    def test_empty_statistics_fields_and_distribution(self):
        value = TLSHandshakeStatistics()
        self.assertEqual(tuple(field.name for field in fields(value)),
                         ('total_message_count', 'zero_length_message_count', 'min_message_length',
                          'max_message_length', 'total_message_length_bytes', 'handshake_type_counts'))
        self.assertEqual((value.total_message_count, value.zero_length_message_count, value.total_message_length_bytes), (0, 0, 0))
        self.assertEqual((value.min_message_length, value.max_message_length, value.mean_message_length), (None, None, None))
        self.assertEqual(value.handshake_type_counts, (0,) * 256)
        self.assertEqual(DirectionalTLSHandshakeStatistics().forward, value)
        self.assertEqual(DirectionalTLSHandshakeStatistics().reverse, value)

    def test_single_complete_message(self):
        value = update_tls_handshake_statistics(None, observed(b'abc', 255))
        self.assertEqual((value.total_message_count, value.zero_length_message_count, value.min_message_length,
                          value.max_message_length, value.total_message_length_bytes, value.mean_message_length),
                         (1, 0, 3, 3, 3, Fraction(3)))
        self.assertEqual(value.handshake_type_counts, bins(255))
        self.assertIs(type(value.mean_message_length), Fraction)

    def test_zero_length_is_counted_in_all_applicable_aggregates(self):
        value = update_tls_handshake_statistics(None, observed())
        self.assertEqual((value.total_message_count, value.zero_length_message_count, value.min_message_length,
                          value.max_message_length, value.total_message_length_bytes, value.mean_message_length),
                         (1, 1, 0, 0, 0, Fraction(0)))
        self.assertEqual(value.handshake_type_counts, bins(1))

    def test_multiple_lengths_repeated_types_and_recurring_mean(self):
        value = None
        for raw in (b'', b'ab', b'abc'):
            value = update_tls_handshake_statistics(value, observed(raw, 7))
        self.assertEqual((value.total_message_count, value.zero_length_message_count, value.min_message_length,
                          value.max_message_length, value.total_message_length_bytes, value.mean_message_length),
                         (3, 1, 0, 3, 5, Fraction(5, 3)))
        self.assertEqual(value.handshake_type_counts, bins(7, 3))

    def test_maximum_framed_message(self):
        raw = b'\x00' * 262144
        data = message(raw, 254)
        state, messages = fragments(tuple(data[i:i + 16384] for i in range(0, len(data), 16384)))
        value = update_tls_handshake_statistics(None, messages[0])
        self.assertEqual((value.min_message_length, value.max_message_length, value.total_message_length_bytes), (262144,) * 3)
        self.assertEqual(value.handshake_type_counts, bins(254))
        self.assertGreater(state.forward.stream.buffer_offset, 0)

    def test_all_256_type_values_and_stable_index_order(self):
        value = None
        for kind in reversed(range(256)):
            value = update_tls_handshake_statistics(value, observed(bytes((kind,)) * kind, kind))
        self.assertEqual(value.handshake_type_counts, (1,) * 256)
        self.assertEqual(value.total_message_length_bytes, sum(range(256)))
        self.assertEqual((value.total_message_count, value.zero_length_message_count), (256, 1))
        self.assertEqual((value.min_message_length, value.max_message_length), (0, 255))
        self.assertEqual(value.mean_message_length, Fraction(255, 2))

    def test_forward_reverse_isolation_and_immutable_previous_values(self):
        forward = observed(b'abc', 1)
        reverse = observed(b'', 255, reverse=True, sequence=900)
        first = update_directional_tls_handshake_statistics(None, reverse)
        second = update_directional_tls_handshake_statistics(first, forward)
        self.assertIs(second.reverse, first.reverse)
        self.assertEqual(first.forward.total_message_count, 0)
        self.assertEqual((second.forward.total_message_count, second.reverse.total_message_count), (1, 1))
        self.assertEqual((second.forward.total_message_length_bytes, second.reverse.total_message_length_bytes), (3, 0))
        self.assertEqual(second.forward.handshake_type_counts, bins(1))
        self.assertEqual(second.reverse.handshake_type_counts, bins(255))
        self.assertIs(forward.direction, FlowDirection.FORWARD)
        self.assertIs(reverse.direction, FlowDirection.REVERSE)

    def test_exact_counters_and_means_beyond_machine_sized_integers(self):
        count = 2 ** 100 + 17
        current = TLSHandshakeStatistics(count, 0, 262144, 262144, count * 262144, bins(7, count))
        value = update_tls_handshake_statistics(current, observed(b'x', 7))
        self.assertEqual(value.total_message_count, count + 1)
        self.assertEqual(value.total_message_length_bytes, count * 262144 + 1)
        self.assertEqual(value.handshake_type_counts[7], count + 1)
        self.assertEqual(value.mean_message_length, Fraction(count * 262144 + 1, count + 1))
        self.assertEqual(current.total_message_count, count)

    def test_long_reduction_keeps_fixed_aggregate_shape(self):
        source = observed(b'abc', 255)
        value = None
        for _ in range(3000):
            value = update_directional_tls_handshake_statistics(value, source)
        self.assertEqual(value.forward.total_message_count, 3000)
        self.assertEqual(value.forward.total_message_length_bytes, 9000)
        self.assertEqual(value.forward.handshake_type_counts, bins(255, 3000))
        self.assertEqual(set(vars(value)), {'forward', 'reverse'})
        for aggregate in (value.forward, value.reverse):
            self.assertEqual(len(vars(aggregate)), 6)
            self.assertEqual(len(aggregate.handshake_type_counts), 256)
            self.assertTrue(all(type(item) is int for item in aggregate.handshake_type_counts))

    def test_no_source_observation_header_stream_or_payload_graph_retention(self):
        source = observed(b'opaque source payload', 254)
        refs = [weakref.ref(item) for item in (source, source.header, source.stream)]
        value = update_directional_tls_handshake_statistics(None, source)
        del source
        gc.collect()
        self.assertTrue(all(ref() is None for ref in refs))
        for aggregate in (value.forward, value.reverse):
            for item in vars(aggregate).values():
                self.assertTrue(item is None or type(item) in (int, tuple))
        self.assertEqual(value.forward.total_message_length_bytes, 21)

    def test_constructor_rejects_wrong_scalar_types_and_negative_values(self):
        for field in ('total_message_count', 'zero_length_message_count', 'min_message_length',
                      'max_message_length', 'total_message_length_bytes'):
            for invalid in (True, 1.0, Fraction(1), '1', []):
                with self.subTest(field=field, invalid=repr(invalid)):
                    with self.assertRaises(TypeError):
                        TLSHandshakeStatistics(**{field: invalid})
            with self.assertRaises(ValueError):
                TLSHandshakeStatistics(**{field: -1})

    def test_constructor_rejects_invalid_fixed_distributions(self):
        for invalid in ([], {}, bytes(256)):
            with self.assertRaises(TypeError):
                TLSHandshakeStatistics(handshake_type_counts=invalid)
        for size in (0, 255, 257):
            with self.assertRaises(ValueError):
                TLSHandshakeStatistics(handshake_type_counts=(0,) * size)
        for invalid, error in ((True, TypeError), (1.0, TypeError), (-1, ValueError)):
            with self.assertRaises(error):
                TLSHandshakeStatistics(handshake_type_counts=(invalid,) + (0,) * 255)
        with self.assertRaises(ValueError):
            TLSHandshakeStatistics(handshake_type_counts=bins(1))

    def test_constructor_rejects_inconsistent_extrema_totals_and_zero_counts(self):
        invalid = (
            dict(total_message_length_bytes=1), dict(min_message_length=0), dict(max_message_length=0),
            dict(zero_length_message_count=1),
        )
        for values in invalid:
            with self.assertRaises(ValueError):
                TLSHandshakeStatistics(**values)
        for zero, minimum, maximum, total in ((0, None, 2, 3), (0, 2, None, 3), (0, 3, 2, 5),
                                              (0, 1, 262145, 262146), (0, 0, 2, 2), (1, 1, 2, 2),
                                              (3, 0, 0, 0), (2, 0, 1, 1), (2, 0, 0, 1),
                                              (0, 1, 4, 4), (0, 1, 4, 6), (1, 0, 4, 3)):
            with self.subTest(values=(zero, minimum, maximum, total)):
                with self.assertRaises(ValueError):
                    TLSHandshakeStatistics(2, zero, minimum, maximum, total, bins(1, 2))

    def test_constructor_accepts_attained_extrema_with_and_without_zero(self):
        for value in (TLSHandshakeStatistics(2, 0, 1, 4, 5, bins(1, 2)),
                      TLSHandshakeStatistics(3, 1, 0, 4, 5, bins(1, 3)),
                      TLSHandshakeStatistics(3, 3, 0, 0, 0, bins(1, 3))):
            self.assertIs(type(value.mean_message_length), Fraction)

    def test_partial_unavailable_and_empty_ready_observations_are_rejected(self):
        for source in (advance(data=b'\x01').state.forward, advance().state.forward,
                       advance(data=b'\x01\xff\xff\xff').state.forward):
            with self.assertRaises(ValueError):
                update_tls_handshake_statistics(None, source)
            with self.assertRaises(ValueError):
                update_directional_tls_handshake_statistics(None, source)

    def test_inconsistent_complete_observations_fail_without_repair(self):
        original = observed(b'abc')
        for changes, error in (({'payload': b'ab'}, ValueError), ({'payload': b'abcd'}, ValueError),
                               ({'payload': bytearray(b'abc')}, TypeError), ({'prefix': b'\x01'}, ValueError),
                               ({'prefix': bytearray()}, TypeError), ({'unavailable_reason': TCPStreamStatus.GAP}, ValueError),
                               ({'header': object()}, TypeError), ({'stream': None}, TypeError),
                               ({'status': TLSHandshakeStatus.INCOMPLETE}, ValueError)):
            with self.subTest(changes=changes):
                with self.assertRaises(error):
                    update_tls_handshake_statistics(None, altered(original, **changes))
        for changes, error in (({'handshake_type': 256}, ValueError), ({'handshake_type': -1}, ValueError),
                               ({'handshake_type': True}, TypeError), ({'declared_length': True}, TypeError),
                               ({'declared_length': -1}, ValueError), ({'declared_length': 262145}, ValueError),
                               ({'declared_length': 2}, ValueError)):
            with self.assertRaises(error):
                update_directional_tls_handshake_statistics(None, altered(original, header=altered(original.header, **changes)))
        with self.assertRaises(TypeError):
            update_directional_tls_handshake_statistics(None, altered(original, stream=altered(original.stream, direction='forward')))
        self.assertEqual(original.payload, b'abc')

    def test_invalid_public_argument_types_and_directional_components(self):
        for reducer in (update_tls_handshake_statistics, update_directional_tls_handshake_statistics):
            with self.assertRaises(TypeError):
                reducer({}, observed())
            for value in (None, {}, b''):
                with self.assertRaises(TypeError):
                    reducer(None, value)
        for name in ('forward', 'reverse'):
            with self.assertRaises(TypeError):
                DirectionalTLSHandshakeStatistics(**{name: {}})

    def test_public_exports_frozen_values_and_tuple_immutability(self):
        for item in (TLSHandshakeStatistics, DirectionalTLSHandshakeStatistics,
                     update_tls_handshake_statistics, update_directional_tls_handshake_statistics):
            self.assertIs(getattr(analysis, item.__name__), item)
        value = update_directional_tls_handshake_statistics(None, observed(b'a'))
        with self.assertRaises(FrozenInstanceError):
            value.forward = TLSHandshakeStatistics()
        with self.assertRaises(FrozenInstanceError):
            value.forward.total_message_count = 9
        with self.assertRaises(TypeError):
            value.forward.handshake_type_counts[1] = 9

    def test_reducer_reads_only_semantic_metadata_and_payload_length(self):
        source = observed(b'\xff\x00opaque')
        with patch('analysis.tcp_stream_observation.TCPStreamObservation.unconsumed_payload', new_callable=PropertyMock,
                   side_effect=AssertionError('TCP bytes')):
            with patch('analysis.dns.analyze_dns_message', side_effect=AssertionError('DNS')):
                with patch('analysis.ldap_stream_framing._message', side_effect=AssertionError('LDAP')):
                    value = update_tls_handshake_statistics(None, source)
        self.assertEqual(value.total_message_length_bytes, 8)
        tree = ast.parse(Path('src/analysis/tls_handshake_statistics.py').read_text())
        imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imports, {'dataclasses', 'fractions', 'typing', 'analysis.flow_direction',
                                  'analysis.tcp_stream_observation', 'analysis.tls_handshake_framing'})
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse(attributes & {'from_bytes', 'raw_bytes', 'unconsumed_payload', 'captured_at', 'protocol_version'})
