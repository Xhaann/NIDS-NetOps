import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from analysis import (
    FlowIdentity,
    FlowIdentityError,
    ICMPMessage,
    IPv4Packet,
    PacketAnalysis,
    TCPControlStatistics,
    TCPControlStatisticsError,
    TCPPacket,
    UDPPacket,
    flow_identity_from_packet,
    update_tcp_control_statistics,
)
from capture.packet_observation import CaptureSource, PacketObservation


TIMESTAMP = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
OBSERVATION = PacketObservation(
    TIMESTAMP, None, 60, 100, bytes(60), CaptureSource("test-tcp-control-statistics"),
)
IPV4 = IPv4Packet(
    version=4, ihl=5, dscp=0, ecn=0, total_length=40, identification=0, flags=0,
    fragment_offset=0, ttl=64, protocol=6, header_checksum=0,
    source_address=b"\x0a\x00\x00\x01", destination_address=b"\x0a\x00\x00\x02",
    options=b"", payload=bytes(20),
)
TCP = TCPPacket(
    source_port=12345, destination_port=443, sequence_number=0, acknowledgment_number=0,
    data_offset=5, reserved_bits=0, ns=False, cwr=False, ece=False, urg=False,
    ack=False, psh=False, rst=False, syn=False, fin=False, window_size=0,
    checksum=0, urgent_pointer=0, options=b"", payload=b"",
)
TCP_ANALYSIS = PacketAnalysis(OBSERVATION, ipv4=IPV4, tcp=TCP)
IDENTITY = flow_identity_from_packet(TCP_ANALYSIS)
FLAGS = ("ns", "cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin")
FIELD_NAMES = (
    "identity", "packet_count", "forward_packet_count", "reverse_packet_count",
    "forward_ns_count", "forward_cwr_count", "forward_ece_count", "forward_urg_count",
    "forward_ack_count", "forward_psh_count", "forward_rst_count", "forward_syn_count",
    "forward_fin_count", "reverse_ns_count", "reverse_cwr_count", "reverse_ece_count",
    "reverse_urg_count", "reverse_ack_count", "reverse_psh_count", "reverse_rst_count",
    "reverse_syn_count", "reverse_fin_count", "forward_syn_ack_count", "reverse_syn_ack_count",
)
COUNTER_NAMES = FIELD_NAMES[1:]


def packet(
    seconds: float = 0.0,
    reverse: bool = False,
    checksum_valid=None,
    **flag_values,
) -> PacketAnalysis:
    ipv4 = IPV4
    tcp = replace(TCP, **flag_values)
    if reverse:
        ipv4 = replace(
            IPV4, source_address=IPV4.destination_address,
            destination_address=IPV4.source_address,
        )
        tcp = replace(tcp, source_port=TCP.destination_port, destination_port=TCP.source_port)
    observation = replace(OBSERVATION, captured_at=TIMESTAMP + timedelta(seconds=seconds))
    return PacketAnalysis(
        observation, ipv4=ipv4, tcp=tcp,
        ipv4_checksum_valid=checksum_valid, tcp_checksum_valid=checksum_valid,
    )


def direct_statistics(**changes) -> TCPControlStatistics:
    identity = changes.pop("identity", IDENTITY)
    values = {name: 0 for name in COUNTER_NAMES}
    values.update(packet_count=1, forward_packet_count=1)
    values.update(changes)
    return TCPControlStatistics(identity=identity, **values)


class TCPControlStatisticsTests(unittest.TestCase):
    def test_no_flags_increment_only_total_and_selected_direction(self) -> None:
        for reverse in (False, True):
            supplied = replace(IDENTITY)
            analysis = packet(reverse=reverse)
            result = update_tcp_control_statistics(None, analysis, supplied)
            selected = "reverse" if reverse else "forward"
            opposite = "forward" if reverse else "reverse"
            self.assertIs(result.identity, supplied)
            self.assertEqual(result.packet_count, 1)
            self.assertEqual(getattr(result, selected + "_packet_count"), 1)
            self.assertEqual(getattr(result, opposite + "_packet_count"), 0)
            for direction in ("forward", "reverse"):
                for flag in FLAGS:
                    self.assertEqual(getattr(result, direction + "_" + flag + "_count"), 0)
                self.assertEqual(getattr(result, direction + "_syn_ack_count"), 0)

    def test_individual_and_combined_flags_are_counted_independently(self) -> None:
        cases = (
            ("SYN", {"syn": True}, ("syn",)),
            ("ACK", {"ack": True}, ("ack",)),
            ("SYN+ACK", {"syn": True, "ack": True}, ("syn", "ack", "syn_ack")),
            ("FIN", {"fin": True}, ("fin",)),
            ("FIN+ACK", {"fin": True, "ack": True}, ("fin", "ack")),
            ("RST", {"rst": True}, ("rst",)),
            ("RST+ACK", {"rst": True, "ack": True}, ("rst", "ack")),
            ("PSH+ACK", {"psh": True, "ack": True}, ("psh", "ack")),
            ("URG+ACK", {"urg": True, "ack": True}, ("urg", "ack")),
            ("NS", {"ns": True}, ("ns",)),
            ("CWR", {"cwr": True}, ("cwr",)),
            ("ECE", {"ece": True}, ("ece",)),
            ("CWR+ECE", {"cwr": True, "ece": True}, ("cwr", "ece")),
            ("SYN+FIN", {"syn": True, "fin": True}, ("syn", "fin")),
            ("SYN+RST", {"syn": True, "rst": True}, ("syn", "rst")),
            ("all", {name: True for name in FLAGS}, FLAGS + ("syn_ack",)),
        )
        for reverse in (False, True):
            direction = "reverse" if reverse else "forward"
            for label, flag_values, expected in cases:
                with self.subTest(reverse=reverse, flags=label):
                    result = update_tcp_control_statistics(None, packet(reverse=reverse, **flag_values), IDENTITY)
                    for name in FLAGS + ("syn_ack",):
                        self.assertEqual(
                            getattr(result, direction + "_" + name + "_count"),
                            int(name in expected),
                        )

    def test_sequence_accounting_properties_direction_isolation_and_repetition(self) -> None:
        observations = (
            packet(0, ack=True),
            packet(1, syn=True),
            packet(2, True, syn=True),
            packet(3, syn=True),
            packet(4, True, syn=True, ack=True),
            packet(5, True, syn=True, ack=True),
            packet(6, rst=True),
            packet(7, rst=True, ack=True),
            packet(8, True, **{name: True for name in FLAGS}),
            packet(9, cwr=True, ece=True),
            packet(10, True, fin=True, ack=True),
            packet(11, psh=True, ack=True),
            packet(12, True, urg=True, ack=True),
            packet(13, syn=True, fin=True),
            packet(14, True, syn=True, rst=True),
        )
        current = None
        accepted = []
        for analysis in observations:
            previous = current
            previous_values = None if previous is None else vars(previous).copy()
            analysis_values = vars(analysis).copy()
            tcp_values = vars(analysis.tcp).copy()
            direction = "forward" if analysis.ipv4.source_address == IPV4.source_address else "reverse"
            opposite = "reverse" if direction == "forward" else "forward"
            current = update_tcp_control_statistics(current, analysis, IDENTITY)
            accepted.append((direction, analysis.tcp))
            self.assertIsNot(current, previous)
            if previous is not None:
                self.assertEqual(vars(previous), previous_values)
                for suffix in ("packet_count",) + tuple(flag + "_count" for flag in FLAGS) + (
                    "syn_ack_count",
                ):
                    self.assertEqual(
                        getattr(current, opposite + "_" + suffix),
                        getattr(previous, opposite + "_" + suffix),
                    )
            self.assertEqual(vars(analysis), analysis_values)
            self.assertEqual(vars(analysis.tcp), tcp_values)
        self.assertEqual(current.packet_count, len(accepted))
        for direction in ("forward", "reverse"):
            selected = [tcp for observed_direction, tcp in accepted if observed_direction == direction]
            self.assertEqual(getattr(current, direction + "_packet_count"), len(selected))
            for flag in FLAGS:
                self.assertEqual(
                    getattr(current, direction + "_" + flag + "_count"),
                    sum(int(getattr(tcp, flag)) for tcp in selected),
                )
            self.assertEqual(
                getattr(current, direction + "_syn_ack_count"),
                sum(int(tcp.syn and tcp.ack) for tcp in selected),
            )
        self.assertEqual(current.forward_packet_count + current.reverse_packet_count, current.packet_count)
        self.assertEqual(current.forward_syn_count, 3)
        self.assertEqual(current.reverse_syn_ack_count, 3)
        self.assertEqual(current.forward_rst_count, 2)

    def test_canonical_direction_and_identity_retention(self) -> None:
        supplied = replace(IDENTITY)
        forward = packet(syn=True)
        reverse = packet(1, True, ack=True)
        first = update_tcp_control_statistics(None, forward, supplied)
        equal_identity = replace(supplied)
        second = update_tcp_control_statistics(first, reverse, equal_identity)
        self.assertIs(first.identity, supplied)
        self.assertIs(second.identity, supplied)
        self.assertIsNot(equal_identity, supplied)
        self.assertEqual((second.forward_packet_count, second.reverse_packet_count), (1, 1))
        self.assertEqual((second.forward_syn_count, second.reverse_ack_count), (1, 1))
        different = replace(IDENTITY, source_port=12346)
        for current, analysis, identity in (
            (None, forward, different),
            (first, reverse, different),
            (replace(first, identity=different), reverse, IDENTITY),
        ):
            with self.assertRaises(TCPControlStatisticsError):
                update_tcp_control_statistics(current, analysis, identity)

    def test_checksum_and_noncontrol_fields_do_not_affect_accounting(self) -> None:
        expected = update_tcp_control_statistics(None, packet(syn=True, ack=True), IDENTITY)
        for checksum_valid in (True, False, None):
            analysis = packet(123.456789, checksum_valid=checksum_valid, syn=True, ack=True)
            analysis = replace(
                analysis,
                observation=replace(
                    analysis.observation, captured_length=7, original_length=70, raw_bytes=b"changed",
                ),
                ipv4=replace(
                    analysis.ipv4, identification=65535, flags=7, ttl=1,
                    options=b"\x01\x02\x03\x04", ihl=6, total_length=44,
                ),
                tcp=replace(
                    analysis.tcp, sequence_number=0xFFFFFFFF,
                    acknowledgment_number=0xFFFFFFFF, data_offset=6, reserved_bits=7,
                    window_size=65535, checksum=65535, urgent_pointer=65535,
                    options=b"\x01\x02\x03\x04", payload=b"payload",
                ),
            )
            self.assertEqual(update_tcp_control_statistics(None, analysis, IDENTITY), expected)

    def test_different_control_sequences_close_the_audited_information_gap(self) -> None:
        left_packets = (packet(0, syn=True), packet(1, ack=True))
        right_packets = (packet(0, rst=True), packet(1, fin=True))
        left = None
        right = None
        for left_packet, right_packet in zip(left_packets, right_packets):
            self.assertEqual(left_packet.observation, right_packet.observation)
            self.assertEqual(left_packet.ipv4, right_packet.ipv4)
            left = update_tcp_control_statistics(left, left_packet, IDENTITY)
            right = update_tcp_control_statistics(right, right_packet, IDENTITY)
        self.assertEqual(left.packet_count, right.packet_count)
        self.assertEqual(left.forward_packet_count, right.forward_packet_count)
        self.assertNotEqual(left, right)
        self.assertEqual((left.forward_syn_count, left.forward_ack_count), (1, 1))
        self.assertEqual((right.forward_rst_count, right.forward_fin_count), (1, 1))

    def test_determinism_large_counts_and_source_immutability(self) -> None:
        observations = (packet(0, syn=True), packet(1, True, syn=True, ack=True), packet(2, rst=True))
        results = []
        for supplied in (IDENTITY, replace(IDENTITY)):
            current = None
            before = [(vars(value).copy(), vars(value.tcp).copy()) for value in observations]
            for analysis in observations:
                current = update_tcp_control_statistics(current, analysis, supplied)
            results.append(current)
            for analysis, (analysis_values, tcp_values) in zip(observations, before):
                self.assertEqual(vars(analysis), analysis_values)
                self.assertEqual(vars(analysis.tcp), tcp_values)
        self.assertEqual(results[0], results[1])
        self.assertIsNot(results[0], results[1])
        count = 10 ** 100
        current = direct_statistics(
            packet_count=count, forward_packet_count=count,
            forward_syn_count=count, forward_ack_count=count,
            forward_syn_ack_count=count,
        )
        updated = update_tcp_control_statistics(current, packet(), IDENTITY)
        self.assertEqual(updated.packet_count, count + 1)
        self.assertEqual(updated.forward_packet_count, count + 1)
        self.assertEqual(updated.forward_syn_ack_count, count)

    def test_wrong_inputs_and_non_tcp_analyses_are_rejected(self) -> None:
        class DerivedAnalysis(PacketAnalysis):
            pass

        class DerivedIdentity(FlowIdentity):
            pass

        class DerivedStatistics(TCPControlStatistics):
            pass

        class DerivedTCPPacket(TCPPacket):
            pass

        current = update_tcp_control_statistics(None, packet(), IDENTITY)
        for value in (
            True, 1, {}, [], SimpleNamespace(**vars(current)), DerivedStatistics(**vars(current)),
        ):
            with self.assertRaises(TypeError):
                update_tcp_control_statistics(value, packet(), IDENTITY)
        for value in (
            None, True, 1, {}, [], TCP, SimpleNamespace(**vars(TCP_ANALYSIS)),
            DerivedAnalysis(**vars(TCP_ANALYSIS)),
        ):
            with self.assertRaises(TypeError):
                update_tcp_control_statistics(current, value, IDENTITY)
        for value in (
            None, True, 1, {}, [], SimpleNamespace(**vars(IDENTITY)), DerivedIdentity(**vars(IDENTITY)),
        ):
            with self.assertRaises(TypeError):
                update_tcp_control_statistics(current, packet(), value)
        derived_tcp = replace(packet(), tcp=DerivedTCPPacket(**vars(TCP)))
        with self.assertRaises(TypeError):
            update_tcp_control_statistics(current, derived_tcp, IDENTITY)
        udp_ipv4 = replace(IPV4, protocol=17, total_length=28, payload=bytes(8))
        udp = PacketAnalysis(OBSERVATION, ipv4=udp_ipv4, udp=UDPPacket(12345, 443, 8, 0, b""))
        udp_identity = flow_identity_from_packet(udp)
        with self.assertRaises(TCPControlStatisticsError):
            update_tcp_control_statistics(None, udp, udp_identity)
        missing = replace(TCP_ANALYSIS, tcp=None)
        icmp = PacketAnalysis(
            OBSERVATION, ipv4=replace(IPV4, protocol=1, total_length=28, payload=bytes(8)),
            icmp=ICMPMessage(8, 0, 0, bytes(4), b""),
        )
        for analysis in (missing, icmp):
            with self.assertRaises(FlowIdentityError):
                update_tcp_control_statistics(None, analysis, IDENTITY)

    def test_direct_model_enforces_types_ranges_and_count_relationships(self) -> None:
        self.assertTrue(issubclass(TCPControlStatisticsError, ValueError))
        for name in COUNTER_NAMES:
            for value in (True, False, 1.0, "1", None):
                with self.subTest(name=name, value=value):
                    with self.assertRaises(TypeError):
                        direct_statistics(**{name: value})
            with self.assertRaises(TCPControlStatisticsError):
                direct_statistics(**{name: -1})
        for changes in (
            {"packet_count": 0, "forward_packet_count": 0},
            {"packet_count": 2},
            {"forward_packet_count": 0, "reverse_packet_count": 0},
            {"forward_syn_count": 2},
            {"reverse_packet_count": 1, "forward_packet_count": 0, "reverse_ack_count": 2},
            {"forward_syn_ack_count": 1},
            {"forward_syn_count": 1, "forward_syn_ack_count": 1},
            {"reverse_packet_count": 1, "forward_packet_count": 0,
             "reverse_ack_count": 1, "reverse_syn_ack_count": 1},
            {"reverse_packet_count": 1, "forward_packet_count": 0,
             "reverse_syn_count": 1, "reverse_syn_ack_count": 1},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(TCPControlStatisticsError):
                    direct_statistics(**changes)
        with self.assertRaises(TypeError):
            direct_statistics(identity=None)
        with self.assertRaises(TypeError):
            direct_statistics(identity=SimpleNamespace(**vars(IDENTITY)))
        with self.assertRaises(TCPControlStatisticsError):
            direct_statistics(identity=replace(IDENTITY, protocol=17))

    def test_exact_frozen_field_order_retains_only_identity_and_scalar_counters(self) -> None:
        result = update_tcp_control_statistics(None, packet(syn=True, ack=True), IDENTITY)
        self.assertEqual(tuple(field.name for field in fields(result)), FIELD_NAMES)
        self.assertEqual(tuple(vars(result)), FIELD_NAMES)
        self.assertEqual(len(fields(result)), 24)
        for name in FIELD_NAMES:
            value = getattr(result, name)
            self.assertIn(type(value), (FlowIdentity, int))
            with self.assertRaises(FrozenInstanceError):
                setattr(result, name, value)
            with self.assertRaises(FrozenInstanceError):
                delattr(result, name)
        with self.assertRaises(TCPControlStatisticsError):
            replace(result, packet_count=2)
        for value in vars(result).values():
            self.assertNotIsInstance(value, (PacketAnalysis, TCPPacket, list, dict, set))
