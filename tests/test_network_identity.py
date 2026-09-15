import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import patch

import analysis
from analysis import (
    FlowIdentity,
    FlowObservationWindowManager,
    extract_flow_feature_snapshot,
    flow_identity_from_addresses,
    flow_identity_from_packet,
)
from analysis import flow_identity
from application import detector_orchestration, run_closed_flow_detectors
from detection import (
    FlowVolumeMetric,
    FlowVolumeThresholdConfiguration,
    FlowVolumeThresholdDecision,
    TCPControlMetric,
    TCPControlThresholdConfiguration,
    TCPControlThresholdDecision,
    evaluate_flow_volume_threshold,
    evaluate_tcp_control_threshold,
)
from tests.test_tcp_control_threshold import closed_window, tcp_packet, udp_packet


def synthetic_window(identity):
    packet = tcp_packet if identity.protocol == 6 else udp_packet
    template = closed_window(packet(0), packet(1))
    state = template.coordinated_state
    components = {}
    for field in fields(state):
        if field.name in ("dns_transaction_statistics", "dns_query_name_statistics"):
            continue
        component = getattr(state, field.name)
        components[field.name] = (
            None if component is None or field.name == "tcp_stream_state" else replace(component, identity=identity)
        )
    return replace(template, coordinated_state=replace(state, **components))


class CanonicalNetworkIdentityTests(unittest.TestCase):
    def test_public_exports_preserve_existing_identity_type(self) -> None:
        self.assertIs(analysis.FlowIdentity, flow_identity.FlowIdentity)
        self.assertIs(flow_identity_from_addresses, flow_identity.flow_identity_from_addresses)
        self.assertIn("flow_identity_from_addresses", analysis.__all__)
        self.assertNotIn("_packed_ip_address", analysis.__all__)

    def test_ipv4_text_matches_existing_packed_identity_and_hash(self) -> None:
        source = b"\xc0\x00\x02\x01"
        destination = b"\xc0\x00\x02\x02"
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                packed = FlowIdentity(source, destination, 12345, 443, protocol)
                text = flow_identity_from_addresses(
                    "192.0.2.1", "192.0.2.2", 12345, 443, protocol,
                )
                self.assertEqual(text, packed)
                self.assertEqual(text.ip_version, 4)
                self.assertEqual(hash(text), hash(packed))
                self.assertEqual(hash(packed), hash((source, destination, 12345, 443, protocol)))
                self.assertIs(packed.source_address, source)
                self.assertIs(packed.destination_address, destination)
                self.assertEqual(str(IPv4Address(text.source_address)), "192.0.2.1")

    def test_ipv6_compressed_expanded_and_case_variants_share_identity(self) -> None:
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                compressed = flow_identity_from_addresses(
                    "2001:db8::a", "2001:db8::b", 12345, 443, protocol,
                )
                expanded = flow_identity_from_addresses(
                    "2001:0DB8:0000:0000:0000:0000:0000:000A",
                    "2001:0db8:0:0:0:0:0:000b", 12345, 443, protocol,
                )
                self.assertEqual(compressed, expanded)
                self.assertEqual(compressed.ip_version, 6)
                self.assertEqual(hash(compressed), hash(expanded))
                self.assertEqual(len({compressed, expanded}), 1)
                self.assertEqual({compressed: "flow"}[expanded], "flow")
                self.assertEqual(str(IPv6Address(compressed.source_address)), "2001:db8::a")

    def test_ipv6_packed_addresses_retain_exact_objects(self) -> None:
        source = IPv6Address("2001:db8::1").packed
        destination = IPv6Address("2001:db8::2").packed
        identity = FlowIdentity(destination, source, 443, 12345, 6)
        self.assertIs(identity.source_address, source)
        self.assertIs(identity.destination_address, destination)
        self.assertEqual((identity.source_port, identity.destination_port), (12345, 443))
        self.assertEqual(identity.ip_version, 6)

    def test_complete_endpoints_use_numeric_address_order_before_port_order(self) -> None:
        for low, high in (("10.0.0.2", "10.0.0.10"), ("2001:db8::2", "2001:db8::10")):
            for protocol in (6, 17):
                with self.subTest(low=low, protocol=protocol):
                    forward = flow_identity_from_addresses(low, high, 65535, 0, protocol)
                    reverse = flow_identity_from_addresses(high, low, 0, 65535, protocol)
                    self.assertEqual(forward, reverse)
                    self.assertEqual(hash(forward), hash(reverse))
                    self.assertEqual((forward.source_port, forward.destination_port), (65535, 0))

    def test_equal_ipv6_addresses_use_ports_and_identical_endpoints_are_valid(self) -> None:
        for source_port, destination_port in ((65535, 0), (0, 65535), (443, 443)):
            with self.subTest(ports=(source_port, destination_port)):
                identity = flow_identity_from_addresses(
                    "::1", "0:0:0:0:0:0:0:1", source_port, destination_port, 6,
                )
                self.assertEqual(identity.source_address, identity.destination_address)
                self.assertEqual(identity.source_port, min(source_port, destination_port))
                self.assertEqual(identity.destination_port, max(source_port, destination_port))

    def test_address_family_is_independent_of_transport_protocol(self) -> None:
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                ipv4 = flow_identity_from_addresses("0.0.0.1", "0.0.0.2", 1, 2, protocol)
                ipv6 = flow_identity_from_addresses("::1", "::2", 1, 2, protocol)
                self.assertEqual((ipv4.ip_version, ipv6.ip_version), (4, 6))
                self.assertNotEqual(ipv4, ipv6)
                self.assertEqual(len({ipv4, ipv6}), 2)

    def test_mapped_ipv6_addresses_keep_ipv6_family(self) -> None:
        ipv4 = flow_identity_from_addresses("192.0.2.1", "192.0.2.2", 1, 2, 6)
        mapped = flow_identity_from_addresses("::ffff:192.0.2.1", "::ffff:192.0.2.2", 1, 2, 6)
        hexadecimal = flow_identity_from_addresses("::ffff:c000:201", "::ffff:c000:202", 1, 2, 6)
        self.assertEqual(mapped.ip_version, 6)
        self.assertEqual(mapped, hexadecimal)
        self.assertNotEqual(ipv4, mapped)

    def test_mixed_families_are_rejected_in_text_and_packed_construction(self) -> None:
        for source, destination in (("192.0.2.1", "2001:db8::1"), ("::1", "192.0.2.1")):
            with self.subTest(source=source):
                with self.assertRaisesRegex(ValueError, "same IP version"):
                    flow_identity_from_addresses(source, destination, 1, 2, 6)
        for source, destination in ((bytes(4), bytes(16)), (bytes(16), bytes(4))):
            with self.subTest(source_length=len(source)):
                with self.assertRaisesRegex(ValueError, "same IP version"):
                    FlowIdentity(source, destination, 1, 2, 17)

    def test_invalid_ipv4_text_is_rejected_at_either_endpoint(self) -> None:
        for invalid in ("256.0.0.1", "192.0.2", "192.0.2.1.2", "192.0.2.-1", "010.0.0.1", "192.0.2.1/24"):
            for source, destination in ((invalid, "192.0.2.1"), ("192.0.2.1", invalid)):
                with self.subTest(source=source, destination=destination):
                    with self.assertRaises(ValueError):
                        flow_identity_from_addresses(source, destination, 1, 2, 6)

    def test_invalid_ipv6_text_is_rejected_at_either_endpoint(self) -> None:
        for invalid in ("2001:db8:::1", "1::2::3", "2001:db8::g", "12345::1", "1:2:3:4:5:6:7:8:9", "2001:db8::1/64", "[::1]"):
            for source, destination in ((invalid, "::1"), ("::1", invalid)):
                with self.subTest(source=source, destination=destination):
                    with self.assertRaises(ValueError):
                        flow_identity_from_addresses(source, destination, 1, 2, 6)

    def test_scoped_ipv6_addresses_are_rejected_without_discarding_scope(self) -> None:
        for scoped in ("fe80::1%eth0", "fe80::1%1"):
            for source, destination in ((scoped, "fe80::2"), ("fe80::2", scoped)):
                with self.subTest(source=source, destination=destination):
                    with self.assertRaisesRegex(ValueError, "scoped IPv6"):
                        flow_identity_from_addresses(source, destination, 1, 2, 17)

    def test_text_constructor_rejects_non_strings_and_non_address_text(self) -> None:
        for invalid in (None, True, 1, bytes(4), bytearray(16), IPv4Address("192.0.2.1")):
            for source, destination in ((invalid, "::1"), ("::1", invalid)):
                with self.subTest(source=source, destination=destination):
                    with self.assertRaises(TypeError):
                        flow_identity_from_addresses(source, destination, 1, 2, 6)
        for invalid in ("", "localhost", " 192.0.2.1", "::1 ", "1234"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    flow_identity_from_addresses(invalid, "::1", 1, 2, 6)

    def test_ipv6_rejects_mutable_and_invalid_packed_addresses(self) -> None:
        identity = FlowIdentity(bytes(16), bytes(16), 1, 2, 6)
        for name in ("source_address", "destination_address"):
            for invalid in (bytearray(16), memoryview(bytes(16)), "::1", None):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(TypeError):
                        replace(identity, **{name: invalid})
            for length in (0, 3, 5, 15, 17):
                with self.subTest(name=name, length=length):
                    with self.assertRaises(ValueError):
                        replace(identity, **{name: bytes(length)})

    def test_ipv6_transport_scope_remains_exactly_tcp_and_udp(self) -> None:
        for protocol in range(256):
            with self.subTest(protocol=protocol):
                if protocol in (6, 17):
                    identity = flow_identity_from_addresses("::1", "::2", 1, 2, protocol)
                    self.assertEqual(identity.protocol, protocol)
                else:
                    with self.assertRaisesRegex(ValueError, "protocol must be 6 or 17"):
                        flow_identity_from_addresses("::1", "::2", 1, 2, protocol)

    def test_ipv6_integer_types_and_port_bounds_remain_strict(self) -> None:
        identity = flow_identity_from_addresses("::1", "::2", 1, 2, 6)
        for name in ("source_port", "destination_port", "protocol"):
            for invalid in (True, False, 6.0, "6", None):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(TypeError):
                        replace(identity, **{name: invalid})
        for name in ("source_port", "destination_port"):
            for invalid in (-1, 65536):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(ValueError):
                        replace(identity, **{name: invalid})

    def test_ipv6_each_endpoint_field_and_transport_distinguish_identity(self) -> None:
        identity = flow_identity_from_addresses("2001:db8::1", "2001:db8::2", 1, 2, 6)
        for changes in (
            {"source_address": IPv6Address("2001:db8::3").packed},
            {"destination_address": IPv6Address("2001:db8::4").packed},
            {"source_port": 3}, {"destination_port": 4}, {"protocol": 17},
        ):
            with self.subTest(changes=changes):
                self.assertNotEqual(identity, replace(identity, **changes))

    def test_repeated_construction_is_equal_hashable_and_immutable(self) -> None:
        for source, destination in (("192.0.2.1", "192.0.2.2"), ("2001:db8::1", "2001:db8::2")):
            with self.subTest(source=source):
                identity = flow_identity_from_addresses(source, destination, 1, 2, 6)
                for _ in range(3):
                    repeated = flow_identity_from_addresses(source, destination, 1, 2, 6)
                    self.assertEqual(identity, repeated)
                    self.assertEqual(hash(identity), hash(repeated))
                self.assertEqual(tuple(field.name for field in fields(identity)), (
                    "source_address", "destination_address", "source_port", "destination_port", "protocol",
                ))
                for name in tuple(field.name for field in fields(identity)) + ("ip_version",):
                    with self.assertRaises(FrozenInstanceError):
                        setattr(identity, name, None)
                    with self.assertRaises(FrozenInstanceError):
                        delattr(identity, name)
                with self.assertRaises(TypeError):
                    identity.source_address[0] = 0


class NetworkIdentityIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.volume = FlowVolumeThresholdConfiguration("volume", "1", FlowVolumeMetric.PACKET_COUNT, 0)
        self.control = TCPControlThresholdConfiguration("control", "1", TCPControlMetric.FORWARD_SYN, 0)

    def test_ipv4_text_identity_locates_and_closes_existing_observation(self) -> None:
        for protocol, packet in ((6, tcp_packet), (17, udp_packet)):
            with self.subTest(protocol=protocol):
                manager = FlowObservationWindowManager("identity", timedelta(seconds=5))
                analysis_result = packet(0)
                active = manager.record(analysis_result).active_window
                identity = flow_identity_from_addresses("10.0.0.1", "10.0.0.2", 12345, 443, protocol)
                self.assertEqual(identity, flow_identity_from_packet(analysis_result))
                self.assertEqual(identity, active.identity)
                closed = manager.close(identity)
                self.assertIs(closed.identity, active.identity)
                snapshot = extract_flow_feature_snapshot(closed)
                self.assertIs(snapshot.observation_window, closed)
                self.assertIs(snapshot.identity, active.identity)
                findings = run_closed_flow_detectors(
                    snapshot, flow_volume_configuration=self.volume,
                    tcp_control_configuration=self.control if protocol == 6 else None,
                )
                self.assertEqual(len(findings), 2 if protocol == 6 else 1)
                self.assertIs(findings[0].raw_evidence.snapshot, snapshot)
                self.assertIs(findings[0].decision, FlowVolumeThresholdDecision.MATCH)
                if protocol == 6:
                    self.assertIs(findings[1].raw_evidence.observation_window, closed)
                    self.assertIs(findings[1].decision, TCPControlThresholdDecision.NO_MATCH)
                self.assertEqual(manager.active_windows(), ())

    def test_synthetic_ipv6_observation_and_features_retain_exact_identity(self) -> None:
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                identity = flow_identity_from_addresses("2001:db8::1", "2001:db8::2", 12345, 443, protocol)
                window = synthetic_window(identity)
                snapshot = extract_flow_feature_snapshot(window)
                self.assertIs(window.identity, identity)
                self.assertIs(snapshot.observation_window, window)
                self.assertIs(snapshot.coordinated_state, window.coordinated_state)
                self.assertIs(snapshot.identity, identity)
                self.assertEqual(snapshot.flow_volume_features.packet_count, 2)
                self.assertEqual(snapshot.flow_duration_features.duration_seconds, 1.0)
                self.assertEqual(snapshot.flow_rate_features.packets_per_second, 2.0)
                self.assertEqual(extract_flow_feature_snapshot(window), snapshot)

    def test_ipv6_identity_supports_volume_detector_and_orchestration(self) -> None:
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                identity = flow_identity_from_addresses("2001:db8::1", "2001:db8::2", 1, 2, protocol)
                window = synthetic_window(identity)
                snapshot = extract_flow_feature_snapshot(window)
                evaluation = evaluate_flow_volume_threshold(snapshot, self.volume)
                self.assertIs(evaluation.decision, FlowVolumeThresholdDecision.MATCH)
                self.assertEqual(evaluation.raw_evidence.observed_value, 2)
                with patch.object(detector_orchestration, "evaluate_tcp_control_threshold",
                                  wraps=evaluate_tcp_control_threshold) as control:
                    findings = run_closed_flow_detectors(
                        snapshot, flow_volume_configuration=self.volume,
                        tcp_control_configuration=self.control,
                    )
                self.assertEqual(len(findings), 2 if protocol == 6 else 1)
                self.assertEqual(control.call_count, int(protocol == 6))
                self.assertIs(findings[0].raw_evidence.snapshot, snapshot)
                self.assertIs(findings[0].decision, FlowVolumeThresholdDecision.MATCH)
                self.assertIs(snapshot.observation_window, window)
                self.assertIs(window.identity, identity)

    def test_ipv6_identity_supports_tcp_control_detector(self) -> None:
        identity = flow_identity_from_addresses("::1", "::2", 1, 2, 6)
        window = synthetic_window(identity)
        evaluation = evaluate_tcp_control_threshold(window, self.control)
        self.assertIs(evaluation.decision, TCPControlThresholdDecision.NO_MATCH)
        self.assertEqual(evaluation.raw_evidence.observed_value, 0)
        self.assertIs(evaluation.raw_evidence.observation_window, window)
        self.assertIs(window.identity, identity)


if __name__ == "__main__":
    unittest.main()
