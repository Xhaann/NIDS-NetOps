import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo

from analysis import (
    DirectionalInterArrivalStatisticsError,
    FlowInterArrivalStatisticsError,
    FlowRateFeaturesError,
    IPv4Packet,
    PacketAnalysis,
    UDPPacket,
    extract_flow_duration_features,
    extract_flow_rate_features,
    extract_inter_arrival_features,
    flow_identity_from_packet,
    update_directional_inter_arrival_statistics,
    update_flow_inter_arrival_statistics,
    update_flow_statistics,
)
from capture import CaptureSource, PacketObservation


TIMESTAMP = datetime(2026, 3, 31, 12, tzinfo=timezone.utc)
OBSERVATION = PacketObservation(TIMESTAMP, None, 60, 100, bytes(60), CaptureSource("test-utc-flow"))
IPV4 = IPv4Packet(
    version=4, ihl=5, dscp=0, ecn=0, total_length=28, identification=0, flags=0,
    fragment_offset=0, ttl=64, protocol=17, header_checksum=0,
    source_address=b"\x0a\x00\x00\x01", destination_address=b"\x0a\x00\x00\x02",
    options=b"", payload=bytes(8),
)
ANALYSIS = PacketAnalysis(OBSERVATION, ipv4=IPV4, udp=UDPPacket(12345, 443, 8, 0, b""))


class ChangingOffset(tzinfo):
    def utcoffset(self, value):
        return timedelta(hours=1 if value.month >= 4 else 0)

    def dst(self, value):
        return timedelta(0)


class UTCFlowTimestampTests(unittest.TestCase):
    def test_offset_transition_is_rejected_at_observation_boundary_and_explicit_utc_is_admitted(self) -> None:
        zone = ChangingOffset()
        local_times = (
            datetime(2026, 3, 31, 12, tzinfo=zone),
            datetime(2026, 3, 31, 23, tzinfo=timezone.utc),
            datetime(2026, 4, 1, 12, tzinfo=zone),
        )
        self.assertEqual(local_times[0].utcoffset(), timedelta(0))
        self.assertEqual(local_times[2].utcoffset(), timedelta(hours=1))
        for timestamp in (local_times[0], local_times[2]):
            with self.assertRaisesRegex(ValueError, "fixed UTC datetime.timezone"):
                replace(OBSERVATION, captured_at=timestamp)
        identity = flow_identity_from_packet(ANALYSIS)
        global_state = None
        intervals = None
        directional = None
        for timestamp in local_times:
            utc = timestamp.astimezone(timezone.utc)
            observation = replace(OBSERVATION, captured_at=utc)
            self.assertIs(observation.captured_at, utc)
            packet = replace(ANALYSIS, observation=observation)
            global_state = update_flow_statistics(global_state, packet, identity)
            intervals = update_flow_inter_arrival_statistics(intervals, packet, identity)
            directional = update_directional_inter_arrival_statistics(directional, packet, identity)
        duration = extract_flow_duration_features(global_state).duration_seconds
        self.assertEqual(global_state.packet_count, 3)
        self.assertEqual(duration, 82800.0)
        self.assertEqual(intervals.inter_arrival_sum_seconds, duration)
        self.assertEqual(directional.forward_inter_arrival_sum_seconds, duration)
        self.assertEqual(extract_inter_arrival_features(intervals).mean_inter_arrival_seconds, 41400.0)
        self.assertEqual(extract_flow_rate_features(global_state).packets_per_second, 3 / 82800)

    def test_equal_and_fractional_utc_instants_preserve_elapsed_time_and_zero_rate_policy(self) -> None:
        identity = flow_identity_from_packet(ANALYSIS)
        global_state = None
        intervals = None
        directional = None
        for seconds, zone in ((0, timezone.utc), (0, timezone(timedelta(0), "UTC alias")),
                              (0.000001, timezone.utc), (1.5, timezone.utc), (4, timezone.utc)):
            timestamp = (TIMESTAMP + timedelta(seconds=seconds)).astimezone(zone)
            packet = replace(ANALYSIS, observation=replace(OBSERVATION, captured_at=timestamp))
            global_state = update_flow_statistics(global_state, packet, identity)
            intervals = update_flow_inter_arrival_statistics(intervals, packet, identity)
            directional = update_directional_inter_arrival_statistics(directional, packet, identity)
            duration = extract_flow_duration_features(global_state).duration_seconds
            self.assertEqual(duration, seconds)
            self.assertAlmostEqual(intervals.inter_arrival_sum_seconds, duration)
            self.assertAlmostEqual(directional.forward_inter_arrival_sum_seconds, duration)
            if seconds == 0:
                with self.assertRaises(FlowRateFeaturesError):
                    extract_flow_rate_features(global_state)
            else:
                self.assertEqual(extract_flow_rate_features(global_state).packets_per_second,
                                 global_state.packet_count / seconds)

    def test_utc_out_of_order_packets_still_fail_without_changing_interval_state(self) -> None:
        identity = flow_identity_from_packet(ANALYSIS)
        later = replace(ANALYSIS, observation=replace(OBSERVATION, captured_at=TIMESTAMP + timedelta(seconds=2)))
        earlier = replace(ANALYSIS, observation=replace(OBSERVATION, captured_at=TIMESTAMP + timedelta(seconds=1)))
        for update, error in ((update_flow_inter_arrival_statistics, FlowInterArrivalStatisticsError),
                              (update_directional_inter_arrival_statistics, DirectionalInterArrivalStatisticsError)):
            current = update(update(None, ANALYSIS, identity), later, identity)
            before = vars(current).copy()
            with self.assertRaises(error):
                update(current, earlier, identity)
            self.assertEqual(vars(current), before)
