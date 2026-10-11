import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from analysis import (
    FeatureContractVersion,
    FlowFeatureProvenance,
    FlowFeatureProvenanceError,
    FlowIdentity,
    FlowObservationWindowClosureReason,
    FlowObservationWindowKey,
    FlowObservationWindowManager,
    extract_flow_feature_snapshot,
    flow_feature_provenance_from_window,
    flow_identity_from_packet,
)
from application import run_flow_observation_session
from capture import PcapPacketSource
from ml import project_flow_features
from research import ResearchDataset, ResearchExample, research_example_from_window
from tests.pcap_scenarios import pcap_bytes, tcp_exchange, udp_exchange
from tests.test_flow_feature_snapshot import TIMESTAMP, active_window_from_packets, packet_at
from tests.test_ipv6_flow import packet_at as ipv6_packet_at
from tests.test_ml_feature_projection import EXPECTED_NAMES


CONTRACT = FeatureContractVersion("flow-feature-snapshot", "1")


def closed_windows(*packets, session="provenance", timeout=timedelta(seconds=5)):
    manager = FlowObservationWindowManager(session, timeout)
    closed = []
    for packet in packets:
        closed.extend(manager.record(packet).closed_windows)
    return tuple(closed) + manager.end_capture_session()


def capture_packets():
    return tuple(sorted(tcp_exchange() + udp_exchange(True) + tcp_exchange(True), key=lambda item: item[0]))


def capture_rows(path, session="capture"):
    windows = []
    source = PcapPacketSource(path)
    run_flow_observation_session(source, capture_session_id=session, inactivity_timeout=timedelta(milliseconds=150),
                                 closed_window_consumer=windows.append)
    if source._file is not None:
        raise AssertionError("capture file must be closed")
    snapshots = tuple(map(extract_flow_feature_snapshot, windows))
    return tuple((snapshot.provenance, project_flow_features(snapshot).values) for snapshot in snapshots)


def replay_digest():
    with TemporaryDirectory() as directory:
        path = Path(directory) / "provenance.pcap"
        path.write_bytes(pcap_bytes(capture_packets()))
        rows = capture_rows(path, "replay-alpha") + capture_rows(path, "replay-beta")
    return sha256(repr(rows).encode()).hexdigest()


def provenance(**changes):
    values = dict(
        feature_contract=CONTRACT,
        window_key=FlowObservationWindowKey("provenance", 0),
        flow_identity=flow_identity_from_packet(packet_at(0)),
        closure_reason=FlowObservationWindowClosureReason.CAPTURE_SESSION_END,
        first_captured_at=TIMESTAMP,
        last_captured_at=TIMESTAMP + timedelta(seconds=2),
    )
    values.update(changes)
    return FlowFeatureProvenance(**values)


class FlowFeatureProvenanceTests(unittest.TestCase):
    def test_snapshot_provenance_identifies_contract_window_flow_and_horizon(self):
        window, = closed_windows(packet_at(0), packet_at(2, True), packet_at(3))
        snapshot = extract_flow_feature_snapshot(window)
        value = snapshot.provenance
        self.assertEqual(tuple(field.name for field in fields(value)), (
            "feature_contract", "window_key", "flow_identity", "closure_reason",
            "first_captured_at", "last_captured_at",
        ))
        self.assertEqual(value.feature_contract, snapshot.feature_contract)
        self.assertIs(value.window_key, window.key)
        self.assertIs(value.flow_identity, window.identity)
        self.assertIs(value.closure_reason, FlowObservationWindowClosureReason.CAPTURE_SESSION_END)
        self.assertEqual((value.first_captured_at, value.last_captured_at),
                         (TIMESTAMP, TIMESTAMP + timedelta(seconds=3)))
        self.assertEqual(value, flow_feature_provenance_from_window(window, CONTRACT))
        self.assertEqual(value, extract_flow_feature_snapshot(window).provenance)
        self.assertEqual(hash(value), hash(snapshot.provenance))
        self.assertNotIn("provenance", tuple(field.name for field in fields(snapshot)))
        with self.assertRaises(FrozenInstanceError):
            value.window_key = FlowObservationWindowKey("other", 1)

    def test_active_snapshots_record_open_scope_and_their_own_horizon(self):
        manager, early = active_window_from_packets(packet_at(0))
        late = manager.record(packet_at(4)).active_window
        first, second = (extract_flow_feature_snapshot(window).provenance for window in (early, late))
        self.assertIsNone(first.closure_reason)
        self.assertEqual(first.window_key, second.window_key)
        self.assertEqual(first.flow_identity, second.flow_identity)
        self.assertEqual(first.last_captured_at, TIMESTAMP)
        self.assertEqual(second.last_captured_at, TIMESTAMP + timedelta(seconds=4))
        self.assertNotEqual(first, second)
        closed, = manager.end_capture_session()
        self.assertNotEqual(extract_flow_feature_snapshot(closed).provenance, second)

    def test_packet_order_and_direction_do_not_change_flow_identity(self):
        pairs = [tuple(closed_windows(packet_at(0, first), packet_at(1, not first))[0] for first in (False, True))]
        for protocol in (6, 17):
            pairs.append(tuple(
                closed_windows(ipv6_packet_at(protocol, 0, first), ipv6_packet_at(protocol, 1, not first))[0]
                for first in (False, True)
            ))
        for windows in pairs:
            first, second = (extract_flow_feature_snapshot(window).provenance for window in windows)
            self.assertEqual(first.flow_identity, second.flow_identity)
            self.assertEqual(first.window_key, second.window_key)
            self.assertEqual(first, second)

    def test_identical_tuples_in_independent_scopes_remain_distinct(self):
        packets = (packet_at(0), packet_at(1, True))
        alpha, = closed_windows(*packets, session="alpha")
        beta, = closed_windows(*packets, session="beta")
        first, second = (extract_flow_feature_snapshot(window).provenance for window in (alpha, beta))
        self.assertEqual(project_flow_features(extract_flow_feature_snapshot(alpha)),
                         project_flow_features(extract_flow_feature_snapshot(beta)))
        self.assertEqual(first.flow_identity, second.flow_identity)
        self.assertEqual((first.window_key.capture_session_id, second.window_key.capture_session_id), ("alpha", "beta"))
        self.assertNotEqual(first, second)

    def test_expired_and_evicted_windows_never_share_provenance_with_successors(self):
        expired, renewed = closed_windows(packet_at(0), packet_at(10))
        old, new = (extract_flow_feature_snapshot(window).provenance for window in (expired, renewed))
        self.assertEqual(old.flow_identity, new.flow_identity)
        self.assertEqual((old.window_key.sequence_number, new.window_key.sequence_number), (0, 1))
        self.assertIs(old.closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
        self.assertEqual((old.first_captured_at, old.last_captured_at), (TIMESTAMP, TIMESTAMP))
        self.assertEqual(new.first_captured_at, TIMESTAMP + timedelta(seconds=10))
        manager = FlowObservationWindowManager("capacity", timedelta.max, max_active_windows=1)
        manager.record(packet_at(0))
        other = replace(packet_at(1), udp=replace(packet_at(1).udp, source_port=23456))
        evicted, = manager.record(other).closed_windows
        returning, = manager.record(packet_at(2)).closed_windows
        tail = manager.end_capture_session()
        values = tuple(extract_flow_feature_snapshot(window).provenance for window in (evicted, returning) + tail)
        self.assertEqual(tuple(value.window_key.sequence_number for value in values), (0, 1, 2))
        self.assertEqual(tuple(value.closure_reason for value in values), (
            FlowObservationWindowClosureReason.CAPACITY,
            FlowObservationWindowClosureReason.CAPACITY,
            FlowObservationWindowClosureReason.CAPTURE_SESSION_END,
        ))
        self.assertEqual(values[0].flow_identity, values[2].flow_identity)
        self.assertNotEqual(values[0].flow_identity, values[1].flow_identity)
        self.assertEqual(values[2].first_captured_at, TIMESTAMP + timedelta(seconds=2))

    def test_ipv4_and_ipv6_provenance_keep_address_families_distinct(self):
        ipv4, = closed_windows(packet_at(0))
        ipv6, = closed_windows(ipv6_packet_at(17, 0))
        first, second = (extract_flow_feature_snapshot(window).provenance for window in (ipv4, ipv6))
        self.assertEqual((first.flow_identity.ip_version, second.flow_identity.ip_version), (4, 6))
        self.assertEqual((len(first.flow_identity.source_address), len(second.flow_identity.source_address)), (4, 16))
        self.assertNotEqual(first, second)

    def test_provenance_never_enters_numerical_projection(self):
        window, = closed_windows(packet_at(0), packet_at(2, True))
        snapshot = extract_flow_feature_snapshot(window)
        projection = project_flow_features(snapshot)
        self.assertEqual(projection.feature_names, EXPECTED_NAMES)
        self.assertEqual(len(projection.values), 49)
        self.assertEqual(tuple(field.name for field in fields(projection)), ("feature_contract", "values"))
        for value in projection.values:
            self.assertIn(type(value), (int, float, type(None)))
        self.assertFalse(hasattr(projection, "provenance"))
        self.assertEqual(snapshot.provenance.feature_contract, projection.feature_contract)

    def test_invalid_fields_are_rejected(self):
        identity = flow_identity_from_packet(packet_at(0))
        for name, value in (
            ("feature_contract", ("flow-feature-snapshot", "1")),
            ("window_key", ("provenance", 0)),
            ("flow_identity", (identity.source_address, identity.destination_address)),
            ("closure_reason", "capture_session_end"),
            ("first_captured_at", TIMESTAMP.replace(tzinfo=None)),
            ("last_captured_at", "2026-09-07T12:00:02Z"),
            ("first_captured_at", TIMESTAMP.date()),
        ):
            with self.subTest(name=name, value=value), self.assertRaises(TypeError):
                provenance(**{name: value})
        offset = timezone(timedelta(hours=5, minutes=30))
        for changes in (
            {"first_captured_at": datetime(2026, 9, 7, 17, 30, tzinfo=offset)},
            {"first_captured_at": TIMESTAMP + timedelta(seconds=3)},
        ):
            with self.subTest(changes=changes), self.assertRaises(FlowFeatureProvenanceError):
                provenance(**changes)
        self.assertTrue(issubclass(FlowFeatureProvenanceError, ValueError))
        self.assertEqual(provenance(last_captured_at=TIMESTAMP).last_captured_at, TIMESTAMP)
        self.assertIsNone(provenance(closure_reason=None).closure_reason)
        with self.assertRaises(TypeError):
            flow_feature_provenance_from_window(extract_flow_feature_snapshot(closed_windows(packet_at(0))[0]), CONTRACT)

    def test_capture_sessions_match_across_all_classic_pcap_encodings(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "provenance.pcap"
            path.write_bytes(pcap_bytes(capture_packets()))
            expected = capture_rows(path)
            for order in ("<", ">"):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(capture_packets(), order, nano))
                        self.assertEqual(capture_rows(path), expected)
        keys = tuple(value.window_key for value, _ in expected)
        self.assertEqual(sorted(key.sequence_number for key in keys), list(range(len(keys))))
        self.assertEqual({key.capture_session_id for key in keys}, {"capture"})
        self.assertEqual({(value.flow_identity.ip_version, value.flow_identity.protocol) for value, _ in expected},
                         {(4, 6), (6, 6), (6, 17)})
        self.assertIn(FlowObservationWindowClosureReason.INACTIVITY, {value.closure_reason for value, _ in expected})
        self.assertIn(FlowObservationWindowClosureReason.CAPTURE_SESSION_END, {value.closure_reason for value, _ in expected})
        for value, values in expected:
            self.assertEqual(len(values), 49)
            self.assertLessEqual(value.first_captured_at, value.last_captured_at)

    def test_established_seed_timezone_replay_matrix(self):
        expected = replay_digest()
        script = "from tests.test_flow_feature_provenance import replay_digest; print(replay_digest())"
        for seed in ("1", "29", "503"):
            for zone in ("UTC", "Asia/Kolkata", "America/New_York"):
                actual = subprocess.check_output([sys.executable, "-B", "-c", script], cwd=Path(__file__).parents[1],
                                                 env=dict(os.environ, PYTHONHASHSEED=seed, TZ=zone, PYTHONPATH="src"),
                                                 text=True).strip()
                self.assertEqual(actual, expected)


class ResearchExampleProvenanceTests(unittest.TestCase):
    def test_window_context_supplies_matching_provenance(self):
        window, = closed_windows(packet_at(0), packet_at(2, True))
        snapshot = extract_flow_feature_snapshot(window)
        projection = project_flow_features(snapshot)
        derived = research_example_from_window(window, "truth")
        self.assertEqual(derived.provenance, snapshot.provenance)
        self.assertEqual(derived, ResearchExample(projection, "truth", window))
        self.assertEqual(derived, ResearchExample(projection, "truth", window, snapshot.provenance))
        self.assertIsNone(ResearchExample(projection).provenance)

    def test_payload_free_provenance_can_replace_window_context(self):
        window, = closed_windows(packet_at(0), packet_at(2, True))
        snapshot = extract_flow_feature_snapshot(window)
        projection = project_flow_features(snapshot)
        supplied = snapshot.provenance
        example = ResearchExample(projection, provenance=supplied)
        self.assertIsNone(example.observation_window)
        self.assertIs(example.provenance, supplied)
        self.assertNotEqual(example, ResearchExample(projection))
        other, = closed_windows(packet_at(0), packet_at(2, True), session="other")
        moved = ResearchExample(projection, provenance=extract_flow_feature_snapshot(other).provenance)
        self.assertNotEqual(ResearchDataset((example,)), ResearchDataset((moved,)))

    def test_mismatched_schema_or_window_is_rejected(self):
        window, = closed_windows(packet_at(0), packet_at(2, True))
        other, = closed_windows(packet_at(0), packet_at(2, True), session="other")
        snapshot = extract_flow_feature_snapshot(window)
        projection = project_flow_features(snapshot)
        for value in (
            replace(snapshot.provenance, feature_contract=FeatureContractVersion("flow-feature-snapshot", "2")),
            replace(snapshot.provenance, feature_contract=FeatureContractVersion("other", "1")),
        ):
            with self.subTest(contract=value.feature_contract), self.assertRaisesRegex(ValueError, "feature contract"):
                ResearchExample(projection, provenance=value)
        for value in (
            extract_flow_feature_snapshot(other).provenance,
            replace(snapshot.provenance, closure_reason=None),
            replace(snapshot.provenance, last_captured_at=TIMESTAMP + timedelta(seconds=3)),
            replace(snapshot.provenance, flow_identity=FlowIdentity(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x03", 12345, 443, 17)),
        ):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "observation window"):
                ResearchExample(projection, None, window, value)
        example = ResearchExample(projection, None, window)
        with self.assertRaisesRegex(ValueError, "observation window"):
            replace(example, observation_window=other)
        for value in (object(), (), snapshot):
            with self.subTest(value=type(value)), self.assertRaises(TypeError):
                ResearchExample(projection, provenance=value)


if __name__ == "__main__":
    unittest.main()
