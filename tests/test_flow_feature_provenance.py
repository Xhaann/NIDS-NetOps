import gc
import os
import subprocess
import sys
import unittest
import weakref
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
        alpha, = closed_windows(packet_at(0), packet_at(2, True), session="alpha")
        beta, = closed_windows(packet_at(0), packet_at(2, True), session="beta")
        first, second = (project_flow_features(extract_flow_feature_snapshot(window)) for window in (alpha, beta))
        for projection, window in ((first, alpha), (second, beta)):
            self.assertEqual(projection.feature_names, EXPECTED_NAMES)
            self.assertEqual(len(projection.values), 49)
            for value in projection.values:
                self.assertIn(type(value), (int, float, type(None)))
            self.assertEqual(projection.provenance, flow_feature_provenance_from_window(window, CONTRACT))
            self.assertNotIn("provenance", repr(projection))
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertNotEqual(first.provenance, second.provenance)
        self.assertEqual(tuple(field.name for field in fields(first) if field.compare), ("feature_contract", "values"))

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
    def setUp(self):
        self.window, = closed_windows(packet_at(0), packet_at(2, True), session="alpha")
        self.other, = closed_windows(packet_at(0), packet_at(2, True), session="beta")
        self.snapshot = extract_flow_feature_snapshot(self.window)
        self.projection = project_flow_features(self.snapshot)
        self.example = ResearchExample(self.projection, "truth", self.window)

    def test_window_context_supplies_the_projection_source_provenance(self):
        derived = research_example_from_window(self.window, "truth")
        self.assertEqual(derived.provenance, self.snapshot.provenance)
        self.assertEqual(derived.provenance, derived.projection.provenance)
        self.assertEqual(derived, self.example)
        self.assertIs(self.example.provenance, self.projection.provenance)
        self.assertEqual(derived, ResearchExample(self.projection, "truth", self.window, self.snapshot.provenance))
        self.assertIsNone(ResearchExample(self.projection).provenance)

    def test_projection_from_another_window_cannot_be_attributed_to_it(self):
        expired, renewed = closed_windows(packet_at(0), packet_at(10))
        renewed_projection = project_flow_features(extract_flow_feature_snapshot(renewed))
        manager, active = active_window_from_packets(packet_at(0), packet_at(2, True), capture_session_id="alpha")
        provisional = project_flow_features(extract_flow_feature_snapshot(active))
        closed, = manager.end_capture_session()
        for projection, window in ((self.projection, self.other), (renewed_projection, expired),
                                   (provisional, closed)):
            with self.subTest(window=window.key), self.assertRaisesRegex(ValueError, "projection source window"):
                ResearchExample(projection, None, window)
            with self.subTest(window=window.key), self.assertRaisesRegex(ValueError, "projection source provenance"):
                ResearchExample(projection, provenance=flow_feature_provenance_from_window(window, CONTRACT))
        self.assertEqual(ResearchExample(provisional, provenance=provisional.provenance).provenance.closure_reason, None)

    def test_replace_cannot_relabel_a_projection(self):
        other = flow_feature_provenance_from_window(self.other, CONTRACT)
        for changes in (
            {"observation_window": self.other},
            {"provenance": None, "observation_window": self.other},
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "projection source window"):
                replace(self.example, **changes)
        for changes in (
            {"provenance": other},
            {"provenance": other, "observation_window": None},
            {"provenance": replace(other, window_key=self.window.key, closure_reason=None)},
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "projection source provenance"):
                replace(self.example, **changes)
        with self.assertRaises(TypeError):
            replace(self.projection, provenance=other)

    def test_supported_replacements_keep_the_verified_source(self):
        detached = replace(self.example, observation_window=None)
        self.assertIsNone(detached.observation_window)
        self.assertIs(detached.provenance, self.projection.provenance)
        self.assertEqual(replace(self.example), self.example)
        self.assertEqual(replace(self.example, provenance=None), self.example)
        self.assertEqual(replace(detached, observation_window=self.window), self.example)
        self.assertEqual(replace(self.example, ground_truth="other").provenance, self.example.provenance)
        unassociated = replace(self.example, provenance=None, observation_window=None)
        self.assertIsNone(unassociated.provenance)
        self.assertEqual(unassociated, ResearchExample(self.projection, "truth"))
        self.assertNotEqual(detached, unassociated)
        with self.assertRaises(FrozenInstanceError):
            detached.provenance = None

    def test_schema_and_type_mismatches_are_rejected(self):
        for contract in (FeatureContractVersion("flow-feature-snapshot", "2"), FeatureContractVersion("other", "1")):
            value = replace(self.projection.provenance, feature_contract=contract)
            with self.subTest(contract=contract), self.assertRaisesRegex(ValueError, "feature contract"):
                ResearchExample(self.projection, provenance=value)
        for value in (object(), (), self.snapshot):
            with self.subTest(value=type(value)), self.assertRaises(TypeError):
                ResearchExample(self.projection, provenance=value)
        unbound = object.__new__(type(self.projection))
        object.__setattr__(unbound, "feature_contract", self.projection.feature_contract)
        object.__setattr__(unbound, "values", self.projection.values)
        with self.assertRaisesRegex(TypeError, "projection provenance"):
            ResearchExample(unbound)

    def test_provenance_only_examples_release_windows_and_capture_state(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "provenance.pcap"
            path.write_bytes(pcap_bytes(capture_packets()))
            collected = []
            source = PcapPacketSource(path)
            run_flow_observation_session(source, capture_session_id="release", inactivity_timeout=timedelta(seconds=60),
                                         closed_window_consumer=collected.append)
        tcp = next(window for window in collected if window.coordinated_state.tcp_stream_state is not None)
        stream = tcp.coordinated_state.tcp_stream_state.forward
        self.assertIn(b"abc", stream.payload)
        snapshot = extract_flow_feature_snapshot(tcp)
        example = ResearchExample(project_flow_features(snapshot), "truth", provenance=snapshot.provenance)
        references = tuple(weakref.ref(value) for value in (tcp, tcp.coordinated_state, stream, snapshot))
        del collected, tcp, stream, snapshot, source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertIsNone(example.observation_window)
        self.assertEqual(example.provenance, example.projection.provenance)
        self.assertEqual(example.provenance.window_key.capture_session_id, "release")

    def test_repeated_construction_retains_no_examples(self):
        references = []
        for _ in range(64):
            example = research_example_from_window(self.window)
            references.append((weakref.ref(example), weakref.ref(example.projection)))
        del example
        gc.collect()
        self.assertTrue(all(first() is None and second() is None for first, second in references))


if __name__ == "__main__":
    unittest.main()
