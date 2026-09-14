from collections import deque
from typing import Callable

from application.detection_evaluation import (
    DetectionEvaluationEntry, ExpectedDetectionResult, _classification, _indexable_identity, _match_findings,
    detection_identity,
)
from detection.detection_finding import DetectionFinding
from detection.packet_integrity import PacketIntegrityEvidence


class _EvaluationChannel:
    def __init__(self, expectations, consumer, packet):
        self.expectations = expectations
        self.consumer = consumer
        self.packet = packet
        self.used = set()
        self.next_index = 0
        self.pending_findings = []
        self.pending_identities = []
        self.pending_offset = 0
        self.expectation_indices = None
        if all(_indexable_identity(expectation.identity) for expectation in expectations):
            self.expectation_indices = {}
            for index, expectation in enumerate(expectations):
                self.expectation_indices.setdefault(expectation.identity, deque()).append(index)

    def _match_current(self, finding, identity):
        if len(self.used) == len(self.expectations):
            return None
        if self.expectation_indices is None or not _indexable_identity(identity):
            assignments, _ = _match_findings((finding,), self.expectations, (identity,), self.used)
            return assignments.get(0)
        candidates = self.expectation_indices.get(identity)
        while candidates and candidates[0] in self.used:
            candidates.popleft()
        if not candidates:
            return None
        index = candidates[0]
        assignments, _ = _match_findings((finding,), (self.expectations[index],), (identity,))
        return index if 0 in assignments else None

    def record(self, finding):
        if type(finding) is not DetectionFinding:
            raise TypeError("finding must be exactly a DetectionFinding")
        if (type(finding.raw_evidence) is PacketIntegrityEvidence) != self.packet:
            raise ValueError("pipeline finding belongs to the other finding channel")
        identity = detection_identity(finding, packet_index=self.next_index if self.packet else None)
        if self.pending_findings:
            self.pending_findings.append(finding)
            self.pending_identities.append(identity)
            self.next_index += 1
            return
        expected_index = self._match_current(finding, identity)
        expectation = None if expected_index is None else self.expectations[expected_index]
        if not self.packet and expectation is not None and finding.decision.value != (
            "match" if expectation.positive else "no_match"
        ):
            self.pending_findings.append(finding)
            self.pending_identities.append(identity)
            self.next_index += 1
            return
        entry = DetectionEvaluationEntry(_classification(expectation, finding), expected_index,
                                         expectation, self.next_index, finding)
        if expected_index is not None:
            self.used.add(expected_index)
        self.next_index += 1
        self.consumer(entry)

    def finish(self):
        if self.pending_findings:
            assignments, used = _match_findings(
                self.pending_findings, self.expectations, self.pending_identities, self.used,
            )
            offset = self.next_index - len(self.pending_findings)
            self.used = used
            for index in range(len(self.pending_findings)):
                finding = self.pending_findings[index]
                expected_index = assignments.get(index)
                expectation = None if expected_index is None else self.expectations[expected_index]
                entry = DetectionEvaluationEntry(_classification(expectation, finding), expected_index,
                                                 expectation, offset + index, finding)
                self.pending_findings[index] = None
                self.pending_identities[index] = None
                self.pending_offset = index + 1
                self.consumer(entry)
            self.clear_pending()
        for index, expectation in enumerate(self.expectations):
            if index not in self.used:
                self.consumer(DetectionEvaluationEntry(_classification(expectation, None), index,
                                                       expectation, None, None))

    def clear_pending(self):
        self.pending_findings.clear()
        self.pending_identities.clear()
        self.pending_offset = 0


class IncrementalDetectionEvaluator:
    def __init__(
        self, expected: ExpectedDetectionResult, *,
        packet_evaluation_consumer: Callable[[DetectionEvaluationEntry], None],
        flow_evaluation_consumer: Callable[[DetectionEvaluationEntry], None],
    ) -> None:
        if type(expected) is not ExpectedDetectionResult:
            raise TypeError("expected must be exactly an ExpectedDetectionResult")
        for name, consumer in (("packet_evaluation_consumer", packet_evaluation_consumer),
                               ("flow_evaluation_consumer", flow_evaluation_consumer)):
            if not callable(consumer):
                raise TypeError(f"{name} must be callable")
        self._packets = _EvaluationChannel(expected.packet_expectations, packet_evaluation_consumer, True)
        self._flows = _EvaluationChannel(expected.flow_expectations, flow_evaluation_consumer, False)
        self._state = "open"

    @property
    def finished(self) -> bool:
        return self._state == "finished"

    @property
    def pending_flow_count(self) -> int:
        return len(self._flows.pending_findings) - self._flows.pending_offset

    def record_packet(self, finding: DetectionFinding) -> None:
        self._record(self._packets, finding)

    def record_flow(self, finding: DetectionFinding) -> None:
        self._record(self._flows, finding)

    def _begin(self) -> None:
        if self._state != "open":
            raise ValueError("evaluator must be open and idle")
        self._state = "busy"

    def _fail(self) -> None:
        self._state = "failed"
        self._packets.clear_pending()
        self._flows.clear_pending()

    def _record(self, channel: _EvaluationChannel, finding: DetectionFinding) -> None:
        self._begin()
        try:
            channel.record(finding)
        except BaseException:
            self._fail()
            raise
        self._state = "open"

    def finish(self) -> None:
        if self.finished:
            return
        self._begin()
        try:
            self._packets.finish()
            self._flows.finish()
        except BaseException:
            self._fail()
            raise
        self._state = "finished"

    def abort(self) -> None:
        if self._state not in ("open", "failed"):
            raise ValueError("only an idle unfinished evaluator can be aborted")
        self._fail()
