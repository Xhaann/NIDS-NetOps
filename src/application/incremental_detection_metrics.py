from application.detection_evaluation import DetectionEvaluationEntry, FlowDetectionIdentity, PacketDetectionIdentity
from application.detection_metrics import DetectionEvaluationMetrics, _MetricCounts
from detection.packet_integrity import PacketIntegrityEvidence


class IncrementalDetectionMetrics:
    def __init__(self) -> None:
        self._packets = _MetricCounts()
        self._flows = _MetricCounts()
        self._state = "open"
        self._result = None

    @property
    def finished(self) -> bool:
        return self._state == "finished"

    def _begin(self) -> None:
        if self._state != "open":
            raise ValueError("metrics must be open and idle")
        self._state = "busy"

    def _record(self, entry: DetectionEvaluationEntry, packet: bool) -> None:
        self._begin()
        try:
            if type(entry) is not DetectionEvaluationEntry:
                raise TypeError("entry must be exactly a DetectionEvaluationEntry")
            identity_type = PacketDetectionIdentity if packet else FlowDetectionIdentity
            if entry.expectation is not None and type(entry.expectation.identity) is not identity_type:
                raise ValueError("entry expectation belongs to the other finding channel")
            if entry.finding is not None:
                is_packet = type(entry.finding.raw_evidence) is PacketIntegrityEvidence
                if is_packet != packet:
                    raise ValueError("entry finding belongs to the other finding channel")
            (self._packets if packet else self._flows).record(entry)
        except BaseException:
            self._state = "failed"
            raise
        self._state = "open"

    def record_packet(self, entry: DetectionEvaluationEntry) -> None:
        self._record(entry, True)

    def record_flow(self, entry: DetectionEvaluationEntry) -> None:
        self._record(entry, False)

    def finish(self) -> DetectionEvaluationMetrics:
        if self.finished:
            return self._result
        self._begin()
        try:
            result = DetectionEvaluationMetrics(self._packets.finish(), self._flows.finish())
        except BaseException:
            self._state = "failed"
            raise
        self._result = result
        self._state = "finished"
        return result

    def abort(self) -> None:
        if self._state not in ("open", "failed"):
            raise ValueError("only idle unfinished metrics can be aborted")
        self._state = "failed"
