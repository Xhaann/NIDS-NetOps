from application.detection_configuration import DetectionConfiguration
from application.detection_evaluation import ExpectedDetection, ExpectedDetectionResult
from application.detection_metrics import DetectionEvaluationMetrics
from application.detection_pipeline import run_detection_stream
from application.detection_session import DetectionSession
from application.ground_truth import GroundTruth, GroundTruthPolarity
from application.incremental_detection_evaluation import IncrementalDetectionEvaluator
from application.incremental_detection_metrics import IncrementalDetectionMetrics
from capture.packet_source import PacketSource


def run_streaming_evaluation(
    source: PacketSource,
    *,
    configuration: DetectionConfiguration,
    capture_session_id: str,
    ground_truth: GroundTruth,
) -> DetectionEvaluationMetrics:
    if type(configuration) is not DetectionConfiguration:
        raise TypeError("configuration must be exactly a DetectionConfiguration")
    if type(ground_truth) is not GroundTruth:
        raise TypeError("ground_truth must be exactly a GroundTruth")
    expectations = ExpectedDetectionResult(
        tuple(ExpectedDetection(record.target, record.polarity is GroundTruthPolarity.POSITIVE)
              for record in ground_truth.packet_records),
        tuple(ExpectedDetection(record.target, record.polarity is GroundTruthPolarity.POSITIVE)
              for record in ground_truth.flow_records),
    )
    session = DetectionSession(configuration.packet_configuration, configuration.flow_volume_configuration,
                               configuration.tcp_control_configuration)
    metrics = IncrementalDetectionMetrics()
    evaluator = None
    try:
        evaluator = IncrementalDetectionEvaluator(
            expectations,
            packet_evaluation_consumer=metrics.record_packet,
            flow_evaluation_consumer=metrics.record_flow,
        )
        run_detection_stream(
            source,
            detection_session=session,
            capture_session_id=capture_session_id,
            inactivity_timeout=configuration.inactivity_timeout,
            max_active_windows=configuration.max_active_windows,
            packet_finding_consumer=evaluator.record_packet,
            flow_finding_consumer=evaluator.record_flow,
        )
        evaluator.finish()
        return metrics.finish()
    except BaseException:
        metrics.abort()
        if evaluator is not None and not evaluator.finished:
            evaluator.abort()
        raise
