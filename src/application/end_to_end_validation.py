from dataclasses import dataclass
from typing import Optional

from application.detection_configuration import DetectionConfiguration
from application.detection_evaluation import DetectionEvaluationResult, ExpectedDetection, ExpectedDetectionResult, evaluate_detection_result
from application.detection_experiment import DetectionExperiment
from application.detection_metrics import calculate_detection_metrics
from application.detection_pipeline import DetectionPipelineResult, run_detection_pipeline
from application.detection_session import DetectionSession
from application.evaluation_report import EvaluationReport
from application.ground_truth import GroundTruth, GroundTruthPolarity
from capture.packet_source import PacketSource


@dataclass(frozen=True)
class EndToEndValidationResult:
    pipeline_result: DetectionPipelineResult
    ground_truth: GroundTruth
    report: EvaluationReport

    def __post_init__(self) -> None:
        if type(self.pipeline_result) is not DetectionPipelineResult:
            raise TypeError("pipeline_result must be exactly a DetectionPipelineResult")
        if type(self.ground_truth) is not GroundTruth:
            raise TypeError("ground_truth must be exactly a GroundTruth")
        if type(self.report) is not EvaluationReport:
            raise TypeError("report must be exactly an EvaluationReport")
        if type(self.report.result) is not DetectionEvaluationResult:
            raise ValueError("validation report must contain a standalone evaluation result")
        if self.report.metrics is None or self.report.configuration is None:
            raise ValueError("validation report must retain metrics and configuration")


def run_end_to_end_validation(
    source: PacketSource,
    *,
    configuration: DetectionConfiguration,
    capture_session_id: str,
    ground_truth: GroundTruth,
    experiment: Optional[DetectionExperiment] = None,
) -> EndToEndValidationResult:
    if type(configuration) is not DetectionConfiguration:
        raise TypeError("configuration must be exactly a DetectionConfiguration")
    if type(ground_truth) is not GroundTruth:
        raise TypeError("ground_truth must be exactly a GroundTruth")
    if experiment is not None and type(experiment) is not DetectionExperiment:
        raise TypeError("experiment must be exactly a DetectionExperiment or None")
    expectations = ExpectedDetectionResult(
        tuple(ExpectedDetection(record.target, record.polarity is GroundTruthPolarity.POSITIVE)
              for record in ground_truth.packet_records),
        tuple(ExpectedDetection(record.target, record.polarity is GroundTruthPolarity.POSITIVE)
              for record in ground_truth.flow_records),
    )
    session = DetectionSession(configuration.packet_configuration, configuration.flow_volume_configuration,
                               configuration.tcp_control_configuration)
    pipeline_result = run_detection_pipeline(
        source, detection_session=session, capture_session_id=capture_session_id,
        inactivity_timeout=configuration.inactivity_timeout,
        max_active_windows=configuration.max_active_windows,
    )
    evaluation = evaluate_detection_result(pipeline_result, expectations)
    metrics = calculate_detection_metrics(evaluation)
    report = EvaluationReport(evaluation, metrics, experiment, configuration)
    return EndToEndValidationResult(pipeline_result, ground_truth, report)
