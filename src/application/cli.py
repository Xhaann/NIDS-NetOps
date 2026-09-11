import argparse
from datetime import timedelta
import json
import sys
from typing import Optional, Sequence

from application import DetectionPipelineResult, DetectionSession, run_detection_pipeline
from capture import CaptureError, PcapPacketSource
from detection import (
    DetectionFinding,
    FlowVolumeMetric,
    FlowVolumeThresholdConfiguration,
    FlowVolumeThresholdEvidence,
    PacketIntegrityConfiguration,
    PacketIntegrityEvidence,
    TCPControlMetric,
    TCPControlThresholdConfiguration,
    TCPControlThresholdEvidence,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nids-netops", allow_abbrev=False,
                                     description="Execute the NIDS detection pipeline on a local classic PCAP file.")
    parser.add_argument("pcap", help="local classic PCAP input path")
    parser.add_argument("--capture-session-id", required=True)
    parser.add_argument("--inactivity-timeout-microseconds", required=True, type=int)
    for prefix in ("packet", "volume", "tcp"):
        parser.add_argument(f"--{prefix}-detector-id", required=True)
        parser.add_argument(f"--{prefix}-detector-version", required=True)
    parser.add_argument("--volume-metric", required=True, choices=[metric.value for metric in FlowVolumeMetric])
    parser.add_argument("--volume-threshold", required=True)
    parser.add_argument("--tcp-metric", required=True, choices=[metric.value for metric in TCPControlMetric])
    parser.add_argument("--tcp-threshold", required=True, type=int)
    return parser


def _finding_json(finding: DetectionFinding) -> dict:
    evidence = finding.raw_evidence
    if type(evidence) is PacketIntegrityEvidence:
        raw_evidence = {
            "captured_at": evidence.captured_at.isoformat(timespec="microseconds"),
            "capture_source": evidence.capture_source.identifier,
            "link_type": None if evidence.link_type is None else evidence.link_type.value,
            "captured_length": evidence.captured_length,
            "original_length": evidence.original_length,
            "protocol": evidence.protocol,
            "failure_classification": None if evidence.failure_classification is None else evidence.failure_classification.value,
            "failure_description": evidence.failure_description,
        }
    elif type(evidence) in (FlowVolumeThresholdEvidence, TCPControlThresholdEvidence):
        identity = evidence.identity
        raw_evidence = {
            "capture_session_id": evidence.capture_session_id,
            "sequence_number": evidence.sequence_number,
            "closure_reason": evidence.closure_reason.value,
            "identity": {
                "ip_version": identity.ip_version,
                "source_address": identity.source_address.hex(),
                "destination_address": identity.destination_address.hex(),
                "source_port": identity.source_port,
                "destination_port": identity.destination_port,
                "protocol": identity.protocol,
            },
            "first_captured_at": evidence.first_captured_at.isoformat(timespec="microseconds"),
            "last_captured_at": evidence.last_captured_at.isoformat(timespec="microseconds"),
            "selected_metric": evidence.selected_metric.value,
            "threshold": evidence.threshold,
            "observed_value": evidence.observed_value,
            "comparison_operator": evidence.comparison_operator.value,
            "total_packet_count": evidence.total_packet_count,
            "forward_packet_count": evidence.forward_packet_count,
            "reverse_packet_count": evidence.reverse_packet_count,
        }
        if type(evidence) is FlowVolumeThresholdEvidence:
            raw_evidence["captured_byte_total"] = evidence.captured_byte_total
            raw_evidence["original_byte_total"] = evidence.original_byte_total
    else:
        raise TypeError("unsupported finding evidence for CLI output")
    return {
        "detector_id": finding.detector_id,
        "detector_version": finding.detector_version,
        "decision": finding.decision.value,
        "raw_evidence": raw_evidence,
        "security_interpretation": finding.security_interpretation.value,
    }


def _result_json(result: DetectionPipelineResult) -> str:
    return json.dumps({
        "packet_findings": [_finding_json(finding) for finding in result.packet_findings],
        "flow_findings": [_finding_json(finding) for finding in result.flow_findings],
    }, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if not args.capture_session_id.strip():
            raise ValueError("capture session ID must not be blank")
        if args.inactivity_timeout_microseconds <= 0:
            raise ValueError("inactivity timeout must be positive")
        timeout = timedelta(microseconds=args.inactivity_timeout_microseconds)
        metric = FlowVolumeMetric(args.volume_metric)
        rate_metrics = (FlowVolumeMetric.PACKETS_PER_SECOND, FlowVolumeMetric.CAPTURED_BYTES_PER_SECOND,
                        FlowVolumeMetric.ORIGINAL_BYTES_PER_SECOND)
        threshold = float(args.volume_threshold) if metric in rate_metrics else int(args.volume_threshold)
        session = DetectionSession(
            PacketIntegrityConfiguration(args.packet_detector_id, args.packet_detector_version),
            FlowVolumeThresholdConfiguration(args.volume_detector_id, args.volume_detector_version, metric, threshold),
            TCPControlThresholdConfiguration(args.tcp_detector_id, args.tcp_detector_version,
                                             TCPControlMetric(args.tcp_metric), args.tcp_threshold),
        )
    except (ValueError, OverflowError) as error:
        parser.error(str(error))
    source = PcapPacketSource(args.pcap)
    try:
        result = run_detection_pipeline(source, detection_session=session,
                                        capture_session_id=args.capture_session_id, inactivity_timeout=timeout)
    except CaptureError:
        sys.stderr.write('{"error":"capture_error"}\n')
        return 1
    sys.stdout.write(_result_json(result))
    return 0
