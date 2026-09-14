import argparse
from datetime import timedelta
from functools import partial
import json
import sys
from typing import Optional, Sequence

from analysis.flow_observation_window import DEFAULT_MAX_ACTIVE_WINDOWS

from application import DetectionPipelineResult, DetectionSession, diagnose_error, run_detection_pipeline
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


class _StoreOnce(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            raise argparse.ArgumentError(self, "must be supplied exactly once")
        setattr(namespace, self.dest, values)


def _integer(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer") from None


def _pcap_path(value: str) -> str:
    if not value.strip() or "\x00" in value:
        raise argparse.ArgumentTypeError("must be a nonblank path without NUL characters")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nids-netops", allow_abbrev=False,
                                     formatter_class=partial(argparse.HelpFormatter, width=100),
                                     description="Execute the NIDS detection pipeline on a local classic PCAP file.",
                                     epilog="Required settings must occur once; optional settings at most once. "
                                            "Output: finding JSON on stdout. "
                                            "Exit 0: completed; 1: capture failure; 2: argument/configuration error. "
                                            "Other execution errors propagate. No live capture or evaluation mode.")
    parser.add_argument("pcap", type=_pcap_path, help="local regular classic PCAP 2.4 input file")
    parser.add_argument("--capture-session-id", required=True, action=_StoreOnce,
                        help="explicit nonblank observation-window session identity")
    parser.add_argument("--inactivity-timeout-microseconds", required=True, type=_integer, action=_StoreOnce,
                        help="positive inactivity interval in integer microseconds")
    parser.add_argument("--max-active-windows", type=_integer, action=_StoreOnce,
                        help=f"positive active-flow limit (default: {DEFAULT_MAX_ACTIVE_WINDOWS}); "
                             "close the least recently observed window at capacity")
    for prefix in ("packet", "volume", "tcp"):
        parser.add_argument(f"--{prefix}-detector-id", required=True, action=_StoreOnce,
                            help="explicit nonblank detector identity")
        parser.add_argument(f"--{prefix}-detector-version", required=True, action=_StoreOnce,
                            help="explicit nonblank detector version; preserved without discovery")
    parser.add_argument("--volume-metric", required=True, action=_StoreOnce,
                        choices=[metric.value for metric in FlowVolumeMetric])
    parser.add_argument("--volume-threshold", required=True, action=_StoreOnce,
                        help="nonnegative integer for counts/bytes; finite nonnegative number for rates")
    parser.add_argument("--tcp-metric", required=True, action=_StoreOnce,
                        choices=[metric.value for metric in TCPControlMetric])
    parser.add_argument("--tcp-threshold", required=True, type=_integer, action=_StoreOnce,
                        help="nonnegative integer; TCP settings are required even for UDP-only input")
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
        max_active_windows = DEFAULT_MAX_ACTIVE_WINDOWS if args.max_active_windows is None else args.max_active_windows
        if max_active_windows < 1:
            raise ValueError("max_active_windows must be positive")
        metric = FlowVolumeMetric(args.volume_metric)
        rate_metrics = (FlowVolumeMetric.PACKETS_PER_SECOND, FlowVolumeMetric.CAPTURED_BYTES_PER_SECOND,
                        FlowVolumeMetric.ORIGINAL_BYTES_PER_SECOND)
        try:
            threshold = float(args.volume_threshold) if metric in rate_metrics else int(args.volume_threshold)
        except ValueError:
            parser.error("--volume-threshold must be a number for rates or an integer for counts/bytes")
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
                                        capture_session_id=args.capture_session_id, inactivity_timeout=timeout,
                                        max_active_windows=max_active_windows)
    except CaptureError as error:
        diagnostic = diagnose_error(error, operation_id="detection-pipeline", message="capture_error")
        sys.stderr.write(json.dumps({"error": diagnostic.message}, separators=(",", ":")) + "\n")
        return 1
    sys.stdout.write(_result_json(result))
    return 0
