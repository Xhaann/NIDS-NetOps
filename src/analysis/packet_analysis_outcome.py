from dataclasses import dataclass
from enum import Enum
from typing import Optional

from analysis.ethernet import EthernetDecodeError
from analysis.icmp import ICMPDecodeError
from analysis.ipv4 import IPv4DecodeError
from analysis.ipv6 import IPv6DecodeError
from analysis.packet_analysis import PacketAnalysis, PacketAnalysisError, analyze_packet
from analysis.tcp import TCPDecodeError
from analysis.udp import UDPDecodeError
from capture.packet_observation import PacketObservation


class PacketAnalysisOutcomeError(ValueError):
    pass


class PacketAnalysisFailureClassification(Enum):
    STRUCTURAL_FAILURE = "structural_failure"
    UNSUPPORTED = "unsupported"
    INCOMPLETE = "incomplete"
    INTEGRITY_FAILURE = "integrity_failure"


@dataclass(frozen=True)
class PacketAnalysisOutcome:
    observation: PacketObservation
    analysis: Optional[PacketAnalysis]
    failure_classification: Optional[PacketAnalysisFailureClassification]
    failure_description: Optional[str]

    def __post_init__(self) -> None:
        if type(self.observation) is not PacketObservation:
            raise TypeError("observation must be exactly a PacketObservation")
        if self.analysis is not None:
            if type(self.analysis) is not PacketAnalysis:
                raise TypeError("analysis must be exactly a PacketAnalysis or None")
            if self.analysis.observation is not self.observation:
                raise PacketAnalysisOutcomeError(
                    "analysis must retain the exact outcome observation"
                )
            if self.failure_classification is not None:
                raise PacketAnalysisOutcomeError(
                    "successful outcome must not have a failure classification"
                )
            if self.failure_description is not None:
                raise PacketAnalysisOutcomeError(
                    "successful outcome must not have a failure description"
                )
            return
        if self.failure_classification is None:
            raise PacketAnalysisOutcomeError(
                "failed outcome must have exactly one failure classification"
            )
        if type(self.failure_classification) is not PacketAnalysisFailureClassification:
            raise TypeError(
                "failure_classification must be exactly a "
                "PacketAnalysisFailureClassification"
            )
        if type(self.failure_description) is not str:
            raise TypeError("failure_description must be exactly a string on failure")
        if not self.failure_description.strip():
            raise PacketAnalysisOutcomeError(
                "failure_description must not be blank on failure"
            )

    @property
    def succeeded(self) -> bool:
        return self.analysis is not None


_PACKET_ANALYSIS_UNSUPPORTED_MESSAGES = (
    "Packet analysis requires Ethernet LinkType(1)",
    "Packet analysis requires IPv4 EtherType 0x0800 or IPv6 EtherType 0x86DD",
)

_ETHERNET_UNSUPPORTED_MESSAGES = (
    "Ethernet decoding requires LinkType(1)",
)

_IPV4_UNSUPPORTED_MESSAGES = (
    "IPv4 decoding requires EtherType 0x0800",
)

_IPV6_UNSUPPORTED_MESSAGES = (
    "IPv6 decoding requires EtherType 0x86DD",
    "ICMPv6 decoding requires terminal Next Header 58",
    "ICMPv6 decoding requires an unfragmented or whole-datagram packet",
)

_TCP_UNSUPPORTED_MESSAGES = (
    "TCP decoding requires IPv4 protocol 6",
    "TCP decoding requires an initial IPv4 fragment",
    "TCP decoding requires terminal IPv6 Next Header 6",
    "TCP decoding requires an initial IPv6 fragment",
)

_UDP_UNSUPPORTED_MESSAGES = (
    "UDP decoding requires IPv4 protocol 17",
    "UDP decoding requires an initial IPv4 fragment",
    "UDP decoding requires terminal IPv6 Next Header 17",
    "UDP decoding requires an initial IPv6 fragment",
)

_ICMP_UNSUPPORTED_MESSAGES = (
    "ICMP decoding requires IPv4 protocol 1",
    "ICMP decoding requires an initial IPv4 fragment",
)

_IPV4_INCOMPLETE_MESSAGES = (
    "IPv4 header is too short: expected at least 20 bytes",
    "IPv4 header length exceeds available bytes",
    "IPv4 total length exceeds available bytes",
)

_IPV6_INCOMPLETE_MESSAGES = (
    "IPv6 header is too short: expected at least 40 bytes",
    "IPv6 payload length exceeds available bytes",
    "IPv6 extension header prefix exceeds available IPv6 payload",
    "IPv6 extension header length exceeds available IPv6 payload",
    "ICMPv6 header is too short: expected at least 4 bytes",
)

_TCP_INCOMPLETE_MESSAGES = (
    "TCP header is too short: expected at least 20 bytes",
    "TCP header length exceeds available IPv4 payload",
    "TCP header length exceeds available IPv6 payload",
)

_UDP_INCOMPLETE_MESSAGES = (
    "UDP header is too short: expected at least 8 bytes",
    "UDP length exceeds available IPv4 payload",
    "UDP length exceeds available IPv6 payload",
)

_ICMP_INCOMPLETE_MESSAGES = (
    "ICMP header is too short: expected at least 8 bytes",
)

_IPV4_STRUCTURAL_MESSAGES = (
    "IPv4 option padding must be zero",
    "IPv4 option length field exceeds option area",
    "IPv4 option length must be at least 2 bytes",
    "IPv4 option length exceeds option area",
    "IPv4 version must be 4",
    "IPv4 IHL must be at least 5",
    "IPv4 total length is smaller than header length",
)

_IPV6_STRUCTURAL_MESSAGES = (
    "IPv6 version must be 6",
)

_TCP_STRUCTURAL_MESSAGES = (
    "TCP option padding must be zero",
    "TCP option length field exceeds option area",
    "TCP option length must be at least 2 bytes",
    "TCP option length exceeds option area",
    "TCP data offset must be at least 5",
)

_UDP_STRUCTURAL_MESSAGES = (
    "UDP length must be at least 8 bytes",
)


def _classify_known_failure(
    error: ValueError,
) -> Optional[PacketAnalysisFailureClassification]:
    message = str(error)
    unsupported = (
        (PacketAnalysisError, _PACKET_ANALYSIS_UNSUPPORTED_MESSAGES),
        (EthernetDecodeError, _ETHERNET_UNSUPPORTED_MESSAGES),
        (IPv4DecodeError, _IPV4_UNSUPPORTED_MESSAGES),
        (IPv6DecodeError, _IPV6_UNSUPPORTED_MESSAGES),
        (TCPDecodeError, _TCP_UNSUPPORTED_MESSAGES),
        (UDPDecodeError, _UDP_UNSUPPORTED_MESSAGES),
        (ICMPDecodeError, _ICMP_UNSUPPORTED_MESSAGES),
    )
    incomplete = (
        (IPv4DecodeError, _IPV4_INCOMPLETE_MESSAGES),
        (IPv6DecodeError, _IPV6_INCOMPLETE_MESSAGES),
        (TCPDecodeError, _TCP_INCOMPLETE_MESSAGES),
        (UDPDecodeError, _UDP_INCOMPLETE_MESSAGES),
        (ICMPDecodeError, _ICMP_INCOMPLETE_MESSAGES),
    )
    structural = (
        (IPv4DecodeError, _IPV4_STRUCTURAL_MESSAGES),
        (IPv6DecodeError, _IPV6_STRUCTURAL_MESSAGES),
        (TCPDecodeError, _TCP_STRUCTURAL_MESSAGES),
        (UDPDecodeError, _UDP_STRUCTURAL_MESSAGES),
    )
    if any(type(error) is error_type and message in messages for error_type, messages in unsupported):
        return PacketAnalysisFailureClassification.UNSUPPORTED
    if any(type(error) is error_type and message in messages for error_type, messages in incomplete):
        return PacketAnalysisFailureClassification.INCOMPLETE
    if any(type(error) is error_type and message in messages for error_type, messages in structural):
        return PacketAnalysisFailureClassification.STRUCTURAL_FAILURE
    if type(error) is EthernetDecodeError and message.startswith(
        "Ethernet frame is too short: expected at least 14 bytes, got "
    ):
        return PacketAnalysisFailureClassification.INCOMPLETE
    return None


def _integrity_failure_description(analysis: PacketAnalysis) -> Optional[str]:
    failed_layers = []
    if analysis.ipv4_checksum_valid is False:
        failed_layers.append("IPv4")
    if analysis.tcp_checksum_valid is False:
        failed_layers.append("TCP")
    if (
        analysis.udp_checksum_valid is False
        and analysis.udp is not None
        and analysis.udp.checksum != 0
    ):
        failed_layers.append("UDP")
    if analysis.icmp_checksum_valid is False:
        failed_layers.append("ICMPv4")
    if not failed_layers:
        return None
    return "Checksum validation failed for " + ", ".join(failed_layers)


def analyze_packet_outcome(observation: PacketObservation) -> PacketAnalysisOutcome:
    if type(observation) is not PacketObservation:
        raise TypeError("observation must be exactly a PacketObservation")
    try:
        analysis = analyze_packet(observation)
    except (
        PacketAnalysisError,
        EthernetDecodeError,
        IPv4DecodeError,
        IPv6DecodeError,
        TCPDecodeError,
        UDPDecodeError,
        ICMPDecodeError,
    ) as error:
        classification = _classify_known_failure(error)
        if classification is None:
            raise
        return PacketAnalysisOutcome(
            observation=observation,
            analysis=None,
            failure_classification=classification,
            failure_description=str(error),
        )
    failure_description = _integrity_failure_description(analysis)
    if failure_description is not None:
        return PacketAnalysisOutcome(
            observation=observation,
            analysis=None,
            failure_classification=PacketAnalysisFailureClassification.INTEGRITY_FAILURE,
            failure_description=failure_description,
        )
    return PacketAnalysisOutcome(
        observation=observation,
        analysis=analysis,
        failure_classification=None,
        failure_description=None,
    )
