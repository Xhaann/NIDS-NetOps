from dataclasses import dataclass, fields
from typing import Optional

from analysis.flow_identity import FlowIdentity, flow_identity_from_packet
from analysis.ldap import LDAPMessageStatus
from analysis.packet_analysis import PacketAnalysis


@dataclass(frozen=True)
class LDAPFlowStatistics:
    identity: FlowIdentity
    complete_message_count: int = 0
    incomplete_observation_count: int = 0
    malformed_observation_count: int = 0
    unsupported_observation_count: int = 0
    request_count: int = 0
    response_count: int = 0
    limited_payload_count: int = 0

    def __post_init__(self) -> None:
        if type(self.identity) is not FlowIdentity:
            raise TypeError("identity must be exactly a FlowIdentity")
        if self.identity.protocol != 6:
            raise ValueError("LDAP statistics require TCP protocol 6")
        for field in fields(self):
            if field.name == "identity":
                continue
            value = getattr(self, field.name)
            if type(value) is not int:
                raise TypeError(f"{field.name} must be exactly an integer")
            if value < 0:
                raise ValueError(f"{field.name} must not be negative")
        if self.request_count + self.response_count != self.complete_message_count:
            raise ValueError("request and response counts must sum to complete_message_count")


def update_ldap_flow_statistics(
    current: Optional[LDAPFlowStatistics], analysis: PacketAnalysis, identity: FlowIdentity,
) -> Optional[LDAPFlowStatistics]:
    if current is not None and type(current) is not LDAPFlowStatistics:
        raise TypeError("current must be exactly an LDAPFlowStatistics or None")
    if type(analysis) is not PacketAnalysis:
        raise TypeError("analysis must be exactly a PacketAnalysis")
    if type(identity) is not FlowIdentity:
        raise TypeError("identity must be exactly a FlowIdentity")
    if identity.protocol != 6 or flow_identity_from_packet(analysis) != identity:
        raise ValueError("identity must match the TCP analysis")
    if current is not None and current.identity != identity:
        raise ValueError("current identity must match the supplied identity")
    observation = analysis.ldap
    if observation is None:
        return current
    values = {field.name: 0 if current is None else getattr(current, field.name)
              for field in fields(LDAPFlowStatistics) if field.name != "identity"}
    for message in observation.messages:
        if message.status is LDAPMessageStatus.COMPLETE:
            values["complete_message_count"] += 1
            values["request_count" if message.operation.is_request else "response_count"] += 1
        else:
            values[message.status.value + "_observation_count"] += 1
    values["limited_payload_count"] += int(observation.limit_reached)
    return LDAPFlowStatistics(identity if current is None else current.identity, **values)
