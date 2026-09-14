from dataclasses import dataclass
from enum import Enum
from typing import Optional

from analysis.flow_direction import FlowDirection
from analysis.flow_identity import FlowIdentity
from analysis.ldap import LDAPMessageObservation


class LDAPRequestSummaryStatus(Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, init=False)
class LDAPRequestSummary:
    identity: FlowIdentity
    direction: FlowDirection
    request: LDAPMessageObservation
    status: LDAPRequestSummaryStatus
    response_count: int
    terminal_response: Optional[LDAPMessageObservation]

    def __init__(self) -> None:
        raise TypeError("request summaries are produced by LDAP correlation")


def _summary(values: dict) -> LDAPRequestSummary:
    result = object.__new__(LDAPRequestSummary)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def _start_request_summary(
    identity: FlowIdentity, direction: FlowDirection, request: LDAPMessageObservation,
    status: LDAPRequestSummaryStatus = LDAPRequestSummaryStatus.PENDING,
) -> LDAPRequestSummary:
    return _summary(dict(identity=identity, direction=direction, request=request,
                         status=status, response_count=0, terminal_response=None))


def _summary_status(current: LDAPRequestSummary, status: LDAPRequestSummaryStatus) -> LDAPRequestSummary:
    if current.status is status:
        return current
    return _summary(dict(vars(current), status=status))


def _summary_response(
    current: LDAPRequestSummary, response: LDAPMessageObservation, terminal: bool,
) -> LDAPRequestSummary:
    return _summary(dict(vars(current), response_count=current.response_count + 1,
                         status=LDAPRequestSummaryStatus.COMPLETED if terminal else LDAPRequestSummaryStatus.PENDING,
                         terminal_response=response if terminal else None))
