from dataclasses import dataclass
from enum import Enum
from typing import Optional

from analysis.flow_direction import FlowDirection
from analysis.flow_identity import FlowIdentity
from analysis.ldap import LDAPMessageObservation, LDAPMessageStatus, LDAPOperation
from analysis.ldap_stream_framing import LDAPStreamState, LDAPStreamStatus
from analysis.ldap_request_summary import (
    LDAPRequestSummary, LDAPRequestSummaryStatus, _start_request_summary, _summary_response, _summary_status,
)


LDAP_MAX_PENDING_REQUESTS = 128
_RESPONSE_REQUESTS = {
    LDAPOperation.BIND_RESPONSE: LDAPOperation.BIND_REQUEST,
    LDAPOperation.SEARCH_RESULT_ENTRY: LDAPOperation.SEARCH_REQUEST,
    LDAPOperation.SEARCH_RESULT_REFERENCE: LDAPOperation.SEARCH_REQUEST,
    LDAPOperation.SEARCH_RESULT_DONE: LDAPOperation.SEARCH_REQUEST,
    LDAPOperation.MODIFY_RESPONSE: LDAPOperation.MODIFY_REQUEST,
    LDAPOperation.ADD_RESPONSE: LDAPOperation.ADD_REQUEST,
    LDAPOperation.DELETE_RESPONSE: LDAPOperation.DELETE_REQUEST,
    LDAPOperation.MODIFY_DN_RESPONSE: LDAPOperation.MODIFY_DN_REQUEST,
    LDAPOperation.COMPARE_RESPONSE: LDAPOperation.COMPARE_REQUEST,
    LDAPOperation.EXTENDED_RESPONSE: LDAPOperation.EXTENDED_REQUEST,
}
_REQUEST_OPERATIONS = frozenset(_RESPONSE_REQUESTS.values())
_SEARCH_CONTINUATIONS = frozenset((LDAPOperation.SEARCH_RESULT_ENTRY, LDAPOperation.SEARCH_RESULT_REFERENCE))


class LDAPCorrelationStatus(Enum):
    PENDING = "pending"
    MATCHED = "matched"
    UNMATCHED = "unmatched"
    AMBIGUOUS = "ambiguous"
    NON_CORRELATABLE = "non_correlatable"
    UNRESOLVED = "unresolved"


class LDAPCorrelationUnavailableReason(Enum):
    STREAM_UNAVAILABLE = "stream_unavailable"
    LIMIT_EXCEEDED = "limit_exceeded"


@dataclass(frozen=True, init=False)
class LDAPCorrelationObservation:
    identity: FlowIdentity
    direction: FlowDirection
    message: LDAPMessageObservation
    status: LDAPCorrelationStatus
    request: Optional[LDAPMessageObservation]
    request_summary: Optional[LDAPRequestSummary]

    def __init__(self) -> None:
        raise TypeError("use update_ldap_correlation_state(current, framing)")

    @property
    def request_direction(self) -> Optional[FlowDirection]:
        if self.request is None:
            return None
        if self.message.operation is not None and self.message.operation.is_request:
            return self.direction
        return FlowDirection.REVERSE if self.direction is FlowDirection.FORWARD else FlowDirection.FORWARD


@dataclass(frozen=True, init=False)
class LDAPCorrelationState:
    framing: LDAPStreamState
    requests: tuple[LDAPCorrelationObservation, ...]
    observations: tuple[LDAPCorrelationObservation, ...]
    matched_response_count: int
    unmatched_response_count: int
    ambiguous_observation_count: int
    non_correlatable_count: int
    unavailable_reason: Optional[LDAPCorrelationUnavailableReason]
    finalized: bool

    def __init__(self) -> None:
        raise TypeError("use update_ldap_correlation_state(current, framing)")

    @property
    def identity(self) -> FlowIdentity:
        return self.framing.identity


def _observation(identity, direction, message, status, request=None, request_summary=None):
    result = object.__new__(LDAPCorrelationObservation)
    for name, value in dict(identity=identity, direction=direction, message=message,
                            status=status, request=request, request_summary=request_summary).items():
        object.__setattr__(result, name, value)
    return result


def _state(values):
    result = object.__new__(LDAPCorrelationState)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def _unresolved(request):
    if request.status is not LDAPCorrelationStatus.PENDING:
        return request
    return _observation(request.identity, request.direction, request.message,
                        LDAPCorrelationStatus.UNRESOLVED, request.request,
                        _summary_status(request.request_summary, LDAPRequestSummaryStatus.UNRESOLVED))


def update_ldap_correlation_state(
    current: Optional[LDAPCorrelationState], framing: LDAPStreamState,
) -> LDAPCorrelationState:
    if current is not None and type(current) is not LDAPCorrelationState:
        raise TypeError("current must be exactly an LDAPCorrelationState or None")
    if type(framing) is not LDAPStreamState:
        raise TypeError("framing must be exactly an LDAPStreamState")
    if current is not None:
        if current.finalized:
            raise ValueError("finalized LDAP correlation cannot continue")
        if current.identity != framing.identity:
            raise ValueError("LDAP correlation and framing identities must match")
        if current.framing is framing:
            return current
    directions = tuple(d for d in (framing.forward, framing.reverse) if d is not None)
    if sum(bool(d.messages) for d in directions) > 1:
        raise ValueError("a framing update must preserve one observed direction's message order")
    values = dict(framing=framing, requests=(), observations=(), matched_response_count=0,
                  unmatched_response_count=0, ambiguous_observation_count=0,
                  non_correlatable_count=0, unavailable_reason=None, finalized=False)
    if current is not None:
        values.update(vars(current))
        values["framing"] = framing
    pending = {(r.direction, r.message.message_id): r for r in values["requests"]}
    if values["unavailable_reason"] is None and any(
        stream is not None and stream.contiguous_payload is None
        for stream in (framing.tcp_stream_state.forward, framing.tcp_stream_state.reverse)
    ):
        values["unavailable_reason"] = LDAPCorrelationUnavailableReason.STREAM_UNAVAILABLE
    observations = []
    for stream in directions:
        direction = stream.direction
        opposite = FlowDirection.REVERSE if direction is FlowDirection.FORWARD else FlowDirection.FORWARD
        for message in stream.messages:
            key = (direction, message.message_id)
            response_key = (opposite, message.message_id)
            operation = message.operation
            candidate = None
            summary = None
            if message.status is not LDAPMessageStatus.COMPLETE or message.message_id == 0 or (
                operation not in _REQUEST_OPERATIONS and operation not in _RESPONSE_REQUESTS
            ):
                status = LDAPCorrelationStatus.NON_CORRELATABLE
                values["non_correlatable_count"] += 1
                if values["unavailable_reason"] is None and key in pending and message.status is LDAPMessageStatus.UNSUPPORTED:
                    previous = pending[key]
                    pending[key] = _observation(framing.identity, direction, previous.message,
                                                LDAPCorrelationStatus.AMBIGUOUS, previous.request,
                                                _summary_status(previous.request_summary, LDAPRequestSummaryStatus.AMBIGUOUS))
            elif operation in _REQUEST_OPERATIONS:
                candidate = message
                if values["unavailable_reason"] is not None:
                    status = LDAPCorrelationStatus.UNRESOLVED
                    summary = _start_request_summary(framing.identity, direction, message, LDAPRequestSummaryStatus.UNRESOLVED)
                elif key in pending:
                    status = LDAPCorrelationStatus.AMBIGUOUS
                    previous = pending[key]
                    candidate = previous.message
                    summary = _summary_status(previous.request_summary, LDAPRequestSummaryStatus.AMBIGUOUS)
                    pending[key] = _observation(framing.identity, direction, previous.message, status, candidate, summary)
                elif len(pending) == LDAP_MAX_PENDING_REQUESTS:
                    values["unavailable_reason"] = LDAPCorrelationUnavailableReason.LIMIT_EXCEEDED
                    status = LDAPCorrelationStatus.UNRESOLVED
                    summary = _start_request_summary(framing.identity, direction, message, LDAPRequestSummaryStatus.UNRESOLVED)
                else:
                    status = LDAPCorrelationStatus.PENDING
                    summary = _start_request_summary(framing.identity, direction, message)
                    pending[key] = _observation(framing.identity, direction, message, status, message, summary)
            else:
                previous = pending.get(response_key)
                status = LDAPCorrelationStatus.UNMATCHED
                if values["unavailable_reason"] is None and previous is not None:
                    if previous.status is LDAPCorrelationStatus.AMBIGUOUS:
                        status = LDAPCorrelationStatus.AMBIGUOUS
                    elif previous.message.operation is _RESPONSE_REQUESTS[operation]:
                        status = LDAPCorrelationStatus.MATCHED
                        candidate = previous.message
                        terminal = operation not in _SEARCH_CONTINUATIONS
                        summary = _summary_response(previous.request_summary, message, terminal)
                        if terminal:
                            del pending[response_key]
                        else:
                            pending[response_key] = _observation(framing.identity, opposite, previous.message,
                                                                  previous.status, previous.request, summary)
                            summary = None
                if status is LDAPCorrelationStatus.MATCHED:
                    values["matched_response_count"] += 1
                elif status is LDAPCorrelationStatus.UNMATCHED:
                    values["unmatched_response_count"] += 1
            if status is LDAPCorrelationStatus.AMBIGUOUS:
                values["ambiguous_observation_count"] += 1
            observations.append(_observation(framing.identity, direction, message, status, candidate, summary))
    if values["unavailable_reason"] is None and any(d.status in (
        LDAPStreamStatus.MALFORMED, LDAPStreamStatus.UNSUPPORTED, LDAPStreamStatus.UNAVAILABLE,
    ) for d in directions):
        values["unavailable_reason"] = LDAPCorrelationUnavailableReason.STREAM_UNAVAILABLE
    requests = tuple(pending.values())
    if values["unavailable_reason"] is not None:
        requests = tuple(_unresolved(r) for r in requests)
    values.update(requests=requests, observations=tuple(observations))
    return _state(values)


def finalize_ldap_correlation_state(current: LDAPCorrelationState) -> LDAPCorrelationState:
    if type(current) is not LDAPCorrelationState:
        raise TypeError("current must be exactly an LDAPCorrelationState")
    if current.finalized:
        return current
    values = dict(vars(current), finalized=True, requests=tuple(_unresolved(r) for r in current.requests),
                  observations=tuple(_unresolved(r) for r in current.observations))
    return _state(values)
