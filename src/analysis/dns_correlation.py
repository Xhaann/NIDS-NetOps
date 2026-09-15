from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from analysis.dns import DNSMessageObservation, DNSMessageStatus
from analysis.flow_direction import FlowDirection
from analysis.flow_identity import FlowIdentity


DNS_MAX_PENDING_REQUESTS = 128


class DNSCorrelationStatus(Enum):
    PENDING = 'pending'
    MATCHED = 'matched'
    UNMATCHED = 'unmatched'
    AMBIGUOUS = 'ambiguous'
    UNRESOLVED = 'unresolved'


class DNSCorrelationReason(Enum):
    LIMIT_EXCEEDED = 'limit_exceeded'
    FLOW_CLOSED = 'flow_closed'


@dataclass(frozen=True, init=False)
class DNSTransactionObservation:
    identity: FlowIdentity
    direction: FlowDirection
    message: DNSMessageObservation
    captured_at: datetime
    status: DNSCorrelationStatus
    request: Optional[DNSMessageObservation]
    request_captured_at: Optional[datetime]
    reason: Optional[DNSCorrelationReason]

    def __init__(self) -> None:
        raise TypeError('use update_dns_correlation_state(current, message, identity, direction, captured_at)')

    @property
    def transaction_id(self) -> int:
        return self.message.header.transaction_id

    @property
    def duration(self) -> Optional[timedelta]:
        if self.status is not DNSCorrelationStatus.MATCHED:
            return None
        return self.captured_at - self.request_captured_at


@dataclass(frozen=True, init=False)
class DNSCorrelationState:
    identity: FlowIdentity
    requests: tuple[DNSTransactionObservation, ...]
    observations: tuple[DNSTransactionObservation, ...]
    last_captured_at: datetime
    unavailable_reason: Optional[DNSCorrelationReason]
    finalized: bool

    def __init__(self) -> None:
        raise TypeError('use update_dns_correlation_state(current, message, identity, direction, captured_at)')


def _build(model, **values):
    result = object.__new__(model)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def _status(observation, status, reason=None):
    return _build(DNSTransactionObservation, **dict(vars(observation), status=status, reason=reason))


def _questions(message):
    return tuple((tuple(label.lower() for label in question.name.labels),
                  question.question_type, question.question_class) for question in message.questions)


def update_dns_correlation_state(
    current: Optional[DNSCorrelationState], message: Optional[DNSMessageObservation],
    identity: FlowIdentity, direction: FlowDirection, captured_at: datetime,
) -> Optional[DNSCorrelationState]:
    if current is not None and type(current) is not DNSCorrelationState:
        raise TypeError('current must be exactly a DNSCorrelationState or None')
    if message is not None and type(message) is not DNSMessageObservation:
        raise TypeError('message must be exactly a DNSMessageObservation or None')
    if type(identity) is not FlowIdentity:
        raise TypeError('identity must be exactly a FlowIdentity')
    if type(direction) is not FlowDirection:
        raise TypeError('direction must be exactly a FlowDirection')
    if type(captured_at) is not datetime:
        raise TypeError('captured_at must be exactly a datetime')
    if type(captured_at.tzinfo) is not timezone or captured_at.utcoffset() != timedelta(0):
        raise ValueError('captured_at must use a fixed UTC datetime.timezone')
    if current is not None:
        if current.finalized:
            raise ValueError('finalized DNS correlation cannot continue')
        if current.identity != identity:
            raise ValueError('DNS correlation identity must match')
        if captured_at < current.last_captured_at:
            raise ValueError('capture timestamp must not precede the previous observation')
    valid = message is not None and message.status is DNSMessageStatus.COMPLETE
    if current is None and not valid:
        return None
    pending = {} if current is None else {(item.direction, item.transaction_id): item for item in current.requests}
    unavailable = None if current is None else current.unavailable_reason
    observations = []
    if valid:
        response = message.header.is_response
        opposite = FlowDirection.REVERSE if direction is FlowDirection.FORWARD else FlowDirection.FORWARD
        key = (opposite if response else direction, message.header.transaction_id)
        previous = pending.get(key)
        request, timestamp, reason = None, None, unavailable
        if not response:
            request, timestamp = message, captured_at
            if unavailable is not None:
                status = DNSCorrelationStatus.UNRESOLVED
            elif previous is not None:
                status = DNSCorrelationStatus.AMBIGUOUS
                pending[key] = _status(previous, status)
                request, timestamp = previous.request, previous.request_captured_at
            elif len(pending) == DNS_MAX_PENDING_REQUESTS:
                unavailable = reason = DNSCorrelationReason.LIMIT_EXCEEDED
                observations.extend(_status(item, DNSCorrelationStatus.UNRESOLVED, reason) for item in pending.values())
                pending.clear()
                status = DNSCorrelationStatus.UNRESOLVED
            else:
                status = DNSCorrelationStatus.PENDING
        else:
            status = DNSCorrelationStatus.UNMATCHED
            if previous is not None and unavailable is None:
                if previous.status is DNSCorrelationStatus.AMBIGUOUS:
                    status = DNSCorrelationStatus.AMBIGUOUS
                elif (message.header.opcode == previous.request.header.opcode
                      and _questions(message) == _questions(previous.request)):
                    status = DNSCorrelationStatus.MATCHED
                    request, timestamp = previous.request, previous.request_captured_at
                    del pending[key]
        observation = _build(DNSTransactionObservation, identity=identity, direction=direction,
                             message=message, captured_at=captured_at, status=status, request=request,
                             request_captured_at=timestamp, reason=reason)
        observations.append(observation)
        if status is DNSCorrelationStatus.PENDING:
            pending[key] = observation
    return _build(DNSCorrelationState, identity=identity, requests=tuple(pending.values()),
                  observations=tuple(observations), last_captured_at=captured_at,
                  unavailable_reason=unavailable, finalized=False)


def finalize_dns_correlation_state(current: DNSCorrelationState) -> DNSCorrelationState:
    if type(current) is not DNSCorrelationState:
        raise TypeError('current must be exactly a DNSCorrelationState')
    if current.finalized:
        return current
    terminal = tuple(_status(item, DNSCorrelationStatus.UNRESOLVED, DNSCorrelationReason.FLOW_CLOSED)
                     for item in current.requests)
    retained = tuple(item for item in current.observations if item.status is not DNSCorrelationStatus.PENDING)
    return _build(DNSCorrelationState, **dict(vars(current), requests=(),
                                             observations=retained + terminal, finalized=True))
