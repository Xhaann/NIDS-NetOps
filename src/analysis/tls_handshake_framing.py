from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from analysis.flow_direction import FlowDirection
from analysis.flow_identity import FlowIdentity
from analysis.tcp_stream_observation import TCPStreamObservation, TCPStreamStatus
from analysis.tls_record_framing import TLSRecordState, TLSRecordStatus, TLSRecordUpdate


TLS_HANDSHAKE_MAX_MESSAGE_LENGTH = 262144


class TLSHandshakeStatus(Enum):
    READY = 'ready'
    INCOMPLETE = 'incomplete'
    UNAVAILABLE = 'unavailable'


@dataclass(frozen=True, init=False)
class TLSHandshakeHeader:
    handshake_type: int
    declared_length: int

    def __init__(self) -> None:
        raise TypeError('use update_tls_handshake_state(current, records)')


@dataclass(frozen=True, init=False)
class TLSHandshakeObservation:
    stream: TCPStreamObservation
    prefix: bytes = field(repr=False)
    header: Optional[TLSHandshakeHeader]
    payload: bytes = field(repr=False)
    status: TLSHandshakeStatus
    unavailable_reason: Optional[TCPStreamStatus]

    def __init__(self) -> None:
        raise TypeError('use update_tls_handshake_state(current, records)')

    @property
    def declared_length(self) -> Optional[int]:
        return None if self.header is None else self.header.declared_length

    @property
    def identity(self) -> FlowIdentity:
        return self.stream.identity

    @property
    def direction(self) -> FlowDirection:
        return self.stream.direction

    @property
    def consumed_offset(self) -> int:
        return self.stream.consumed_offset


@dataclass(frozen=True, init=False)
class TLSHandshakeState:
    tls_record_state: TLSRecordState
    forward: Optional[TLSHandshakeObservation]
    reverse: Optional[TLSHandshakeObservation]

    def __init__(self) -> None:
        raise TypeError('use update_tls_handshake_state(current, records)')

    @property
    def identity(self) -> FlowIdentity:
        return self.tls_record_state.identity


@dataclass(frozen=True, init=False)
class TLSHandshakeUpdate:
    state: TLSHandshakeState
    forward_messages: tuple[TLSHandshakeObservation, ...] = field(repr=False)
    reverse_messages: tuple[TLSHandshakeObservation, ...] = field(repr=False)

    def __init__(self) -> None:
        raise TypeError('use update_tls_handshake_state(current, records)')


def _build(model, **values):
    result = object.__new__(model)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def _frame_direction(current, framing, records):
    if framing is None:
        if current is not None:
            raise ValueError('an established handshake direction cannot lose its TLS record observation')
        return None, ()
    if current is not None and framing.consumed_offset < current.consumed_offset:
        raise ValueError('TLS handshake framing cannot move backwards in the record stream')
    prefix = b'' if current is None else current.prefix
    header = None if current is None else current.header
    payload = b'' if current is None else current.payload
    reason = None if current is None else current.unavailable_reason
    messages = []
    for record in records:
        if reason is not None:
            break
        if current is not None and record.consumed_offset <= current.consumed_offset:
            continue
        if record.header.content_type != 22:
            continue
        data = record.payload
        offset = 0
        while offset < len(data):
            if header is None:
                count = min(4 - len(prefix), len(data) - offset)
                prefix += data[offset:offset + count]
                offset += count
                if len(prefix) < 4:
                    break
                header = _build(TLSHandshakeHeader, handshake_type=prefix[0],
                                declared_length=int.from_bytes(prefix[1:4], 'big'))
                prefix = b''
                if header.declared_length > TLS_HANDSHAKE_MAX_MESSAGE_LENGTH:
                    reason = TCPStreamStatus.LIMIT_EXCEEDED
                    break
            count = min(header.declared_length - len(payload), len(data) - offset)
            payload += data[offset:offset + count]
            offset += count
            if len(payload) < header.declared_length:
                break
            messages.append(_build(TLSHandshakeObservation, stream=record.stream, prefix=b'', header=header,
                                   payload=payload, status=TLSHandshakeStatus.READY, unavailable_reason=None))
            header, payload = None, b''
    if reason is None and framing.status is TLSRecordStatus.UNAVAILABLE:
        reason = framing.unavailable_reason
    status = TLSHandshakeStatus.UNAVAILABLE if reason is not None else (
        TLSHandshakeStatus.INCOMPLETE if prefix or header is not None else TLSHandshakeStatus.READY
    )
    observation = _build(TLSHandshakeObservation, stream=framing.stream, prefix=prefix, header=header,
                         payload=payload, status=status, unavailable_reason=reason)
    return observation, tuple(messages)


def update_tls_handshake_state(current: Optional[TLSHandshakeState], records: TLSRecordUpdate) -> TLSHandshakeUpdate:
    if current is not None and type(current) is not TLSHandshakeState:
        raise TypeError('current must be exactly a TLSHandshakeState or None')
    if type(records) is not TLSRecordUpdate:
        raise TypeError('records must be exactly a TLSRecordUpdate')
    if current is not None and current.identity != records.state.identity:
        raise ValueError('handshake and TLS record identities must match')
    forward, forward_messages = _frame_direction(None if current is None else current.forward,
                                                 records.state.forward, records.forward_records)
    reverse, reverse_messages = _frame_direction(None if current is None else current.reverse,
                                                 records.state.reverse, records.reverse_records)
    state = _build(TLSHandshakeState, tls_record_state=records.state, forward=forward, reverse=reverse)
    return _build(TLSHandshakeUpdate, state=state, forward_messages=forward_messages, reverse_messages=reverse_messages)
