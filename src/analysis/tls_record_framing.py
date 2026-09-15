from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Optional

from analysis.flow_direction import FlowDirection
from analysis.flow_identity import FlowIdentity
from analysis.tcp_stream_observation import TCPStreamObservation, TCPStreamState, TCPStreamStatus, consume_tcp_stream


TLS_RECORD_MAX_PAYLOAD_BYTES = 18432


class TLSRecordStatus(Enum):
    READY = 'ready'
    INCOMPLETE = 'incomplete'
    UNAVAILABLE = 'unavailable'


@dataclass(frozen=True, init=False)
class TLSRecordHeader:
    content_type: int
    protocol_version: bytes
    declared_length: int

    def __init__(self) -> None:
        raise TypeError('use update_tls_record_state(current, streams)')


@dataclass(frozen=True, init=False)
class TLSRecordObservation:
    stream: TCPStreamObservation
    prefix: bytes = field(repr=False)
    header: Optional[TLSRecordHeader]
    payload: bytes = field(repr=False)
    status: TLSRecordStatus
    unavailable_reason: Optional[TCPStreamStatus]

    def __init__(self) -> None:
        raise TypeError('use update_tls_record_state(current, streams)')

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
class TLSRecordState:
    tcp_stream_state: TCPStreamState
    forward: Optional[TLSRecordObservation]
    reverse: Optional[TLSRecordObservation]

    def __init__(self) -> None:
        raise TypeError('use update_tls_record_state(current, streams)')

    @property
    def identity(self) -> FlowIdentity:
        return self.tcp_stream_state.identity


@dataclass(frozen=True, init=False)
class TLSRecordUpdate:
    state: TLSRecordState
    forward_records: tuple[TLSRecordObservation, ...] = field(repr=False)
    reverse_records: tuple[TLSRecordObservation, ...] = field(repr=False)

    def __init__(self) -> None:
        raise TypeError('use update_tls_record_state(current, streams)')


def _build(model, **values):
    result = object.__new__(model)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def _frame_direction(current, stream):
    if stream is None:
        if current is not None:
            raise ValueError('an established TLS direction cannot lose its TCP observation')
        return None, ()
    if current is not None and stream.consumed_offset != current.consumed_offset:
        raise ValueError('TLS framing must continue from its published consumption offset')
    prefix = b'' if current is None else current.prefix
    header = None if current is None else current.header
    payload = b'' if current is None else current.payload
    reason = None if current is None else current.unavailable_reason
    if stream.contiguous_payload is None and reason is None:
        reason = stream.status
    complete = []
    if reason is None:
        data = stream.unconsumed_payload
        offset = 0
        while offset < len(data):
            if header is None:
                count = min(5 - len(prefix), len(data) - offset)
                prefix += data[offset:offset + count]
                offset += count
                if len(prefix) < 5:
                    break
                header = _build(TLSRecordHeader, content_type=prefix[0], protocol_version=prefix[1:3],
                                declared_length=int.from_bytes(prefix[3:5], 'big'))
                prefix = b''
                if header.declared_length > TLS_RECORD_MAX_PAYLOAD_BYTES:
                    reason = TCPStreamStatus.LIMIT_EXCEEDED
                    break
            count = min(header.declared_length - len(payload), len(data) - offset)
            payload += data[offset:offset + count]
            offset += count
            if len(payload) < header.declared_length:
                break
            complete.append((header, payload))
            header, payload = None, b''
        stream = consume_tcp_stream(stream, offset)
    records = tuple(_build(TLSRecordObservation, stream=stream, prefix=b'', header=record_header,
                           payload=record_payload, status=TLSRecordStatus.READY, unavailable_reason=None)
                    for record_header, record_payload in complete)
    status = TLSRecordStatus.UNAVAILABLE if reason is not None else (
        TLSRecordStatus.INCOMPLETE if prefix or header is not None else TLSRecordStatus.READY
    )
    observation = _build(TLSRecordObservation, stream=stream, prefix=prefix, header=header,
                         payload=payload, status=status, unavailable_reason=reason)
    return observation, records


def update_tls_record_state(current: Optional[TLSRecordState], streams: TCPStreamState) -> Optional[TLSRecordUpdate]:
    if current is not None and type(current) is not TLSRecordState:
        raise TypeError('current must be exactly a TLSRecordState or None')
    if type(streams) is not TCPStreamState:
        raise TypeError('streams must be exactly a TCPStreamState')
    if current is not None and current.identity != streams.identity:
        raise ValueError('TLS and TCP stream identities must match')
    ports = (streams.identity.source_port, streams.identity.destination_port)
    if 443 not in ports or 389 in ports or 53 in ports:
        return None
    if current is None and any(stream is not None and stream.consumed_offset != 0
                               for stream in (streams.forward, streams.reverse)):
        raise ValueError('TLS framing must start at an unconsumed stream origin')
    forward, forward_records = _frame_direction(None if current is None else current.forward, streams.forward)
    reverse, reverse_records = _frame_direction(None if current is None else current.reverse, streams.reverse)
    consumed = replace(streams, forward=None if forward is None else forward.stream,
                       reverse=None if reverse is None else reverse.stream)
    state = _build(TLSRecordState, tcp_stream_state=consumed, forward=forward, reverse=reverse)
    return _build(TLSRecordUpdate, state=state, forward_records=forward_records, reverse_records=reverse_records)
