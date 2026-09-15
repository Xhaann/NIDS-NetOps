from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Optional

from analysis.dns import DNS_MAX_MESSAGE_BYTES
from analysis.flow_direction import FlowDirection
from analysis.flow_identity import FlowIdentity
from analysis.tcp_stream_observation import TCPStreamObservation, TCPStreamState, TCPStreamStatus, consume_tcp_stream


class DNSStreamStatus(Enum):
    READY = 'ready'
    INCOMPLETE = 'incomplete'
    UNAVAILABLE = 'unavailable'


@dataclass(frozen=True, init=False)
class DNSStreamObservation:
    stream: TCPStreamObservation
    prefix: bytes = field(repr=False)
    declared_length: Optional[int]
    payload: bytes = field(repr=False)
    status: DNSStreamStatus
    unavailable_reason: Optional[TCPStreamStatus]

    def __init__(self) -> None:
        raise TypeError('use update_dns_stream_state(current, streams)')

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
class DNSStreamState:
    tcp_stream_state: TCPStreamState
    forward: Optional[DNSStreamObservation]
    reverse: Optional[DNSStreamObservation]

    def __init__(self) -> None:
        raise TypeError('use update_dns_stream_state(current, streams)')

    @property
    def identity(self) -> FlowIdentity:
        return self.tcp_stream_state.identity


@dataclass(frozen=True, init=False)
class DNSStreamUpdate:
    state: DNSStreamState
    forward_frames: tuple[bytes, ...] = field(repr=False)
    reverse_frames: tuple[bytes, ...] = field(repr=False)

    def __init__(self) -> None:
        raise TypeError('use update_dns_stream_state(current, streams)')


def _build(model, **values):
    result = object.__new__(model)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def _frame_direction(current, stream):
    if stream is None:
        if current is not None:
            raise ValueError('an established DNS direction cannot lose its TCP observation')
        return None, ()
    if current is not None and stream.consumed_offset != current.consumed_offset:
        raise ValueError('DNS framing must continue from its published consumption offset')
    prefix = b'' if current is None else current.prefix
    payload = b'' if current is None else current.payload
    declared = None if current is None else current.declared_length
    reason = None if current is None else current.unavailable_reason
    if stream.contiguous_payload is None:
        reason = stream.status if reason is None else reason
    frames = []
    if reason is None:
        data = stream.unconsumed_payload
        offset = 0
        while offset < len(data):
            if declared is None:
                count = min(2 - len(prefix), len(data) - offset)
                prefix += data[offset:offset + count]
                offset += count
                if len(prefix) < 2:
                    break
                declared = int.from_bytes(prefix, 'big')
                prefix = b''
                if declared > DNS_MAX_MESSAGE_BYTES:
                    reason = TCPStreamStatus.LIMIT_EXCEEDED
                    break
            count = min(declared - len(payload), len(data) - offset)
            payload += data[offset:offset + count]
            offset += count
            if len(payload) < declared:
                break
            frames.append(payload)
            payload, declared = b'', None
        stream = consume_tcp_stream(stream, offset)
    status = DNSStreamStatus.UNAVAILABLE if reason is not None else (
        DNSStreamStatus.INCOMPLETE if prefix or declared is not None else DNSStreamStatus.READY
    )
    return _build(DNSStreamObservation, stream=stream, prefix=prefix, declared_length=declared,
                  payload=payload, status=status, unavailable_reason=reason), tuple(frames)


def update_dns_stream_state(current: Optional[DNSStreamState], streams: TCPStreamState) -> Optional[DNSStreamUpdate]:
    if current is not None and type(current) is not DNSStreamState:
        raise TypeError('current must be exactly a DNSStreamState or None')
    if type(streams) is not TCPStreamState:
        raise TypeError('streams must be exactly a TCPStreamState')
    if current is not None and current.identity != streams.identity:
        raise ValueError('DNS and TCP stream identities must match')
    ports = (streams.identity.source_port, streams.identity.destination_port)
    if 53 not in ports or 389 in ports:
        return None
    if current is None and any(stream is not None and stream.consumed_offset != 0 for stream in (streams.forward, streams.reverse)):
        raise ValueError('DNS framing must start at an unconsumed stream origin')
    forward, forward_frames = _frame_direction(None if current is None else current.forward, streams.forward)
    reverse, reverse_frames = _frame_direction(None if current is None else current.reverse, streams.reverse)
    consumed = replace(streams, forward=None if forward is None else forward.stream,
                       reverse=None if reverse is None else reverse.stream)
    state = _build(DNSStreamState, tcp_stream_state=consumed, forward=forward, reverse=reverse)
    return _build(DNSStreamUpdate, state=state, forward_frames=forward_frames, reverse_frames=reverse_frames)
