from dataclasses import dataclass, replace
from enum import Enum
from typing import Optional

from analysis.flow_direction import FlowDirection
from analysis.flow_identity import FlowIdentity
from analysis.ldap import LDAP_MAX_PAYLOAD_BYTES, LDAPMessageObservation, LDAPMessageStatus, _message
from analysis.tcp_stream_observation import TCPStreamObservation, TCPStreamState, consume_tcp_stream


class LDAPStreamStatus(Enum):
    READY = "ready"
    INCOMPLETE = "incomplete"
    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, init=False)
class LDAPStreamObservation:
    stream: TCPStreamObservation
    messages: tuple[LDAPMessageObservation, ...]
    pending_message: Optional[LDAPMessageObservation]
    status: LDAPStreamStatus
    complete_message_count: int
    unsupported_message_count: int
    malformed_message_count: int

    def __init__(self) -> None:
        raise TypeError("use update_ldap_stream_state(current, streams)")

    @property
    def identity(self) -> FlowIdentity:
        return self.stream.identity

    @property
    def direction(self) -> FlowDirection:
        return self.stream.direction

    @property
    def consumed_offset(self) -> int:
        return self.stream.consumed_offset

    @property
    def retained_suffix(self) -> bytes:
        return self.stream.payload[self.stream.consumed_length:]


@dataclass(frozen=True, init=False)
class LDAPStreamState:
    tcp_stream_state: TCPStreamState
    forward: Optional[LDAPStreamObservation]
    reverse: Optional[LDAPStreamObservation]

    def __init__(self) -> None:
        raise TypeError("use update_ldap_stream_state(current, streams)")

    @property
    def identity(self) -> FlowIdentity:
        return self.tcp_stream_state.identity


def _frame_direction(
    current: Optional[LDAPStreamObservation], stream: Optional[TCPStreamObservation],
) -> Optional[LDAPStreamObservation]:
    if stream is None:
        if current is not None:
            raise ValueError("an established LDAP direction cannot lose its TCP observation")
        return None
    if current is None and (not stream.payload or stream.payload[0] != 0x30):
        return None
    if current is not None and stream.consumed_offset != current.consumed_offset:
        raise ValueError("LDAP framing must continue from its published consumption offset")
    values = dict(stream=stream, messages=(), pending_message=None, status=LDAPStreamStatus.READY,
                  complete_message_count=0, unsupported_message_count=0, malformed_message_count=0)
    if current is not None:
        values.update(vars(current))
        values.update(stream=stream, messages=())
    if stream.contiguous_payload is None:
        values["status"] = LDAPStreamStatus.UNAVAILABLE
    elif values["status"] not in (LDAPStreamStatus.MALFORMED, LDAPStreamStatus.UNSUPPORTED, LDAPStreamStatus.UNAVAILABLE):
        pending = values["pending_message"]
        available = len(stream.payload)
        offset = stream.consumed_length
        unchanged = current is not None and available + stream.buffer_offset == (
            len(current.stream.payload) + current.stream.buffer_offset
        )
        waiting = pending is not None and pending.message_length is not None and (
            pending.status is LDAPMessageStatus.UNSUPPORTED
            or (pending.operation_length is not None and pending.controls_present is False)
        ) and (
            available - offset < pending.message_length
        )
        if not unchanged and not waiting:
            messages = []
            values.update(pending_message=None, status=LDAPStreamStatus.READY)
            while offset < available:
                message = _message(stream.payload, offset, available, stream.buffer_offset)
                if message.status is LDAPMessageStatus.MALFORMED:
                    values.update(pending_message=message, status=LDAPStreamStatus.MALFORMED)
                    values["malformed_message_count"] += 1
                    break
                if message.envelope_complete and message.message_length is not None:
                    messages.append(message)
                    counter = "complete_message_count" if message.status is LDAPMessageStatus.COMPLETE else "unsupported_message_count"
                    values[counter] += 1
                    offset += message.message_length
                else:
                    values["pending_message"] = message
                    if message.status is LDAPMessageStatus.INCOMPLETE or (
                        message.message_length is not None and message.message_length <= LDAP_MAX_PAYLOAD_BYTES
                    ):
                        values["status"] = LDAPStreamStatus.INCOMPLETE
                    else:
                        values["status"] = LDAPStreamStatus.UNSUPPORTED
                        values["unsupported_message_count"] += 1
                    break
            values["messages"] = tuple(messages)
            values["stream"] = consume_tcp_stream(stream, offset - stream.consumed_length)
    result = object.__new__(LDAPStreamObservation)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def update_ldap_stream_state(
    current: Optional[LDAPStreamState], streams: TCPStreamState,
) -> Optional[LDAPStreamState]:
    if current is not None and type(current) is not LDAPStreamState:
        raise TypeError("current must be exactly an LDAPStreamState or None")
    if type(streams) is not TCPStreamState:
        raise TypeError("streams must be exactly a TCPStreamState")
    if current is not None and current.identity != streams.identity:
        raise ValueError("LDAP and TCP stream identities must match")
    ports = (streams.identity.source_port, streams.identity.destination_port)
    if 389 not in ports or 636 in ports:
        return None
    if current is None and any(stream is not None and stream.consumed_offset != 0 for stream in (streams.forward, streams.reverse)):
        raise ValueError("LDAP framing must start at an unconsumed stream origin")
    forward = _frame_direction(None if current is None else current.forward, streams.forward)
    reverse = _frame_direction(None if current is None else current.reverse, streams.reverse)
    if forward is None and reverse is None:
        return None
    consumed = replace(streams, forward=streams.forward if forward is None else forward.stream,
                       reverse=streams.reverse if reverse is None else reverse.stream)
    result = object.__new__(LDAPStreamState)
    object.__setattr__(result, "tcp_stream_state", consumed)
    object.__setattr__(result, "forward", forward)
    object.__setattr__(result, "reverse", reverse)
    return result
