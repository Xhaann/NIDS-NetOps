from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity
from analysis.packet_analysis import PacketAnalysis
from analysis.tcp import TCPPacket


TCP_STREAM_MAX_BYTES = 65536
_SEQUENCE_MODULUS = 1 << 32
_SEQUENCE_HALF_RANGE = 1 << 31


class TCPPayloadRelation(Enum):
    FIRST = "first"
    CONTIGUOUS = "contiguous"
    GAP = "gap"
    OVERLAP = "overlap"
    DUPLICATE = "duplicate"
    EMPTY = "empty"
    AMBIGUOUS = "ambiguous"
    UNAVAILABLE = "unavailable"


class TCPStreamStatus(Enum):
    OPEN = "open"
    FIN = "fin"
    RESET = "reset"
    AFTER_CLOSE = "after_close"
    GAP = "gap"
    OVERLAP = "overlap"
    CONFLICT = "conflict"
    AMBIGUOUS = "ambiguous"
    LIMIT_EXCEEDED = "limit_exceeded"
    RESTART = "restart"
    FRAGMENTED = "fragmented"


@dataclass(frozen=True, init=False)
class TCPStreamObservation:
    identity: FlowIdentity
    direction: FlowDirection
    payload: bytes = field(repr=False)
    start_sequence: Optional[int]
    next_sequence: Optional[int]
    syn_sequence: Optional[int]
    status: TCPStreamStatus
    last_relation: TCPPayloadRelation
    last_sequence_number: int
    last_payload_sequence: int
    last_payload_length: int
    last_sequence_delta: Optional[int]

    def __init__(self) -> None:
        raise TypeError("use update_tcp_stream_state(current, analysis, identity)")

    @property
    def contiguous_payload(self) -> Optional[bytes]:
        if self.status in (TCPStreamStatus.OPEN, TCPStreamStatus.FIN, TCPStreamStatus.RESET):
            return self.payload
        return None

    @property
    def payload_length(self) -> int:
        return len(self.payload)

    @property
    def end_sequence(self) -> Optional[int]:
        if self.start_sequence is None:
            return None
        return (self.start_sequence + len(self.payload)) % _SEQUENCE_MODULUS


@dataclass(frozen=True)
class TCPStreamState:
    identity: FlowIdentity
    forward: Optional[TCPStreamObservation] = None
    reverse: Optional[TCPStreamObservation] = None

    def __post_init__(self) -> None:
        if type(self.identity) is not FlowIdentity:
            raise TypeError("identity must be exactly a FlowIdentity")
        if self.identity.protocol != 6:
            raise ValueError("TCP stream state requires protocol 6")
        for name, direction in (("forward", FlowDirection.FORWARD), ("reverse", FlowDirection.REVERSE)):
            observation = getattr(self, name)
            if observation is not None:
                if type(observation) is not TCPStreamObservation:
                    raise TypeError(f"{name} must be exactly a TCPStreamObservation or None")
                if observation.identity != self.identity or observation.direction is not direction:
                    raise ValueError("stream observation identity and direction must match")


def _sequence_delta(sequence: int, expected: int) -> Optional[int]:
    delta = (sequence - expected) % _SEQUENCE_MODULUS
    if delta == _SEQUENCE_HALF_RANGE:
        return None
    return delta if delta < _SEQUENCE_HALF_RANGE else delta - _SEQUENCE_MODULUS


def _observe_payload(values: dict, tcp: TCPPacket) -> None:
    sequence = values["last_payload_sequence"]
    expected = values["next_sequence"]
    if expected is None:
        delta = 0
    else:
        delta = _sequence_delta(sequence, expected)
        values["last_sequence_delta"] = delta
    if delta is None:
        values.update(status=TCPStreamStatus.AMBIGUOUS, last_relation=TCPPayloadRelation.AMBIGUOUS)
        return
    if delta > 0:
        values.update(status=TCPStreamStatus.GAP, last_relation=TCPPayloadRelation.GAP)
        return
    if delta < 0:
        values["last_relation"] = TCPPayloadRelation.OVERLAP
        offset = len(values["payload"]) + delta
        overlap_start = max(0, offset)
        overlap_end = min(len(values["payload"]), offset + len(tcp.payload))
        if overlap_start < overlap_end and (
            values["payload"][overlap_start:overlap_end]
            != tcp.payload[overlap_start - offset:overlap_end - offset]
        ):
            values["status"] = TCPStreamStatus.CONFLICT
        elif offset >= 0 and offset + len(tcp.payload) <= len(values["payload"]):
            values["last_relation"] = TCPPayloadRelation.DUPLICATE
        else:
            values["status"] = TCPStreamStatus.OVERLAP
        return
    values["last_relation"] = (
        TCPPayloadRelation.FIRST if values["start_sequence"] is None else TCPPayloadRelation.CONTIGUOUS
    )
    if len(values["payload"]) + len(tcp.payload) > TCP_STREAM_MAX_BYTES:
        values["status"] = TCPStreamStatus.LIMIT_EXCEEDED
        return
    if values["start_sequence"] is None:
        values["start_sequence"] = sequence
    values["payload"] += tcp.payload
    values["next_sequence"] = (sequence + len(tcp.payload)) % _SEQUENCE_MODULUS


def _observe_segment(
    current: Optional[TCPStreamObservation], tcp: TCPPacket, identity: FlowIdentity,
    direction: FlowDirection, fragmented: bool,
) -> TCPStreamObservation:
    values = dict(identity=identity, direction=direction, payload=b"", start_sequence=None,
                  next_sequence=None, syn_sequence=None, status=TCPStreamStatus.OPEN)
    if current is not None:
        values.update(vars(current))
    sequence = (tcp.sequence_number + int(tcp.syn)) % _SEQUENCE_MODULUS
    values.update(last_relation=TCPPayloadRelation.EMPTY, last_sequence_number=tcp.sequence_number,
                  last_payload_sequence=sequence, last_payload_length=len(tcp.payload), last_sequence_delta=None)
    if values["status"] in (TCPStreamStatus.FIN, TCPStreamStatus.RESET) and (tcp.payload or tcp.syn):
        values.update(status=TCPStreamStatus.AFTER_CLOSE, last_relation=TCPPayloadRelation.UNAVAILABLE)
    elif values["status"] is not TCPStreamStatus.OPEN:
        values["last_relation"] = TCPPayloadRelation.UNAVAILABLE if tcp.payload else TCPPayloadRelation.EMPTY
    elif fragmented:
        values.update(status=TCPStreamStatus.FRAGMENTED, last_relation=TCPPayloadRelation.UNAVAILABLE)
    elif tcp.syn and values["next_sequence"] is not None and values["syn_sequence"] != tcp.sequence_number:
        values.update(status=TCPStreamStatus.RESTART, last_relation=TCPPayloadRelation.UNAVAILABLE)
    else:
        if tcp.syn and values["syn_sequence"] is None:
            values.update(syn_sequence=tcp.sequence_number, next_sequence=sequence)
        if tcp.payload:
            _observe_payload(values, tcp)
        if values["status"] is TCPStreamStatus.OPEN:
            if tcp.rst:
                values["status"] = TCPStreamStatus.RESET
            elif tcp.fin:
                fin_sequence = (sequence + len(tcp.payload)) % _SEQUENCE_MODULUS
                expected = values["next_sequence"]
                delta = 0 if expected is None else _sequence_delta(fin_sequence, expected)
                if not tcp.payload:
                    values["last_sequence_delta"] = delta
                if delta == 0:
                    values.update(status=TCPStreamStatus.FIN, next_sequence=(fin_sequence + 1) % _SEQUENCE_MODULUS)
                elif delta is None:
                    values["status"] = TCPStreamStatus.AMBIGUOUS
                else:
                    values["status"] = TCPStreamStatus.GAP if delta > 0 else TCPStreamStatus.OVERLAP
    result = object.__new__(TCPStreamObservation)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def update_tcp_stream_state(
    current: Optional[TCPStreamState], analysis: PacketAnalysis, identity: FlowIdentity,
) -> TCPStreamState:
    if current is not None and type(current) is not TCPStreamState:
        raise TypeError("current must be exactly a TCPStreamState or None")
    if type(analysis) is not PacketAnalysis:
        raise TypeError("analysis must be exactly a PacketAnalysis")
    if type(identity) is not FlowIdentity:
        raise TypeError("identity must be exactly a FlowIdentity")
    if identity.protocol != 6:
        raise ValueError("TCP stream state requires protocol 6")
    direction = flow_direction_from_packet(analysis, identity)
    if current is not None and current.identity != identity:
        raise ValueError("current stream identity must match")
    tcp = analysis.tcp if identity.ip_version == 4 else analysis.ipv6_tcp
    if type(tcp) is not TCPPacket:
        raise TypeError("analysis must contain exactly a TCPPacket")
    fragmented = bool(analysis.ipv4 is not None and analysis.ipv4.flags & 1) or (
        analysis.ipv6_fragmentation is not None
        and any(not header.is_whole_datagram for header in analysis.ipv6_fragmentation.headers)
    )
    identity = identity if current is None else current.identity
    forward = None if current is None else current.forward
    reverse = None if current is None else current.reverse
    if direction is FlowDirection.FORWARD:
        forward = _observe_segment(forward, tcp, identity, direction, fragmented)
    else:
        reverse = _observe_segment(reverse, tcp, identity, direction, fragmented)
    return TCPStreamState(identity, forward, reverse)
