from dataclasses import dataclass, fields, replace
from fractions import Fraction
from typing import Optional

from analysis.flow_direction import FlowDirection
from analysis.tcp_stream_observation import TCPStreamObservation
from analysis.tls_handshake_framing import (
    TLS_HANDSHAKE_MAX_MESSAGE_LENGTH, TLSHandshakeHeader, TLSHandshakeObservation, TLSHandshakeStatus,
)


@dataclass(frozen=True)
class TLSHandshakeStatistics:
    total_message_count: int = 0
    zero_length_message_count: int = 0
    min_message_length: Optional[int] = None
    max_message_length: Optional[int] = None
    total_message_length_bytes: int = 0
    handshake_type_counts: tuple[int, ...] = (0,) * 256

    def __post_init__(self) -> None:
        for member in fields(self):
            value = getattr(self, member.name)
            if member.name == 'handshake_type_counts':
                if type(value) is not tuple:
                    raise TypeError('handshake_type_counts must be exactly a tuple')
                if len(value) != 256:
                    raise ValueError('handshake_type_counts must contain 256 bins')
                values = value
            elif value is None and member.name in ('min_message_length', 'max_message_length'):
                continue
            else:
                values = (value,)
            for number in values:
                if type(number) is not int:
                    raise TypeError(f'{member.name} must contain exact integers')
                if number < 0:
                    raise ValueError(f'{member.name} must not be negative')
        count = self.total_message_count
        zero = self.zero_length_message_count
        total = self.total_message_length_bytes
        minimum, maximum = self.min_message_length, self.max_message_length
        if sum(self.handshake_type_counts) != count:
            raise ValueError('type bins must count every message exactly once')
        if zero > count:
            raise ValueError('zero-length count must not exceed message count')
        if count == 0:
            if total != 0 or minimum is not None or maximum is not None:
                raise ValueError('empty statistics require zero total and absent extrema')
        elif minimum is None or maximum is None or not 0 <= minimum <= maximum <= TLS_HANDSHAKE_MAX_MESSAGE_LENGTH:
            raise ValueError('message extrema must be ordered within the framing bound')
        elif (minimum == 0) != (zero > 0):
            raise ValueError('zero-length count and minimum must agree')
        elif zero == count:
            if maximum != 0 or total != 0:
                raise ValueError('all-zero messages require zero maximum and total')
        else:
            nonzero = count - zero
            positive_minimum = 1 if zero else minimum
            lower = maximum + (nonzero - 1) * positive_minimum
            upper = nonzero * maximum if zero else minimum + (nonzero - 1) * maximum
            if maximum == 0 or not lower <= total <= upper:
                raise ValueError('message total must attain the extrema with the observed zero count')

    @property
    def mean_message_length(self) -> Optional[Fraction]:
        return None if self.total_message_count == 0 else Fraction(self.total_message_length_bytes, self.total_message_count)


@dataclass(frozen=True)
class DirectionalTLSHandshakeStatistics:
    forward: TLSHandshakeStatistics = TLSHandshakeStatistics()
    reverse: TLSHandshakeStatistics = TLSHandshakeStatistics()

    def __post_init__(self) -> None:
        if type(self.forward) is not TLSHandshakeStatistics or type(self.reverse) is not TLSHandshakeStatistics:
            raise TypeError('directional aggregates must be exactly TLSHandshakeStatistics values')


def _validate_observation(observation):
    if type(observation) is not TLSHandshakeObservation:
        raise TypeError('observation must be exactly a TLSHandshakeObservation')
    if type(observation.stream) is not TCPStreamObservation or type(observation.direction) is not FlowDirection:
        raise TypeError('observation must have an existing TCP stream and flow direction')
    if observation.status is not TLSHandshakeStatus.READY or observation.header is None:
        raise ValueError('statistics require a complete handshake message')
    if type(observation.header) is not TLSHandshakeHeader:
        raise TypeError('header must be exactly a TLSHandshakeHeader')
    if type(observation.prefix) is not bytes or type(observation.payload) is not bytes:
        raise TypeError('handshake prefix and payload must be exact bytes')
    if observation.prefix or observation.unavailable_reason is not None:
        raise ValueError('complete messages require no partial prefix or failure reason')
    kind, length = observation.header.handshake_type, observation.declared_length
    if type(kind) is not int or type(length) is not int:
        raise TypeError('handshake type and declared length must be exact integers')
    if not 0 <= kind <= 255 or not 0 <= length <= TLS_HANDSHAKE_MAX_MESSAGE_LENGTH:
        raise ValueError('handshake metadata must be within framing bounds')
    if length != len(observation.payload):
        raise ValueError('complete handshake declared length must equal payload length')


def _reduce(current, observation):
    length = observation.declared_length
    counts = list(current.handshake_type_counts)
    counts[observation.header.handshake_type] += 1
    return TLSHandshakeStatistics(
        total_message_count=current.total_message_count + 1,
        zero_length_message_count=current.zero_length_message_count + int(length == 0),
        min_message_length=length if current.min_message_length is None else min(current.min_message_length, length),
        max_message_length=length if current.max_message_length is None else max(current.max_message_length, length),
        total_message_length_bytes=current.total_message_length_bytes + length,
        handshake_type_counts=tuple(counts),
    )


def update_tls_handshake_statistics(
    current: Optional[TLSHandshakeStatistics], observation: TLSHandshakeObservation,
) -> TLSHandshakeStatistics:
    if current is not None and type(current) is not TLSHandshakeStatistics:
        raise TypeError('current must be exactly a TLSHandshakeStatistics or None')
    _validate_observation(observation)
    return _reduce(TLSHandshakeStatistics() if current is None else current, observation)


def update_directional_tls_handshake_statistics(
    current: Optional[DirectionalTLSHandshakeStatistics], observation: TLSHandshakeObservation,
) -> DirectionalTLSHandshakeStatistics:
    if current is not None and type(current) is not DirectionalTLSHandshakeStatistics:
        raise TypeError('current must be exactly a DirectionalTLSHandshakeStatistics or None')
    _validate_observation(observation)
    current = DirectionalTLSHandshakeStatistics() if current is None else current
    name = 'forward' if observation.direction is FlowDirection.FORWARD else 'reverse'
    return replace(current, **{name: _reduce(getattr(current, name), observation)})
