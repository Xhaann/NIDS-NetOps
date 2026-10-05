from dataclasses import dataclass, replace
from typing import Optional

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity
from analysis.ipv6 import IPv6Packet
from analysis.packet_analysis import PacketAnalysis


IPV6_FLOW_LABEL_VALUES = 1048576
IPV6_FLOW_LABEL_MAX_BINS = 256


@dataclass(frozen=True)
class IPv6FlowLabelStatistics:
    flow_label_counts: tuple[tuple[int, int], ...] = ()
    saturated_packet_count: int = 0

    def __post_init__(self) -> None:
        if type(self.flow_label_counts) is not tuple:
            raise TypeError('flow_label_counts must be exactly an immutable tuple')
        if len(self.flow_label_counts) > IPV6_FLOW_LABEL_MAX_BINS:
            raise ValueError('flow_label_counts exceeds its structural bin bound')
        previous = -1
        for item in self.flow_label_counts:
            if type(item) is not tuple or len(item) != 2:
                raise TypeError('flow_label_counts must contain exact (value, count) tuples')
            value, count = item
            if type(value) is not int or type(count) is not int:
                raise TypeError('flow_label_counts values and counts must be exact integers')
            if not previous < value < IPV6_FLOW_LABEL_VALUES:
                raise ValueError('flow_label_counts values must be strictly ordered within their wire domain')
            if count <= 0:
                raise ValueError('flow_label_counts counts must be positive')
            previous = value
        if type(self.saturated_packet_count) is not int:
            raise TypeError('saturated_packet_count must be an exact integer')
        if self.saturated_packet_count < 0:
            raise ValueError('saturated_packet_count must not be negative')
        if self.saturated_packet_count:
            if self.flow_label_counts:
                raise ValueError('a saturated aggregate cannot retain exact bins')
            if self.saturated_packet_count <= IPV6_FLOW_LABEL_MAX_BINS:
                raise ValueError('saturated_packet_count must exceed the structural bin bound')

    @property
    def saturated(self) -> bool:
        return self.saturated_packet_count > 0

    @property
    def packet_count(self) -> int:
        return sum(count for _, count in self.flow_label_counts) + self.saturated_packet_count


@dataclass(frozen=True)
class DirectionalIPv6FlowLabelStatistics:
    forward: IPv6FlowLabelStatistics = IPv6FlowLabelStatistics()
    reverse: IPv6FlowLabelStatistics = IPv6FlowLabelStatistics()

    def __post_init__(self) -> None:
        if type(self.forward) is not IPv6FlowLabelStatistics or type(self.reverse) is not IPv6FlowLabelStatistics:
            raise TypeError('directions must contain exact IPv6FlowLabelStatistics values')


def _increment(current: IPv6FlowLabelStatistics, value: int) -> IPv6FlowLabelStatistics:
    if current.saturated:
        return IPv6FlowLabelStatistics((), current.saturated_packet_count + 1)
    bins = current.flow_label_counts
    for index, (existing, count) in enumerate(bins):
        if existing == value:
            return IPv6FlowLabelStatistics(bins[:index] + ((value, count + 1),) + bins[index + 1:])
        if existing > value:
            break
    else:
        index = len(bins)
    if len(bins) == IPV6_FLOW_LABEL_MAX_BINS:
        return IPv6FlowLabelStatistics((), current.packet_count + 1)
    return IPv6FlowLabelStatistics(bins[:index] + ((value, 1),) + bins[index:])


def _validate_packet(packet) -> IPv6Packet:
    if type(packet) is not IPv6Packet:
        raise TypeError('IPv6 Flow Label statistics require exactly an IPv6Packet')
    for name, minimum, maximum in (('version', 6, 6), ('flow_label', 0, IPV6_FLOW_LABEL_VALUES - 1)):
        value = getattr(packet, name)
        if type(value) is not int:
            raise TypeError(f'decoded IPv6 {name} must be exactly an integer')
        if not minimum <= value <= maximum:
            raise ValueError(f'decoded IPv6 {name} must be within {minimum} through {maximum}')
    return packet


def update_directional_ipv6_flow_label_statistics(
    current: Optional[DirectionalIPv6FlowLabelStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> DirectionalIPv6FlowLabelStatistics:
    if current is not None and type(current) is not DirectionalIPv6FlowLabelStatistics:
        raise TypeError('current must be exactly a DirectionalIPv6FlowLabelStatistics or None')
    if type(analysis) is not PacketAnalysis:
        raise TypeError('analysis must be exactly a PacketAnalysis')
    if type(identity) is not FlowIdentity:
        raise TypeError('identity must be exactly a FlowIdentity')
    current = DirectionalIPv6FlowLabelStatistics() if current is None else current
    if identity.ip_version != 6:
        if analysis.ipv6 is not None:
            raise ValueError('IPv4 flows cannot contribute IPv6 Flow Label observations')
        flow_direction_from_packet(analysis, identity)
        return current
    if analysis.ipv4 is not None:
        raise ValueError('IPv6 Flow Label statistics require exactly one IP family')
    packet = _validate_packet(analysis.ipv6)
    direction = flow_direction_from_packet(analysis, identity)
    name = 'forward' if direction is FlowDirection.FORWARD else 'reverse'
    return replace(current, **{name: _increment(getattr(current, name), packet.flow_label)})
