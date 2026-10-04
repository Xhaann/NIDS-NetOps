from dataclasses import dataclass, replace
from typing import Optional

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity
from analysis.ipv6 import IPv6Packet
from analysis.packet_analysis import PacketAnalysis


IPV6_TRAFFIC_CLASS_BINS = 256


@dataclass(frozen=True)
class IPv6TrafficClassStatistics:
    traffic_class_counts: tuple[tuple[int, int], ...] = ()

    def __post_init__(self) -> None:
        if type(self.traffic_class_counts) is not tuple:
            raise TypeError('traffic_class_counts must be exactly an immutable tuple')
        if len(self.traffic_class_counts) > IPV6_TRAFFIC_CLASS_BINS:
            raise ValueError('traffic_class_counts exceeds its wire domain')
        previous = -1
        for item in self.traffic_class_counts:
            if type(item) is not tuple or len(item) != 2:
                raise TypeError('traffic_class_counts must contain exact (value, count) tuples')
            value, count = item
            if type(value) is not int or type(count) is not int:
                raise TypeError('traffic_class_counts values and counts must be exact integers')
            if not previous < value < IPV6_TRAFFIC_CLASS_BINS:
                raise ValueError('traffic_class_counts values must be strictly ordered within their wire domain')
            if count <= 0:
                raise ValueError('traffic_class_counts counts must be positive')
            previous = value

    @property
    def packet_count(self) -> int:
        return sum(count for _, count in self.traffic_class_counts)


@dataclass(frozen=True)
class DirectionalIPv6TrafficClassStatistics:
    forward: IPv6TrafficClassStatistics = IPv6TrafficClassStatistics()
    reverse: IPv6TrafficClassStatistics = IPv6TrafficClassStatistics()

    def __post_init__(self) -> None:
        if type(self.forward) is not IPv6TrafficClassStatistics or type(self.reverse) is not IPv6TrafficClassStatistics:
            raise TypeError('directions must contain exact IPv6TrafficClassStatistics values')


def _increment(current: IPv6TrafficClassStatistics, value: int) -> IPv6TrafficClassStatistics:
    bins = current.traffic_class_counts
    for index, (existing, count) in enumerate(bins):
        if existing == value:
            return IPv6TrafficClassStatistics(bins[:index] + ((value, count + 1),) + bins[index + 1:])
        if existing > value:
            return IPv6TrafficClassStatistics(bins[:index] + ((value, 1),) + bins[index:])
    return IPv6TrafficClassStatistics(bins + ((value, 1),))


def _validate_packet(packet) -> IPv6Packet:
    if type(packet) is not IPv6Packet:
        raise TypeError('IPv6 Traffic Class statistics require exactly an IPv6Packet')
    for name, minimum, maximum in (('version', 6, 6), ('traffic_class', 0, 255)):
        value = getattr(packet, name)
        if type(value) is not int:
            raise TypeError(f'decoded IPv6 {name} must be exactly an integer')
        if not minimum <= value <= maximum:
            raise ValueError(f'decoded IPv6 {name} must be within {minimum} through {maximum}')
    return packet


def update_directional_ipv6_traffic_class_statistics(
    current: Optional[DirectionalIPv6TrafficClassStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> DirectionalIPv6TrafficClassStatistics:
    if current is not None and type(current) is not DirectionalIPv6TrafficClassStatistics:
        raise TypeError('current must be exactly a DirectionalIPv6TrafficClassStatistics or None')
    if type(analysis) is not PacketAnalysis:
        raise TypeError('analysis must be exactly a PacketAnalysis')
    if type(identity) is not FlowIdentity:
        raise TypeError('identity must be exactly a FlowIdentity')
    current = DirectionalIPv6TrafficClassStatistics() if current is None else current
    if identity.ip_version != 6:
        if analysis.ipv6 is not None:
            raise ValueError('IPv4 flows cannot contribute IPv6 Traffic Class observations')
        flow_direction_from_packet(analysis, identity)
        return current
    if analysis.ipv4 is not None:
        raise ValueError('IPv6 Traffic Class statistics require exactly one IP family')
    packet = _validate_packet(analysis.ipv6)
    direction = flow_direction_from_packet(analysis, identity)
    name = 'forward' if direction is FlowDirection.FORWARD else 'reverse'
    return replace(current, **{name: _increment(getattr(current, name), packet.traffic_class)})
