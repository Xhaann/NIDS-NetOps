from dataclasses import dataclass, replace
from fractions import Fraction
from typing import Optional

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity
from analysis.ipv4 import IPv4Packet
from analysis.ipv6 import IPv6Packet
from analysis.packet_analysis import PacketAnalysis


IP_HOP_LIMIT_BINS = 256


@dataclass(frozen=True)
class IPHopLimitStatistics:
    hop_limit_counts: tuple[tuple[int, int], ...] = ()

    def __post_init__(self) -> None:
        if type(self.hop_limit_counts) is not tuple:
            raise TypeError('hop_limit_counts must be exactly an immutable tuple')
        if len(self.hop_limit_counts) > IP_HOP_LIMIT_BINS:
            raise ValueError('hop_limit_counts exceeds the eight-bit wire domain')
        previous = -1
        for item in self.hop_limit_counts:
            if type(item) is not tuple or len(item) != 2:
                raise TypeError('hop_limit_counts must contain exact (value, count) tuples')
            value, count = item
            if type(value) is not int or type(count) is not int:
                raise TypeError('hop-limit values and counts must be exact integers')
            if not previous < value < IP_HOP_LIMIT_BINS:
                raise ValueError('hop-limit values must be strictly ordered within 0 through 255')
            if count <= 0:
                raise ValueError('occupied hop-limit bins must have positive counts')
            previous = value

    @property
    def packet_count(self) -> int:
        return sum(count for _, count in self.hop_limit_counts)

    @property
    def distinct_hop_limit_count(self) -> int:
        return len(self.hop_limit_counts)

    @property
    def min_hop_limit(self) -> Optional[int]:
        return self.hop_limit_counts[0][0] if self.hop_limit_counts else None

    @property
    def max_hop_limit(self) -> Optional[int]:
        return self.hop_limit_counts[-1][0] if self.hop_limit_counts else None

    @property
    def total_hop_limit(self) -> int:
        return sum(value * count for value, count in self.hop_limit_counts)

    @property
    def mean_hop_limit(self) -> Optional[Fraction]:
        return Fraction(self.total_hop_limit, self.packet_count) if self.hop_limit_counts else None

    @property
    def zero_hop_limit_packet_count(self) -> int:
        if self.hop_limit_counts and self.hop_limit_counts[0][0] == 0:
            return self.hop_limit_counts[0][1]
        return 0


@dataclass(frozen=True)
class DirectionalIPHopLimitStatistics:
    forward: IPHopLimitStatistics = IPHopLimitStatistics()
    reverse: IPHopLimitStatistics = IPHopLimitStatistics()

    def __post_init__(self) -> None:
        if type(self.forward) is not IPHopLimitStatistics or type(self.reverse) is not IPHopLimitStatistics:
            raise TypeError('directions must contain exact IPHopLimitStatistics values')


def _increment(current: IPHopLimitStatistics, value: int) -> IPHopLimitStatistics:
    bins = []
    inserted = False
    for index, count in current.hop_limit_counts:
        if not inserted and value <= index:
            bins.append((value, count + 1 if value == index else 1))
            inserted = True
            if value == index:
                continue
        bins.append((index, count))
    if not inserted:
        bins.append((value, 1))
    return IPHopLimitStatistics(tuple(bins))


def update_directional_ip_hop_limit_statistics(
    current: Optional[DirectionalIPHopLimitStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> DirectionalIPHopLimitStatistics:
    if current is not None and type(current) is not DirectionalIPHopLimitStatistics:
        raise TypeError('current must be exactly a DirectionalIPHopLimitStatistics or None')
    if type(analysis) is not PacketAnalysis:
        raise TypeError('analysis must be exactly a PacketAnalysis')
    if type(identity) is not FlowIdentity:
        raise TypeError('identity must be exactly a FlowIdentity')
    if analysis.ipv4 is not None and analysis.ipv6 is not None:
        raise ValueError('hop-limit statistics require exactly one IP family')
    network = analysis.ipv6 if analysis.ipv6 is not None else analysis.ipv4
    expected = IPv6Packet if analysis.ipv6 is not None else IPv4Packet
    if type(network) is not expected:
        raise TypeError('hop-limit statistics require an exact decoded IP packet')
    version = 6 if expected is IPv6Packet else 4
    if type(network.version) is not int or network.version != version:
        raise ValueError("decoded IP version must match its packet model")
    value = network.hop_limit if expected is IPv6Packet else network.ttl
    if type(value) is not int:
        raise TypeError("decoded hop limit must be exactly an integer")
    if not 0 <= value < IP_HOP_LIMIT_BINS:
        raise ValueError("decoded hop limit must be within 0 through 255")
    direction = flow_direction_from_packet(analysis, identity)
    current = DirectionalIPHopLimitStatistics() if current is None else current
    name = 'forward' if direction is FlowDirection.FORWARD else 'reverse'
    return replace(current, **{name: _increment(getattr(current, name), value)})
