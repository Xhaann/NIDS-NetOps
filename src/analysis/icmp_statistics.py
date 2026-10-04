from bisect import bisect_left
from dataclasses import dataclass, replace
from typing import Optional

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity
from analysis.icmp import ICMPMessage
from analysis.icmpv6 import ICMPv6Packet
from analysis.packet_analysis import PacketAnalysis


ICMP_TYPE_CODE_BINS = 65536
_ICMP_PROTOCOLS = (1, 58)


@dataclass(frozen=True)
class ICMPStatistics:
    type_code_counts: tuple[tuple[int, int, int], ...] = ()

    def __post_init__(self) -> None:
        if type(self.type_code_counts) is not tuple:
            raise TypeError('type_code_counts must be exactly an immutable tuple')
        if len(self.type_code_counts) > ICMP_TYPE_CODE_BINS:
            raise ValueError('type_code_counts exceeds the eight-bit type/code domain')
        previous = (-1, -1)
        for item in self.type_code_counts:
            if type(item) is not tuple or len(item) != 3:
                raise TypeError('type_code_counts must contain exact (type, code, count) tuples')
            icmp_type, code, count = item
            if type(icmp_type) is not int or type(code) is not int or type(count) is not int:
                raise TypeError('ICMP types, codes and counts must be exact integers')
            if not (0 <= icmp_type <= 255 and 0 <= code <= 255):
                raise ValueError('ICMP types and codes must be within 0 through 255')
            if (icmp_type, code) <= previous:
                raise ValueError('ICMP type/code bins must be strictly ordered')
            if count <= 0:
                raise ValueError('occupied ICMP type/code bins must have positive counts')
            previous = (icmp_type, code)

    @property
    def packet_count(self) -> int:
        return sum(count for _, _, count in self.type_code_counts)

    @property
    def distinct_type_code_count(self) -> int:
        return len(self.type_code_counts)

    @property
    def type_counts(self) -> tuple[tuple[int, int], ...]:
        counts = []
        for icmp_type, _, count in self.type_code_counts:
            if counts and counts[-1][0] == icmp_type:
                counts[-1] = (icmp_type, counts[-1][1] + count)
            else:
                counts.append((icmp_type, count))
        return tuple(counts)

    @property
    def distinct_type_count(self) -> int:
        return len(self.type_counts)


@dataclass(frozen=True)
class DirectionalICMPStatistics:
    forward: ICMPStatistics = ICMPStatistics()
    reverse: ICMPStatistics = ICMPStatistics()
    protocol: Optional[int] = None

    def __post_init__(self) -> None:
        if type(self.forward) is not ICMPStatistics or type(self.reverse) is not ICMPStatistics:
            raise TypeError('directions must contain exact ICMPStatistics values')
        if self.protocol is not None and (type(self.protocol) is not int or self.protocol not in _ICMP_PROTOCOLS):
            raise ValueError('protocol must be None, 1 or 58')
        empty = not self.forward.type_code_counts and not self.reverse.type_code_counts
        if empty != (self.protocol is None):
            raise ValueError('protocol must be present exactly when ICMP observations exist')


def _increment(current: ICMPStatistics, icmp_type: int, code: int) -> ICMPStatistics:
    bins = current.type_code_counts
    index = bisect_left(bins, (icmp_type, code))
    if index < len(bins) and bins[index][:2] == (icmp_type, code):
        entry = (icmp_type, code, bins[index][2] + 1)
        return ICMPStatistics(bins[:index] + (entry,) + bins[index + 1:])
    return ICMPStatistics(bins[:index] + ((icmp_type, code, 1),) + bins[index:])


def _message(analysis: PacketAnalysis, protocol: int):
    if protocol == 1:
        if analysis.ipv6 is not None or type(analysis.icmp) is not ICMPMessage:
            raise TypeError('ICMPv4 statistics require exactly a decoded ICMPMessage')
        return analysis.icmp
    if analysis.ipv4 is not None or type(analysis.ipv6_icmpv6) is not ICMPv6Packet:
        raise TypeError('ICMPv6 statistics require exactly a decoded ICMPv6Packet')
    return analysis.ipv6_icmpv6


def update_directional_icmp_statistics(
    current: Optional[DirectionalICMPStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> DirectionalICMPStatistics:
    if current is not None and type(current) is not DirectionalICMPStatistics:
        raise TypeError('current must be exactly a DirectionalICMPStatistics or None')
    if type(analysis) is not PacketAnalysis:
        raise TypeError('analysis must be exactly a PacketAnalysis')
    if type(identity) is not FlowIdentity:
        raise TypeError('identity must be exactly a FlowIdentity')
    current = DirectionalICMPStatistics() if current is None else current
    protocol = identity.protocol
    if current.protocol not in (None, protocol):
        raise ValueError('ICMP statistics protocol must match the flow identity')
    if protocol not in _ICMP_PROTOCOLS:
        if analysis.icmp is not None or analysis.ipv6_icmpv6 is not None:
            raise ValueError('non-ICMP flows cannot contribute ICMP observations')
        flow_direction_from_packet(analysis, identity)
        return current
    message = _message(analysis, protocol)
    icmp_type, code = message.icmp_type, message.code
    if type(icmp_type) is not int or type(code) is not int:
        raise TypeError('decoded ICMP type and code must be exact integers')
    if not (0 <= icmp_type <= 255 and 0 <= code <= 255):
        raise ValueError('decoded ICMP type and code must be within 0 through 255')
    direction = flow_direction_from_packet(analysis, identity)
    name = 'forward' if direction is FlowDirection.FORWARD else 'reverse'
    return replace(current, protocol=protocol, **{name: _increment(getattr(current, name), icmp_type, code)})
