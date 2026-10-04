from dataclasses import dataclass, fields, replace
from typing import Optional

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity
from analysis.ipv4 import IPv4Packet
from analysis.packet_analysis import PacketAnalysis


IPV4_DSCP_BINS = 64
IPV4_ECN_BINS = 4
IPV4_MAX_OPTIONS_LENGTH = 40


def _validate_bins(value, size, name):
    if type(value) is not tuple:
        raise TypeError(f'{name} must be exactly an immutable tuple')
    if len(value) > size:
        raise ValueError(f'{name} exceeds its wire domain')
    previous = -1
    total = 0
    for item in value:
        if type(item) is not tuple or len(item) != 2:
            raise TypeError(f'{name} must contain exact (value, count) tuples')
        index, count = item
        if type(index) is not int or type(count) is not int:
            raise TypeError(f'{name} values and counts must be exact integers')
        if not previous < index < size:
            raise ValueError(f'{name} values must be strictly ordered within their wire domain')
        if count <= 0:
            raise ValueError(f'{name} counts must be positive')
        previous = index
        total += count
    return total


@dataclass(frozen=True)
class IPv4HeaderStatistics:
    dscp_counts: tuple[tuple[int, int], ...] = ()
    ecn_counts: tuple[tuple[int, int], ...] = ()
    dont_fragment_packet_count: int = 0
    more_fragments_packet_count: int = 0
    reserved_flag_packet_count: int = 0
    options_packet_count: int = 0
    total_options_length: int = 0

    def __post_init__(self) -> None:
        packets = _validate_bins(self.dscp_counts, IPV4_DSCP_BINS, 'dscp_counts')
        if _validate_bins(self.ecn_counts, IPV4_ECN_BINS, 'ecn_counts') != packets:
            raise ValueError('DSCP and ECN distributions must count the same packets')
        for member in fields(self):
            if member.name.endswith('_counts'):
                continue
            value = getattr(self, member.name)
            if type(value) is not int:
                raise TypeError(f'{member.name} must be exactly an integer')
            if value < 0:
                raise ValueError(f'{member.name} must not be negative')
            if member.name.endswith('_packet_count') and value > packets:
                raise ValueError(f'{member.name} must not exceed the IPv4 packet count')
        options, length = self.options_packet_count, self.total_options_length
        if length % 4 or not 4 * options <= length <= IPV4_MAX_OPTIONS_LENGTH * options:
            raise ValueError('total options length is inconsistent with the options packet count')

    @property
    def packet_count(self) -> int:
        return sum(count for _, count in self.dscp_counts)

    @property
    def options_absent_packet_count(self) -> int:
        return self.packet_count - self.options_packet_count

    @property
    def ecn_capable_packet_count(self) -> int:
        return sum(count for value, count in self.ecn_counts if value in (1, 2))

    @property
    def congestion_experienced_packet_count(self) -> int:
        return sum(count for value, count in self.ecn_counts if value == 3)


@dataclass(frozen=True)
class DirectionalIPv4HeaderStatistics:
    forward: IPv4HeaderStatistics = IPv4HeaderStatistics()
    reverse: IPv4HeaderStatistics = IPv4HeaderStatistics()

    def __post_init__(self) -> None:
        if type(self.forward) is not IPv4HeaderStatistics or type(self.reverse) is not IPv4HeaderStatistics:
            raise TypeError('directions must contain exact IPv4HeaderStatistics values')


def _increment(bins, value):
    for index, (current, count) in enumerate(bins):
        if current == value:
            return bins[:index] + ((value, count + 1),) + bins[index + 1:]
        if current > value:
            return bins[:index] + ((value, 1),) + bins[index:]
    return bins + ((value, 1),)


def _reduce(current: IPv4HeaderStatistics, packet: IPv4Packet) -> IPv4HeaderStatistics:
    options_length = packet.header_length - 20
    return IPv4HeaderStatistics(
        dscp_counts=_increment(current.dscp_counts, packet.dscp),
        ecn_counts=_increment(current.ecn_counts, packet.ecn),
        dont_fragment_packet_count=current.dont_fragment_packet_count + (packet.flags >> 1 & 1),
        more_fragments_packet_count=current.more_fragments_packet_count + (packet.flags & 1),
        reserved_flag_packet_count=current.reserved_flag_packet_count + (packet.flags >> 2 & 1),
        options_packet_count=current.options_packet_count + int(options_length > 0),
        total_options_length=current.total_options_length + options_length,
    )


def _validate_packet(packet) -> IPv4Packet:
    if type(packet) is not IPv4Packet:
        raise TypeError('IPv4 header statistics require exactly an IPv4Packet')
    for name, minimum, maximum in (('version', 4, 4), ('ihl', 5, 15), ('dscp', 0, 63), ('ecn', 0, 3),
                                   ('flags', 0, 7), ('fragment_offset', 0, 8191)):
        value = getattr(packet, name)
        if type(value) is not int:
            raise TypeError(f'decoded IPv4 {name} must be exactly an integer')
        if not minimum <= value <= maximum:
            raise ValueError(f'decoded IPv4 {name} must be within {minimum} through {maximum}')
    if packet.fragment_offset:
        raise ValueError('flow-admitted IPv4 header statistics require an initial fragment')
    return packet


def update_directional_ipv4_header_statistics(
    current: Optional[DirectionalIPv4HeaderStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> DirectionalIPv4HeaderStatistics:
    if current is not None and type(current) is not DirectionalIPv4HeaderStatistics:
        raise TypeError('current must be exactly a DirectionalIPv4HeaderStatistics or None')
    if type(analysis) is not PacketAnalysis:
        raise TypeError('analysis must be exactly a PacketAnalysis')
    if type(identity) is not FlowIdentity:
        raise TypeError('identity must be exactly a FlowIdentity')
    current = DirectionalIPv4HeaderStatistics() if current is None else current
    if identity.ip_version != 4:
        if analysis.ipv4 is not None:
            raise ValueError('IPv6 flows cannot contribute IPv4 header observations')
        flow_direction_from_packet(analysis, identity)
        return current
    if analysis.ipv6 is not None:
        raise ValueError('IPv4 header statistics require exactly one IP family')
    packet = _validate_packet(analysis.ipv4)
    direction = flow_direction_from_packet(analysis, identity)
    name = 'forward' if direction is FlowDirection.FORWARD else 'reverse'
    return replace(current, **{name: _reduce(getattr(current, name), packet)})
