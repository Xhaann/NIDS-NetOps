from dataclasses import dataclass, fields, replace
from typing import Optional

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity
from analysis.ipv6 import IPv6Packet
from analysis.ipv6_extension_header_statistics import IPV6_EXTENSION_HEADER_MAX_COUNT
from analysis.ipv6_extension_headers import IPv6ExtensionHeader, IPv6ExtensionHeaderChain
from analysis.ipv6_fragmentation import IPv6FragmentHeader, IPv6Fragmentation
from analysis.packet_analysis import PacketAnalysis


IPV6_FRAGMENT_HEADER_MAX_COUNT = IPV6_EXTENSION_HEADER_MAX_COUNT


@dataclass(frozen=True)
class IPv6FragmentationStatistics:
    ipv6_packet_count: int = 0
    fragment_header_packet_count: int = 0
    fragmented_packet_count: int = 0
    repeated_fragment_header_packet_count: int = 0
    first_fragment_header_count: int = 0
    atomic_fragment_header_count: int = 0
    nonzero_reserved_header_count: int = 0
    nonzero_reserved_bits_header_count: int = 0

    def __post_init__(self) -> None:
        for member in fields(self):
            value = getattr(self, member.name)
            if type(value) is not int:
                raise TypeError(f'{member.name} must be exactly an integer')
            if value < 0:
                raise ValueError(f'{member.name} must not be negative')
        packets = self.fragment_header_packet_count
        headers = self.fragment_header_count
        if packets > self.ipv6_packet_count:
            raise ValueError('Fragment Header packet count must not exceed IPv6 packet count')
        if self.fragmented_packet_count > packets or self.repeated_fragment_header_packet_count > packets:
            raise ValueError('fragment packet classes must not exceed Fragment Header packet count')
        if headers < packets + self.repeated_fragment_header_packet_count:
            raise ValueError('Fragment Header count is too small for its packet classes')
        if headers > packets * IPV6_FRAGMENT_HEADER_MAX_COUNT:
            raise ValueError('Fragment Header count exceeds the per-packet bound')
        if self.fragmented_packet_count > self.first_fragment_header_count:
            raise ValueError('fragmented packets require first-fragment headers')
        if self.first_fragment_header_count and not self.fragmented_packet_count:
            raise ValueError('first-fragment headers require a fragmented packet')
        if self.atomic_fragment_header_count < packets - self.fragmented_packet_count:
            raise ValueError('atomic-only packets require atomic-fragment headers')
        if max(self.nonzero_reserved_header_count, self.nonzero_reserved_bits_header_count) > headers:
            raise ValueError('reserved-field counts must not exceed Fragment Header count')

    @property
    def fragment_header_count(self) -> int:
        return self.first_fragment_header_count + self.atomic_fragment_header_count

    @property
    def fragment_header_absent_packet_count(self) -> int:
        return self.ipv6_packet_count - self.fragment_header_packet_count

    @property
    def atomic_fragment_packet_count(self) -> int:
        return self.fragment_header_packet_count - self.fragmented_packet_count

    @property
    def more_fragments_set_header_count(self) -> int:
        return self.first_fragment_header_count

    @property
    def more_fragments_clear_header_count(self) -> int:
        return self.atomic_fragment_header_count


@dataclass(frozen=True)
class DirectionalIPv6FragmentationStatistics:
    forward: IPv6FragmentationStatistics = IPv6FragmentationStatistics()
    reverse: IPv6FragmentationStatistics = IPv6FragmentationStatistics()

    def __post_init__(self) -> None:
        if type(self.forward) is not IPv6FragmentationStatistics:
            raise TypeError('forward must be exactly an IPv6FragmentationStatistics')
        if type(self.reverse) is not IPv6FragmentationStatistics:
            raise TypeError('reverse must be exactly an IPv6FragmentationStatistics')


def _fragment_headers(analysis):
    packet = analysis.ipv6
    chain = analysis.ipv6_extension_headers
    fragmentation = analysis.ipv6_fragmentation
    if type(packet) is not IPv6Packet:
        raise TypeError('IPv6 analysis must contain exactly an IPv6Packet')
    if type(chain) is not IPv6ExtensionHeaderChain or chain.packet is not packet:
        raise ValueError('IPv6 fragmentation statistics require the exact packet chain')
    if type(chain.headers) is not tuple:
        raise TypeError('IPv6 extension headers must be exactly an immutable tuple')
    if len(chain.headers) > IPV6_EXTENSION_HEADER_MAX_COUNT:
        raise ValueError('IPv6 extension-header chain exceeds its bound')
    for entry in chain.headers:
        if type(entry) is not IPv6ExtensionHeader:
            raise TypeError('IPv6 extension headers must contain exact IPv6ExtensionHeader values')
    entries = tuple(entry for entry in chain.headers if entry.header_type == 44)
    if fragmentation is None:
        if entries:
            raise ValueError('Fragment Headers require the exact fragmentation analysis')
        return ()
    if type(fragmentation) is not IPv6Fragmentation or fragmentation.extension_headers is not chain:
        raise ValueError('IPv6 fragmentation statistics require the exact fragmentation context')
    headers = fragmentation.headers
    if type(headers) is not tuple:
        raise TypeError('Fragment Header views must be exactly an immutable tuple')
    if len(headers) != len(entries):
        raise ValueError('Fragment Header views must match the extension-header chain')
    for header, entry in zip(headers, entries):
        if type(header) is not IPv6FragmentHeader:
            raise TypeError('Fragment Header views must contain exact IPv6FragmentHeader values')
        if header.extension_header is not entry:
            raise ValueError('Fragment Header views must retain their exact chain entries')
        if entry.declared_length != 8 or type(entry.raw_bytes) is not bytes or len(entry.raw_bytes) != 8:
            raise ValueError('Fragment Header length is inconsistent')
        if type(header.more_fragments) is not bool:
            raise TypeError('Fragment Header M flag must be exactly a boolean')
        offset = header.fragment_offset
        if type(offset) is not int or not 0 <= offset <= 8191:
            raise ValueError('Fragment Header offset exceeds its thirteen-bit domain')
        if offset:
            raise ValueError('flow-admitted IPv6 fragmentation requires initial Fragment Headers')
    return headers


def _reduce(current, headers):
    first = sum(1 for header in headers if header.more_fragments)
    return IPv6FragmentationStatistics(
        ipv6_packet_count=current.ipv6_packet_count + 1,
        fragment_header_packet_count=current.fragment_header_packet_count + int(bool(headers)),
        fragmented_packet_count=current.fragmented_packet_count + int(bool(first)),
        repeated_fragment_header_packet_count=current.repeated_fragment_header_packet_count + int(len(headers) > 1),
        first_fragment_header_count=current.first_fragment_header_count + first,
        atomic_fragment_header_count=current.atomic_fragment_header_count + len(headers) - first,
        nonzero_reserved_header_count=current.nonzero_reserved_header_count
        + sum(1 for header in headers if header.reserved),
        nonzero_reserved_bits_header_count=current.nonzero_reserved_bits_header_count
        + sum(1 for header in headers if header.reserved_bits),
    )


def update_directional_ipv6_fragmentation_statistics(
    current: Optional[DirectionalIPv6FragmentationStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> DirectionalIPv6FragmentationStatistics:
    if current is not None and type(current) is not DirectionalIPv6FragmentationStatistics:
        raise TypeError('current must be exactly a DirectionalIPv6FragmentationStatistics or None')
    if type(analysis) is not PacketAnalysis:
        raise TypeError('analysis must be exactly a PacketAnalysis')
    if type(identity) is not FlowIdentity:
        raise TypeError('identity must be exactly a FlowIdentity')
    current = DirectionalIPv6FragmentationStatistics() if current is None else current
    if analysis.ipv6 is None:
        if analysis.ipv6_extension_headers is not None or analysis.ipv6_fragmentation is not None:
            raise ValueError('IPv4 analysis cannot contribute IPv6 fragmentation metadata')
        flow_direction_from_packet(analysis, identity)
        return current
    headers = _fragment_headers(analysis)
    direction = flow_direction_from_packet(analysis, identity)
    name = 'forward' if direction is FlowDirection.FORWARD else 'reverse'
    return replace(current, **{name: _reduce(getattr(current, name), headers)})
