from dataclasses import dataclass, fields, replace

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity
from analysis.ipv6 import IPv6Packet
from analysis.ipv6_extension_headers import IPv6ExtensionHeader, IPv6ExtensionHeaderChain
from analysis.packet_analysis import PacketAnalysis


IPV6_EXTENSION_HEADER_MAX_COUNT = 8191
IPV6_EXTENSION_HEADER_TYPE_BINS = 256
IPV6_TERMINAL_NEXT_HEADER_BINS = 256
_EMPTY_BINS = ()
_EXTENSION_HEADER_TYPES = (0, 43, 44, 60)


def _validate_count(value, name):
    if type(value) is not int:
        raise TypeError(f'{name} must be exactly an integer')
    if value < 0:
        raise ValueError(f'{name} must not be negative')


def _validate_bins(value, size, name, total):
    if type(value) is not tuple:
        raise TypeError(f'{name} must be exactly an immutable tuple of occupied bins')
    previous = None
    counted = 0
    for item in value:
        if type(item) is not tuple or len(item) != 2:
            raise TypeError(f'{name} must contain exact (value, count) tuples')
        index, count = item
        if type(index) is not int or not 0 <= index < size:
            raise ValueError(f'{name} values must be within their wire domain')
        if type(count) is not int:
            raise TypeError(f'{name} counts must contain exact integers')
        if count <= 0:
            raise ValueError(f'{name} counts must be positive')
        if previous is not None and index <= previous:
            raise ValueError(f'{name} values must be strictly ordered')
        previous = index
        counted += count
    if counted != total:
        raise ValueError(f'{name} must sum to its total observation count')


def _validate_extrema(count, minimum, maximum, limit, name):
    if count == 0:
        if minimum is not None or maximum is not None:
            raise ValueError(f'empty {name} observations require absent extrema')
        return
    if type(minimum) is not int or type(maximum) is not int:
        raise TypeError(f'{name} extrema must be exact integers when observations exist')
    if not 0 <= minimum <= maximum <= limit:
        raise ValueError(f'{name} extrema exceed their parser bounds')


@dataclass(frozen=True)
class IPv6ExtensionHeaderStatistics:
    total_ipv6_packet_count: int = 0
    packets_with_extension_headers: int = 0
    min_extension_header_count: int = None
    max_extension_header_count: int = None
    total_extension_header_count: int = 0
    extension_header_type_counts: tuple[tuple[int, int], ...] = _EMPTY_BINS
    terminal_next_header_counts: tuple[tuple[int, int], ...] = _EMPTY_BINS
    duplicate_extension_header_count: int = 0

    def __post_init__(self) -> None:
        for member in fields(self):
            value = getattr(self, member.name)
            if member.name.endswith('_counts'):
                continue
            if value is None:
                if not member.name.startswith(('min_', 'max_')):
                    raise TypeError(f'{member.name} must be exactly an integer')
                continue
            _validate_count(value, member.name)
        _validate_bins(
            self.extension_header_type_counts,
            IPV6_EXTENSION_HEADER_TYPE_BINS,
            'extension_header_type_counts',
            self.total_extension_header_count,
        )
        _validate_bins(
            self.terminal_next_header_counts,
            IPV6_TERMINAL_NEXT_HEADER_BINS,
            'terminal_next_header_counts',
            self.total_ipv6_packet_count,
        )
        _validate_extrema(
            self.total_ipv6_packet_count,
            self.min_extension_header_count,
            self.max_extension_header_count,
            IPV6_EXTENSION_HEADER_MAX_COUNT,
            'extension header count',
        )
        if self.packets_with_extension_headers > self.total_ipv6_packet_count:
            raise ValueError('extension-header packet count must not exceed IPv6 packet count')
        if self.total_extension_header_count == 0 and self.packets_with_extension_headers != 0:
            raise ValueError('extension-header packet count requires extension headers')
        if self.total_extension_header_count and self.packets_with_extension_headers == 0:
            raise ValueError('extension headers require an extension-header packet')
        if self.total_extension_header_count > self.total_ipv6_packet_count * IPV6_EXTENSION_HEADER_MAX_COUNT:
            raise ValueError('total extension-header count exceeds the packet bound')
        if self.duplicate_extension_header_count > self.total_extension_header_count:
            raise ValueError('duplicate extension-header count must not exceed total extension-header count')

    @property
    def ipv6_packet_count(self) -> int:
        return self.total_ipv6_packet_count

    @property
    def extension_header_count(self) -> int:
        return self.total_extension_header_count

    @property
    def extension_header_type_frequency(self) -> tuple[tuple[int, int], ...]:
        return self.extension_header_type_counts

    @property
    def terminal_next_header_frequency(self) -> tuple[tuple[int, int], ...]:
        return self.terminal_next_header_counts

    @property
    def extension_header_absent_packet_count(self) -> int:
        return self.total_ipv6_packet_count - self.packets_with_extension_headers


@dataclass(frozen=True)
class DirectionalIPv6ExtensionHeaderStatistics:
    forward: IPv6ExtensionHeaderStatistics = IPv6ExtensionHeaderStatistics()
    reverse: IPv6ExtensionHeaderStatistics = IPv6ExtensionHeaderStatistics()

    def __post_init__(self) -> None:
        if type(self.forward) is not IPv6ExtensionHeaderStatistics:
            raise TypeError('forward must be exactly an IPv6ExtensionHeaderStatistics')
        if type(self.reverse) is not IPv6ExtensionHeaderStatistics:
            raise TypeError('reverse must be exactly an IPv6ExtensionHeaderStatistics')


def _validate_chain(analysis):
    if analysis.ipv6 is None:
        return None
    packet = analysis.ipv6
    chain = analysis.ipv6_extension_headers
    if type(packet) is not IPv6Packet:
        raise TypeError('IPv6 analysis must contain exactly an IPv6Packet')
    if type(chain) is not IPv6ExtensionHeaderChain or chain.packet is not packet:
        raise ValueError('IPv6 extension-header statistics require the exact packet chain')
    if type(chain.headers) is not tuple:
        raise TypeError('IPv6 extension headers must be exactly an immutable tuple')
    if len(chain.headers) > IPV6_EXTENSION_HEADER_MAX_COUNT:
        raise ValueError('IPv6 extension-header chain exceeds its bound')
    expected_type = packet.next_header
    payload_offset = 0
    for header in chain.headers:
        if type(header) is not IPv6ExtensionHeader:
            raise TypeError('IPv6 extension headers must contain exact IPv6ExtensionHeader values')
        if header.header_type != expected_type:
            raise ValueError('IPv6 extension-header ordering is inconsistent')
        if header.offset != packet.header_length + payload_offset:
            raise ValueError('IPv6 extension-header offset is inconsistent')
        if header.declared_length is None:
            raise ValueError('IPv6 extension-header length is inconsistent')
        if header.header_type == 44:
            if header.declared_length != 8:
                raise ValueError('IPv6 Fragment Header length is inconsistent')
        elif header.header_type in (0, 43, 60):
            if header.declared_length < 8 or header.declared_length % 8:
                raise ValueError('IPv6 extension-header length is inconsistent')
        else:
            raise ValueError('IPv6 extension-header type is unsupported')
        payload_offset += header.declared_length
        if payload_offset > packet.payload_length:
            raise ValueError('IPv6 extension-header extent exceeds the packet payload')
        expected_type = header.next_header
    if expected_type in _EXTENSION_HEADER_TYPES:
        raise ValueError('IPv6 extension-header chain is incomplete')
    if chain.terminating_next_header != expected_type:
        raise ValueError('IPv6 terminal Next Header is inconsistent')
    return chain


def _validate_inputs(current, analysis, identity):
    if current is not None and type(current) is not IPv6ExtensionHeaderStatistics:
        raise TypeError('current must be exactly an IPv6ExtensionHeaderStatistics or None')
    if type(analysis) is not PacketAnalysis:
        raise TypeError('analysis must be exactly a PacketAnalysis')
    if type(identity) is not FlowIdentity:
        raise TypeError('identity must be exactly a FlowIdentity')
    direction = flow_direction_from_packet(analysis, identity)
    return (IPv6ExtensionHeaderStatistics() if current is None else current), direction, _validate_chain(analysis)


def _reduce(current, chain):
    values = {member.name: getattr(current, member.name) for member in fields(current)}
    values['total_ipv6_packet_count'] += 1
    count = len(chain.headers)
    values['min_extension_header_count'] = (
        count if values['min_extension_header_count'] is None
        else min(values['min_extension_header_count'], count)
    )
    values['max_extension_header_count'] = (
        count if values['max_extension_header_count'] is None
        else max(values['max_extension_header_count'], count)
    )
    values['total_extension_header_count'] += count
    if count:
        values['packets_with_extension_headers'] += 1
    extension_counts = dict(values['extension_header_type_counts'])
    for header in chain.headers:
        extension_counts[header.header_type] = extension_counts.get(header.header_type, 0) + 1
    values['extension_header_type_counts'] = tuple(sorted(extension_counts.items()))
    terminal_counts = dict(values['terminal_next_header_counts'])
    terminal = chain.terminating_next_header
    terminal_counts[terminal] = terminal_counts.get(terminal, 0) + 1
    values['terminal_next_header_counts'] = tuple(sorted(terminal_counts.items()))
    values['duplicate_extension_header_count'] += count - len({header.header_type for header in chain.headers})
    return IPv6ExtensionHeaderStatistics(**values)


def update_ipv6_extension_header_statistics(current, analysis, identity):
    current, _, chain = _validate_inputs(current, analysis, identity)
    if chain is None:
        return current
    return _reduce(current, chain)


def update_directional_ipv6_extension_header_statistics(current, analysis, identity):
    if current is not None and type(current) is not DirectionalIPv6ExtensionHeaderStatistics:
        raise TypeError('current must be exactly a DirectionalIPv6ExtensionHeaderStatistics or None')
    previous = current
    _, direction, chain = _validate_inputs(
        None,
        analysis,
        identity,
    )
    directional = DirectionalIPv6ExtensionHeaderStatistics() if previous is None else previous
    if chain is None:
        return directional
    name = 'forward' if direction is FlowDirection.FORWARD else 'reverse'
    return replace(directional, **{name: _reduce(getattr(directional, name), chain)})
