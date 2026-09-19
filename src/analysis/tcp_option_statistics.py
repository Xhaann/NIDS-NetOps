from dataclasses import dataclass, fields, replace

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity
from analysis.packet_analysis import PacketAnalysis
from analysis.tcp import TCPPacket, _validate_tcp_options


TCP_OPTION_MAX_BYTES = 40
TCP_OPTION_MAX_COUNT = 40
TCP_OPTION_KIND_BINS = 256
TCP_OPTION_MSS_BINS = 65536
TCP_OPTION_WINDOW_SCALE_BINS = 256
TCP_OPTION_MAX_SACK_BLOCKS = 4


def _validate_bins(value, limit, name):
    if type(value) is not tuple:
        raise TypeError(f'{name} must be exactly an immutable tuple')
    if len(value) > limit:
        raise ValueError(f'{name} exceeds its wire-domain cardinality')
    previous = -1
    total = 0
    for item in value:
        if type(item) is not tuple or len(item) != 2:
            raise TypeError(f'{name} must contain exact (value, count) tuples')
        index, count = item
        if type(index) is not int or type(count) is not int:
            raise TypeError(f'{name} values and counts must be exact integers')
        if not previous < index < limit or count <= 0:
            raise ValueError(f'{name} requires ordered wire values and positive counts')
        previous = index
        total += count
    return total


@dataclass(frozen=True)
class TCPOptionStatistics:
    tcp_packet_count: int = 0
    malformed_option_packet_count: int = 0
    packets_with_options: int = 0
    total_option_bytes: int = 0
    option_kind_counts: tuple[tuple[int, int], ...] = ()
    duplicate_option_count: int = 0
    mss_value_counts: tuple[tuple[int, int], ...] = ()
    window_scale_counts: tuple[tuple[int, int], ...] = ()
    sack_block_count: int = 0

    def __post_init__(self) -> None:
        for member in fields(self):
            if member.name.endswith('_counts'):
                continue
            value = getattr(self, member.name)
            if type(value) is not int:
                raise TypeError(f'{member.name} must be exactly an integer')
            if value < 0:
                raise ValueError(f'{member.name} must not be negative')
        count = _validate_bins(self.option_kind_counts, TCP_OPTION_KIND_BINS, 'option_kind_counts')
        mss_count = _validate_bins(self.mss_value_counts, TCP_OPTION_MSS_BINS, 'mss_value_counts')
        scale_count = _validate_bins(self.window_scale_counts, TCP_OPTION_WINDOW_SCALE_BINS, 'window_scale_counts')
        if self.malformed_option_packet_count > self.tcp_packet_count:
            raise ValueError('malformed packet count must not exceed TCP packet count')
        if self.packets_with_options > self.complete_option_packet_count:
            raise ValueError('packets with options must not exceed complete packet count')
        if not 4 * self.packets_with_options <= self.total_option_bytes <= TCP_OPTION_MAX_BYTES * self.packets_with_options:
            raise ValueError('option bytes must fit the observed TCP option areas')
        if self.total_option_bytes % 4:
            raise ValueError('TCP option areas must be aligned to four bytes')
        if not self.packets_with_options <= count <= TCP_OPTION_MAX_COUNT * self.packets_with_options:
            raise ValueError('option count must fit the observed TCP option areas')
        kinds = dict(self.option_kind_counts)
        if mss_count != kinds.get(2, 0) or scale_count != kinds.get(3, 0):
            raise ValueError('MSS and window scale distributions must match their option counts')
        if kinds.get(0, 0) > self.packets_with_options:
            raise ValueError('each option area may contain at most one EOL')
        sack_count = kinds.get(5, 0)
        if not sack_count <= self.sack_block_count <= TCP_OPTION_MAX_SACK_BLOCKS * sack_count:
            raise ValueError('SACK block count must fit the observed SACK options')
        nonpadding = count - kinds.get(0, 0) - kinds.get(1, 0)
        if self.duplicate_option_count > max(0, nonpadding - sum(kind > 1 for kind in kinds)):
            raise ValueError('duplicate count must fit non-padding option occurrences')
        minimum_bytes = sum(amount * {0: 1, 1: 1, 2: 4, 3: 3, 4: 2, 5: 2, 8: 10}.get(kind, 2)
                            for kind, amount in self.option_kind_counts) + 8 * self.sack_block_count
        if minimum_bytes > self.total_option_bytes:
            raise ValueError('option structures exceed the observed option bytes')
        if self.sack_block_count > TCP_OPTION_MAX_SACK_BLOCKS * self.packets_with_options:
            raise ValueError('SACK blocks exceed the per-packet bound')

    @property
    def complete_option_packet_count(self) -> int:
        return self.tcp_packet_count - self.malformed_option_packet_count

    @property
    def timestamp_option_count(self) -> int:
        return next((count for kind, count in self.option_kind_counts if kind == 8), 0)

    @property
    def sack_permitted_option_count(self) -> int:
        return next((count for kind, count in self.option_kind_counts if kind == 4), 0)


@dataclass(frozen=True)
class DirectionalTCPOptionStatistics:
    forward: TCPOptionStatistics = TCPOptionStatistics()
    reverse: TCPOptionStatistics = TCPOptionStatistics()

    def __post_init__(self) -> None:
        if type(self.forward) is not TCPOptionStatistics or type(self.reverse) is not TCPOptionStatistics:
            raise TypeError('directions must contain exact TCPOptionStatistics values')


def _summarize_options(tcp):
    if type(tcp) is not TCPPacket:
        raise TypeError('TCP option statistics require exactly a TCPPacket')
    options = tcp.options
    if type(options) is not bytes or type(tcp.data_offset) is not int:
        raise TypeError('TCP options and data offset must have exact built-in types')
    if not 5 <= tcp.data_offset <= 15 or len(options) > TCP_OPTION_MAX_BYTES:
        raise ValueError('TCP option area exceeds its header bound')
    if len(options) != (tcp.data_offset - 5) * 4:
        raise ValueError('TCP option area must match data offset')
    _validate_tcp_options(tcp)
    kinds, mss, scales = {}, {}, {}
    duplicates = 0
    blocks = 0
    offset = 0
    while offset < len(options):
        kind = options[offset]
        length = 1 if kind in (0, 1) else options[offset + 1]
        if kind in (2, 3, 4, 8) and length != {2: 4, 3: 3, 4: 2, 8: 10}[kind]:
            return None
        if kind == 5:
            if length < 10 or (length - 2) % 8:
                return None
            blocks += (length - 2) // 8
        if kind > 1 and kind in kinds:
            duplicates += 1
        kinds[kind] = kinds.get(kind, 0) + 1
        if kind == 2:
            value = int.from_bytes(options[offset + 2:offset + 4], 'big')
            mss[value] = mss.get(value, 0) + 1
        elif kind == 3:
            value = options[offset + 2]
            scales[value] = scales.get(value, 0) + 1
        offset += length
        if kind == 0:
            break
    return kinds, mss, scales, duplicates, blocks


def _merge_bins(current, addition):
    values = dict(current)
    for value, count in addition.items():
        values[value] = values.get(value, 0) + count
    return tuple(sorted(values.items()))


def _reduce(current, tcp):
    summary = _summarize_options(tcp)
    if summary is None:
        return replace(current, tcp_packet_count=current.tcp_packet_count + 1,
                       malformed_option_packet_count=current.malformed_option_packet_count + 1)
    kinds, mss, scales, duplicates, blocks = summary
    return TCPOptionStatistics(
        tcp_packet_count=current.tcp_packet_count + 1,
        malformed_option_packet_count=current.malformed_option_packet_count,
        packets_with_options=current.packets_with_options + int(bool(tcp.options)),
        total_option_bytes=current.total_option_bytes + len(tcp.options),
        option_kind_counts=_merge_bins(current.option_kind_counts, kinds),
        duplicate_option_count=current.duplicate_option_count + duplicates,
        mss_value_counts=_merge_bins(current.mss_value_counts, mss),
        window_scale_counts=_merge_bins(current.window_scale_counts, scales),
        sack_block_count=current.sack_block_count + blocks,
    )


def update_directional_tcp_option_statistics(current, analysis, identity):
    if current is not None and type(current) is not DirectionalTCPOptionStatistics:
        raise TypeError('current must be exactly a DirectionalTCPOptionStatistics or None')
    if type(analysis) is not PacketAnalysis:
        raise TypeError('analysis must be exactly a PacketAnalysis')
    if type(identity) is not FlowIdentity:
        raise TypeError('identity must be exactly a FlowIdentity')
    direction = flow_direction_from_packet(analysis, identity)
    current = DirectionalTCPOptionStatistics() if current is None else current
    if identity.protocol != 6:
        return current
    tcp = analysis.tcp if identity.ip_version == 4 else analysis.ipv6_tcp
    name = 'forward' if direction is FlowDirection.FORWARD else 'reverse'
    return replace(current, **{name: _reduce(getattr(current, name), tcp)})
