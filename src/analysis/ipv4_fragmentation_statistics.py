from dataclasses import dataclass, fields, replace
from typing import Optional

from analysis.ethernet import EthernetDecodeError, decode_ethernet
from analysis.ipv4 import IPv4DecodeError, IPv4Packet, decode_ipv4
from analysis.ipv4_checksum import validate_ipv4_checksum
from analysis.packet_analysis_outcome import PacketAnalysisFailureClassification, PacketAnalysisOutcome


_TRANSPORT_PROTOCOLS = (1, 6, 17)

_CATEGORIES = ("unfragmented", "initial_fragment", "intermediate_fragment", "final_fragment")


@dataclass(frozen=True)
class IPv4FragmentationStatistics:
    unfragmented_packet_count: int = 0
    initial_fragment_packet_count: int = 0
    intermediate_fragment_packet_count: int = 0
    final_fragment_packet_count: int = 0
    unfragmented_df_packet_count: int = 0
    initial_fragment_df_packet_count: int = 0
    intermediate_fragment_df_packet_count: int = 0
    final_fragment_df_packet_count: int = 0
    reserved_flag_packet_count: int = 0

    def __post_init__(self) -> None:
        for member in fields(self):
            value = getattr(self, member.name)
            if type(value) is not int:
                raise TypeError(f'{member.name} must be exactly an integer')
            if value < 0:
                raise ValueError(f'{member.name} must not be negative')
        for category in _CATEGORIES:
            if getattr(self, f'{category}_df_packet_count') > getattr(self, f'{category}_packet_count'):
                raise ValueError(f'{category} DF count must not exceed its packet count')
        if self.reserved_flag_packet_count > self.packet_count:
            raise ValueError('reserved flag count must not exceed the IPv4 packet count')

    @property
    def packet_count(self) -> int:
        return sum(getattr(self, f'{category}_packet_count') for category in _CATEGORIES)

    @property
    def non_initial_fragment_packet_count(self) -> int:
        return self.intermediate_fragment_packet_count + self.final_fragment_packet_count

    @property
    def fragment_packet_count(self) -> int:
        return self.initial_fragment_packet_count + self.non_initial_fragment_packet_count

    @property
    def more_fragments_packet_count(self) -> int:
        return self.initial_fragment_packet_count + self.intermediate_fragment_packet_count

    @property
    def dont_fragment_packet_count(self) -> int:
        return sum(getattr(self, f'{category}_df_packet_count') for category in _CATEGORIES)


def _category(packet: IPv4Packet) -> str:
    more_fragments = packet.flags & 1
    if packet.fragment_offset == 0:
        return 'initial_fragment' if more_fragments else 'unfragmented'
    return 'intermediate_fragment' if more_fragments else 'final_fragment'


def _reduce(current: IPv4FragmentationStatistics, packet: IPv4Packet) -> IPv4FragmentationStatistics:
    category = _category(packet)
    changes = {f'{category}_packet_count': getattr(current, f'{category}_packet_count') + 1}
    if packet.flags >> 1 & 1:
        name = f'{category}_df_packet_count'
        changes[name] = getattr(current, name) + 1
    if packet.flags >> 2 & 1:
        changes['reserved_flag_packet_count'] = current.reserved_flag_packet_count + 1
    return replace(current, **changes)


def _non_initial_fragment(outcome: PacketAnalysisOutcome) -> Optional[IPv4Packet]:
    if outcome.failure_classification is not PacketAnalysisFailureClassification.UNSUPPORTED:
        return None
    try:
        packet = decode_ipv4(decode_ethernet(outcome.observation))
    except (EthernetDecodeError, IPv4DecodeError):
        return None
    if (
        packet.fragment_offset == 0
        or packet.protocol not in _TRANSPORT_PROTOCOLS
        or not validate_ipv4_checksum(packet)
    ):
        return None
    return packet


def update_ipv4_fragmentation_statistics(
    current: Optional[IPv4FragmentationStatistics],
    outcome: PacketAnalysisOutcome,
) -> IPv4FragmentationStatistics:
    if current is not None and type(current) is not IPv4FragmentationStatistics:
        raise TypeError('current must be exactly an IPv4FragmentationStatistics or None')
    if type(outcome) is not PacketAnalysisOutcome:
        raise TypeError('outcome must be exactly a PacketAnalysisOutcome')
    current = IPv4FragmentationStatistics() if current is None else current
    packet = outcome.analysis.ipv4 if outcome.analysis is not None else _non_initial_fragment(outcome)
    if packet is None:
        return current
    return _reduce(current, packet)
