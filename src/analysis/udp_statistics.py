from dataclasses import dataclass, fields, replace
from typing import Optional

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity
from analysis.ipv4 import IPv4Packet
from analysis.ipv6 import IPv6Packet
from analysis.ipv6_extension_headers import IPv6ExtensionHeaderChain
from analysis.packet_analysis import PacketAnalysis
from analysis.udp import UDPPacket


UDP_MAX_PAYLOAD_LENGTH = 65527


@dataclass(frozen=True)
class UDPStatistics:
    datagram_count: int = 0
    empty_payload_datagram_count: int = 0
    min_payload_length: Optional[int] = None
    max_payload_length: Optional[int] = None
    total_payload_length: int = 0
    trailing_surplus_datagram_count: int = 0
    total_trailing_surplus_length: int = 0

    def __post_init__(self) -> None:
        for member in fields(self):
            value = getattr(self, member.name)
            if value is None and member.name in ('min_payload_length', 'max_payload_length'):
                continue
            if type(value) is not int:
                raise TypeError(f'{member.name} must be exactly an integer')
            if value < 0:
                raise ValueError(f'{member.name} must not be negative')
        count = self.datagram_count
        minimum, maximum = self.min_payload_length, self.max_payload_length
        if count == 0:
            if minimum is not None or maximum is not None:
                raise ValueError('empty UDP statistics require absent payload extrema')
        elif minimum is None or maximum is None:
            raise TypeError('observed UDP datagrams require exact integer payload extrema')
        elif not 0 <= minimum <= maximum <= UDP_MAX_PAYLOAD_LENGTH:
            raise ValueError('UDP payload extrema exceed the UDP length domain')
        elif not count * minimum <= self.total_payload_length <= count * maximum:
            raise ValueError('total UDP payload length is inconsistent with its extrema')
        for name in ('empty_payload_datagram_count', 'trailing_surplus_datagram_count'):
            if getattr(self, name) > count:
                raise ValueError(f'{name} must not exceed datagram_count')
        if count and (minimum == 0) != (self.empty_payload_datagram_count > 0):
            raise ValueError('empty-payload count must agree with the minimum payload length')
        if count and self.empty_payload_datagram_count == count and maximum != 0:
            raise ValueError('all-empty datagrams require a zero maximum payload length')
        surplus_count, surplus = self.trailing_surplus_datagram_count, self.total_trailing_surplus_length
        if not surplus_count <= surplus <= surplus_count * UDP_MAX_PAYLOAD_LENGTH:
            raise ValueError('trailing surplus length is inconsistent with its datagram count')

    @property
    def nonempty_payload_datagram_count(self) -> int:
        return self.datagram_count - self.empty_payload_datagram_count


@dataclass(frozen=True)
class DirectionalUDPStatistics:
    forward: UDPStatistics = UDPStatistics()
    reverse: UDPStatistics = UDPStatistics()

    def __post_init__(self) -> None:
        if type(self.forward) is not UDPStatistics or type(self.reverse) is not UDPStatistics:
            raise TypeError('directions must contain exact UDPStatistics values')


def _ip_payload_length(analysis: PacketAnalysis) -> int:
    if analysis.ipv6 is None:
        packet = analysis.ipv4
        if type(packet) is not IPv4Packet:
            raise TypeError('IPv4 UDP statistics require exactly an IPv4Packet')
        return packet.total_length - packet.header_length
    packet = analysis.ipv6
    chain = analysis.ipv6_extension_headers
    if type(packet) is not IPv6Packet:
        raise TypeError('IPv6 UDP statistics require exactly an IPv6Packet')
    if type(chain) is not IPv6ExtensionHeaderChain or chain.packet is not packet:
        raise ValueError('IPv6 UDP statistics require the exact packet chain')
    extent = 0
    if chain.headers:
        last = chain.headers[-1]
        extent = last.offset + last.declared_length - packet.header_length
    return packet.payload_length - extent


def _reduce(current: UDPStatistics, payload_length: int, surplus: int) -> UDPStatistics:
    count = current.datagram_count
    return UDPStatistics(
        datagram_count=count + 1,
        empty_payload_datagram_count=current.empty_payload_datagram_count + int(payload_length == 0),
        min_payload_length=payload_length if count == 0 else min(current.min_payload_length, payload_length),
        max_payload_length=payload_length if count == 0 else max(current.max_payload_length, payload_length),
        total_payload_length=current.total_payload_length + payload_length,
        trailing_surplus_datagram_count=current.trailing_surplus_datagram_count + int(surplus > 0),
        total_trailing_surplus_length=current.total_trailing_surplus_length + surplus,
    )


def update_directional_udp_statistics(
    current: Optional[DirectionalUDPStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> DirectionalUDPStatistics:
    if current is not None and type(current) is not DirectionalUDPStatistics:
        raise TypeError('current must be exactly a DirectionalUDPStatistics or None')
    if type(analysis) is not PacketAnalysis:
        raise TypeError('analysis must be exactly a PacketAnalysis')
    if type(identity) is not FlowIdentity:
        raise TypeError('identity must be exactly a FlowIdentity')
    current = DirectionalUDPStatistics() if current is None else current
    if identity.protocol != 17:
        if analysis.udp is not None or analysis.ipv6_udp is not None:
            raise ValueError('non-UDP flows cannot contribute UDP observations')
        flow_direction_from_packet(analysis, identity)
        return current
    datagram = analysis.udp if analysis.ipv6 is None else analysis.ipv6_udp
    if type(datagram) is not UDPPacket:
        raise TypeError('UDP statistics require exactly a decoded UDPPacket')
    length = datagram.length
    if type(length) is not int:
        raise TypeError('decoded UDP length must be exactly an integer')
    if not 8 <= length <= 65535:
        raise ValueError('decoded UDP length must be within 8 through 65535')
    surplus = _ip_payload_length(analysis) - length
    if surplus < 0:
        raise ValueError('UDP length exceeds the decoded IP payload')
    if length - 8 > UDP_MAX_PAYLOAD_LENGTH or surplus > UDP_MAX_PAYLOAD_LENGTH:
        raise ValueError('UDP payload and surplus lengths exceed the UDP length domain')
    direction = flow_direction_from_packet(analysis, identity)
    name = 'forward' if direction is FlowDirection.FORWARD else 'reverse'
    return replace(current, **{name: _reduce(getattr(current, name), length - 8, surplus)})
