from struct import pack

from analysis.ipv4 import IPv4Packet
from analysis.udp import UDPPacket


class UDPChecksumValidationError(ValueError):
    pass


def validate_udp_checksum(packet: IPv4Packet, datagram: UDPPacket) -> bool:
    if not isinstance(packet, IPv4Packet):
        raise TypeError("packet must be an IPv4Packet")
    if not isinstance(datagram, UDPPacket):
        raise TypeError("datagram must be a UDPPacket")
    if packet.protocol != 17:
        raise UDPChecksumValidationError("UDP checksum validation requires IPv4 protocol 17")
    if packet.fragment_offset != 0:
        raise UDPChecksumValidationError(
            "UDP checksum validation requires an initial IPv4 fragment"
        )
    if datagram.length != 8 + len(datagram.payload):
        raise UDPChecksumValidationError("UDP length must equal 8 plus payload length")
    if datagram.checksum == 0:
        return False
    pseudo_header = pack(
        "!4s4sBBH",
        packet.source_address,
        packet.destination_address,
        0,
        packet.protocol,
        datagram.length,
    )
    header = pack(
        "!HHHH", datagram.source_port, datagram.destination_port, datagram.length, 0
    )
    checksum_bytes = pseudo_header + header + datagram.payload
    if len(checksum_bytes) % 2:
        checksum_bytes += b"\x00"
    total = sum(
        int.from_bytes(checksum_bytes[offset:offset + 2], byteorder="big")
        for offset in range(0, len(checksum_bytes), 2)
    )
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    checksum = (~total & 0xFFFF) or 0xFFFF
    return checksum == datagram.checksum
