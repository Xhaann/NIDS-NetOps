from struct import pack

from analysis.icmp import ICMPMessage
from analysis.ipv4 import IPv4Packet


class ICMPChecksumValidationError(ValueError):
    pass


def validate_icmp_checksum(packet: IPv4Packet, message: ICMPMessage) -> bool:
    if not isinstance(packet, IPv4Packet):
        raise TypeError("packet must be an IPv4Packet")
    if not isinstance(message, ICMPMessage):
        raise TypeError("message must be an ICMPMessage")
    if packet.protocol != 1:
        raise ICMPChecksumValidationError("ICMP checksum validation requires IPv4 protocol 1")
    if packet.fragment_offset != 0:
        raise ICMPChecksumValidationError(
            "ICMP checksum validation requires an initial IPv4 fragment"
        )
    header = pack("!BBH", message.icmp_type, message.code, 0) + message.rest_of_header
    checksum_bytes = header + message.payload
    if len(checksum_bytes) % 2:
        checksum_bytes += b"\x00"
    total = sum(
        int.from_bytes(checksum_bytes[offset:offset + 2], byteorder="big")
        for offset in range(0, len(checksum_bytes), 2)
    )
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total & 0xFFFF) == message.checksum
