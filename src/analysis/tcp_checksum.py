from struct import pack

from analysis.ipv4 import IPv4Packet
from analysis.tcp import TCPPacket


class TCPChecksumValidationError(ValueError):
    pass


def validate_tcp_checksum(packet: IPv4Packet, segment: TCPPacket) -> bool:
    if not isinstance(packet, IPv4Packet):
        raise TypeError("packet must be an IPv4Packet")
    if not isinstance(segment, TCPPacket):
        raise TypeError("segment must be a TCPPacket")
    if packet.protocol != 6:
        raise TCPChecksumValidationError("TCP checksum validation requires IPv4 protocol 6")
    if packet.fragment_offset != 0:
        raise TCPChecksumValidationError(
            "TCP checksum validation requires an initial IPv4 fragment"
        )
    segment_length = segment.header_length + len(segment.payload)
    if segment_length > 65535:
        raise TCPChecksumValidationError("TCP segment length exceeds 65535 bytes")
    control_field = (
        (segment.data_offset << 12)
        | (segment.reserved_bits << 9)
        | (segment.ns << 8)
        | (segment.cwr << 7)
        | (segment.ece << 6)
        | (segment.urg << 5)
        | (segment.ack << 4)
        | (segment.psh << 3)
        | (segment.rst << 2)
        | (segment.syn << 1)
        | segment.fin
    )
    header = pack(
        "!HHIIHHHH",
        segment.source_port,
        segment.destination_port,
        segment.sequence_number,
        segment.acknowledgment_number,
        control_field,
        segment.window_size,
        0,
        segment.urgent_pointer,
    ) + segment.options
    pseudo_header = pack(
        "!4s4sBBH",
        packet.source_address,
        packet.destination_address,
        0,
        packet.protocol,
        segment_length,
    )
    checksum_bytes = pseudo_header + header + segment.payload
    if len(checksum_bytes) % 2:
        checksum_bytes += b"\x00"
    total = sum(
        int.from_bytes(checksum_bytes[offset:offset + 2], byteorder="big")
        for offset in range(0, len(checksum_bytes), 2)
    )
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total & 0xFFFF) == segment.checksum
