from struct import pack

from analysis.ipv4 import IPv4Packet


def validate_ipv4_checksum(packet: IPv4Packet) -> bool:
    if not isinstance(packet, IPv4Packet):
        raise TypeError("packet must be an IPv4Packet")
    header = pack(
        "!BBHHHBBH4s4s",
        (packet.version << 4) | packet.ihl,
        (packet.dscp << 2) | packet.ecn,
        packet.total_length,
        packet.identification,
        (packet.flags << 13) | packet.fragment_offset,
        packet.ttl,
        packet.protocol,
        0,
        packet.source_address,
        packet.destination_address,
    ) + packet.options
    total = sum(
        int.from_bytes(header[offset:offset + 2], byteorder="big")
        for offset in range(0, packet.header_length, 2)
    )
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total & 0xFFFF) == packet.header_checksum
