from struct import pack

from tests.test_ipv6 import SOURCE_ADDRESS, DESTINATION_ADDRESS
from tests.test_ipv6_transport import fragment_header, observation_for
from tests.test_packet_analysis import make_observation
from tests.test_pcap_packet_source import global_header, record


def addresses(ipv6=False, reverse=False):
    pair = (SOURCE_ADDRESS, DESTINATION_ADDRESS) if ipv6 else (
        bytes.fromhex('c0000201'), bytes.fromhex('c6336402'))
    return pair[::-1] if reverse else pair


def checksum(data):
    padded = data + bytes(len(data) % 2)
    return 65535 - sum(int.from_bytes(padded[i:i + 2], 'big') for i in range(0, len(padded), 2)) % 65535


def transport(protocol, payload=b'', ipv6=False, reverse=False, sequence=100, acknowledgment=0, flags=2):
    ports = (443, 12345) if reverse else (12345, 443)
    if protocol == 6:
        segment = pack('!HHIIHHHH', *ports, sequence, acknowledgment, 0x5000 | flags, 4096, 0, 0) + payload
        offset = 16
    else:
        segment = pack('!HHHH', *ports, 8 + len(payload), 0) + payload
        offset = 6
    source, destination = addresses(ipv6, reverse)
    pseudo = source + destination + (pack('!I3xB', len(segment), protocol) if ipv6 else pack('!BBH', 0, protocol, len(segment)))
    value = checksum(pseudo + segment)
    return segment[:offset] + value.to_bytes(2, 'big') + segment[offset + 2:]


def frame(protocol, segment, ipv6=False, reverse=False, extensions=(), fragment=None):
    if ipv6:
        base, prefix = protocol, b''
        if fragment is not None:
            prefix = fragment_header(protocol, *fragment)
            base = 44
        for kind in reversed(extensions):
            prefix = bytes((base, 0, 1, 4, 0, 0, 0, 0)) + prefix
            base = kind
        raw = observation_for(protocol, segment, prefix, base).raw_bytes
        source, destination = addresses(True, reverse)
        raw = raw[:22] + source + destination + raw[54:]
    else:
        raw = make_observation(protocol, segment).raw_bytes
        source, destination = addresses(False, reverse)
        raw = raw[:26] + source + destination + raw[34:]
    if reverse:
        raw = raw[6:12] + raw[:6] + raw[12:]
    return raw.ljust(60, b'\x00')


def tcp_exchange(ipv6=False):
    specifications = (
        (1000000, False, 100, 0, 2, b''),
        (1100000, True, 900, 101, 18, b''),
        (1200000, False, 101, 901, 16, b''),
        (1300000, False, 101, 901, 24, b'abc'),
        (1500000, True, 901, 104, 16, b''),
        (1700000, True, 901, 104, 17, b''),
        (1800000, False, 104, 902, 16, b''),
    )
    return tuple((time, frame(6, transport(6, payload, ipv6, reverse, sequence, acknowledgment, flags), ipv6, reverse))
                 for time, reverse, sequence, acknowledgment, flags, payload in specifications)


def udp_exchange(ipv6=False, extensions=(), fragment=None):
    return tuple((time, frame(17, transport(17, payload, ipv6, reverse), ipv6, reverse, extensions, fragment))
                 for time, reverse, payload in ((1000000, False, b'query'),
                                                (1500000, True, b'response'),
                                                (2000000, False, b'query')))


def pcap_bytes(packets, order='<', nano=False):
    return global_header(order=order, nano=nano) + b''.join(
        record(raw, order=order, seconds=time // 1000000,
               fraction=time % 1000000 * (1000 if nano else 1)) for time, raw in packets)
