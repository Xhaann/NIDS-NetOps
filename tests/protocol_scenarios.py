from dataclasses import replace
from datetime import datetime, timedelta, timezone

from capture import CaptureSource, LinkType, PacketObservation
from tests.pcap_scenarios import frame, transport
from tests.test_ipv4_options import with_options
from tests.test_ipv6_extension_transport import extension_chain
from tests.test_ipv6_transport import fragment_header, observation_for
from tests.test_packet_analysis import make_observation


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def observation(raw, seconds, extra_length=0):
    return PacketObservation(EPOCH + timedelta(seconds=seconds), LinkType(1), len(raw),
                             len(raw) + extra_length, raw, CaptureSource('protocol-combinations'))


def protocol_flows():
    groups = []
    for index, (ipv6, protocol) in enumerate(((False, 6), (False, 17), (True, 6), (True, 17))):
        observations = []
        restart = (10, 9, 8, 11)[index]
        for step, seconds in enumerate((1, 2, 3, restart, restart + 1)):
            reverse = step in (1, 4)
            segment = transport(protocol, bytes((index + 1,)) * (step + index + 1), ipv6, reverse,
                                flags=(2, 18, 16, 4, 16)[step])
            raw = frame(protocol, segment, ipv6, reverse)
            if ipv6 and step == 0:
                prefix, base = extension_chain(44, ((60, 16), (43, 24), (60, 8)))
                raw = observation_for(protocol, segment, prefix + fragment_header(protocol, more=protocol == 6), base).raw_bytes
            current = observation(raw, seconds, extra_length=index + step)
            if not ipv6 and step == 0:
                current = with_options(current, bytes.fromhex('9e0400ff01000000'))
                current = replace(current, original_length=current.captured_length + index)
            observations.append(current)
        groups.append(tuple(observations))
    return tuple(groups)


def failed_observations():
    bad_options = with_options(make_observation(17, transport(17)), b'\x9e\xff\x00\x00')
    non_initial = make_observation(6, transport(6), fragment_field=1)
    malformed_tcp = bytearray(transport(6, ipv6=True))
    malformed_tcp[12] = 0x40
    prefix, base = extension_chain(58, ((60, 16), (43, 24)))
    raw_packets = (
        bad_options.raw_bytes,
        non_initial.raw_bytes,
        make_observation(1, b'\x08').raw_bytes,
        observation_for(58, b'\x80', prefix, base).raw_bytes,
        observation_for(6, bytes(malformed_tcp)).raw_bytes,
        observation_for(17, bytes.fromhex('303901bbffff0000')).raw_bytes,
        observation_for(60, b'\x06\xff').raw_bytes,
    )
    return tuple(observation(raw, 2.5) for raw in raw_packets)


def interleaved_observations(include_failures=True, reverse_ties=False):
    groups = protocol_flows()
    if reverse_ties:
        groups = groups[::-1]
    observations = tuple(sorted((o for group in groups for o in group), key=lambda o: o.captured_at))
    if include_failures:
        observations = observations[:8] + failed_observations() + observations[8:]
    return observations
