from dataclasses import dataclass, field
from enum import Enum
from struct import unpack_from
from typing import Optional, Tuple


DNS_MAX_MESSAGE_BYTES = 65535
DNS_MAX_ENTRIES = 128
DNS_MAX_POINTER_HOPS = 32
DNS_MAX_LABEL_BYTES = 63
DNS_MAX_NAME_BYTES = 255
DNS_MAX_EDNS_OPTIONS = DNS_MAX_ENTRIES
DNS_MAX_EDNS_OPTION_BYTES = DNS_MAX_MESSAGE_BYTES - 23
DNS_MAX_EDNS_OPTION_DATA_BYTES = DNS_MAX_EDNS_OPTION_BYTES - 4


class DNSMessageStatus(Enum):
    COMPLETE = 'complete'
    INCOMPLETE = 'incomplete'
    MALFORMED = 'malformed'
    UNSUPPORTED = 'unsupported'


@dataclass(frozen=True, init=False)
class DNSHeader:
    transaction_id: int
    flags: int
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int

    def __init__(self) -> None:
        raise TypeError('use analyze_dns_message(payload)')

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 15

    @property
    def response_code(self) -> int:
        return self.flags & 15

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def authoritative_answer(self) -> bool:
        return bool(self.flags & 0x0400)

    @property
    def recursion_desired(self) -> bool:
        return bool(self.flags & 0x0100)

    @property
    def recursion_available(self) -> bool:
        return bool(self.flags & 0x0080)

    @property
    def authenticated_data(self) -> bool:
        return bool(self.flags & 0x0020)

    @property
    def checking_disabled(self) -> bool:
        return bool(self.flags & 0x0010)


@dataclass(frozen=True, init=False)
class DNSName:
    offset: int
    encoded_length: int
    labels: Tuple[bytes, ...] = field(repr=False)
    pointer_hops: int

    def __init__(self) -> None:
        raise TypeError('use analyze_dns_message(payload)')

    @property
    def expanded_length(self) -> int:
        return 1 + sum(1 + len(label) for label in self.labels)


@dataclass(frozen=True, init=False)
class DNSQuestion:
    name: DNSName
    question_type: int
    question_class: int

    def __init__(self) -> None:
        raise TypeError('use analyze_dns_message(payload)')


@dataclass(frozen=True, init=False)
class DNSEDNSOption:
    code: int
    data: bytes = field(repr=False)

    def __init__(self) -> None:
        raise TypeError('use analyze_dns_message(payload)')

    @property
    def data_length(self) -> int:
        return len(self.data)


@dataclass(frozen=True, init=False)
class DNSEDNS:
    udp_payload_size: int
    extended_rcode: int
    version: int
    flags: int
    options: Tuple[DNSEDNSOption, ...]

    def __init__(self) -> None:
        raise TypeError('use analyze_dns_message(payload)')

    @property
    def dnssec_ok(self) -> bool:
        return bool(self.flags & 0x8000)


@dataclass(frozen=True, init=False)
class DNSResourceRecord:
    name: DNSName
    record_type: int
    record_class: int
    ttl: int
    rdlength: int
    rdata: bytes = field(repr=False)
    edns: Optional[DNSEDNS] = None

    def __init__(self) -> None:
        raise TypeError('use analyze_dns_message(payload)')


@dataclass(frozen=True, init=False)
class DNSMessageObservation:
    status: DNSMessageStatus
    reason: Optional[str]
    header: Optional[DNSHeader]
    questions: Tuple[DNSQuestion, ...]
    answers: Tuple[DNSResourceRecord, ...]
    authorities: Tuple[DNSResourceRecord, ...]
    additionals: Tuple[DNSResourceRecord, ...]
    parsed_length: int
    remaining_bytes: int
    failure_offset: Optional[int]
    limit_reached: bool

    def __init__(self) -> None:
        raise TypeError('use analyze_dns_message(payload)')

    @property
    def edns(self) -> Optional[DNSEDNS]:
        if self.status is DNSMessageStatus.COMPLETE:
            return next((record.edns for record in self.additionals if record.edns is not None), None)
        return None


def _observation(model, **values):
    result = object.__new__(model)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


class _DNSParseError(Exception):
    def __init__(self, status, reason, offset, limit_reached=False):
        self.status = status
        self.reason = reason
        self.offset = offset
        self.limit_reached = limit_reached


def _require(payload, position, count):
    if position + count > len(payload):
        raise _DNSParseError(DNSMessageStatus.INCOMPLETE, 'truncated structural field', position)


def _name(payload, start, boundaries, opaque_ranges):
    position, end, expanded, hops = start, None, 1, 0
    labels, visited = [], set()
    while True:
        _require(payload, position, 1)
        if position in visited:
            raise _DNSParseError(DNSMessageStatus.MALFORMED, 'compression pointer loop', position)
        visited.add(position)
        length = payload[position]
        if length == 0:
            boundaries.add(position)
            if end is None:
                end = position + 1
            return _observation(DNSName, offset=start, encoded_length=end - start,
                                labels=tuple(labels), pointer_hops=hops)
        if length & 0xC0 == 0xC0:
            _require(payload, position, 2)
            target = ((length & 0x3F) << 8) | payload[position + 1]
            if target in visited:
                raise _DNSParseError(DNSMessageStatus.MALFORMED, 'compression pointer loop', position)
            if target < 12 or target >= len(payload):
                raise _DNSParseError(DNSMessageStatus.MALFORMED, 'compression pointer outside name area', position)
            if target >= position:
                raise _DNSParseError(DNSMessageStatus.MALFORMED, 'compression pointer must point backwards', position)
            if target not in boundaries:
                if any(lower <= target < upper for lower, upper in opaque_ranges):
                    raise _DNSParseError(DNSMessageStatus.UNSUPPORTED, 'compression target in opaque RDATA', position)
                raise _DNSParseError(DNSMessageStatus.MALFORMED, 'compression target is not a name boundary', position)
            if hops == DNS_MAX_POINTER_HOPS:
                raise _DNSParseError(DNSMessageStatus.UNSUPPORTED, 'compression traversal limit', position, True)
            boundaries.add(position)
            hops += 1
            if end is None:
                end = position + 2
            position = target
            continue
        if length & 0xC0 == 0x40:
            raise _DNSParseError(DNSMessageStatus.UNSUPPORTED, 'extended label encoding', position)
        if length > DNS_MAX_LABEL_BYTES:
            raise _DNSParseError(DNSMessageStatus.MALFORMED, 'reserved label encoding', position)
        _require(payload, position + 1, length)
        expanded += length + 1
        if expanded > DNS_MAX_NAME_BYTES:
            raise _DNSParseError(DNSMessageStatus.MALFORMED, 'expanded name exceeds wire limit', position)
        boundaries.add(position)
        labels.append(payload[position + 1:position + 1 + length])
        position += length + 1


def _edns(record, rdata_start):
    data = record.rdata
    if len(data) > DNS_MAX_EDNS_OPTION_BYTES:
        raise _DNSParseError(DNSMessageStatus.UNSUPPORTED, 'EDNS option byte limit', rdata_start, True)
    position, options = 0, []
    while position < len(data):
        if len(options) == DNS_MAX_EDNS_OPTIONS:
            raise _DNSParseError(DNSMessageStatus.UNSUPPORTED, 'EDNS option count limit', rdata_start + position, True)
        if len(data) - position < 4:
            raise _DNSParseError(DNSMessageStatus.MALFORMED, 'EDNS option header exceeds RDATA', rdata_start + position)
        code, length = unpack_from('!HH', data, position)
        end = position + 4 + length
        if end > len(data):
            raise _DNSParseError(DNSMessageStatus.MALFORMED, 'EDNS option data exceeds RDATA', rdata_start + position)
        options.append(_observation(DNSEDNSOption, code=code, data=data[position + 4:end]))
        position = end
    return _observation(DNSEDNS, udp_payload_size=record.record_class,
                        extended_rcode=record.ttl >> 24, version=(record.ttl >> 16) & 255,
                        flags=record.ttl & 65535, options=tuple(options))


def analyze_dns_message(payload: bytes) -> DNSMessageObservation:
    if type(payload) is not bytes:
        raise TypeError('payload must be exactly bytes')
    header, position, count = None, 0, 0
    sections = ([], [], [], [])
    boundaries, opaque_ranges = set(), []
    status, reason, failure_offset, limited = DNSMessageStatus.COMPLETE, None, None, False
    edns, edns_index = None, None
    try:
        if len(payload) > DNS_MAX_MESSAGE_BYTES:
            raise _DNSParseError(DNSMessageStatus.UNSUPPORTED, 'DNS message size limit', 0, True)
        _require(payload, 0, 12)
        values = unpack_from('!6H', payload)
        header = _observation(DNSHeader, **dict(zip(
            ('transaction_id', 'flags', 'question_count', 'answer_count', 'authority_count', 'additional_count'),
            values)))
        position = 12
        for section_index, declared_count in enumerate(values[2:]):
            for _ in range(declared_count):
                if count == DNS_MAX_ENTRIES:
                    raise _DNSParseError(DNSMessageStatus.UNSUPPORTED, 'DNS entry limit', position, True)
                name = _name(payload, position, boundaries, opaque_ranges)
                envelope = position + name.encoded_length
                if section_index == 0:
                    _require(payload, envelope, 4)
                    question_type, question_class = unpack_from('!HH', payload, envelope)
                    entry = _observation(DNSQuestion, name=name, question_type=question_type,
                                         question_class=question_class)
                    end = envelope + 4
                else:
                    _require(payload, envelope, 10)
                    record_type, record_class, ttl, rdlength = unpack_from('!HHIH', payload, envelope)
                    rdata_start = envelope + 10
                    _require(payload, rdata_start, rdlength)
                    end = rdata_start + rdlength
                    entry = _observation(DNSResourceRecord, name=name, record_type=record_type,
                                         record_class=record_class, ttl=ttl, rdlength=rdlength,
                                         rdata=payload[rdata_start:end], edns=None)
                    if record_type == 41:
                        if section_index != 3:
                            raise _DNSParseError(DNSMessageStatus.MALFORMED, 'OPT requires additional section', position)
                        if name.labels:
                            raise _DNSParseError(DNSMessageStatus.MALFORMED, 'OPT requires root owner', position)
                        if edns is not None:
                            raise _DNSParseError(DNSMessageStatus.MALFORMED, 'multiple OPT records', position)
                        edns = _edns(entry, rdata_start)
                        edns_index = len(sections[3])
                    opaque_ranges.append((rdata_start, end))
                sections[section_index].append(entry)
                position = end
                count += 1
        if position != len(payload):
            raise _DNSParseError(DNSMessageStatus.MALFORMED, 'bytes after declared DNS sections', position)
        if edns is not None:
            sections[3][edns_index] = _observation(DNSResourceRecord, **dict(vars(sections[3][edns_index]), edns=edns))
    except _DNSParseError as error:
        status, reason, failure_offset, limited = error.status, error.reason, error.offset, error.limit_reached
    return _observation(DNSMessageObservation, status=status, reason=reason, header=header,
                        questions=tuple(sections[0]), answers=tuple(sections[1]),
                        authorities=tuple(sections[2]), additionals=tuple(sections[3]),
                        parsed_length=position, remaining_bytes=len(payload) - position,
                        failure_offset=failure_offset, limit_reached=limited)
