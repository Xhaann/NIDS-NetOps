from dataclasses import dataclass
from enum import Enum
from typing import Optional


LDAP_MAX_PAYLOAD_BYTES = 65536
LDAP_MAX_MESSAGES = 128


class LDAPMessageStatus(Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"


class LDAPOperation(Enum):
    BIND_REQUEST = 0x60
    BIND_RESPONSE = 0x61
    UNBIND_REQUEST = 0x42
    SEARCH_REQUEST = 0x63
    SEARCH_RESULT_ENTRY = 0x64
    SEARCH_RESULT_DONE = 0x65
    MODIFY_REQUEST = 0x66
    MODIFY_RESPONSE = 0x67
    ADD_REQUEST = 0x68
    ADD_RESPONSE = 0x69
    DELETE_REQUEST = 0x4A
    DELETE_RESPONSE = 0x6B
    MODIFY_DN_REQUEST = 0x6C
    MODIFY_DN_RESPONSE = 0x6D
    COMPARE_REQUEST = 0x6E
    COMPARE_RESPONSE = 0x6F
    ABANDON_REQUEST = 0x50
    SEARCH_RESULT_REFERENCE = 0x73
    EXTENDED_REQUEST = 0x77
    EXTENDED_RESPONSE = 0x78
    INTERMEDIATE_RESPONSE = 0x79

    @property
    def is_request(self) -> bool:
        return self.name.endswith("REQUEST")


@dataclass(frozen=True, init=False)
class LDAPMessageObservation:
    offset: int
    status: LDAPMessageStatus
    reason: Optional[str]
    message_length: Optional[int]
    envelope_complete: bool
    message_id: Optional[int]
    operation_tag: Optional[int]
    operation: Optional[LDAPOperation]
    operation_length: Optional[int]
    controls_present: Optional[bool]
    controls_length: Optional[int]

    def __init__(self) -> None:
        raise TypeError("use analyze_ldap_payload(payload)")


@dataclass(frozen=True, init=False)
class LDAPPayloadObservation:
    messages: tuple[LDAPMessageObservation, ...]
    remaining_bytes: int
    limit_reached: bool

    def __init__(self) -> None:
        raise TypeError("use analyze_ldap_payload(payload)")


class _EnvelopeError(Exception):
    def __init__(self, status: LDAPMessageStatus, reason: str) -> None:
        self.status = status
        self.reason = reason


def _require_bytes(position: int, count: int, available: int, boundary: Optional[int]) -> None:
    if boundary is not None and position + count > boundary:
        raise _EnvelopeError(LDAPMessageStatus.MALFORMED, "envelope exceeds parent boundary")
    if position + count > available:
        raise _EnvelopeError(LDAPMessageStatus.INCOMPLETE, "envelope bytes unavailable")


def _envelope(payload: bytes, position: int, available: int,
              boundary: Optional[int] = None) -> tuple[int, int, int]:
    _require_bytes(position, 1, available, boundary)
    tag = payload[position]
    if tag & 0x1F == 0x1F:
        raise _EnvelopeError(LDAPMessageStatus.UNSUPPORTED, "high-tag-number encoding")
    _require_bytes(position + 1, 1, available, boundary)
    first = payload[position + 1]
    start = position + 2
    if first == 0xFF:
        raise _EnvelopeError(LDAPMessageStatus.MALFORMED, "reserved BER length octet")
    if first == 0x80:
        raise _EnvelopeError(LDAPMessageStatus.UNSUPPORTED, "indefinite BER length")
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count > 4:
            raise _EnvelopeError(LDAPMessageStatus.UNSUPPORTED, "BER length exceeds four octets")
        _require_bytes(start, count, available, boundary)
        length = int.from_bytes(payload[start:start + count], "big")
        start += count
    if boundary is not None and start + length > boundary:
        raise _EnvelopeError(LDAPMessageStatus.MALFORMED, "declared length exceeds parent boundary")
    return tag, start, start + length


def _message(payload: bytes, offset: int, available: int, base_offset: int = 0) -> LDAPMessageObservation:
    values = dict(offset=base_offset + offset, status=LDAPMessageStatus.COMPLETE, reason=None,
                  message_length=None, envelope_complete=False, message_id=None,
                  operation_tag=None, operation=None, operation_length=None,
                  controls_present=None, controls_length=None)
    try:
        _require_bytes(offset, 1, available, None)
        if payload[offset] != 0x30:
            raise _EnvelopeError(LDAPMessageStatus.MALFORMED, "expected LDAPMessage SEQUENCE")
        _, start, end = _envelope(payload, offset, available)
        values["message_length"] = end - offset
        values["envelope_complete"] = end <= available
        if end - offset > LDAP_MAX_PAYLOAD_BYTES:
            raise _EnvelopeError(LDAPMessageStatus.UNSUPPORTED, "LDAP message exceeds byte limit")
        tag, integer_start, integer_end = _envelope(payload, start, available, end)
        if tag != 0x02:
            raise _EnvelopeError(LDAPMessageStatus.MALFORMED, "expected message identifier INTEGER")
        size = integer_end - integer_start
        if not 1 <= size <= 4:
            raise _EnvelopeError(LDAPMessageStatus.MALFORMED, "message identifier length outside LDAP range")
        _require_bytes(integer_start, size, available, end)
        integer = payload[integer_start:integer_end]
        if integer[0] & 0x80 or (size > 1 and integer[0] == 0 and integer[1] < 0x80):
            raise _EnvelopeError(LDAPMessageStatus.MALFORMED, "invalid message identifier encoding")
        values["message_id"] = int.from_bytes(integer, "big")
        _require_bytes(integer_end, 1, available, end)
        values["operation_tag"] = payload[integer_end]
        try:
            values["operation"] = LDAPOperation(payload[integer_end])
        except ValueError:
            pass
        _, operation_start, operation_end = _envelope(payload, integer_end, available, end)
        values["operation_length"] = operation_end - operation_start
        if operation_end == end:
            values["controls_present"] = False
        _require_bytes(operation_start, operation_end - operation_start, available, end)
        if operation_end < end:
            _require_bytes(operation_end, 1, available, end)
            if payload[operation_end] != 0xA0:
                raise _EnvelopeError(LDAPMessageStatus.UNSUPPORTED, "unsupported trailing LDAP component")
            values["controls_present"] = True
            _, controls_start, controls_end = _envelope(payload, operation_end, available, end)
            values["controls_length"] = controls_end - controls_start
            _require_bytes(controls_start, controls_end - controls_start, available, end)
            if controls_end != end:
                raise _EnvelopeError(LDAPMessageStatus.UNSUPPORTED, "trailing component after controls")
        if values["operation"] is None:
            raise _EnvelopeError(LDAPMessageStatus.UNSUPPORTED, "unknown protocol operation")
    except _EnvelopeError as error:
        values["status"] = error.status
        values["reason"] = error.reason
    result = object.__new__(LDAPMessageObservation)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def analyze_ldap_payload(payload: bytes) -> LDAPPayloadObservation:
    if type(payload) is not bytes:
        raise TypeError("payload must be exactly immutable bytes")
    available = min(len(payload), LDAP_MAX_PAYLOAD_BYTES)
    offset = 0
    messages = []
    while len(messages) < LDAP_MAX_MESSAGES:
        message = _message(payload, offset, available)
        messages.append(message)
        if not message.envelope_complete or message.message_length is None:
            break
        offset += message.message_length
        if offset >= available:
            break
    result = object.__new__(LDAPPayloadObservation)
    object.__setattr__(result, "messages", tuple(messages))
    object.__setattr__(result, "remaining_bytes", len(payload) - offset)
    object.__setattr__(result, "limit_reached", len(payload) > available or (
        len(messages) == LDAP_MAX_MESSAGES and offset < available
    ))
    return result
