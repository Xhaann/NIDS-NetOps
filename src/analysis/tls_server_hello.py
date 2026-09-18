from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from analysis.flow_direction import FlowDirection
from analysis.flow_identity import FlowIdentity
from analysis.tcp_stream_observation import TCPStreamObservation
from analysis.tls_handshake_framing import (
    TLS_HANDSHAKE_MAX_MESSAGE_LENGTH, TLSHandshakeHeader, TLSHandshakeObservation, TLSHandshakeStatus,
)


TLS_SERVER_HELLO_MAX_BODY_BYTES = TLS_HANDSHAKE_MAX_MESSAGE_LENGTH
TLS_SERVER_HELLO_MAX_SESSION_ID_BYTES = 32
TLS_SERVER_HELLO_MAX_EXTENSION_BYTES = 65535
TLS_SERVER_HELLO_MAX_EXTENSION_DATA_BYTES = TLS_SERVER_HELLO_MAX_EXTENSION_BYTES - 4
TLS_SERVER_HELLO_MAX_EXTENSIONS = 1024


class TLSServerHelloStatus(Enum):
    COMPLETE = 'complete'
    INCOMPLETE = 'incomplete'
    MALFORMED = 'malformed'
    UNSUPPORTED = 'unsupported'


@dataclass(frozen=True, init=False)
class TLSServerHelloExtension:
    extension_type: int
    data: bytes = field(repr=False)

    def __init__(self) -> None:
        raise TypeError('use analyze_tls_server_hello(observation)')

    @property
    def data_length(self) -> int:
        return len(self.data)


@dataclass(frozen=True, init=False)
class TLSServerHello:
    legacy_version: bytes
    random: bytes = field(repr=False)
    session_id: bytes = field(repr=False)
    cipher_suite: int
    compression_method: int
    extensions_length: Optional[int]
    extensions: tuple[TLSServerHelloExtension, ...]
    extensions_present: bool

    def __init__(self) -> None:
        raise TypeError('use analyze_tls_server_hello(observation)')

    @property
    def session_id_length(self) -> int:
        return len(self.session_id)

    @property
    def extension_count(self) -> int:
        return len(self.extensions)


@dataclass(frozen=True, init=False)
class TLSServerHelloObservation:
    identity: FlowIdentity
    direction: FlowDirection
    consumed_offset: int
    status: TLSServerHelloStatus
    reason: Optional[str]
    server_hello: Optional[TLSServerHello]
    failure_offset: Optional[int]

    def __init__(self) -> None:
        raise TypeError('use analyze_tls_server_hello(observation)')


def _build(model, **values):
    result = object.__new__(model)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


class _ServerHelloError(Exception):
    def __init__(self, status, reason, offset):
        self.status, self.reason, self.offset = status, reason, offset


def _require(body, offset, size):
    if size > len(body) - offset:
        raise _ServerHelloError(TLSServerHelloStatus.INCOMPLETE, 'missing ServerHello field bytes', offset)


def _extension(kind, data, offset):
    if type(kind) is not int or not 0 <= kind <= 65535:
        raise _ServerHelloError(TLSServerHelloStatus.MALFORMED, 'extension type exceeds two-byte bounds', offset)
    if type(data) is not bytes:
        raise _ServerHelloError(TLSServerHelloStatus.MALFORMED, 'extension data must be bytes', offset)
    return _build(TLSServerHelloExtension, extension_type=kind, data=data)


def _parse(body):
    _require(body, 0, 2)
    version = body[:2]
    _require(body, 2, 32)
    random = body[2:34]
    _require(body, 34, 1)
    session_length = body[34]
    if session_length > TLS_SERVER_HELLO_MAX_SESSION_ID_BYTES:
        raise _ServerHelloError(TLSServerHelloStatus.MALFORMED, 'session ID exceeds ServerHello bound', 34)
    _require(body, 35, session_length)
    session = body[35:35 + session_length]
    offset = 35 + session_length
    _require(body, offset, 2)
    cipher_suite = int.from_bytes(body[offset:offset + 2], 'big')
    offset += 2
    _require(body, offset, 1)
    compression_method = body[offset]
    offset += 1
    present = offset < len(body)
    extensions_length = None
    extensions = []
    if present:
        _require(body, offset, 2)
        extensions_length = int.from_bytes(body[offset:offset + 2], 'big')
        offset += 2
        _require(body, offset, extensions_length)
        end = offset + extensions_length
        if end != len(body):
            raise _ServerHelloError(TLSServerHelloStatus.MALFORMED, 'trailing bytes outside extensions block', end)
        while offset < end:
            if end - offset < 4:
                raise _ServerHelloError(TLSServerHelloStatus.MALFORMED, 'extension header exceeds block', offset)
            kind = int.from_bytes(body[offset:offset + 2], 'big')
            size = int.from_bytes(body[offset + 2:offset + 4], 'big')
            if size > end - offset - 4:
                raise _ServerHelloError(TLSServerHelloStatus.MALFORMED, 'extension data exceeds block', offset + 2)
            if len(extensions) == TLS_SERVER_HELLO_MAX_EXTENSIONS:
                raise _ServerHelloError(TLSServerHelloStatus.UNSUPPORTED, 'extension count exceeds implementation bound', offset)
            offset += 4
            extensions.append(_extension(kind, body[offset:offset + size], offset))
            offset += size
    return _build(
        TLSServerHello,
        legacy_version=version,
        random=random,
        session_id=session,
        cipher_suite=cipher_suite,
        compression_method=compression_method,
        extensions_length=extensions_length,
        extensions=tuple(extensions),
        extensions_present=present,
    )


def analyze_tls_server_hello(observation: TLSHandshakeObservation) -> TLSServerHelloObservation:
    if type(observation) is not TLSHandshakeObservation:
        raise TypeError('observation must be exactly a TLSHandshakeObservation')
    if type(observation.stream) is not TCPStreamObservation or type(observation.direction) is not FlowDirection:
        raise TypeError('observation must have an exact TCP stream and direction')
    if type(observation.header) is not TLSHandshakeHeader:
        raise TypeError('observation must have an exact TLSHandshakeHeader')
    if type(observation.payload) is not bytes or type(observation.prefix) is not bytes:
        raise TypeError('observation binary fields must be exact bytes')
    if observation.status is not TLSHandshakeStatus.READY or observation.prefix or observation.unavailable_reason is not None:
        raise ValueError('ServerHello analysis requires a completed handshake observation')
    header = observation.header
    if type(header.handshake_type) is not int or type(header.declared_length) is not int:
        raise TypeError('handshake header values must be exact integers')
    if not 0 <= header.handshake_type <= 255 or not 0 <= header.declared_length <= TLS_SERVER_HELLO_MAX_BODY_BYTES:
        raise ValueError('handshake header exceeds framing bounds')
    if header.declared_length != len(observation.payload):
        raise ValueError('completed handshake length must equal payload length')
    status, reason, hello, offset = TLSServerHelloStatus.COMPLETE, None, None, None
    if header.handshake_type != 2:
        status, reason = TLSServerHelloStatus.UNSUPPORTED, 'handshake type is not ServerHello'
    else:
        try:
            hello = _parse(observation.payload)
        except _ServerHelloError as error:
            status, reason, offset = error.status, error.reason, error.offset
    return _build(
        TLSServerHelloObservation,
        identity=observation.identity,
        direction=observation.direction,
        consumed_offset=observation.consumed_offset,
        status=status,
        reason=reason,
        server_hello=hello,
        failure_offset=offset,
    )
