from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from analysis.flow_direction import FlowDirection
from analysis.flow_identity import FlowIdentity
from analysis.tcp_stream_observation import TCPStreamObservation
from analysis.tls_handshake_framing import (
    TLS_HANDSHAKE_MAX_MESSAGE_LENGTH, TLSHandshakeHeader, TLSHandshakeObservation, TLSHandshakeStatus,
)


TLS_CLIENT_HELLO_MAX_BODY_BYTES = TLS_HANDSHAKE_MAX_MESSAGE_LENGTH
TLS_CLIENT_HELLO_MAX_SESSION_ID_BYTES = 255
TLS_CLIENT_HELLO_MAX_CIPHER_SUITE_BYTES = 65535
TLS_CLIENT_HELLO_MAX_COMPRESSION_BYTES = 255
TLS_CLIENT_HELLO_MAX_EXTENSION_BYTES = 65535
TLS_CLIENT_HELLO_MAX_EXTENSION_DATA_BYTES = TLS_CLIENT_HELLO_MAX_EXTENSION_BYTES - 4
TLS_CLIENT_HELLO_MAX_EXTENSIONS = 1024


class TLSClientHelloStatus(Enum):
    COMPLETE = 'complete'
    INCOMPLETE = 'incomplete'
    MALFORMED = 'malformed'
    UNSUPPORTED = 'unsupported'


@dataclass(frozen=True, init=False)
class TLSClientHelloExtension:
    extension_type: int
    data: bytes = field(repr=False)
    supported_groups: Optional[tuple[int, ...]]
    signature_algorithms: Optional[tuple[int, ...]]
    alpn_protocols: Optional[tuple[bytes, ...]]

    def __init__(self) -> None:
        raise TypeError('use analyze_tls_client_hello(observation)')


@dataclass(frozen=True, init=False)
class TLSClientHello:
    legacy_version: bytes
    random: bytes = field(repr=False)
    session_id: bytes = field(repr=False)
    cipher_suites: tuple[int, ...]
    compression_methods: tuple[int, ...]
    extensions: tuple[TLSClientHelloExtension, ...]
    extensions_present: bool

    def __init__(self) -> None:
        raise TypeError('use analyze_tls_client_hello(observation)')


@dataclass(frozen=True, init=False)
class TLSClientHelloObservation:
    stream: TCPStreamObservation
    status: TLSClientHelloStatus
    reason: Optional[str]
    client_hello: Optional[TLSClientHello]
    failure_offset: Optional[int]

    def __init__(self) -> None:
        raise TypeError('use analyze_tls_client_hello(observation)')

    @property
    def identity(self) -> FlowIdentity:
        return self.stream.identity

    @property
    def direction(self) -> FlowDirection:
        return self.stream.direction

    @property
    def consumed_offset(self) -> int:
        return self.stream.consumed_offset


def _build(model, **values):
    result = object.__new__(model)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


class _ClientHelloError(Exception):
    def __init__(self, status, reason, offset):
        self.status, self.reason, self.offset = status, reason, offset


def _require(body, offset, size):
    if size > len(body) - offset:
        raise _ClientHelloError(TLSClientHelloStatus.INCOMPLETE, 'missing ClientHello field bytes', offset)


def _extension(kind, data, offset):
    groups, signatures, protocols = None, None, None
    if kind in (10, 13, 16):
        if len(data) < 2:
            raise _ClientHelloError(TLSClientHelloStatus.MALFORMED, 'missing selected extension vector length', offset)
        size = int.from_bytes(data[:2], 'big')
        if size != len(data) - 2:
            raise _ClientHelloError(TLSClientHelloStatus.MALFORMED, 'selected vector must fill extension data', offset)
        if kind in (10, 13):
            if size % 2:
                raise _ClientHelloError(TLSClientHelloStatus.MALFORMED, 'identifier vector length must be even', offset)
            identifiers = tuple(int.from_bytes(data[i:i + 2], 'big') for i in range(2, len(data), 2))
            if kind == 10:
                groups = identifiers
            else:
                signatures = identifiers
        else:
            if size < 2:
                raise _ClientHelloError(TLSClientHelloStatus.MALFORMED, 'ALPN list must contain a nonempty name', offset)
            names, position = [], 2
            while position < len(data):
                length = data[position]
                position += 1
                if length == 0 or length > len(data) - position:
                    raise _ClientHelloError(TLSClientHelloStatus.MALFORMED, 'invalid ALPN name boundary', offset + position - 1)
                names.append(data[position:position + length])
                position += length
            protocols = tuple(names)
    return _build(TLSClientHelloExtension, extension_type=kind, data=data, supported_groups=groups,
                  signature_algorithms=signatures, alpn_protocols=protocols)


def _parse(body):
    _require(body, 0, 2)
    version = body[:2]
    _require(body, 2, 32)
    random = body[2:34]
    _require(body, 34, 1)
    length = body[34]
    _require(body, 35, length)
    session = body[35:35 + length]
    offset = 35 + length
    _require(body, offset, 2)
    length = int.from_bytes(body[offset:offset + 2], 'big')
    if length == 0 or length % 2:
        raise _ClientHelloError(TLSClientHelloStatus.MALFORMED, 'cipher suite vector must be nonempty and even', offset)
    offset += 2
    _require(body, offset, length)
    suites = tuple(int.from_bytes(body[i:i + 2], 'big') for i in range(offset, offset + length, 2))
    offset += length
    _require(body, offset, 1)
    length = body[offset]
    if length == 0:
        raise _ClientHelloError(TLSClientHelloStatus.MALFORMED, 'compression method vector must be nonempty', offset)
    offset += 1
    _require(body, offset, length)
    compression = tuple(body[offset:offset + length])
    offset += length
    present = offset < len(body)
    extensions = []
    if present:
        _require(body, offset, 2)
        length = int.from_bytes(body[offset:offset + 2], 'big')
        offset += 2
        _require(body, offset, length)
        end = offset + length
        if end != len(body):
            raise _ClientHelloError(TLSClientHelloStatus.MALFORMED, 'trailing bytes outside extensions block', end)
        while offset < end:
            if end - offset < 4:
                raise _ClientHelloError(TLSClientHelloStatus.MALFORMED, 'extension header exceeds block', offset)
            kind = int.from_bytes(body[offset:offset + 2], 'big')
            size = int.from_bytes(body[offset + 2:offset + 4], 'big')
            if size > end - offset - 4:
                raise _ClientHelloError(TLSClientHelloStatus.MALFORMED, 'extension data exceeds block', offset + 2)
            if len(extensions) == TLS_CLIENT_HELLO_MAX_EXTENSIONS:
                raise _ClientHelloError(TLSClientHelloStatus.UNSUPPORTED, 'extension count exceeds implementation bound', offset)
            offset += 4
            extensions.append(_extension(kind, body[offset:offset + size], offset))
            offset += size
    return _build(TLSClientHello, legacy_version=version, random=random, session_id=session,
                  cipher_suites=suites, compression_methods=compression, extensions=tuple(extensions),
                  extensions_present=present)


def analyze_tls_client_hello(observation: TLSHandshakeObservation) -> TLSClientHelloObservation:
    if type(observation) is not TLSHandshakeObservation:
        raise TypeError('observation must be exactly a TLSHandshakeObservation')
    if type(observation.stream) is not TCPStreamObservation or type(observation.direction) is not FlowDirection:
        raise TypeError('observation must have an exact TCP stream and direction')
    if type(observation.header) is not TLSHandshakeHeader:
        raise TypeError('observation must have an exact TLSHandshakeHeader')
    if type(observation.payload) is not bytes or type(observation.prefix) is not bytes:
        raise TypeError('observation binary fields must be exact bytes')
    if observation.status is not TLSHandshakeStatus.READY or observation.prefix or observation.unavailable_reason is not None:
        raise ValueError('ClientHello analysis requires a completed handshake observation')
    header = observation.header
    if type(header.handshake_type) is not int or type(header.declared_length) is not int:
        raise TypeError('handshake header values must be exact integers')
    if not 0 <= header.handshake_type <= 255 or not 0 <= header.declared_length <= TLS_CLIENT_HELLO_MAX_BODY_BYTES:
        raise ValueError('handshake header exceeds framing bounds')
    if header.declared_length != len(observation.payload):
        raise ValueError('completed handshake length must equal payload length')
    status, reason, hello, offset = TLSClientHelloStatus.COMPLETE, None, None, None
    if header.handshake_type != 1:
        status, reason = TLSClientHelloStatus.UNSUPPORTED, 'handshake type is not ClientHello'
    else:
        try:
            hello = _parse(observation.payload)
        except _ClientHelloError as error:
            status, reason, offset = error.status, error.reason, error.offset
    return _build(TLSClientHelloObservation, stream=observation.stream, status=status, reason=reason,
                  client_hello=hello, failure_offset=offset)
