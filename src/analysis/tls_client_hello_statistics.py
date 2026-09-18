from dataclasses import dataclass, fields, replace
from typing import Optional

from analysis.flow_direction import FlowDirection
from analysis.tcp_stream_observation import TCPStreamObservation
from analysis.tls_client_hello import (
    TLS_CLIENT_HELLO_MAX_BODY_BYTES,
    TLS_CLIENT_HELLO_MAX_CIPHER_SUITE_BYTES,
    TLS_CLIENT_HELLO_MAX_COMPRESSION_BYTES,
    TLS_CLIENT_HELLO_MAX_EXTENSIONS,
    TLS_CLIENT_HELLO_MAX_SESSION_ID_BYTES,
    TLSClientHelloExtension,
    TLSClientHelloObservation,
    TLSClientHelloStatus,
)


TLS_CLIENT_HELLO_VERSION_BINS = 65536
TLS_CLIENT_HELLO_CIPHER_SUITE_BINS = 65536
TLS_CLIENT_HELLO_EXTENSION_TYPE_BINS = 65536
TLS_CLIENT_HELLO_COMPRESSION_METHOD_BINS = 256
_EMPTY_16 = (0,) * 65536
_EMPTY_8 = (0,) * 256


def _validate_bins(value, size, name, total):
    if type(value) is not tuple or len(value) != size:
        raise TypeError(f'{name} must be exactly an immutable tuple of {size} bins')
    for count in value:
        if type(count) is not int:
            raise TypeError(f'{name} bins must contain exact integers')
        if count < 0:
            raise ValueError(f'{name} bins must not be negative')
    if sum(value) != total:
        raise ValueError(f'{name} must sum to its total observation count')


def _validate_range(count, total, minimum, maximum, limit, name):
    if type(count) is not int or type(total) is not int:
        raise TypeError(f'{name} counts and totals must be exact integers')
    if count < 0 or total < 0:
        raise ValueError(f'{name} counts and totals must not be negative')
    if count == 0:
        if total != 0 or minimum is not None or maximum is not None:
            raise ValueError(f'empty {name} observations require zero total and absent extrema')
        return
    if type(minimum) is not int or type(maximum) is not int:
        raise TypeError(f'{name} extrema must be exact integers when observations exist')
    if not 0 <= minimum <= maximum <= limit:
        raise ValueError(f'{name} extrema exceed their parser bounds')
    if minimum * count > total or maximum * count < total:
        raise ValueError(f'{name} total must lie within its observed extrema')


def _validate_extrema(count, minimum, maximum, limit, name):
    if count == 0:
        if minimum is not None or maximum is not None:
            raise ValueError(f'empty {name} observations require absent extrema')
        return
    if type(minimum) is not int or type(maximum) is not int:
        raise TypeError(f'{name} extrema must be exact integers when observations exist')
    if not 0 <= minimum <= maximum <= limit:
        raise ValueError(f'{name} extrema exceed their parser bounds')


def _validate_count(value, name):
    if type(value) is not int:
        raise TypeError(f'{name} must be exactly an integer')
    if value < 0:
        raise ValueError(f'{name} must not be negative')


@dataclass(frozen=True)
class TLSClientHelloStatistics:
    total_client_hello_count: int = 0
    legacy_version_counts: tuple[int, ...] = _EMPTY_16
    min_legacy_version: Optional[int] = None
    max_legacy_version: Optional[int] = None
    min_session_id_length: Optional[int] = None
    max_session_id_length: Optional[int] = None
    total_session_id_bytes: int = 0
    min_cipher_suite_count: Optional[int] = None
    max_cipher_suite_count: Optional[int] = None
    total_cipher_suite_count: int = 0
    cipher_suite_counts: tuple[int, ...] = _EMPTY_16
    min_compression_method_count: Optional[int] = None
    max_compression_method_count: Optional[int] = None
    total_compression_method_count: int = 0
    compression_method_counts: tuple[int, ...] = _EMPTY_8
    min_extension_count: Optional[int] = None
    max_extension_count: Optional[int] = None
    total_extension_count: int = 0
    extension_type_counts: tuple[int, ...] = _EMPTY_16
    unknown_extension_count: int = 0
    duplicate_extension_count: int = 0
    supported_groups_extension_count: int = 0
    min_supported_groups_count: Optional[int] = None
    max_supported_groups_count: Optional[int] = None
    total_supported_groups_count: int = 0
    signature_algorithms_extension_count: int = 0
    min_signature_algorithms_count: Optional[int] = None
    max_signature_algorithms_count: Optional[int] = None
    total_signature_algorithms_count: int = 0
    alpn_extension_count: int = 0
    min_alpn_protocol_count: Optional[int] = None
    max_alpn_protocol_count: Optional[int] = None
    total_alpn_protocol_count: int = 0

    def __post_init__(self) -> None:
        for member in fields(self):
            value = getattr(self, member.name)
            if member.name.endswith('_counts') or member.name in (
                'legacy_version_counts', 'cipher_suite_counts', 'compression_method_counts',
                'extension_type_counts',
            ):
                continue
            if value is None:
                if not (member.name.startswith('min_') or member.name.startswith('max_')):
                    raise TypeError(f'{member.name} must be exactly an integer')
                continue
            _validate_count(value, member.name)
        _validate_bins(self.legacy_version_counts, 65536, 'legacy_version_counts', self.total_client_hello_count)
        _validate_bins(self.cipher_suite_counts, 65536, 'cipher_suite_counts', self.total_cipher_suite_count)
        _validate_bins(self.compression_method_counts, 256, 'compression_method_counts', self.total_compression_method_count)
        _validate_bins(self.extension_type_counts, 65536, 'extension_type_counts', self.total_extension_count)
        _validate_extrema(self.total_client_hello_count, self.min_legacy_version,
                          self.max_legacy_version, 65535, 'legacy version')
        _validate_range(self.total_client_hello_count, self.total_session_id_bytes,
                        self.min_session_id_length, self.max_session_id_length,
                        TLS_CLIENT_HELLO_MAX_SESSION_ID_BYTES, 'session ID')
        _validate_range(self.total_client_hello_count, self.total_cipher_suite_count,
                        self.min_cipher_suite_count, self.max_cipher_suite_count,
                        TLS_CLIENT_HELLO_MAX_CIPHER_SUITE_BYTES // 2, 'cipher suite')
        _validate_range(self.total_client_hello_count, self.total_compression_method_count,
                        self.min_compression_method_count, self.max_compression_method_count,
                        TLS_CLIENT_HELLO_MAX_COMPRESSION_BYTES, 'compression method')
        _validate_range(self.total_client_hello_count, self.total_extension_count,
                        self.min_extension_count, self.max_extension_count,
                        TLS_CLIENT_HELLO_MAX_EXTENSIONS, 'extension')
        for extension_count, total, minimum, maximum, name in (
            (self.supported_groups_extension_count, self.total_supported_groups_count,
             self.min_supported_groups_count, self.max_supported_groups_count, 'supported groups'),
            (self.signature_algorithms_extension_count, self.total_signature_algorithms_count,
             self.min_signature_algorithms_count, self.max_signature_algorithms_count, 'signature algorithms'),
            (self.alpn_extension_count, self.total_alpn_protocol_count,
             self.min_alpn_protocol_count, self.max_alpn_protocol_count, 'ALPN'),
        ):
            _validate_range(extension_count, total, minimum, maximum, TLS_CLIENT_HELLO_MAX_BODY_BYTES, name)
        if self.unknown_extension_count > self.total_extension_count:
            raise ValueError('unknown extension count must not exceed total extension count')
        if self.duplicate_extension_count > self.total_extension_count:
            raise ValueError('duplicate extension count must not exceed total extension count')
        if self.supported_groups_extension_count + self.signature_algorithms_extension_count + self.alpn_extension_count > self.total_extension_count:
            raise ValueError('selected extension counts must not exceed total extension count')

    @property
    def client_hello_count(self) -> int:
        return self.total_client_hello_count

    @property
    def total_supported_group_count(self) -> int:
        return self.total_supported_groups_count

    @property
    def total_signature_algorithm_count(self) -> int:
        return self.total_signature_algorithms_count

    @property
    def total_alpn_protocols(self) -> int:
        return self.total_alpn_protocol_count

    @property
    def legacy_version_distribution(self) -> tuple[int, ...]:
        return self.legacy_version_counts

    @property
    def cipher_suite_frequency(self) -> tuple[int, ...]:
        return self.cipher_suite_counts

    @property
    def compression_method_frequency(self) -> tuple[int, ...]:
        return self.compression_method_counts

    @property
    def extension_type_frequency(self) -> tuple[int, ...]:
        return self.extension_type_counts

    @property
    def unknown_extension_occurrence_count(self) -> int:
        return self.unknown_extension_count

    @property
    def duplicate_extension_occurrence_count(self) -> int:
        return self.duplicate_extension_count


@dataclass(frozen=True)
class DirectionalTLSClientHelloStatistics:
    forward: TLSClientHelloStatistics = TLSClientHelloStatistics()
    reverse: TLSClientHelloStatistics = TLSClientHelloStatistics()

    def __post_init__(self) -> None:
        if type(self.forward) is not TLSClientHelloStatistics or type(self.reverse) is not TLSClientHelloStatistics:
            raise TypeError('directional aggregates must be exactly TLSClientHelloStatistics values')


def _validate_observation(observation):
    if type(observation) is not TLSClientHelloObservation:
        raise TypeError('observation must be exactly a TLSClientHelloObservation')
    if type(observation.stream) is not TCPStreamObservation or type(observation.direction) is not FlowDirection:
        raise TypeError('observation must have an existing TCP stream and flow direction')
    if observation.status is not TLSClientHelloStatus.COMPLETE or observation.client_hello is None:
        raise ValueError('statistics require a complete ClientHello observation')
    hello = observation.client_hello
    if type(hello.legacy_version) is not bytes or len(hello.legacy_version) != 2:
        raise TypeError('ClientHello legacy version must be exactly two bytes')
    if type(hello.session_id) is not bytes or len(hello.session_id) > TLS_CLIENT_HELLO_MAX_SESSION_ID_BYTES:
        raise ValueError('ClientHello session ID exceeds its parser bound')
    if type(hello.cipher_suites) is not tuple or type(hello.compression_methods) is not tuple or type(hello.extensions) is not tuple:
        raise TypeError('ClientHello structural vectors must be exact tuples')
    if not hello.cipher_suites or len(hello.cipher_suites) > TLS_CLIENT_HELLO_MAX_CIPHER_SUITE_BYTES // 2:
        raise ValueError('ClientHello cipher-suite vector exceeds its parser bound')
    if not hello.compression_methods or len(hello.compression_methods) > TLS_CLIENT_HELLO_MAX_COMPRESSION_BYTES:
        raise ValueError('ClientHello compression vector exceeds its parser bound')
    if len(hello.extensions) > TLS_CLIENT_HELLO_MAX_EXTENSIONS:
        raise ValueError('ClientHello extension vector exceeds its parser bound')
    for value in hello.cipher_suites:
        if type(value) is not int or not 0 <= value <= 65535:
            raise ValueError('cipher-suite identifiers must be bounded integers')
    for value in hello.compression_methods:
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError('compression identifiers must be bounded integers')
    for extension in hello.extensions:
        if type(extension) is not TLSClientHelloExtension:
            raise TypeError('ClientHello extensions must be exact TLSClientHelloExtension values')
        if type(extension.extension_type) is not int or not 0 <= extension.extension_type <= 65535:
            raise ValueError('extension identifiers must be bounded integers')
        for name, values in (('supported_groups', extension.supported_groups),
                             ('signature_algorithms', extension.signature_algorithms)):
            if values is not None:
                if type(values) is not tuple:
                    raise TypeError(f'{name} must be exactly a tuple')
                if any(type(value) is not int or not 0 <= value <= 65535 for value in values):
                    raise ValueError(f'{name} identifiers must be bounded integers')
                if extension.extension_type != (10 if name == 'supported_groups' else 13):
                    raise ValueError(f'{name} values require their selected extension type')
        if extension.alpn_protocols is not None:
            if type(extension.alpn_protocols) is not tuple:
                raise TypeError('alpn_protocols must be exactly a tuple')
            if any(type(value) is not bytes or not value or len(value) > 255 for value in extension.alpn_protocols):
                raise ValueError('ALPN names must be nonempty bounded bytes')
            if extension.extension_type != 16:
                raise ValueError('ALPN values require extension type 16')
        if extension.extension_type == 10 and extension.supported_groups is None:
            raise ValueError('supported_groups extension must expose its structural vector')
        if extension.extension_type == 13 and extension.signature_algorithms is None:
            raise ValueError('signature_algorithms extension must expose its structural vector')
        if extension.extension_type == 16 and extension.alpn_protocols is None:
            raise ValueError('ALPN extension must expose its structural vector')


def _reduce(current, observation):
    _validate_observation(observation)
    hello = observation.client_hello
    values = {member.name: getattr(current, member.name) for member in fields(current)}
    values['total_client_hello_count'] += 1
    legacy = int.from_bytes(hello.legacy_version, 'big')
    legacy_counts = list(values['legacy_version_counts'])
    legacy_counts[legacy] += 1
    values['legacy_version_counts'] = tuple(legacy_counts)
    for field, value, operation in (
        ('min_legacy_version', legacy, min), ('max_legacy_version', legacy, max),
        ('min_session_id_length', len(hello.session_id), min), ('max_session_id_length', len(hello.session_id), max),
        ('min_cipher_suite_count', len(hello.cipher_suites), min), ('max_cipher_suite_count', len(hello.cipher_suites), max),
        ('min_compression_method_count', len(hello.compression_methods), min), ('max_compression_method_count', len(hello.compression_methods), max),
        ('min_extension_count', len(hello.extensions), min), ('max_extension_count', len(hello.extensions), max),
    ):
        values[field] = value if values[field] is None else operation(values[field], value)
    values['total_session_id_bytes'] += len(hello.session_id)
    values['total_cipher_suite_count'] += len(hello.cipher_suites)
    values['total_compression_method_count'] += len(hello.compression_methods)
    values['total_extension_count'] += len(hello.extensions)
    cipher_counts = list(values['cipher_suite_counts'])
    for suite in hello.cipher_suites:
        cipher_counts[suite] += 1
    values['cipher_suite_counts'] = tuple(cipher_counts)
    compression_counts = list(values['compression_method_counts'])
    for method in hello.compression_methods:
        compression_counts[method] += 1
    values['compression_method_counts'] = tuple(compression_counts)
    extension_counts = list(values['extension_type_counts'])
    seen = ()
    for extension in hello.extensions:
        kind = extension.extension_type
        extension_counts[kind] += 1
        if kind in seen:
            values['duplicate_extension_count'] += 1
        else:
            seen += (kind,)
        if kind not in (10, 13, 16):
            values['unknown_extension_count'] += 1
        selected = (
            ('supported_groups', 'supported_groups_extension_count', 'total_supported_groups_count',
             'min_supported_groups_count', 'max_supported_groups_count', extension.supported_groups),
            ('signature_algorithms', 'signature_algorithms_extension_count', 'total_signature_algorithms_count',
             'min_signature_algorithms_count', 'max_signature_algorithms_count', extension.signature_algorithms),
            ('alpn', 'alpn_extension_count', 'total_alpn_protocol_count',
             'min_alpn_protocol_count', 'max_alpn_protocol_count', extension.alpn_protocols),
        )
        for _, extension_field, total_field, minimum_field, maximum_field, items in selected:
            if items is not None:
                count = len(items)
                values[extension_field] += 1
                values[total_field] += count
                values[minimum_field] = count if values[minimum_field] is None else min(values[minimum_field], count)
                values[maximum_field] = count if values[maximum_field] is None else max(values[maximum_field], count)
    values['extension_type_counts'] = tuple(extension_counts)
    return TLSClientHelloStatistics(**values)


def update_tls_client_hello_statistics(
    current: Optional[TLSClientHelloStatistics], observation: TLSClientHelloObservation,
) -> TLSClientHelloStatistics:
    if current is not None and type(current) is not TLSClientHelloStatistics:
        raise TypeError('current must be exactly a TLSClientHelloStatistics or None')
    return _reduce(TLSClientHelloStatistics() if current is None else current, observation)


def update_directional_tls_client_hello_statistics(
    current: Optional[DirectionalTLSClientHelloStatistics], observation: TLSClientHelloObservation,
) -> DirectionalTLSClientHelloStatistics:
    if current is not None and type(current) is not DirectionalTLSClientHelloStatistics:
        raise TypeError('current must be exactly a DirectionalTLSClientHelloStatistics or None')
    _validate_observation(observation)
    current = DirectionalTLSClientHelloStatistics() if current is None else current
    name = 'forward' if observation.direction is FlowDirection.FORWARD else 'reverse'
    return replace(current, **{name: _reduce(getattr(current, name), observation)})
