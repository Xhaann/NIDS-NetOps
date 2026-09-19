from dataclasses import dataclass, fields, replace
from typing import Optional

from analysis.flow_direction import FlowDirection
from analysis.flow_identity import FlowIdentity
from analysis.tls_server_hello import (
    TLS_SERVER_HELLO_MAX_EXTENSION_DATA_BYTES,
    TLS_SERVER_HELLO_MAX_EXTENSIONS,
    TLS_SERVER_HELLO_MAX_SESSION_ID_BYTES,
    TLSServerHelloExtension,
    TLSServerHello,
    TLSServerHelloObservation,
    TLSServerHelloStatus,
)


TLS_SERVER_HELLO_VERSION_BINS = 65536
TLS_SERVER_HELLO_CIPHER_SUITE_BINS = 65536
TLS_SERVER_HELLO_COMPRESSION_METHOD_BINS = 256
TLS_SERVER_HELLO_EXTENSION_TYPE_BINS = 65536
_EMPTY_16 = ()
_EMPTY_8 = ()


def _validate_bins(value, size, name, total):
    if type(value) is not tuple:
        raise TypeError(f'{name} must be exactly an immutable tuple of occupied bins')
    previous = None
    counted = 0
    for item in value:
        if type(item) is not tuple or len(item) != 2:
            raise TypeError(f'{name} must contain exact (bin, count) tuples')
        index, count = item
        if type(index) is not int or not 0 <= index < size:
            raise ValueError(f'{name} bin indexes must be within their wire domain')
        if type(count) is not int:
            raise TypeError(f'{name} bins must contain exact integers')
        if count <= 0:
            raise ValueError(f'{name} bins must be positive')
        if previous is not None and index <= previous:
            raise ValueError(f'{name} bins must be strictly ordered')
        previous = index
        counted += count
    if counted != total:
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
class TLSServerHelloStatistics:
    total_server_hello_count: int = 0
    legacy_version_counts: tuple[tuple[int, int], ...] = _EMPTY_16
    min_legacy_version: Optional[int] = None
    max_legacy_version: Optional[int] = None
    min_session_id_length: Optional[int] = None
    max_session_id_length: Optional[int] = None
    total_session_id_bytes: int = 0
    cipher_suite_counts: tuple[tuple[int, int], ...] = _EMPTY_16
    compression_method_counts: tuple[tuple[int, int], ...] = _EMPTY_8
    extensions_present_count: int = 0
    min_extension_count: Optional[int] = None
    max_extension_count: Optional[int] = None
    total_extension_count: int = 0
    extension_type_counts: tuple[tuple[int, int], ...] = _EMPTY_16
    min_extension_data_length: Optional[int] = None
    max_extension_data_length: Optional[int] = None
    total_extension_data_bytes: int = 0
    duplicate_extension_count: int = 0

    def __post_init__(self) -> None:
        for member in fields(self):
            value = getattr(self, member.name)
            if member.name.endswith('_counts'):
                continue
            if value is None:
                if not (member.name.startswith('min_') or member.name.startswith('max_')):
                    raise TypeError(f'{member.name} must be exactly an integer')
                continue
            _validate_count(value, member.name)
        _validate_bins(self.legacy_version_counts, 65536, 'legacy_version_counts', self.total_server_hello_count)
        _validate_bins(self.cipher_suite_counts, 65536, 'cipher_suite_counts', self.total_server_hello_count)
        _validate_bins(self.compression_method_counts, 256, 'compression_method_counts', self.total_server_hello_count)
        _validate_bins(self.extension_type_counts, 65536, 'extension_type_counts', self.total_extension_count)
        _validate_extrema(self.total_server_hello_count, self.min_legacy_version,
                          self.max_legacy_version, 65535, 'legacy version')
        _validate_range(self.total_server_hello_count, self.total_session_id_bytes,
                        self.min_session_id_length, self.max_session_id_length,
                        TLS_SERVER_HELLO_MAX_SESSION_ID_BYTES, 'session ID')
        _validate_range(self.total_server_hello_count, self.total_extension_count,
                        self.min_extension_count, self.max_extension_count,
                        TLS_SERVER_HELLO_MAX_EXTENSIONS, 'extension')
        _validate_range(self.total_extension_count, self.total_extension_data_bytes,
                        self.min_extension_data_length, self.max_extension_data_length,
                        TLS_SERVER_HELLO_MAX_EXTENSION_DATA_BYTES, 'extension data')
        if self.extensions_present_count > self.total_server_hello_count:
            raise ValueError('extensions-present count must not exceed ServerHello count')
        if self.duplicate_extension_count > self.total_extension_count:
            raise ValueError('duplicate extension count must not exceed total extension count')

    @property
    def server_hello_count(self) -> int:
        return self.total_server_hello_count

    @property
    def legacy_version_distribution(self) -> tuple[tuple[int, int], ...]:
        return self.legacy_version_counts

    @property
    def cipher_suite_frequency(self) -> tuple[tuple[int, int], ...]:
        return self.cipher_suite_counts

    @property
    def compression_method_frequency(self) -> tuple[tuple[int, int], ...]:
        return self.compression_method_counts

    @property
    def extension_type_frequency(self) -> tuple[tuple[int, int], ...]:
        return self.extension_type_counts

    @property
    def extensions_absent_count(self) -> int:
        return self.total_server_hello_count - self.extensions_present_count

    @property
    def duplicate_extension_occurrence_count(self) -> int:
        return self.duplicate_extension_count


@dataclass(frozen=True)
class DirectionalTLSServerHelloStatistics:
    forward: TLSServerHelloStatistics = TLSServerHelloStatistics()
    reverse: TLSServerHelloStatistics = TLSServerHelloStatistics()

    def __post_init__(self) -> None:
        if type(self.forward) is not TLSServerHelloStatistics or type(self.reverse) is not TLSServerHelloStatistics:
            raise TypeError('directional aggregates must be exactly TLSServerHelloStatistics values')


def _validate_observation(observation):
    if type(observation) is not TLSServerHelloObservation:
        raise TypeError('observation must be exactly a TLSServerHelloObservation')
    if type(observation.identity) is not FlowIdentity or type(observation.direction) is not FlowDirection:
        raise TypeError('observation must have an exact flow identity and direction')
    if observation.status is not TLSServerHelloStatus.COMPLETE or observation.server_hello is None:
        raise ValueError('statistics require a complete ServerHello observation')
    hello = observation.server_hello
    if type(hello) is not TLSServerHello:
        raise TypeError('ServerHello value must be exactly a TLSServerHello')
    if type(hello.legacy_version) is not bytes or len(hello.legacy_version) != 2:
        raise TypeError('ServerHello legacy version must be exactly two bytes')
    if type(hello.session_id) is not bytes or len(hello.session_id) > TLS_SERVER_HELLO_MAX_SESSION_ID_BYTES:
        raise ValueError('ServerHello session ID exceeds its parser bound')
    if type(hello.cipher_suite) is not int or not 0 <= hello.cipher_suite <= 65535:
        raise ValueError('ServerHello cipher suite must be a bounded integer')
    if type(hello.compression_method) is not int or not 0 <= hello.compression_method <= 255:
        raise ValueError('ServerHello compression method must be a bounded integer')
    if type(hello.extensions_present) is not bool:
        raise TypeError('ServerHello extension presence must be exactly a boolean')
    if type(hello.extensions) is not tuple or len(hello.extensions) > TLS_SERVER_HELLO_MAX_EXTENSIONS:
        raise ValueError('ServerHello extension vector exceeds its parser bound')
    if hello.extensions_present:
        if type(hello.extensions_length) is not int or not 0 <= hello.extensions_length <= 65535:
            raise ValueError('present ServerHello extensions require a bounded length')
    elif hello.extensions_length is not None or hello.extensions:
        raise ValueError('absent ServerHello extensions require no length or values')
    for extension in hello.extensions:
        if type(extension) is not TLSServerHelloExtension:
            raise TypeError('ServerHello extensions must be exact TLSServerHelloExtension values')
        if type(extension.extension_type) is not int or not 0 <= extension.extension_type <= 65535:
            raise ValueError('extension identifiers must be bounded integers')
        if type(extension.data) is not bytes or len(extension.data) > TLS_SERVER_HELLO_MAX_EXTENSION_DATA_BYTES:
            raise ValueError('extension data exceeds its parser bound')
    if hello.extensions_length is not None and hello.extensions_length != sum(4 + len(item.data) for item in hello.extensions):
        raise ValueError('ServerHello extension values must fill their declared length')


def _reduce(current, observation):
    _validate_observation(observation)
    hello = observation.server_hello
    values = {member.name: getattr(current, member.name) for member in fields(current)}
    values['total_server_hello_count'] += 1
    legacy = int.from_bytes(hello.legacy_version, 'big')
    legacy_counts = dict(values['legacy_version_counts'])
    legacy_counts[legacy] = legacy_counts.get(legacy, 0) + 1
    values['legacy_version_counts'] = tuple(sorted(legacy_counts.items()))
    for field, value, operation in (
        ('min_legacy_version', legacy, min), ('max_legacy_version', legacy, max),
        ('min_session_id_length', len(hello.session_id), min), ('max_session_id_length', len(hello.session_id), max),
        ('min_extension_count', len(hello.extensions), min), ('max_extension_count', len(hello.extensions), max),
    ):
        values[field] = value if values[field] is None else operation(values[field], value)
    values['total_session_id_bytes'] += len(hello.session_id)
    cipher_counts = dict(values['cipher_suite_counts'])
    cipher_counts[hello.cipher_suite] = cipher_counts.get(hello.cipher_suite, 0) + 1
    values['cipher_suite_counts'] = tuple(sorted(cipher_counts.items()))
    compression_counts = dict(values['compression_method_counts'])
    compression_counts[hello.compression_method] = compression_counts.get(hello.compression_method, 0) + 1
    values['compression_method_counts'] = tuple(sorted(compression_counts.items()))
    values['extensions_present_count'] += int(hello.extensions_present)
    values['total_extension_count'] += len(hello.extensions)
    extension_counts = dict(values['extension_type_counts'])
    for extension in hello.extensions:
        extension_counts[extension.extension_type] = extension_counts.get(extension.extension_type, 0) + 1
        values['total_extension_data_bytes'] += len(extension.data)
        values['min_extension_data_length'] = (
            len(extension.data) if values['min_extension_data_length'] is None
            else min(values['min_extension_data_length'], len(extension.data))
        )
        values['max_extension_data_length'] = (
            len(extension.data) if values['max_extension_data_length'] is None
            else max(values['max_extension_data_length'], len(extension.data))
        )
    seen = ()
    for extension in hello.extensions:
        if extension.extension_type in seen:
            values['duplicate_extension_count'] += 1
        else:
            seen += (extension.extension_type,)
    values['extension_type_counts'] = tuple(sorted(extension_counts.items()))
    return TLSServerHelloStatistics(**values)


def update_tls_server_hello_statistics(
    current: Optional[TLSServerHelloStatistics], observation: TLSServerHelloObservation,
) -> TLSServerHelloStatistics:
    if current is not None and type(current) is not TLSServerHelloStatistics:
        raise TypeError('current must be exactly a TLSServerHelloStatistics or None')
    return _reduce(TLSServerHelloStatistics() if current is None else current, observation)


def update_directional_tls_server_hello_statistics(
    current: Optional[DirectionalTLSServerHelloStatistics], observation: TLSServerHelloObservation,
) -> DirectionalTLSServerHelloStatistics:
    if current is not None and type(current) is not DirectionalTLSServerHelloStatistics:
        raise TypeError('current must be exactly a DirectionalTLSServerHelloStatistics or None')
    _validate_observation(observation)
    current = DirectionalTLSServerHelloStatistics() if current is None else current
    name = 'forward' if observation.direction is FlowDirection.FORWARD else 'reverse'
    return replace(current, **{name: _reduce(getattr(current, name), observation)})
