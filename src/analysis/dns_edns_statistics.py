from dataclasses import dataclass, fields
from fractions import Fraction
from typing import Optional

from analysis.dns import (
    DNSEDNS, DNSEDNSOption, DNSMessageObservation, DNSMessageStatus,
    DNS_MAX_EDNS_OPTIONS, DNS_MAX_EDNS_OPTION_BYTES, DNS_MAX_EDNS_OPTION_DATA_BYTES,
)
from analysis.dns_correlation import DNSCorrelationStatus, DNSTransactionObservation


_EMPTY_BINS = (0,) * 256
_EMPTY_CODES = (_EMPTY_BINS,) * 256


def _bins_total(bins, name):
    if bins is _EMPTY_BINS:
        return 0
    if type(bins) is not tuple or len(bins) != 256:
        raise TypeError(f'{name} must contain exactly 256 immutable bins')
    for count in bins:
        if type(count) is not int:
            raise TypeError(f'{name} bins must be exact integers')
        if count < 0:
            raise ValueError(f'{name} bins must not be negative')
    return sum(bins)


def _range(count, total, minimum, maximum, limit):
    if count == 0:
        if total != 0 or minimum is not None or maximum is not None:
            raise ValueError('empty observations require zero total and absent extrema')
    elif minimum is None or maximum is None or not 0 <= minimum <= maximum <= limit:
        raise ValueError('observed extrema must be ordered within parser bounds')
    elif not (count - 1) * minimum + maximum <= total <= (count - 1) * maximum + minimum:
        raise ValueError('total must be consistent with observed extrema')


def _bounded_integer(value, limit, name):
    if type(value) is not int:
        raise TypeError(f'{name} must be exactly an integer')
    if not 0 <= value <= limit:
        raise ValueError(f'{name} exceeds parser bounds')
    return value


@dataclass(frozen=True)
class DNSEDNSStatistics:
    edns_message_count: int = 0
    option_count: int = 0
    min_option_data_length: Optional[int] = None
    max_option_data_length: Optional[int] = None
    total_option_data_length_bytes: int = 0
    zero_length_option_count: int = 0
    max_options_in_message: Optional[int] = None
    min_options_in_message: Optional[int] = None
    udp_payload_size_min: Optional[int] = None
    udp_payload_size_max: Optional[int] = None
    udp_payload_size_total: int = 0
    extended_rcode_counts: tuple[int, ...] = _EMPTY_BINS
    version_counts: tuple[int, ...] = _EMPTY_BINS
    option_code_counts: tuple[tuple[int, ...], ...] = _EMPTY_CODES
    dnssec_ok_count: int = 0

    def __post_init__(self) -> None:
        for member in fields(self):
            if member.name.endswith('_counts'):
                continue
            value = getattr(self, member.name)
            if value is None and (member.name.startswith(('min_', 'max_')) or member.name.endswith(('_min', '_max'))):
                continue
            if type(value) is not int:
                raise TypeError(f'{member.name} must be exactly an integer')
            if value < 0:
                raise ValueError(f'{member.name} must not be negative')
        _range(self.option_count, self.total_option_data_length_bytes, self.min_option_data_length,
               self.max_option_data_length, DNS_MAX_EDNS_OPTION_DATA_BYTES)
        _range(self.edns_message_count, self.option_count, self.min_options_in_message,
               self.max_options_in_message, DNS_MAX_EDNS_OPTIONS)
        _range(self.edns_message_count, self.udp_payload_size_total, self.udp_payload_size_min,
               self.udp_payload_size_max, 65535)
        if self.dnssec_ok_count > self.edns_message_count:
            raise ValueError('DO count must not exceed EDNS message count')
        if self.zero_length_option_count > self.option_count:
            raise ValueError('zero-length count must not exceed option count')
        if self.option_count:
            if (self.min_option_data_length == 0) != (self.zero_length_option_count > 0):
                raise ValueError('zero-length observations must agree with minimum length')
            positive = self.option_count - self.zero_length_option_count
            if not positive <= self.total_option_data_length_bytes <= positive * self.max_option_data_length:
                raise ValueError('data total must agree with positive-length option count')
            if positive and self.total_option_data_length_bytes < self.max_option_data_length + positive - 1:
                raise ValueError('data total must include the maximum and every positive-length option')
        if self.total_option_data_length_bytes + 4 * self.option_count > self.edns_message_count * DNS_MAX_EDNS_OPTION_BYTES:
            raise ValueError('option envelopes must fit aggregate parser byte bounds')
        for name in ('extended_rcode_counts', 'version_counts'):
            if _bins_total(getattr(self, name), name) != self.edns_message_count:
                raise ValueError(f'{name} must sum to edns_message_count')
        codes = self.option_code_counts
        if type(codes) is not tuple or len(codes) != 256:
            raise TypeError('option_code_counts must contain 256 immutable blocks')
        total = 0 if codes is _EMPTY_CODES else sum(_bins_total(block, 'option_code_counts') for block in codes)
        if total != self.option_count:
            raise ValueError('option_code_counts must sum to option_count')

    @property
    def mean_option_data_length(self) -> Optional[Fraction]:
        return None if self.option_count == 0 else Fraction(self.total_option_data_length_bytes, self.option_count)

    @property
    def unknown_option_count(self) -> int:
        return self.option_count

    @property
    def non_dnssec_ok_count(self) -> int:
        return self.edns_message_count - self.dnssec_ok_count


def update_dns_edns_statistics(
    current: Optional[DNSEDNSStatistics], observation: DNSTransactionObservation,
) -> DNSEDNSStatistics:
    if current is not None and type(current) is not DNSEDNSStatistics:
        raise TypeError('current must be exactly a DNSEDNSStatistics or None')
    if type(observation) is not DNSTransactionObservation:
        raise TypeError('observation must be exactly a DNSTransactionObservation')
    if observation.status not in (DNSCorrelationStatus.MATCHED, DNSCorrelationStatus.UNMATCHED,
                                  DNSCorrelationStatus.AMBIGUOUS, DNSCorrelationStatus.UNRESOLVED):
        raise ValueError('EDNS statistics require a terminal transaction observation')
    current = DNSEDNSStatistics() if current is None else current
    values = {member.name: getattr(current, member.name) for member in fields(current) if not member.name.endswith('_counts')}
    rcodes, versions, codes = list(current.extended_rcode_counts), list(current.version_counts), list(current.option_code_counts)
    messages = (observation.request, observation.message) if observation.status is DNSCorrelationStatus.MATCHED else (observation.message,)
    for message in messages:
        if type(message) is not DNSMessageObservation:
            raise TypeError('contributing messages must be exactly DNSMessageObservation values')
        if message.status is not DNSMessageStatus.COMPLETE:
            raise ValueError('contributing DNS messages must be complete')
        edns = message.edns
        if edns is None:
            continue
        if type(edns) is not DNSEDNS:
            raise TypeError('EDNS must be exactly a parsed DNSEDNS value')
        if type(edns.options) is not tuple:
            raise TypeError('EDNS options must be exactly a tuple')
        count = len(edns.options)
        if count > DNS_MAX_EDNS_OPTIONS:
            raise ValueError('EDNS option count exceeds parser bound')
        size = _bounded_integer(edns.udp_payload_size, 65535, 'UDP payload size')
        rcode = _bounded_integer(edns.extended_rcode, 255, 'extended RCODE')
        version = _bounded_integer(edns.version, 255, 'EDNS version')
        enabled = edns.dnssec_ok
        if type(enabled) is not bool:
            raise TypeError('DNSSEC OK must be exactly a boolean')
        values['edns_message_count'] += 1
        values['option_count'] += count
        values['dnssec_ok_count'] += int(enabled)
        values['udp_payload_size_total'] += size
        for name, value, operation in (
            ('min_options_in_message', count, min), ('max_options_in_message', count, max),
            ('udp_payload_size_min', size, min), ('udp_payload_size_max', size, max),
        ):
            values[name] = value if values[name] is None else operation(values[name], value)
        rcodes[rcode] += 1
        versions[version] += 1
        message_bytes = 4 * count
        for option in edns.options:
            if type(option) is not DNSEDNSOption:
                raise TypeError('options must be exactly parsed DNSEDNSOption values')
            length = _bounded_integer(option.data_length, DNS_MAX_EDNS_OPTION_DATA_BYTES, 'option data length')
            code = _bounded_integer(option.code, 65535, 'option code')
            message_bytes += length
            if message_bytes > DNS_MAX_EDNS_OPTION_BYTES:
                raise ValueError('option envelopes exceed parser byte bound')
            values['total_option_data_length_bytes'] += length
            values['zero_length_option_count'] += int(length == 0)
            for name, operation in (('min_option_data_length', min), ('max_option_data_length', max)):
                values[name] = length if values[name] is None else operation(values[name], length)
            high, low = divmod(code, 256)
            block = list(codes[high])
            block[low] += 1
            codes[high] = tuple(block)
    if values['edns_message_count'] == current.edns_message_count:
        return current
    return DNSEDNSStatistics(**values, extended_rcode_counts=tuple(rcodes), version_counts=tuple(versions),
                             option_code_counts=tuple(codes))
