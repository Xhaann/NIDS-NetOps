from dataclasses import dataclass
from fractions import Fraction
from typing import Optional

from analysis.dns import DNSMessageObservation, DNSMessageStatus
from analysis.dns_correlation import DNSCorrelationStatus, DNSTransactionObservation


_EMPTY_BLOCK = (0,) * 256
_EMPTY_COUNTS = (_EMPTY_BLOCK,) * 256


def _distribution_total(counts, name):
    if counts is _EMPTY_COUNTS:
        return 0
    if type(counts) is not tuple or len(counts) != 256:
        raise TypeError(f'{name} must be a tuple of 256 immutable blocks')
    total = 0
    for block in counts:
        if type(block) is not tuple or len(block) != 256:
            raise TypeError(f'{name} blocks must be tuples of 256 integers')
        if block is _EMPTY_BLOCK:
            continue
        for count in block:
            if type(count) is not int:
                raise TypeError(f'{name} bins must be exact integers')
            if count < 0:
                raise ValueError(f'{name} bins must not be negative')
            total += count
    return total


@dataclass(frozen=True)
class DNSResourceRecordStatistics:
    answer_count: int = 0
    authority_count: int = 0
    additional_count: int = 0
    total_rdata_length_bytes: int = 0
    min_rdata_length_bytes: Optional[int] = None
    max_rdata_length_bytes: Optional[int] = None
    type_counts: tuple[tuple[int, ...], ...] = _EMPTY_COUNTS
    class_counts: tuple[tuple[int, ...], ...] = _EMPTY_COUNTS

    def __post_init__(self) -> None:
        for name in ('answer_count', 'authority_count', 'additional_count', 'total_rdata_length_bytes',
                     'min_rdata_length_bytes', 'max_rdata_length_bytes'):
            value = getattr(self, name)
            if value is None and name in ('min_rdata_length_bytes', 'max_rdata_length_bytes'):
                continue
            if type(value) is not int:
                raise TypeError(f'{name} must be exactly an integer')
            if value < 0:
                raise ValueError(f'{name} must not be negative')
        minimum = self.min_rdata_length_bytes
        maximum = self.max_rdata_length_bytes
        count = self.resource_record_count
        if count == 0:
            if minimum is not None or maximum is not None or self.total_rdata_length_bytes != 0:
                raise ValueError('no records require absent extrema and zero RDATA total')
        elif minimum is None or maximum is None or not 0 <= minimum <= maximum <= 65535:
            raise ValueError('records require ordered unsigned 16-bit RDATA length extrema')
        elif not minimum * count <= self.total_rdata_length_bytes <= maximum * count:
            raise ValueError('RDATA total must lie within extrema bounds')
        for name in ('type_counts', 'class_counts'):
            if _distribution_total(getattr(self, name), name) != count:
                raise ValueError(f'{name} must sum to resource_record_count')

    @property
    def resource_record_count(self) -> int:
        return self.answer_count + self.authority_count + self.additional_count

    @property
    def mean_rdata_length_bytes(self) -> Optional[Fraction]:
        return None if self.resource_record_count == 0 else Fraction(self.total_rdata_length_bytes, self.resource_record_count)


def _increment_code(blocks, code):
    high, low = divmod(code, 256)
    block = list(blocks[high])
    block[low] += 1
    blocks[high] = tuple(block)


def update_dns_resource_record_statistics(
    current: Optional[DNSResourceRecordStatistics], observation: DNSTransactionObservation,
) -> DNSResourceRecordStatistics:
    if current is not None and type(current) is not DNSResourceRecordStatistics:
        raise TypeError('current must be exactly a DNSResourceRecordStatistics or None')
    if type(observation) is not DNSTransactionObservation:
        raise TypeError('observation must be exactly a DNSTransactionObservation')
    if observation.status not in (DNSCorrelationStatus.MATCHED, DNSCorrelationStatus.UNMATCHED,
                                  DNSCorrelationStatus.AMBIGUOUS, DNSCorrelationStatus.UNRESOLVED):
        raise ValueError('resource-record statistics require a terminal transaction observation')
    messages = (observation.request, observation.message) if observation.status is DNSCorrelationStatus.MATCHED else (observation.message,)
    for message in messages:
        if type(message) is not DNSMessageObservation:
            raise TypeError('contributing messages must be exactly DNSMessageObservation values')
        if message.status is not DNSMessageStatus.COMPLETE:
            raise ValueError('contributing DNS messages must be complete')
    current = DNSResourceRecordStatistics() if current is None else current
    values = dict(answer_count=current.answer_count, authority_count=current.authority_count,
                  additional_count=current.additional_count, total_rdata_length_bytes=current.total_rdata_length_bytes,
                  min_rdata_length_bytes=current.min_rdata_length_bytes, max_rdata_length_bytes=current.max_rdata_length_bytes)
    types, classes = list(current.type_counts), list(current.class_counts)
    added = 0
    for message in messages:
        for section, field in ((message.answers, 'answer_count'), (message.authorities, 'authority_count'),
                               (message.additionals, 'additional_count')):
            values[field] += len(section)
            for record in section:
                length = record.rdlength
                added += 1
                values['total_rdata_length_bytes'] += length
                for name, operation in (('min_rdata_length_bytes', min), ('max_rdata_length_bytes', max)):
                    values[name] = length if values[name] is None else operation(values[name], length)
                _increment_code(types, record.record_type)
                _increment_code(classes, record.record_class)
    if added == 0:
        return current
    return DNSResourceRecordStatistics(**values, type_counts=tuple(types), class_counts=tuple(classes))
