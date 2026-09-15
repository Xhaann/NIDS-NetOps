from dataclasses import dataclass, fields
from fractions import Fraction
from typing import Optional

from analysis.dns import DNS_MAX_LABEL_BYTES, DNS_MAX_NAME_BYTES
from analysis.dns_correlation import DNSCorrelationStatus, DNSTransactionObservation


@dataclass(frozen=True)
class DNSQueryNameStatistics:
    query_name_count: int = 0
    label_count: int = 0
    total_name_length_bytes: int = 0
    min_name_length_bytes: Optional[int] = None
    max_name_length_bytes: Optional[int] = None
    total_label_length_bytes: int = 0
    min_label_length_bytes: Optional[int] = None
    max_label_length_bytes: Optional[int] = None
    max_labels_per_name: Optional[int] = None
    min_labels_per_non_root_name: Optional[int] = None
    root_name_count: int = 0
    digit_name_count: int = 0
    hyphen_name_count: int = 0
    underscore_name_count: int = 0
    non_ascii_name_count: int = 0

    def __post_init__(self) -> None:
        for member in fields(self):
            value = getattr(self, member.name)
            if value is None and member.name.startswith(('min_', 'max_')):
                continue
            if type(value) is not int:
                raise TypeError(f'{member.name} must be exactly an integer')
            if value < 0:
                raise ValueError(f'{member.name} must not be negative')
        if self.root_name_count > self.query_name_count:
            raise ValueError('root count must not exceed query-name count')
        non_root = self.query_name_count - self.root_name_count
        for count in (self.digit_name_count, self.hyphen_name_count, self.underscore_name_count, self.non_ascii_name_count):
            if count > non_root:
                raise ValueError('byte-class counts must not exceed non-root name count')
        if self.total_name_length_bytes != self.total_label_length_bytes + self.label_count + self.query_name_count:
            raise ValueError('expanded name totals must include label lengths and root octets')
        for count, total, minimum, maximum, limit in (
            (self.query_name_count, self.total_name_length_bytes, self.min_name_length_bytes,
             self.max_name_length_bytes, DNS_MAX_NAME_BYTES),
            (self.label_count, self.total_label_length_bytes, self.min_label_length_bytes,
             self.max_label_length_bytes, DNS_MAX_LABEL_BYTES),
        ):
            if count == 0:
                if total != 0 or minimum is not None or maximum is not None:
                    raise ValueError('empty lengths require zero total and absent extrema')
            elif minimum is None or maximum is None or not 1 <= minimum <= maximum <= limit:
                raise ValueError('observed lengths require ordered extrema within parser bounds')
            elif not minimum * count <= total <= maximum * count:
                raise ValueError('length total must lie within extrema bounds')
        maximum = self.max_labels_per_name
        minimum = self.min_labels_per_non_root_name
        if self.query_name_count == 0:
            if maximum is not None:
                raise ValueError('no names require absent maximum label count')
        elif maximum is None or not 0 <= maximum <= (DNS_MAX_NAME_BYTES - 1) // 2:
            raise ValueError('maximum label count must lie within parser bounds')
        if non_root == 0:
            if self.label_count != 0 or minimum is not None or (self.query_name_count and maximum != 0):
                raise ValueError('no non-root names require zero labels and absent non-root minimum')
        elif minimum is None or maximum is None or not 1 <= minimum <= maximum:
            raise ValueError('non-root names require ordered positive label counts')
        elif not minimum * non_root <= self.label_count <= maximum * non_root:
            raise ValueError('label total must lie within non-root count bounds')
        if self.root_name_count and self.min_name_length_bytes != 1:
            raise ValueError('root observations require minimum expanded length one')
        if non_root and self.min_name_length_bytes == 1 and self.root_name_count == 0:
            raise ValueError('expanded length one requires a root observation')

    @property
    def mean_name_length_bytes(self) -> Optional[Fraction]:
        return None if self.query_name_count == 0 else Fraction(self.total_name_length_bytes, self.query_name_count)

    @property
    def mean_label_length_bytes(self) -> Optional[Fraction]:
        return None if self.label_count == 0 else Fraction(self.total_label_length_bytes, self.label_count)


def update_dns_query_name_statistics(
    current: Optional[DNSQueryNameStatistics], observation: DNSTransactionObservation,
) -> DNSQueryNameStatistics:
    if current is not None and type(current) is not DNSQueryNameStatistics:
        raise TypeError('current must be exactly a DNSQueryNameStatistics or None')
    if type(observation) is not DNSTransactionObservation:
        raise TypeError('observation must be exactly a DNSTransactionObservation')
    if observation.status is DNSCorrelationStatus.PENDING:
        raise ValueError('query-name statistics require a finalized transaction observation')
    current = DNSQueryNameStatistics() if current is None else current
    values = {member.name: getattr(current, member.name) for member in fields(current)}
    messages = (observation.request, observation.message) if observation.status is DNSCorrelationStatus.MATCHED else (observation.message,)
    for message in messages:
        for question in message.questions:
            name = question.name
            count = len(name.labels)
            length = name.expanded_length
            values['query_name_count'] += 1
            values['label_count'] += count
            values['total_name_length_bytes'] += length
            values['root_name_count'] += int(count == 0)
            for field, value, operation in (
                ('min_name_length_bytes', length, min),
                ('max_name_length_bytes', length, max),
                ('max_labels_per_name', count, max),
            ):
                values[field] = value if values[field] is None else operation(values[field], value)
            if count:
                minimum = values['min_labels_per_non_root_name']
                values['min_labels_per_non_root_name'] = count if minimum is None else min(minimum, count)
            digit = hyphen = underscore = non_ascii = False
            for label in name.labels:
                length = len(label)
                values['total_label_length_bytes'] += length
                for field, operation in (('min_label_length_bytes', min), ('max_label_length_bytes', max)):
                    values[field] = length if values[field] is None else operation(values[field], length)
                for byte in label:
                    digit |= 48 <= byte <= 57
                    hyphen |= byte == 45
                    underscore |= byte == 95
                    non_ascii |= byte >= 128
            for field, present in (('digit_name_count', digit), ('hyphen_name_count', hyphen),
                                   ('underscore_name_count', underscore), ('non_ascii_name_count', non_ascii)):
                values[field] += int(present)
    return DNSQueryNameStatistics(**values)
