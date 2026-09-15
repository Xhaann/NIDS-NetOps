from dataclasses import dataclass, fields, replace
from fractions import Fraction
from typing import Optional

from analysis.dns_correlation import DNSCorrelationStatus, DNSTransactionObservation


@dataclass(frozen=True)
class DNSTransactionStatistics:
    matched_count: int = 0
    unmatched_response_count: int = 0
    ambiguous_count: int = 0
    unresolved_count: int = 0
    question_count: int = 0
    answer_count: int = 0
    authority_count: int = 0
    additional_count: int = 0
    total_matched_latency_microseconds: int = 0
    min_matched_latency_microseconds: Optional[int] = None
    max_matched_latency_microseconds: Optional[int] = None
    opcode_counts: tuple[int, ...] = (0,) * 16
    response_code_counts: tuple[int, ...] = (0,) * 16

    def __post_init__(self) -> None:
        for member in fields(self):
            value = getattr(self, member.name)
            if member.name in ('opcode_counts', 'response_code_counts'):
                if type(value) is not tuple:
                    raise TypeError(f'{member.name} must be exactly a tuple')
                if len(value) != 16:
                    raise ValueError(f'{member.name} must contain 16 bins')
                values = value
            elif member.name in ('min_matched_latency_microseconds', 'max_matched_latency_microseconds') and value is None:
                continue
            else:
                values = (value,)
            for count in values:
                if type(count) is not int:
                    raise TypeError(f'{member.name} must contain exact integers')
                if count < 0:
                    raise ValueError(f'{member.name} must not be negative')
        minimum = self.min_matched_latency_microseconds
        maximum = self.max_matched_latency_microseconds
        if self.matched_count == 0:
            if minimum is not None or maximum is not None or self.total_matched_latency_microseconds != 0:
                raise ValueError('no matches require absent extrema and zero total latency')
        elif minimum is None or maximum is None or minimum > maximum:
            raise ValueError('matches require ordered latency extrema')
        elif not minimum * self.matched_count <= self.total_matched_latency_microseconds <= maximum * self.matched_count:
            raise ValueError('latency total must be within the extrema bounds')
        if sum(self.opcode_counts) != self.total_transaction_count + self.matched_count:
            raise ValueError('opcode bins must count all contributing messages')
        responses = self.matched_count + self.unmatched_response_count
        if not responses <= sum(self.response_code_counts) <= responses + self.ambiguous_count:
            raise ValueError('response-code bins must count responding messages')
        if self.total_transaction_count == 0 and any((
            self.question_count, self.answer_count, self.authority_count, self.additional_count,
        )):
            raise ValueError('no transactions require zero record counts')

    @property
    def unmatched_count(self) -> int:
        return self.unmatched_response_count

    @property
    def total_transaction_count(self) -> int:
        return self.matched_count + self.unmatched_count + self.ambiguous_count + self.unresolved_count

    @property
    def mean_matched_latency_microseconds(self) -> Optional[Fraction]:
        if self.matched_count == 0:
            return None
        return Fraction(self.total_matched_latency_microseconds, self.matched_count)


def update_dns_transaction_statistics(
    current: Optional[DNSTransactionStatistics], observation: DNSTransactionObservation,
) -> DNSTransactionStatistics:
    if current is not None and type(current) is not DNSTransactionStatistics:
        raise TypeError('current must be exactly a DNSTransactionStatistics or None')
    if type(observation) is not DNSTransactionObservation:
        raise TypeError('observation must be exactly a DNSTransactionObservation')
    if observation.status is DNSCorrelationStatus.PENDING:
        raise ValueError('statistics require a finalized transaction observation')
    bucket = {
        DNSCorrelationStatus.MATCHED: 'matched_count',
        DNSCorrelationStatus.UNMATCHED: 'unmatched_response_count',
        DNSCorrelationStatus.AMBIGUOUS: 'ambiguous_count',
        DNSCorrelationStatus.UNRESOLVED: 'unresolved_count',
    }[observation.status]
    current = DNSTransactionStatistics() if current is None else current
    values = {bucket: getattr(current, bucket) + 1}
    messages = (observation.message,)
    if observation.status is DNSCorrelationStatus.MATCHED:
        messages = (observation.request, observation.message)
        duration = observation.duration
        latency = (duration.days * 86400 + duration.seconds) * 1000000 + duration.microseconds
        values['total_matched_latency_microseconds'] = current.total_matched_latency_microseconds + latency
        values['min_matched_latency_microseconds'] = latency if current.matched_count == 0 else min(
            current.min_matched_latency_microseconds, latency,
        )
        values['max_matched_latency_microseconds'] = latency if current.matched_count == 0 else max(
            current.max_matched_latency_microseconds, latency,
        )
    opcodes = list(current.opcode_counts)
    response_codes = list(current.response_code_counts)
    for message in messages:
        header = message.header
        for name in ('question_count', 'answer_count', 'authority_count', 'additional_count'):
            values[name] = values.get(name, getattr(current, name)) + getattr(header, name)
        opcodes[header.opcode] += 1
        if header.is_response:
            response_codes[header.response_code] += 1
    return replace(current, **values, opcode_counts=tuple(opcodes), response_code_counts=tuple(response_codes))
