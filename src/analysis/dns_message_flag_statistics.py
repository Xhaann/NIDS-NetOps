from dataclasses import dataclass, fields
from typing import Optional

from analysis.dns import DNSHeader, DNSMessageObservation, DNSMessageStatus
from analysis.dns_correlation import DNSCorrelationStatus, DNSTransactionObservation


@dataclass(frozen=True)
class DNSMessageFlagStatistics:
    message_count: int = 0
    response_count: int = 0
    truncated_count: int = 0
    authoritative_answer_count: int = 0
    recursion_desired_count: int = 0
    recursion_available_count: int = 0
    authenticated_data_count: int = 0
    checking_disabled_count: int = 0

    def __post_init__(self) -> None:
        for member in fields(self):
            value = getattr(self, member.name)
            if type(value) is not int:
                raise TypeError(f'{member.name} must be exactly an integer')
            if value < 0:
                raise ValueError(f'{member.name} must not be negative')
        for member in fields(self):
            if getattr(self, member.name) > self.message_count:
                raise ValueError('set-flag counts must not exceed message_count')

    @property
    def query_count(self) -> int:
        return self.message_count - self.response_count


def update_dns_message_flag_statistics(
    current: Optional[DNSMessageFlagStatistics], observation: DNSTransactionObservation,
) -> DNSMessageFlagStatistics:
    if current is not None and type(current) is not DNSMessageFlagStatistics:
        raise TypeError('current must be exactly a DNSMessageFlagStatistics or None')
    if type(observation) is not DNSTransactionObservation:
        raise TypeError('observation must be exactly a DNSTransactionObservation')
    if observation.status not in (DNSCorrelationStatus.MATCHED, DNSCorrelationStatus.UNMATCHED,
                                  DNSCorrelationStatus.AMBIGUOUS, DNSCorrelationStatus.UNRESOLVED):
        raise ValueError('message flag statistics require a terminal transaction observation')
    current = DNSMessageFlagStatistics() if current is None else current
    values = {member.name: getattr(current, member.name) for member in fields(current)}
    messages = (observation.request, observation.message) if observation.status is DNSCorrelationStatus.MATCHED else (observation.message,)
    for message in messages:
        if type(message) is not DNSMessageObservation:
            raise TypeError('contributing messages must be exactly DNSMessageObservation values')
        if message.status is not DNSMessageStatus.COMPLETE:
            raise ValueError('contributing DNS messages must be complete')
        if type(message.header) is not DNSHeader:
            raise TypeError('contributing messages require an established DNSHeader')
        values['message_count'] += 1
        for name, attribute in (
            ('response_count', 'is_response'), ('truncated_count', 'truncated'),
            ('authoritative_answer_count', 'authoritative_answer'), ('recursion_desired_count', 'recursion_desired'),
            ('recursion_available_count', 'recursion_available'), ('authenticated_data_count', 'authenticated_data'),
            ('checking_disabled_count', 'checking_disabled'),
        ):
            enabled = getattr(message.header, attribute)
            if type(enabled) is not bool:
                raise TypeError('parsed header flag properties must be exactly booleans')
            values[name] += int(enabled)
    return DNSMessageFlagStatistics(**values)
