import json
from typing import Iterable, Iterator

from analysis.ldap import LDAPMessageObservation
from analysis.ldap_request_summary import LDAPRequestSummary


def _message_json(message: LDAPMessageObservation) -> dict:
    return {
        "offset": message.offset,
        "status": message.status.value,
        "reason": message.reason,
        "message_length": message.message_length,
        "envelope_complete": message.envelope_complete,
        "message_id": message.message_id,
        "operation_tag": message.operation_tag,
        "operation": None if message.operation is None else message.operation.value,
        "operation_length": message.operation_length,
        "controls_present": message.controls_present,
        "controls_length": message.controls_length,
    }


def iter_ldap_summary_jsonl(summaries: Iterable[LDAPRequestSummary]) -> Iterator[bytes]:
    for summary in summaries:
        if type(summary) is not LDAPRequestSummary:
            raise TypeError("summaries must contain exactly LDAPRequestSummary values")
        identity = summary.identity
        record = {
            "identity": {
                "ip_version": identity.ip_version,
                "source_address": identity.source_address.hex(),
                "destination_address": identity.destination_address.hex(),
                "source_port": identity.source_port,
                "destination_port": identity.destination_port,
                "protocol": identity.protocol,
            },
            "direction": summary.direction.value,
            "request": _message_json(summary.request),
            "status": summary.status.value,
            "response_count": summary.response_count,
            "terminal_response": None if summary.terminal_response is None else _message_json(summary.terminal_response),
        }
        yield (json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
