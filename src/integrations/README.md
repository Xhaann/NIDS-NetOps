# Integration boundary

This directory owns adapters between NIDS-NetOps and external consumers.

Dashboard integration will expose supported event queries, evidence references, and alert operations through contracts defined with the eventual presentation layer. Reads use [storage](../storage/README.md) query interfaces; alert changes pass through [event processing](../events/README.md) so lifecycle rules stay authoritative.

Presentation frameworks and external data formats must not become dependencies of parsing or detection logic. Authentication, authorization, pagination, export limits, and external delivery semantics must be defined when an adapter is implemented. SIEM or notification adapters can fit here when separately scoped; this task adds no API server, dashboard, frontend, webhook, or SIEM functionality.

## Offline LDAP summary export

`integrations.iter_ldap_summary_jsonl(summaries)` lazily consumes an iterable of established `LDAPRequestSummary` objects and yields one immutable UTF-8 JSON Lines byte record per summary. It preserves supplied observation order, including repeated observations and non-FIFO completions. It does not merge independent streams or select summaries from flow state. Callers supply summaries from correlation updates or finalized observations while those bounded observations are available; a final window does not contain every earlier completed request.

Records contain `identity`, `direction`, `request`, `status`, `response_count`, and `terminal_response`, in that order. Identity uses the CLI's packed-address hexadecimal representation and canonical endpoint order, with IP version, ports, and protocol. Directions and statuses use their existing enum values. Request and optional terminal references preserve all existing message-observation metadata in contract field order, including stream offset, message ID, operation enum value (the numeric tag), lengths, and controls-envelope facts. Absent values use JSON `null`. Encoding uses compact separators, ASCII escaping, and a single trailing LF, independent of locale.

Export preserves active `pending` and finalized `completed`, `ambiguous`, or `unresolved` status, exact logical response counts, and optional terminal references. It neither finalizes flows nor performs parsing, correlation, or summary generation. Unmatched responses and non-correlatable observations are not summary inputs. The field whitelist contains summary metadata, never LDAP payloads, credentials, filters, or attribute values. Export is observational, performs no network communication, and creates no detections.

The iterator retains only the current summary and one record's serialization work, with no lookahead, collection of input, or historical event storage. Memory depends on one record, not capture length; caller-owned input or output buffering remains the caller's responsibility. Invalid members raise `TypeError` when reached. Iterable and serialization exceptions propagate and terminate iteration; earlier yielded records remain valid partial output, not evidence of complete export. The adapter opens no files and owns no output target, so writing, encoding-independent binary destinations, output failures, and any file atomicity belong to the caller.

```python
from integrations import iter_ldap_summary_jsonl

for record in iter_ldap_summary_jsonl(summary_observations):
    destination.write(record)
```

Here `summary_observations` is a caller-supplied ordered iterable and `destination` is a caller-owned binary stream. A write failure propagates through this loop; the exporter makes no delivery, retry, or transaction guarantee.
