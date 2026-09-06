# Integration boundary

This directory owns future adapters between NIDS-NetOps and external consumers. It contains documentation only.

Dashboard integration will expose supported event queries, evidence references, and alert operations through contracts defined with the eventual presentation layer. Reads use [storage](../storage/README.md) query interfaces; alert changes pass through [event processing](../events/README.md) so lifecycle rules stay authoritative.

Presentation frameworks and external data formats must not become dependencies of parsing or detection logic. Authentication, authorization, pagination, export limits, and external delivery semantics must be defined when an adapter is implemented. SIEM or notification adapters can fit here when separately scoped; this task adds no API server, dashboard, frontend, webhook, or SIEM functionality.
