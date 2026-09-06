# Storage and evidence boundary

This directory owns two future persistence responsibilities. It contains documentation only.

Event storage will persist and query structured observations, findings, enrichment context, correlations, risk assessments, and alerts according to explicit persistence policies. It owns database adapters, schema migrations, indexing, and record retention. Security decisions remain with the modules that produce those records.

PCAP management will own evidence files, metadata, indexing, rotation, retention, integrity metadata, and retrieval. It receives packet evidence from [capture](../capture/README.md). Stable evidence references connect event records to packet data; expired or unavailable evidence must be represented explicitly.

Persistence and query interfaces should allow [integrations](../integrations/README.md) to use supported operations without depending on a database schema. Backend selection, consistency guarantees, capacity limits, access controls, and retention values remain undecided. No database, schema, PCAP files, or persistence code is created now.
