# Threat-intelligence enrichment boundary

This directory owns future intelligence-provider adapters, indicator normalization, and attributed lookup context. It contains documentation only.

Enrichment accepts lookup subjects derived from observations or findings and returns context with source, retrieval time, validity or freshness, and confidence where available. It must distinguish a match, no match, stale data, and lookup failure. Cache bounds and provider failure policies must be explicit when implemented.

Enrichment supplies context to [event processing](../events/README.md); it does not parse packets, independently issue alerts, or own risk policy. Provider credentials and network access remain within this boundary, with data-sharing policy specified before external lookups are enabled. No feeds, credentials, clients, or external connections are configured.
