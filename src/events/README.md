# Event processing boundary

This directory owns future processing from security findings to managed alerts. It contains documentation only. Three responsibilities must remain distinct:

- Correlation associates observations and findings by flow, entity, and time while preserving evidence links.
- Risk scoring assesses findings, correlations, and available enrichment using an explainable, versioned policy.
- Alert management owns alert identity, deduplication, suppression, and lifecycle transitions.

Inputs come from [analysis](../analysis/README.md), [detection](../detection/README.md), and [enrichment](../enrichment/README.md). Outputs include correlation records, risk assessments, alerts, and lifecycle changes for [storage](../storage/README.md) and supported [integrations](../integrations/README.md).

Event processing does not recapture traffic, reimplement protocol parsing, render dashboards, or implement persistence drivers. Time windows, late-arriving evidence, score semantics, and alert transition rules require explicit decisions in later tasks. Automated blocking or other active response is outside this boundary.
