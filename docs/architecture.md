# Architecture

## Scope and implementation posture

This document establishes logical ownership for implementation. The Python [capture boundary](../src/capture/README.md) implements packet observations, source contracts, ingestion, and an iterable source. The [analysis boundary](../src/analysis/README.md) implements Ethernet II and IPv4 transport decoding, checksum validation, packet analysis, IPv4 TCP/UDP flow identity/direction/tracking, coordinated raw statistics through directional inter-arrival and TCP control observation accumulation, protocol-neutral observation windows, and typed numerical feature families. The [application boundary](../src/application/README.md) synchronously composes one packet-source run with packet analysis and observation-window lifecycle. The [detection boundary](../src/detection/README.md) implements deterministic flow-volume and flow-rate threshold evaluation. The subsystem map below includes future responsibilities beyond that implemented scope. Other detection families, application parsing, reassembly, network capture, PCAP ingestion, and downstream runtime subsystems remain unimplemented. No concurrency mechanism, transport, database, or deployment topology is selected.

Begin with a modular application. Keep module contracts independent of capture libraries, database drivers, and presentation frameworks so later implementation choices can evolve within these boundaries. Split modules into processes or services only when measured requirements justify it.

## Subsystem ownership

| # | Future subsystem | Established owner | Planned internal area and responsibility |
| --- | --- | --- | --- |
| 1 | Packet capture | [capture](../src/capture/README.md) | Acquire packet bytes and capture metadata; report acquisition loss and source state. |
| 2 | Ethernet and Layer 2 analysis | [analysis](../src/analysis/README.md) | Layer 2 decoding and link metadata. |
| 3 | IP and Layer 3 analysis | [analysis](../src/analysis/README.md) | Network-layer decoding and bounded IP fragment handling. |
| 4 | TCP/UDP and Layer 4 analysis | [analysis](../src/analysis/README.md) | Transport decoding and protocol-specific validation. |
| 5 | Session and flow tracking | [analysis](../src/analysis/README.md) | Flow identity, direction, lifecycle, and bounded transport reassembly state. |
| 6 | Application protocol analysis | [analysis](../src/analysis/README.md) | Application observations from available datagrams or reconstructed streams. |
| 7 | Feature extraction | [analysis](../src/analysis/README.md) | Defined packet, flow, and window measurements with units and provenance. |
| 8 | Signature-based detection | [detection](../src/detection/README.md) | Pattern matching over approved analysis inputs. |
| 9 | Rule-based detection | [detection](../src/detection/README.md) | Explicit predicates over structured observations and features. |
| 10 | Threshold detection | [detection](../src/detection/README.md) | Deterministic configured limits over finalized flow-window volume and rate measurements; other threshold objectives remain future work. |
| 11 | Statistical anomaly detection | [detection](../src/detection/README.md) | Baselines and statistical deviation with explicit assumptions. |
| 12 | Behavioral detection | [detection](../src/detection/README.md) | Stateful entity or sequence evaluation within bounded windows. |
| 13 | Threat-intelligence enrichment | [enrichment](../src/enrichment/README.md) | Indicator context, source attribution, confidence, and freshness. |
| 14 | Event correlation | [events](../src/events/README.md) | Associate observations and findings by entity, flow, and time. |
| 15 | Risk scoring | [events](../src/events/README.md) | Explainable assessment of findings, correlations, and available context. |
| 16 | Alert management | [events](../src/events/README.md) | Alert identity, deduplication, suppression, and lifecycle. |
| 17 | Event storage | [storage](../src/storage/README.md) | Persist and query observations, findings, correlations, and alerts. |
| 18 | PCAP management | [storage](../src/storage/README.md) | Evidence files, indexing, rotation, retention, and retrieval. |
| 19 | Dashboard integration | [integrations](../src/integrations/README.md) | Presentation-facing adapters over supported queries and alert operations. |
| 20 | Automated testing | [tests](../tests/README.md) | Unit, contract, integration, regression, and performance verification. |
| 21 | VM-based security testing | [labs](../labs/README.md) | Controlled end-to-end experiments in isolated, authorized networks. |

## Planned data flow

```text
Application orchestration: packet source -> capture -> analysis
Analysis -> detection -> events -> integration consumers

Analysis observations / detector findings -> enrichment -> events
Capture evidence ---------------------> storage: PCAP management
Analysis / detection / event records -> storage: event persistence
Integration queries ------------------> storage: supported query interface
```

The enrichment branch is optional: observations or findings supply lookup subjects, and attributed context becomes available to event processing. Missing or stale intelligence must remain distinguishable from a clean result. The diagram represents information flow, not synchronous calls or an implemented scheduling model.

Packet observations, protocol observations, flow summaries, feature records, findings, enrichment records, correlations, risk assessments, and alerts are distinct conceptual outputs. An individual detector finding is not automatically an alert. Correlation links evidence; scoring assesses risk; alert management owns notification eligibility and lifecycle.

PCAP evidence and structured event records have different storage and retention needs. Event records should refer to evidence by stable identifiers instead of embedding packet bytes. Packet acquisition owns access to a source; PCAP management owns evidence files. A future offline replay adapter must feed the same capture-to-analysis contract used for live observations.

## Dependency and state boundaries

- Capture does not decode protocols or decide whether traffic is malicious.
- Analysis owns protocol and flow state; feature extraction consumes its outputs without duplicating parsing or session ownership.
- Detectors consume defined observations or features and emit findings. They may own detector-specific windows or baselines, but do not mutate analysis state or manage alerts.
- Enrichment owns intelligence access and caching. Protocol parsers and detectors must not embed provider-specific network clients.
- Event processing owns correlation state, scoring policy, and alert transitions. Its policies must remain independent of dashboard rendering and storage engines.
- Storage implements persistence and query boundaries. Integrations use supported operations instead of reaching into detector state or database internals.
- Application composition owns only the implemented synchronous binding among one source run, packet analysis, and one observation-window manager. Broader configuration, executable startup, and downstream subsystem lifecycle remain future work.

Define small, versioned contracts as the first consumers are implemented. Place shared contracts only when there are real consumers; avoid a general-purpose shared module with unclear ownership. Implementation dependencies should remain acyclic, using narrow interfaces at storage and integration boundaries.

## Coordinated flow-state ownership

The analysis [flow-state coordinator](../src/analysis/flow_state_coordinator.py) owns synchronous admission for a single flow. It constructs candidates through the five immutable protocol-neutral global volume, directional volume, packet-size, global inter-arrival, and directional inter-arrival accumulators and, for TCP, the TCP control accumulator. A packet is admitted only when all applicable candidates succeed; one replacement publishes the complete immutable state. Failures propagate without replacing any published component. Calls must be sequential and non-overlapping; no concurrency or durability guarantee is introduced.

The coordinator retains only the current bundle of authoritative accumulator references. It derives the canonical identity on first admission and preserves that exact object thereafter. The immutable coordinated state rejects disagreement among shared identity, packet-count, directional-count, byte-total, and endpoint-timestamp projections. It introduces no numerical copies, packet history, or provenance identifier. Shared admission history still follows from coordinated construction, not from equal identities, equal statistics, or manually assembling a bundle. Existing extractors consume the published components without changing their mathematical contracts.

The [TCP control statistics](../src/analysis/tcp_control_statistics.py) boundary aggregates exact directional observations of the nine TCP control bits and SYN+ACK co-occurrence in constant memory. It uses existing TCP packet, flow identity, and canonical direction contracts and infers no connection state or security meaning. The coordinator retains its exact updater result for TCP flows and explicit `None` for UDP flows, validates identity and total and directional packet-count agreement, and publishes it atomically with the protocol-neutral state. It is not a direct feature-snapshot field, and numerical TCP feature extraction remains intentionally unimplemented.

`FlowTracker` continues to own its existing independent multi-flow packet-count and first/latest-analysis tracking. Extending it would change its acceptance semantics or require a second state store. A standalone immutable bundle would provide storage but no admission owner; independent accumulators alone would leave publication uncoordinated. A dedicated mutable single-flow owner publishing immutable state establishes the required guarantee while leaving those existing APIs unchanged. Directional inter-arrival state participates because its previous directional timestamps, aggregates, and derived feature family require the same admission history.

The [flow feature snapshot](../src/analysis/flow_feature_snapshot.py) requires an exact `FlowObservationWindow`, retains that exact object, and eagerly applies the established volume, packet-size, duration, rate, global inter-arrival, and directional inter-arrival extractors to its coordinated state. Read-only snapshot properties expose the coordinated state and identity through the retained window, so the model stores neither twice. It accepts no coordinator, independently assembled state, or precomputed feature combination through its public construction API. Rate absence is specifically `None` for validated zero duration. Directional absence remains five `None` values per direction with no intervals, while observed zero-second intervals remain real `0.0` values. All extraction errors propagate.

The retained window preserves capture-session identity, sequence number, and closure reason as lifecycle provenance without converting them into numerical features. Active windows may be extracted as provisional analytical views; closed windows remain the authoritative finalized downstream artifacts. Closure reason does not alter extraction formulas. The snapshot does not own admission or lifecycle transitions, flatten values, serialize records, or define an ML or detection contract.

## Deterministic flow-threshold detection

The [flow-volume threshold detector](../src/detection/flow_volume_threshold.py) consumes one exact `FlowFeatureSnapshot` whose retained observation window is closed. It selects exactly one configured global or canonical-direction packet-count, byte-total, or global rate measurement and compares that value with an exact metric-appropriate threshold using strict greater-than. Equality does not match. TCP and UDP share this detector contract; ICMP remains outside flow identity.

The detector returns an immutable evaluation containing a typed `MATCH`, `NO_MATCH`, or `NOT_EVALUABLE` decision, exact raw evidence, and a separate bounded security interpretation. Zero-duration windows make rate metrics unavailable and therefore not evaluable; count and byte metrics remain valid. The evidence retains the exact snapshot, window, identity, capture-session and sequence provenance, closure reason, timestamps, comparison, configuration, protocol, and volume context without numerical provenance encoding or duplicate analytical state.

A match establishes only that one configured measurement in one finalized observation window exceeded its configured threshold. It does not establish DoS, DDoS, flooding, scanning, brute force, exfiltration, maliciousness, service impact, or endpoint roles. The detector owns no lifecycle, packet history, cross-flow or host aggregation, timer, cache, normalization, vectorization, network access, filesystem access, severity, confidence, score, correlation, alert state, or response action. Application orchestration integration remains future work.

The protocol-neutral [flow observation-window boundary](../src/analysis/flow_observation_window.py) distinguishes canonical flow identity from one bounded accumulation period. One manager owns the active windows for one explicitly identified capture session and delegates each accepted TCP or UDP packet to exactly one `FlowStateCoordinator`. A packet continues its identity's active window when its capture-time gap is less than the configured positive inactivity interval; a gap at or above the interval closes that window and starts a new sequence-numbered window. The manager rejects timestamps below its latest accepted canonical UTC capture time, uses no processing clock, and does not scan unrelated identities for expiration.

Explicit segmentation and capture-session end close immutable windows without reopening or retaining them in the manager. Session end closes active windows in ascending sequence-number order and permanently ends admission. TCP flags have no lifecycle meaning, UDP has no transaction inference, and ICMP remains outside the current TCP/UDP flow-identity contract. Application orchestration composes this lifecycle with capture ingestion and emits windows; feature extraction remains an independent deterministic projection from those windows, and feature inputs remain separate.

## Capture-session application composition

The [application flow-observation session](../src/application/flow_observation_session.py) binds one caller-identified capture session to one `FlowObservationWindowManager`. It delegates source lifecycle and ordered `PacketObservation` delivery to unchanged `consume()`, applies `analyze_packet()` once per observation, and passes each exact result to the manager. Inactivity closures are delivered synchronously before the next source observation. After `consume()` has attempted source cleanup, application orchestration ends the manager session and delivers remaining closures in the manager's order.

Closed-window delivery provides synchronous backpressure and at-most-once attempts. The application layer retains no packet or closed-window history, queue, retry state, or feature output. Existing component exceptions propagate without translation. After downstream delivery fails, the source is stopped and lifecycle state is finalized without invoking the failed consumer again. Skipping malformed or unsupported packets is **UNDEFINED POLICY**. TCP and UDP use the same path, TCP flags have no lifecycle meaning, and unsupported ICMP flow identity remains an analysis error.

## Cross-cutting requirements for later tasks

- Preserve sensor/source identity, capture time, processing time where needed, and provenance across transformations. Specify identifier and schema evolution rules before persisting records.
- Treat malformed, truncated, unsupported, duplicated, and out-of-order traffic explicitly. Missing visibility, packet loss, encrypted payloads, and partial sessions must not silently become evidence of benign traffic.
- Bound buffers, fragment and stream reassembly, flow tables, detector windows, and enrichment caches. Define timeouts, overload behavior, and loss accounting before sustained capture is enabled.
- Specify event-time and clock assumptions for reproducible windowing and correlation. Record configuration, rule, and baseline versions needed to explain findings and scores.
- Separate capture privileges from analysis and presentation where the chosen platform permits it. Define authentication, authorization, retention, and sensitive-data handling when the corresponding runtime boundaries are implemented.
- Make operational health observable independently of security findings. Define failure handling, shutdown, recovery, and delivery guarantees with the execution model rather than assuming lossless or exactly-once processing.

These are design requirements for subsequent work, not capabilities delivered by this repository scaffold. Machine learning, active response, SIEM adapters, and dashboard implementation are not introduced by this task.
