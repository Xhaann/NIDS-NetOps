# Architecture

## Scope and implementation posture

This document establishes logical ownership for implementation. The Python [capture boundary](../src/capture/README.md) implements packet observations, source contracts, ingestion, and an iterable source. The [analysis boundary](../src/analysis/README.md) implements Ethernet II and IPv4 transport decoding, checksum validation, IPv6 base-header decoding, packet analysis, IPv4 TCP/UDP flow identity/direction/tracking, coordinated raw statistics through directional inter-arrival and TCP control observation accumulation, protocol-neutral observation windows, and typed numerical feature families. The [application boundary](../src/application/README.md) synchronously composes capture sessions with packet analysis and observation-window lifecycle and separately orchestrates packet and closed-flow detectors into immutable finding tuples. The [detection boundary](../src/detection/README.md) implements packet-integrity, flow-volume/rate, and raw TCP control-counter evaluation plus their common immutable finding contract. The subsystem map below includes future responsibilities beyond that implemented scope. Other detection families, application parsing, reassembly, network capture, PCAP ingestion, and downstream runtime subsystems remain unimplemented. No concurrency mechanism, transport, database, or deployment topology is selected.

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

## Failure-preserving packet analysis

The [packet-analysis outcome](../src/analysis/packet_analysis_outcome.py) is an optional immutable boundary around the existing single-packet analysis operation. `analyze_packet()` retains its established behavior and continues to return one exact `PacketAnalysis` or propagate an exception. `analyze_packet_outcome()` calls that operation once and retains the exact supplied `PacketObservation`; success retains the exact returned analysis, while a recognized failure retains no partial analysis and instead records one bounded classification and deterministic description.

The outcome recognizes only existing structural decoder failures, unsupported analysis scope, explicitly insufficient available bytes, and explicit checksum mismatches. It does not broadly catch programming errors, add parser or checksum rules, or reinterpret UDP checksum omission as mismatch. Unknown IPv4 protocols retain the existing successful network-layer analysis result. The classification describes the implemented analysis attempt and carries no maliciousness, attack, severity, confidence, or RFC-wide compliance conclusion.

This boundary is stateless, performs no acquisition, lifecycle management, feature extraction, or detection, and retains no packet history. It supplies the failure-preserving analytical input consumed by the packet-integrity detector without changing the current application orchestration.

## IPv6 base-header analysis

The [IPv6 decoder](../src/analysis/ipv6.py) follows the existing Ethernet-frame-to-concrete-packet boundary. `IPv6Packet` is immutable and retains the eight fixed header fields plus opaque declared payload bytes. Addresses remain sixteen-byte packed values, directly compatible with the canonical identity representation. The decoder validates EtherType `0x86DD`, the forty-byte base header, version 6, and availability of the declared payload. It retains raw field values and slices payload only to the declared bound, leaving excess capture bytes in the Ethernet frame. Payload Length zero is preserved literally; Jumbo Payload options and jumbogram completeness are outside this boundary.

`analyze_packet()` dispatches IPv6 from the existing Ethernet EtherType and retains the exact decoder result in the appended optional `PacketAnalysis.ipv6` field. IPv4 positional arguments and processing remain unchanged. IPv6 analysis contains no IPv4 model, transport model, or checksum result. Next Header is observed without extension or transport dispatch. `analyze_packet_outcome()` classifies short headers and insufficient declared payload as `INCOMPLETE`, and wrong versions as `STRUCTURAL_FAILURE`, retaining exact observation provenance and no partial analytical model. Unrecognized exceptions still propagate.

Success means the base header and its declared byte extent were decoded, not that opaque extensions or upper-layer content were validated. Analysis invokes no detector, flow admission, or lifecycle operation. Existing IPv4-only flow and threshold boundaries remain intact. No IPv6 extension parsing or validation, fragmentation, ICMPv6, Neighbor Discovery, transport, or detector implementation is included.

## IPv6 extension-header representation

The [extension-header value models](../src/analysis/ipv6_extension_headers.py) hold supplied observations without parsing or certifying protocol structure. `IPv6ExtensionHeader` retains a raw header-type identifier, a packet-relative byte offset, an optional declared byte length, exact raw bytes, and an optional Next Header value. Optional metadata uses `None` when unavailable. Identifiers are exact eight-bit integers, offsets and supplied lengths are exact nonnegative integers, and raw data is exact immutable bytes. No header contents, encoded length fields, or type-specific rules are interpreted.

`IPv6ExtensionHeaderChain` retains the exact `IPv6Packet` as context and an exact immutable tuple of entries in caller-supplied order. This separate object preserves the distinction between base-header Next Header and entry identifiers without adding fields to the packet model or creating an empty chain during decoding. An empty tuple records no represented entries and makes no assertion about extension absence or chain completeness. Lists and invalid element types are rejected; entries and bytes are never reconstructed, reordered, or deduplicated.

Construction checks value types and scalar domains only. It does not verify packet bounds, ordering, Next Header agreement, lengths against bytes, or raw data against packet payload. Metadata inconsistencies remain representable for later validation. Extension parsing, traversal, validation, fragmentation, and content interpretation remain future work; existing packet decoding, outcomes, transport, flow, and detection paths are unchanged.

## Deterministic packet-integrity detection

The [packet-integrity detector](../src/detection/packet_integrity.py) consumes one exact immutable `PacketAnalysisOutcome`. Successful analysis produces `NO_MATCH`; structural and explicit integrity failures produce `MATCH`; and incomplete or unsupported analysis produces `NOT_EVALUABLE`. The fixed predicate is not configurable, and detector configuration contains only exact nonblank identity and version strings.

Raw evidence retains the exact outcome and configuration and projects packet provenance without reconstructing observations or analyses. Protocol is exposed only from a successful retained IPv4 analysis; the detector does not parse raw bytes to recover it from a failed outcome. Existing failure descriptions pass through unchanged. A separate typed interpretation describes only the implemented analytical predicate and makes no maliciousness, attack, intent, endpoint-role, protocol-stack, or RFC-wide conclusion.

The detector is packet-local, synchronous, deterministic, stateless, and constant-memory. It performs no packet decoding, checksum validation, flow processing, history retention, network or filesystem access, orchestration, correlation, alerting, or response behavior.

## Canonical IPv4 and IPv6 flow identity

The [flow identity](../src/analysis/flow_identity.py) retains the established frozen five-field value and canonical ordering of complete `(address, port)` endpoints. Packed addresses have matching lengths of four bytes for IPv4 or sixteen bytes for IPv6; mixed families are invalid. The derived `ip_version` property exposes network family independently of transport protocol, which remains restricted to TCP (6) and UDP (17). Existing IPv4 byte references, endpoint ordering, equality, hashing, and direction comparisons are preserved.

The exported `flow_identity_from_addresses()` converts validated text using standard-library `ipaddress` and delegates to the same packed identity constructor. Equivalent IPv6 compression and case variants normalize to equal values. IPv4-mapped IPv6 remains a distinct IPv6 identity. Scoped IPv6 text is rejected because the existing identity owns no zone or interface context; it is never silently stripped. No timestamps, metadata, security fields, or redundant family field are added.

The existing immutable analytical value models can hold manually constructed IPv6 identities and numerical statistics without redesigning windows or feature snapshots. Packet-derived identity, direction, and accumulation retain their IPv4 input boundary; the separate IPv6 packet-analysis path stops at the base header. Volume and TCP-control detectors now explicitly check IPv4 family, preserving the applicability previously guaranteed by four-byte-only identities. IPv6 flow admission, extension processing, fragmentation, ICMPv6, and detection remain unimplemented.

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

A match establishes only that one configured measurement in one finalized observation window exceeded its configured threshold. It does not establish DoS, DDoS, flooding, scanning, brute force, exfiltration, maliciousness, service impact, or endpoint roles. The detector owns no lifecycle, packet history, cross-flow or host aggregation, timer, cache, normalization, vectorization, network access, filesystem access, severity, confidence, score, correlation, alert state, or response action. The application detector orchestration invokes this evaluator before any applicable TCP-control evaluation; capture-session wiring remains separate.

## Deterministic TCP control-threshold detection

The [TCP control-threshold detector](../src/detection/tcp_control_threshold.py) consumes one exact closed IPv4 TCP `FlowObservationWindow` and selects one of the twenty existing canonical-direction TCP control counters: forward or reverse NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN, or SYN+ACK. It reads the exact coordinated `TCPControlStatistics`; no flag is recounted from packets and no redundant statistics input is accepted. UDP and unsupported protocols are rejected.

The configured threshold is an exact nonnegative integer, and the sole comparison is strict greater-than. Valid control counters are always available integers, so supported evaluation produces `MATCH` or `NO_MATCH`; the decision vocabulary reserves `NOT_EVALUABLE` without inventing a missing-counter state. Raw evidence retains the exact window, control statistics, configuration, selected value, comparison, flow and session provenance, timestamps, protocol, and total and directional packet counts. Security interpretation separately states only whether the configured raw counter threshold was exceeded.

SYN+ACK is the existing independent same-packet joint count and is not derived from SYN and ACK marginals. The detector observes aggregate counts within one finalized window and cannot distinguish packet order or flag transitions. It infers no TCP state machine, lifecycle, handshake result, connection outcome, retransmission, endpoint role, flood, scan, attack, or maliciousness. Flags do not affect observation-window creation or closure, and lifecycle segmentation naturally resets control accounting through a new coordinator. The detector adds no history, cross-flow state, rate, ratio, normalized feature, vector, model, or persistence. Application detector orchestration invokes it only for TCP after volume evaluation and finding conversion.

## Immutable detector finding boundary

The [detection finding](../src/detection/detection_finding.py) normalizes one completed current detector evaluation into a frozen five-field value: detector identity, detector version, the exact detector-specific decision, the exact detector-specific raw evidence, and the exact detector-specific security interpretation. The conversion accepts only the three implemented evaluation types and never executes their detectors again.

The finding validates evidence metadata and detector-family agreement without recomputing packet-integrity or threshold predicates. It preserves separate detector decision and interpretation enum types and retains evidence by object identity, leaving packet, flow, metric, threshold, and lifecycle provenance in the detector-specific evidence model. It introduces no common detector input, generic decision enum, universal feature vector, serialization, or duplicated provenance.

The resulting dataflow is detector-specific evaluation to `DetectionFinding` to future event or correlation policy. The latter boundary remains unimplemented. A finding is not an alert, correlation result, risk score, security incident, or attack classification and carries no finding identifier, severity, confidence, alert state, response, persistence, networking, filesystem access, or orchestration behavior.

The protocol-neutral [flow observation-window boundary](../src/analysis/flow_observation_window.py) distinguishes canonical flow identity from one bounded accumulation period. One manager owns the active windows for one explicitly identified capture session and delegates each accepted TCP or UDP packet to exactly one `FlowStateCoordinator`. A packet continues its identity's active window when its capture-time gap is less than the configured positive inactivity interval; a gap at or above the interval closes that window and starts a new sequence-numbered window. The manager rejects timestamps below its latest accepted canonical UTC capture time, uses no processing clock, and does not scan unrelated identities for expiration.

Explicit segmentation and capture-session end close immutable windows without reopening or retaining them in the manager. Session end closes active windows in ascending sequence-number order and permanently ends admission. TCP flags have no lifecycle meaning, UDP has no transaction inference, and ICMP remains outside the current TCP/UDP flow-identity contract. Application orchestration composes this lifecycle with capture ingestion and emits windows; feature extraction remains an independent deterministic projection from those windows, and feature inputs remain separate.

## Capture-session application composition

The [application flow-observation session](../src/application/flow_observation_session.py) binds one caller-identified capture session to one `FlowObservationWindowManager`. It delegates source lifecycle and ordered `PacketObservation` delivery to unchanged `consume()`, applies `analyze_packet()` once per observation, and passes each exact result to the manager. Inactivity closures are delivered synchronously before the next source observation. After `consume()` has attempted source cleanup, application orchestration ends the manager session and delivers remaining closures in the manager's order.

Closed-window delivery provides synchronous backpressure and at-most-once attempts. The application layer retains no packet or closed-window history, queue, retry state, or feature output. Existing component exceptions propagate without translation. After downstream delivery fails, the source is stopped and lifecycle state is finalized without invoking the failed consumer again. Skipping malformed or unsupported packets is **UNDEFINED POLICY**. TCP and UDP use the same path, TCP flags have no lifecycle meaning, and unsupported ICMP flow identity remains an analysis error.

## Deterministic detector orchestration

The [application detector orchestration](../src/application/detector_orchestration.py) exports `run_packet_detectors()` and `run_closed_flow_detectors()`. The packet function evaluates the exact `PacketAnalysisOutcome` with its exact configuration and converts the resulting evaluation once. The closed-flow function evaluates the exact `FlowFeatureSnapshot` for volume first, converts that evaluation, and, for TCP only, evaluates its exact retained `FlowObservationWindow` for raw control counts and converts that evaluation second. UDP requires no TCP configuration and returns only the volume finding.

Each invocation returns a complete immutable `tuple[DetectionFinding, ...]` in that order, retaining all decisions and the exact converted findings, evidence, and configuration objects. Applicable detectors run once. Detector and conversion exceptions propagate unchanged, stop further work, and publish no partial tuple. Active snapshots are rejected by the existing volume detector without lifecycle mutation. Unsupported flow protocols are rejected at valid `FlowIdentity` construction; no protocol-model bypass is introduced.

This boundary composes the existing three detector contracts without a shared input model, registry, generic framework, history, background state, cross-flow correlation, or security conclusion. It performs no analysis, feature extraction, window closure, filtering, scoring, alerting, persistence, or response. Capture-session composition continues to emit closed windows independently.

## Cross-cutting requirements for later tasks

- Preserve sensor/source identity, capture time, processing time where needed, and provenance across transformations. Specify identifier and schema evolution rules before persisting records.
- Treat malformed, truncated, unsupported, duplicated, and out-of-order traffic explicitly. Missing visibility, packet loss, encrypted payloads, and partial sessions must not silently become evidence of benign traffic.
- Bound buffers, fragment and stream reassembly, flow tables, detector windows, and enrichment caches. Define timeouts, overload behavior, and loss accounting before sustained capture is enabled.
- Specify event-time and clock assumptions for reproducible windowing and correlation. Record configuration, rule, and baseline versions needed to explain findings and scores.
- Separate capture privileges from analysis and presentation where the chosen platform permits it. Define authentication, authorization, retention, and sensitive-data handling when the corresponding runtime boundaries are implemented.
- Make operational health observable independently of security findings. Define failure handling, shutdown, recovery, and delivery guarantees with the execution model rather than assuming lossless or exactly-once processing.

These are design requirements for subsequent work, not capabilities delivered by this repository scaffold. Machine learning, active response, SIEM adapters, and dashboard implementation are not introduced by this task.
