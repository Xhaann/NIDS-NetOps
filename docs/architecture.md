# Architecture

## Scope and implementation posture

This document establishes logical ownership for implementation. The Python [capture boundary](../src/capture/README.md) implements packet observations, source contracts, ingestion, an iterable source, and a classic PCAP file source. The [analysis boundary](../src/analysis/README.md) implements Ethernet II and IPv4 transport decoding, checksum validation, IPv6 base-header decoding, packet analysis, IPv4/IPv6 TCP/UDP flow identity/direction/tracking, coordinated raw statistics through directional inter-arrival and TCP control observation accumulation, protocol-neutral observation windows, and typed numerical feature families. The [application boundary](../src/application/README.md) synchronously composes capture sessions with packet analysis and observation-window lifecycle and separately orchestrates packet and closed-flow detectors into immutable finding tuples. The [detection boundary](../src/detection/README.md) implements packet-integrity, flow-volume/rate, and raw TCP control-counter evaluation plus their common immutable finding contract. The subsystem map below includes future responsibilities beyond that implemented scope. Other detection families, application parsing, reassembly, live network capture, and downstream runtime subsystems remain unimplemented. No concurrency mechanism, transport, database, or deployment topology is selected.

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

PCAP evidence and structured event records have different storage and retention needs. Event records should refer to evidence by stable identifiers instead of embedding packet bytes. Packet acquisition owns access to a source; PCAP management owns evidence files. The classic PCAP input adapter feeds the existing capture-to-analysis contract; live acquisition remains unimplemented.

## Dependency and state boundaries

- Capture does not decode protocols or decide whether traffic is malicious.
- Analysis owns protocol and flow state; feature extraction consumes its outputs without duplicating parsing or session ownership.
- Detectors consume defined observations or features and emit findings. They may own detector-specific windows or baselines, but do not mutate analysis state or manage alerts.
- Enrichment owns intelligence access and caching. Protocol parsers and detectors must not embed provider-specific network clients.
- Event processing owns correlation state, scoring policy, and alert transitions. Its policies must remain independent of dashboard rendering and storage engines.
- Storage implements persistence and query boundaries. Integrations use supported operations instead of reaching into detector state or database internals.
- Application composition owns only the implemented synchronous binding among one source run, packet analysis, and one observation-window manager. The CLI adapts explicit arguments to this pipeline; configuration loading and downstream subsystem lifecycle remain future work.

Define small, versioned contracts as the first consumers are implemented. Place shared contracts only when there are real consumers; avoid a general-purpose shared module with unclear ownership. Implementation dependencies should remain acyclic, using narrow interfaces at storage and integration boundaries.

## Failure-preserving packet analysis

The [packet-analysis outcome](../src/analysis/packet_analysis_outcome.py) is an optional immutable boundary around the existing single-packet analysis operation. `analyze_packet()` retains its established behavior and continues to return one exact `PacketAnalysis` or propagate an exception. `analyze_packet_outcome()` calls that operation once and retains the exact supplied `PacketObservation`; success retains the exact returned analysis, while a recognized failure retains no partial analysis and instead records one bounded classification and deterministic description.

The outcome recognizes only existing structural decoder failures, unsupported analysis scope, explicitly insufficient available bytes, and explicit checksum mismatches. It does not broadly catch programming errors, add parser or checksum rules, or reinterpret UDP checksum omission as mismatch. Unknown IPv4 protocols retain the existing successful network-layer analysis result. The classification describes the implemented analysis attempt and carries no maliciousness, attack, severity, confidence, or RFC-wide compliance conclusion.

This boundary is stateless, performs no acquisition, lifecycle management, feature extraction, or detection, and retains no packet history. It supplies the failure-preserving analytical input consumed by the packet-integrity detector without changing the current application orchestration.

## IPv6 base-header analysis

The [IPv6 decoder](../src/analysis/ipv6.py) follows the existing Ethernet-frame-to-concrete-packet boundary. `IPv6Packet` is immutable and retains the eight fixed header fields plus opaque declared payload bytes. Addresses remain sixteen-byte packed values, directly compatible with the canonical identity representation. The decoder validates EtherType `0x86DD`, the forty-byte base header, version 6, and availability of the declared payload. It retains raw field values and slices payload only to the declared bound, leaving excess capture bytes in the Ethernet frame. Payload Length zero is preserved literally; Jumbo Payload options and jumbogram completeness are outside this boundary.

`analyze_packet()` dispatches IPv6 from the existing Ethernet EtherType and retains the exact decoder result in the appended optional `PacketAnalysis.ipv6` field. IPv4 positional arguments and processing remain unchanged. IPv6 analysis contains no IPv4 model or IPv4 transport/checksum result. The base Next Header is retained unchanged and starts the supported structural extension traversal. Separate appended IPv6 transport fields are populated at the validated terminal boundary as described below. `analyze_packet_outcome()` classifies short base or extension headers and insufficient declared payload as `INCOMPLETE`, and wrong versions as `STRUCTURAL_FAILURE`, retaining exact observation provenance and no partial analytical model. Unrecognized exceptions still propagate.

Successful packet analysis includes base-header decoding and structural traversal of the supported extension headers. TCP, UDP, and the common ICMPv6 header are decoded at their safe terminal boundaries; unsupported upper-layer content remains opaque. Analysis invokes no detector, flow admission, or lifecycle operation. Flow admission separately consumes decoded IPv4/IPv6 TCP/UDP semantics; the existing threshold detectors support both families at their separate closed-flow boundary. Fragment Header semantics are analyzed in the packet-local boundary below. Reassembly, ICMPv6 subtype decoding, Neighbor Discovery, IPv6 transport checksum validation, and IPv6 detection remain outside this feature.

## IPv6 extension-header representation

The [extension-header value models](../src/analysis/ipv6_extension_headers.py) hold supplied observations without parsing or certifying protocol structure. `IPv6ExtensionHeader` retains a raw header-type identifier, a packet-relative byte offset, an optional declared byte length, exact raw bytes, and an optional Next Header value. Optional metadata uses `None` when unavailable. Identifiers are exact eight-bit integers, offsets and supplied lengths are exact nonnegative integers, and raw data is exact immutable bytes. No header contents, encoded length fields, or type-specific rules are interpreted.

`IPv6ExtensionHeaderChain` retains the exact `IPv6Packet` as context and an exact immutable tuple of entries in caller-supplied order. This separate object preserves the distinction between base-header Next Header and entry identifiers without adding fields to the packet model or creating a chain during base-header decoding. A directly supplied empty tuple records no represented entries and makes no assertion about extension absence or chain completeness. Lists and invalid element types are rejected; entries and bytes are never reconstructed, reordered, or deduplicated.

Construction checks value types and scalar domains only. It does not verify packet bounds, ordering, Next Header agreement, lengths against bytes, or raw data against packet payload. Metadata inconsistencies remain representable; direct construction does not certify a chain.

`validate_ipv6_extension_headers()` constructs validated representations directly from the already-bounded `IPv6Packet.payload`, starting at the base Next Header and advancing only by validated lengths. Hop-by-Hop Options (0), Routing (43), and Destination Options (60) use `(Hdr Ext Len + 1) * 8` bytes after checking the two-byte prefix; Fragment (44) requires exactly eight bytes and leaves its semantic fields opaque. Entries preserve exact raw bytes, Next Header links, and packet-relative offsets beginning at 40. Repeated headers preserve observed order, with no scan-ahead or ordering policy. Each step consumes at least eight payload bytes, bounding traversal by the packet size.

Any Next Header outside those four types terminates traversal without decoding the indicated protocol. The chain exposes the terminating value through `terminating_next_header`, including the base value when no extensions were traversed. No Next Header (59) stops traversal and leaves any trailing payload bytes untouched. AH and ESP are not parsed. Missing prefix or declared bytes raise the existing `IPv6DecodeError` and become `INCOMPLETE` outcomes, with no successful partial chain or analysis. Unexpected errors still propagate.

Packet analysis retains the complete chain in the appended optional `PacketAnalysis.ipv6_extension_headers` field, whose packet context must be the exact retained IPv6 model. The base-header decoder remains independent. Extension validation stays entirely inside IPv6 packet analysis; it adds no fragment semantics or reassembly, transport decoding, ICMPv6, Neighbor Discovery, flow integration, feature extraction, detector, finding, alert, or correlation behavior.

## IPv6 fragmentation analysis

The [fragmentation boundary](../src/analysis/ipv6_fragmentation.py) consumes the existing extension-header chain and returns immutable `IPv6Fragmentation` with exact chain and packet context. It delegates structural certification to the existing extension validator before building its ordered tuple of `IPv6FragmentHeader` views. This check is needed because direct chain construction permits unvalidated metadata; it introduces no alternative traversal or payload-boundary logic. Repeated type-44 entries remain separate views in their observed order.

Each view retains the exact extension entry and derives Next Header, the Reserved byte, thirteen-bit Fragment Offset in eight-octet units, the adjacent two reserved bits, the boolean M flag, and the 32-bit Identification from its exact eight bytes, following [RFC 8200, Section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5). Nonzero reserved values are preserved. Local position predicates depend only on offset and M, and make no packet-completeness or security claim. Offset zero with M false preserves the whole-datagram Fragment Header and does not synthesize a reassembled packet.

The appended optional `PacketAnalysis.ipv6_fragmentation` retains this analysis when Fragment Headers are present and requires the exact retained extension-header chain. Existing positional arguments, IPv4 behavior, IPv6 base decoding, extension traversal, and outcome classifications remain unchanged. Insufficient bytes still yield `INCOMPLETE` with no partial analysis; inconsistent manually supplied models and unexpected internal exceptions propagate.

This boundary is stateless and analyzes one observed packet only. Fragment reassembly, buffering, cross-packet fragment correlation, overlap and duplicate detection, fragmentation attack detection, ICMPv6, transport decoding, IPv6 flow integration, and IPv6 detection remain outside it. Detector behavior, findings, alerts, and correlation architecture are unchanged.

## ICMPv6 foundation

The [ICMPv6 decoder](../src/analysis/icmpv6.py) consumes the validated IPv6 extension-header boundary and retains the exact chain and IPv6 packet in frozen `ICMPv6Packet`. Terminal Next Header 58 selects the common four-byte header defined in [RFC 4443, Section 2.1](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1). Type, Code, observed Checksum, exact raw bytes, and the opaque remaining body are preserved. The packet-relative offset follows the last validated extension extent, or is 40 without extensions. Existing chain validation remains authoritative; there is no scan-ahead or alternative extension traversal.

The appended `PacketAnalysis.ipv6_icmpv6` field preserves positional compatibility and requires the exact retained chain. Dispatch requires no Fragment Header or only whole-datagram Fragment Headers (offset zero and M false). Other fragments retain existing IPv6 analysis with no ICMPv6 model. This packet-local gate uses Commit #20's semantic boundary without changing fragment or traversal behavior. Safe ICMPv6 boundaries shorter than four bytes yield `INCOMPLETE` with no partial analysis; unexpected internal failures propagate.

Type-based error/informational properties are protocol-local. Checksum validation, message subtype and embedded-packet parsing, Neighbor Discovery, reassembly, cross-packet state, flow integration, and security interpretation are outside this foundation. Detectors and finding contracts are unchanged.

## IPv6 transport header analysis

The existing [TCP](../src/analysis/tcp.py) and [UDP](../src/analysis/udp.py) decoders accept the existing immutable `IPv6Fragmentation` context as well as `IPv4Packet`. IPv6 context retains a chain certified by the existing validator and its fragment semantics; no parallel transport model or extension traversal is introduced. Empty-fragment context handles unfragmented packets. Terminal Next Header chooses the decoder, and the last validated extension extent establishes the byte offset, or forty without extensions. Decoders read only the bounded IPv6 payload and never scan ahead or consume Ethernet trailing bytes.

The same frozen `TCPPacket` and `UDPPacket` retain exact semantic fields and opaque bytes for both families. TCP requires its complete indicated header, including options; UDP requires its complete declared datagram. Non-first fragments retain IPv6/fragmentation analysis with no TCP or UDP result. First and whole-datagram fragments decode only when those structural requirements hold. No fragment reassembly, cache, correlation, or synthesized header is introduced. The existing ICMPv6 path and its whole-datagram gate remain unchanged.

`PacketAnalysis.ipv6_tcp` and `ipv6_udp` are appended after all prior fields. Existing IPv4 transport fields, positional construction, checksum semantics, and failure propagation are preserved. Incomplete transport bytes yield `INCOMPLETE`; invalid TCP data offsets and UDP lengths below eight yield `STRUCTURAL_FAILURE`, with no partial packet result. IPv6 checksum fields are observed values, not validation results. Flow integration, feature parity, detection parity, and Flow Label semantics are outside this boundary. See the [transport contract](../src/analysis/README.md#ipv6-transport-header-analysis) for the protocol references and direct decoder requirements.

## Deterministic packet-integrity detection

The [packet-integrity detector](../src/detection/packet_integrity.py) consumes one exact immutable `PacketAnalysisOutcome`. Successful analysis produces `NO_MATCH`; structural and explicit integrity failures produce `MATCH`; and incomplete or unsupported analysis produces `NOT_EVALUABLE`. The fixed predicate is not configurable, and detector configuration contains only exact nonblank identity and version strings.

Raw evidence retains the exact outcome and configuration and projects packet provenance without reconstructing observations or analyses. Protocol is exposed only from a successful retained IPv4 analysis; the detector does not parse raw bytes to recover it from a failed outcome. Existing failure descriptions pass through unchanged. A separate typed interpretation describes only the implemented analytical predicate and makes no maliciousness, attack, intent, endpoint-role, protocol-stack, or RFC-wide conclusion.

The detector is packet-local, synchronous, deterministic, stateless, and constant-memory. It performs no packet decoding, checksum validation, flow processing, history retention, network or filesystem access, orchestration, correlation, alerting, or response behavior.

## Canonical IPv4 and IPv6 flow identity

The [flow identity](../src/analysis/flow_identity.py) retains the established frozen five-field value and canonical ordering of complete `(address, port)` endpoints. Packed addresses have matching lengths of four bytes for IPv4 or sixteen bytes for IPv6; mixed families are invalid. The derived `ip_version` property exposes network family independently of transport protocol, which remains restricted to TCP (6) and UDP (17). Existing IPv4 byte references, endpoint ordering, equality, hashing, and direction comparisons are preserved.

The exported `flow_identity_from_addresses()` converts validated text using standard-library `ipaddress` and delegates to the same packed identity constructor. Equivalent IPv6 compression and case variants normalize to equal values. IPv4-mapped IPv6 remains a distinct IPv6 identity. Scoped IPv6 text is rejected because the existing identity owns no zone or interface context; it is never silently stripped. No timestamps, metadata, security fields, or redundant family field are added.

Valid IPv6 TCP/UDP PacketAnalysis results now enter the existing flow identity and lifecycle. An internal semantic endpoint selector shared by identity and direction reads packed IPv6 addresses, `ipv6_tcp`/`ipv6_udp` ports, and the retained extension chain's terminal protocol. It does not parse bytes, traverse extension headers, normalize text, or create a second identity model. Unsupported protocols, missing transport/context, and non-first fragments retain deterministic admission errors. ICMPv6 supplies no ports and remains outside flow admission.

FlowTracker, FlowStateCoordinator, FlowObservationWindowManager, and the application flow session reuse their existing state and delivery paths. TCP's required raw control accumulator selects the family-appropriate decoded model; its counters are unchanged. Canonical UTC time, direction, timeout, and publication rules are preserved. No fragment reassembly, correlation, or Flow Label key dimension is added. Admission invokes no feature extraction or detection. Feature snapshot schemas and calculations are shared by both families. The existing volume and TCP-control detectors separately accept applicable closed IPv4 and IPv6 flows.

## Coordinated flow-state ownership

The analysis [flow-state coordinator](../src/analysis/flow_state_coordinator.py) owns synchronous admission for a single flow. It constructs candidates through the five immutable protocol-neutral global volume, directional volume, packet-size, global inter-arrival, and directional inter-arrival accumulators and, for TCP, the TCP control accumulator. A packet is admitted only when all applicable candidates succeed; one replacement publishes the complete immutable state. Failures propagate without replacing any published component. Calls must be sequential and non-overlapping; no concurrency or durability guarantee is introduced.

The coordinator retains only the current bundle of authoritative accumulator references. It derives the canonical identity on first admission and preserves that exact object thereafter. The immutable coordinated state rejects disagreement among shared identity, packet-count, directional-count, byte-total, and endpoint-timestamp projections. It introduces no numerical copies, packet history, or provenance identifier. Shared admission history still follows from coordinated construction, not from equal identities, equal statistics, or manually assembling a bundle. Existing extractors consume the published components without changing their mathematical contracts.

The [TCP control statistics](../src/analysis/tcp_control_statistics.py) boundary aggregates exact directional observations of the nine TCP control bits and SYN+ACK co-occurrence in constant memory. It uses existing TCP packet, flow identity, and canonical direction contracts and infers no connection state or security meaning. The coordinator retains its exact updater result for TCP flows and explicit `None` for UDP flows, validates identity and total and directional packet-count agreement, and publishes it atomically with the protocol-neutral state. It is not a direct feature-snapshot field, and numerical TCP feature extraction remains intentionally unimplemented.

`FlowTracker` continues to own its existing independent multi-flow packet-count and first/latest-analysis tracking. Extending it would change its acceptance semantics or require a second state store. A standalone immutable bundle would provide storage but no admission owner; independent accumulators alone would leave publication uncoordinated. A dedicated mutable single-flow owner publishing immutable state establishes the required guarantee while leaving those existing APIs unchanged. Directional inter-arrival state participates because its previous directional timestamps, aggregates, and derived feature family require the same admission history.

The [flow feature snapshot](../src/analysis/flow_feature_snapshot.py) requires an exact `FlowObservationWindow`, retains that exact object, and eagerly applies the established volume, packet-size, duration, rate, global inter-arrival, and directional inter-arrival extractors to its coordinated state. Read-only snapshot properties expose the coordinated state and identity through the retained window, so the model stores neither twice. It accepts no coordinator, independently assembled state, or precomputed feature combination through its public construction API. Rate absence is specifically `None` for validated zero duration. Directional absence remains five `None` values per direction with no intervals, while observed zero-second intervals remain real `0.0` values. All extraction errors propagate.

The retained window preserves capture-session identity, sequence number, and closure reason as lifecycle provenance without converting them into numerical features. Active windows may be extracted as provisional analytical views; closed windows remain the authoritative finalized downstream artifacts. Closure reason does not alter extraction formulas. The snapshot does not own admission or lifecycle transitions, flatten values, serialize records, or define an ML or detection contract.

## Shared IPv4 and IPv6 flow features

Validated IPv4 and IPv6 TCP/UDP observations use the same coordinated state and feature snapshot path. Volume, directional balance, packet-size, duration, rate, and global and directional inter-arrival features preserve their existing formulas and absence rules. Captured and original byte totals use exact observation metadata, including the actual IPv6 header length; no family-dependent length normalization occurs. TCP control statistics consume the decoded family-appropriate TCP model through the existing accumulator and remain available through the snapshot's coordinated state. UDP retains absent TCP control state.

Feature extraction reads aggregate state, never packet bytes, extension chains, or fragmentation headers. First/whole fragments participate only after existing transport admission succeeds; non-first fragments without decoded transport cannot contribute. No reassembly, fragment correlation, extension-header metrics, fragmentation metrics, or Flow Label metrics are introduced. ICMPv6 remains outside TCP/UDP flow features. Application sessions still emit closed windows; consumers explicitly request feature snapshots. Extraction invokes no detectors; callers separately request the applicable existing detector evaluations for either family.

## IPv6 detection applicability

The existing detectors share their configurations, decision enums, evidence models, and five-field `DetectionFinding` contract across IP families. Packet-integrity evaluation already applies its outcome predicates to IPv6: successful analysis yields `NO_MATCH`, supported structural/integrity failures yield `MATCH`, and incomplete/unsupported outcomes yield `NOT_EVALUABLE`. Its protocol evidence now projects the retained IPv6 extension chain's terminal Next Header; missing context remains `None`, without falling back to the base header or scanning bytes.

The flow-volume detector accepts closed IPv6 TCP/UDP feature snapshots, and the TCP-control detector accepts closed IPv6 TCP windows with their existing control statistics. UDP remains inapplicable to TCP-control evaluation and direct calls raise the existing applicability error. Both threshold predicates remain strict greater-than; zero-duration rate absence remains `NOT_EVALUABLE`. Orchestration retains volume-before-control ordering, exact references, fail-fast propagation, and explicit caller invocation. Capture sessions and feature extraction do not automatically execute detectors.

Detectors consume semantic outcomes and finalized flow state without parsing packets, revalidating extension headers, creating flow state, or reassembling fragments. First/whole fragments with admitted transport use normal flow detection; non-first fragments without transport, ICMPv6, and unsupported protocols remain outside TCP/UDP flow detection. Generic packet-outcome evaluation of those protocols does not introduce an ICMPv6-specific detector. No extension-header, Flow Label, or fragmentation metrics, new attack interpretations, correlation, or response semantics are added. This parity does not establish full IPv6 or fragmented-flow attack coverage.

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

## Capture execution between acquisition and analysis

The [capture execution boundary](../src/application/capture_execution.py) exports `run_capture_execution(source, consumer)`. It runs an existing `PacketSource` through `consume()`, calls `analyze_packet_outcome()` exactly once for each observation, and synchronously delivers the exact outcome to its consumer. The application layer composes acquisition and analysis without importing analysis into capture sources or moving protocol interpretation out of analysis.

No outcome is reconstructed or filtered. Failed analytical outcomes remain observable; acquisition, unexpected analysis, and consumer exceptions retain fail-fast behavior and existing cleanup precedence. The callback completes before the next observation is acquired. There is no full-source buffering, sorting, deduplication, timestamp normalization, cache, or shared execution state. Source-dependent timestamp behavior remains unchanged, including deterministic PCAP order and the iterable source's acquisition clock.

The detection pipeline invokes this boundary once and retains its existing packet-detection-before-admission ordering. The standalone flow-observation session shares the private execution primitive while selecting its original `analyze_packet()` operation, preserving its distinct exception contract. `consume()` still exclusively implements source startup and cleanup; flow observation exclusively owns manager admission and finalization. Feature extraction and detector execution remain in their established downstream paths. Direct capture execution is detector-free and introduces no live capture, reassembly, persistence, or alerting.

## Capture-session application composition

The [application flow-observation session](../src/application/flow_observation_session.py) binds one caller-identified capture session to one `FlowObservationWindowManager`. It delegates source lifecycle and ordered `PacketObservation` delivery through the shared capture-execution primitive to unchanged `consume()`, applies `analyze_packet()` once per observation, and passes each exact result to the manager. Inactivity closures are delivered synchronously before the next source observation. After `consume()` has attempted source cleanup, application orchestration ends the manager session and delivers remaining closures in the manager's order.

Closed-window delivery provides synchronous backpressure and at-most-once attempts. The application layer retains no packet or closed-window history, queue, retry state, or feature output. Existing component exceptions propagate without translation. After downstream delivery fails, the source is stopped and lifecycle state is finalized without invoking the failed consumer again. Skipping malformed or unsupported packets is **UNDEFINED POLICY**. TCP and UDP use the same path, TCP flags have no lifecycle meaning, and unsupported ICMP flow identity remains an analysis error.

## Deterministic detector orchestration

The [application detector orchestration](../src/application/detector_orchestration.py) exports `run_packet_detectors()` and `run_closed_flow_detectors()`. The packet function evaluates the exact `PacketAnalysisOutcome` with its exact configuration and converts the resulting evaluation once. The closed-flow function evaluates the exact `FlowFeatureSnapshot` for volume first, converts that evaluation, and, for TCP only, evaluates its exact retained `FlowObservationWindow` for raw control counts and converts that evaluation second. UDP requires no TCP configuration and returns only the volume finding.

Each invocation returns a complete immutable `tuple[DetectionFinding, ...]` in that order, retaining all decisions and the exact converted findings, evidence, and configuration objects. Applicable detectors run once. Detector and conversion exceptions propagate unchanged, stop further work, and publish no partial tuple. Active snapshots are rejected by the existing volume detector without lifecycle mutation. Unsupported flow protocols are rejected at valid `FlowIdentity` construction; no protocol-model bypass is introduced.

This boundary composes the existing three detector contracts without a shared input model, registry, generic framework, history, background state, cross-flow correlation, or security conclusion. It performs no analysis, feature extraction, window closure, filtering, scoring, alerting, persistence, or response. Capture-session composition continues to emit closed windows independently.

## Explicit application detection session

The [detection session](../src/application/detection_session.py) is a frozen application configuration bundle with explicit ordered execution methods. `DetectionSession.run_packets()` consumes `PacketAnalysisOutcome` values and delegates to the existing packet orchestration. `run_closed_flows()` consumes `FlowFeatureSnapshot` values and delegates to the existing closed-flow orchestration. The session retains the exact existing detector configurations; orchestration continues to own detector ordering, applicability, evaluation, and finding normalization for both IPv4 and IPv6.

Each call returns a flat tuple of the exact findings in input order and per-input detector order, including duplicates and `NOT_EVALUABLE` decisions. Empty input returns an empty tuple. Evaluation is synchronous and eager over finite caller-owned iterables. An iteration or detector failure propagates unchanged, stops further consumption, and returns no partial tuple; earlier evaluations are not rolled back or retried. Results are accumulated only in a local call buffer, and repeated calls or separate sessions share no execution state.

The session does not accept raw packets or bare flow windows, perform packet analysis or feature extraction, own a flow/window lifecycle, or alter detector and finding schemas. Active snapshots remain rejected by existing detector validation. Capture/observation sessions still emit closed windows without automatic detection; callers explicitly produce semantic inputs and invoke detection. No new detector, protocol-specific execution path, reassembly, correlation, alerting, or response boundary is introduced.

## Explicit application detection pipeline

The [detection pipeline](../src/application/detection_pipeline.py) exports one opt-in `run_detection_pipeline()` function over an existing `PacketSource` and caller-supplied `DetectionSession`. It shares the flow-observation session's private lifecycle runner, preserving one source consumption, one observation-window manager, and existing cleanup and closure ordering. The public flow-observation function still analyzes and emits closed windows without detection.

For each observation, the pipeline receives the exact outcome through `run_capture_execution()`, which calls `analyze_packet_outcome()` once. The pipeline invokes `DetectionSession.run_packets()` with that exact semantic outcome, and supplies the outcome's analysis to normal flow admission. Recognized failure outcomes receive packet detection but contribute no flow state because their analysis is absent. Raised exceptions propagate; successful analyses with unsupported flow transport retain existing admission errors. The pipeline neither repeats packet analysis nor adds protocol-specific admission rules.

For each closed window delivered by the shared runner, the pipeline calls the existing snapshot extractor once and passes the exact snapshot to `DetectionSession.run_closed_flows()`. Active windows never enter this path. Capture still owns acquisition, analysis still owns packet semantics, flow lifecycle and feature derivation, and detector orchestration still owns execution order and semantics through `DetectionSession`. IPv4 and IPv6 use the same composition. Non-first fragments without transport and ICMPv6 remain outside TCP/UDP flow detection; extension traversal and fragmentation handling remain entirely within packet analysis.

The immutable result retains separate ordered tuples of packet and flow findings, preserving duplicates, exact evidence and configuration references, and existing detector order. Execution is synchronous with local result buffers and no retained history. Errors return no partial result or synthetic finding and are never retried. Existing source-cleanup and window-finalization exception precedence is preserved; packet-detector failure suppresses further detection during cleanup, while downstream feature/detection failures use the runner's existing stop-delivery behavior. The [application contract](../src/application/README.md#explicit-detection-pipeline) specifies these boundaries.

This composition adds no parsing, feature formulas, individual detector calls, new detector family, finding fields, hidden flow state, reassembly, correlation, alerting, persistence, or background execution. Detection remains explicit, and invoking capture or flow observation alone does not execute this pipeline.

## Deterministic PCAP input

The [PCAP packet source](../src/capture/pcap_packet_source.py) incrementally supplies `PacketObservation` values from a regular classic PCAP 2.4 file. It supports both byte orders and both microsecond and nanosecond formats. The source owns only file acquisition and PCAP framing; it delegates no packet decoding, flow state, features, or detector execution. Existing consumers, including `run_detection_pipeline()`, accept it without interface changes.

Global-header validation precedes delivery. Record headers and payload lengths are checked before yielding each observation. Exact bytes, captured/original length distinctions, unknown portable link codes, and record order are preserved. Historical timezone/significant-figures values are ignored; unsigned epoch seconds and fractional fields become canonical UTC timestamps through integer arithmetic. Nanoseconds below microsecond precision are truncated explicitly. PCAPNG and additional network-field metadata are outside this first boundary; see the [capture contract](../src/capture/README.md#classic-pcap-packet-source).

The file is read-only and processed within its startup extent without whole-file buffering. Callers supply an unchanged file, and fresh instances provide deterministic repeated reads. Existing single-session startup, permanent exhaustion, failure, and cleanup rules apply. Corruption raises `CaptureError`; previously delivered observations are not rolled back. No live capture backend, reassembly, storage/retention policy, automatic detection, or correlation is introduced.

## Explicit command-line adapter

`python -m application` invokes [cli.main()](../src/application/cli.py), a standard-library argparse adapter over the single authoritative `run_detection_pipeline()` path. It requires a local PCAP path, explicit detector configuration, session identity, and inactivity duration. It constructs the existing public configuration/session models and `PcapPacketSource`, without owning source lifecycle, packet analysis, flow state, feature derivation, or detector orchestration.

Successful execution emits ordered packet and flow finding arrays as JSON. A private explicit projection preserves the five finding field names and selected existing evidence properties without changing domain schemas or recursively serializing packet/state graphs. Capture timestamps come from observations; no execution-time identifiers, host metadata, or path-derived identities are generated. Address hex encoding is presentation only. The [CLI contract](../src/application/README.md#command-line-adapter) specifies every output field and exit behavior.

Success exits 0 independently of detector decisions; invalid arguments use argparse's exit 2; capture errors exit 1 with a fixed JSON error on stderr and no result. Other exceptions propagate normally without retries or fake findings. Analytical failure outcomes retain their existing meanings. The CLI preserves source/pipeline ordering and existing flow-admission errors, including decreasing admitted-flow timestamps. Capture and detection remain opt-in, and no live capture, PCAPNG, reassembly, persistence, alerting, or new detection semantics are added.

## Deterministic detection result evaluation

The application [evaluation boundary](../src/application/detection_evaluation.py) consumes `DetectionPipelineResult` and explicit immutable `ExpectedDetectionResult` values. It returns separate ordered packet/flow evaluation entries with original finding references, expectation references, input indices, and justified binary classifications. No capture, parsing, flow lifecycle, feature derivation, detection execution, or CLI invocation takes place. Existing detector and pipeline contracts remain authoritative.

Positive expectations require MATCH; negative expectations require NO_MATCH. NOT_EVALUABLE remains attached as its existing typed decision and never earns TP or TN. An unsatisfied positive is FN, including when its retained decision is NOT_EVALUABLE. A negative without NO_MATCH remains unresolved unless contradicted by MATCH (FP). Unlabeled MATCH is FP; unlabeled NO_MATCH/NOT_EVALUABLE is unclassified. Absence never creates TN. The [evaluation contract](../src/application/README.md#detection-result-evaluation) specifies the full table, identity fields, multiplicity, validation, and audit ordering.

Packet identities combine detector configuration, position in the supplied result sequence, and capture metadata. Their scope requires caller-aligned input provenance; they are not content fingerprints or cross-dataset IDs. Flow identities reuse configuration, existing window keys, canonical packed endpoints, and timestamps. No raw bytes, object identity, repr, wall clock, or persistent matching state participate. All matching is local, one-to-one, and deterministic. No metrics, ground-truth files, datasets, benchmarking, ML, correlation, persistence, or additional CLI behavior is introduced.

## Explicit external ground truth

The application [ground-truth boundary](../src/application/ground_truth.py) represents externally supplied positive/negative truth using frozen `GroundTruthRecord` values and separate ordered packet/flow tuples in `GroundTruth`. `GroundTruthPolarity` requires explicit labeling; an unlisted target is unlabeled, never implicitly negative. Truth is independent of actual detector decisions, including NOT_EVALUABLE.

Targets reuse the existing packet and flow detection identities. Packet-position/provenance limitations remain unchanged, and flow targets reuse canonical packed endpoints, window keys, and timestamps. Existing immutable detector configuration scopes which target is labeled without retaining implementation state or detector output. Each target can occur only once in a truth collection; duplicate and contradictory records are rejected deterministically. This does not change evaluation's existing duplicate-expectation semantics.

Ground truth describes externally asserted truth; detection results describe produced decisions; evaluation compares results with explicit expectations. [The ground-truth contract](../src/application/README.md#explicit-ground-truth) defines validation and identity scope. Conversion into evaluation expectations remains future explicit work: no current evaluator, pipeline, or CLI consumes truth automatically. Construction executes no acquisition, analysis, features, detectors, or evaluation and reads no packets or files. No datasets, metrics, benchmarks, experiment framework, ML, persistence, or alerting are introduced.

## Deterministic evaluation metrics

The application [metrics boundary](../src/application/detection_metrics.py) consumes only the existing `DetectionEvaluationResult`. `calculate_detection_metrics()` aggregates entry classifications into separate immutable packet and flow `DetectionMetrics`, grouped in `DetectionEvaluationMetrics`. Counts preserve multiplicity and exact integer values; precision, recall, F1, and accuracy follow the [documented formulas and undefined-value rules](../src/application/README.md#detection-evaluation-metrics) without rounding or smoothing.

Classification is authoritative: an existing FN associated with NOT_EVALUABLE remains an FN. Metrics do not inspect findings, evidence, expectations, detector decisions, or ground truth. Entries with `classification=None` contribute only to `unclassified_count` and are excluded from binary denominators. This does not identify unevaluable cases; the existing result exposes no independent unevaluable count. Neither the evaluation contract nor its semantics changes.

Ground truth supplies external truth, evaluation compares actual results with explicit expectations, and metrics aggregate already-produced classifications. Calculation performs no upstream execution, file access, hidden caching, ground-truth adaptation, or input mutation. Packet and flow channels remain independent. Reporting, benchmarking, dataset loading, experiment tracking, and CLI metrics output are not introduced.

## Immutable detection datasets

The application [dataset representation](../src/application/detection_dataset.py) consists of `DetectionDataset(name, cases)` and `DetectionDatasetCase(case_id, target, ground_truth=None)`. Both are frozen values. Dataset names and case IDs are explicit nonblank strings, with no generation or path interpretation. Cases form an exact ordered tuple; empty datasets are valid and duplicate case IDs are rejected across domains without overwriting or deduplication.

Each case retains an existing typed packet or flow detection identity and optional matching `GroundTruthRecord`. Supplied truth must describe that exact semantic target; absence is unlabeled, never negative. Existing identity, packet-position provenance, flow/window, detector configuration, and truth semantics remain authoritative. No new domain enum, label model, matching key, or automatic expectation conversion is introduced. Distinct cases remain independent associations rather than an implicitly merged truth collection.

[The dataset contract](../src/application/README.md#detection-dataset-representation) organizes already-defined evaluation targets and external truth for later consumers. It does not require actual detector output, establish truth, load data, execute capture or the pipeline, run evaluation, or calculate metrics. Ordering is caller-defined, references are immutable, and validation uses only local temporary state. Dataset loaders, performance benchmarks, experiment frameworks, reporting, and storage remain unimplemented.

## Deterministic benchmark orchestration

The application [benchmark framework](../src/application/detection_benchmark.py) exports `run_detection_benchmark(dataset, operation)`. It accepts the existing `DetectionDataset` and a synchronous callable receiving each exact `DetectionDatasetCase` once in caller-defined order. The callable returns a frozen `DetectionBenchmarkCaseResult` retaining its case and optional existing `DetectionEvaluationResult` and `DetectionEvaluationMetrics`. The framework validates case association without inspecting evaluation entries, findings, evidence, or metric values.

A frozen `DetectionBenchmarkResult` retains the source dataset and exact ordered case-result references, exposes the unchanged dataset name and total case count, and validates one result per case. Empty datasets yield zero results; duplicate case identities remain governed by dataset validation. Packet/flow targets and supplied truth are preserved. Missing payloads remain absent and are never synthesized. Exceptions propagate immediately without retry, later-case execution, or returned partial results; earlier callable side effects are not rolled back.

[The benchmark contract](../src/application/README.md#deterministic-benchmark-execution) owns orchestration only. Explicit operations may use existing evaluation and metrics APIs; the framework does not invoke them or the NIDS pipeline itself. It adds no parsing, capture, detection, feature logic, truth inference, timing, performance measurement, loading, concurrency, reporting, or experiment tracking. Framework state is local to each invocation, and deterministic operation outputs produce deterministic ordered results. Performance benchmarking remains future work.

## Deterministic configuration representation

The application [configuration value](../src/application/detection_configuration.py) is a frozen `DetectionConfiguration` retaining the existing packet-integrity and flow-volume configurations, optional TCP-control configuration, and a positive exact `timedelta` for window inactivity. This composes reusable settings without retaining execution provenance, sources, sessions, results, or callables. Capture-session identity and acquisition inputs remain explicit per-execution concerns.

Existing detector values own identity/version, metric selection, threshold validation, and semantics; window lifecycle still owns how the timeout is applied. The configuration validates only composition types and the established positive-duration constraint. Equality uses all supplied immutable settings, with no generated configuration identity, copying, normalization, sorting, or hidden state. [The configuration contract](../src/application/README.md#deterministic-configuration-representation) documents optional TCP configuration and exact reference preservation.

Construction and inspection execute no NIDS or evaluation behavior. Existing experiment, dataset, benchmark, session, pipeline, CLI, evaluation, and metrics contracts remain unchanged. This boundary provides representation and validation only, with no loading, persistence, registries, reporting, or execution. Detector version references are a separate detection value contract; feature-contract provenance is owned separately by analysis.

## Reproducible experiment definitions

The application [experiment definition](../src/application/detection_experiment.py) is the frozen `DetectionExperiment(experiment_id, dataset, benchmark_operation_id, benchmark_operation_version)`. It retains the existing dataset and explicit nonblank identity strings. Full value equality includes dataset cases, ordering, truth, target configurations, and the declared operation ID/version; it does not use object identity or generated fingerprints.

The operation reference describes caller-defined benchmark/evaluation work and is not resolved or executed. Callers own the correspondence between that reference and the external procedure and its inputs. Existing detector configuration and version values remain on dataset targets; evaluation and metrics are not redefined. [The experiment contract](../src/application/README.md#reproducible-experiment-definition) adds no configuration-management, detector-versioning, or feature-versioning subsystem.

Datasets define cases, benchmarks execute explicit operations, and experiments describe intended work. Definitions contain no callable, execution result, finding, metric output, or runtime metadata. Construction and inspection perform no loading, system execution, external access, timing, randomness, or persistence. Experiment executors, tracking, result storage, performance benchmarking, configuration loading, version management, and reporting remain future work.

## Explicit detector version references

The detection layer exports the frozen [DetectorVersion](../src/detection/detector_version.py) pair of exact nonblank `detector_id` and `detector_version` strings. Identity specifies which detector; version specifies its caller-declared revision. Equality compares both strings with no normalization, semantic-version interpretation, automatic discovery, or generated identity.

The three detector configurations and `DetectionFinding` provide a read-only `version_reference` projection from their existing fields, adding no stored state. Operational metrics/thresholds remain in configurations. Evidence, configuration constructors, finding schema, CLI output, and evaluation matching remain unchanged. Evaluation, truth, dataset, benchmark, and experiment identities retain full configuration and packet/flow provenance; a version reference is not a replacement matching key.

[The version-reference contract](../src/detection/README.md#explicit-detector-version-references) performs no execution or external access and introduces no registry, loading, Git/package discovery, persistence, or deployment. Configuration management continues to compose settings; feature-contract provenance remains a separate analysis contract.

## Explicit feature contract provenance

Analysis exports the frozen [FeatureContractVersion](../src/analysis/feature_contract_version.py) pair of exact nonblank `contract_id` and `contract_version` strings. The current `FlowFeatureSnapshot.feature_contract` statically declares `flow-feature-snapshot` / `1`. This read-only projection adds no stored field, selectable extractor, generated identity, or cache. It names the current typed snapshot composition and existing nested feature/availability semantics without duplicating a schema.

The seven snapshot fields, field order, exact retained window, feature formulas, numeric precision, TCP/UDP optionality, IPv4/IPv6 parity, and lifecycle remain unchanged. Snapshot equality retains its original fields: there is only one controlled snapshot implementation, so provenance is fixed rather than a new caller-selectable equality dimension. Independently supplied contract reference values may differ, but cannot relabel or migrate existing snapshots. [The feature-contract documentation](../src/analysis/README.md#explicit-feature-contract-version) defines that scope and the current zero/absent semantics.

Detector versions and operational configurations remain separate. Existing finding/evaluation/ground-truth identities, datasets, benchmarks, and experiments do not gain feature-version fields or new matching behavior. Flow-volume evidence already retains the snapshot; consumers can inspect its provenance through that association. Construction and inspection execute no features or NIDS behavior and access no external state. No registry, migration, discovery, serialization, persistence, reporting, or performance infrastructure is introduced.

## Evaluation reporting data contract

The application [EvaluationReport](../src/application/evaluation_report.py) retains either an existing `DetectionEvaluationResult` with optional supplied `DetectionEvaluationMetrics`, or an existing `DetectionBenchmarkResult` whose case results already retain evaluations and metrics. This avoids a duplicate report-entry model. Benchmark reports reject top-level metrics because no aggregate benchmark metric contract exists.

Optional exact experiment and system-configuration references preserve explicitly declared context. Benchmark/experiment datasets must compare equal in full; dataset identity and case count are projected from retained objects, never independently copied or discovered. Missing dataset context remains `None`; an empty dataset has zero cases. No report identity, benchmark identity, execution attestation, or new version fields are generated.

[The reporting contract](../src/application/README.md#evaluation-reporting-representation) preserves classifications, packet/flow separation, undefined metric values, unclassified/unlabeled distinctions, exact input references, and ordering. Evaluation owns matching; metrics own counts and derived values; reporting owns only an immutable presentation-neutral association. It neither checks numerical consistency by recomputing metrics nor reinterprets NOT_EVALUABLE. Rendering, serialization, persistence, execution, discovery, and timing remain outside this boundary. CLI output and all upstream semantics remain unchanged.

## End-to-end system validation

The application [validation operation](../src/application/end_to_end_validation.py) composes existing calls: `PcapPacketSource` (or another explicitly supplied packet source) → `run_detection_pipeline` → `evaluate_detection_result` → `calculate_detection_metrics` → `EvaluationReport`. The pipeline continues to own capture execution, packet analysis, flow lifecycle, feature extraction, and detector orchestration. Supplied `GroundTruth` records are explicitly adapted into existing packet/flow expectations without consulting detector output.

`EndToEndValidationResult` retains the authoritative pipeline result, supplied truth, and report. Observations/outcomes and windows/snapshots remain accessible through existing finding evidence. Report evaluation, metrics, configuration, and optional experiment references are preserved. Dataset context remains explicitly declared context, not an executed dataset benchmark. Feature and detector versions keep their established independent semantics.

[The validation contract](../src/application/README.md#end-to-end-system-validation) preserves ordering, failures, source cleanup, and historical evaluation semantics. Returning a result establishes completed composition rather than a new pass/fail classification. Repeated deterministic PCAP inputs use fresh sources; no timing or external metadata enters the operation. Tests guard against duplicate analysis, extraction, detection, evaluation, metric calculation, and report construction. No upstream contract, renderer, serializer, storage, network, or performance framework is added.

## Cross-cutting requirements for later tasks

- Preserve sensor/source identity, capture time, processing time where needed, and provenance across transformations. Specify identifier and schema evolution rules before persisting records.
- Treat malformed, truncated, unsupported, duplicated, and out-of-order traffic explicitly. Missing visibility, packet loss, encrypted payloads, and partial sessions must not silently become evidence of benign traffic.
- Bound buffers, fragment and stream reassembly, flow tables, detector windows, and enrichment caches. Define timeouts, overload behavior, and loss accounting before sustained capture is enabled.
- Specify event-time and clock assumptions for reproducible windowing and correlation. Record configuration, rule, and baseline versions needed to explain findings and scores.
- Separate capture privileges from analysis and presentation where the chosen platform permits it. Define authentication, authorization, retention, and sensitive-data handling when the corresponding runtime boundaries are implemented.
- Make operational health observable independently of security findings. Define failure handling, shutdown, recovery, and delivery guarantees with the execution model rather than assuming lossless or exactly-once processing.

These are design requirements for subsequent work, not capabilities delivered by this repository scaffold. Machine learning, active response, SIEM adapters, and dashboard implementation are not introduced by this task.
