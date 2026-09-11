# Detection boundary

This directory owns detector-specific evaluation contracts. Implemented detectors evaluate packet-local integrity outcomes, flow-volume and flow-rate thresholds over finalized analysis windows, and raw TCP control-counter thresholds. It does not provide a generic detector framework, event correlation, alerting, or a numerical vector boundary.

| Family | Responsibility |
| --- | --- |
| Signature | Match defined patterns against supported analysis inputs. |
| Rule | Evaluate explicit predicates over structured observations or features. |
| Threshold | Evaluate counters or measurements against configured limits and windows. Deterministic flow-volume and flow-rate threshold evaluation is implemented. |
| Statistical | Compare measurements with defined statistical baselines. |
| Behavioral | Evaluate entity activity or sequences using bounded state. |

Detectors consume [analysis](../analysis/README.md) outputs through explicit contracts and produce immutable evaluations with detector identity/version, supporting evidence, and a bounded interpretation. Severity and confidence require separately defined meanings and are not supplied by the current detector. Each detector owns only its detection-specific state, not protocol or session state.

The families use detector-specific input contracts and remain independently testable and configurable. [Event processing](../events/README.md) owns cross-finding correlation, risk scoring, deduplication, and alert lifecycle. External intelligence access belongs to [enrichment](../enrichment/README.md). No signature, statistical, behavioral, training, or model implementation is established here.

## IPv4 and IPv6 applicability

| Existing detector | Input and family applicability |
| --- | --- |
| Packet integrity | Packet-local `PacketAnalysisOutcome`; the same structural/integrity predicates already apply to both families. IPv6 protocol evidence uses the retained terminal extension-chain selector. |
| Flow volume/rate threshold | Closed `FlowFeatureSnapshot` for IPv4 or IPv6 TCP/UDP, using unchanged generic measurements and thresholds. |
| TCP control threshold | Closed IPv4 or IPv6 TCP window with existing `TCPControlStatistics`. UDP remains rejected by direct evaluation and skipped by orchestration. |

Validated extension-header transport and first/whole fragments with decoded TCP/UDP follow the same flow detector applicability. Non-first fragments without decoded transport, ICMPv6, and unsupported protocols cannot enter TCP/UDP flow detection. Successful packet analysis for these protocols is not itself an integrity violation; incomplete and malformed analysis retain the existing outcome predicates. No ICMPv6-specific detector or IPv6 transport checksum validation is introduced.

Detectors do not inspect raw IPv6 payloads, scan ahead, repeat extension validation, create flow state, or reassemble or correlate fragments. Exact captured and original byte measurements remain unnormalized. No extension-header, Flow Label, or fragmentation metrics are added. Detection remains explicitly invoked through the existing APIs and orchestration, preserving ordering, errors, evidence, interpretations, and finding schemas. Parity does not imply full IPv6 attack coverage, reassembly coverage, correlation, alerting, or incident response.

## Immutable detector findings

[detection_finding.py](detection_finding.py) exports `DetectionFinding`, `DetectionFindingError`, and `detection_finding_from_evaluation(evaluation) -> DetectionFinding`. The conversion accepts exactly a current packet-integrity, flow-volume threshold, or TCP-control threshold evaluation. It does not define a common detector input or execute a detector.

The frozen finding stores exactly detector identity, detector version, the exact detector-specific decision enum member, the exact raw evidence object, and the exact detector-specific security interpretation object. It validates nonblank exact-string metadata against evidence metadata, preserves the current detector family across decision, evidence, and interpretation, and enforces the established decision-to-interpretation mapping. Evidence decision is compared when the evidence contract exposes it. No detector predicate is recomputed.

Detector-specific evidence remains authoritative for packet, flow, metric, threshold, and lifecycle provenance. The finding neither duplicates nor flattens those values and creates no dictionary, text, byte, serialization, or universal feature representation. Separate detector decision enum types and input contracts remain intact.

`DetectionFinding` is a normalized immutable detector result. It is not an alert, event correlation, risk score, incident, attack classification, or persistence record. It has no finding identifier, severity, confidence, priority, response, deduplication, aggregation, networking, filesystem access, or orchestration behavior. Future event and correlation policy may consume findings through a separately approved contract.

## Packet integrity and structural outcomes

[packet_integrity.py](packet_integrity.py) exports `PacketIntegrityConfiguration`, `PacketIntegrityDecision`, `PacketIntegrityEvidence`, `PacketIntegrityInterpretation`, `PacketIntegrityEvaluation`, `PacketIntegrityError`, and `evaluate_packet_integrity(outcome, configuration) -> PacketIntegrityEvaluation`.

The evaluator accepts exactly one immutable `PacketAnalysisOutcome` and one exact frozen configuration containing only nonblank detector identity and version strings. It accepts successful, structural-failure, integrity-failure, incomplete, and unsupported outcomes across the existing packet-analysis scope. It does not accept observations, analyses, bytes, flow windows, feature snapshots, or aggregate state as separate inputs.

The fixed predicate maps successful analysis to `NO_MATCH`; `STRUCTURAL_FAILURE` and `INTEGRITY_FAILURE` to `MATCH`; and `INCOMPLETE` and `UNSUPPORTED` to `NOT_EVALUABLE`. An unsupported or insufficient observation is not treated as a violation. IPv4 UDP checksum omission remains the existing successful analysis outcome and therefore produces `NO_MATCH`; no checksum is recomputed or reinterpreted by detection.

Raw evidence retains the exact outcome and exact configuration. Read-only properties expose the exact observation and successful analysis when present, capture timestamp, capture source, link type, captured and original lengths, existing failure classification and unchanged description, detector identity and version, derived decision, and the IPv4 protocol number or the retained IPv6 extension chain's terminal Next Header when available from a successful analysis. Missing analysis or terminal context yields `None`; the IPv6 base Next Header is not substituted for a missing chain. The detector does not parse raw bytes to recover missing protocol context.

Security interpretation is a separate closed enum. It states only that no supported violation was observed, that a supported structural or integrity violation was observed, or that analysis was not evaluable. A match describes the current implemented analysis predicate and does not establish maliciousness, an attack, exploit, scan, flood, intent, endpoint role, protocol-stack compromise, or RFC-wide noncompliance.

Evaluation is synchronous, packet-local, deterministic, stateless, immutable, and constant-memory. The detector performs no decoding, checksum validation, flow processing, packet history, caching, filesystem or network access, orchestration, persistence, alerting, or response behavior.

## Flow-volume and flow-rate thresholds

[flow_volume_threshold.py](flow_volume_threshold.py) exports `FlowVolumeThresholdConfiguration`, `FlowVolumeMetric`, `FlowVolumeThresholdDecision`, `FlowVolumeThresholdComparison`, `FlowVolumeThresholdEvidence`, `FlowVolumeThresholdInterpretation`, `FlowVolumeThresholdEvaluation`, `FlowVolumeThresholdError`, and `evaluate_flow_volume_threshold(snapshot, configuration) -> FlowVolumeThresholdEvaluation`.

The evaluator requires an exact `FlowFeatureSnapshot` whose retained observation window is closed by `INACTIVITY`, `CAPTURE_SESSION_END`, or `EXPLICIT_SEGMENTATION`. It supports the common IPv4/IPv6 TCP and UDP flow-identity boundary. Active snapshots, subclasses, unrelated inputs, and unsupported protocols are rejected. Feature extraction, lifecycle closure, packet admission, and application orchestration remain separate operations.

The closed metric enumeration contains exactly:

| Metric | Type and source |
| --- | --- |
| `packet_count` | Exact nonnegative integer from flow-volume features. |
| `captured_bytes` | Exact nonnegative integer from flow-volume features. |
| `original_bytes` | Exact nonnegative integer from flow-volume features. |
| `forward_packet_count` | Exact nonnegative integer in canonical forward direction. |
| `reverse_packet_count` | Exact nonnegative integer in canonical reverse direction. |
| `forward_captured_bytes` | Exact nonnegative integer in canonical forward direction. |
| `reverse_captured_bytes` | Exact nonnegative integer in canonical reverse direction. |
| `forward_original_bytes` | Exact nonnegative integer in canonical forward direction. |
| `reverse_original_bytes` | Exact nonnegative integer in canonical reverse direction. |
| `packets_per_second` | Exact finite nonnegative float from flow-rate features when available. |
| `captured_bytes_per_second` | Exact finite nonnegative float from flow-rate features when available. |
| `original_bytes_per_second` | Exact finite nonnegative float from flow-rate features when available. |

Configuration is a frozen value containing a nonblank detector identifier, nonblank detector version, exact metric enum member, and exact threshold. Count and byte thresholds require built-in nonnegative integers and reject booleans. Rate thresholds require built-in finite nonnegative floats. No value is coerced, rounded, clipped, normalized, or replaced by a sentinel.

The sole predicate is strict greater-than: an observed value greater than its threshold produces `MATCH`; equality or a smaller value produces `NO_MATCH`. A zero-duration window has no flow-rate feature family, so a selected rate produces `NOT_EVALUABLE` with `observed_value=None`. Its counts and byte totals remain evaluable. No NaN or infinity represents absence.

Raw evidence retains the exact snapshot, configuration, selected metric value, and typed `>` comparison. Read-only properties preserve the exact observation window and identity and expose capture-session identifier, window sequence number, closure reason, first and last captured timestamps, protocol, total and directional packet counts, and captured and original byte totals. Provenance is neither reconstructed nor numerically encoded.

Security interpretation is a separate typed field. It states only that the configured threshold was exceeded, was not exceeded, or could not be evaluated. A match does not establish DoS, DDoS, flooding, scanning, brute force, exfiltration, malware, maliciousness, service degradation, or resource exhaustion. Forward and reverse remain canonical endpoint directions rather than client/server, initiator/responder, or attacker/victim roles.

Evaluation is synchronous, deterministic, stateless, and constant-memory. It retains no packet or window history, cross-flow state, cache, queue, timer, filesystem resource, or network resource. It does not inspect packet-size, inter-arrival, ratio, or TCP-control features. Detector integration into capture-session application orchestration remains unimplemented.

The detector evaluates the finalized analytical state it receives. A difference between captured-byte and original-byte totals preserves capture truncation already represented by packet observations, but the current input carries no packet-loss or duplication classification. Loss, duplication, asymmetric visibility, lifecycle configuration, and capture position can change the measurement and must not be inferred from the detector result.

## TCP control-counter thresholds

[tcp_control_threshold.py](tcp_control_threshold.py) exports `TCPControlThresholdConfiguration`, `TCPControlMetric`, `TCPControlThresholdDecision`, `TCPControlThresholdComparison`, `TCPControlThresholdEvidence`, `TCPControlThresholdInterpretation`, `TCPControlThresholdEvaluation`, `TCPControlThresholdError`, and `evaluate_tcp_control_threshold(window, configuration) -> TCPControlThresholdEvaluation`.

The evaluator requires one exact closed `FlowObservationWindow` for IPv4 or IPv6 TCP protocol 6. It reads the existing exact `TCPControlStatistics` from the window's coordinated state. Active windows, UDP, unsupported protocols, subclasses, unrelated objects, and malformed configurations are rejected. The detector neither accepts a redundant statistics argument nor performs feature extraction, packet decoding, checksum validation, flag accounting, lifecycle mutation, or application orchestration.

The closed metric enumeration contains exactly the forward and reverse NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN, and SYN+ACK counters already accumulated by analysis. SYN+ACK remains an independent joint same-packet observation; it is not reconstructed from SYN and ACK marginals. Packet counts, duration, rates, packet sizes, inter-arrival statistics, ratios, and other flag combinations are not selectable metrics.

Configuration is a frozen value containing an exact nonblank detector identifier, exact nonblank detector version, exact metric enum member, and exact built-in nonnegative integer threshold. Booleans, floats, strings, `None`, negative integers, integer subclasses, coercion, normalization, and arbitrary predicate functions are rejected.

The only predicate is strict greater-than. A selected count above its threshold produces `MATCH`; equality or a smaller count produces `NO_MATCH`. Zero is a valid threshold, so a positive count exceeds it while a zero count does not. `NOT_EVALUABLE` is reserved in the decision enum, but valid TCP control statistics always provide exact integer counters and normal supported evaluation therefore produces only `MATCH` or `NO_MATCH`. Unsupported and invalid inputs raise errors rather than becoming unavailable measurements.

Raw evidence retains the exact observation window and configuration and exposes the exact coordinated `TCPControlStatistics` object. It preserves the selected count, threshold, typed `>` comparison, capture-session identifier, window sequence number, closure reason, exact flow identity, first and last captured timestamps, TCP protocol number, total TCP packet count, and forward and reverse packet counts without reconstructing or numerically encoding provenance.

Security interpretation is a separate typed field and states only whether the configured TCP control-counter threshold was exceeded. A SYN, RST, FIN, or SYN+ACK threshold match does not establish an attack, SYN flood, DoS, DDoS, scan, handshake outcome, connection failure or termination, retransmission, endpoint role, or maliciousness. Forward and reverse retain canonical endpoint ordering and do not mean client/server, initiator/responder, or attacker/victim.

Each evaluation covers one finalized observation window closed by inactivity, capture-session end, or explicit segmentation. Counts reset through the existing new-window coordinator boundary and never span windows. TCP flags do not create, close, or segment windows. Because analysis retains aggregate counters rather than packet or flag-transition order, distinct packet orders with the same counters are intentionally indistinguishable to this detector.

Evaluation is synchronous, deterministic, stateless, immutable, and constant-memory. It retains no packet history, window history, cross-flow or host state, cache, queue, timer, thread, filesystem resource, or network resource. It introduces no derived TCP numerical feature family, state machine, normalization, vectorization, persistence, machine learning, severity, confidence, score, finding identifier, correlation, alert state, or response action. Automatic detector execution within capture sessions remains unimplemented.


## Explicit detector version references

`DetectorVersion(detector_id, detector_version)` is a frozen value exported by `detection`. The ID identifies the detector; the version identifies its explicitly declared revision. Both must be exact nonblank strings: wrong types raise `TypeError`, blank values raise `ValueError`. Whitespace, case, Unicode, and arbitrary nonblank revision labels are retained exactly. There is no semantic-version parsing, coercion, normalization, version ordering, or generated identifier.

`PacketIntegrityConfiguration`, `FlowVolumeThresholdConfiguration`, `TCPControlThresholdConfiguration`, and `DetectionFinding` expose a read-only `version_reference` property returning this pair from their existing fields. No additional field or cached copy is stored. Existing constructors, configuration validation/errors, finding schema, evidence references, detector formulas, and CLI JSON remain unchanged. A reference can also be constructed directly from externally supplied identity strings without creating a detector configuration or finding.

Value equality compares both strings. This identifies a declared detector revision independently of selected metrics and thresholds; it does not identify a complete configuration or evaluation target. Different thresholds may share a version reference while remaining different configurations. The caller owns the correspondence between a declared ID/version and an implementation; the reference does not prove implementation equivalence or enforce globally unique IDs across detector families.

Raw evidence continues to retain exact configurations and expose their original ID/version strings. Packet/flow evaluation identities continue to include full configurations and existing provenance. Ground truth, dataset targets, benchmark artifacts, experiments, and aggregate `DetectionConfiguration` retain those same objects and can obtain references through their existing configuration associations. Matching never substitutes the smaller version pair for target identity, and no application contract changes.

Construction and projection perform no detector, capture, analysis, feature, pipeline, evaluation, metrics, benchmark, or experiment execution. They access no packets, evidence contents, files, network, Git state, package metadata, environment, clock, or random state. No discovery, dynamic loading, registry, persistence, deployment, reporting, or performance measurement is provided. The [feature contract reference](../analysis/README.md#explicit-feature-contract-version) separately identifies the typed snapshot representation; neither detector nor feature versions imply one another.
