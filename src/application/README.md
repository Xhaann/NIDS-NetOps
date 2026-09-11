# Application composition

The `application` package composes implemented subsystem contracts without taking ownership of their internal state. It does not define packet acquisition, protocol decoding, flow identity, accumulation, feature extraction, detection, persistence, or user interfaces.

## Capture execution

[capture_execution.py](capture_execution.py) exports `run_capture_execution(source: PacketSource, consumer: Callable[[PacketAnalysisOutcome], None]) -> None`. This synchronous application boundary delegates source startup, ordered delivery, and cleanup to unchanged `consume()`. It invokes `analyze_packet_outcome()` once per observation and immediately passes that exact outcome to the caller's consumer. The original observation, bytes, timestamps, lengths, and link type remain unchanged. Empty sources deliver no outcomes.

A callback fits the existing ingestion lifecycle: it runs before the next observation is requested, and its exceptions remain inside `consume()`'s cleanup guarantee. The boundary retains no source-wide buffer, result collection, or execution history. Caller-owned consumers may collect outcomes if desired. An abandoned lazy iterator would require an additional explicit cleanup contract; none is introduced here.

Successful and failed analytical outcomes are both delivered without reconstruction, filtering, or reclassification. Acquisition errors, unexpected analysis exceptions, and consumer exceptions propagate without retry and stop further delivery. Source cleanup is attempted exactly once by `consume()`, even after startup failure; cleanup failures preserve existing Python exception precedence and context. Earlier delivered outcomes are neither rolled back nor converted into synthetic results.

Both `IterablePacketSource` and `PcapPacketSource` use this same path. Record order, duplicate observations, and decreasing timestamps remain intact. Determinism is relative to observations supplied by the source: PCAP timestamps remain deterministic, while the iterable source retains its existing acquisition-time clock behavior. Repeatable reads use independent source instances according to their existing lifecycle contracts.

The detection pipeline uses this public boundary. The standalone flow-observation session reuses its private execution primitive with `analyze_packet()` to preserve the established parser-exception and checksum behavior; it does not substitute failure outcomes for exceptions. The primitive only couples one analysis call to one consumer call through `consume()`. Packet interpretation remains in analysis, window lifecycle remains in flow observation, and detection remains explicit through `DetectionSession`. Direct capture execution invokes no detectors and creates no flow state, features, reassembly, persistence, or background work.

## Detector orchestration

[detector_orchestration.py](detector_orchestration.py) exports two synchronous functions through the `application` package:

- `run_packet_detectors(outcome: PacketAnalysisOutcome, configuration: PacketIntegrityConfiguration) -> tuple[DetectionFinding, ...]`
- `run_closed_flow_detectors(snapshot: FlowFeatureSnapshot, *, flow_volume_configuration: FlowVolumeThresholdConfiguration, tcp_control_configuration: Optional[TCPControlThresholdConfiguration] = None) -> tuple[DetectionFinding, ...]`

The packet path passes the exact outcome and configuration to the packet-integrity evaluator once, converts its exact evaluation through `detection_finding_from_evaluation()`, and returns a one-finding tuple.

The closed-flow path first evaluates the exact snapshot with the exact volume configuration and converts that evaluation to a finding. For TCP, it then evaluates the snapshot's exact retained observation window with the exact TCP-control configuration and converts that evaluation. The tuple order is always volume first, TCP control second. TCP requires its configuration. UDP invokes only the volume detector and requires no TCP configuration; a supplied TCP configuration must still have the exact supported type.

Existing detector validation rejects active snapshots without closing or modifying their windows. `FlowIdentity` construction accepts only protocols 6 and 17, so unsupported flow protocols cannot reach this path through valid model construction. Packet orchestration preserves the separate packet-analysis outcome contract.

Each applicable detector and finding conversion runs once per invocation. Every `MATCH`, `NO_MATCH`, and `NOT_EVALUABLE` finding is retained. The returned immutable tuple contains the exact converted findings, which retain exact detector evidence, interpretation, and configuration references. A detector or conversion failure propagates unchanged immediately, with no retry, later detector execution, or partial tuple publication.

These functions retain no history or background state and introduce no common detector input, registry, generic framework, filtering, attack inference, severity, confidence, risk, correlation, alerting, persistence, or response behavior. Callers supply already-produced analytical inputs; capture-session wiring, packet analysis, feature extraction, and observation-window lifecycle remain separate operations.

## Explicit detection sessions

[detection_session.py](detection_session.py) exports the frozen `DetectionSession(packet_configuration, flow_volume_configuration, tcp_control_configuration=None)` through `application`. It retains the exact existing `PacketIntegrityConfiguration`, `FlowVolumeThresholdConfiguration`, and optional `TCPControlThresholdConfiguration` objects. Construction validates their exact types and runs no detectors. No session identifier, timestamp, execution history, or lifecycle state is created.

- `run_packets(outcomes: Iterable[PacketAnalysisOutcome]) -> tuple[DetectionFinding, ...]` delegates once per outcome to `run_packet_detectors()` with the retained packet configuration.
- `run_closed_flows(snapshots: Iterable[FlowFeatureSnapshot]) -> tuple[DetectionFinding, ...]` delegates once per snapshot to `run_closed_flow_detectors()` with the retained flow configurations.

Each call consumes a finite iterable synchronously in caller-supplied order and returns one flat immutable tuple containing the exact findings produced by orchestration. Empty input returns `()`. Per-input detector ordering, all three decision meanings, configuration identity, and evidence references are preserved. Inputs and findings are neither sorted nor deduplicated. Repeated calls execute again; sessions retain no results or shared mutable state. The only execution buffer is local to each call and grows with its returned findings.

Detector orchestration remains authoritative for validation, applicability, ordering, and normalization. Flow calls require snapshots whose retained windows are closed; bare windows are not converted into snapshots. Active windows, missing TCP configuration/state, and malformed inputs retain existing errors. IPv4 and IPv6 follow the same path: closed TCP flows invoke volume then TCP control, and UDP invokes only volume. Non-first fragments without transport cannot become flow inputs, while their packet outcomes retain existing packet-integrity semantics. No new detector family or ICMPv6 detector is introduced.

An input-iteration or orchestration exception propagates unchanged and stops the call before the next input. No retry or partial tuple is returned. Earlier completed evaluations are not rolled back; their locally accumulated findings are not published by the failed call. A later explicit call remains independent. Iterables and their resource cleanup remain caller-owned.

The session accepts established semantic inputs only. It does not capture packets, parse bytes, re-run packet analysis or extension validation, build flow state, close windows, extract features, or reconstruct findings. `run_flow_observation_session()` remains unchanged and emits closed windows without detector execution. Callers explicitly extract snapshots and invoke the detection session when desired. No reassembly, correlation, alerting, persistence, or background execution is added.

## Explicit detection pipeline

[detection_pipeline.py](detection_pipeline.py) exports `run_detection_pipeline(source, *, detection_session, capture_session_id, inactivity_timeout) -> DetectionPipelineResult`. The caller supplies an existing `PacketSource` and exact `DetectionSession`; detector configuration is not duplicated. Only invoking this function performs the composition. Capture/observation APIs and session construction do not automatically run detectors.

The pipeline and `run_flow_observation_session()` share a private lifecycle runner. That runner alone constructs the observation-window manager, records admitted analyses, and finalizes windows. Source execution delegates to the shared capture-execution primitive around `consume()`. The public flow-observation API still uses `analyze_packet()` and preserves its existing signature and behavior. The pipeline executes `run_capture_execution()` once: each exact outcome reaches `DetectionSession.run_packets()` before its analysis is supplied for normal flow admission. Detection never receives raw bytes or repeats analysis.

Recognized analysis failures remain structured outcomes: packet detection evaluates them using its existing semantics, and their absent analysis contributes no flow observation. Exceptions escaping the outcome API propagate. Successful analyses without supported transport, including ICMPv6, unsupported protocols, and non-first IPv6 fragments, retain the existing flow-admission errors. They are not silently skipped or assigned fabricated transport state.

Each delivered closed window passes once through `extract_flow_feature_snapshot()`. Its exact snapshot and retained window reach `DetectionSession.run_closed_flows()`. Active windows are never delivered. IPv4 and IPv6 share this path: TCP receives volume then TCP-control detection, and UDP receives only volume detection. First/whole fragments participate only when existing transport admission succeeds. The pipeline performs no protocol decoding, extension traversal, fragmentation analysis, feature calculation, detector evaluation, or finding construction itself.

The frozen `DetectionPipelineResult(packet_findings, flow_findings)` contains two tuples of exact findings. Packet findings preserve observation and detector order; flow findings preserve window-closure and detector order. There is no combined chronological sorting, deduplication, or correlation. Evidence and configuration references are retained. Empty input returns two empty tuples. Results accumulate synchronously in local memory, so callers must use finite input and account for result size. Repeated calls with equivalent sources and configurations produce equal results without retaining execution history.

Errors propagate without translation, retry, or a partial result. Source cleanup and window finalization retain the existing flow-session semantics: source, analysis, or admission errors still finalize prior windows and attempt their delivery. A packet-detector failure suppresses subsequent feature/detector execution during finalization; feature or closed-flow detector failures stop downstream delivery through the existing runner. Source `stop()` failures can supersede an earlier failure, and final-delivery failures can supersede source failures, retaining normal Python exception context. Earlier local findings are neither rolled back nor published by a failed call.

The pipeline owns composition only. Capture owns acquisition; analysis owns packet semantics, flow lifecycle, and feature derivation; `DetectionSession` delegates ordering, applicability, and finding normalization to detector orchestration. Finding/configuration schemas and feature/threshold formulas remain unchanged. No additional tracker, hidden state, background execution, cache, reassembly, new detector family, alerting, or persistence is introduced.

## Flow observation sessions

[flow_observation_session.py](flow_observation_session.py) exports `run_flow_observation_session(source, *, capture_session_id, inactivity_timeout, closed_window_consumer) -> None`. One invocation constructs one `FlowObservationWindowManager`, runs the source exactly once through the shared capture-execution primitive and `consume()`, analyzes each delivered `PacketObservation` with `analyze_packet()`, and passes the resulting `PacketAnalysis` unchanged to the manager.

The caller selects `capture_session_id` and owns its uniqueness outside the invocation. The function passes it unchanged to the manager and does not generate identifiers from time, flow identity, process state, or object identity.

Inactivity-closed windows are delivered synchronously in the order returned by `record()` before the source can produce the next observation. Active windows are not delivered. After `consume()` has attempted `source.stop()`, `end_capture_session()` closes the remaining active windows and those windows are delivered in the manager's returned order. Empty sessions produce no windows.

Delivery is ordered and at most once. A downstream failure is not retried, an attempted window is not re-emitted, and no further calls are made to a failed consumer. Remaining active windows are still finalized. The function retains no closed-window history or output queue. Synchronous delivery supplies backpressure by preventing the next source observation until the consumer returns.

Existing source, decoding, analysis, identity, coordination, lifecycle, and downstream exceptions propagate without translation. Source cleanup follows `consume()`: a `stop()` failure can supersede an active failure while retaining it as exception context. Lifecycle finalization is attempted after source cleanup even when source start, iteration, analysis, identity, coordination, lifecycle, or stop fails. A later finalization or final-delivery failure follows normal Python exception precedence.

TCP and UDP use the same path. TCP flags do not control lifecycle, UDP has no transaction inference, and TCP control state remains absent for UDP. ICMP packet analysis exists, but the current flow identity contract rejects ICMP and that error propagates. Skipping invalid or unsupported packets is **UNDEFINED POLICY**.

The application boundary continues to emit exact `FlowObservationWindow` objects and does not perform feature extraction. Downstream consumers may independently pass an emitted closed window to `extract_flow_feature_snapshot()`, which retains that exact window as provenance. Active windows are also valid provisional extraction inputs through the analysis API. Explicit segmentation during a running source, durable delivery, retries, rejected-packet routing, live capture, packet-loss accounting, ML vectorization, and serialization are not part of this layer.
