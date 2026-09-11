# Application composition

The `application` package composes implemented subsystem contracts without taking ownership of their internal state. It does not define packet acquisition, protocol decoding, flow identity, accumulation, feature extraction, detection, persistence, or graphical interfaces.

## Command-line adapter

[cli.py](cli.py) provides `main(argv=None) -> int`; [__main__.py](__main__.py) exposes it through `PYTHONPATH=src python3 -B -m application`. Importing either module performs no execution. The CLI adds no package-level exports; serialization helpers stay private. The adapter accepts one authoritative local classic PCAP path, constructs `PcapPacketSource`, and invokes `run_detection_pipeline()` exactly once. Capture acquisition, execution, analysis, flow lifecycle, feature derivation, and detector orchestration remain delegated to their existing owners.

All detector configuration is explicit because the domain models define no canonical defaults. Required options are `--capture-session-id`, `--inactivity-timeout-microseconds`, `--packet-detector-id`, `--packet-detector-version`, `--volume-detector-id`, `--volume-detector-version`, `--volume-metric`, `--volume-threshold`, `--tcp-detector-id`, `--tcp-detector-version`, `--tcp-metric`, and `--tcp-threshold`. Metric choices are the existing enum values shown by `--help`. Count/byte and TCP thresholds become integers; rate thresholds become floats. The existing configuration models validate their values. Timeout is a positive integer microsecond duration representable by `timedelta`. Detector metadata and session identity must be nonblank. TCP settings are always explicit, even for a UDP-only input; applicability remains owned by the pipeline. PCAP provenance retains its existing `local-pcap` default, and no path-derived identity is introduced.

### JSON result

Successful execution writes one compact ASCII-escaped JSON object followed by a newline. Its only root fields are `packet_findings` and `flow_findings`, both arrays. They retain pipeline order and duplicates, with no sorting or correlation. Each finding has exactly the existing five field names: `detector_id`, `detector_version`, `decision`, `raw_evidence`, and `security_interpretation`. Enum members use their existing values. `raw_evidence` is an explicit presentation projection, not a lossless serialization of the nested analytical object graph:

- Packet evidence: `captured_at`, `capture_source`, `link_type`, `captured_length`, `original_length`, `protocol`, `failure_classification`, and `failure_description`.
- Both flow evidence types: `capture_session_id`, `sequence_number`, `closure_reason`, `identity`, `first_captured_at`, `last_captured_at`, `selected_metric`, `threshold`, `observed_value`, `comparison_operator`, `total_packet_count`, `forward_packet_count`, and `reverse_packet_count`.
- Volume evidence additionally includes `captured_byte_total` and `original_byte_total`.
- Flow `identity` contains `ip_version`, `source_address`, `destination_address`, `source_port`, `destination_port`, and `protocol`. Addresses are lowercase hexadecimal encodings of the canonical packed bytes for presentation only; the domain identity remains packed bytes.

Capture times use ISO 8601 with six fractional digits and the retained UTC offset. Missing metadata, failure fields, and unavailable rate measurements use JSON `null`; integers and floats retain their model values. Nonfinite JSON numbers are prohibited. The projection reads semantic evidence only and excludes packet bytes, full packet models, complete feature snapshots, object representations, and any generated host/process/time/path metadata. Explicit caller-supplied identifiers are preserved as supplied. Findings, configurations, formulas, and decision meanings are unchanged.

### Exit behavior

| Condition | Behavior |
| --- | --- |
| Pipeline and serialization succeed | Return/exit 0; one JSON result on stdout, empty stderr. MATCH and NOT_EVALUABLE findings do not change this status. |
| `--help` | argparse exits 0 with help text; no acquisition. |
| Invalid/missing arguments or invalid configuration | argparse exits 2 with usage/error text on stderr; no acquisition. |
| Pipeline raises `CaptureError` | Return/exit 1; exactly `{"error":"capture_error"}` plus newline on stderr; empty stdout. Exception details and source paths are not printed. |
| Other pipeline, serialization, or output exception | Propagate unchanged from `main()`; normal uncaught Python failure when invoked as a module, with no synthetic success result or retry. |

The JSON string is fully prepared before writing stdout; pipeline/serialization failure publishes no partial result. Output-stream failures follow Python stream behavior and are not given rollback guarantees. Standard tracebacks for unexpected exceptions are not JSON and may include normal Python source locations. Structured packet-analysis failures remain findings and do not become capture errors. Successful unsupported-transport analyses and decreasing admitted-flow timestamps retain existing pipeline errors. Decreasing timestamps for observations that never enter flow state remain in packet-finding order.

Equivalent PCAP observations and configuration produce equivalent output; no execution history or cache is retained. The CLI does not load the PCAP itself, manage source startup/cleanup, decode packets, extract features, invoke individual detectors, or build flow state. It serializes the pipeline's existing in-memory result, so memory still grows with retained findings. No live capture, PCAPNG, reassembly, application parsing, ML, storage, alerting, or correlation is introduced.

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


## Detection result evaluation

[detection_evaluation.py](detection_evaluation.py) exposes `evaluate_detection_result(actual, expected)`. It consumes an already-produced `DetectionPipelineResult` and an immutable `ExpectedDetectionResult`, returning a frozen `DetectionEvaluationResult`. This is an explicit in-memory comparison API. It executes no acquisition, analysis, flow observation, feature extraction, detector, session, pipeline, or CLI. The existing CLI JSON and pipeline contracts are unchanged.

`ExpectedDetectionResult(packet_expectations, flow_expectations)` requires two tuples of `ExpectedDetection(identity, positive)` values. The boolean is mandatory: `True` requires an actual `MATCH`; `False` requires an actual `NO_MATCH`. Expectations must be independently supplied, never inferred from missing results. No attack labels or dataset format are defined.

### Stable matching identity

The two frozen identity types preserve packet/flow separation:

- `PacketDetectionIdentity(configuration, packet_index, captured_at, capture_source, link_type, captured_length, original_length)` uses the existing packet-integrity configuration, the zero-based position in `DetectionPipelineResult.packet_findings`, and capture metadata. Its index is a position in the supplied result sequence, not a generated finding identifier. Duplicate observations at different positions remain distinct. Missing link type and original length remain `None`; UTC timestamps remain unchanged.
- `FlowDetectionIdentity(configuration, window_key, flow_identity, first_captured_at, last_captured_at)` reuses the existing typed detector configuration, `FlowObservationWindowKey`, canonical packed `FlowIdentity`, and window timestamps. Detector family, ID, version, selected metric, and threshold all participate through configuration equality. IPv4/IPv6 and TCP/UDP remain distinct through the existing flow identity. Counters, feature graphs, and raw packet bytes are not copied into identity.

`detection_identity(finding, packet_index=...)` projects the packet identity from established evidence. Omit `packet_index` for flow findings. Callers can also construct identities directly from independently known metadata and configuration. The helper derives no expectation label and runs no detector. Decision, interpretation, failure description, and measured counters are deliberately excluded from identity so differing decisions about the same subject can be compared.

Packet evidence has no independent packet identifier or capture-session key. Consequently packet expectations are scoped to a caller-aligned result sequence and capture provenance. Reordering/removing earlier packet results changes later positions. Matching is not content authentication: it cannot distinguish substitutions with identical metadata at the same position without packet bytes, which this layer never reads. Callers must supply expectations for the corresponding input sequence. Flow session IDs and window keys likewise remain caller-established provenance, not globally unique identifiers. No cross-dataset matching or raw-byte fingerprint is claimed.

### Classification and audit records

`DetectionClassification` contains only `TRUE_POSITIVE`, `FALSE_POSITIVE`, `FALSE_NEGATIVE`, and `TRUE_NEGATIVE`. The exact existing detector decision remains available on each retained finding. `NOT_EVALUABLE` is neither positive nor negative and never satisfies an expectation.

| Explicit expectation | Actual MATCH | Actual NO_MATCH | Actual NOT_EVALUABLE | No corresponding result |
| --- | --- | --- | --- | --- |
| Positive | TP | FN | FN, retaining NOT_EVALUABLE | FN |
| Negative | FP | TN | Unclassified, retaining NOT_EVALUABLE | Unclassified, missing result |
| None | FP | Unclassified | Unclassified, retaining NOT_EVALUABLE | No entry |

An FN records failure to obtain the required MATCH, not a claim that the detector evaluated a negative. Later reporting can distinguish an unevaluable FN from an evaluated NO_MATCH or missing result using the retained finding and decision. `classification=None` means no binary classification is justified; it is not a TN. In particular a missing negative never earns credit.

Each `DetectionEvaluationEntry` contains `classification`, `expectation_index`, the exact `expectation`, `actual_index`, and the exact `finding`. An absent side and its index are both `None`. Indices refer to the corresponding packet or flow input tuple. `DetectionEvaluationResult.packet_evaluations` and `.flow_evaluations` are immutable tuples: one entry for every actual finding in original order, followed by entries for unmatched expectations in expectation order. No sorting, deduplication, or input mutation occurs. Findings and their original evidence remain attached for auditing, without reconstruction.

Matching is one-to-one and multiplicity-sensitive. For each channel, expectations in input order first consume the earliest unassigned same-identity finding with the required decision. A second pass associates remaining expectations with opposite binary decisions; a final pass associates remaining NOT_EVALUABLE findings. Extra MATCH findings are FP; extra NO_MATCH/NOT_EVALUABLE findings remain unclassified. Duplicate positive expectations require separate MATCH results; duplicate negatives require separate NO_MATCH results. Contradictory positive and negative labels for the same identity are rejected with `ValueError`, rather than interpreted as implicit occurrence labels. Packet-position identities disambiguate packet occurrences explicitly; repeated flow identities use the documented multiplicity rule.

Public constructors reject wrong types, mutable collections, invalid identity metadata, inconsistent audit entries, and mixed channels using `TypeError` or `ValueError`. Evaluation is synchronous and deterministic; exceptions propagate without retries or partial returned results. All working assignments are local to one call. The evaluator retains references to supplied immutable evidence but never reads raw packet bytes or creates execution state.

Evaluation does not calculate metrics. The separate [metrics boundary](#detection-evaluation-metrics) consumes its completed classifications. Benchmarking, dataset ingestion, experiment tracking, ML, persistence, correlation, alerting, and a CLI evaluation mode remain unimplemented.


## Explicit ground truth

[ground_truth.py](ground_truth.py) adds three frozen/value contracts through the application exports:

- `GroundTruthPolarity` has `POSITIVE` (the target is externally expected to be present) and `NEGATIVE` (explicitly absent/non-detected). These are truth assertions, not detector decisions.
- `GroundTruthRecord(target, polarity)` requires an existing `PacketDetectionIdentity` or `FlowDetectionIdentity` and an explicit `GroundTruthPolarity` member.
- `GroundTruth(packet_records, flow_records)` holds two ordered tuples of those records, validating the target domain of each tuple.

No record for a target means **unlabeled**, never negative. Empty tuples express no supplied truth. Omitting polarity from a record is an error; there is no default label. NOT_EVALUABLE remains a detector result, not a truth polarity. Ground truth introduces no attack classification or probabilistic label.

Targets reuse Commit #31's identity contracts without changing them. Packet targets retain their position in the corresponding packet-result sequence, capture metadata, and packet-integrity configuration. They remain family-neutral and require caller-aligned provenance; they cannot distinguish content substitutions with identical metadata at the same position. No packet-content fingerprint or additional IP-family field is introduced. Flow targets retain the canonical packed IPv4/IPv6 TCP/UDP identity, existing window key, timestamps, and applicable detector configuration. Existing detector IDs, versions, and flow metric/threshold values scope the target being labeled; these immutable configuration references are not detector execution state. Truth contains no actual finding, decision, observed counter, feature snapshot, or analytical evidence graph.

Construct targets directly from externally supplied metadata and the existing configuration/identity constructors. Ground-truth construction neither derives an identity from a finding nor infers a label from detector output or absence. Existing target/configuration constructors remain responsible for their field validation; this module validates only record types, explicit polarity, tuple types, domains, and label consistency. It does not normalize or reinterpret permitted metadata.

A collection permits exactly one truth record per target. Repeated same-polarity targets raise `ValueError` identifying a duplicate; opposite polarities for the same target raise `ValueError` identifying a contradiction, in either order. Equal independently constructed targets and reversed endpoints that canonicalize to the same flow identity obey the same rule. Distinct packet positions, windows, flow identities, or detector configurations remain distinct targets. This uniqueness rule is specific to externally supplied truth; it does not change the multiplicity-sensitive evaluation expectations established in Commit #31.

Collections must be exact tuples of exact `GroundTruthRecord` values. Lists, dictionaries, missing targets, invalid polarity types, and unsupported record types raise `TypeError`; wrong-domain records raise `ValueError`. Records, targets, and configurations are retained by reference without copying or mutation. Input order is preserved without sorting or deduplication. Validation uses only local temporary state and performs no capture, packet access, parsing, feature extraction, detector execution, evaluation, filesystem/network access, or CLI invocation.

Ground truth describes what is externally asserted to be true. `DetectionPipelineResult` describes what the detectors produced. Evaluation compares results with explicit expectations. A future explicit adapter may translate truth into those expectations; this commit adds no conversion, automatic discovery, evaluator overload, pipeline wiring, or CLI/JSON changes. Metrics, datasets, annotation formats, loaders, benchmarking, experiment tracking, ML, storage, correlation, and alerting remain outside this contract.


## Detection evaluation metrics

[detection_metrics.py](detection_metrics.py) exposes `calculate_detection_metrics(result)`, accepting exactly an existing `DetectionEvaluationResult`. It returns a frozen `DetectionEvaluationMetrics` with separate `packet_metrics` and `flow_metrics`, each a frozen `DetectionMetrics`. The channels are never pooled or matched again.

Each channel exposes exact nonnegative integer `true_positives`, `false_positives`, `false_negatives`, `true_negatives`, and `unclassified_count`. Every supplied classification entry contributes once, including duplicates. `classification=None` contributes only to `unclassified_count`. That count describes unclassified entries, not a particular detector decision or a count of NOT_EVALUABLE cases.

The existing evaluation classification is authoritative. An FN remains FN even when the associated finding is NOT_EVALUABLE. Metrics never inspect findings or expectations to reinterpret that classification. The evaluation result has no independent unevaluable count, so metrics expose none. Unclassified entries are excluded from every binary denominator; classified entries retain their established contribution. No evaluation field or matching behavior changes.

The numeric properties use standard Python floating-point division without rounding or smoothing:

| Property | Definition | Undefined (`None`) when |
| --- | --- | --- |
| `precision` | TP / (TP + FP) | TP + FP = 0 |
| `recall` | TP / (TP + FN) | TP + FN = 0 |
| `f1` | 2 × precision × recall / (precision + recall) | Either input is undefined, or their sum is zero |
| `accuracy` | (TP + TN) / (TP + FP + FN + TN) | No binary classifications exist |

A defined `0.0` remains distinct from `None`. In particular, TP=0 with FP>0 and FN>0 yields zero precision and recall but undefined F1 under the stated harmonic-mean definition. TP=8, FP=2, FN=4, TN=86 yields precision 8/10, recall 8/12, F1 from those two ratios, and accuracy 94/100. Counts stay integers regardless of size; metric values are numbers, not formatted strings.

`DetectionMetrics` accepts four required counts and an optional `unclassified_count` defaulting to zero. Count types must be exactly `int`, excluding booleans; wrong types raise `TypeError`, and negative counts raise `ValueError`. `DetectionEvaluationMetrics` requires exact `DetectionMetrics` values for both channels. Aggregation relies on the existing evaluation result's validated immutable entries.

Calculation uses only local aggregation state and does not mutate inputs, reorder entries, infer truth, construct ground truth, rerun evaluation, or execute any capture, analysis, features, detectors, pipeline, or CLI. Ground truth remains external truth; evaluation compares actual results with explicit expectations; metrics aggregate the completed classifications. Ground-truth adaptation, reporting, benchmarking, datasets, and experiment tracking remain separate future work. No CLI JSON change is introduced.
