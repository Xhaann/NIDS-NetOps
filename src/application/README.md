# Application composition

The `application` package composes capture, analysis, and detection, and owns the evaluation, metrics, reporting, dataset, experiment, configuration, benchmark, and operational-diagnostic contracts documented below. It does not redefine packet decoding, flow accumulation, feature formulas, or detector predicates. See the [architecture reference](../../docs/architecture.md) for the current data flow and cross-layer limits; public exports are defined in [__init__.py](__init__.py).

## Command-line adapter

[cli.py](cli.py) provides `main(argv=None) -> int`; [__main__.py](__main__.py) exposes it through `PYTHONPATH=src python3 -B -m application`. Importing either module performs no execution. The CLI adds no package-level exports; serialization helpers stay private. The adapter accepts one authoritative local classic PCAP path, constructs `PcapPacketSource`, and invokes `run_detection_pipeline()` exactly once. Capture acquisition, execution, analysis, flow lifecycle, feature derivation, and detector orchestration remain delegated to their existing owners.

All detector configuration is explicit because the domain models define no canonical defaults. Each setting must appear exactly once; duplicates are argument errors even when their values agree. Both separate and `--option=value` forms remain supported, without option abbreviation. Help and usage use a fixed width of 100 columns rather than discovering terminal width. Required options are `--capture-session-id`, `--inactivity-timeout-microseconds`, `--packet-detector-id`, `--packet-detector-version`, `--volume-detector-id`, `--volume-detector-version`, `--volume-metric`, `--volume-threshold`, `--tcp-detector-id`, `--tcp-detector-version`, `--tcp-metric`, and `--tcp-threshold`. Metric choices are the existing enum values shown by `--help`. Count/byte and TCP thresholds become integers; rate thresholds become floats. The existing configuration models validate their values. Timeout is a positive integer microsecond duration representable by `timedelta`. Detector metadata and session identity must be nonblank. TCP settings are always explicit, even for a UDP-only input; applicability remains owned by the pipeline. PCAP provenance retains its existing `local-pcap` default, and no path-derived identity is introduced.

The CLI rejects blank paths and embedded NUL characters before constructing a source, while preserving every permitted path string exactly. It does not pre-open, stat, repair, or copy input files. Missing paths, directories, unreadable files, unsupported PCAP formats, and corrupt records retain the capture reader's `CaptureError` behavior. An empty valid PCAP succeeds; a zero-byte file lacks a PCAP header and fails. Integer/volume-number conversion errors use fixed explanations without echoing rejected numeric text. Domain models still validate numeric ranges and detector identities. Argparse may include explicitly supplied tokens in other argument errors; this is not a general redaction facility.

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
| Invalid/missing/repeated arguments, blank/NUL path, or invalid configuration | argparse exits 2 with usage/error text on stderr; no acquisition. |
| Pipeline raises `CaptureError` | Return/exit 1; exactly `{"error":"capture_error"}` plus newline on stderr; empty stdout. Exception details and source paths are not printed. The existing diagnostic adapter supplies the fixed presentation message. |
| Other pipeline, serialization, or output exception | Propagate unchanged from `main()`; normal uncaught Python failure when invoked as a module, with no synthetic success result or retry. |

At the existing `CaptureError` handler, the CLI calls `diagnose_error()` once with operation ID `detection-pipeline`, message `capture_error`, and empty context. The diagnostic message is presented under the existing JSON `error` key; no diagnostic fields are added to successful finding output. Classification remains owned by `OperationalErrorCategory`, including conservative unclassified handling of unrecognized subclasses. No exception text or cause is read, no additional exception family is caught, and output/diagnostic-construction errors propagate.

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

Evaluation does not calculate metrics. The separate [metrics boundary](#detection-evaluation-metrics) consumes its completed classifications. Detection and performance benchmarking are separate APIs described below. Dataset ingestion, experiment tracking, ML, persistence, correlation, alerting, and a CLI evaluation mode remain unimplemented.


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

Ground truth describes what is externally asserted to be true. `DetectionPipelineResult` describes what the detectors produced. Evaluation compares results with explicit expectations. `run_end_to_end_validation()` explicitly converts supplied truth records into those expectations before invoking the existing evaluation API. Ground-truth construction itself performs no conversion, inference, or execution. Metrics, datasets, annotation formats, loaders, benchmarking, experiment tracking, ML, storage, correlation, and alerting remain outside this contract.


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

Calculation uses only local aggregation state and does not mutate inputs, reorder entries, infer truth, construct ground truth, rerun evaluation, or execute any capture, analysis, features, detectors, pipeline, or CLI. Ground truth remains external truth; evaluation compares actual results with explicit expectations; metrics aggregate the completed classifications. Ground-truth adaptation is explicit in `run_end_to_end_validation()`; reporting and performance benchmarking have separate contracts below. Dataset loading and experiment tracking remain unimplemented. No CLI JSON change is introduced.


## Detection dataset representation

[detection_dataset.py](detection_dataset.py) exposes two frozen data contracts:

- `DetectionDatasetCase(case_id, target, ground_truth=None)` associates an explicit case ID with an existing `PacketDetectionIdentity` or `FlowDetectionIdentity` and an optional existing `GroundTruthRecord`.
- `DetectionDataset(name, cases)` associates an explicit dataset name with an ordered tuple of cases. An empty tuple is valid and retains the dataset name.

Names and case IDs must be exact nonblank strings. Wrong types raise `TypeError`; empty or whitespace-only strings raise `ValueError`. Permitted strings are retained exactly without trimming, case folding, or automatic generation. They are caller-supplied logical identifiers, not file locations, global IDs, timestamps, or execution counters. No filesystem interpretation or identity discovery occurs.

Case IDs are unique within one dataset, across both domains. Duplicate IDs raise `ValueError`, even for equal cases or different targets or labels. No case is overwritten or deduplicated. The same case ID may occur in independent datasets. Distinct IDs may retain equal targets; each case is an independent association, and construction does not merge their truth or convert the cases into a single `GroundTruth` collection. Existing ground-truth collection uniqueness rules remain unchanged.

The case target carries its existing explicit type, so packet and flow domains remain distinguishable in a mixed ordered dataset. Packet targets retain the established position/provenance limitation and require caller-aligned result sequences; a case ID is not a packet-content fingerprint or an alternative evaluation matching key. Flow targets retain existing canonical IPv4/IPv6 endpoints, transport, window, timestamps, and detector configuration. Dataset construction neither derives nor alters these identities.

A supplied `ground_truth` must be exactly a `GroundTruthRecord` whose target equals the case target under existing value equality. Equal independently constructed targets are accepted. Other targets, including cross-domain targets, raise `ValueError`; unsupported target or truth types raise `TypeError`. Truth is retained without reconstruction. Its existing positive or negative polarity is unchanged. `None` means unlabeled, never negative. No actual finding, pipeline result, evaluation result, or metric is needed to construct a case.

`cases` must be exactly a tuple of exact `DetectionDatasetCase` values, following the existing immutable collection convention. Lists, mappings, sets, iterators, and malformed elements raise `TypeError` without coercion or mutation. Callers can explicitly snapshot a list with `tuple(cases)` before construction. Order and multiplicity of distinct case IDs are preserved. The dataset retains the tuple, cases, targets, and truth by reference; their immutable contracts prevent exposed mutable state. All validation state is local to construction.

Dataset representation organizes evaluation cases. Ground truth supplies external truth; evaluation compares actual detection results with explicit expectations; metrics aggregate resulting classifications. Dataset construction performs none of those operations and does not establish truth. It reads no packets, files, network, or clock; invokes no capture, analysis, features, detection, pipeline, evaluation, or metrics; and creates no random IDs or caches. Ground-truth conversion, dataset loading, PCAP management, reporting, benchmarking, experiment execution, and ML remain outside this boundary. Existing execution APIs and CLI JSON are unchanged.


## Deterministic benchmark execution

[detection_benchmark.py](detection_benchmark.py) exposes `run_detection_benchmark(dataset, operation)`. The input must be exactly a `DetectionDataset`; `operation` must be callable with one `DetectionDatasetCase` argument and return exactly a `DetectionBenchmarkCaseResult`. Ordinary functions and callable objects use the same synchronous path. There is no operation registry or discovery mechanism.

`DetectionBenchmarkCaseResult(case, evaluation=None, metrics=None)` is frozen and retains an exact `DetectionDatasetCase`, an optional exact `DetectionEvaluationResult`, and optional exact `DetectionEvaluationMetrics`. The latter is the existing grouping of packet and flow `DetectionMetrics`. Payloads are independently optional: neither, either, or both may be supplied. `None` means not supplied, not an evaluation classification or a failed operation. The framework does not compute missing payloads, inspect their entries or numeric values, or reconcile their consistency. Their correctness and relevance to the case remain the explicit operation's responsibility.

The framework passes each exact source case to the operation once, preserving dataset order across packet and flow cases. Before proceeding to the next case, it validates that the returned result has the supported type and that its complete case value equals the source case, including ID, typed target, and optional truth. Equal independently constructed cases are accepted; mismatched IDs, targets, domains, or truth are rejected. It retains the exact returned case result and payload references without rebuilding them. Existing target identity and ground-truth semantics remain unchanged; unlabeled cases stay unlabeled.

The frozen `DetectionBenchmarkResult(dataset, case_results)` retains the exact source dataset and an ordered tuple of case results. `dataset_name` exposes the unchanged dataset name, and `total_case_count` is the exact tuple length. Construction requires exactly one corresponding result per dataset case in dataset order. Mutable collections, unsupported values, missing/extra results, and incorrect associations are rejected rather than repaired. Dataset identity and case uniqueness remain owned by `DetectionDataset`. Distinct case IDs with equal targets still execute separately. Empty datasets produce an empty result tuple and count zero without invoking the operation; the operation must still be callable.

Type violations raise `TypeError`; count or case-association violations raise `ValueError`. An operation exception propagates unchanged immediately. There are no retries, skipped cases, synthetic failure records, or returned partial benchmark results. Earlier callable side effects are not rolled back. A later explicit invocation has independent framework state. Result construction itself executes nothing.

The framework owns only ordered invocation, association validation, and immutable result collection. Dataset representation owns cases; ground truth supplies external truth; evaluation compares supplied results with expectations; metrics aggregate existing classifications. A caller may explicitly invoke those existing APIs inside its operation. The framework never invokes them internally, converts truth to expectations, inspects findings/evidence, or recalculates classifications or ratios. It introduces no capture or pipeline wrapper. Deterministic callable outputs over equivalent datasets produce equal ordered benchmark results; determinism and side effects inside the supplied operation remain caller-owned.

No timing, performance measurement, concurrency, filesystem/network access, randomness, hidden caches, dataset loading, reporting, experiment metadata, or ML is introduced. Performance measurement is provided separately by the performance boundary below; reproducible experiment tracking remains a future concern. Existing capture, detection, evaluation, metrics, and CLI contracts are unchanged.


## Reproducible experiment definition

[detection_experiment.py](detection_experiment.py) exports the frozen `DetectionExperiment(experiment_id, dataset, benchmark_operation_id, benchmark_operation_version)` value. All four arguments are required. The dataset must be exactly an existing `DetectionDataset`; the three identity values must be exact nonblank strings. Wrong types raise `TypeError`, and empty or whitespace-only identities raise `ValueError`. Permitted strings remain unchanged without trimming, case folding, version parsing, path interpretation, or automatic ID generation.

The dataset is retained by reference, including its name, ordered cases, existing typed packet/flow targets, and explicit positive/negative or missing truth. No case or configuration is copied. Equality follows the complete frozen value: experiment ID, dataset contents and order, operation ID, and operation version all participate. Equivalent independent objects compare equal; reusing a dataset name for different cases does not make the definitions equal. Existing packet provenance limitations and flow/window identity semantics remain unchanged.

The benchmark-operation ID/version pair is an explicit caller-supplied reference to the intended operation, including the caller-defined evaluation procedure and any operation-specific inputs or settings. The pair must change when that declared procedure changes. It is not a callable, import path, executable binding, registry key lookup, generated fingerprint, or proof that external code and inputs are available. The definition neither inspects a callable nor verifies its implementation. Callers remain responsible for assigning stable references and preserving the corresponding external procedure. There is no automatic execution or resolution bridge to `run_detection_benchmark()`.

Detector IDs, versions, metrics, and thresholds already reside in immutable configurations on dataset targets and participate through dataset equality. They are retained without a second detector-configuration list. Evaluation and metrics currently expose fixed contracts rather than independent configuration/version objects; this definition introduces none. Feature-contract provenance exists on `FlowFeatureSnapshot.feature_contract`; dataset targets and experiment definitions contain no feature-contract field. It is not inferred from detector versions or the operation ID. The operation reference distinguishes caller-defined procedures without adding arbitrary parameter mappings, configuration management, detector version management, or feature version management.

Dataset representation defines cases. Benchmark execution invokes an explicit operation over those cases. An experiment describes the intended dataset and operation but contains no benchmark result, evaluation result, calculated metrics, finding, raw packet, execution timestamp, or runtime measurement. Construction and inspection perform no capture, analysis, detection, feature extraction, evaluation, metrics, benchmark execution, filesystem/network access, timing, randomness, or persistence. The only nested collection is the dataset's existing immutable case tuple; input values remain unchanged and no execution state is retained.

Experiment execution, tracking, result storage, dataset loading, and ML are not implemented. Configuration, detector/feature version references, reporting representation, and performance measurement are separate existing contracts; the experiment definition does not execute them. An experiment ID is an explicit logical label, not a globally generated identifier or stored run record. Existing benchmark, pipeline, evaluation, metrics, and CLI APIs remain unchanged.


## Deterministic configuration representation

`DetectionConfiguration(packet_configuration, flow_volume_configuration, inactivity_timeout, tcp_control_configuration=None)` is a frozen data-only composition of the existing `PacketIntegrityConfiguration`, `FlowVolumeThresholdConfiguration`, optional `TCPControlThresholdConfiguration`, and an exact positive `timedelta`. The timeout is included because it controls observation-window closure and therefore the semantic inputs to detection. It has no implicit default or rounding. Wrong reference/duration types raise `TypeError`; a nonpositive duration raises `ValueError`, consistent with the existing positive-duration requirement.

The configuration retains the exact supplied immutable values. Detector IDs, versions, selected metrics, and thresholds remain owned and validated by the existing detector configurations. No threshold fields, formulas, applicability rules, or detector order are duplicated. Optional TCP configuration mirrors `DetectionSession`: absence is representable for non-TCP workloads, but does not bypass the existing requirement for TCP-control configuration when a TCP closed flow is explicitly evaluated.

Value equality includes all four settings, using the existing nested value semantics. No separate configuration ID/version, collection, generated identity, or runtime state is needed. Capture source/path and capture-session identity remain per-execution inputs; they are not reusable system settings. Callers can explicitly supply these fields to existing session/pipeline APIs, whose interfaces and behavior remain unchanged. The configuration itself creates no session or window manager and exposes no execution method.

Datasets define evaluation cases and truth associations; benchmarks execute explicit operations over datasets; experiments describe a dataset and a declared operation. None of these contracts is modified or automatically connected to this configuration. Evaluation and metrics retain their fixed contracts. Configuration construction and inspection perform no capture, analysis, feature extraction, detection, evaluation, metrics, benchmark or experiment execution, external access, timing, randomness, or persistence.

Configuration management here means representation and validation only. Configuration-file/environment loading, discovery, registries, merging, and persistence are not implemented. The existing CLI parses explicit detector settings; `EvaluationReport` may retain a supplied `DetectionConfiguration` without executing it. Existing detector configurations now expose the [explicit detector version reference](../detection/README.md#explicit-detector-version-references) through `version_reference`; their stored ID/version strings and configuration equality remain unchanged. The [feature contract reference](../analysis/README.md#explicit-feature-contract-version) is static snapshot provenance, separate from these configurable detector settings. Configuration management itself introduces no version discovery or feature-contract version.


## Evaluation reporting representation

`EvaluationReport(result, metrics=None, experiment=None, configuration=None)` is a frozen application value for already-produced information. It introduces no report ID, entry model, or copied result collection. Its two supported result forms reuse existing contracts:

- An exact `DetectionEvaluationResult`, with optional exact `DetectionEvaluationMetrics`. `report.result` retains the packet/flow evaluation tuples; `report.metrics.packet_metrics` and `.flow_metrics`, when supplied, retain their exact existing `DetectionMetrics` objects. Absent metrics remain `None`, distinct from a supplied metrics object with mathematically undefined values.
- An exact `DetectionBenchmarkResult`. Its dataset and ordered `case_results` already own case associations, optional evaluations, and optional packet/flow metrics. These remain accessible through `report.result`. Top-level metrics must be `None` in this form; supplying them raises `ValueError` because there is no authoritative cross-case aggregation contract.

`experiment` optionally retains an exact `DetectionExperiment`, including its explicit experiment ID, dataset, and declared benchmark-operation ID/version. `configuration` optionally retains an exact `DetectionConfiguration`. They are caller-declared context, not evidence that an experiment or configuration was executed. No benchmark ID exists in the current result contract, and reporting invents none. A benchmark report with an experiment requires full dataset value equality, including name, order, cases, and truth; a mismatch raises `ValueError`. Equivalent independent datasets are accepted without replacing either reference.

The read-only `dataset` property returns the benchmark's dataset when present, otherwise the explicit experiment's dataset, otherwise `None`. `dataset_case_count` returns the existing benchmark count or the declared experiment dataset's case count; without context it is `None`. An empty dataset has count zero. These are dataset case counts, not evaluation-entry counts. No independent dataset name/count fields can drift from their authoritative objects.

Wrong result, metrics, experiment, or configuration types, including subclasses, raise `TypeError`. Existing nested contracts remain responsible for their own validation, ordering, duplicate-case rules, and packet/flow separation. Reporting does not infer dataset provenance from findings or validate that supplied metrics were calculated from a supplied evaluation: that association remains caller-owned, as with benchmark operation outputs. It never reconciles classifications, recomputes metrics, or checks execution provenance by rerunning work.

Evaluation results remain authoritative matching records. Metrics retain TP/FP/FN/TN, unclassified counts, and existing derived-value/undefined semantics. Reading a metric property uses the original metrics contract; report construction and its properties never read or calculate precision, recall, F1, or accuracy. Missing truth remains unlabeled, and NOT_EVALUABLE behavior is preserved exactly, including existing positive-expectation FN classifications. No historical evaluation semantics are corrected here.

Detector versions remain on supplied configurations/findings. Feature-contract provenance remains on retained flow snapshots where already available; neither is discovered, flattened into a list, or inferred from the other. Findings/evidence, truth, dataset cases, benchmark outputs, and experiment definitions remain exact references. Frozen value equality includes all four report fields. Case, finding, evaluation, and packet/flow metric ordering are preserved without sorting, deduplication, or hidden state.

This is the reporting data contract only. Construction and inspection execute no capture, parsing, analysis, feature extraction, detectors, sessions, pipelines, evaluation, metrics, benchmarks, or experiments. They perform no rendering, serialization, file/network access, persistence, timing, randomness, automatic metadata discovery, or registry lookup. Existing CLI JSON output is unchanged.


## End-to-end system validation

`run_end_to_end_validation(source, *, configuration, capture_session_id, ground_truth, experiment=None)` composes the established pipeline with evaluation, metrics, and reporting. Supply an existing `PacketSource`, an exact `DetectionConfiguration`, and explicit `GroundTruth`. Local classic PCAP input uses `PcapPacketSource`; reproducibility requires equivalent ordered observations and a fresh source for each execution. PCAP timestamps remain input data. Sources that generate acquisition timestamps do not gain reproducibility from this wrapper.

Ground-truth packet and flow records are adapted explicitly, in their existing order, into `ExpectedDetectionResult`: POSITIVE becomes a positive expectation and NEGATIVE becomes a negative expectation, preserving exact target references. Missing records add no expectations. Callers supply targets independently, including existing packet index/time/source metadata and flow capture-session/window identity. The operation does not infer labels or targets from findings or automatically import truth from a dataset.

The operation constructs the existing `DetectionSession` from the supplied nested configurations, then calls `run_detection_pipeline`, `evaluate_detection_result`, `calculate_detection_metrics`, and `EvaluationReport` once each, in that order. Detection remains pipeline-owned, evaluation remains matching-owned, metrics remain calculation-owned, and the report retains the existing evaluation and metrics objects. No classification, NOT_EVALUABLE behavior, formula, feature, or detector is reimplemented.

Frozen `EndToEndValidationResult(pipeline_result, ground_truth, report)` retains these exact outputs. The report must contain a standalone evaluation, metrics, and configuration. Packet finding evidence retains capture observations and analysis outcomes; flow-volume finding evidence retains closed windows and feature snapshots, including their existing feature-contract provenance. No parallel observation buffers or feature copies are introduced. Existing packet, flow, finding, and evaluation order is preserved. Optional experiment context is passed unchanged to the report, making its declared dataset available without executing an experiment or benchmark or attesting that its cases were executed individually.

A returned result means the composition completed, not that all expectations passed: FP, FN, unclassified entries, and undefined metrics remain observable. The wrapper propagates failures without retries or partial success results and preserves the pipeline's existing source cleanup and flow-finalization behavior. Unsupported flow transports and non-initial IPv6 fragments retain their existing flow-admission exceptions; atomic IPv6 fragments retain transport admission. Structured packet-analysis failures remain packet findings where the existing pipeline permits completion.

Tests exercise real deterministic PCAP bytes through IPv4/IPv6 TCP/UDP, inactivity closure, directional features, packet integrity failures, explicit truth, and final reports. Execution guards verify one analysis per observation, one extraction per closed window, pipeline-owned detector calls, and one evaluation, metrics calculation, and report construction. This boundary introduces no capture/parser implementation, rendering, serialization, storage, networking, automatic metadata discovery, or performance measurement.


## Performance benchmarking

`run_performance_benchmark(operation, *, configuration, clock=None)` measures a synchronous, caller-supplied zero-argument operation. `PerformanceBenchmarkConfiguration(operation_id, operation_version, measured_executions, warmup_executions=0, dataset=None, experiment=None, detection_configuration=None)` declares the methodology and optional existing context. Identity/version are exact nonblank strings, preserved without normalization or discovery. Measured executions must be positive exact integers; warmups must be nonnegative exact integers. Booleans and coercible alternatives are rejected. Invalid configuration, operation, or clock references fail before warmups or measured calls.

Each warmup calls the operation once without reading the clock. Measured calls then run serially: start clock, operation, end clock. A successful run invokes the operation exactly `warmup_executions + measured_executions` times and reads the clock exactly twice per measured call. There are no implicit repetitions, retries, calibration runs, overhead subtraction, or concurrent calls. The interval includes the operation call and small timing-wrapper overhead; observation aggregation and measured-output disposal occur after the end reading. Warmup output disposal is also untimed. An operation's own side effects, setup, cleanup, retained outputs, and internal work remain its responsibility.

The production default is `time.perf_counter`, a monotonic high-resolution elapsed-time clock. An injected clock must return finite exact floats in seconds with a consistent origin and nondecreasing readings, including between repetitions. Negative origins and equal readings are valid. Invalid readings, reversed clocks, or nonfinite elapsed differences raise immediately. Real timings are environment-sensitive: deterministic methodology and controlled-clock equality do not imply identical measurements on real machines. Timings are not rounded, formatted, converted into throughput, or assigned machine-speed thresholds.

Frozen `PerformanceBenchmarkResult(configuration, elapsed_seconds)` retains the exact configuration and an ordered tuple of finite nonnegative float durations, one per measured execution. Zero duration is valid. Mutable collections and mismatched observation counts are rejected. Read-only `minimum_elapsed_seconds`, `maximum_elapsed_seconds`, `total_elapsed_seconds`, `mean_elapsed_seconds`, and `median_elapsed_seconds` derive from those observations. Total uses `math.fsum`; mean divides that total by the measured count. Median uses the standard-library median without reordering the stored observations. An unrepresentable total raises `OverflowError` rather than publishing an infinite summary. Equality includes configuration and ordered observations; no separate aggregate fields can drift from the raw measurements.

Dataset, experiment, and detection-configuration references must be exact existing value objects. If supplied together, dataset and experiment dataset must compare equal in full, and the experiment operation ID/version must match the declared measured operation. These are caller-declared associations, not executable bindings or automatic validation of a callable's implementation. Result `dataset` projects the explicit dataset, otherwise the experiment dataset, otherwise `None`; `dataset_case_count` is its existing case count, or `None` without context. Empty datasets retain zero cases, while a configured whole-dataset invocation is still measured. Case order, packet/flow targets, ground truth, detector configurations, and detector versions remain on their existing objects unchanged. Feature-contract provenance remains on the original feature snapshots; timing does not create, infer, copy, or rewrite it.

The operation can explicitly bind `run_detection_pipeline` or `run_end_to_end_validation`, `DetectionSession.run_packets` over prepared outcomes, `DetectionSession.run_closed_flows` over prepared snapshots, or `run_detection_benchmark(dataset, case_operation)`. One observation always means one call of the supplied operation: measuring a whole dataset is distinct from measuring a single case, and the declared operation identity must describe that scope. The performance layer never traverses cases, inspects findings, calls individual detectors, extracts features, evaluates results, or computes detection metrics independently.

For example, a caller can measure the existing dataset framework:

```python
configuration = PerformanceBenchmarkConfiguration(
    "dataset-evaluation", "1", measured_executions=5, warmup_executions=1,
    dataset=dataset,
)
result = run_performance_benchmark(
    lambda: run_detection_benchmark(dataset, case_operation),
    configuration=configuration,
)
```

The callable must complete its work synchronously; a returned iterator or awaitable is not consumed or awaited. Return values are not retained in the performance result or interpreted as success/failure classifications. A caller can retain authoritative outputs explicitly if needed. For complete PCAP runs, create a fresh `PcapPacketSource` inside each invocation; setup inside that callable is included in the measurement. Reusing an exhausted source preserves its existing error rather than triggering an automatic reset. The framework does not reset external state between repetitions or verify that the caller supplied equivalent workloads.

An operation or clock exception propagates unchanged, stops further work, and returns no partial success summary. Failed operations get no fabricated end reading or elapsed observation. Earlier caller side effects are not rolled back. Detection benchmarking remains ordered case execution; end-to-end validation remains composition of the existing system; performance benchmarking measures an explicitly selected boundary. No optimization, caching, detailed profiling, storage, serialization, network access, randomness, metadata discovery, registries, or ML/MLOps is introduced. Existing evaluation metrics and reporting semantics remain unchanged.


## Operational errors and diagnostics

`diagnose_error(error, *, operation_id, message, context=())` describes an already-caught `Exception`. It returns frozen `OperationalDiagnostic(category, operation_id, message, context)`. It does not invoke an operation, install a handler, wrap an exception, attach state to an exception, or return an execution result. Existing capture, pipeline, evaluation, and benchmark APIs already propagate failures; this passive boundary adds a diagnostic value without replacing that behavior. The caller remains responsible for propagating or handling the original exception according to its existing contract.

`OperationalErrorCategory` distinguishes five domains using exact existing exception types:

- `CAPTURE_FAILURE`: `CaptureError`.
- `PACKET_ANALYSIS_FAILURE`: existing packet-analysis/outcome, Ethernet/IP/transport/ICMP decoding, and checksum-validation exceptions.
- `FLOW_PROCESSING_FAILURE`: existing flow identity, direction, tracking, statistics, coordination, window, and feature-value exceptions.
- `DETECTION_FAILURE`: packet-integrity, flow-volume, TCP-control, and finding-contract exceptions.
- `UNCLASSIFIED_FAILURE`: other exceptions, including plain `TypeError`, `ValueError`, `OverflowError`, `RuntimeError`, and unrecognized subclasses.

These categories identify the domain of a known exception contract, not its root cause, security meaning, or recoverability. Evaluation and configuration validation commonly use generic built-in exceptions shared with programmer errors; diagnosis does not guess their origin from message text or call stacks. An explicit `operation_id` locates the caller's boundary while the generic failure remains unclassified. No classification is inferred from an exception's cause chain. Existing cleanup-error precedence and the original exception's type, arguments, traceback, cause, and context remain untouched and available to the caller.

Operation names and messages must be exact nonblank strings, preserved without normalization. The message must be explicitly supplied by the caller: arbitrary exception text, arguments, representations, tracebacks, packet bytes, paths, or environment state are never copied automatically. Callers should supply an appropriate explanation without sensitive content. No generated diagnostic ID, timestamp, exception object, operational handle, or security severity is stored.

Optional context must be an exact tuple of existing immutable `CaptureSource`, `FlowObservationWindowKey`, `DetectionConfiguration`, `DetectionDataset`, `DetectionExperiment`, `DetectorVersion`, or `FeatureContractVersion` objects. Exact references, order, and multiplicity are preserved, including duplicate references; empty context remains empty. Arbitrary text entries, mappings, mutable collections, findings, outcomes, snapshots, and raw packets are rejected. Context is caller-declared, not discovered or reconciled into new provenance. Nested contracts continue to own their own semantics. Diagnostic equality uses all four frozen fields.

A caller may diagnose a capture exception at its existing catch boundary and then re-raise it:

```python
try:
    result = run_detection_pipeline(source, detection_session=session,
                                    capture_session_id=capture_session_id,
                                    inactivity_timeout=inactivity_timeout)
except CaptureError as error:
    diagnostic = diagnose_error(error, operation_id="detection-pipeline",
                                message="Capture failed", context=(capture_source,))
    raise
```

The example executes the pipeline once. Diagnosis performs no capture, parsing, feature extraction, detection, evaluation, metric calculation, reporting, or benchmark execution. Invalid diagnostic arguments raise their own validation error; callers should supply valid explicit metadata when diagnosing a caught failure. The adapter itself never catches or suppresses an operation exception. Interrupts such as `KeyboardInterrupt` and `SystemExit` are outside its `Exception` input contract.

A `PacketAnalysisOutcome` already represents expected analysis non-success and retains its authoritative classification/description. It is not an operational exception and is not accepted by `diagnose_error`. Detection findings remain detector outputs; evaluation outcomes remain comparisons against explicit expectations. MATCH, NO_MATCH, NOT_EVALUABLE, TP/FP/FN/TN, and undefined/unclassified metrics retain their historical semantics. End-to-end validation continues to compose these systems; performance benchmarking continues to time only the configured operation, with unchanged counts and warmup policy. Diagnosis adds no clock reads or retries. If callers put diagnostic work inside a measured callable, that explicit work is part of the measured boundary.

No logging, telemetry, rendering, serialization, persistence, storage, network access, randomness, automatic metadata discovery, registries, optimization, or ML/MLOps is introduced. The CLI uses this adapter only at its existing handled `CaptureError` boundary, preserving its output and exception contract. Diagnostics describe failure; they do not fabricate partial or successful results, alerts, incidents, or attack classifications.
