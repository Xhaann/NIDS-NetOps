# Architecture

## Scope and implementation posture

NIDS-NetOps provides an offline deterministic detection and evaluation system for research on explicit packet and flow predicates. Its purpose is to preserve the relationship between observations, measurements, decisions, and independently supplied expectations. It does not establish real-world attack-detection effectiveness beyond the input and ground truth under evaluation.

The implementation is a synchronous Python application using standard-library contracts. Capture and flow managers own bounded execution lifecycles; immutable values carry observations, configurations, findings, and results. Collections preserve their documented order. There is no service topology, database, live capture backend, or production deployment contract.

## Current ownership and data flow

| Package | Implemented responsibility |
| --- | --- |
| [capture](../src/capture/README.md) | Source lifecycle, packet observations, ordered ingestion, iterable and classic PCAP sources. |
| [analysis](../src/analysis/README.md) | Protocol decoding/validation, flow identity and observation windows, raw statistics, typed feature extraction and feature-contract provenance. |
| [detection](../src/detection/README.md) | Packet-integrity and flow threshold predicates, detector configuration/version references, evidence, and the common finding. |
| [application](../src/application/README.md) | Composition, evaluation, truth/dataset/experiment contracts, metrics, reporting representation, benchmarks, diagnostics, and CLI adaptation. |
| [ml](../src/ml/README.md) | Explicit immutable numerical projection of existing feature snapshots for future model inputs. |
| [research](../src/research/README.md) | Immutable examples associating existing projections with explicitly supplied research truth, and ordered research datasets, independently of detector/evaluation targets. |

The principal path is:

```text
Local classic PCAP -> PcapPacketSource -> consume / run_capture_execution
                                           |
                                    PacketObservation
                                           |
                                    analyze_packet_outcome
                                           |
                                    PacketAnalysisOutcome
                                      /              \
                     packet detection              successful analysis
                           |                         flow admission
                           |                         FlowObservationWindow
                           |                         closed-window extraction
                           |                         FlowFeatureSnapshot
                           |                         .feature_contract
                           |                         closed-flow detection
                           \                          /
                            DetectionPipelineResult
                                      |
Explicit GroundTruth -> expectations -> evaluate_detection_result
                                      |
                            DetectionEvaluationResult
                                      |
                            calculate_detection_metrics
                                      |
                            DetectionEvaluationMetrics
                                      |
                               EvaluationReport
```

`run_detection_stream()` composes capture, analysis, and the two detection paths through `DetectionSession`, delivering individual findings to synchronous packet and flow consumers. `run_detection_pipeline()` collects those same findings into `DetectionPipelineResult`; it is a function, not a `DetectionPipeline` class. `run_end_to_end_validation()` composes that collecting pipeline with explicit truth-to-expectation conversion, evaluation, metrics, and report construction. The diagram describes the collecting path and retained information; a feature-contract projection is not another processing stage, and ground truth does not originate from detector output.

`run_performance_benchmark()` can measure a caller-bound invocation of this path or another existing public operation. `diagnose_error()` can describe an exception at a caller's catch boundary. Neither automatically follows every pipeline run. Datasets, experiments, and configuration provide explicit context; they do not execute merely because they are constructed.

## Capture and packet analysis

`PacketSource` defines startup, ordered iteration, and cleanup. `consume()` calls `start()`, delivers observations synchronously, and attempts `stop()` in `finally`, including after startup failure. Consumer exceptions stop further acquisition. `PacketObservation` retains immutable raw bytes, capture time/source, link type, and captured/original lengths without protocol interpretation.

`PcapPacketSource` reads local regular files in classic PCAP 2.4 format, supporting both byte orders and microsecond/nanosecond timestamp formats. It preserves record order and supplied lengths/link code, rejects malformed or truncated records, and maps timestamps to UTC; sub-microsecond nanosecond precision is truncated to Python datetime resolution. Sources cannot be restarted: repeatable runs require fresh instances. PCAP loading is not dataset loading or evidence storage. `IterablePacketSource` accepts supplied byte records but timestamps acquisition with the current UTC clock; it is not a deterministic timestamp replay source.

`analyze_packet()` delegates to protocol decoders and checksum validators. `analyze_packet_outcome()` calls it once and preserves either the exact successful analysis or a recognized failure with no partial analysis. Its classifications are `STRUCTURAL_FAILURE`, `UNSUPPORTED`, `INCOMPLETE`, and `INTEGRITY_FAILURE`. Explicit checksum mismatches become integrity failures; IPv4 UDP checksum omission is not treated as a mismatch. Unrecognized exceptions propagate. `run_capture_execution()` delivers both successful and failed outcomes without filtering them.

### Protocol coverage and admission

| Family or boundary | Current behavior and limits |
| --- | --- |
| Ethernet II | Packet analysis requires `LinkType(1)` and dispatches IPv4/IPv6 EtherTypes. Other link formats and VLAN decoding are not implemented. |
| IPv4 | Header/declared-length validation, TCP/UDP/ICMPv4 structural decoding, IPv4 and supported transport checksum validation. Unknown IP protocols retain network-layer analysis without a transport model. |
| IPv6 | Fixed 40-byte header and declared payload bounds; packed 16-byte addresses. Zero Payload Length is literal; jumbogram interpretation is absent. |
| IPv6 extension headers | Bounded traversal of Hop-by-Hop Options (0), Routing (43), Destination Options (60), and Fragment (44), retaining order, bytes, offsets, and Next Header links. Option bodies/routing semantics are not interpreted. AH/ESP are not parsed; No Next Header (59) terminates traversal. |
| IPv6 TCP/UDP | Existing transport models decode at the validated terminal boundary, without IPv6 checksum validation. No application semantics or general reassembly; separate LDAP and bounded directional stream observation use decoded TCP payloads. |
| IPv6 fragments | Packet-local offset, M flag, identification, and reserved fields are retained. No buffering, reassembly, cross-packet correlation, or fragmentation-attack detection. |
| ICMPv6 | Common four-byte Type/Code/Checksum header and opaque body, only for unfragmented or whole-datagram fragment context. No checksum validation, subtype/embedded-packet parsing, or Neighbor Discovery. |
| Flow admission | Decoded IPv4/IPv6 TCP and UDP only. ICMPv4/ICMPv6 and unsupported upper-layer analyses are not flow inputs. |

Transport decoding requires an initial fragment. For IPv6 non-first fragments, extension traversal stops at the Fragment Header and packet analysis retains fragmentation information with no TCP/UDP model. Following fragment bytes remain opaque even when the retained Next Header names a supported extension. An offset-zero fragment can supply TCP only if its header is available; UDP requires its complete declared datagram in the represented bytes. Whole-datagram Fragment Headers remain visible and are not replaced with synthetic reassembly. IPv4 non-initial TCP/UDP/ICMP fragments retain decoder rejection through the outcome contract. These are packet-local rules, not completeness guarantees across a capture.

Protocol analysis and flow admission have different domains. A failed analysis outcome produces a packet finding and no flow observation. A successful analysis without supported transport reaches the existing flow-identity error in the pipeline; it is not silently skipped. Consequently, packet-analysis support for ICMPv6 or non-first IPv6 fragments does not imply successful complete flow-pipeline execution for those inputs.

## Flow observation and features

`FlowIdentity` canonicalizes packed address/port endpoints for bidirectional IPv4/IPv6 TCP/UDP identity. Direction follows canonical endpoints, not inferred client/server roles. `FlowStateCoordinator` accumulates total/directional counts, lengths, timestamps, packet-size and inter-arrival statistics. TCP-control state counts observed flags and selected combinations per direction; UDP retains no TCP-control state. This is not a TCP handshake/connection state machine.

`FlowObservationWindowManager` separates repeated windows using an explicit capture-session ID and sequence number. Admitted timestamps must be nondecreasing. Inactivity is checked when another observation for the same flow arrives: a gap greater than or equal to the configured timeout closes the prior window before creating the next. It is not a wall-clock timer or global expiration sweep. End-of-capture closes remaining windows in creation-sequence order. TCP FIN/RST flags do not close windows. The standalone `run_flow_observation_session()` emits closed windows without detection and retains its direct `analyze_packet()` exception behavior.

The manager's positive integer `max_active_windows` defaults to 1,024. New identities at capacity close the least recently observed window for `CAPACITY`, using creation sequence to break capture-timestamp ties. The old state and actual packet timestamps pass through normal closure, LDAP finalization, feature extraction, and detection; the incoming identity starts a new window. Preparation or table-allocation failure preserves the prior active table, timestamp frontier, and sequence number. Capacity selection and candidate table replacement use `O(L)` work/temporary references for limit `L`; there is no second lifecycle or growing eviction history. Active state holds at most `L` windows with existing per-flow buffer bounds. Retained findings and caller-held windows remain outside this bound.

This closes the gap between bounded per-flow protocol state and previously unlimited distinct active identities. Same-flow inactivity checks cannot reclaim flows that never return, making a flow-count bound necessary for captures containing scans or many short conversations. Bounding the shared owner benefits every current and future flow observer without extending protocol parsing. Capacity can shorten observation horizons and change window-based threshold results; its reason remains explicit in existing evidence, and end-to-end reports retain the configured limit. Numerical feature definitions and detector predicates remain unchanged. A capacity closure is a resource boundary, not evidence of an attack or a completed transport connection.

`extract_flow_feature_snapshot()` composes existing numerical extractors without re-parsing bytes. `FlowFeatureSnapshot` stores these fields in their existing order:

1. `observation_window`
2. `flow_volume_features`
3. `packet_size_features`
4. `flow_duration_features`
5. `flow_rate_features`
6. `inter_arrival_features`
7. `directional_inter_arrival_features`

The snapshot retains its exact window and exposes coordinated state through it. Volume, packet-size, duration, rate, global inter-arrival, and directional inter-arrival formulas retain their own types and units. Zero duration makes `flow_rate_features` absent (`None`); insufficient directional intervals remain unavailable under the existing feature contracts. TCP-control statistics remain raw window state rather than an additional numerical feature family. IPv4 and IPv6 share the same extraction and optionality rules. Analysis permits provisional snapshots of active windows; detectors require closed windows.

`FlowFeatureSnapshot.feature_contract` projects the statically defined `FeatureContractVersion("flow-feature-snapshot", "1")`. It adds no stored feature field, ordering change, or alternate extractor. Snapshot equality remains based on the existing fields; callers cannot select a different contract for the current extractor. This is provenance, not a flattened ML vector, schema registry, or migration mechanism.

## ML feature projection

The separate path is `FlowFeatureSnapshot -> project_flow_features(snapshot) -> MLFeatureProjection`. It reads the six existing numerical families into 49 fixed, qualified columns, preserving exact integers, floats and unavailable `None` values without recomputation or preprocessing. It retains the canonical `FeatureContractVersion("flow-feature-snapshot", "1")` and rejects other versions. The [ML input contract](../src/ml/README.md) specifies every column and its canonical source. No second versioning scheme is introduced.

The projection retains no snapshot/window graph, raw TCP-control state, identity, timestamp, label, finding, decision or evaluation result. Active and closed snapshots are supported; callers must select the appropriate observation horizon for their research target. Later state cannot alter an earlier projection. Existing detection datasets and experiments describe labeled evaluation subjects and procedures rather than numerical inputs, so they are neither consumed nor modified. The deterministic pipeline does not invoke this boundary. Dataset loading, splitting, preprocessing, training, inference and MLOps remain deferred.

`ResearchExample(projection, ground_truth=None, observation_window=None)` separately retains an exact `MLFeatureProjection` and optional caller-supplied nonblank truth text. The [research contract](../src/research/README.md) defines no binary/attack vocabulary, detector identity, or conversion from evaluation truth. It preserves the projection's authoritative contract, names, values, and unavailable slots by reference. An optional exact closed `FlowObservationWindow` retains scoped observation context alongside the projection and participates in example equality. It is caller-declared association, not verified origin or an admission policy. Frozen examples have no generated identity or row position; callers own observation/truth association. This package belongs to experimental data representation rather than application evaluation or model implementation.

`ResearchDataset(examples)` accepts an exact list or tuple of exact `ResearchExample` objects and publishes immutable tuple membership in supplied order. Its sole field is `examples`; equality reflects their ordered values. Empty datasets and repeated equal examples are valid. Construction retains exact members without inspecting projections or truth, sorting, deduplicating, or invoking other layers. Caller list mutation cannot alter published membership. The research dataset is separate from `DetectionDataset` and `DetectionExperiment`; the deterministic detection branch does not invoke it.

## Detection and findings

`DetectionSession` retains explicit immutable detector configurations and delegates to `run_packet_detectors()` and `run_closed_flow_detectors()`. It has no retained execution history. The pipeline analyzes each observation once and extracts one snapshot per delivered closed window. Within each window, detector order is volume first, then TCP control for TCP only. TCP requires a TCP-control configuration; UDP does not invoke that detector.

| Detector | Authoritative predicate |
| --- | --- |
| Packet integrity | Successful analysis gives `NO_MATCH`; structural/integrity failure gives `MATCH`; unsupported/incomplete analysis gives `NOT_EVALUABLE`. It does not establish maliciousness or complete protocol compliance. |
| Flow volume/rate | Compares one configured count, byte total, directional count, or rate against a nonnegative threshold using strict `>`; equality gives `NO_MATCH`. An unavailable selected rate gives `NOT_EVALUABLE`. |
| TCP control | Compares one configured raw directional TCP-control counter against a nonnegative integer threshold using strict `>`. It does not infer scanning, flooding, sessions, or attacks. |

The common frozen `DetectionFinding` has exactly five stored fields: `detector_id`, `detector_version`, `decision`, `raw_evidence`, and `security_interpretation`. The family-specific decision, interpretation, evidence, and configuration remain attached; normalization does not introduce security scores or finding IDs. `DetectionPipelineResult` retains separate packet and flow finding tuples, preserving observation order and window-closure/detector order respectively. There is no combined chronological sort, deduplication, alert state, incident lifecycle, or response action.

Failures propagate without retries or a partial returned pipeline result. Source cleanup and flow finalization retain their existing guarantees and Python exception precedence; finalization may deliver previously admitted windows after a source failure. A packet-detector or packet-consumer failure suppresses subsequent feature/detector work during finalization, and a failed downstream consumer is not called again. Previously executed effects are not rolled back. The collecting pipeline's results are retained in memory and can grow with input size.

### Output delivery and retention

The [incremental application boundary](../src/application/README.md#incremental-detection-finding-delivery) addresses mandatory pipeline accumulation after active flow state was bounded. Closed-window consumers already existed, but they did not provide the packet and closed-flow detection path without retaining every finding. A format-only exporter would still require removing that upstream accumulation. `run_detection_stream()` supplies two required synchronous finding callbacks and returns `None`; the existing pipeline is its collecting adapter, so both paths share one capture, admission, detector, and finalization lifecycle.

Packet findings are delivered before that observation's admission and resulting capacity/inactivity closures. Window findings follow closure order, with volume before TCP control; a complete detector batch is built before any finding in it is delivered. At capture end, source cleanup precedes sequence-ordered final windows. Callback failure can leave partial delivery and terminates further output without retry. Failed manager publication preserves active state but cannot retract an earlier packet callback. Fresh replay may repeat deliveries; there is no acknowledgement, persistence, or resume protocol.

Active analysis remains bounded by the configured window count and per-flow protocol limits. Output delivery retains the current detector batch and call frames, plus existing bounded finalization windows, rather than a history of findings or packet payloads. Caller-owned sources, retained findings/windows, and exception tracebacks can still retain arbitrarily many objects. Rich finding evidence is unchanged and may include packet or stream bytes through existing references. The CLI and end-to-end reporting APIs still use the collecting result and retain its memory cost. Neither delivery mode writes persistent archives; LDAP metadata serialization remains separately owned by its existing exporter. No stream-specific protocol, research projection, detector, or archival schema is introduced.


## LDAP observation boundary

The [LDAP foundation](../src/analysis/README.md#ldap-protocol-observations) observes bounded BER message envelopes through `PacketAnalysis.ldap` and accumulates optional immutable `LDAPFlowStatistics` in `CoordinatedFlowState`. `FlowFeatureSnapshot.ldap_statistics` exposes that same aggregate without changing numerical features, detector predicates, or research projections. Existing TCP parsing, flow admission, and publication ownership remain authoritative for both IP families.

Automatic candidate selection uses TCP port 389 plus a leading SEQUENCE tag, excluding port 636. Multiple envelopes in one payload are separated by declared BER lengths. Packet-local split observations remain incomplete. The incremental layer uses the same BER parser to consume complete envelopes from contiguous directional bytes and retain an incomplete suffix; packet-local counts remain observation counts. Malformed/unsupported observations do not become packet-analysis failures or security findings. Operation and control contents, encrypted LDAP, and LDAP-specific attack detection remain outside scope.

## Directional TCP payload continuity

The [bounded stream contract](../src/analysis/README.md#bounded-directional-tcp-stream-observation) is an analysis component published atomically in `CoordinatedFlowState.tcp_stream_state`. It reuses canonical flow identity/direction and decoded TCP payload/sequence values. Independent forward/reverse prefixes append only contiguous bytes, suppress identical contained retransmissions, and stop on gaps, unresolved overlaps, ambiguous ordering, incomplete fragments, capacity limits, or observed control boundaries. It creates no parallel flow owner or lifecycle.

Each direction retains at most 64 KiB with no segment history, reordering queue, or gap repair. A consumption cursor allows already-framed bytes to be reclaimed when an append needs space, preserving unconsumed suffixes and avoiding repeated parsing of emitted messages. Retained history supports existing retransmission comparisons; overlap into evicted history remains unavailable. LDAP shares this buffer and retains only the latest message batch plus cumulative counts, not an unbounded message history. Unavailable continuation is explicit and never silently resumes within the window. Existing finalization and publication-failure guarantees apply to the bytes and sequence frontier together. Numerical features and detection remain unchanged; retained windows, including those associated with research examples, now also retain bounded application bytes. The optional `CoordinatedFlowState.ldap_stream_state` frames port-389 candidates independently in each direction. It publishes newly completed message batches, absolute byte boundaries, cumulative framing counts, and pending status together with the exact consumed TCP state. Malformed boundaries stop without resynchronization; unsupported messages advance only when their complete bounded envelope is known. Existing packet-local LDAP statistics and detectors are unchanged.

## LDAP request/response association

[Bounded correlation](../src/analysis/README.md#bounded-ldap-requestresponse-correlation) consumes the incremental framer's new message batches after TCP continuity is established. `CoordinatedFlowState.ldap_correlation_state` retains the exact framing source, up to 128 outstanding direction/ID keys, the latest event batch, and cumulative counters. Only compatible complete opposite-direction messages associate; multiple outstanding IDs do not imply FIFO response order. Reuse before resolution is ambiguous, unsupported messages are non-correlatable, and unmatched responses are never assigned invented requests. Stream loss or capacity exhaustion disables further association within the window.

Correlation uses the existing prepare/commit boundary. The closed window's `ldap_correlation_state` property exposes a finalized immutable projection with pending requests unresolved, preserving the original admitted state and completed/unmatched observations. Message IDs have no cross-flow or cross-window scope. No LDAP body decoding, payload buffer, attack finding, numerical feature, or detector/evaluation change is introduced.

[Request termination summaries](../src/analysis/README.md#bounded-ldap-request-termination-summaries) extend existing correlation records with an immutable request reference, response count, termination status, and optional terminal-response reference. The existing pending dictionary carries counts across batches; its match/retirement decisions update summaries without another ID map or history scan. Non-terminal Search responses leave the request pending, terminal events emit completed summaries, and finalization preserves unresolved or ambiguous state. The existing pending-key and event-batch bounds remain authoritative; no response list, payload copy, feature projection, or security interpretation is added.

## Ground truth and evaluation

`GroundTruthRecord(target, polarity)` labels an existing `PacketDetectionIdentity` or `FlowDetectionIdentity` with explicit `POSITIVE` or `NEGATIVE` truth. `GroundTruth` holds separate ordered packet/flow record tuples and rejects duplicate or contradictory targets. Missing truth is unlabeled, never negative. Labels must be supplied independently of actual detector decisions.

`evaluate_detection_result(actual, expected)` consumes `DetectionPipelineResult` and `ExpectedDetectionResult`, not packets or a source. Expectations contain typed identities and explicit positive/negative booleans. `run_end_to_end_validation()` explicitly converts supplied truth records to these expectations without inferring labels.

Packet matching uses detector configuration, position in the packet-result sequence, and capture metadata. Flow matching uses detector configuration, window key, canonical flow identity, and first/last timestamps. Configuration equality includes detector ID/version and applicable metric/threshold. Packet/flow channels never satisfy one another. `detection_identity()` projects existing evidence identity without establishing truth. Packet identity is caller-aligned provenance, not content authentication: identical metadata at the same position cannot distinguish substituted bytes.

Matching is deterministic, one-to-one, and multiplicity-sensitive. Required decisions are matched first, then opposite binary decisions, then `NOT_EVALUABLE`. Output entries retain actual-finding order, followed by unmatched expectations in expectation order. Unlike truth records, same-polarity duplicate expectations are permitted and require separate findings; contradictory expectations are rejected.

| Expectation | MATCH | NO_MATCH | NOT_EVALUABLE | Missing result |
| --- | --- | --- | --- | --- |
| Positive | TP | FN | FN with original decision retained | FN |
| Negative | FP | TN | Unclassified | Unclassified |
| None | FP | Unclassified | Unclassified | No entry |

An FN means the required MATCH was not obtained, including when evaluation of the detector predicate was unavailable. It does not convert `NOT_EVALUABLE` into `NO_MATCH`. `classification=None` is unclassified, not TN. `DetectionEvaluationEntry` retains both sides and their indices; the original decision remains observable. These rules describe the existing contract and do not certify real-world security effectiveness.

### Incremental evaluation

`IncrementalDetectionEvaluator` is a downstream application consumer of the existing finding stream. It receives explicit `ExpectedDetectionResult` input and emits existing `DetectionEvaluationEntry` objects through separate synchronous packet and flow consumers. It invokes no upstream stage. Ground truth remains externally supplied and adapted through the established record-to-expectation mapping. The collecting evaluator retains its signature and validation/result behavior, sharing its original indexed/fallback three-phase assignment routine with the incremental boundary.

Historical matching prefers the expected decision over an opposite or unavailable decision before preserving actual finding order. Immediate irrevocable classification of every flow arrival is therefore impossible: a late preferred finding can change an earlier assignment. Packet positions distinguish occurrences, allowing immediate packet evaluation. Settled flow prefixes are delivered immediately; the first ambiguous flow entry defers the remaining flow suffix until explicit successful `finish()`. Missing expectations are emitted only at finalization, in expectation order. Per-channel output is exactly equivalent to collecting evaluation, including duplicates, unclassified entries, and positive `NOT_EVALUABLE` false negatives.

The evaluator retains `O(E + B)` state for `E` expectations and `B` deferred flow findings. Ordinary expectation indexing avoids rescanning the full expectation collection for each settled arrival; deferred matching reuses the collecting algorithm. The equality fallback for custom addresses remains supported. `B` can grow to the entire remaining flow stream when exact matching and ordering require end-of-input knowledge. The boundary avoids mandatory retention of the complete detection result, not every possible history dependency. Original findings are referenced without copying packet or LDAP contents. Caller buffers and retained exceptions remain caller-owned.

An upstream failure must lead the caller to `abort()` rather than `finish()`; the evaluator owns no source and cannot infer successful capture completion. Evaluation or consumer failure is terminal and clears deferred references without retry, retracting prior effects, or claiming completion. Successful finalization is idempotent. Metrics may consume the evaluation entries directly through `IncrementalDetectionMetrics`; reporting/end-to-end validation remain collecting APIs. Neither detection streaming nor incremental evaluation performs persistent archival. See the [application contract](../src/application/README.md#incremental-detection-evaluation) for ordering, failure, and resource details.

## Metrics and reporting

`calculate_detection_metrics()` aggregates completed classifications once into `DetectionEvaluationMetrics`, with separate packet and flow `DetectionMetrics`. Each includes TP, FP, FN, TN, and `unclassified_count`. Unclassified entries are excluded from binary denominators; this count is not a count of unevaluable findings. No finding decisions are reinterpreted.

Precision is TP/(TP+FP), recall is TP/(TP+FN), and accuracy is (TP+TN)/(TP+FP+FN+TN). F1 uses `2 * precision * recall / (precision + recall)`. Undefined denominators yield `None`; F1 is also `None` when either input is undefined or their sum is zero. Values are neither smoothed nor prematurely rounded.

`IncrementalDetectionMetrics` consumes existing evaluation entries through synchronous `record_packet()` and `record_flow()` calls. It shares the collecting metric function's canonical counting logic and returns the existing immutable `DetectionEvaluationMetrics` from `finish()`. Each entry contributes its classification once, including duplicates; indices and decisions are not reinterpreted. Packet and flow counts remain independent. Channel validation reads only existing identity/evidence type discriminants. No upstream execution, matching, ground truth, metric definition, or serialization is added.

Metrics retain ten arbitrary-precision integer counters and, after completion, the immutable result. The number of counters is constant and no entries or evidence graphs are retained. Exact integer storage grows as `O(log(N + 1))` bits for `N` entries, rather than retaining `O(N)` objects. Incremental evaluation's separate expectation/deferred-suffix state and caller retention remain unchanged. This is not a claim that the entire pipeline uses constant memory.

The caller finishes evaluation successfully before finishing metrics. Successful metric finalization is idempotent and returns the same result; later recording is rejected. Invalid inputs, wrong channels, counting failures, and result-construction failures propagate and make the metrics consumer terminal without a completed result or retry. On upstream/evaluation failure the caller aborts metrics, preventing partial counts from being finalized. The consumer cannot infer external completion. No persistent metric archival, CLI streaming, report streaming, queues, or separate capture lifecycle is introduced. See the [incremental metrics contract](../src/application/README.md#incremental-detection-metrics).

`EvaluationReport` retains a standalone evaluation result with optional metrics, or an existing benchmark result with per-case metrics. Benchmark reports reject additional top-level metrics. Optional experiment and detection-configuration references remain explicit context; a benchmark report with an experiment requires equal datasets. Dataset identity/count is exposed where supplied, not inferred from findings. The report does not evaluate, recalculate, reconcile supplied metrics, execute, render, serialize, or persist anything. The CLI's separate finding JSON projection is not an evaluation-report renderer.

## Datasets, experiments, and configuration

`DetectionDataset(name, cases)` defines an immutable exact tuple of `DetectionDatasetCase(case_id, target, ground_truth=None)`. Names and IDs are explicit nonblank strings; case IDs are unique across the dataset. Empty datasets are valid. Explicit order is retained across mixed packet/flow cases, and distinct case IDs may share a target. Optional truth must refer to an equal target; absence stays unlabeled.

Targets preserve detector configuration/version and packet or flow provenance. They do not contain raw captures, loaders, aggregate system configuration, or a feature-contract field. Feature provenance remains attached to snapshots in detection evidence; it must not be inferred from a dataset name or detector version. Datasets describe evaluation subjects, not executable packet workloads.

`DetectionExperiment(experiment_id, dataset, benchmark_operation_id, benchmark_operation_version)` describes the intended dataset and procedure. It retains no results, callable, arbitrary parameter map, or runtime state. Its operation ID/version must identify the caller-maintained procedure and change when that procedure changes. No registry resolves it, and no automatic mechanism verifies external code or inputs. Complete value equality includes dataset contents/order, not only names.

| Contract | Meaning |
| --- | --- |
| `PacketIntegrityConfiguration`, `FlowVolumeThresholdConfiguration`, `TCPControlThresholdConfiguration` | Detector ID/version plus detector-owned metric/threshold settings where applicable. |
| `DetectionConfiguration` | Existing packet/volume configurations, optional TCP-control configuration, positive inactivity timeout, and positive active-window limit (default 1,024). No generated configuration ID; capture-session ID remains a separate execution input. |
| `DetectorVersion` | Exact nonblank detector ID and version strings; read-only `version_reference` projections on detector configurations/findings preserve their stored values. |
| `FeatureContractVersion` | Exact nonblank feature-contract ID/version, distinct from detector implementation identity. |
| Detection benchmark inputs | Explicit dataset and callable. There is no separate `DetectionBenchmarkConfiguration` class. |
| `PerformanceBenchmarkConfiguration` | Operation ID/version, positive measured count, nonnegative warmup count, and optional dataset/experiment/detection-configuration context. |

Version strings are not normalized or forced into SemVer. Neither version implies the other. Configuration management is representation/validation, not file loading, merging, discovery, or persistence. There is no Git-derived identity, package-version discovery, detector registry, feature registry, or version migration.

## End-to-end system validation

`run_end_to_end_validation()` receives a source, `DetectionConfiguration`, explicit capture-session ID, `GroundTruth`, and optional experiment. It constructs the existing session, invokes the authoritative pipeline once, evaluates once, calculates metrics once, and constructs `EvaluationReport` from those exact outputs.

The frozen `EndToEndValidationResult` retains `pipeline_result`, `ground_truth`, and `report`. Capture observations, analysis outcomes, windows, and snapshots remain reachable through retained finding evidence rather than duplicated buffers. The report retains evaluation, metrics, and configuration. Empty input remains valid; failures propagate without a fabricated successful result. Completion means the components composed successfully, not that every expectation matched or every dataset case was executed. Optional experiment context is a declaration, not an execution attestation.

The integration tests exercise IPv4/IPv6 TCP/UDP, extensions/fragments, inactivity and ordering, expected analysis failures, and fail-fast execution guards. Validation delegates to the existing parsing, feature, detector, evaluation, metric, and reporting implementations; it is not a second implementation of them.

### Streaming end-to-end evaluation

`run_streaming_evaluation()` provides the application composition previously left to callers: source → `run_detection_stream()` → `IncrementalDetectionEvaluator` → `IncrementalDetectionMetrics` → completed `DetectionEvaluationMetrics`. It accepts the same configuration, capture-session ID, and external truth conventions as collecting validation. Ordered truth-to-expectation conversion and session construction reuse those contracts; all processing delegates to the established components.

The function returns metrics only after the detection stream, evaluator finalization, and metric finalization succeed in that order. Upstream failures abort metrics and the unfinished evaluator without attempting completion or retry. A metric-finalization failure leaves the completed evaluator completed and returns no metrics. Capture/flow cleanup and exception precedence stay with the existing owners. No findings or evaluation entries are collected, and no report is constructed.

The memory guarantee combines bounded active flow state, the evaluator's `O(E + B)` expectation/deferred-suffix state, and fixed-count incremental metric state. The evaluator's suffix can grow with input; caller-retained sources and tracebacks have separate costs. This is not constant memory for the entire operation. The metrics-only convenience API has no extra output consumers; the lower-level synchronous APIs remain available when callers need individual outputs. Existing collecting validation, CLI, and reporting remain compatible. No new detection, matching, metric, protocol, persistence, or research/ML behavior is introduced. See the [application contract](../src/application/README.md#streaming-end-to-end-evaluation).

## Detection and performance benchmarking

`run_detection_benchmark(dataset, operation)` invokes `operation(case)` once for each exact dataset case in order. Each returned `DetectionBenchmarkCaseResult` must refer to an equal case and may retain optional evaluation/metrics. `DetectionBenchmarkResult` validates one ordered result per case and exposes dataset name and case count. Empty datasets invoke no operation. The caller owns payload relevance and any detection/evaluation inside the operation; the framework does not fill in missing results or aggregate metrics. Exceptions stop execution without retries, skipped cases, or a partial returned summary.

`run_performance_benchmark(operation, *, configuration, clock=None)` measures a synchronous zero-argument callable. Callers can bind pipeline or end-to-end execution, existing packet/closed-flow session methods, or dataset benchmarking. This introduces no internal profiling stages or independent detector calls. A repeatable PCAP operation must create a fresh source each time; setup included inside the callable is part of the measured boundary. Lazy or asynchronous work is not automatically drained or awaited.

Warmup count defaults to zero and is explicit. Warmups call the operation without reading the measurement clock. Each measured execution reads the clock, calls the operation once, then reads the clock again. The default is `time.perf_counter`; injected clocks must return finite exact floats in nondecreasing order. Successful execution makes exactly warmup + measured operation calls and twice the measured count of clock calls. Operation failure propagates immediately without a closing clock read or fabricated successful summary. No hidden retries, repetitions, or warmups occur.

`PerformanceBenchmarkResult` retains configuration and an ordered tuple of finite nonnegative elapsed seconds, one per measured execution. Read-only minimum, maximum, total (`math.fsum`), mean, and median derive from those observations without sorting the stored tuple or rounding it. Callable outputs are not retained. Dataset identity/count is projected from explicit dataset or experiment context; experiment operation ID/version and any separately supplied dataset must agree. Context does not prove the callable performed the declared workload.

Timing observations are environment-sensitive. Controlled-clock tests verify methodology, not real-speed guarantees. This is elapsed measurement, not optimization, CPU/memory monitoring, function-level profiling, throughput reporting, or persisted benchmark history.

## Operational diagnostics

`OperationalDiagnostic(category, operation_id, message, context=())` is an immutable in-memory description. `diagnose_error(error, *, operation_id, message, context=())` classifies a supplied `Exception`; it does not execute or catch an operation. The caller supplies exact nonblank operation/message strings and remains responsible for appropriate, non-sensitive content and exception propagation.

`OperationalErrorCategory` conservatively recognizes exact existing exception types:

- `CAPTURE_FAILURE`: `CaptureError`.
- `PACKET_ANALYSIS_FAILURE`: known packet-analysis, decoder, and checksum-validation exception contracts.
- `FLOW_PROCESSING_FAILURE`: known identity, tracking, statistics, coordination, window, and feature exception contracts.
- `DETECTION_FAILURE`: known detector and finding-contract exceptions.
- `UNCLASSIFIED_FAILURE`: all other exceptions, including generic built-ins and unrecognized subclasses.

Classification describes a known exception domain, not a root cause or security meaning. Generic evaluation/configuration errors cannot reliably identify their subsystem from type alone and remain unclassified. No cause-chain, message-text, traceback, Git, package, or environment inspection occurs. Arbitrary exception text is not copied automatically.

Optional context is an exact tuple of existing immutable `CaptureSource`, `FlowObservationWindowKey`, `DetectionConfiguration`, `DetectionDataset`, `DetectionExperiment`, `DetectorVersion`, or `FeatureContractVersion` objects. References, order, and duplicates are preserved. Raw packets, findings, snapshots, mappings, and arbitrary process state are not diagnostic context. No timestamp, generated ID, severity, or terminal/recoverable flag is invented.

A `PacketAnalysisOutcome` non-success is already an analytical result, not an exception accepted by this adapter. Detector decisions, evaluation classifications, and benchmark observations are not operational error categories. Diagnosis adds no timing, logging, telemetry, storage, network access, retry, or automatic pipeline hook. The original exception remains caller-owned; invalid diagnostic arguments can themselves raise validation errors.

## CLI and public API

The CLI is `PYTHONPATH=src python3 -B -m application`, with a local PCAP path and explicit required detector/session options. See the [tested command](../README.md#run-and-verify) and [CLI contract](../src/application/README.md#command-line-adapter). It executes detection once, emits ordered packet/flow finding JSON, exits 0 on successful output, exits 2 for argument/configuration errors, and returns 1 for handled `CaptureError`. Repeated settings, blank/NUL paths, and invalid arguments fail before acquisition. Help/usage formatting has a fixed width. The handled capture failure passes through `diagnose_error()` with a fixed message and retains its existing JSON error; no new exception family is caught. Other execution/output exceptions propagate. It provides no evaluation, report, benchmark, experiment, or diagnostic subcommand.

Stable application concepts are exported by [application/__init__.py](../src/application/__init__.py). Detector/version contracts belong to `detection`; feature/version contracts belong to `analysis`; source contracts belong to `capture`. CLI formatting and lifecycle helpers remain private. Module import does not start execution.

## Preserved boundaries and reproducibility

| Separate responsibilities | Reason |
| --- | --- |
| Packet analysis / detection | Structural interpretation and recognized analysis failures do not themselves establish a security finding. |
| Flow observation / detection | Lifecycle and raw accumulation remain independent of thresholds. |
| Features / detector logic | Numerical definitions are reusable and versioned independently of predicates. |
| Findings / evaluation | Actual decisions cannot establish their own ground truth. |
| Evaluation / reporting | Matching owns classifications; reports preserve completed information. |
| Dataset / benchmark execution | Cases are immutable data; only an explicit callable performs work. |
| Benchmarking / detection semantics | Repetition does not change predicates or matching rules. |
| Performance / optimization | Elapsed observations do not replace algorithms or justify unimplemented speed claims. |
| Diagnostics / security findings | Operational failure descriptions are not attacks, alerts, or incidents. |
| Configuration / version identity | Settings, detector identity, and feature provenance answer different questions. |
| End-to-end validation / implementation logic | Integration verifies composition through authoritative operations. |

Reproducibility requires equivalent explicit observations, configuration, externally maintained procedure references, and ground truth. Capture order, closure order, feature fields, detector order, and evaluation/case order remain defined. Immutable results preserve values and references without shared mutable history. Detection introduces no randomness; benchmarks add only configured repetitions/warmups; diagnostics add no retries or execution. Local PCAP execution requires filesystem input but no network service or external runtime dependency. Benchmark state is not persisted. Capture-acquisition clocks and real elapsed timings are explicitly outside bit-for-bit reproducibility claims.

## Intentional limits and future work

There is no live interface capture, PCAPNG, reassembly, complete protocol stack, general application semantics, TCP connection state, signature catalog, behavioral baseline, autonomous response, blocking, firewall integration, SIEM integration, threat intelligence, credential protection, endpoint response, or remediation. Findings do not implement severity, confidence, risk, correlation, alerting, or production SOC functionality.

The research branch provides explicit feature projection, examples, and immutable ordered datasets only: no dataset loading, splitting, preprocessing, training, inference, model registry, feature store, drift detection, model serving, or experiment tracking infrastructure is implemented. Future research must use stable feature/evaluation contracts and separate empirical claims from deterministic predicate behavior. No future capability is implied by the current version objects.

The `enrichment`, `events`, `storage`, and `integrations` responsibility notes describe possible future ownership, not runtime implementations. Further operational resource limits, deployment, and any future subsystem require separate scoped work. This baseline finalizes documentation without adding functionality.

## DNS protocol analysis foundation

`PacketAnalysis.dns` exposes a lazy, immutable DNS observation from the established IPv4/IPv6 UDP payload boundary on source or destination port 53. The port-independent `analyze_dns_message()` also accepts an already-delimited message supplied by a caller. TCP DNS framing is not yet provided; TCP stream ownership stays unchanged. DNS observation does not participate in detection or change packet validity, flow admission, publication, evaluation, or metrics.

Header, ordered question/record envelopes and binary names are parsed with explicit message, entry, expanded-name and pointer limits. Ordinary malformed/truncated input produces a status and complete parsed prefix; unsupported encodings, operational limits and pointers into opaque RDATA are explicit stops. RDATA remains opaque, including unknown and EDNS types. This establishes structural observations for protocol consumers without inferring attacks. See the [DNS contract](../src/analysis/README.md#dns-message-observation) for exact limits and compression behavior. Parser state is bounded per message; caller-retained outputs remain caller-owned. No persistent archival or parallel capture/flow lifecycle is introduced.

## DNS transaction observation

The UDP `FlowStateCoordinator` consumes `PacketAnalysis.dns` into bounded immutable DNS correlation state as part of existing atomic admission. State is local to the existing flow window; matching uses canonical flow endpoints, opposite request/response directions, DNS ID, opcode and ordered questions. No DNS parsing, flow identity, detector or lifecycle is duplicated.

The 128-key pending limit follows the LDAP conservative saturation convention: overflow explicitly closes outstanding requests and disables matching until a new window. Request-ID reuse remains ambiguous; unmatched responses and unresolved requests are observations, not findings. Closed-window construction finalizes DNS before publication and removes pending state. Capture timestamps supply exact matched durations. Latest batches and final snapshots remain bounded; caller-retained histories have separate costs. See the [DNS transaction contract](../src/analysis/README.md#bounded-dns-transaction-correlation) for matching limitations, closure, retry and ownership semantics. Automatic TCP DNS framing and DNS-specific detection remain outside this boundary.

## DNS transaction-derived statistics

Finalized `DNSTransactionObservation` values feed `DNSTransactionStatistics` through the existing coordinator and closed-window publication path. This extends the coordinator's established protocol-specific state boundary, already used by LDAP, without modifying DNS parsing or correlation. The generic `FlowFeatureSnapshot` groups describe protocol-independent packet/flow quantities; DNS transaction statuses and message counts belong in the protocol-specific state. Its version-1 feature schema and numerical projection remain unchanged.

Each active update contributes its non-PENDING observations once. Closure aggregates only the newly appended terminal observations after correlation's retained output prefix, so the final snapshot does not count the last completed batch twice. Finalization and feature publication participate in the same atomic flow lifecycle, including inactivity, segmentation, session end and capacity eviction. Features store no identity or lifecycle of their own; their enclosing flow owns scope and release. IPv4 and IPv6 use the same aggregation path. Standalone callers can consume already-delimited TCP transaction observations; automatic TCP framing is still unavailable.

The immutable result stores status counts, section totals, two fixed 16-bin distributions and exact integer latency aggregates with an exact rational mean. It stores no packets, messages, transaction history, names or RDATA. Eleven scalar slots and 32 distribution bins bound the number of retained values; exact integer storage grows with counter bit length. See the [statistics contract](../src/analysis/README.md#dns-transaction-derived-statistics) for accounting and empty-state semantics. No DNS detector, alert, evaluation rule, LDAP behavior or ML pipeline is added.

## DNS query-name structure

The same terminal-observation delivery path feeds `DNSQueryNameStatistics` from each contributing `DNSMessageObservation.questions` sequence. The parser owns decoded `DNSName.labels` and `expanded_length`; correlation owns transaction association; the new reducer owns only structural aggregation. The coordinator's existing protocol-specific boundary is extended with `dns_query_name_statistics`. The existing transaction-statistics model, generic snapshot version 1 and 49-value ML projection remain unchanged. Existing flow accumulators are specialized models, not a shared exact name-statistics helper; no generic feature framework is introduced.

Question accounting matches DNS transaction statistics: a MATCHED observation contributes request and response question sections as separate observed messages; other terminal observations contribute only their observed message. Answers, authorities, additionals and RDATA are excluded. Closure uses the existing newly terminal suffix, avoiding repeated aggregation of correlation's retained completed prefix. Aggregation and publication remain atomic under the existing flow/window lifecycle, including eviction and explicit retry after failure.

Names use expanded wire octets, including label-length octets and the single terminal root octet, excluding compression-pointer encoding. Labels use their parsed payload octets. Root has expanded length one and zero labels; case and binary bytes remain unchanged. Fifteen scalar slots hold counts and extrema, with exact rational means computed on access. No source object, identity or name history is retained. Storage grows only with integer bit lengths and the existing number of owners/caller-retained results. IPv4 and IPv6 share the UDP DNS path; externally delimited TCP transactions can use the reducer, but automatic DNS TCP framing remains unavailable. See the [query-name contract](../src/analysis/README.md#dns-query-name-structural-statistics) for empty-state and byte-class semantics. These structural observations do not detect tunneling, DGA activity or any other attack.

## DNS resource-record structure

Terminal `DNSTransactionObservation` → contributing `DNSMessageObservation` → parsed answer/authority/additional sequences → `DNSResourceRecordStatistics`. This DNS-specific boundary reads only section membership, `rdlength`, `record_type` and `record_class`. Questions are excluded; RDATA and owner names are never decoded or inspected. MATCHED contributes both observed messages; other terminal observations contribute their own message. Repeated records remain separate observations. Parsing, correlation, transaction statistics and query-name semantics retain their existing boundaries.

Six scalar fields store section counts and RDATA byte-length totals/extrema. Total record count is the sum of section counts; the mean is an exact `Fraction`, computed on access. Two fixed 256-by-256 immutable tuple distributions cover every unsigned 16-bit type/class code, including unknown codes. Unchanged blocks can be shared without retaining earlier aggregates. This bounds structural state to 131,072 bin positions and six scalars per result; integer bit lengths and caller-retained snapshots have separate storage costs. Empty counts/totals/bins are zero and empty extrema/mean are `None`; observed zero-byte RDATA has measured extrema and mean zero.

The additive coordinator field and window property use the same atomic preparation/publication and newly terminal closure suffix as the previous DNS statistics. Failed aggregation leaves the prior state retryable, publication retry cannot duplicate records, and existing eviction/readmission and source release remain authoritative. The result retains no packet, message, transaction, resource record, RDATA, name or flow. IPv4/IPv6 share the established UDP path; already-delimited TCP observations can use the reducer, while automatic TCP framing remains unavailable. Invalid DNS contributes no records, including valid prefixes of invalid messages. See the [resource-record contract](../src/analysis/README.md#dns-resource-record-structural-statistics). Generic version 1, the 49-value ML projection, LDAP, detectors and evaluation are unchanged. This layer does not detect attacks.

## DNS message flags

Terminal `DNSTransactionObservation` → contributing complete `DNSMessageObservation` → semantic `DNSHeader` control properties → `DNSMessageFlagStatistics`. This extends the existing DNS-specific statistics boundary. It counts messages and independent QR, AA, TC, RD, RA, AD and CD contributions, with QR-clear queries derived by subtraction. MATCHED contributes request and response once each; UNMATCHED, AMBIGUOUS and UNRESOLVED contribute only their observed message. Header properties determine the measurements independently of transaction status, questions or records.

The parser preserves a 16-bit flag word and now exposes QR, AA, TC, RD, RA, AD and CD through semantic properties. The existing Feature 17 reducer now consumes all seven semantic properties. Feature 18 remains the sole flag-decoding boundary; the reducer never reads the raw word. The original message/response/truncated fields keep their order and semantics; five new zero-default counters follow them. Opcode and response-code statistics remain solely in Feature 14. Eight exact integer fields give fixed scalar shape, with all-zero empty state; integer bit lengths may grow. The frozen result retains no source graph, flags word or timestamp.

The additive coordinator field and window property join the existing atomic preparation/publication and newly terminal closure suffix. Failed aggregation leaves prior state intact, publication retry cannot duplicate messages, and repeated finalization is idempotent. Existing flow identity, capacity, inactivity/explicit/session closure and readmission own the state. IPv4/IPv6 use the established UDP path; already-delimited TCP transactions can use the reducer, while automatic DNS-over-TCP framing remains unavailable. Invalid messages contribute nothing, even if a valid header or section prefix was parsed. Features 14–16 and 18, generic version 1, the 49-value ML projection, LDAP, detectors, evaluation and metrics remain unchanged. See the [flag statistics contract](../src/analysis/README.md#dns-message-flag-statistics). These observations do not detect attacks.

## Semantic DNS header control flags

The existing frozen, parser-created `DNSHeader` owns control-flag decoding. Its `is_response` (QR) and `truncated` (TC) properties remain unchanged; `authoritative_answer` (AA), `recursion_desired` (RD), `recursion_available` (RA), `authenticated_data` (AD) and `checking_disabled` (CD) follow the same computed-boolean pattern. Consumers use these properties instead of interpreting the raw flag word. No new header abstraction, stored fields, constructor path, flow state or source references are introduced.

The full unsigned 16-bit `flags` value, including every historical Z position, remains intact. AD and CD expose their assigned positions; the remaining reserved position is preserved without new semantics or rejection. A set property reports the observed wire bit, independently of message role or parser status; it does not perform DNSSEC validation or attack detection. Existing malformed/incomplete/unsupported observations keep their previous behavior, including partial headers. UDP over IPv4/IPv6 uses the same parser; already-delimited TCP messages can use it, while automatic DNS-over-TCP framing remains unavailable. Features 12–17, generic version 1 and the 49-value ML projection remain compatible. See the [header contract](../src/analysis/README.md#semantic-dns-header-control-flags).
