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

`run_detection_pipeline()` composes capture, analysis, and the two detection paths through `DetectionSession`. It is a function, not a `DetectionPipeline` class. `run_end_to_end_validation()` composes that pipeline with explicit truth-to-expectation conversion, evaluation, metrics, and report construction. The diagram describes ownership and retained information; a feature-contract projection is not another processing stage, and ground truth does not originate from detector output.

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
| IPv6 TCP/UDP | Existing transport models decode at the validated terminal boundary, without IPv6 checksum validation. No application parsing or stream reconstruction. |
| IPv6 fragments | Packet-local offset, M flag, identification, and reserved fields are retained. No buffering, reassembly, cross-packet correlation, or fragmentation-attack detection. |
| ICMPv6 | Common four-byte Type/Code/Checksum header and opaque body, only for unfragmented or whole-datagram fragment context. No checksum validation, subtype/embedded-packet parsing, or Neighbor Discovery. |
| Flow admission | Decoded IPv4/IPv6 TCP and UDP only. ICMPv4/ICMPv6 and unsupported upper-layer analyses are not flow inputs. |

Transport decoding requires an initial fragment. For IPv6 non-first fragments, packet analysis retains fragmentation information with no TCP/UDP model. An offset-zero fragment can supply TCP only if its header is available; UDP requires its complete declared datagram in the represented bytes. Whole-datagram Fragment Headers remain visible and are not replaced with synthetic reassembly. IPv4 non-initial TCP/UDP/ICMP fragments retain decoder rejection through the outcome contract. These are packet-local rules, not completeness guarantees across a capture.

Protocol analysis and flow admission have different domains. A failed analysis outcome produces a packet finding and no flow observation. A successful analysis without supported transport reaches the existing flow-identity error in the pipeline; it is not silently skipped. Consequently, packet-analysis support for ICMPv6 or non-first IPv6 fragments does not imply successful complete flow-pipeline execution for those inputs.

## Flow observation and features

`FlowIdentity` canonicalizes packed address/port endpoints for bidirectional IPv4/IPv6 TCP/UDP identity. Direction follows canonical endpoints, not inferred client/server roles. `FlowStateCoordinator` accumulates total/directional counts, lengths, timestamps, packet-size and inter-arrival statistics. TCP-control state counts observed flags and selected combinations per direction; UDP retains no TCP-control state. This is not a TCP handshake/connection state machine.

`FlowObservationWindowManager` separates repeated windows using an explicit capture-session ID and sequence number. Admitted timestamps must be nondecreasing. Inactivity is checked when another observation for the same flow arrives: a gap greater than or equal to the configured timeout closes the prior window before creating the next. It is not a wall-clock timer or global expiration sweep. End-of-capture closes remaining windows in creation-sequence order. TCP FIN/RST flags do not close windows. The standalone `run_flow_observation_session()` emits closed windows without detection and retains its direct `analyze_packet()` exception behavior.

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

## Detection and findings

`DetectionSession` retains explicit immutable detector configurations and delegates to `run_packet_detectors()` and `run_closed_flow_detectors()`. It has no retained execution history. The pipeline analyzes each observation once and extracts one snapshot per delivered closed window. Within each window, detector order is volume first, then TCP control for TCP only. TCP requires a TCP-control configuration; UDP does not invoke that detector.

| Detector | Authoritative predicate |
| --- | --- |
| Packet integrity | Successful analysis gives `NO_MATCH`; structural/integrity failure gives `MATCH`; unsupported/incomplete analysis gives `NOT_EVALUABLE`. It does not establish maliciousness or complete protocol compliance. |
| Flow volume/rate | Compares one configured count, byte total, directional count, or rate against a nonnegative threshold using strict `>`; equality gives `NO_MATCH`. An unavailable selected rate gives `NOT_EVALUABLE`. |
| TCP control | Compares one configured raw directional TCP-control counter against a nonnegative integer threshold using strict `>`. It does not infer scanning, flooding, sessions, or attacks. |

The common frozen `DetectionFinding` has exactly five stored fields: `detector_id`, `detector_version`, `decision`, `raw_evidence`, and `security_interpretation`. The family-specific decision, interpretation, evidence, and configuration remain attached; normalization does not introduce security scores or finding IDs. `DetectionPipelineResult` retains separate packet and flow finding tuples, preserving observation order and window-closure/detector order respectively. There is no combined chronological sort, deduplication, alert state, incident lifecycle, or response action.

Failures propagate without retries or a partial returned pipeline result. Source cleanup and flow finalization retain their existing guarantees and Python exception precedence; finalization may deliver previously admitted windows after a source failure. A packet-detector failure suppresses subsequent feature/detector work during finalization, and a failed downstream window consumer is not called again. Previously executed effects are not rolled back. Results are retained in memory and can grow with input size.

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

## Metrics and reporting

`calculate_detection_metrics()` aggregates completed classifications once into `DetectionEvaluationMetrics`, with separate packet and flow `DetectionMetrics`. Each includes TP, FP, FN, TN, and `unclassified_count`. Unclassified entries are excluded from binary denominators; this count is not a count of unevaluable findings. No finding decisions are reinterpreted.

Precision is TP/(TP+FP), recall is TP/(TP+FN), and accuracy is (TP+TN)/(TP+FP+FN+TN). F1 uses `2 * precision * recall / (precision + recall)`. Undefined denominators yield `None`; F1 is also `None` when either input is undefined or their sum is zero. Values are neither smoothed nor prematurely rounded.

`EvaluationReport` retains a standalone evaluation result with optional metrics, or an existing benchmark result with per-case metrics. Benchmark reports reject additional top-level metrics. Optional experiment and detection-configuration references remain explicit context; a benchmark report with an experiment requires equal datasets. Dataset identity/count is exposed where supplied, not inferred from findings. The report does not evaluate, recalculate, reconcile supplied metrics, execute, render, serialize, or persist anything. The CLI's separate finding JSON projection is not an evaluation-report renderer.

## Datasets, experiments, and configuration

`DetectionDataset(name, cases)` defines an immutable exact tuple of `DetectionDatasetCase(case_id, target, ground_truth=None)`. Names and IDs are explicit nonblank strings; case IDs are unique across the dataset. Empty datasets are valid. Explicit order is retained across mixed packet/flow cases, and distinct case IDs may share a target. Optional truth must refer to an equal target; absence stays unlabeled.

Targets preserve detector configuration/version and packet or flow provenance. They do not contain raw captures, loaders, aggregate system configuration, or a feature-contract field. Feature provenance remains attached to snapshots in detection evidence; it must not be inferred from a dataset name or detector version. Datasets describe evaluation subjects, not executable packet workloads.

`DetectionExperiment(experiment_id, dataset, benchmark_operation_id, benchmark_operation_version)` describes the intended dataset and procedure. It retains no results, callable, arbitrary parameter map, or runtime state. Its operation ID/version must identify the caller-maintained procedure and change when that procedure changes. No registry resolves it, and no automatic mechanism verifies external code or inputs. Complete value equality includes dataset contents/order, not only names.

| Contract | Meaning |
| --- | --- |
| `PacketIntegrityConfiguration`, `FlowVolumeThresholdConfiguration`, `TCPControlThresholdConfiguration` | Detector ID/version plus detector-owned metric/threshold settings where applicable. |
| `DetectionConfiguration` | Existing packet/volume configurations, optional TCP-control configuration, and positive inactivity timeout. No generated configuration ID; capture-session ID remains a separate execution input. |
| `DetectorVersion` | Exact nonblank detector ID and version strings; read-only `version_reference` projections on detector configurations/findings preserve their stored values. |
| `FeatureContractVersion` | Exact nonblank feature-contract ID/version, distinct from detector implementation identity. |
| Detection benchmark inputs | Explicit dataset and callable. There is no separate `DetectionBenchmarkConfiguration` class. |
| `PerformanceBenchmarkConfiguration` | Operation ID/version, positive measured count, nonnegative warmup count, and optional dataset/experiment/detection-configuration context. |

Version strings are not normalized or forced into SemVer. Neither version implies the other. Configuration management is representation/validation, not file loading, merging, discovery, or persistence. There is no Git-derived identity, package-version discovery, detector registry, feature registry, or version migration.

## End-to-end system validation

`run_end_to_end_validation()` receives a source, `DetectionConfiguration`, explicit capture-session ID, `GroundTruth`, and optional experiment. It constructs the existing session, invokes the authoritative pipeline once, evaluates once, calculates metrics once, and constructs `EvaluationReport` from those exact outputs.

The frozen `EndToEndValidationResult` retains `pipeline_result`, `ground_truth`, and `report`. Capture observations, analysis outcomes, windows, and snapshots remain reachable through retained finding evidence rather than duplicated buffers. The report retains evaluation, metrics, and configuration. Empty input remains valid; failures propagate without a fabricated successful result. Completion means the components composed successfully, not that every expectation matched or every dataset case was executed. Optional experiment context is a declaration, not an execution attestation.

The integration tests exercise IPv4/IPv6 TCP/UDP, extensions/fragments, inactivity and ordering, expected analysis failures, and fail-fast execution guards. Validation delegates to the existing parsing, feature, detector, evaluation, metric, and reporting implementations; it is not a second implementation of them.

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

There is no live interface capture, PCAPNG, reassembly, complete protocol stack, application parsing, TCP connection state, signature catalog, behavioral baseline, autonomous response, blocking, firewall integration, SIEM integration, threat intelligence, credential protection, endpoint response, or remediation. Findings do not implement severity, confidence, risk, correlation, alerting, or production SOC functionality.

There is no ML/MLOps: no training, inference, model registry, feature store, drift detection, model serving, or experiment tracking infrastructure. Future research must use stable feature/evaluation contracts and separate empirical claims from deterministic predicate behavior. No future capability is implied by the current version objects.

The `enrichment`, `events`, `storage`, and `integrations` responsibility notes describe possible future ownership, not runtime implementations. Further operational resource limits, deployment, and any future subsystem require separate scoped work. This baseline finalizes documentation without adding functionality.
