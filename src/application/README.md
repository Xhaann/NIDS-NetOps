# Application composition

`application` connects capture, analysis, and detection, and owns the evaluation, metrics, reporting, dataset, experiment, configuration, benchmark, and diagnostic APIs below. Packet decoding, flow accumulation, feature formulas, and detector predicates stay in their respective packages. See the [architecture reference](../../docs/architecture.md) and [public exports](__init__.py).

The value contracts below are immutable and retain accepted nested objects by reference. Construction does not execute the operations they describe. Execution is synchronous and explicit; there is no background work, automatic discovery, registry, cache, persistence, or ML/MLOps integration.

## Command-line adapter

[cli.py](cli.py) exposes `main(argv=None) -> int`; [__main__.py](__main__.py) enables `PYTHONPATH=src python3 -B -m application`. Neither module runs the pipeline on import. Serialization helpers are private, with no added package exports. The CLI passes one local classic PCAP path to `PcapPacketSource` and runs `run_detection_pipeline()` once; capture and the pipeline own acquisition, cleanup, analysis, flows, features, and detection.

### Arguments

The settings below are required exactly once, including TCP settings for UDP-only input. Optional settings may occur at most once. Equal repeated values are still errors. Both `--option value` and `--option=value` work; abbreviations do not. Help/usage use a fixed 100-column width and list metric enum values.

| Required settings | Validation |
| --- | --- |
| `--capture-session-id` | Nonblank session identity |
| `--inactivity-timeout-microseconds` | Positive integer microseconds representable by `timedelta` |
| `--packet-detector-id`, `--packet-detector-version` | Nonblank metadata |
| `--volume-detector-id`, `--volume-detector-version`, `--volume-metric`, `--volume-threshold` | Integer count/byte thresholds; float rate thresholds |
| `--tcp-detector-id`, `--tcp-detector-version`, `--tcp-metric`, `--tcp-threshold` | Integer thresholds; applicability remains pipeline-owned |

Detector configurations validate identities, ranges, and metrics; there are no canonical defaults. PCAP provenance keeps the `local-pcap` default, with no path-derived identity.

Optional `--max-active-windows` accepts a positive integer and defaults to 1,024. It is validated before source construction and passed to the existing pipeline manager. At capacity, new identities close the least recently observed window, with creation sequence breaking timestamp ties. Existing flow finding JSON exposes `"closure_reason":"capacity"`; no finding field is added.

Blank/NUL paths and invalid numeric arguments fail before acquisition. Other path strings pass unchanged: the CLI does not open, stat, repair, or copy files. Capture owns missing/unreadable paths, directories, unsupported formats, and corrupt records, all reported through `CaptureError`. An empty valid PCAP succeeds; a zero-byte file fails for lack of a header.

Numeric conversion errors use fixed explanations that omit rejected numeric text. Other argparse errors may echo argument tokens; this is not general redaction.

### JSON result

Success writes one compact, ASCII-escaped JSON object and a newline. Its only root fields, `packet_findings` and `flow_findings`, are arrays in pipeline order, including duplicates. Each finding contains `detector_id`, `detector_version`, `decision`, `raw_evidence`, and `security_interpretation`; enums use their values.

`raw_evidence` is a presentation projection, not a lossless object serialization:

- **Packet:** `captured_at`, `capture_source`, `link_type`, `captured_length`, `original_length`, `protocol`, `failure_classification`, `failure_description`.
- **Both flow types:** `capture_session_id`, `sequence_number`, `closure_reason`, `identity`, `first_captured_at`, `last_captured_at`, `selected_metric`, `threshold`, `observed_value`, `comparison_operator`, `total_packet_count`, `forward_packet_count`, `reverse_packet_count`.
- **Volume additionally:** `captured_byte_total`, `original_byte_total`.
- **Flow identity:** `ip_version`, `source_address`, `destination_address`, `source_port`, `destination_port`, `protocol`. Addresses display canonical packed bytes as lowercase hexadecimal; domain identities remain bytes.

Times use ISO 8601 with six fractional digits and their UTC offset. Missing metadata/failure fields and unavailable rates become `null`; integers/floats keep their values, with nonfinite numbers prohibited. Only semantic evidence is read: no packet bytes, full models, feature snapshots, object representations, or generated host/process/time/path metadata. Caller identifiers remain unchanged.

### Exit behavior

| Condition | Behavior |
| --- | --- |
| Pipeline and serialization succeed | 0; JSON on stdout, empty stderr, regardless of MATCH or NOT_EVALUABLE. |
| `--help` | argparse exits 0; no acquisition. |
| Invalid/missing/repeated arguments, blank/NUL path, or invalid configuration | argparse exits 2; usage/error on stderr, no acquisition. |
| Pipeline raises `CaptureError` | 1; exactly `{"error":"capture_error"}` plus newline on stderr, empty stdout. No exception details or source paths. |
| Other pipeline, serialization, or output exception | Propagates from `main()`; normal uncaught Python failure as a module. No synthetic result or retry. |

The `CaptureError` handler calls `diagnose_error()` once with operation ID `detection-pipeline`, message `capture_error`, and empty context, then presents the diagnostic message under `error`. It reads no exception text/cause and catches no additional exception family. `OperationalErrorCategory` owns classification, including unclassified unknown subclasses. Diagnostic-construction and output errors propagate; successful output gains no diagnostic fields.

JSON is prepared before stdout is written, so pipeline/serialization failures publish no partial result. Stream failures have no rollback guarantee; unexpected tracebacks may show Python source locations. Structured analysis failures remain findings. Unsupported-transport analyses and decreasing admitted-flow timestamps retain pipeline errors; observations excluded from flow state retain packet order even with decreasing timestamps.

Equivalent PCAP observations/configurations yield equivalent output, with no history or cache. The CLI serializes retained in-memory findings, so memory grows with results. It adds no evaluation/report rendering, live capture, PCAPNG, reassembly, application parsing, ML, storage, alerting, or correlation.

## Capture execution

[capture_execution.py](capture_execution.py) exports `run_capture_execution(source: PacketSource, consumer: Callable[[PacketAnalysisOutcome], None]) -> None`. Through `consume()`, it starts the source, analyzes each observation once with `analyze_packet_outcome()`, delivers that exact outcome, and attempts cleanup. Observations, bytes, timestamps, lengths, and link types are unchanged; empty sources deliver nothing.

The consumer runs before the next observation is requested, inside the cleanup guarantee. Success and recognized failure outcomes are delivered alike, with no filtering or reclassification. There is no source-wide buffer or retained history; consumers may collect results. No lazy iterator with a separate cleanup contract is exposed.

Acquisition, unexpected analysis, and consumer errors stop delivery and propagate without retry. `consume()` attempts cleanup once, even after startup failure; cleanup errors follow Python exception precedence/context. Earlier deliveries are not rolled back or replaced with synthetic results.

Both `IterablePacketSource` and `PcapPacketSource` retain record order, duplicates, and decreasing timestamps. PCAP timestamps are input data; iterable timestamps come from acquisition. Repeatable reads need independent source instances under their lifecycle contracts.

The detection pipeline uses this API. The standalone flow session shares its private one-analysis/one-consumer primitive but uses `analyze_packet()`, retaining parser/checksum exceptions rather than substituting outcomes. Direct capture execution creates no flow state, features, detectors, reassembly, or background work.

## Detector orchestration

[detector_orchestration.py](detector_orchestration.py) exports:

- `run_packet_detectors(outcome: PacketAnalysisOutcome, configuration: PacketIntegrityConfiguration) -> tuple[DetectionFinding, ...]`
- `run_closed_flow_detectors(snapshot: FlowFeatureSnapshot, *, flow_volume_configuration: FlowVolumeThresholdConfiguration, tcp_control_configuration: Optional[TCPControlThresholdConfiguration] = None) -> tuple[DetectionFinding, ...]`

The packet path evaluates the exact outcome/configuration once and converts the evaluation through `detection_finding_from_evaluation()`, returning one finding.

The flow path evaluates volume on the snapshot first. For TCP, it then evaluates TCP control on the retained window; TCP configuration is required. UDP runs volume only, though any supplied TCP configuration must still have the supported exact type. Detector validation rejects active snapshots rather than closing them. Valid `FlowIdentity` values admit only protocols 6 and 17.

Each applicable evaluator and conversion runs once. Returned tuples retain every MATCH, NO_MATCH, and NOT_EVALUABLE finding, with original evidence, interpretation, and configuration references. A failure propagates immediately: no retry, later detector, or partial tuple.

Orchestration owns applicability and order, not capture, analysis, features, or lifecycle. It adds no common detector-input model, registry, filtering, attack inference, severity, confidence, risk, correlation, alerting, or response.

## Explicit detection sessions

[detection_session.py](detection_session.py) exports `DetectionSession(packet_configuration, flow_volume_configuration, tcp_control_configuration=None)`. Construction validates exact `PacketIntegrityConfiguration`, `FlowVolumeThresholdConfiguration`, and optional `TCPControlThresholdConfiguration` types. It creates no session ID, timestamp, lifecycle state, or detector execution.

- `run_packets(outcomes: Iterable[PacketAnalysisOutcome]) -> tuple[DetectionFinding, ...]` calls `run_packet_detectors()` once per outcome.
- `run_closed_flows(snapshots: Iterable[FlowFeatureSnapshot]) -> tuple[DetectionFinding, ...]` calls `run_closed_flow_detectors()` once per snapshot.

Each finite iterable is consumed synchronously in caller order. Results are flat tuples of the exact findings; empty input returns `()`. No sorting/deduplication occurs. Calls retain configurations and evidence, buffer findings locally, and execute independently on repetition. Iterables and their cleanup remain caller-owned.

Orchestration owns validation, applicability, ordering, and finding normalization. Flow calls accept closed snapshots, not bare windows. Active windows, missing TCP configuration/state, and malformed inputs retain their errors. IPv4/IPv6 TCP runs volume then TCP control; UDP runs volume only. Non-first fragments lacking transport cannot enter flows; packet-integrity semantics remain separate. No ICMPv6 detector is added.

Iteration/orchestration failures propagate before the next input, with no retry or partial tuple. Earlier evaluations are not rolled back, but their local findings are not published. Sessions do not capture, parse, repeat analysis, build/close flows, extract snapshots, or reconstruct findings. `run_flow_observation_session()` still emits closed windows for consumers to extract and detect separately.

## Explicit detection pipeline

[detection_pipeline.py](detection_pipeline.py) exports `run_detection_pipeline(source, *, detection_session, capture_session_id, inactivity_timeout, max_active_windows=1024) -> DetectionPipelineResult`. It collects findings from `run_detection_stream()` into the established result, preserving the exact finding objects. It accepts a `PacketSource` and exact `DetectionSession`, reusing its configuration. The positive integer active-window limit passes to the shared lifecycle manager and is validated before acquisition. Construction of sources or sessions never triggers detection.

A private lifecycle runner shared with `run_flow_observation_session()` owns the window manager, admission, and finalization. The standalone session keeps `analyze_packet()`; the pipeline calls `run_capture_execution()` once. Each outcome reaches `DetectionSession.run_packets()` before its analysis enters flow admission. Detection neither receives raw bytes nor repeats analysis.

Recognized analysis failures become packet findings and contribute no flow observation. Escaping exceptions propagate. Successful unsupported transports—including ICMPv6, unsupported protocols, and non-first IPv6 fragments—raise admission errors rather than being skipped or given fabricated transport state. First/whole fragments enter only when transport admission succeeds.

Every delivered closed window gets one `extract_flow_feature_snapshot()` call, then `DetectionSession.run_closed_flows()` receives that snapshot. Active windows are never delivered. IPv4/IPv6 share the volume-then-TCP-control path for TCP and volume-only path for UDP.

`DetectionPipelineResult(packet_findings, flow_findings)` holds two tuples: packet findings in observation/detector order, flow findings in closure/detector order. References are retained; there is no combined chronological sort, deduplication, or correlation. Empty input returns two empty tuples. Local result buffers require finite input and grow with findings; equivalent sources/configurations yield equal results across calls.

Failures propagate with no translation, retry, or partial result:

- Source, analysis, and admission errors still finalize and attempt delivery of prior windows.
- Packet-detector failure suppresses later feature/detector execution during finalization. Feature or closed-flow detector failures stop downstream delivery.
- `source.stop()` failures may supersede earlier failures; final-delivery failures may supersede source failures, retaining Python exception context.

Earlier local findings are not rolled back or published on failure. The pipeline composes its owners; it adds no parser, feature formula, detector, tracker, hidden state, or persistence.

## Incremental detection finding delivery

`run_detection_stream(source, *, detection_session, capture_session_id, inactivity_timeout, packet_finding_consumer, flow_finding_consumer, max_active_windows=1024) -> None` is exported by `application`. It runs the same detection and flow lifecycle as the collecting pipeline, with no result accumulator. Both consumers are required synchronous callables accepting one existing immutable `DetectionFinding`. Noncallable consumers raise `TypeError` before source acquisition, including for empty input. Session and manager configuration retain their existing validation. Callback return values are ignored; they are not cancellation, acknowledgement, or retry instructions. Empty input starts/stops the source, calls neither consumer, and returns `None`.

Each packet's detector batch completes before its findings are delivered in detector order to the packet consumer. Delivery precedes admission of that packet's successful analysis. A failed analysis still produces its existing packet finding and is not admitted. Any capacity/inactivity closure caused by the incoming packet follows that packet's finding delivery, before another observation is requested. Closed windows pass through existing snapshot extraction and `DetectionSession.run_closed_flows()`: UDP produces volume findings; TCP produces volume then control findings. The entire single-window detector batch completes before its first callback, so a TCP-control detector failure does not publish that window's already-computed volume finding. Consumer failure during delivery can leave a partially delivered batch.

Source cleanup is attempted before capture-end closures. Remaining windows are finalized and delivered in creation-sequence order. These rules define the interleaving of the two consumer channels; there is no timestamp merge, hash-order traversal, identifier generation, deduplication, or parallel delivery. Synchronous callbacks provide backpressure, and a callback finishes before acquisition or delivery proceeds. The same callable may serve both channels. Use the existing closed-window session when windows without detection are wanted; this function does not introduce another window consumer or LDAP lifecycle.

| Failure boundary | Behavior |
| --- | --- |
| Packet detection or packet consumer | Propagates; rejects admission of that packet, stops acquisition, attempts cleanup/finalization, and suppresses subsequent feature/detector execution and delivery. |
| Snapshot extraction, flow detection, or flow consumer | Propagates; stops further downstream delivery without retry. Previously committed flow admission is not rolled back. Source cleanup and manager finalization still occur. |
| Capture, unexpected analysis, or flow admission | Propagates after existing cleanup/finalization attempts; previously admitted windows can still produce findings. Packet findings delivered before failed admission remain delivered. |
| Manager window/update publication | Preserves the existing active state, sequence number, and timestamp frontier. No new flow finding is fabricated; finalization uses previously admitted state. It cannot undo an earlier packet callback. |
| Manager finalization publication | Retains the manager's existing atomicity and direct retry behavior; the stream function propagates and supplies no resume handle or automatic retry. |
| Cleanup/final-delivery errors | Preserve Python exception precedence/context: stop errors may supersede earlier failures, and finalization or final-consumer errors may supersede capture errors. |

Each callback is attempted at most once per finding within a run. An exception, including interruption, is not swallowed or translated. A callback may perform an effect and then fail; the boundary cannot determine whether an external destination accepted it. Earlier deliveries are valid partial output, not a successful-run certificate. There is no rollback, acknowledgement record, durable-delivery guarantee, resume offset, or automatic replay. Replaying a fresh source can repeat a previously delivered prefix; callers own that decision and any effects. Repeated direct manager finalization retains its existing empty result after successful closure and does not re-invoke consumers.

Resource ownership is separate at each boundary:

- **Active analysis:** the existing manager retains at most `max_active_windows` flow states with their established TCP/LDAP bounds. Capture-end finalization temporarily holds at most that many closed windows.
- **Output delivery:** the stream retains only the current packet/window detector batch and synchronous call frames, with no growing finding list, history, queue, or output cache. Current batches contain one packet finding, one UDP flow finding, or two TCP flow findings. Previously delivered objects can be released once current processing returns, provided no caller retains them. Per-delivery work is proportional to the current batch plus consumer work; capacity selection retains its existing bounded scan.
- **Caller retention:** consumer buffers, caller-owned input collections, and retained exceptions/tracebacks remain outside this bound. Findings preserve rich existing evidence: packet evidence references its observation/analysis, and flow evidence references its window/snapshot with bounded TCP bytes. Retaining findings can therefore retain payloads. The boundary neither copies payloads nor redacts these existing contracts. `run_detection_pipeline()`, CLI JSON generation, evaluation, and reporting deliberately continue to collect their full results and can grow with input.
- **Persistent archival:** the stream opens no destination, serializes nothing, and performs no logging, network delivery, or persistence. It is independent of the bounded LDAP summary exporter, which remains an optional caller-invoked metadata adapter over existing summaries. Delivery is not archival.

For example, a caller can keep only aggregate decision counts:

```python
from collections import Counter
from application import run_detection_stream

counts = Counter()

def count_finding(finding):
    counts[finding.decision.value] += 1

run_detection_stream(
    source,
    detection_session=session,
    capture_session_id="offline-review",
    inactivity_timeout=timeout,
    max_active_windows=1024,
    packet_finding_consumer=count_finding,
    flow_finding_consumer=count_finding,
)
```

Here `source`, `session`, and `timeout` are caller-supplied existing contracts. This counter illustrates consumer ownership; it is not ground-truth evaluation or a detection metric definition. No async iterator, background thread, timer, or separate capture lifecycle is introduced.

## Flow observation sessions

[flow_observation_session.py](flow_observation_session.py) exports `run_flow_observation_session(source, *, capture_session_id, inactivity_timeout, closed_window_consumer, max_active_windows=1024) -> None`. Each call creates one `FlowObservationWindowManager` with the positive integer limit, runs the source once through the capture primitive/`consume()`, analyzes each `PacketObservation` with `analyze_packet()`, and passes the `PacketAnalysis` unchanged to the manager. Capture-session IDs pass unchanged; uniqueness outside the call is caller-defined, never generated.

Inactivity and capacity closures are delivered in `record()` order before requesting another observation. After `source.stop()` is attempted, `end_capture_session()` closes and delivers remaining windows in manager order. Active windows are not delivered; empty sessions emit none. Capacity closures follow the same feature/detector path as other closures, preserving TCP volume-then-control and UDP volume-only ordering.

Delivery is synchronous and at most once, providing backpressure. A failed consumer is never called again, attempted windows are not re-emitted, and remaining active windows are still finalized. No closed-window history or output queue is retained.

Source, decoding, analysis, identity, coordination, lifecycle, and consumer errors propagate unchanged. Finalization is attempted after cleanup even if startup, iteration, processing, lifecycle, or stop fails. Stop, finalization, and final-delivery failures follow normal Python exception precedence/context.

TCP/UDP share lifecycle rules: TCP flags do not close windows, UDP has no transaction inference or TCP-control state. ICMP analysis exists but flow admission rejects it. Skipping invalid/unsupported packets is **UNDEFINED POLICY**.

Consumers receive exact `FlowObservationWindow` objects and may extract features separately; extraction retains the window as provenance. Analysis also accepts active windows as provisional extraction inputs. This layer provides no explicit segmentation during a running source, durable delivery, retries, rejected-packet routing, live capture, loss accounting, ML vectorization, or serialization.

## Detection result evaluation

[detection_evaluation.py](detection_evaluation.py) exposes `evaluate_detection_result(actual, expected)`: an in-memory comparison of a completed `DetectionPipelineResult` and immutable `ExpectedDetectionResult`, returning `DetectionEvaluationResult`. It executes no upstream work or CLI operation.

`ExpectedDetectionResult(packet_expectations, flow_expectations)` requires two tuples of `ExpectedDetection(identity, positive)`. The mandatory boolean requires MATCH for `True`, NO_MATCH for `False`. Expectations are independently supplied, never inferred from absence; no attack labels or dataset format are defined.

### Stable matching identity

- `PacketDetectionIdentity(configuration, packet_index, captured_at, capture_source, link_type, captured_length, original_length)` includes packet-integrity configuration and zero-based position in `packet_findings`. Duplicate observations at different positions remain distinct. Optional metadata stays `None`; UTC times are unchanged.
- `FlowDetectionIdentity(configuration, window_key, flow_identity, first_captured_at, last_captured_at)` includes typed detector configuration, `FlowObservationWindowKey`, canonical packed `FlowIdentity`, and timestamps. Configuration equality covers family, ID, version, metric, and threshold; flow identity separates IPv4/IPv6 and TCP/UDP.

`detection_identity(finding, packet_index=...)` projects packet identity from evidence; omit `packet_index` for flows. Identities may also be built from independently known metadata/configuration. Neither path generates labels or executes detectors. Decisions, interpretations, failure descriptions, measured counters, feature graphs, and packet bytes are excluded so different decisions about one subject can be compared.

Packet identities have no independent packet ID/session key: expectations require aligned result positions and capture provenance. Removing/reordering earlier results changes positions. Identical metadata at the same position cannot reveal content substitution; matching is not authentication. Flow session/window keys are also caller-established, not globally unique. No cross-dataset matching or byte fingerprint is claimed.

### Classification and audit records

`DetectionClassification` contains only `TRUE_POSITIVE`, `FALSE_POSITIVE`, `FALSE_NEGATIVE`, and `TRUE_NEGATIVE`. NOT_EVALUABLE is neither positive nor negative and never satisfies an expectation.

| Expectation | MATCH | NO_MATCH | NOT_EVALUABLE | Missing result |
| --- | --- | --- | --- | --- |
| Positive | TP | FN | FN, retaining NOT_EVALUABLE | FN |
| Negative | FP | TN | Unclassified | Unclassified |
| None | FP | Unclassified | Unclassified | No entry |

FN means a required MATCH was not obtained; it does not imply an evaluated negative. Retained findings distinguish NO_MATCH, NOT_EVALUABLE, and missing results. `classification=None` is unclassified, never TN; a missing negative earns no credit.

`DetectionEvaluationEntry` holds `classification`, `expectation_index`, `expectation`, `actual_index`, and `finding`. Missing sides and indices are `None`; indices refer to their channel's input tuple. `DetectionEvaluationResult.packet_evaluations` and `.flow_evaluations` are tuples containing every actual finding in original order, then unmatched expectations in expectation order. Evidence stays attached; inputs are neither mutated, sorted, nor deduplicated.

Matching is one-to-one and multiplicity-sensitive. Within each channel, expectations in order consume the earliest unassigned same-identity finding in three passes: required decision, opposite binary decision, then NOT_EVALUABLE. Duplicate expectations require separate results. Extra MATCH is FP; extra NO_MATCH/NOT_EVALUABLE is unclassified. Contradictory positive/negative expectations for one identity raise `ValueError`; they do not label separate occurrences. Packet positions disambiguate occurrences; repeated flow identities use multiplicity.

Constructors reject wrong types, mutable collections, invalid metadata, inconsistent entries, and mixed channels with `TypeError`/`ValueError`. Assignments remain local; exceptions propagate with no retry or partial result. Evaluation reads no packet bytes and calculates no metrics; the [metrics boundary](#detection-evaluation-metrics) consumes completed classifications. Dataset ingestion, experiment tracking, persistence, ML, correlation, alerting, and CLI evaluation are unimplemented.

## Incremental detection evaluation

`IncrementalDetectionEvaluator(expected, *, packet_evaluation_consumer, flow_evaluation_consumer)` consumes the existing exact `ExpectedDetectionResult`. Both consumers are required synchronous callables receiving existing immutable `DetectionEvaluationEntry` objects. `record_packet(finding)` and `record_flow(finding)` accept the exact `DetectionFinding` objects supplied by `run_detection_stream()`, return `None`, and maintain separate zero-based actual indices. The evaluator owns no capture, detector, protocol parser, flow state, metric calculation, or serialization. It preserves references to findings and expectations without copying payloads or creating labels. The collecting `evaluate_detection_result()` keeps its public signature, validation order, result construction, and exception behavior; both paths share the extracted three-phase assignment routine and classification function.

Matching remains expected-decision first, opposite binary decision second, then `NOT_EVALUABLE`, in expectation order within each phase. Duplicate expectations require distinct findings; existing expectation validation is unchanged. Extra `MATCH` findings are false positives, while extra `NO_MATCH`/`NOT_EVALUABLE` findings are unclassified. A positive expectation paired with `NOT_EVALUABLE` remains a false negative; a negative one remains unclassified. Missing positives become false negatives; missing negatives remain unclassified. These historical semantics are unchanged.

`ExpectedDetectionResult` historically checks contradictory expectations using dictionary keys. Custom address subclasses that compare equal but supply different hashes can bypass that check. This existing validation limitation is not corrected here; accepted inputs preserve the same equality-fallback matching behavior.

Packet identities include their actual-result position, so a later packet finding cannot compete for the same target: packet entries can be delivered immediately, including opposite and unavailable decisions. A flow entry is settled when it matches the required decision or has no remaining expectation to match. Such entries are delivered immediately until an ambiguous entry is encountered. A matching opposite or unavailable flow finding can be displaced by a later preferred finding with the same identity. That entry and the subsequent flow suffix are therefore deferred until `finish()`, even when some later entries are individually settled. For example, with one positive expectation and flow decisions `NO_MATCH, MATCH`, the first finding must remain unmatched and the second must satisfy the expectation. Assigning the expectation to the first arrival would change the established result.

Per-channel delivery preserves actual finding order, followed by unmatched expectations in their original order. Packet evaluation continues while a flow suffix is deferred. `finish()` emits missing packet expectations, then evaluates/delivers the deferred flow suffix and missing flow expectations. There is no new cross-channel timestamp sort or combined evaluation result order. Collecting the two consumer channels into `DetectionEvaluationResult` after successful finalization produces the same entries, indices, classifications, and references as the collecting evaluator on the same channel sequences and expectations.

`finished` is a read-only boolean, true only after all final deliveries succeed. `pending_flow_count` reports the number of deferred findings still awaiting delivery. Successful `finish()` returns `None`; repeating it emits nothing. Recording after completion and aborting a completed evaluator raise `ValueError`. Reentrant record/finalize/abort calls from a consumer are rejected. Callback return values are ignored.

Invalid constructor inputs raise `TypeError` before evaluation. Invalid findings, wrong channels, identity validation, matching, entry construction, and consumer failures propagate unchanged. A failure during recording or finalization makes the evaluator terminal, clears deferred finding/identity references, and leaves `finished` false. Subsequent record/finalize calls raise `ValueError`; there is no retry or rollback of earlier consumer effects. In particular, finalization failure can leave a delivered prefix and never certifies a completed evaluation. Caller-retained exceptions can still retain local references through tracebacks.

Only call `finish()` after successful detection-stream completion. The evaluator cannot infer whether an external source completed or failed. `abort()` discards deferred state without emitting missing expectations and prevents subsequent finalization; it is idempotent after abort/failure. On an upstream capture/detector/publication error, the caller aborts and propagates that error. Findings delivered during the detection stream's normal failure cleanup remain partial observations. A fresh evaluator/source can replay them, potentially repeating previously delivered effects.

Resource ownership is explicit. For `E` supplied expectations and a deferred flow suffix of length `B`, retained evaluation state is `O(E + B)`: ordered expectation references, an index of ordinary identities, used expectation indices, channel counters, and the deferred original findings with derived matching identities. Packet findings and settled flow prefixes are not retained after delivery. Ordinary expectation lookup is indexed; custom address subclasses reuse the established equality fallback without hashing those addresses. Ordinary pre-deferral matching is amortized constant work per finding after `O(E)` index construction. Deferred final matching is `O(E + B)` for ordinary identities; the historical fallback can require `O(E * B)` work, or `O(E)` for an immediate finding. No repeated matching of an accumulated suffix occurs before finalization.

`B` has no fixed cap and may be the entire remaining flow stream: exact preference matching and output order can require waiting for a preferred finding at the end. This removes mandatory full-result accumulation, not the information dependency inherent in historical matching. Deferred findings retain their existing evidence graphs, including any bounded TCP bytes. No extra payload copies or history beyond that suffix are introduced. Caller-owned input, output collections, and exceptions remain outside the resource guarantee. Callers can observe `pending_flow_count` and abort if their own resource budget is exceeded; the evaluator never silently drops findings or changes classifications to meet a budget.

Ground truth stays external. As in `run_end_to_end_validation()`, callers adapt ordered `GroundTruth` records into existing expectations without deriving polarity from findings:

```python
from application import (
    ExpectedDetection, ExpectedDetectionResult, GroundTruthPolarity,
    IncrementalDetectionEvaluator, run_detection_stream,
)

expected = ExpectedDetectionResult(
    tuple(ExpectedDetection(record.target, record.polarity is GroundTruthPolarity.POSITIVE)
          for record in truth.packet_records),
    tuple(ExpectedDetection(record.target, record.polarity is GroundTruthPolarity.POSITIVE)
          for record in truth.flow_records),
)
evaluator = IncrementalDetectionEvaluator(
    expected,
    packet_evaluation_consumer=consume_packet_entry,
    flow_evaluation_consumer=consume_flow_entry,
)
try:
    run_detection_stream(
        source, detection_session=session, capture_session_id=session_id,
        inactivity_timeout=timeout,
        packet_finding_consumer=evaluator.record_packet,
        flow_finding_consumer=evaluator.record_flow,
    )
except BaseException:
    evaluator.abort()
    raise
else:
    evaluator.finish()
```

The example assumes caller-supplied truth, consumers, source, and detection configuration. `GroundTruth` still rejects duplicate targets, while `ExpectedDetectionResult` retains its existing same-polarity multiplicity. Passing `GroundTruth` directly in place of expectations is rejected. Neither representation is inferred or redesigned.

Metrics remain separate: `IncrementalDetectionMetrics` can consume the entries directly, while `calculate_detection_metrics()` still accepts a completed `DetectionEvaluationResult`. Both preserve the same definitions. Consumers may explicitly collect entries for existing reporting, accepting the associated retention cost. CLI output, `EvaluationReport`, and `run_end_to_end_validation()` remain collecting paths. Incremental evaluation creates no persistent archive, export format, research projection, or ML dependency.

## Explicit ground truth

[ground_truth.py](ground_truth.py) exports:

- `GroundTruthPolarity`: POSITIVE (externally expected present) or NEGATIVE (explicitly absent/non-detected), not detector decisions.
- `GroundTruthRecord(target, polarity)`: packet/flow detection identity plus a required `GroundTruthPolarity` member.
- `GroundTruth(packet_records, flow_records)`: ordered, domain-validated tuples of records.

Absent records mean **unlabeled**, never negative; empty tuples mean no truth supplied. NOT_EVALUABLE is not truth, and no attack/probabilistic labels are introduced.

Targets use the matching identities above. Packet targets remain family-neutral and position/provenance-dependent, with no new IP-family field or content fingerprint. Flow targets retain canonical endpoints, transport, window, times, and detector configuration. IDs, versions, metrics, and thresholds scope the target; truth contains no actual findings, decisions, counters, snapshots, or evidence graphs.

Build targets from external metadata/configuration. Construction neither derives identities from findings nor infers labels from output/absence. Nested constructors own field validation; ground truth checks record/polarity/tuple types, domains, and consistency, with no metadata normalization.

Each target may appear once in a truth collection. Same-polarity repeats raise duplicate `ValueError`; opposite polarities raise contradiction `ValueError`, in either order. Equal targets—including reversed endpoints canonicalizing to one flow—follow this rule. Different packet positions, windows, flows, or configurations are distinct. This rule does not change evaluation-expectation multiplicity.

Collections require exact tuples of exact `GroundTruthRecord` values. Wrong types raise `TypeError`; wrong domains raise `ValueError`. Order/references are retained, with no sorting, deduplication, mutation, or external work. `run_end_to_end_validation()` adapts truth into expectations; construction itself neither converts nor executes. Annotation formats, loaders, metrics, benchmarking, tracking, storage, and ML remain separate.

## Detection evaluation metrics

[detection_metrics.py](detection_metrics.py) exports `calculate_detection_metrics(result)`, accepting exactly `DetectionEvaluationResult`. It returns `DetectionEvaluationMetrics(packet_metrics, flow_metrics)`, with separate `DetectionMetrics` values; channels are never pooled or rematched.

Each entry contributes once, including duplicates, to integer `true_positives`, `false_positives`, `false_negatives`, `true_negatives`, or `unclassified_count`. `classification=None` contributes only to the last. That count is not a NOT_EVALUABLE count; no separate unevaluable count exists. An FN remains FN even with a NOT_EVALUABLE finding. Unclassified entries are excluded from binary denominators; findings/expectations are never reinterpreted.

Properties use Python floating-point division, with no rounding or smoothing:

| Property | Definition | Undefined (`None`) when |
| --- | --- | --- |
| `precision` | TP / (TP + FP) | TP + FP = 0 |
| `recall` | TP / (TP + FN) | TP + FN = 0 |
| `f1` | 2 × precision × recall / (precision + recall) | Either input is undefined, or their sum is zero |
| `accuracy` | (TP + TN) / (TP + FP + FN + TN) | No binary classifications exist |

`0.0` differs from `None`: TP=0, FP>0, FN>0 gives zero precision/recall but undefined F1. Counts remain integers of any size; metrics are numbers, not formatted strings.

F1 preserves those undefined-result rules and the ordinary floating-point formula. When its intermediate numerator is below the minimum normal float, it instead divides `2 * TP` by `2 * TP + FP + FN` using the original integer counts. This avoids intermediate-product underflow and subnormal precision loss without changing classification or matching. The final ratio remains a float and can itself underflow.

`DetectionMetrics` requires four counts; `unclassified_count` defaults to zero. Counts must be exact `int` (not bool): wrong types raise `TypeError`, negatives `ValueError`. `DetectionEvaluationMetrics` requires exact `DetectionMetrics` for both channels. Calculation aggregates validated entries locally, without mutation, reordering, truth inference, reevaluation, or upstream execution. Reporting and performance measurement are separate; CLI JSON is unchanged.

## Incremental detection metrics

[`IncrementalDetectionMetrics()`](incremental_detection_metrics.py) removes mandatory evaluation-result collection when only final metrics are needed. `record_packet(entry)` and `record_flow(entry)` accept exact existing `DetectionEvaluationEntry` objects and return `None`. They validate the channel using expectation identity and finding evidence types, then count only the supplied classification. They do not recompute classification, match expectations, inspect decisions or payload contents, or execute detection. Duplicate entries count separately; actual/expectation indices are neither retained nor required to be unique, contiguous, or ordered. Packet and flow counts are independent.

`finish() -> DetectionEvaluationMetrics` publishes the existing immutable result only after both channel metrics and the combined result construct successfully. Its counts and precision/recall/F1/accuracy properties are exactly those described above. Counts stay integers throughout accumulation; no ratios are calculated or rounded during recording or finalization. The ordinary F1 formula, integer-count fallback near underflow, and historical undefined-result rules are unchanged.

`finished` is read-only and becomes true only on success. Repeated successful `finish()` returns the same object without reaggregation. Recording or aborting after completion raises `ValueError`. There is no partial-result accessor, reset, count-seeding, merge, or replay API.

Invalid entry types raise `TypeError`; wrong channels raise `ValueError`. Recording/finalization exceptions propagate unchanged and leave a terminal unfinished consumer. No result is published on failure, including failure after one channel's immutable metrics have been constructed. Subsequent record/finish calls are rejected, with no retry or rollback. `abort()` prevents unfinished counts from being finalized and is idempotent after abort/failure. Reentrant operations are rejected. No input or exception references are stored; caller-retained exceptions can still keep local inputs reachable through tracebacks.

The caller must complete evaluation before finalizing metrics. A source, detector, publication, or evaluator failure means the counts are partial: abort the metrics consumer and propagate the error. Neither consumer owns capture or can infer external success. For existing caller-supplied expectations and stream configuration:

```python
from application import IncrementalDetectionEvaluator, IncrementalDetectionMetrics, run_detection_stream

metrics = IncrementalDetectionMetrics()
evaluator = IncrementalDetectionEvaluator(
    expected,
    packet_evaluation_consumer=metrics.record_packet,
    flow_evaluation_consumer=metrics.record_flow,
)
try:
    run_detection_stream(
        source, detection_session=session, capture_session_id=session_id,
        inactivity_timeout=timeout,
        packet_finding_consumer=evaluator.record_packet,
        flow_finding_consumer=evaluator.record_flow,
    )
    evaluator.finish()
    completed_metrics = metrics.finish()
except BaseException:
    metrics.abort()
    if not evaluator.finished:
        evaluator.abort()
    raise
```

Metrics retain only ten exact integer counters, fixed channel/lifecycle state, and the completed immutable result after success. The number of counters is independent of entry count; exact integer bit storage is `O(log(N + 1))` for `N` entries. Each arrival performs a fixed number of counter operations, with integer arithmetic cost depending on count width. No evaluation entries, findings, expectations, payload graphs, or complete evaluation results are retained. Upstream active analysis, incremental evaluation's `O(E + B)` state, caller-owned collections, and exception tracebacks have separate ownership and limits.

The collecting function shares the private counting primitive but retains its signature, exact result-type check, packet-before-flow calculation order, and classification-only access contract. It does not acquire the new consumer's channel-inspection step because its result input has already validated channels. No metric definitions or existing value dataclasses change. `EvaluationReport`, the CLI, and `run_end_to_end_validation()` remain collecting APIs. There is no new persistence, archival, report format, streaming JSON, research/ML integration, or network delivery.

## Detection dataset representation

[detection_dataset.py](detection_dataset.py) exports:

- `DetectionDatasetCase(case_id, target, ground_truth=None)`: case ID, packet/flow detection identity, optional `GroundTruthRecord`.
- `DetectionDataset(name, cases)`: name and ordered case tuple; empty tuples are valid.

Names/IDs must be exact nonblank strings. Wrong types raise `TypeError`, blank strings `ValueError`; accepted text is unchanged. These are caller-defined logical labels, not paths, global IDs, timestamps, counters, or discovered identities.

Case IDs must be unique across both domains within a dataset; duplicates raise `ValueError`, regardless of case equality. Independent datasets may reuse IDs. Distinct IDs may share targets; cases are not merged into a `GroundTruth` collection. A case ID neither authenticates packet content nor replaces evaluation identity. Packet alignment and canonical flow/window/configuration semantics remain those of the target.

Truth must be exactly `GroundTruthRecord`, with a target equal to the case target. Equal independently constructed targets are accepted; mismatches/cross-domain targets raise `ValueError`, unsupported types `TypeError`. Polarity is unchanged; `None` remains unlabeled. No finding, result, or metric is needed.

`cases` requires an exact tuple of exact `DetectionDatasetCase` values. Other containers/malformed members raise `TypeError`, with no coercion or mutation; callers may use `tuple(cases)`. The tuple and nested objects are retained by reference, preserving order and distinct-ID multiplicity. Validation uses local state only.

This contract organizes evaluation cases; it neither establishes truth nor converts or executes it. It reads no packets/files/network/clock and performs no capture, analysis, features, detection, evaluation, metrics, ID generation, or caching. Loading, PCAP management, reporting, benchmarking, experiments, and ML are separate concerns.

## Deterministic benchmark execution

[detection_benchmark.py](detection_benchmark.py) exports `run_detection_benchmark(dataset, operation)`. It accepts exactly `DetectionDataset` and a callable taking one `DetectionDatasetCase`, returning exactly `DetectionBenchmarkCaseResult`. Functions and callable objects follow the same synchronous path.

`DetectionBenchmarkCaseResult(case, evaluation=None, metrics=None)` accepts an exact case and optional exact `DetectionEvaluationResult`/`DetectionEvaluationMetrics`. Either, both, or neither payload may be supplied. `None` means absent, not failure/classification. The operation owns payload relevance and consistency; the framework neither inspects entries/values nor computes missing payloads.

Each exact source case is passed once, in dataset order. Before the next call, the framework validates the result type and full case equality (ID, typed target, truth). Equal independent cases are accepted; mismatches are rejected. Returned objects and payloads are retained unchanged.

`DetectionBenchmarkResult(dataset, case_results)` requires one corresponding result per case, in order, as an immutable tuple. `dataset_name` reads the source name; `total_case_count` is tuple length. Distinct IDs with equal targets run separately. Empty datasets return zero results without calls, but still require a callable. Mutable collections/unsupported types raise `TypeError`; count/association mismatches raise `ValueError`.

Operation failures propagate immediately, with no retry, skipped case, synthetic record, or partial result. Earlier side effects are not rolled back; later calls use independent framework state. Determinism depends on the operation's outputs. Result construction executes nothing.

The framework only invokes, validates associations, and collects results. Operations may call evaluation/metrics themselves; the framework never converts truth, inspects findings, recalculates classifications, or wraps capture/pipelines. It adds no timing, concurrency, external access, loading, reporting, metadata discovery, or ML. Performance measurement is separate.

## Reproducible experiment definition

[detection_experiment.py](detection_experiment.py) exports `DetectionExperiment(experiment_id, dataset, benchmark_operation_id, benchmark_operation_version)`. All arguments are required: an exact `DetectionDataset` and three exact nonblank strings. Wrong types raise `TypeError`; blank strings raise `ValueError`. Text is neither normalized, parsed as versions/paths, nor generated.

The dataset is retained, including ordered cases, typed targets, configurations, and optional truth. Equality includes all four fields; equal independent definitions compare equal, but a shared dataset name alone is insufficient.

Operation ID/version names the intended procedure and its inputs/settings; the pair must change when that declaration changes. It is not a callable, import binding, registry lookup, fingerprint, or proof that code/inputs are available. Callers must keep stable references and the corresponding external procedure. No resolution/execution bridge to `run_detection_benchmark()` exists.

Detector settings/versioning already participate through target configurations; no second list is stored. Evaluation/metrics have fixed contracts, with no new configuration/version objects. Feature provenance stays on `FlowFeatureSnapshot.feature_contract`, not dataset targets or experiments, and is not inferred from operation/detector versions. No arbitrary parameter mappings are added.

An experiment describes a dataset and operation, not a run or result. It contains no findings, packets, metrics, timings, execution timestamps, or mutable execution state. It performs no upstream work, benchmark execution, external access, timing, or randomness. Loading, execution, tracking, storage, and ML remain unimplemented; an experiment ID is a logical label, not a global identifier or stored run.

## Deterministic configuration representation

`DetectionConfiguration(packet_configuration, flow_volume_configuration, inactivity_timeout, tcp_control_configuration=None, max_active_windows=1024)` groups a run's detector settings, window timeout, and active-window limit. It requires exact `PacketIntegrityConfiguration`, `FlowVolumeThresholdConfiguration`, optional `TCPControlThresholdConfiguration`, positive `timedelta`, and exact positive integer limit values. Wrong types raise `TypeError`; nonpositive duration or limit raises `ValueError`. The timeout controls closure/detector inputs and has no default or rounding. End-to-end validation passes the limit to the pipeline, and the report retains it as part of the supplied configuration.

It retains the supplied immutable values. Detector configurations still validate IDs, versions, metrics, and thresholds; formulas, applicability, and order are not duplicated. TCP configuration may be absent for non-TCP workloads, but remains required when evaluating a closed TCP flow.

Equality covers all five settings. Capture path/source and session identity remain per-run inputs, not reusable settings. There is no separate configuration ID/version, runtime state, session/window construction, or execution method. Pass its fields to session/pipeline APIs explicitly; datasets, experiments, and benchmarks are not automatically connected.

Configuration management means representation and validation only: no file/environment loading, discovery, merging, registries, or persistence. The CLI parses settings; `EvaluationReport` can retain them. Detector configurations expose an [explicit detector version reference](../detection/README.md#explicit-detector-version-references) through `version_reference`, keeping stored strings/equality unchanged. The [feature contract reference](../analysis/README.md#explicit-feature-contract-version) remains separate, static snapshot provenance; configuration introduces no version discovery or feature version.

## Evaluation reporting representation

`EvaluationReport(result, metrics=None, experiment=None, configuration=None)` wraps an already-computed evaluation or benchmark result:

| Result type (exact) | Metrics |
| --- | --- |
| `DetectionEvaluationResult` | Optional exact `DetectionEvaluationMetrics`, retaining packet/flow `DetectionMetrics`. `None` differs from supplied metrics with undefined values. |
| `DetectionBenchmarkResult` | Per-case evaluations/metrics remain in ordered `case_results`. Top-level metrics must be `None`; otherwise `ValueError`, since cross-case aggregation is undefined. |

Optional exact `DetectionExperiment` and `DetectionConfiguration` provide declared context, not proof of execution. A benchmark's dataset must equal the experiment dataset in full—name, case order, targets, and truth—or raise `ValueError`. Equal independent datasets are accepted; neither reference is replaced.

- `dataset`: benchmark dataset, otherwise experiment dataset, otherwise `None`.
- `dataset_case_count`: that dataset's case count; zero for empty, `None` without context. It does not count evaluation entries.

Wrong types, including subclasses, raise `TypeError`. Nested contracts own validation, ordering, and case uniqueness. Reports neither infer provenance nor verify that metrics came from the evaluation. They do not reconcile classifications, recompute precision/recall/F1/accuracy, or rerun work. Reading metrics uses their original contract; unlabeled truth, NOT_EVALUABLE, positive-expectation FN, unclassified counts, and undefined values keep their meanings.

All four fields participate in equality. Findings/evidence, truth, cases, results, and context retain their references and order, with no copied collections, sorting, deduplication, report/benchmark ID, or independent name/count fields. Detector versions remain on configurations/findings; feature provenance remains on retained snapshots, with neither inferred from the other or flattened into lists.

This is a data contract: no execution, rendering, serialization, external access, persistence, timing, randomness, discovery, or registry lookup. CLI JSON is unchanged.

## End-to-end system validation

`run_end_to_end_validation(source, *, configuration, capture_session_id, ground_truth, experiment=None)` connects the pipeline, evaluation, metrics, and reporting. It requires a `PacketSource`, exact `DetectionConfiguration`, and explicit `GroundTruth`. Replay needs equivalent ordered observations and fresh sources: PCAP retains timestamps; acquisition-clock sources do not become reproducible through this wrapper.

Truth records become `ExpectedDetectionResult` in channel order, retaining targets: POSITIVE → positive, NEGATIVE → negative, absent records → no expectations. Targets must be independently supplied with packet position/time/source or flow session/window metadata. No labels/targets are inferred from findings or imported from a dataset.

The wrapper builds `DetectionSession`, then calls `run_detection_pipeline`, `evaluate_detection_result`, `calculate_detection_metrics`, and `EvaluationReport` once each, in that order. Each owner retains its detector, feature, matching, classification, and formula semantics.

`EndToEndValidationResult(pipeline_result, ground_truth, report)` retains the outputs. The report requires a standalone evaluation, metrics, and configuration. Packet evidence retains observations/outcomes; flow-volume evidence retains closed windows/snapshots and feature-contract provenance. Ordering is unchanged, with no parallel buffers or feature copies. Optional experiment context declares a dataset; it does not attest that cases ran individually or execute a benchmark.

Completion does not mean all expectations passed: FP, FN, unclassified entries, and undefined metrics remain visible. Failures propagate with no retry or partial success, retaining pipeline cleanup/finalization. Unsupported transports/non-initial IPv6 fragments retain admission errors; atomic fragments retain admission. Structured analysis failures remain findings where the pipeline can complete.

Tests cover real synthetic PCAP bytes across IPv4/IPv6 TCP/UDP, inactivity, directional features, packet-integrity failures, truth, and reports. Guards check one analysis per observation, extraction per closed window, pipeline-owned detectors, and one evaluation/metrics/report call. This boundary adds no parser, rendering, serialization, storage, networking, discovery, or timing.

## Performance benchmarking

`run_performance_benchmark(operation, *, configuration, clock=None)` times a synchronous zero-argument operation. `PerformanceBenchmarkConfiguration(operation_id, operation_version, measured_executions, warmup_executions=0, dataset=None, experiment=None, detection_configuration=None)` declares repetitions and context.

IDs/versions must be exact nonblank strings, unchanged. Measured counts are positive exact integers; warmups nonnegative exact integers, excluding booleans/coercible alternatives. Invalid configuration, operation, or clock references fail before execution.

Warmups call the operation once each, with no clock reads. Each measured call runs serially between start/end readings: exactly `warmup_executions + measured_executions` operation calls and two clock reads per measured call on success. No retries, calibration, hidden repeats, overhead subtraction, or concurrency. Timing includes the call and small wrapper overhead; aggregation and output disposal occur afterward. Warmup output disposal is untimed. Work and side effects inside the operation remain its responsibility.

The default clock is monotonic high-resolution `time.perf_counter`. Injected clocks must return finite exact floats in seconds with consistent origin and nondecreasing readings, including across repetitions. Negative origins/equal readings are valid; reversed/invalid readings or nonfinite elapsed differences raise immediately. Real timing is environment-sensitive. No rounding, formatting, throughput conversion, or machine-speed threshold is applied.

`PerformanceBenchmarkResult(configuration, elapsed_seconds)` retains an ordered tuple of finite nonnegative floats, one per measured call; zero is valid. Mutable collections/count mismatches are rejected. Properties `minimum_elapsed_seconds`, `maximum_elapsed_seconds`, `total_elapsed_seconds`, `mean_elapsed_seconds`, and `median_elapsed_seconds` derive from observations. Total uses `math.fsum`, mean total/count, median the standard library without reordering stored values. An unrepresentable total raises `OverflowError`. Equality includes configuration and ordered observations; no separate aggregates are stored.

Context requires exact dataset/experiment/detection-configuration types. Dataset and experiment dataset must compare equal when both are present; experiment operation ID/version must match the measured operation. These declarations neither bind nor verify code. Result `dataset` prefers the explicit dataset, then experiment dataset, else `None`; `dataset_case_count` is its count or `None`. An empty dataset has zero cases but its whole-dataset operation is still timed. Nested order, truth, configurations, and versions stay unchanged; feature provenance stays on original snapshots.

One elapsed observation means one operation call, whether it binds `run_detection_pipeline`, `run_end_to_end_validation`, `DetectionSession.run_packets`, `DetectionSession.run_closed_flows`, or `run_detection_benchmark`. Operation identity must describe that scope. Timing never independently traverses cases, inspects findings, invokes detectors, extracts features, evaluates results, or calculates detection metrics.

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

Returned iterators/awaitables are not consumed/awaited. Outputs are neither retained nor interpreted as success/failure; retain them explicitly if needed. Full PCAP operations need a fresh `PcapPacketSource` per call; setup inside the callable is timed. Exhausted sources retain their errors, with no reset or equivalent-workload check.

Operation/clock failures propagate and stop execution, with no partial summary, fabricated end reading, or failed-call elapsed value. Earlier side effects remain. Detection benchmarking executes ordered cases; end-to-end validation composes the system; performance benchmarking times the chosen boundary. It adds no optimization, detailed profiling, storage, serialization, external access, randomness, discovery, or ML/MLOps.

## Operational errors and diagnostics

`diagnose_error(error, *, operation_id, message, context=())` describes an already-caught `Exception` as `OperationalDiagnostic(category, operation_id, message, context)`. It neither runs/catches operations, wraps or mutates exceptions, nor returns execution results. Original propagation/handling remains with the operation's caller.

`OperationalErrorCategory` classifies exact known exception types:

| Category | Exceptions |
| --- | --- |
| `CAPTURE_FAILURE` | `CaptureError` |
| `PACKET_ANALYSIS_FAILURE` | Packet-analysis/outcome, Ethernet/IP/transport/ICMP decoding, checksum validation |
| `FLOW_PROCESSING_FAILURE` | Flow identity, direction, tracking, statistics, coordination, window, feature values |
| `DETECTION_FAILURE` | Packet integrity, flow volume, TCP control, finding contracts |
| `UNCLASSIFIED_FAILURE` | Others, including plain `TypeError`, `ValueError`, `OverflowError`, `RuntimeError`, and unknown subclasses |

Categories describe exception domains, not root cause, security meaning, or recoverability. Generic evaluation/configuration errors remain unclassified; diagnosis does not infer origin from text, stacks, or cause chains. `operation_id` names the boundary. Type, arguments, traceback, cause, context, and cleanup-error precedence remain untouched.

Operation IDs/messages must be exact nonblank strings, unchanged. Supply a message appropriate for disclosure: exception text, arguments, representations, tracebacks, packets, paths, and environment data are never copied automatically. No diagnostic ID, timestamp, exception object, handle, or severity is stored.

Context must be an exact tuple of exact immutable `CaptureSource`, `FlowObservationWindowKey`, `DetectionConfiguration`, `DetectionDataset`, `DetectionExperiment`, `DetectorVersion`, or `FeatureContractVersion` objects. Exact references, order, duplicates, and empty context are retained. Text entries, mappings, mutable collections, findings, outcomes, snapshots, and raw packets are rejected. Context declares associations; it does not discover/reconcile provenance. Nested contracts own their semantics; equality covers all four diagnostic fields.

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

This runs the pipeline once. Diagnosis adds no upstream execution, evaluation, metrics, report, benchmark, clock read, or retry. Invalid diagnostic arguments raise validation errors; `KeyboardInterrupt`/`SystemExit` are outside the `Exception` contract. A `PacketAnalysisOutcome` is a structured result, not an accepted exception; its failure classification/description remain authoritative.

Findings, evaluation outcomes, and metric semantics—including MATCH, NO_MATCH, NOT_EVALUABLE, TP/FP/FN/TN, undefined and unclassified values—are unchanged. Diagnostic work placed inside a timed callable counts as part of that operation. The CLI uses diagnosis only in its existing `CaptureError` handler. No logging, telemetry, rendering, serialization, persistence, external access, randomness, metadata discovery, or ML/MLOps is added; diagnostics never fabricate results, alerts, incidents, or attack classifications.
