# NIDS-NetOps

NIDS-NetOps is a network intrusion detection system project intended for production-quality engineering and reproducible security research. Its planned scope spans packet observation, protocol analysis, flow tracking, multiple detection methods, evidence management, and actionable alerts.

## Current status

The accepted baseline includes capture contracts, synchronous ingestion, an iterable packet source, classic PCAP file ingestion, Ethernet II/IPv4/TCP/UDP/ICMPv4 decoding and checksum validation, single-packet analysis, and immutable failure-preserving packet-analysis outcomes. IPv4 and IPv6 TCP/UDP flow analysis provides canonical identity and direction, coordinated raw flow state, directional TCP control observations, protocol-neutral observation windows, and immutable typed feature snapshots. The application layer composes one packet-source run with analysis and observation-window lifecycle management and synchronously emits closed windows. Detection includes packet-local deterministic integrity/structural evaluation plus deterministic flow-volume/rate and raw TCP control-counter threshold evaluation, all with exact raw evidence and bounded interpretations. Completed detector evaluations can be normalized into immutable common findings without replacing their detector-specific evidence or interpretation.

Canonical `FlowIdentity` values support same-family IPv4 and IPv6 packed endpoints, with validated textual construction through the standard library. Ethernet IPv6 analysis includes the fixed base header, declared-payload bounds, validated supported extension chains, Fragment Header semantics, and the common ICMPv6 header. Validated IPv6 transport boundaries now feed the existing TCP/UDP decoders and immutable semantic models. Non-first fragments produce neither TCP nor UDP; first fragments require the complete indicated TCP header or complete declared UDP datagram. No reassembly or transport checksum validation is performed for IPv6. Valid IPv6 TCP/UDP results now enter the existing canonical flow identity, direction, tracker, coordinator, and observation-window lifecycle. IPv4 and IPv6 TCP/UDP share the existing generic volume, directional, packet-size, duration, rate, and inter-arrival feature layer, with applicable directional TCP control statistics. Extraction consumes coordinated flow state without packet parsing or detector execution. The existing flow-volume thresholds apply to IPv4 and IPv6 TCP/UDP, and TCP-control thresholds apply to TCP in both families. Packet-integrity decisions use the existing packet-analysis outcome classifications. Detection remains explicitly invoked and introduces no IPv6-specific attack semantics, reassembly, or full IPv6 attack coverage.

The application package also exposes deterministic packet and closed-flow detector orchestration. It returns immutable finding tuples, preserves all detector decisions and exact evidence/configuration references, runs volume before TCP control for TCP windows, and runs only volume for UDP windows. Failures propagate without retry or partial results. A frozen application `DetectionSession` retains existing detector configurations and explicitly executes ordered batches of packet outcomes or closed-flow feature snapshots through that same orchestration. It preserves finding order and duplicates, retains no execution history, and does not enable detection inside capture/observation sessions.

The opt-in `run_detection_pipeline()` composes an existing packet source, one packet analysis outcome per observation, packet detection, the shared flow-observation lifecycle, and feature extraction and detection for each closed window. Callers supply a `DetectionSession`; the immutable result groups packet findings in observation order and flow findings in closure order. IPv4 and IPv6 use the same path. Direct capture/flow-observation calls remain detector-free. No new detector, reassembly, correlation, or alerting is introduced. See the [application pipeline contract](src/application/README.md#explicit-detection-pipeline) for admission and failure boundaries.

The capture package now provides `PcapPacketSource` for incremental classic PCAP 2.4 ingestion in both byte orders and microsecond/nanosecond formats. Packet bytes, lengths, order, and portable link codes are preserved. Timestamps use canonical UTC; sub-microsecond nanosecond precision is explicitly truncated to the existing timestamp type. Malformed records raise capture errors. The source works with the existing opt-in pipeline without changing analysis or detection. See the [PCAP input contract](src/capture/README.md#classic-pcap-packet-source) for format and lifecycle limits.

The application `run_capture_execution(source, consumer)` boundary exposes ordered packet-analysis outcomes without requiring callers to manage source lifecycle. It delegates to `consume()`, analyzes each observation once, delivers both successful and failed outcomes, and retains no result history. The detection pipeline uses this boundary; standalone flow observation shares its execution primitive while preserving its existing analysis errors. Capture execution itself remains detector-free. See the [capture execution contract](src/application/README.md#capture-execution).

The complete deterministic suite contains 1278 passing tests. Code uses only the Python standard library and supports Python 3.9 or newer. Live network capture, application parsing, reassembly, TCP connection state, other detector families, automatic detector wiring into capture sessions, machine learning, storage, and graphical interfaces are not implemented. Findings do not establish alerting, correlation, risk, incident, persistence, or response semantics. Packaging and deployment remain undecided. Production quality is a design objective, not a claim of operational readiness.

The explicit [detection evaluation boundary](src/application/README.md#detection-result-evaluation) compares an existing `DetectionPipelineResult` with immutable, independently supplied packet/flow expectations. MATCH is positive, NO_MATCH is negative, and NOT_EVALUABLE stays distinguishable. Evaluation retains auditable TP/FP/FN/TN classifications without running the pipeline again; it introduces no datasets and does not change CLI output.

The in-memory [ground-truth contract](src/application/README.md#explicit-ground-truth) represents externally supplied positive or negative truth about those existing targets. Unspecified targets remain unlabeled. It stores no detector result and performs no execution or automatic conversion into evaluation expectations.

The pure [evaluation metrics boundary](src/application/README.md#detection-evaluation-metrics) counts the existing evaluation classifications separately for packets and flows and derives precision, recall, F1, and accuracy. Undefined ratios are `None`; unclassified entries are counted separately and excluded from binary denominators. Metrics neither reinterpret detector decisions nor rerun evaluation.

The [dataset representation](src/application/README.md#detection-dataset-representation) groups an explicitly named, ordered tuple of immutable cases. Each case retains an existing packet/flow target and optional externally supplied ground truth. Construction performs no loading, execution, evaluation, or metrics calculation.

The explicit [benchmark framework](src/application/README.md#deterministic-benchmark-execution) invokes a supplied case operation once per dataset case in source order, preserving optional evaluation and metrics values in immutable results. It is synchronous and fail-fast, and adds no performance measurement, dataset loading, or experiment tracking.

The [experiment definition](src/application/README.md#reproducible-experiment-definition) retains an explicit experiment ID, the immutable dataset, and an explicit benchmark-operation ID/version. It describes intended work without retaining a callable or results, resolving operations, or executing anything.

The [configuration contract](src/application/README.md#deterministic-configuration-representation) composes existing immutable detector configurations and a positive observation-window inactivity timeout. It represents and validates settings without executing, loading, or persisting them.

## Command-line execution

Run a local classic PCAP through the existing detection pipeline with explicit configuration:

```sh
PYTHONPATH=src python3 -B -m application input.pcap \
  --capture-session-id offline-example \
  --inactivity-timeout-microseconds 5000000 \
  --packet-detector-id packet-integrity --packet-detector-version 1 \
  --volume-detector-id flow-volume-threshold --volume-detector-version 1 \
  --volume-metric packet_count --volume-threshold 100 \
  --tcp-detector-id tcp-control-threshold --tcp-detector-version 1 \
  --tcp-metric forward_syn_count --tcp-threshold 20
```

These values are explicit examples, not canonical detector defaults or attack criteria. All shown settings are required; `--help` lists supported metrics. TCP configuration is supplied for every run, but UDP still receives only volume detection. Timeout units are integer microseconds.

Successful execution writes one JSON object to stdout with ordered `packet_findings` and `flow_findings` arrays and exits 0, including when findings match or packet analysis reports a failure outcome. Capture errors exit 1 with `{"error":"capture_error"}` on stderr and no result. Invalid arguments exit 2 through argparse; other pipeline exceptions propagate. The [CLI contract](src/application/README.md#command-line-adapter) defines the evidence projection and remaining error behavior. Output contains capture timestamps, not execution-time metadata or automatically derived file paths.

This is an opt-in adapter over the existing pipeline. It adds no live capture, PCAPNG, reassembly, new detector, correlation, persistence, or alerting. Source and flow ordering rules remain authoritative, including rejection of decreasing admitted-flow timestamps.

## Repository structure

| Path | Responsibility |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Subsystem map, planned data flow, ownership boundaries, and design constraints. |
| [docs/development.md](docs/development.md) | Contribution discipline, validation expectations, and research reproducibility. |
| [src/capture/](src/capture/README.md) | Packet observation and capture-source contracts, packet ingestion, and future packet acquisition. |
| [src/analysis/](src/analysis/README.md) | Layer 2–4 decoding, checksum validation, packet/flow analysis, raw statistics, and explicit feature families. |
| [src/application/](src/application/README.md) | Capture-session composition and deterministic packet/closed-flow detector orchestration. |
| [src/detection/](src/detection/README.md) | Three deterministic detector contracts and their common immutable finding boundary. |
| [src/enrichment/](src/enrichment/README.md) | Future threat-intelligence context. |
| [src/events/](src/events/README.md) | Future correlation, risk scoring, and alert lifecycle. |
| [src/storage/](src/storage/README.md) | Future event persistence and PCAP evidence management. |
| [src/integrations/](src/integrations/README.md) | Future dashboard and external-system adapters. |
| [tests/](tests/README.md) | Capture and analysis unit tests, accumulation and feature tests, and automated verification strategy. |
| [labs/](labs/README.md) | Isolated VM security-testing strategy and reproducible experiment requirements. |
| [.gitignore](.gitignore) | Keeps local environments and generated or sensitive artifacts out of version control. |

Every established directory contains documentation defining its purpose. Additional modules, configuration directories, fixtures, and tooling should be introduced with the task that needs them; no empty scaffolding is required.

## Architectural direction

Start with one cohesive system organized into explicit internal modules. Module boundaries do not imply separate services, processes, queues, or deployment units. Capture supplies packet observations; analysis produces protocol, flow, and feature observations; detectors produce findings; event processing correlates findings, assesses risk, and manages alerts. Enrichment provides external context, storage preserves records and evidence, and integration adapters expose supported views to external consumers.

The [architecture guide](docs/architecture.md) defines all 21 subsystem boundaries. Capture primitives, the analysis components described above, capture-session composition, three deterministic detector contracts, common findings, and detector orchestration are implemented; other detection and downstream records remain conceptual.

## Development philosophy

Build in small, verifiable increments. Prefer explicit ownership, bounded resource use, testable modules, reproducible experiments, and evidence-backed detection decisions. Treat network inputs as untrusted and traffic evidence as potentially sensitive. Add dependencies only when an approved implementation task needs them and the choice is justified.

Source code must contain no comments unless a comment is genuinely necessary to explain a non-obvious technical reason. Keep architecture and rationale in documentation.

See the [development guide](docs/development.md), [test commands and strategy](tests/README.md), and [VM-lab strategy](labs/README.md) before implementing a subsystem. The [capture boundary](src/capture/README.md) documents the observation contract.
