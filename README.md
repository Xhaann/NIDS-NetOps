# NIDS-NetOps

NIDS-NetOps is a deterministic network intrusion detection research implementation. It makes packet interpretation, flow measurements, detector decisions, and evaluation against explicit expectations inspectable through separate typed contracts. The current offline path processes local classic PCAP input with the Python standard library; no external runtime service is required.

The implementation provides packet-integrity detection, closed-flow volume/rate thresholds, and TCP-control counter thresholds for supported IPv4/IPv6 traffic. Findings describe those specific predicates. They are not alerts, incidents, risk scores, or proof of an attack. This repository is not a production SOC, SIEM, or deployable IDS appliance.

## Current architecture

Capture supplies immutable `PacketObservation` values. Analysis produces `PacketAnalysisOutcome` values, retaining recognized non-success outcomes. `run_detection_pipeline()` uses `DetectionSession` for packet detection and for detection over closed flow-window features, returning ordered packet and flow findings in `DetectionPipelineResult`.

Explicit ground truth supplies evaluation expectations. `evaluate_detection_result()` compares completed findings against them; `calculate_detection_metrics()` aggregates the resulting classifications. `EvaluationReport` preserves already-computed results and metrics without rendering them. `run_end_to_end_validation()` composes these existing operations through report construction.

Supporting boundaries remain distinct:

- `DetectionDataset` defines ordered evaluation cases; `run_detection_benchmark()` invokes a supplied operation once per case.
- `DetectionExperiment` describes a dataset and an explicit operation ID/version without executing it.
- `DetectionConfiguration`, `DetectorVersion`, and `FeatureContractVersion` preserve explicit settings and provenance.
- `run_performance_benchmark()` measures a supplied operation with explicit repetitions and warmups, preserving ordered elapsed observations and summary statistics.
- `OperationalDiagnostic` describes a failure; `diagnose_error()` conservatively classifies a supplied exception without catching, retrying, or logging an operation.

The [architecture reference](docs/architecture.md) explains the actual execution path, ownership, evaluation rules, reproducibility limits, and preserved boundaries. The [application API guide](src/application/README.md) documents public signatures and failure behavior.

## Protocol scope

Packet analysis supports Ethernet II carrying IPv4 or IPv6. IPv4 includes TCP, UDP, and ICMPv4 structural decoding and checksum validation. IPv6 includes the fixed header, bounded Hop-by-Hop/Routing/Destination Options/Fragment header traversal, packet-local fragmentation information, TCP/UDP headers, and the common four-byte ICMPv6 header. IPv6 transport and ICMPv6 checksum validation, ICMPv6 subtype interpretation, and Neighbor Discovery are not implemented.

Canonical bidirectional flows accept decoded IPv4/IPv6 TCP and UDP. They accumulate directional statistics, packet sizes, inter-arrival measurements, and TCP-control counters, with observation-driven inactivity closure. TCP receives volume then TCP-control detection; UDP receives volume detection only. Analysis of ICMP or an opaque upper-layer payload does not make it an admissible flow. The pipeline propagates existing flow-admission errors. See [protocol and fragment limits](docs/architecture.md#protocol-coverage-and-admission) before choosing inputs.

## Run and verify

The verified interpreter is Python 3.9.6. From the repository root, no installation or third-party package is needed:

```sh
PYTHONPATH=src python3 -B -m unittest discover -s tests
PYTHONPATH=src python3 -B -m application --help
```

The current suite contains 1582 tests. Fixtures are synthetic; PCAP tests create local temporary files. Tests use controlled clocks for timing semantics rather than machine-speed thresholds.

To run detection, supply your own local classic PCAP file in place of `input.pcap`:

```sh
PYTHONPATH=src python3 -B -m application input.pcap \
  --capture-session-id review-session \
  --inactivity-timeout-microseconds 5000000 \
  --packet-detector-id packet-integrity \
  --packet-detector-version 1 \
  --volume-detector-id flow-volume-threshold \
  --volume-detector-version 1 \
  --volume-metric packet_count \
  --volume-threshold 100 \
  --tcp-detector-id tcp-control-threshold \
  --tcp-detector-version 1 \
  --tcp-metric forward_syn_count \
  --tcp-threshold 20
```

These are explicit example settings, not recommended operational thresholds. All shown options are required exactly once, including TCP settings for UDP-only input. Repeated settings are rejected rather than overriding earlier values. Blank/NUL paths and malformed numeric arguments fail before acquisition; path existence, readability, and PCAP validation remain owned by the capture reader. `--help` lists supported metrics, units, and exit behavior using fixed-width formatting independent of terminal width. The CLI runs the detection pipeline once and writes one JSON object with `packet_findings` and `flow_findings`; it does not run evaluation or render `EvaluationReport`.

Successful execution exits 0 regardless of detector decisions. Invalid arguments/configuration exit 2. A `CaptureError` exits 1 with `{"error":"capture_error"}` on stderr. Other execution/output exceptions propagate from `main()` without a synthetic result or retry. The [CLI contract](src/application/README.md#command-line-adapter) describes the evidence projection and error boundaries.

## Reproducibility and limits

Equivalent explicit observations, configuration, ground truth, and caller operations preserve defined ordering and value semantics. Detector and feature versions are explicit strings, not discovered from Git or packages. PCAP preserves recorded timestamps; `IterablePacketSource` uses acquisition-time timestamps, so deterministic replay requires explicit observations or PCAP. Performance timing is environment-sensitive and is not claimed to be bit-for-bit reproducible. Warmups and measured repetitions are explicit; no retries or hidden executions are added.

The current implementation has no live network capture, PCAPNG, fragment/stream reassembly, application-protocol parsing, TCP connection state machine, autonomous response, blocking, firewall/SIEM integration, threat intelligence, correlation, alert management, or persistence. In-memory results can grow with input size; operational resource hardening and deployment are not established. Benchmarking measures elapsed execution, not CPU/memory use or function-level profiling, and does not optimize algorithms or store results.

ML/MLOps is not implemented: there are no models, training, inference, feature stores, model registries, drift detection, serving, or experiment tracking infrastructure. Any future work must build on the explicit feature and evaluation contracts; it is not part of the current detection path.

## Repository guide

| Documentation | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Current data flow, semantics, ownership, and limitations. |
| [Application](src/application/README.md) | Execution, evaluation, reporting, datasets, benchmarking, and diagnostics APIs. |
| [Capture](src/capture/README.md) | Sources, observations, ingestion, and classic PCAP lifecycle. |
| [Analysis](src/analysis/README.md) | Protocol models, flow lifecycle, raw statistics, and feature contracts. |
| [Detection](src/detection/README.md) | Detector predicates, configurations, evidence, and findings. |
| [Tests](tests/README.md) | Verification scope and commands. |
| [Development](docs/development.md) | Scope, source policy, and evidence discipline. |
| [Labs](labs/README.md) | Planned authorized lab methodology, not an implemented runtime. |

The `enrichment`, `events`, `storage`, and `integrations` directories contain future responsibility notes, not implemented services. Documentation lives in Markdown; source follows the repository's zero-comment rule.
