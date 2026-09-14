# NIDS-NetOps

NIDS-NetOps is a deterministic network intrusion detection research implementation. It analyzes local classic PCAP traffic, checks packet integrity, applies volume/rate and TCP-control counter thresholds to closed flows, and evaluates findings against supplied expectations. It uses only the Python standard library. Findings are not alerts, incidents, risk scores, or proof of attack; this is not a production SOC, SIEM, or deployable IDS appliance.

## Current architecture

Capture → packet analysis → flow/features → detection → evaluation against ground truth → metrics/reporting.

Capture supplies immutable `PacketObservation` values. Analysis returns `PacketAnalysisOutcome`, including recognized failures. `run_detection_pipeline()` uses `DetectionSession` to produce ordered packet and closed-flow findings in `DetectionPipelineResult`.

For incremental processing of large captures, [`run_detection_stream()`](src/application/README.md#incremental-detection-finding-delivery) delivers those findings to synchronous packet and flow consumers without accumulating a result history. The collecting pipeline uses this same lifecycle. Active analysis remains bounded by the window limit; consumer-retained findings can still retain packet/window evidence. Delivery adds no persistent archival, output queue, or serialization. The CLI and evaluation/reporting path continue to collect complete results.

`evaluate_detection_result()` compares findings with ground-truth expectations; `calculate_detection_metrics()` aggregates classifications. `EvaluationReport` holds computed results and metrics. `run_end_to_end_validation()` connects these steps through report construction.

[`IncrementalDetectionEvaluator`](src/application/README.md#incremental-detection-evaluation) evaluates the same finding objects downstream of the detection stream, using explicit existing expectations. It delivers settled entries without collecting a complete detection result. Exact historical matching can defer a flow suffix until explicit finalization, so memory is proportional to expectations plus that suffix, not necessarily constant. Metrics and reporting remain separate collecting boundaries.

Supporting contracts:

- `DetectionDataset`: ordered evaluation cases; `run_detection_benchmark()` calls an operation once per case.
- `DetectionExperiment`: dataset and operation ID/version, with no execution.
- [ResearchExample and ResearchDataset](src/research/README.md): projections, optional research truth, and ordered examples, independent of detector/evaluation targets.
- `DetectionConfiguration`, `DetectorVersion`, `FeatureContractVersion`: settings and version provenance.
- `run_performance_benchmark()`: configured warmups, repetitions, ordered elapsed times, and summary statistics.
- `OperationalDiagnostic` and `diagnose_error()`: conservative exception classification, with no catching, retrying, or logging of operations.

See the [architecture reference](docs/architecture.md) for ownership and limits, and the [application API guide](src/application/README.md) for signatures and failure behavior.

## Protocol scope

- **Packets:** Ethernet II with IPv4/IPv6. IPv4 supports TCP, UDP, and ICMPv4 decoding and checksum validation. IPv6 supports its fixed header, bounded Hop-by-Hop/Routing/Destination Options/Fragment traversal, packet-local fragmentation information, TCP/UDP headers, and the common four-byte ICMPv6 header.
- **Flows:** canonical bidirectional IPv4/IPv6 TCP/UDP, with directional statistics, packet sizes, inter-arrival measurements, TCP-control counters, and observation-driven inactivity closure. Active windows are bounded at 1,024 by default; new identities at capacity close the least recently observed window through the existing lifecycle. TCP runs volume then TCP-control detection; UDP runs volume detection only.
- **TCP streams:** independent directional buffers retain up to 64 KiB, append contiguous payload, suppress verifiable identical retransmissions, and expose gaps/overlaps as unavailable. Consumption reclaims framed bytes when space is needed. See [stream contract](src/analysis/README.md#bounded-directional-tcp-stream-observation).
- **LDAP:** bounded plaintext LDAP message framing, operation identification, and immutable flow observation counters for TCP port 389. Incomplete and malformed candidates remain observations, with no LDAP attack detector. Incremental stream framing consumes complete messages and retains incomplete suffixes across contiguous TCP observations, with bounded storage and no malformed-boundary resynchronization. Bounded [request/response correlation](src/analysis/README.md#bounded-ldap-requestresponse-correlation) associates compatible opposite-direction messages within one flow/window and preserves unmatched or ambiguous observations. Per-request [termination summaries](src/analysis/README.md#bounded-ldap-request-termination-summaries) retain exact associated-response counts and observed terminal references without response history. See [LDAP scope](src/analysis/README.md#ldap-protocol-observations).
- **Limits:** no IPv6 transport/ICMPv6 checksum validation, ICMPv6 subtype interpretation, or Neighbor Discovery. ICMP and opaque upper-layer analysis do not qualify for flow admission; the pipeline propagates admission errors. See [protocol and fragment limits](docs/architecture.md#protocol-coverage-and-admission).

## Run and verify

Verified with Python 3.9.6. From the repository root, no installation or third-party packages are needed:

```sh
PYTHONPATH=src python3 -B -m unittest discover -s tests
PYTHONPATH=src python3 -B -m application --help
```

The tests use synthetic fixtures, temporary PCAP files, and controlled clocks rather than machine-speed thresholds.

Replace `input.pcap` with your local classic PCAP file:

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

These are example settings, not operational recommendations. Every option shown is required exactly once, including TCP settings for UDP-only input. Repeated settings, blank/NUL paths, and malformed numeric arguments fail before acquisition. Capture owns path existence, readability, and PCAP validation. Fixed-width `--help` lists metrics, units, and exit behavior.

Optional `--max-active-windows N` sets a positive active-flow limit (default 1,024). At capacity, the least recent last-packet timestamp wins, with creation sequence breaking ties. The resulting findings expose the existing closure field as `"capacity"`. This bounds active analysis state; returned findings and caller-retained windows still grow with input. Capacity boundaries can split a conversation and change per-window counts, so choose and retain the limit as part of the replay configuration.

The CLI runs one pipeline and writes one JSON object containing `packet_findings` and `flow_findings`; it performs no evaluation or report rendering.

- **Exit 0:** success, regardless of detector decisions.
- **Exit 2:** invalid arguments/configuration.
- **Exit 1:** `CaptureError`, with `{"error":"capture_error"}` on stderr.
- Other execution/output exceptions propagate from `main()`; no synthetic result or retry.

See the [CLI contract](src/application/README.md#command-line-adapter) for evidence fields and error boundaries.

## Reproducibility and limits

- **Replay:** equivalent observations, configuration, ground truth, and caller operations retain defined order and value semantics. Versions are explicit strings, not discovered from Git or packages. PCAP retains recorded timestamps; `IterablePacketSource` timestamps acquisition. Repeatable replay therefore needs explicit observations or PCAP.
- **Timing:** benchmarks use configured warmups/repetitions with no hidden executions or retries. Elapsed measurements depend on the environment; they are not bit-for-bit reproducible, CPU/memory measurements, or function-level profiles. Benchmarking neither optimizes algorithms nor stores results.
- **Runtime scope:** no live capture, PCAPNG, fragment/general TCP reassembly, general application-protocol semantics, TCP connection state machine, autonomous response, blocking, firewall/SIEM integration, threat intelligence, correlation, alert management, or persistence. In-memory results grow with input; deployment and operational resource hardening are not established.
- **Research inputs:** the [ML feature projection](src/ml/README.md) contains 49 ordered canonical numerical inputs with explicit version and availability semantics. Labels and detector outcomes stay outside the representation; projection stays separate from the deterministic detection path. Research datasets provide in-memory membership only. Models, preprocessing, dataset loading, splitting, training, inference, feature stores, model registries, drift detection, serving, and experiment tracking infrastructure are unimplemented.

## Repository guide

| Documentation | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Architecture and system flow |
| [Application](src/application/README.md) | Application APIs and evaluation |
| [Capture](src/capture/README.md) | Capture and PCAP handling |
| [Analysis](src/analysis/README.md) | Protocol and flow analysis |
| [Detection](src/detection/README.md) | Detector behavior and findings |
| [ML inputs](src/ml/README.md) | ML feature inputs |
| [Tests](tests/README.md) | Test scope and commands |
| [Development](docs/development.md) | Scope, source policy, and evidence |
| [Labs](labs/README.md) | Planned authorized lab methodology |

`enrichment`, `events`, `storage`, and `integrations` contain future responsibility notes, not services. Documentation is Markdown; source follows the zero-comment rule.
