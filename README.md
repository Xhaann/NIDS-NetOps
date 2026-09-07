# NIDS-NetOps

NIDS-NetOps is a network intrusion detection system project intended for production-quality engineering and reproducible security research. Its planned scope spans packet observation, protocol analysis, flow tracking, multiple detection methods, evidence management, and actionable alerts.

## Current status

The accepted baseline includes capture contracts, synchronous ingestion, an iterable packet source, Ethernet II/IPv4/TCP/UDP/ICMPv4 decoding and checksum validation, single-packet analysis, and immutable failure-preserving packet-analysis outcomes. IPv4 TCP/UDP flow analysis provides canonical identity and direction, coordinated raw flow state, directional TCP control observations, protocol-neutral observation windows, and immutable typed feature snapshots. The application layer composes one packet-source run with analysis and observation-window lifecycle management and synchronously emits closed windows. Detection includes packet-local deterministic integrity/structural evaluation plus deterministic flow-volume/rate and raw TCP control-counter threshold evaluation, all with exact raw evidence and bounded interpretations.

The complete deterministic suite contains 504 passing tests. Code uses only the Python standard library and supports Python 3.9 or newer. Network capture, PCAP ingestion, application parsing, reassembly, TCP connection state, other detector families, detector orchestration, machine learning, storage, and interfaces are not implemented. Packaging and deployment remain undecided. Production quality is a design objective, not a claim of operational readiness.

## Repository structure

| Path | Responsibility |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Subsystem map, planned data flow, ownership boundaries, and design constraints. |
| [docs/development.md](docs/development.md) | Contribution discipline, validation expectations, and research reproducibility. |
| [src/capture/](src/capture/README.md) | Packet observation and capture-source contracts, packet ingestion, and future packet acquisition. |
| [src/analysis/](src/analysis/README.md) | Layer 2–4 decoding, checksum validation, packet/flow analysis, raw statistics, and explicit feature families. |
| [src/application/](src/application/README.md) | Synchronous composition of one capture-source run with packet analysis and observation-window lifecycle. |
| [src/detection/](src/detection/README.md) | Deterministic flow and TCP control-counter threshold detection and future detector-specific contracts. |
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

The [architecture guide](docs/architecture.md) defines all 21 subsystem boundaries. Capture primitives, the analysis components described above, the narrow capture-session composition boundary, and two deterministic threshold detector contracts are implemented; other detection and downstream records remain conceptual.

## Development philosophy

Build in small, verifiable increments. Prefer explicit ownership, bounded resource use, testable modules, reproducible experiments, and evidence-backed detection decisions. Treat network inputs as untrusted and traffic evidence as potentially sensitive. Add dependencies only when an approved implementation task needs them and the choice is justified.

Source code must contain no comments unless a comment is genuinely necessary to explain a non-obvious technical reason. Keep architecture and rationale in documentation.

See the [development guide](docs/development.md), [test commands and strategy](tests/README.md), and [VM-lab strategy](labs/README.md) before implementing a subsystem. The [capture boundary](src/capture/README.md) documents the observation contract.
