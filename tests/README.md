# Automated testing strategy

This directory contains 325 standard-library `unittest` tests covering capture contracts and ingestion, the iterable source, structural decoders and checksum validators, packet analysis, flow identity/direction/tracking, raw statistics through directional inter-arrival accumulation, and the implemented volume, packet-size, duration, rate, and global inter-arrival feature families. It also establishes verification responsibilities for later subsystems. The tests use synthetic byte strings and deterministic in-memory sources, with no captured traffic or external services.

Run the full suite from the repository root with Python 3.9 or newer:

```sh
PYTHONPATH=src python3 -B -m unittest discover -s tests -v
```

Verify the package exports independently:

```sh
PYTHONPATH=src python3 -B -c 'import analysis, capture; print("analysis and capture imports OK")'
```

No installation or third-party dependencies are required. `src` is the import root; distribution packaging is deferred. No formatter, linter, or static type checker is configured yet.

| Future test area | Purpose |
| --- | --- |
| Unit | Verify parsing, flow transitions, feature calculations, detector decisions, scoring, and alert transitions in isolation. |
| Contract | Verify producer/consumer agreement, invalid inputs, schema evolution, and evidence references. |
| Integration | Verify module interactions, offline replay, persistence, and adapters with controlled dependencies. |
| Regression | Preserve reproducible examples of resolved bugs and validated detection scenarios. |
| Robustness | Exercise malformed, truncated, fragmented, duplicated, and out-of-order traffic plus resource exhaustion limits. |
| Performance | Measure throughput, latency, memory use, and loss against recorded hardware, configuration, and workloads. |

Use deterministic clocks and seeded randomness where relevant. Test flow expiration, late events, missing enrichment, storage failures, and alert deduplication when those behaviors exist. Routine automated tests should not require live capture privileges, Internet access, or running VMs.

Small synthetic or sanitized fixtures may be committed when their provenance, expected results, and redistribution permission are documented. Raw packet captures are ignored by default; review any narrowly scoped fixture exception before adding one. Keep large datasets and generated reports in external storage or the ignored root `artifacts/` area, created only when needed.

VM experiments belong to [labs](../labs/README.md). Portable checks derived from a lab result should become automated regression tests when practical. The current test count records the validated baseline; it is not a coverage target.
