# Automated testing strategy

The current suite contains 1542 standard-library `unittest` tests. It covers capture/source contracts and classic PCAP input; Ethernet, IPv4/IPv6 and transport analysis; flow identity, lifecycle, statistics and features; detector configurations, predicates and findings; evaluation, truth, metrics and reporting; datasets, experiments, version references, end-to-end composition, performance methodology, diagnostics, and the CLI.

The verified interpreter is Python 3.9.6. Run from the repository root:

```sh
PYTHONPATH=src python3 -B -m unittest discover -s tests
```

Verify every declared package export:

```sh
PYTHONPATH=src python3 -B -c 'import analysis, application, capture, detection; packages = (analysis, application, capture, detection); assert all(hasattr(package, name) for package in packages for name in package.__all__); print("all public exports resolve")'
```

No installation, third-party dependencies, network services, live-capture privileges, or running VMs are required. Fixtures use synthetic bytes and explicit observations; PCAP and CLI tests create temporary local files. Performance tests use controlled clocks for exact timing assertions and do not set machine-speed thresholds. The suite checks normal results, ordering, immutable inputs/results, malformed inputs, failure propagation, and execution counts.

| Existing verification area | Representative tests |
| --- | --- |
| Capture and lifecycle | [PCAP source](test_pcap_packet_source.py), [capture execution](test_capture_execution.py). |
| Protocol and fragment boundaries | [packet outcomes](test_packet_analysis_outcome.py), [IPv6 transport](test_ipv6_transport.py), [fragmentation](test_ipv6_fragmentation.py), [ICMPv6](test_icmpv6.py). |
| Flow and feature semantics | [observation windows](test_flow_observation_window.py), [snapshots](test_flow_feature_snapshot.py), [IPv6 features](test_ipv6_features.py). |
| Detection and application composition | [orchestration](test_detector_orchestration.py), [pipeline](test_detection_pipeline.py), [end-to-end validation](test_end_to_end_validation.py). |
| Evaluation and presentation-neutral results | [evaluation](test_detection_evaluation.py), [metrics](test_detection_metrics.py), [reporting](test_evaluation_report.py). |
| Dataset and execution methodology | [datasets](test_detection_dataset.py), [experiments](test_detection_experiment.py), [case benchmarks](test_detection_benchmark.py), [performance benchmarks](test_performance_benchmark.py). |
| Operational boundaries | [diagnostics](test_operational_diagnostics.py), [CLI](test_cli.py). |

Tests verify implemented predicates and composition, not production attack-detection coverage. There are no CPU/memory profiling or throughput acceptance guarantees. Future tests for storage, enrichment, alerting, deployment, or resource exhaustion require those capabilities to be implemented first. Do not manufacture tests to meet a count or weaken failures to match documentation.

Small synthetic or sanitized fixtures require documented provenance and redistribution permission. Raw captures are ignored by default; review any fixture exception before committing it. Keep credentials, large datasets, and generated reports out of version control. The ignored root `artifacts/` location is a development convenience, not an implemented storage service.

Authorized lab methodology belongs to [labs](../labs/README.md). Portable checks derived from future lab results should become regressions where appropriate. The test count records the verified baseline and is not a coverage target.
