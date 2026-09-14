# Automated testing strategy

The suite uses standard-library `unittest` tests. It covers capture/source contracts and classic PCAP input; Ethernet, IPv4/IPv6 and transport analysis; flow identity, lifecycle, statistics and features; detector configurations, predicates and findings; evaluation, truth, metrics and reporting; datasets, experiments, version references, end-to-end composition, performance methodology, diagnostics, and the CLI.

The verified interpreter is Python 3.9.6. Run from the repository root:

```sh
PYTHONPATH=src python3 -B -m unittest discover -s tests
```

Verify every declared package export:

```sh
PYTHONPATH=src python3 -B -c 'import analysis, application, capture, detection, ml; packages = (analysis, application, capture, detection, ml); assert all(hasattr(package, name) for package in packages for name in package.__all__); print("all public exports resolve")'
```

No installation, third-party dependencies, network services, live-capture privileges, or running VMs are required. Fixtures use synthetic bytes and explicit observations; PCAP and CLI tests create temporary local files. Performance tests use controlled clocks for exact timing assertions and do not set machine-speed thresholds. The suite checks normal results, ordering, immutable inputs/results, malformed inputs, failure propagation, and execution counts.

| Existing verification area | Representative tests |
| --- | --- |
| Capture and lifecycle | [PCAP source](test_pcap_packet_source.py), [capture execution](test_capture_execution.py). |
| Protocol and fragment boundaries | [packet outcomes](test_packet_analysis_outcome.py), [IPv6 transport](test_ipv6_transport.py), [fragmentation](test_ipv6_fragmentation.py), [ICMPv6](test_icmpv6.py). |
| Directional TCP stream observation | [Sequence contract](test_tcp_stream_observation.py) and [flow/LDAP integration](test_tcp_stream_integration.py): exact bytes/ranges, wraparound, gaps, overlaps, controls, resource limits, directional isolation, publication failures, PCAP parity, and structural determinism. |
| Incremental LDAP framing | [Framing](test_ldap_stream_framing.py), [TCP consumption](test_tcp_stream_consumption.py), and [lifecycle](test_ldap_stream_lifecycle.py): exact batches/boundaries/suffixes, malformed stops, bounded unsupported messages, storage reclamation, parser call counts, directional IPv4/IPv6 isolation, immutable publication failures, PCAP parity, and structural determinism. |
| LDAP request/response correlation | [Association policy](test_ldap_correlation.py) and [lifecycle](test_ldap_correlation_lifecycle.py): exact references/directions, non-FIFO replies, Search continuations, ambiguous reuse, unavailable streams, bounded pending state, final unresolved projections, publication failures, IPv4/IPv6 PCAP parity, unchanged detection/research results, and structural determinism. |
| LDAP request termination summaries | [Summary updates](test_ldap_request_summary.py) and [lifecycle](test_ldap_request_summary_lifecycle.py): exact request/terminal references, Search response counts, ambiguity/unavailability, bounded storage, allocation/publication failures, finalization, IPv4/IPv6 PCAP parity, detector/research compatibility, and structural determinism. |
| LDAP protocol foundation | [Envelope parsing](test_ldap.py) and [flow integration](test_ldap_flow_statistics.py): operation tags, truncation, BER bounds, controls, resource limits, coalesced and split observations, IPv4/IPv6, immutable publication, PCAP/detection parity, and hash-seed/timezone determinism. |
| Flow and feature semantics | [observation windows](test_flow_observation_window.py), [snapshots](test_flow_feature_snapshot.py), [IPv6 features](test_ipv6_features.py). |
| Detection and application composition | [orchestration](test_detector_orchestration.py), [pipeline](test_detection_pipeline.py), [end-to-end validation](test_end_to_end_validation.py). |
| Evaluation and presentation-neutral results | [evaluation](test_detection_evaluation.py), [metrics](test_detection_metrics.py), [reporting](test_evaluation_report.py). |
| Dataset and execution methodology | [datasets](test_detection_dataset.py), [experiments](test_detection_experiment.py), [case benchmarks](test_detection_benchmark.py), [performance benchmarks](test_performance_benchmark.py). |
| Operational boundaries | [diagnostics](test_operational_diagnostics.py), [CLI](test_cli.py). |
| ML input boundary | [Feature projection](test_ml_feature_projection.py): canonical values and ordering, direct scalar preservation, availability, version rejection, immutable factory-only construction, label/detector exclusion, future-state isolation, pipeline independence, and hash-seed/timezone equivalence. |
| Research example boundary | [Research examples](test_research_example.py), [observation association](test_research_observation.py), [timestamp ownership](test_research_observation_timestamps.py), and [direct construction](test_research_construction.py): projection/truth retention, same-window derivation, optional closed-window context, nested timestamp validation, immutable ownership, validation, equality/repeats, outcome-based PCAP regression, and complete-output equivalence across hash seeds/timezones with detector/application imports blocked. |
| Research dataset boundary | [Research datasets](test_research_dataset.py): exact ordered membership, preserved repeats, empty datasets, value equality, caller-list isolation, invalid collections/members, no feature/truth inspection, and detector-independent construction across hash seeds/timezones. |

Tests verify implemented predicates and composition, not production attack-detection coverage. There are no CPU/memory profiling or throughput acceptance guarantees. Future tests for storage, enrichment, alerting, deployment, or resource exhaustion require those capabilities to be implemented first. Do not manufacture tests to meet a count or weaken failures to match documentation.

Small synthetic or sanitized fixtures require documented provenance and redistribution permission. Raw captures are ignored by default; review any fixture exception before committing it. Keep credentials, large datasets, and generated reports out of version control. The ignored root `artifacts/` location is a development convenience, not an implemented storage service.

## Curated PCAP scenarios

[Scenario helpers](pcap_scenarios.py) construct original synthetic Ethernet/IP bytes using the existing packet and classic-PCAP construction helpers. These fixtures contain no third-party traffic. TCP sequence/acknowledgment numbers describe a handshake, three-byte transfer and server half-close; UDP carries opaque request/response bytes with a repeated request. Fixtures include IPv4 header checksums and TCP/UDP pseudo-header checksums for both address families. Short Ethernet frames include padding without an FCS. Payloads do not imply application-protocol analysis. IPv6 transport checksums are fixture data; the current IPv6 analyzer does not validate them.

[Scenario tests](test_pcap_scenarios.py) write named, temporary PCAPs with short protocol scenarios and longer periodic-flow regressions and execute them through `PcapPacketSource`. They cover bidirectional IPv4/IPv6 TCP/UDP exchanges, interleaved families, SYN retransmission windows below/equal/above detector thresholds, Hop-by-Hop/Destination Options with atomic fragments, mixed malformed headers, and complementary UDP fragments. All timestamps are explicit; representative mixed traffic uses little-endian microsecond and big-endian nanosecond PCAP encodings. Repeated reads and CLI subprocess runs verify equivalent outputs. Temporary files are cleaned up; no binary captures are committed.

Complementary IPv6 fragments deliberately do not become a reassembled flow: an incomplete first UDP fragment remains an analysis failure, and the non-first fragment reaches the existing flow-admission error, preventing evaluation. ICMPv6's analysis/admission distinction, empty PCAPs, malformed PCAP records and all four encoding variants remain covered by the existing [system regressions](test_system_regressions.py), [end-to-end tests](test_end_to_end_validation.py) and [source tests](test_pcap_packet_source.py).

### Protocol coverage review

The matrix records coverage inspected at `7f27d98` and the selected additions in the scenario tests. Unit coverage includes tests composed from in-memory observations; the PCAP column describes execution through temporary wire-format captures. The additions preserve current contracts and do not broaden protocol support.

| Protocol / packet form | Existing unit coverage | Existing PCAP/system coverage at review | Selected regression and architectural purpose |
| --- | --- | --- | --- |
| IPv4/IPv6 TCP and UDP exchanges | [Flow identity](test_flow_identity.py), [IPv6 flows](test_ipv6_flow.py), directional statistics and features | Bidirectional exchanges, payload, ACK, half-close, retransmissions, thresholds, mixed families | Interleave TCP and UDP with identical addresses and ports in each family. Separate windows, byte/direction totals and detector counts prevent transport-state contamination. TCP options retain payload boundaries; RST increments its counter without closing the window. |
| TCP/UDP checksum fields | [Outcomes](test_packet_analysis_outcome.py), [TCP checksum](test_tcp_checksum.py), [UDP checksum](test_udp_checksum.py), [IPv6 transport](test_ipv6_transport.py) | Valid exchanges and IPv4 header checksum failure | Corrupt transport checksums exclude IPv4 packets from flows; omitted IPv4 UDP checksums remain admissible. The same IPv6 checksum fields remain observed without validation. Exact packet metrics and admitted counts protect this distinction. |
| UDP lengths and Ethernet trailing bytes | [UDP](test_udp.py), [IPv6 transport](test_ipv6_transport.py) | UDP payload exchanges; malformed TCP/extension sequences | Both families distinguish length below eight, length beyond IP payload and short headers. Ethernet padding cannot repair them. Excess IP bytes stay outside UDP payload but captured bytes remain included in flow volume. |
| IPv4 ICMP | [ICMP](test_icmp.py), [ICMP checksum](test_icmp_checksum.py), [Outcomes](test_packet_analysis_outcome.py) | Generic unsupported IPv4 transport admission; no dedicated ICMP capture scenario | A checksummed echo message succeeds at capture analysis but stops the full pipeline at flow admission. One packet analysis/detection, no feature extraction or evaluation, and no delivery of the following packet. |
| Failed ICMPv4/ICMPv6 messages | [Outcomes](test_packet_analysis_outcome.py), [ICMPv6](test_icmpv6.py) | Basic successful ICMPv6 analysis followed by admission failure | Corrupt ICMPv4 and short ICMPv4/ICMPv6 headers between valid UDP packets preserve integrity/incomplete classifications and create no flow state. Short ICMPv6 follows Destination Options and an atomic Fragment Header. Positive expectations retain historical NOT_EVALUABLE false negatives. |
| Non-initial IPv4 TCP/UDP/ICMP fragments | [Outcomes](test_packet_analysis_outcome.py) | IPv6 non-first/complementary fragment rejection | Final and intermediate IPv4 fragments remain unsupported, non-evaluable packet findings while subsequent valid datagrams continue the existing flow. No fragment payload is interpreted as a transport header. |
| Initial IPv6 TCP fragment and variable extension lengths | [IPv6 transport](test_ipv6_transport.py), [IPv6 detection](test_ipv6_detection.py) | Fixed-length Hop-by-Hop/Routing/Destination Options, atomic fragments, incomplete first UDP fragment | A complete TCP header with options in an initial fragment supplies only available payload. A following packet uses 24-byte Routing and 16-byte Destination Options headers; an atomic fragment shares the same flow. Exact payload, offsets, bytes and counters assert packet-local admission without reassembly. |
| Opaque IPv6 terminal selectors | [ICMPv6](test_icmpv6.py), [IPv6 detection](test_ipv6_detection.py), [in-memory pipeline](test_detection_pipeline.py) | No dedicated opaque-selector capture sequence | ESP, AH, No Next Header and an unknown selector after Destination Options must not scan TCP-looking payload. Admission fails after two observations, finalizes only the preceding UDP window, and never evaluates or consumes the following TCP packet. |
| Empty/truncated PCAP, encoding variants, malformed TCP/extensions | Source, outcome and protocol unit tests | Already covered by source, system, end-to-end and scenario tests | Retained without duplicating existing scenarios. |

These eight additional test methods use subtests for related protocol cases; subtests are not counted as separate tests. Assertions use production outcomes, findings, flow snapshots and reports. Failure scenarios also check source cleanup and relevant execution counts. Existing packet/PCAP helpers construct the wire data; the shared transport helper additionally supports TCP option bytes.

This review is not an exhaustive protocol matrix. IPv4 option combinations, repeated extension headers, and ICMPv6 partial-fragment combinations retain unit coverage without new dedicated PCAP scenarios here. Reassembly, IPv6 checksum validation, AH/ESP decoding, ICMP subtype semantics, VLAN decoding and application semantics beyond LDAP envelopes remain unimplemented; tests do not invent them.

## File-acquisition reliability regressions

The security/reliability review at `5515814` identified an acquisition defect: opening a FIFO before checking its file type could wait for a writer instead of reaching the existing regular-file rejection. The [source correction](../src/capture/README.md#classic-pcap-packet-source) checks before opening, retains descriptor validation, and requests nonblocking acquisition where supported.

Six additional tests establish the following specific properties:

- [PCAP source tests](test_pcap_packet_source.py) reject FIFO, FIFO-symlink and directory paths before opening; preserve terminal source state and zero delivery; replace a regular path with a FIFO at the open boundary without concurrency and verify rejection before reads plus descriptor closure; and preserve metadata-error causes and ownership-sensitive cleanup.
- [System regressions](test_system_regressions.py) repeat rejected startup and assert zero analysis, feature extraction, detector, evaluation, metric and report calls. Subsequent valid captures produce equivalent reports. Symlinks to regular captures retain equivalent packet/flow results across repeated runs.
- [CLI tests](test_cli.py) repeatedly execute FIFO and FIFO-symlink inputs in subprocesses and require exactly exit 1, empty stdout and the existing capture-error JSON on stderr. A subprocess timeout is a hang safeguard, not an elapsed-time or throughput assertion.

Temporary FIFOs, symlinks and captures are removed by the existing temporary-directory cleanup. FIFO tests are conditional on platform support; the replacement test additionally requires `os.O_NONBLOCK`. Existing handle-tracking tests intercept `io.open`, the acquisition boundary now used to supply an opener, with their read, close, ordering and error-cause assertions retained.

The review also checked existing parser bounds, maximum repeated IPv6 extension traversal, checksum/outcome distinctions, flow admission and state isolation, lifecycle/error precedence, feature validation, finding construction, evaluation, diagnostics and deterministic execution. Their established regressions remain in place, including historical NOT_EVALUABLE positive-expectation false negatives. This pass adds no protocol or detector semantics. Per-record memory can scale with the represented capture length; accumulated findings and active flows scale with input volume, and new-flow insertion copies the active mapping. No global memory/CPU limit, arbitrary-filesystem timeout or immunity to resource exhaustion is established. The input-stability requirement and existing protocol limitations remain unchanged.

## Accumulated inter-arrival roundoff regressions

The final readiness review reproduced valid periodic flows failing feature extraction because the negative-variance allowance omitted rounding accumulated across intervals. Three focused tests cover global and independent directional float sums, continued rejection of materially inconsistent moments, and 1,002-packet bidirectional TCP/UDP captures in both IP families. Complete PCAP-to-report runs repeat with fresh sources and compare full results, exact truth metrics, interval features, feature-contract provenance and cleanup. The population formulas, raw accumulators, public schemas and historical NOT_EVALUABLE semantics remain unchanged.

Authorized lab methodology belongs to [labs](../labs/README.md). Portable checks derived from future lab results should become regressions where appropriate. The test count records the verified baseline and is not a coverage target.
