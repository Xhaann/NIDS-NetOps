# Traffic analysis boundary

This directory implements Ethernet II, IPv4, TCP, UDP, and generic ICMPv4 decoding and checksum validation, single-packet analysis and failure-preserving analysis outcomes, canonical IPv4 TCP/UDP flow identity and direction, in-memory tracking, and explicit raw accumulation and feature boundaries. Raw accumulation includes global and directional volume, packet-size statistics, global and directional inter-arrival statistics, and directional TCP control observations. Implemented features cover volume and directional balance, packet sizes, duration, rates, and global and directional inter-arrival statistics. Each module's exact scope is documented below.

Additional link formats, fragment and stream reassembly, TCP connection state, flow expiration, and application parsing remain unimplemented.

## Single-packet analysis

`analysis` exports `analyze_packet(observation: PacketObservation) -> PacketAnalysis`, `PacketAnalysis`, and `PacketAnalysisError` from [packet_analysis.py](packet_analysis.py). This synchronous operation analyzes exactly one captured observation without keeping state across packets. It requires Ethernet `LinkType(1)` and IPv4 EtherType `0x0800`; unknown or other link types and non-IPv4 Ethernet frames raise `PacketAnalysisError(ValueError)`. Wrong input types raise `TypeError`.

The operation delegates Ethernet and IPv4 decoding to the existing decoders, then explicitly validates the IPv4 checksum. It selects the existing TCP, UDP, or ICMPv4 decoder for IPv4 protocols 6, 17, or 1 respectively and validates the corresponding checksum when fragment offset is zero. Other IPv4 protocol numbers retain the Ethernet and IPv4 results without further decoding. Decoder failures propagate unchanged; no partial result is returned after a failure.

`PacketAnalysis` is a frozen dataclass retaining the exact original `observation` and the exact decoder-produced model references in `ethernet`, `ipv4`, `tcp`, `udp`, and `icmp`. Unused optional model fields are `None`. Its four optional boolean fields are `ipv4_checksum_valid`, `tcp_checksum_valid`, `udp_checksum_valid`, and `icmp_checksum_valid`. Direct construction checks model types and requires checksum results to be booleans or `None`.

A checksum result of `True` or `False` is preserved directly from its validator; `None` means not applicable or not performed. IPv4 is always checked on successful analysis, and a failed checksum does not stop subsequent structural decoding. UDP checksum zero retains `False` (integrity not validated), while a valid ICMP checksum of zero can retain `True`. No result is normalized or converted into an exception.

Transport/ICMP decoders are called before their checksum guards. The current decoders reject non-initial fragments, so those existing decode errors propagate and no transport/ICMP checksum validator runs. If a decoder returns a model for such a fragment, its checksum result remains `None`. Initial fragments with MF set may be checked subject to existing decoder requirements; checks cover only the represented bytes, without fragment reassembly.

This boundary contains orchestration only. It does not alter observations or packet bytes, perform stream reassembly, connection/flow tracking, application parsing, feature extraction, or detection, or assign threat verdicts, severity, or alerts. Capture remains responsible for acquisition. No additional link formats, EtherTypes, or protocol decoders are introduced.

## Failure-preserving packet-analysis outcome

`analysis` additionally exports `analyze_packet_outcome(observation: PacketObservation) -> PacketAnalysisOutcome`, `PacketAnalysisOutcome`, `PacketAnalysisFailureClassification`, and `PacketAnalysisOutcomeError` from [packet_analysis_outcome.py](packet_analysis_outcome.py). The existing `analyze_packet()` contract remains unchanged for callers that require its exact successful return or exception behavior. The outcome helper is the separate boundary for a caller that must preserve a recognized unsuccessful analysis attempt as immutable analytical evidence.

Every outcome retains the exact supplied `PacketObservation`. Success retains the exact `PacketAnalysis` returned by `analyze_packet()` and has no failure classification or description. Failure has no `PacketAnalysis`, has exactly one classification, and has a deterministic nonblank description. The frozen model rejects mixed success/failure states, nonexact model types, blank failure descriptions, and a successful analysis that does not retain the same observation object.

The bounded classifications are `STRUCTURAL_FAILURE`, `UNSUPPORTED`, `INCOMPLETE`, and `INTEGRITY_FAILURE`. They cover only conditions established by the current top-level analysis and decoder messages: invalid implemented header structure; unsupported link, network, protocol-decoder, or non-initial-fragment scope; explicitly insufficient available bytes; and explicit checksum mismatches. Unknown exceptions and unrecognized messages within existing broad exception classes continue to propagate rather than becoming packet evidence. No new structural or checksum rule is introduced.

An IPv4 UDP zero checksum remains a successful analysis with `udp_checksum_valid is False` because the existing boolean validator cannot distinguish omission from mismatch without inspecting the decoded checksum field; the outcome helper uses that field and does not label omission as an integrity failure. Unknown IPv4 protocol numbers likewise retain the existing successful network-layer analysis behavior. A failure classification records what happened under implemented analysis rules and does not establish maliciousness, an attack type, intent, or RFC-wide noncompliance.

This boundary keeps no state or packet history and does not perform detection. A future network-integrity detector may consume it, but that detector and its security predicate are outside this feature.

## Bidirectional flow identity

`analysis` exports `flow_identity_from_packet(analysis: PacketAnalysis) -> FlowIdentity`, `FlowIdentity`, and `FlowIdentityError` from [flow_identity.py](flow_identity.py). The operation uses only decoded IPv4 addresses, transport ports, and the IPv4 protocol number. It supports TCP (6) and UDP (17); ICMP and other protocols are intentionally outside this boundary. Checksum results do not affect identity creation, and no checksum validation or raw-byte inspection is performed.

`FlowIdentity` is a frozen dataclass containing `source_address`, `destination_address`, `source_port`, `destination_port`, and `protocol`. Addresses remain exactly four immutable bytes, ports are integers from 0 through 65535, and protocol is exactly 6 or 17. Wrong field types raise `TypeError`, including booleans in integer fields and mutable address containers; invalid values raise `ValueError`.

Construction orders the complete `(address, port)` endpoints lexicographically using bytes and integer comparison. The smaller endpoint occupies the source fields; the larger occupies the destination fields. This also applies to direct model construction. Equal addresses are ordered by port, and identical endpoints are valid. Forward and reverse packets produce equal identities; protocol remains part of equality. Canonical source/destination labels do not preserve packet direction or identify clients and servers.

Wrong top-level input raises `TypeError`. Missing IPv4, unsupported protocol, missing corresponding TCP/UDP model, or conflicting transport models raises `FlowIdentityError(ValueError)`. No missing fields are inferred from observations or payloads. The value retains no analysis reference or capture metadata and modifies no existing model.

This is identity only: it maintains no flow state and performs no tracking, timeout handling, TCP connection tracking, stream or fragment reassembly, feature extraction, or detection.

## Packet direction relative to flow identity

`analysis` exports `FlowDirection`, `FlowDirectionError`, and `flow_direction_from_packet(analysis: PacketAnalysis, identity: FlowIdentity) -> FlowDirection` from [flow_direction.py](flow_direction.py). The enum contains `FORWARD = "forward"` and `REVERSE = "reverse"`; the function returns an enum member, not a string.

`FlowIdentity` remains authoritative for canonical endpoint ordering. Each endpoint includes its four-byte IPv4 address and transport port. For TCP (6) and UDP (17), the function compares both decoded packet endpoints directly with the supplied identity and requires the protocol to match. Canonical source-to-destination is `FORWARD`; the opposite pair is `REVERSE`. No new identity is constructed and no endpoints are sorted. If both canonical endpoints are identical, the forward match takes precedence and returns `FORWARD` deterministically.

Wrong argument types raise `TypeError`. Missing IPv4 or corresponding transport models, conflicting transport models, ICMP, and unsupported protocols retain the existing `FlowIdentityError` boundary. A supported packet with a different protocol or endpoint pair from the supplied identity raises `FlowDirectionError(ValueError)`. Inputs remain unchanged.

Direction is stateless and deterministic, independent of checksum results, timestamps, payload contents, TCP flags, and call order. Port values participate only in endpoint equality; no client/server or initiator/responder roles are inferred. The module does not calculate statistics or depend on `FlowTracker` or `FlowStatistics`. It adds no IPv6 or ICMP direction, application parsing, flow tracking, TCP state, reassembly, timeouts, persistence, concurrency, feature extraction, detection, alerting, PCAP, or live capture.

## In-memory bidirectional flow tracking

`analysis` exports `FlowPacket`, `FlowSnapshot`, `FlowTracker`, and `FlowTrackingError` from [flow_tracker.py](flow_tracker.py). `FlowTracker()` starts empty and groups analyzed IPv4 TCP/UDP packets through the authoritative `flow_identity_from_packet()` operation. Reverse-direction packets update the same bidirectional entry. Checksums are not inspected, and identity errors propagate unchanged; ICMP and unsupported traffic are not silently discarded.

`FlowPacket(identity: FlowIdentity, analysis: PacketAnalysis)` is a frozen association retaining both exact supplied objects. `FlowSnapshot(identity: FlowIdentity, packet_count: int, first_analysis: PacketAnalysis, last_analysis: PacketAnalysis)` is a frozen snapshot retaining exact references. Both models validate field types with `TypeError`; counts must be exact integers (not booleans) and at least one. Invalid count values raise `FlowTrackingError(ValueError)`.

| Operation | Behavior |
| --- | --- |
| `record(analysis: PacketAnalysis) -> FlowSnapshot` | Delegates identity construction once. A new identity starts at count one; an existing identity increments by one, preserves the first analysis, and retains the supplied analysis as latest. Every successful call creates a new snapshot with the identity returned by that call. |
| `get(identity: FlowIdentity) -> Optional[FlowSnapshot]` | Returns the current snapshot or `None` without creating or changing a flow. Wrong identity types raise `TypeError`. |
| `flow_count() -> int` | Returns the number of tracked identities. |
| `identities() -> tuple[FlowIdentity, ...]` | Returns the keys as an immutable tuple in dictionary insertion order. |
| `snapshots() -> tuple[FlowSnapshot, ...]` | Returns current immutable snapshots in dictionary insertion order. |

Wrong record inputs raise `TypeError`. Identity construction and snapshot validation finish before the mapping changes, so a failed record leaves existing state intact. Earlier snapshots and tuples remain unchanged after later records. Equal identity keys follow normal dictionary behavior, retaining the original key object; each replacement snapshot retains its newly supplied identity object. No mutable mapping or packet copy is exposed.

The tracker is synchronous and single-owner; it does not claim thread safety. First/latest refer only to record-call order, not capture timestamps or client/server roles. It does not classify direction or implement TCP connection state, timeouts, expiration, eviction, byte counting, feature extraction, detection, stream/fragment reassembly, application parsing, or persistence.

## Accumulated flow statistics

`analysis` exports `FlowStatistics`, `FlowStatisticsError`, and `update_flow_statistics(current: Optional[FlowStatistics], analysis: PacketAnalysis, identity: FlowIdentity) -> FlowStatistics` from [flow_statistics.py](flow_statistics.py). The function is independent of `FlowTracker` and keeps no state. It verifies membership through `flow_identity_from_packet(analysis) == identity`, supporting the existing IPv4 TCP/UDP boundary without inspecting checksums. Identity errors propagate unchanged; mismatched supplied or current identities raise `FlowStatisticsError(ValueError)`.

The frozen model contains only `identity`, `packet_count`, `captured_bytes`, `original_bytes`, `first_captured_at`, and `last_captured_at`. It retains the exact supplied identity object, even when equal to a distinct current identity. It stores no packet objects or raw bytes. Wrong types raise `TypeError`; counts and byte totals require exact integers, excluding booleans. The packet count must be at least one, captured bytes nonnegative, and original bytes at least captured bytes. Invalid numeric or temporal values raise `FlowStatisticsError`.

With `current=None`, the result starts at one packet, using `PacketObservation.captured_length`, `original_length`, and `captured_at` directly. Subsequent calls increment the count, add those capture lengths, preserve the first timestamp, and use the newly supplied capture timestamp as latest. No lengths are derived from packet bytes or decoded payloads. An unknown observation `original_length=None` raises `FlowStatisticsError` because an exact original-byte total cannot be accumulated.

Both timestamps must be timezone-aware, and latest cannot precede first. Updates may move latest backwards relative to the previous latest timestamp, provided it remains at or after first. Packets are never sorted, timestamps are never normalized, and no clock is consulted. Invalid updates leave every input unchanged; successful updates return a new immutable value.

This is raw accumulation only. It does not classify direction or client/server roles, calculate durations, rates, packet-size aggregates or other derived features, perform feature extraction, detection, TCP state tracking, timeout/expiration, reassembly, or application parsing, or introduce persistence or concurrency.

## Directional raw flow statistics

`analysis` exports `DirectionalFlowStatistics`, `DirectionalFlowStatisticsError`, and `update_directional_flow_statistics(current: Optional[DirectionalFlowStatistics], analysis: PacketAnalysis, identity: FlowIdentity) -> DirectionalFlowStatistics` from [directional_flow_statistics.py](directional_flow_statistics.py).

The frozen model contains exactly seven fields: `identity`, `forward_packet_count`, `reverse_packet_count`, `forward_captured_bytes`, `reverse_captured_bytes`, `forward_original_bytes`, and `reverse_original_bytes`. The identity must be a `FlowIdentity`; all six counters must be exact nonnegative integers, excluding booleans. Original bytes must be at least captured bytes independently in each direction. All-zero models are valid. Wrong types raise `TypeError`; invalid values raise `DirectionalFlowStatisticsError(ValueError)`.

The stateless update delegates flow membership and direction to `flow_direction_from_packet(analysis, identity)` exactly once. `FlowIdentity` defines membership and `FlowDirection` defines canonical forward/reverse ordering. With no current value, only the selected direction starts at one packet and the observation's byte lengths; the opposite direction remains zero. Subsequent updates increment only the selected direction. Every result retains the exact supplied identity object, including a distinct but equal identity supplied on a later update. Previous statistics and all packet inputs remain unchanged.

Byte totals use only `PacketObservation.captured_length` and `original_length`. Unknown `original_length=None` raises `DirectionalFlowStatisticsError`; no substitute length is invented. A mismatched current identity raises the same statistics error. Packet membership failures retain `FlowDirectionError`, and unsupported or incomplete packet layers retain `FlowIdentityError`. Checksum results, timestamps, and payload contents do not affect accumulation when capture metadata is fixed.

This remains raw accumulation. The model retains no packet objects, raw bytes, direction state, or timestamps. It calculates no duration, rates, averages, minimums, maximums, or TCP flag statistics. It adds no feature extraction, detection, TCP state tracking, reassembly, persistence, or concurrency, and changes no existing tracker, statistics, identity, or direction implementation.

## TCP control observation statistics

`analysis` exports `TCPControlStatistics`, `TCPControlStatisticsError(ValueError)`, and `update_tcp_control_statistics(current: Optional[TCPControlStatistics], analysis: PacketAnalysis, identity: FlowIdentity) -> TCPControlStatistics` from [tcp_control_statistics.py](tcp_control_statistics.py). This TCP-specific raw accumulator counts the nine decoded TCP control bits independently for canonical forward and reverse directions. It also counts packets where SYN and ACK occur together because that co-occurrence cannot be recovered from the two marginal counts.

The frozen model retains the TCP flow identity, total and directional packet counts, eighteen directional flag counts, and two directional SYN+ACK counts. Every counter is an exact nonnegative integer. Directional packet counts sum to the total; each flag count is bounded by its directional packet count; and each SYN+ACK count is bounded by both corresponding SYN and ACK counts. The updater delegates membership and direction to the existing identity and direction operations, retains the supplied identity on the first update and the current identity thereafter, and returns a new value without mutating its inputs.

The state records observed flags only. Flags are not mutually exclusive, a packet with no flags is valid, and forward/reverse remain canonical endpoint directions rather than client/server roles. Checksums, timestamps, sequence and acknowledgment numbers, window size, options, and payload do not affect accounting. No connection establishment, handshake, termination, retransmission, attack behavior, or suspiciousness is inferred.

Memory remains constant because only the identity and fixed scalar counters are retained. No packet, payload, timestamp, history, collection, cache, or hidden state is stored. `FlowStateCoordinator` includes this raw state for TCP flows and publishes `None` for UDP flows. It is not a direct `FlowFeatureSnapshot` field or a numerical feature family. Detection and machine-learning semantics remain outside the analysis layer.

## Raw-statistics input for future features

`analysis` exports `FlowFeatureInput`, `FlowFeatureInputError`, and `flow_feature_input_from_statistics(statistics: FlowStatistics, directional: DirectionalFlowStatistics) -> FlowFeatureInput` from [flow_feature_input.py](flow_feature_input.py). This is an explicit input contract for future feature extraction; it performs no feature extraction or detection and computes no derived metric.

The frozen model contains exactly ten fields: `identity`, `packet_count`, `captured_bytes`, `original_bytes`, `forward_packet_count`, `reverse_packet_count`, `forward_captured_bytes`, `reverse_captured_bytes`, `forward_original_bytes`, and `reverse_original_bytes`. It retains only the immutable `FlowIdentity` and nine integer values, with no packets, raw bytes, timestamps, source-statistics objects, or mutable collections.

`FlowStatistics` is authoritative for the three total fields; `DirectionalFlowStatistics` is authoritative for the six directional fields. The function copies each value directly. Totals are neither recomputed from directional values nor required to equal their sums. No reconciliation or repair is performed, and neither source model is mutated.

`FlowIdentity` remains authoritative for membership: both source identities must compare equal or `FlowFeatureInputError(ValueError)` is raised. The result retains the exact identity object from `statistics`, even when `directional.identity` is equal but distinct. Wrong source or model-field types raise `TypeError`. All nine numeric fields require exact nonnegative integers, excluding booleans; original bytes must cover captured bytes for the total and independently for each direction. Invalid values raise `FlowFeatureInputError`. All-zero direct construction is valid.

The module depends only on the identity and raw-statistics models. It introduces no feature vectors, feature registry, generic framework, derived statistics, flow state, persistence, or concurrency. Future feature extraction can consume this boundary without receiving packet or tracker objects.

## Flow volume and directional-balance features

`analysis` exports `FlowVolumeFeatures`, `FlowVolumeFeaturesError`, and `extract_flow_volume_features(input_data: FlowFeatureInput) -> FlowVolumeFeatures` from [flow_volume_features.py](flow_volume_features.py). `FlowFeatureInput` is the sole project-layer input dependency; other input types raise `TypeError`. Extraction is pure and deterministic, leaving the input unchanged.

The frozen model has exactly sixteen fields. The first nine are copied directly: `packet_count`, `captured_bytes`, `original_bytes`, `forward_packet_count`, `reverse_packet_count`, `forward_captured_bytes`, `reverse_captured_bytes`, `forward_original_bytes`, and `reverse_original_bytes`. The remaining seven are computed as follows:

| Field | Formula |
| --- | --- |
| `forward_packet_ratio` | `forward_packet_count / packet_count` |
| `reverse_packet_ratio` | `reverse_packet_count / packet_count` |
| `forward_captured_byte_ratio` | `forward_captured_bytes / captured_bytes` |
| `reverse_captured_byte_ratio` | `reverse_captured_bytes / captured_bytes` |
| `forward_original_byte_ratio` | `forward_original_bytes / original_bytes` |
| `reverse_original_byte_ratio` | `reverse_original_bytes / original_bytes` |
| `capture_ratio` | `captured_bytes / original_bytes` |

Each zero denominator produces `0.0`, including when its directional numerator is nonzero. Otherwise ordinary floating-point division is used, without rounding, formatting, clamping, or reconciliation. Capture ratio expresses the fraction of original bytes captured; equal nonzero captured/original totals produce `1.0`. Directional sums need not equal global totals or sum to a ratio of one.

Direct construction requires nine exact nonnegative integers and seven exact finite floats in `[0.0, 1.0]`, rejecting booleans. Wrong types raise `TypeError`; invalid values raise `FlowVolumeFeaturesError(ValueError)`. Because `FlowFeatureInput` permits directional values greater than their corresponding global totals, some valid inputs produce ratios above one: those results are rejected by the feature-model range validation, never clamped or repaired. All-zero input produces zero copied fields and `0.0` ratios.

This is one explicit numerical feature family. It retains no identity, packets, raw bytes, or timestamps and introduces no duration, rates, packet-length statistics, other feature families, machine-learning code or dependencies, detection, state, caching, or generic framework.

## Raw packet-size accumulation

`analysis` exports `FlowPacketSizeStatistics`, `FlowPacketSizeStatisticsError`, and `update_flow_packet_size_statistics(current: Optional[FlowPacketSizeStatistics], analysis: PacketAnalysis, identity: FlowIdentity) -> FlowPacketSizeStatistics` from [flow_packet_size_statistics.py](flow_packet_size_statistics.py). This independent, stateless update accumulates raw packet lengths for future packet-size feature extraction without changing existing trackers or feature models.

The frozen model contains exactly 28 fields: `identity`; global `packet_count`, `captured_bytes`, `original_bytes`, `min_captured_length`, `max_captured_length`, `sum_captured_length_squares`, `min_original_length`, `max_original_length`, and `sum_original_length_squares`; and nine fields for each of the `forward_` and `reverse_` prefixes: `packet_count`, `captured_bytes`, `min_captured_length`, `max_captured_length`, `sum_captured_length_squares`, `original_bytes`, `min_original_length`, `max_original_length`, and `sum_original_length_squares`.

Lengths come directly from `PacketObservation.captured_length` and `original_length`, never from raw bytes or protocol models. Unknown `original_length=None` raises `FlowPacketSizeStatisticsError(ValueError)`. Each update adds one to the global count, adds both lengths to byte totals, and adds each length multiplied by itself to the corresponding sum of squares using integer arithmetic. Global minima and maxima begin at the first packet's lengths and subsequently use `min`/`max`.

Direction and membership delegate once to `flow_direction_from_packet()`. Only the selected direction's aggregates change. Its first packet initializes minima and maxima to its lengths; an unused direction retains zero counters and aggregates. A genuine zero-length packet is valid and remains part of later minimum calculations. The result retains the exact supplied identity object; unequal current identities raise `FlowPacketSizeStatisticsError`, and existing direction/identity errors propagate unchanged. Failed updates preserve every input.

Direct construction requires a `FlowIdentity` and 27 exact nonnegative integers, rejecting booleans and other wrong types with `TypeError`. Global packet count must be at least one. Global and directional minima cannot exceed maxima; original-byte totals must cover captured-byte totals. A direction with zero packets must have all eight length aggregates zero. Invalid values raise `FlowPacketSizeStatisticsError`. Sums of squares are validated as nonnegative integers without reconstruction or reconciliation from other fields.

Only the identity and integers are retained: no packets, raw bytes, timestamps, packet collections, direction state, or previous statistics object. No floating-point accumulation, mean, variance, standard deviation, ratios, rates, duration, feature extraction, detection, machine learning, reassembly, persistence, or concurrency is added.

## Packet-size statistical features

`analysis` exports `PacketSizeFeatures`, `PacketSizeFeaturesError`, and `extract_packet_size_features(statistics: FlowPacketSizeStatistics) -> PacketSizeFeatures` from [packet_size_features.py](packet_size_features.py). `FlowPacketSizeStatistics` is the sole project-layer input boundary. Wrong input types raise `TypeError`; extraction is deterministic and leaves its input unchanged.

The frozen model contains fourteen fields: `min_captured_length`, `max_captured_length`, `mean_captured_length`, `variance_captured_length`, `standard_deviation_captured_length`, `min_original_length`, `max_original_length`, `mean_original_length`, `variance_original_length`, `standard_deviation_original_length`, `forward_mean_captured_length`, `reverse_mean_captured_length`, `forward_variance_captured_length`, and `reverse_variance_captured_length`. All four min/max values are copied directly as integers; the other ten fields are floats. Direct construction rejects booleans and incorrect types with `TypeError`, and rejects negative values, non-finite floats, or reversed min/max pairs with `PacketSizeFeaturesError(ValueError)`.

For each global length kind, mean is its byte total divided by `packet_count`; population variance is its sum of squared lengths divided by `packet_count`, minus mean squared: `E[X^2] - E[X]^2`. Global standard deviation is `math.sqrt(variance)`. Forward and reverse captured means and population variances use their own byte totals, squared-length totals, and packet counts. An unused direction produces exactly `0.0` for mean and variance. Global count is already positive under the accumulator contract. No sample-variance denominator, rounding, string conversion, or reconciliation of global and directional values is used.

Negative variance is corrected only within a deterministic floating-point error bound. With computed mean `m`, second moment `s`, squared mean `q = m*m`, and `u = math.ulp(m)`, the bound is `math.ulp(s) + math.ulp(q) + u * (2*abs(m) + u)`. This conservatively accounts for moment rounding and propagation of mean rounding through squaring. A negative variance whose magnitude is at most this bound becomes `0.0`; a more negative result raises `PacketSizeFeaturesError`. Zero and positive results are unchanged. This does not recover precision lost to cancellation or reconcile source aggregates. Non-finite or overflowing moments also raise `PacketSizeFeaturesError`.

The result retains only integers and floats, with no identity, input object, packets, raw bytes, or timestamps. This family adds no directional standard deviations, duration/rate/inter-arrival features, ratios, medians, percentiles, histograms, entropy, other feature families, detection, machine learning, or generic framework.

## Flow duration feature

`analysis` exports `FlowDurationFeatures`, `FlowDurationFeaturesError`, and `extract_flow_duration_features(statistics: FlowStatistics) -> FlowDurationFeatures` from [flow_duration_features.py](flow_duration_features.py). `FlowStatistics` is the sole input boundary; the extractor requires its exact type and rejects subclasses and other inputs with `TypeError`.

The frozen result contains exactly one field, `duration_seconds: float`, calculated as `(statistics.last_captured_at - statistics.first_captured_at).total_seconds()`. Python datetime subtraction is used directly, with no wall-clock access, rounding, truncation, or timezone normalization. Zero duration produces exactly `0.0`; fractional seconds, including microseconds, are preserved by the ordinary `total_seconds()` calculation.

Direct construction requires an exact float, rejecting booleans, integers, strings, and other types with `TypeError`. Negative or non-finite values raise `FlowDurationFeaturesError(ValueError)` without coercion or clamping. Extraction is deterministic, leaves the source unchanged, and retains no input object, identity, timestamps, packets, raw bytes, or metadata. This family implements duration only and performs no detection or machine learning.

## Flow rate features

`analysis` exports `FlowRateFeatures`, `FlowRateFeaturesError`, and `extract_flow_rate_features(statistics: FlowStatistics) -> FlowRateFeatures` from [flow_rate_features.py](flow_rate_features.py). `FlowStatistics` is the sole project-layer input boundary. Its exact type is required; subclasses and unrelated objects raise `TypeError`. No duration feature object is used.

Duration is computed directly as `(statistics.last_captured_at - statistics.first_captured_at).total_seconds()`. For positive duration, the three frozen fields are `packets_per_second = packet_count / duration_seconds`, `captured_bytes_per_second = captured_bytes / duration_seconds`, and `original_bytes_per_second = original_bytes / duration_seconds`. Each uses its own authoritative numerator with ordinary floating-point division, without rounding, truncation, normalization, or transformation.

For zero duration, all-zero numerators produce exactly `0.0` for all three rates; any positive numerator makes extraction undefined and raises `FlowRateFeaturesError(ValueError)` for the entire operation. No infinity, NaN, or partial result is returned. Under the current `FlowStatistics` invariant `packet_count >= 1`, every normally constructed zero-duration input is therefore rejected; the all-zero policy remains explicit without weakening that model. Negative or non-finite duration and overflowing/non-finite rates are also rejected without clamping.

Direct construction requires three exact finite nonnegative floats, rejecting integers, booleans, and other types with `TypeError`, and invalid numerical values with `FlowRateFeaturesError`. Zero floats are valid. Extraction is deterministic, leaves its source unchanged, and retains no input or duration object, identity, timestamps, packets, raw bytes, or metadata. This family contains only the three global rates and performs no detection or machine learning.

## Flow inter-arrival statistics

`analysis` exports `FlowInterArrivalStatistics`, `FlowInterArrivalStatisticsError(ValueError)`, and `update_flow_inter_arrival_statistics(current: Optional[FlowInterArrivalStatistics], analysis: PacketAnalysis, identity: FlowIdentity) -> FlowInterArrivalStatistics` from [flow_inter_arrival_statistics.py](flow_inter_arrival_statistics.py).

The frozen model has exactly nine fields: `identity`, `packet_count`, `first_captured_at`, `last_captured_at`, `inter_arrival_count`, `inter_arrival_sum_seconds`, `inter_arrival_sum_seconds_squared`, `min_inter_arrival_seconds`, and `max_inter_arrival_seconds`. Timestamps are timezone-aware, counts are exact integers, and aggregates are finite nonnegative floats. Validation requires `packet_count >= 1`, `inter_arrival_count == packet_count - 1`, ordered timestamps and minimum/maximum, and all-zero aggregates when there are no intervals. Wrong types raise `TypeError`; invalid values raise `FlowInterArrivalStatisticsError`.

An interval is `(analysis.observation.captured_at - current.last_captured_at).total_seconds()` between consecutive packets of the same bidirectional flow. The first packet sets both timestamps and has zero intervals and four `0.0` aggregates. Each later packet adds one interval, its seconds to the sum, and its squared seconds to the sum of squares. The first actual interval initializes minimum and maximum; subsequent intervals update those extrema. Zero-second intervals are valid. Negative or non-finite intervals are rejected atomically; out-of-order packets are never reordered, skipped, or converted to positive intervals. The first timestamp remains stable and the last becomes the current capture timestamp.

Flow membership is verified through `flow_identity_from_packet()`. Mismatched flow identities raise `FlowInterArrivalStatisticsError`; unsupported analyses preserve the existing identity error boundary. The first update retains the exact supplied identity, and later updates retain the exact existing `current.identity`, accepting equal but distinct supplied identities. Every update returns a new value and leaves all inputs unchanged.

Only aggregate state and the two endpoint timestamps are retained, with a fixed number of fields regardless of packet count. There is no timestamp history, packet history, packet object, or raw-byte retention. This module performs no directional inter-arrival accumulation, feature extraction, rate calculation, detection, or machine learning.

## Inter-arrival features

`analysis` exports `InterArrivalFeatures`, `InterArrivalFeaturesError(ValueError)`, and `extract_inter_arrival_features(statistics: FlowInterArrivalStatistics) -> InterArrivalFeatures` from [inter_arrival_features.py](inter_arrival_features.py). The sole project-layer input boundary is exactly `FlowInterArrivalStatistics`; subclasses, mocks, and unrelated objects raise `TypeError`.

The frozen model contains exactly five finite nonnegative float fields: `mean_inter_arrival_seconds`, `variance_inter_arrival_seconds`, `standard_deviation_inter_arrival_seconds`, `min_inter_arrival_seconds`, and `max_inter_arrival_seconds`. Direct construction rejects other types with `TypeError`, and invalid numerical values or reversed extrema with `InterArrivalFeaturesError`.

For interval count `n > 0`, mean is `inter_arrival_sum_seconds / n`, second moment is `inter_arrival_sum_seconds_squared / n`, and population variance is `second_moment - mean * mean`. Standard deviation is `math.sqrt(variance)`. Minimum and maximum are copied directly from the source. Zero interval count produces five exact `0.0` values. No rounding, truncation, or reconstruction from timestamps occurs.

Cancellation handling follows the existing packet-size feature policy. With `e = math.ulp(mean)`, a negative variance is treated as zero only when its magnitude is at most `math.ulp(second_moment) + math.ulp(mean * mean) + e * (2 * abs(mean) + e)`. This deterministic bound accounts for moment rounding and propagation of one ULP of mean error through squaring. More negative variance raises `InterArrivalFeaturesError`; overflow and non-finite derived values are rejected without normalization.

Extraction is pure, deterministic, global, and non-directional. Its result retains only the five float values, with no identity, source object, timestamps, packet/history objects, raw bytes, or aggregate sums. This module adds no rates, advanced statistics, detection, or machine learning.

## Directional inter-arrival statistics

`analysis` exports `DirectionalInterArrivalStatistics`, `DirectionalInterArrivalStatisticsError(ValueError)`, and `update_directional_inter_arrival_statistics(current: Optional[DirectionalInterArrivalStatistics], analysis: PacketAnalysis, identity: FlowIdentity) -> DirectionalInterArrivalStatistics` from [directional_inter_arrival_statistics.py](directional_inter_arrival_statistics.py).

The frozen model contains exactly sixteen fields: `identity`, `packet_count`, `first_captured_at`, `last_captured_at`, `last_forward_captured_at`, `last_reverse_captured_at`, `forward_inter_arrival_count`, `reverse_inter_arrival_count`, `forward_inter_arrival_sum_seconds`, `reverse_inter_arrival_sum_seconds`, `forward_inter_arrival_sum_seconds_squared`, `reverse_inter_arrival_sum_seconds_squared`, `forward_min_inter_arrival_seconds`, `forward_max_inter_arrival_seconds`, `reverse_min_inter_arrival_seconds`, and `reverse_max_inter_arrival_seconds`.

Unlike global adjacent-packet timing, each directional interval uses `(analysis.observation.captured_at - previous_same_direction_timestamp).total_seconds()`. The two explicit directional timestamps independently retain that necessary state; `None` means the direction is unseen. Each direction's first packet establishes its timestamp without creating an interval. Later packets add one interval, its seconds to the sum, and its squared seconds to the sum of squares. The first actual interval initializes minimum and maximum. Opposite-direction timestamps and aggregates remain unchanged. For F0, R1, F3, R4, F7, forward intervals are 3 and 4 seconds and the reverse interval is 3 seconds.

Validation requires exact identity and integer count types, aware ordered global timestamps, directional timestamps within the global interval, and exact finite nonnegative float aggregates. Counts satisfy `forward_inter_arrival_count + reverse_inter_arrival_count == packet_count - observed_direction_count`, where each non-`None` directional timestamp contributes one observed direction. Unseen directions have no intervals; any direction with zero intervals has four zero aggregates. Wrong types raise `TypeError`; invalid values raise `DirectionalInterArrivalStatisticsError`.

Identity and direction delegate to `flow_identity_from_packet()` and `flow_direction_from_packet()`, each once per valid update. Unsupported analyses preserve `FlowIdentityError`; mismatched identities raise `DirectionalInterArrivalStatisticsError`. The initial result retains the supplied identity; later results retain the exact existing identity even when an equal, distinct identity is supplied. First capture time remains stable, and last capture time advances to the packet timestamp without timezone normalization. Globally out-of-order packets, negative or non-finite intervals, and aggregate overflow are rejected atomically. Zero-second intervals are valid; no rounding or clamping occurs.

Every update returns a new immutable value with a fixed number of fields. It retains no packets, observations, raw bytes, history collections, caches, or hidden state. This is raw accumulation only, with no directional feature extraction, inter-arrival rates, detection, or machine learning.

## Directional inter-arrival features

`analysis` exports `DirectionalInterArrivalFeatures`, `DirectionalInterArrivalFeaturesError(ValueError)`, and `extract_directional_inter_arrival_features(statistics: DirectionalInterArrivalStatistics) -> DirectionalInterArrivalFeatures` from [directional_inter_arrival_features.py](directional_inter_arrival_features.py). The extractor requires exactly the existing raw directional statistics model and rejects subclasses, mocks, unrelated objects, inconsistent counts, and malformed aggregates.

The frozen model contains ten fields, with the five forward fields followed by the five reverse fields. Each direction has `mean_inter_arrival_seconds`, `variance_inter_arrival_seconds`, `standard_deviation_inter_arrival_seconds`, `min_inter_arrival_seconds`, and `max_inter_arrival_seconds`, prefixed by its direction. The five values for one direction are either all exact finite nonnegative floats or all `None`. No identity or raw source field is retained.

For a direction with interval count `n > 0`, mean is its accumulated sum divided by `n`, population variance is its accumulated sum of squares divided by `n` minus the squared mean, standard deviation is the square root of that variance, and minimum and maximum are copied from the raw accumulator. A small negative variance caused by floating-point cancellation is clamped only within the same ULP-derived bound used by global inter-arrival features. A materially negative or non-finite result raises `DirectionalInterArrivalFeaturesError`.

For a direction with no intervals, all five values are `None`. This applies when the direction is unseen and when exactly one packet has been observed in that direction. An observed zero-second interval instead produces real `0.0` values, preserving the distinction between available zero-valued data and unavailable statistics. Forward and reverse availability are independent for unidirectional and bidirectional flows.

Extraction uses only the fixed-size directional aggregates, is deterministic, and retains no packet or timestamp history. Global `InterArrivalFeatures` remain a separate family over adjacent packets regardless of direction. Counts, sums, durations, rates, ratios, percentiles, histograms, detection semantics, and machine-learning representations are not added. `FlowFeatureSnapshot` composes this established family from the directional statistics in its coordinated state without changing the standalone contract.

## Coordinated flow-state admission

[flow_state_coordinator.py](flow_state_coordinator.py) exports `FlowStateCoordinator`, `CoordinatedFlowState`, and `FlowCoordinationError(ValueError)`. A coordinator owns admission for one flow and starts with `state is None`. Its first successful `record(analysis: PacketAnalysis) -> CoordinatedFlowState` binds that flow; a supported packet from another flow raises `FlowCoordinationError`. The read-only `state` property returns the exact latest published object. There is no seed, restore, or externally supplied state argument.

Admission means that every applicable accumulator successfully accepts the same exact `PacketAnalysis` object. Successful packet analysis or `FlowTracker.record()` alone does not establish admission here. The fixed protocol-neutral participants are `FlowStatistics`, `DirectionalFlowStatistics`, `FlowPacketSizeStatistics`, `FlowInterArrivalStatistics`, and `DirectionalInterArrivalStatistics`. TCP flows additionally include `TCPControlStatistics`; UDP flows carry explicit `None` in that field. The first two protocol-neutral components provide volume and temporal extent inputs, packet-size statistics retain length moments, and the last two retain adjacent global and same-direction timing. Directional timing participates as complete raw state and supplies its directional feature family; it cannot be reconstructed from global aggregates.

`record()` requires exactly `PacketAnalysis`, raising `TypeError` otherwise. It derives membership through `flow_identity_from_packet()` and retains the first accepted packet's derived identity object for every subsequent accumulator update. Existing accumulator identity and direction helper calls remain unchanged. Unsupported analyses retain `FlowIdentityError`. No endpoint logic is duplicated.

Candidates are constructed in the participant order above using the previous published components and the same packet and canonical identity. A TCP candidate is produced by the established TCP control updater; UDP requires no TCP candidate. Only after all applicable updates and the result construction succeed does one reference assignment publish the new state. Any exception propagates unchanged and leaves the previous state, every previous component, and packet inputs unchanged. Earlier successful candidates are discarded; no rollback, partial publication, automatic retry, or rejected-packet retention occurs. This is a synchronous contract for sequential, non-overlapping calls; it does not provide concurrent-writer or durable transaction guarantees.

The frozen `CoordinatedFlowState` has exactly six fields: `flow_statistics`, `directional_flow_statistics`, `flow_packet_size_statistics`, `flow_inter_arrival_statistics`, `directional_inter_arrival_statistics`, and `tcp_control_statistics`. The first five retain exact updater-produced objects. The final field retains the exact TCP updater result for protocol 6 and is `None` for protocol 17. Its read-only `identity` property returns `flow_statistics.identity`, without storing another identity or copying any numerical fields. Direct construction checks exact component types and equal flow identities. It also reconciles global packet counts, directional packet and interval counts, global and directional captured and original byte totals, the global first and last capture timestamps shared by the temporal accumulators, and TCP control total and directional packet counts when present. Wrong types raise `TypeError`; missing TCP state, TCP state on UDP, or any cross-component disagreement raises `FlowCoordinationError`.

The provenance guarantee belongs to the coordinator's construction protocol: every state it publishes represents the same ordered sequence of successfully admitted analysis objects in all applicable components. By induction, the empty owner starts the protocol-neutral components together and starts TCP control state only for TCP, each successful call advances every applicable component with one common packet, and a failed call advances none. Repeated successful calls with the same packet count separately; there is no deduplication. State validation rejects observable cross-family contradictions but does not infer admission history from aggregates. Neither numerical equality, object equality, nor direct construction of a `CoordinatedFlowState` proves this history. Manually assembled or replaced bundles cannot be imported into a coordinator through its public API. References identify the retained sources but are not persistent provenance identifiers, and the packet sequence cannot be recovered from these aggregates.

The combined acceptance policy is the intersection of the existing accumulator contracts: original length must be known, globally out-of-order timestamps are rejected, and zero intervals are valid. A populated zero-duration flow is admitted as raw state; later rate extraction still raises `FlowRateFeaturesError`. Feature availability does not control admission. No rate, variance, or other feature is calculated or redefined here, and no missing-value policy is added.

Consumers can retain one published state and use its exact components with existing extractors. This provides coherent source inputs without binding arbitrary precomputed numerical features to a flow. The [feature snapshot boundary](flow_feature_snapshot.py) composes those extractors from the coordinated state retained by an observation window. The coordinator holds one current state, retains no analyses, observations, packet history, or timestamp history, and has a fixed number of retained objects regardless of packet count. `FlowTracker` remains independent and retains its existing tracking API and semantics.

## Flow observation-window lifecycle

[flow_observation_window.py](flow_observation_window.py) exports `FlowObservationWindowKey`, `FlowObservationWindowClosureReason`, `FlowObservationWindow`, `FlowObservationWindowUpdate`, `FlowObservationWindowManager`, and `FlowObservationWindowError(ValueError)`. A canonical `FlowIdentity` identifies an endpoint/protocol equivalence class rather than a lifetime. One identity may therefore produce multiple observation windows within one explicitly identified capture session. Every new window receives the next nonnegative session-scoped sequence number; failed admission never consumes a number.

The manager accepts exactly `PacketAnalysis`, uses `flow_identity_from_packet()`, and delegates accumulation to one `FlowStateCoordinator` per active identity. For an identity with an active window, an equal or later canonical UTC capture timestamp continues that window exactly when its gap from the identity's last accepted packet is less than the configured positive `timedelta`. A gap equal to or greater than the timeout closes the old window for `INACTIVITY` and admits the current packet into a new window. The old duration and global and directional inter-arrival aggregates end at its actual last packet, so the boundary gap is never accumulated. TCP flags do not create or close windows, and UDP follows the same timing rule while retaining absent TCP control state. ICMP remains unsupported by the current flow identity contract.

The latest successfully admitted capture timestamp is a nondecreasing session frontier. Earlier timestamps raise `FlowObservationWindowError` without changing active state, consuming a sequence number, or advancing the frontier. The manager uses no processing time, timestamp conversion, buffering, reordering, watermark, timer, thread, or proactive scan of other identities. A failed coordinator update likewise publishes no lifecycle transition.

`close(identity)` emits an immutable window closed for `EXPLICIT_SEGMENTATION`, and a later packet with that identity creates a new window. `end_capture_session()` closes every active window for `CAPTURE_SESSION_END` in ascending sequence-number order, removes all active entries, and permanently rejects later recording. Repeated session end returns an empty tuple. `active_windows()` exposes freshly constructed immutable wrappers in sequence order without exposing coordinators or the active mapping. Closed windows are returned to callers and are not retained internally.

The manager retains a fixed coordinator, key, and mapping entry per active identity plus scalar session state, giving `O(A)` retained state for `A` active identities and `O(1)` state per window independent of packet count. It retains no packet, closed-window, feature, flag, or payload history. `FlowTracker` and `FlowFeatureInput` remain independent. The [application composition boundary](../application/README.md) connects source-session completion with lifecycle closure without moving capture ownership into analysis.

## Typed flow feature snapshots

[flow_feature_snapshot.py](flow_feature_snapshot.py) exports `FlowFeatureSnapshot`, `FlowFeatureSnapshotError(ValueError)`, and `extract_flow_feature_snapshot(window: FlowObservationWindow) -> FlowFeatureSnapshot`. The function requires exactly `FlowObservationWindow` and reads `window.coordinated_state` once as the source for every established extractor. Coordinators, bare states, subclasses, mocks, and caller-supplied feature combinations are rejected with `TypeError`. Direct snapshot construction and `dataclasses.replace()` are not supported; extraction is the sole public construction path.

The window is the authoritative observation and lifecycle provenance boundary. The snapshot retains the exact supplied window rather than reconstructing it or storing a second coordinated-state field. Its read-only `coordinated_state` and `identity` properties delegate through that window. Active windows are valid provisional inputs, while closed windows are the authoritative finalized artifacts delivered by application orchestration. Extraction neither closes nor mutates a window.

The frozen snapshot retains exactly these seven typed fields in the listed order:

| Field | Source and extraction path |
| --- | --- |
| `observation_window` | Exact `FlowObservationWindow` supplied to extraction. |
| `flow_volume_features` | `flow_feature_input_from_statistics(state.flow_statistics, state.directional_flow_statistics)`, then `extract_flow_volume_features()`. |
| `packet_size_features` | `extract_packet_size_features(state.flow_packet_size_statistics)`. |
| `flow_duration_features` | `extract_flow_duration_features(state.flow_statistics)`. |
| `flow_rate_features` | `extract_flow_rate_features(state.flow_statistics)` for positive duration; otherwise the specific zero-duration absence described below. |
| `inter_arrival_features` | `extract_inter_arrival_features(state.flow_inter_arrival_statistics)`. |
| `directional_inter_arrival_features` | `extract_directional_inter_arrival_features(state.directional_inter_arrival_statistics)`. |

`flow_rate_features` is `Optional[FlowRateFeatures]`. `None` means only that the validated duration is exactly `0.0`, making rates undefined for a populated flow. It is distinct from an existing rate model containing numerical zero. The snapshot uses the extracted duration to recognize this case and does not call the rate extractor for it; direct rate extraction still raises `FlowRateFeaturesError`. Positive-duration rate extraction and all other extraction failures propagate unchanged. Exceptions are never converted into generic absence, and no other optional feature policy is introduced.

The snapshot retains the exact objects returned by each extractor. Lifecycle provenance remains available through `observation_window.key` and `observation_window.closure_reason` without becoming numerical feature content. It stores no duplicate coordinated state, identity, raw source fields, raw directional statistics, intermediate `FlowFeatureInput`, coordinator reference, cache, or flattened values. The directional feature object is derived from the raw directional statistics reached through the retained window. Its forward and reverse groups independently contain five `None` values when that direction has no intervals; an observed zero-second interval produces five real `0.0` values. Global features continue to describe adjacent packets, while directional features describe same-direction intervals. Later lifecycle admissions do not change an earlier window or snapshot, and repeated extraction from the same window produces equal values without caching.

One-packet windows preserve zero duration, absent rates, zero global inter-arrival features, and unavailable directional inter-arrival groups. Equal packet timestamps and unused directions preserve their established interval and packet-size semantics. Closure reason does not alter any numerical formula. Mathematical definitions, population variances, rounding policy, and validation remain owned by the existing extractors. Eager typed composition avoids repeated lazy extraction and duplicate raw-state references. This is not an ML vector or detector input contract; no numerical ordering, flattening, serialization, detection, or machine learning is defined.

## Ethernet II decoder

`analysis` exports `decode_ethernet(observation: PacketObservation) -> EthernetFrame`, `EthernetFrame`, and `EthernetDecodeError` from [ethernet.py](ethernet.py). The decoder consumes the existing capture observation model and requires explicit `LinkType(1)`. Unknown (`None`) and non-Ethernet link types raise `EthernetDecodeError`; the decoder never infers a format from packet contents.

`EthernetFrame` is a frozen dataclass with four fields:

| Field | Representation |
| --- | --- |
| `destination_mac` | Exactly six immutable bytes, preserving the destination address. |
| `source_mac` | Exactly six immutable bytes, preserving the source address. |
| `ether_type` | Integer from 0 through 65535, decoded from bytes 12–13 in network byte order. No protocol names or dispatch are assigned. |
| `payload` | Immutable bytes containing everything after the 14-byte header, unchanged and uninterpreted. |

Direct model construction validates MAC lengths, immutable byte storage, and the unsigned integer range; invalid types raise `TypeError` and invalid values raise `ValueError`. Booleans are not accepted as EtherType integers.

Frames shorter than 14 bytes raise `EthernetDecodeError` with a short-frame explanation. Exactly 14 bytes is valid and yields an empty payload. No partial frame is returned. `EthernetDecodeError` is an analysis-specific `ValueError`, never a `CaptureError`. Passing anything other than `PacketObservation` raises `TypeError`.

Only the fixed header is decoded. The two-byte type field is exposed numerically across its full range; 802.3 length interpretation, LLC/SNAP, VLAN tags, and payload protocols are not implemented. Payload includes all available trailing bytes: no padding or FCS is identified, removed, or validated, and no maximum frame size is enforced.

The observation and its capture metadata remain unchanged. The result contains decoded fields only; callers retain the original observation alongside the result when provenance is needed. Ethernet decoding does not invoke downstream decoders.

## IPv4 decoder

`analysis` exports `decode_ipv4(frame: EthernetFrame) -> IPv4Packet`, `IPv4Packet`, and `IPv4DecodeError` from [ipv4.py](ipv4.py). The caller explicitly passes an Ethernet-decoded frame; EtherType must be `0x0800`. Other types are rejected without guessing or protocol dispatch.

`IPv4Packet` is a frozen dataclass containing `version`, `ihl`, `dscp`, `ecn`, `total_length`, `identification`, `flags`, `fragment_offset`, `ttl`, `protocol`, `header_checksum`, `source_address`, `destination_address`, `options`, and `payload`. Numeric fields retain their wire values and unsigned ranges. Multi-byte numeric fields use network byte order. Addresses are exactly four immutable bytes in wire order.

Version must be 4. IHL is retained in 32-bit words, from 5 through 15; the read-only `header_length` property computes `ihl * 4` in bytes. The entire indicated header must be available. `options` preserves bytes between offsets 20 and `header_length` without interpreting individual options.

`total_length` includes the complete header and IPv4 payload. It must be at least `header_length` and no larger than the available Ethernet payload. IPv4 `payload` contains exactly `frame.payload[header_length:total_length]` as immutable bytes and may be empty. Any excess remains in the unchanged Ethernet frame, accessible as `frame.payload[packet.total_length:]`; it is not assigned padding or FCS semantics and is not part of the IPv4 packet. Callers retain the enclosing frame when those bytes are needed.

Flags preserve all three bits; fragment offset preserves the encoded 13-bit value without conversion to byte offsets or reassembly. TTL and protocol remain unsigned eight-bit integers without classification or protocol names. The structural decoder exposes the header checksum unchanged, without recalculation or validation. Options and payload are never decoded or transformed.

Malformed input raises `IPv4DecodeError`, an analysis-specific `ValueError`, never `CaptureError`. Validation rejects headers shorter than 20 bytes, incorrect version or EtherType, IHL below 5, unavailable header bytes, and inconsistent total lengths. No partial result is returned. Passing anything other than `EthernetFrame` raises `TypeError`. Direct model construction validates integer ranges, immutable byte fields, address lengths, options length, and exact header-plus-payload length; invalid types raise `TypeError` and invalid values raise `ValueError`.

IPv4 decoding does not invoke transport decoders. The caller selects each analysis operation explicitly.

## IPv4 header checksum validation

`analysis` exports `validate_ipv4_checksum(packet: IPv4Packet) -> bool` from [ipv4_checksum.py](ipv4_checksum.py). Validation is explicitly requested by the caller; `decode_ipv4()` and the TCP, UDP, and ICMP decoders do not invoke it.

The validator reconstructs the complete IPv4 header in network byte order from the existing fields, including the stored `total_length` and every option byte. It uses the standard 16-bit one's-complement checksum: the checksum field is set to zero for calculation, carries are folded back into the low 16 bits, and the complemented sum is compared with `packet.header_checksum`. The calculation covers exactly `packet.header_length` bytes, including options without interpretation, and excludes payload.

It returns `True` for a matching checksum and `False` for a mismatch. A mismatch raises neither `IPv4DecodeError` nor `CaptureError` and carries no detection or scoring semantics. Wrong input types raise `TypeError`. The packet, its checksum, options, and payload remain unchanged; no corrected packet is created.

## TCP decoder

`analysis` exports `decode_tcp(packet: IPv4Packet) -> TCPPacket`, `TCPPacket`, and `TCPDecodeError` from [tcp.py](tcp.py). The decoder accepts only `IPv4Packet`, requires protocol number 6, and rejects any nonzero IPv4 fragment offset before interpreting TCP bytes. An initial fragment may be decoded if the complete indicated TCP header is present, even when the IPv4 more-fragments flag is set. Its TCP payload includes only the bytes supplied by that fragment; successful header decoding does not imply a complete TCP segment.

`TCPPacket` is a frozen dataclass with these fields:

| Fields | Representation |
| --- | --- |
| `source_port`, `destination_port` | Unsigned 16-bit integers without service-name mapping. |
| `sequence_number`, `acknowledgment_number` | Unsigned 32-bit integers without progression or connection-state interpretation. |
| `data_offset` | Header length in 32-bit words, from 5 through 15. The read-only `header_length` property computes `data_offset * 4` bytes. |
| `reserved_bits` | Three-bit numeric value between the data-offset nibble and NS bit, retained unchanged. |
| `ns`, `cwr`, `ece`, `urg`, `ack`, `psh`, `rst`, `syn`, `fin` | Explicit booleans preserving each control bit. NS is represented separately from the three reserved bits. No flag combination is classified or normalized. |
| `window_size`, `checksum`, `urgent_pointer` | Unsigned 16-bit integers. Window scaling is not interpreted, checksum is not validated or recalculated, and urgent pointer is preserved regardless of the URG flag. |
| `options`, `payload` | Immutable bytes without interpretation or transformation. |

All multi-byte fields use network byte order. Options contain exactly the bytes from offset 20 through `header_length`; payload begins at `header_length` and extends to the end of the supplied IPv4 payload. A complete header with no following bytes yields an empty TCP payload. The original IPv4 packet remains unchanged.

Malformed input raises `TCPDecodeError`, an analysis-specific `ValueError`, never `CaptureError`. The decoder rejects incorrect IPv4 protocol, non-initial fragments, fewer than 20 bytes, data offset below 5, and indicated headers longer than the available IPv4 payload. No partial result, padding, truncation, or correction is performed. Wrong input types raise `TypeError`. Direct model construction validates integer ranges, boolean flag types, immutable byte storage, and options length; invalid types raise `TypeError` and invalid values raise `ValueError`.

This decoder performs no TCP option interpretation, stream reassembly, connection/flow tracking, or application parsing. Bidirectional flow tracking is provided separately by `FlowTracker`.

## TCP checksum validation over IPv4

`analysis` exports `validate_tcp_checksum(packet: IPv4Packet, segment: TCPPacket) -> bool` and `TCPChecksumValidationError` from [tcp_checksum.py](tcp_checksum.py). The caller supplies the decoded segment explicitly. The validator never invokes `decode_tcp()`, and neither structural decoders nor IPv4 checksum validation invoke this operation automatically.

The validator reconstructs every TCP header field in network byte order, including reserved bits and all nine control bits, with the checksum field set to zero for calculation. It appends options and payload exactly as stored, without interpretation or normalization. The IPv4 pseudo-header contains source and destination addresses, a zero byte, protocol number 6, and the reconstructed TCP header-plus-payload length. That length excludes IPv4 and Ethernet headers and is not taken from `packet.total_length`.

The standard 16-bit one's-complement sum covers the pseudo-header, TCP header, options, and payload. An odd final byte receives a zero low-order byte only in the temporary checksum input. Carries are folded, the sum is complemented, and the result is compared with `segment.checksum`: a match returns `True`, and a mismatch returns `False` without raising `TCPDecodeError` or `CaptureError`. Both input models and all byte fields remain unchanged.

Wrong object types raise `TypeError`. Non-TCP IPv4 protocol, a nonzero fragment offset, or a segment length exceeding the pseudo-header's unsigned 16-bit range raises `TCPChecksumValidationError`, an analysis-specific `ValueError`. An initial fragment with more-fragments set may proceed; the result covers only the represented segment bytes and does not establish the checksum of a complete reassembled segment.

The supplied `TCPPacket` defines the checksum bytes. IPv4 payload bytes outside it, other IPv4 header fields, and Ethernet bytes are excluded. The caller is responsible for supplying the corresponding packet and segment; the validator does not compare their payloads. No fragment or stream reassembly, connection/flow tracking, application parsing, or detection is performed.

## UDP decoder

`analysis` exports `decode_udp(packet: IPv4Packet) -> UDPPacket`, `UDPPacket`, and `UDPDecodeError` from [udp.py](udp.py). The caller chooses this independent decoder explicitly; it requires IPv4 protocol number 17 and fragment offset zero. Non-initial fragments are rejected. Initial fragments may proceed, but the complete declared UDP datagram must be present in the supplied IPv4 payload even when the more-fragments flag is set. No reassembly is attempted.

`UDPPacket` is a frozen dataclass with `source_port`, `destination_port`, `length`, `checksum`, and `payload`. Ports and checksum are unsigned 16-bit integers decoded in network byte order, without service mapping, checksum recalculation, or checksum validation. `length` is the unsigned 16-bit UDP datagram length including its fixed eight-byte header; its valid range is 8 through 65535.

The decoder requires at least eight bytes and validates that the declared length does not exceed the available IPv4 payload. UDP payload is exactly `packet.payload[8:length]` as immutable bytes, including an empty value when length is 8. Excess bytes remain in the unchanged IPv4 packet and are accessible as `packet.payload[udp.length:]`; they are not included in UDP payload or interpreted as padding or FCS. No payload bytes are inspected, transformed, padded, or invented.

Invalid protocol, fragment offset, header size, or declared length raises `UDPDecodeError`, an analysis-specific `ValueError`, never `CaptureError`. Wrong input types raise `TypeError`. Direct model construction requires exact integers, rejects booleans and mutable payload containers, checks numeric ranges, and enforces `length == 8 + len(payload)`. Invalid field types raise `TypeError`; invalid values raise `ValueError`.

This decoder performs no UDP application parsing, flow/session tracking, or detection. Bidirectional flow tracking is provided separately by `FlowTracker`; IPv6 and live capture remain unimplemented. TCP and UDP share no transport abstraction and do not dispatch to each other.

## UDP checksum validation over IPv4

`analysis` exports `validate_udp_checksum(packet: IPv4Packet, datagram: UDPPacket) -> bool` and `UDPChecksumValidationError` from [udp_checksum.py](udp_checksum.py). The caller explicitly supplies both models. The validator does not call `decode_udp()`, and neither structural decoding nor other checksum validators invoke it automatically.

The IPv4 pseudo-header contains source and destination addresses, a zero byte, protocol 17, and `datagram.length`. The UDP header is reconstructed from source port, destination port, length, and a zero checksum field, followed by unchanged payload bytes. Length must equal `8 + len(datagram.payload)` and is used in both headers; `packet.total_length` is not substituted. All multi-byte fields use network byte order.

The 16-bit one's-complement calculation covers the pseudo-header, UDP header, and payload. An odd final byte receives a zero low-order byte only in the temporary checksum input. Carries are folded and the sum is complemented. A calculated zero is compared as `0xFFFF`, its transmitted representation under [RFC 768](https://www.rfc-editor.org/rfc/rfc768.html).

A matching nonzero checksum returns `True`. A nonzero mismatch returns `False`. A stored checksum of `0x0000` also returns `False`: IPv4 UDP permits checksum omission, so this result means integrity was not validated. The boolean API does not distinguish omission from mismatch; callers can inspect `datagram.checksum`. Neither result raises a decoding or capture error, repairs data, or assigns threat meaning.

Wrong object types raise `TypeError`. Protocol other than 17, nonzero fragment offset, or inconsistent datagram length raises `UDPChecksumValidationError`, an analysis-specific `ValueError`. These boundary checks precede the zero-checksum result. Initial fragments with more-fragments set may proceed using only the represented datagram; no future fragment bytes are invented.

Both models and their byte fields remain unchanged. The supplied datagram defines the checksum bytes; Ethernet bytes, unrelated IPv4 header fields, and IPv4 payload bytes outside that datagram are excluded. The caller supplies the corresponding models; payloads are not compared. No fragment or stream reassembly, connection/flow tracking, application parsing, or detection is performed.

## ICMPv4 decoder

`analysis` exports `decode_icmp(packet: IPv4Packet) -> ICMPMessage`, `ICMPMessage`, and `ICMPDecodeError` from [icmp.py](icmp.py). The caller chooses this independent decoder explicitly; it requires IPv4 protocol number 1 and fragment offset zero. Non-initial fragments are rejected. Initial fragments may decode when the complete eight-byte generic header is present, even with the more-fragments flag set. The result contains only the supplied bytes and does not imply a complete reassembled message.

`ICMPMessage` is a frozen dataclass with `icmp_type` and `code` as unsigned eight-bit integers, `checksum` as an unsigned 16-bit integer decoded in network byte order, `rest_of_header` as exactly four immutable bytes from offsets 4–7, and `payload` as immutable bytes. Type and code retain their numeric values without names or semantic interpretation. The checksum is exposed unchanged without validation or recalculation; the rest of the header remains raw bytes without type-specific interpretation.

Payload is exactly `packet.payload[8:]`, including an empty value for an eight-byte message. The enclosing IPv4 packet and its bytes remain unchanged. No payload transformation, embedded packet decoding, or ICMP-specific message parsing is performed.

Incorrect protocol, non-initial fragments, or fewer than eight bytes raise `ICMPDecodeError`, an analysis-specific `ValueError`, never `CaptureError`. Wrong input types raise `TypeError`. Direct model construction requires exact integers, rejects booleans and mutable byte containers, checks numeric ranges, and enforces the four-byte rest-of-header length. Invalid field types raise `TypeError`; invalid values raise `ValueError`. No partial results, padding, or corrections are produced.

ICMP type/code semantics, fragment reassembly, application protocols, detection, and flow/session functionality remain unimplemented.

## ICMPv4 checksum validation

`analysis` exports `validate_icmp_checksum(packet: IPv4Packet, message: ICMPMessage) -> bool` and `ICMPChecksumValidationError` from [icmp_checksum.py](icmp_checksum.py). The caller supplies both models explicitly. The validator never invokes `decode_icmp()`, and structural decoders and other checksum validators do not invoke it automatically.

Only the ICMP message participates in the checksum. The validator reconstructs type, code, a zero 16-bit checksum field, and the four unchanged `rest_of_header` bytes, followed by unchanged payload. It interprets no type-specific fields or payload content. There is no IPv4 pseudo-header: Ethernet bytes, IPv4 addresses, other IPv4 header fields, and IPv4 payload bytes outside the supplied message are excluded. The caller supplies the corresponding models; payloads are not compared.

The standard 16-bit one's-complement calculation processes network-order words, folds carries, and complements the sum. Odd input receives a temporary zero low-order byte without altering payload. The calculated checksum is compared directly with `message.checksum`: a match returns `True`, and a mismatch returns `False` without a decoding or capture error. Zero is an ordinary checksum value and can validate successfully; it is neither an omission indicator nor mapped to `0xFFFF`.

Wrong object types raise `TypeError`. IPv4 protocol other than 1 or a nonzero fragment offset raises `ICMPChecksumValidationError`, an analysis-specific `ValueError`. Initial fragments with more-fragments set may proceed using only the represented message bytes; the result does not establish integrity of a complete reassembled message. Both models and all byte fields remain unchanged. No fragment or stream reassembly, connection/flow tracking, application parsing, or detection is performed.

## Future analysis

Analysis consumes [capture](../capture/README.md) observations. Future structured observations and features will support [detection](../detection/README.md), enrichment, event processing, and persistence as needed. Transformations must retain provenance and distinguish malformed, unsupported, and incomplete inputs.

The current tracker owns only packet counts and first/latest packet references, with no session or TCP connection semantics. Future application analysis will consume explicit analysis boundaries. Existing feature extractors consume their documented aggregate models and do not independently parse traffic. Analysis does not assign threat verdicts or manage alerts. Additional protocol support, reassembly policies, and feature families remain future implementation decisions.
