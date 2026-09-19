# Traffic analysis boundary

This directory implements Ethernet II, IPv4, TCP, UDP, and generic ICMPv4 decoding and checksum validation, IPv6 base-header, extension, fragmentation, ICMPv6, and structural TCP/UDP analysis, single-packet analysis and failure-preserving analysis outcomes, canonical IPv4/IPv6 identity values and TCP/UDP packet direction for both families, in-memory tracking, and explicit raw accumulation and feature boundaries. Raw accumulation includes global and directional volume, packet-size statistics, global and directional inter-arrival statistics, and directional TCP control observations. Implemented features cover volume and directional balance, packet sizes, duration, rates, and global and directional inter-arrival statistics. Each module's exact scope is documented below.

Additional link formats, fragment and full TCP reassembly, TCP connection state, and application semantics remain unimplemented. Bounded directional TCP prefixes and LDAP envelope observation are supported separately from transport decoding. Observation-driven inactivity closure is implemented by `FlowObservationWindowManager`; there is no background expiration timer.

## Single-packet analysis

`analysis` exports `analyze_packet(observation: PacketObservation) -> PacketAnalysis`, `PacketAnalysis`, and `PacketAnalysisError` from [packet_analysis.py](packet_analysis.py). This synchronous operation analyzes exactly one captured observation without keeping state across packets. It requires Ethernet `LinkType(1)` and dispatches IPv4 EtherType `0x0800` or IPv6 EtherType `0x86DD`; unknown or other link types and unsupported EtherTypes raise `PacketAnalysisError(ValueError)`. Wrong input types raise `TypeError`.

On the IPv4 path, the operation delegates Ethernet and IPv4 decoding to the existing decoders, validates the option envelope, then explicitly validates the IPv4 checksum. It selects the existing TCP, UDP, or ICMPv4 decoder for IPv4 protocols 6, 17, or 1 respectively and validates the corresponding checksum when fragment offset is zero. Other IPv4 protocol numbers retain the Ethernet and IPv4 results without further decoding. Decoder failures propagate unchanged; no partial result is returned after a failure.

IPv4 packet analysis validates options only within the IHL-declared option area. End of Option List (0) requires zero padding; No Operation (1) occupies one byte. Other types retain opaque data and require an available length byte, a length of at least two, and an extent within the option area. Violations raise `IPv4DecodeError` and become `STRUCTURAL_FAILURE` outcomes without partial transport or flow admission. Capture truncation remains `INCOMPLETE`. The base `IPv4Packet` and `decode_ipv4()` representation contracts remain unchanged; neither interprets option-specific semantics.

TCP packet analysis validates the option envelope in both families after decoding the complete data-offset-declared header and before IPv4 TCP checksum validation. End of Option List (0) requires zero padding, No Operation (1) occupies one byte, and other kinds require a length byte of at least two with an extent inside the option area. Malformed envelopes raise `TCPDecodeError` and yield `STRUCTURAL_FAILURE` without partial analysis or flow admission; an unavailable declared TCP header remains `INCOMPLETE`. Option-specific bodies remain opaque at this boundary; the [flow statistics reducer](#tcp-option-structural-statistics) measures selected layouts after admission. The base `TCPPacket` and `decode_tcp()` representation contracts are unchanged. IPv4 and TCP use the same bounded envelope validator without sharing protocol-specific interpretation.

`PacketAnalysis` is a frozen dataclass retaining the exact original `observation` and the exact decoder-produced model references in `ethernet`, `ipv4`, `tcp`, `udp`, `icmp`, and `ipv6`. The optional `ipv6`, `ipv6_extension_headers`, `ipv6_fragmentation`, `ipv6_icmpv6`, `ipv6_tcp`, and `ipv6_udp` fields are appended after the existing fields to preserve positional construction. The IPv6 path decodes the base header, validates the supported extension-header chain, and retains both results. When Fragment Headers are present, it also retains their packet-local semantic analysis. Terminal selectors 6 and 17 dispatch the existing TCP and UDP decoders at the validated boundary when no fragment offset is nonzero. Their results populate `ipv6_tcp` and `ipv6_udp`. A terminal selector of 58 dispatches the common ICMPv6 decoder when fragmentation permits a whole message within this packet. A supplied chain must retain the exact `ipv6` packet, and supplied fragmentation or ICMPv6 analysis must retain the exact extension-header chain. Direct construction rejects combining IPv6 with IPv4, the IPv4 `tcp`/`udp`/`icmp` fields, or checksum results. IPv6 TCP/UDP results require IPv6 and extension context, matching terminal protocol, exactly one upper-layer model, and initial-fragment semantics when Fragment Headers are present. Unused optional model fields are `None`. Its four optional boolean fields are `ipv4_checksum_valid`, `tcp_checksum_valid`, `udp_checksum_valid`, and `icmp_checksum_valid`. Direct construction checks model types and requires checksum results to be booleans or `None`.

A checksum result of `True` or `False` is preserved directly from its validator; `None` means not applicable or not performed. The IPv4 header checksum is always checked on successful IPv4 analysis, and a failed checksum does not stop subsequent structural decoding. UDP checksum zero retains `False` (integrity not validated), while a valid ICMP checksum of zero can retain `True`. No result is normalized or converted into an exception.

On the IPv4 path, transport/ICMP decoders are called before their checksum guards. The current decoders reject non-initial fragments, so those existing decode errors propagate and no transport/ICMP checksum validator runs. If a decoder returns a model for such a fragment, its checksum result remains `None`. Initial fragments with MF set may be checked subject to existing decoder requirements; checks cover only the represented bytes, without fragment reassembly.

This boundary contains orchestration only. It does not alter observations or packet bytes, perform stream reassembly, connection/flow tracking, operation-body parsing, feature extraction, or detection, or assign threat verdicts, severity, or alerts. Capture remains responsible for acquisition. IPv6 Next Header values dispatch supported structural extension validation, then TCP, UDP, or the common ICMPv6 header at the appropriate safe terminal boundary. No detector runs on this path.

## Failure-preserving packet-analysis outcome

`analysis` additionally exports `analyze_packet_outcome(observation: PacketObservation) -> PacketAnalysisOutcome`, `PacketAnalysisOutcome`, `PacketAnalysisFailureClassification`, and `PacketAnalysisOutcomeError` from [packet_analysis_outcome.py](packet_analysis_outcome.py). The existing `analyze_packet()` contract remains unchanged for callers that require its exact successful return or exception behavior. The outcome helper is the separate boundary for a caller that must preserve a recognized unsuccessful analysis attempt as immutable analytical evidence.

Every outcome retains the exact supplied `PacketObservation`. Success retains the exact `PacketAnalysis` returned by `analyze_packet()` and has no failure classification or description. Failure has no `PacketAnalysis`, has exactly one classification, and has a deterministic nonblank description. The frozen model rejects mixed success/failure states, nonexact model types, blank failure descriptions, and a successful analysis that does not retain the same observation object.

The bounded classifications are `STRUCTURAL_FAILURE`, `UNSUPPORTED`, `INCOMPLETE`, and `INTEGRITY_FAILURE`. They cover only conditions established by the current top-level analysis and decoder messages: invalid implemented header structure; unsupported link, network, protocol-decoder, or non-initial-fragment scope; explicitly insufficient available bytes; and explicit checksum mismatches. Unknown exceptions and unrecognized messages within existing broad exception classes continue to propagate rather than becoming packet evidence. IPv6 header or declared-payload truncation maps to `INCOMPLETE`; a non-6 version under IPv6 EtherType maps to `STRUCTURAL_FAILURE`. These failures retain the exact observation and decoder message with no partial analysis. Existing IPv4 and checksum classifications are unchanged.

An IPv4 UDP zero checksum remains a successful analysis with `udp_checksum_valid is False` because the existing boolean validator cannot distinguish omission from mismatch without inspecting the decoded checksum field; the outcome helper uses that field and does not label omission as an integrity failure. Unknown IPv4 protocol numbers likewise retain the existing successful network-layer analysis behavior. A failure classification records what happened under implemented analysis rules and does not establish maliciousness, an attack type, intent, or RFC-wide noncompliance.

This boundary keeps no state or packet history and does not perform detection. The packet-integrity detector consumes it through explicit application orchestration; the detector predicate remains outside analysis.

## IPv6 base-header analysis

`analysis` exports `IPv6Packet`, `IPv6DecodeError(ValueError)`, and `decode_ipv6(frame: EthernetFrame) -> IPv6Packet` from [ipv6.py](ipv6.py). The concrete frozen model follows the IPv4 decoder convention. It stores version, Traffic Class, Flow Label, Payload Length, raw Next Header, Hop Limit, packed source and destination addresses, and opaque payload bytes. The fixed header fields follow [RFC 8200, Section 3](https://www.rfc-editor.org/rfc/rfc8200.html#section-3); `header_length` is always 40. Integer types and bit ranges are validated, including exact version 6; each address must contain sixteen immutable bytes, consistent with canonical identity storage. Direct construction retains exact address and payload references and requires `payload_length == len(payload)`.

The decoder requires EtherType `0x86DD`, at least forty IPv6 bytes, version 6, and at least `40 + payload_length` available bytes. It preserves exactly the declared payload bytes and leaves any excess bytes in the retained Ethernet frame, matching IPv4's declared-length boundary. The sixteen-bit length is used literally: zero denotes zero represented payload bytes and is never replaced with captured length. Jumbo Payload options are not read; this boundary makes no jumbogram completeness claim.

Success establishes only the decoded base-header fields and availability of the bytes declared by that header. All Next Header values remain raw integers, including TCP, UDP, ICMPv6, and extension-header values. `decode_ipv6()` leaves payload opaque; extension validation is a separate operation invoked by packet analysis. Zero Hop Limit and zero Flow Label remain observed values without security interpretation. Fragment Header semantics and the common ICMPv6 header are analyzed separately as described below. Reassembly, ICMPv6 subtype decoding, Neighbor Discovery, IPv6 transport checksums remain unimplemented. Validated IPv6 TCP/UDP results support the shared flow admission described below. The existing flow-volume and TCP-control detectors separately consume applicable closed IPv4 and IPv6 flow state.

## IPv6 extension-header representation

`analysis` exports the frozen `IPv6ExtensionHeader` and `IPv6ExtensionHeaderChain` value objects from [ipv6_extension_headers.py](ipv6_extension_headers.py). Direct construction represents supplied observed metadata only. Construction does not parse, traverse, or validate an IPv6 extension-header chain, and accepted metadata does not establish protocol validity.

| Entry field | Representation |
| --- | --- |
| `header_type` | Exact integer from 0 through 255 identifying this represented header, separately from the base packet's `next_header`. No known-type whitelist or extension-type inference is applied. |
| `offset` | Exact nonnegative byte offset relative to the beginning of the IPv6 packet, not the Ethernet frame or IPv6 payload. Placement within the packet is not checked. |
| `declared_length` | Exact nonnegative declared length in bytes, or `None` when unavailable. This is supplied metadata, not an encoded length field read or converted by this model. |
| `raw_bytes` | Exact immutable `bytes` object retained unchanged. Empty or partial observations can be represented independently of declared length. |
| `next_header` | Exact integer from 0 through 255, or `None` when unavailable. It records the supplied link value without reading header contents or verifying the next entry. |

The chain retains one exact `IPv6Packet` in `packet` and one exact `tuple[IPv6ExtensionHeader, ...]` in `headers`. Packet retention anchors the offset origin and preserves base-header context without modifying `IPv6Packet` or duplicating its Next Header field. Entries remain in exactly the supplied order, including repeated entries, and retain object identity. Empty tuples are valid and mean only that no entries are represented; they do not certify that the packet contains no extensions.

Wrong scalar, byte, packet, collection, or entry types raise `TypeError`; negative offsets/lengths and out-of-range protocol identifiers raise `ValueError`. Lists and tuple subclasses are rejected rather than copied. No relationship among offsets, declared lengths, raw bytes, packet payload, or Next Header values is checked or repaired. Equality and hashing use ordinary frozen-dataclass value semantics, including ordered tuple equality.

## IPv6 extension-header validation

`analysis` exports `validate_ipv6_extension_headers(packet: IPv6Packet) -> IPv6ExtensionHeaderChain`. It accepts the exact IPv6 packet model and traverses its already-bounded payload from `packet.next_header`, following each validated header's Next Header byte in packet order. Supported structural types are Hop-by-Hop Options (0), Routing (43), Fragment (44), and Destination Options (60), using the header extents in [RFC 8200, Section 4](https://www.rfc-editor.org/rfc/rfc8200.html#section-4).

Hop-by-Hop, Routing, and Destination Options require two prefix bytes before reading Hdr Ext Len and occupy `(Hdr Ext Len + 1) * 8` bytes. Fragment occupies exactly eight bytes. A nonzero fragment offset terminates traversal immediately after that header: following bytes are fragment payload, even when Next Header names a supported extension. The retained terminal selector is that observed Next Header value, not a claim that its header is present. Offset-zero fragments continue traversal; reserved fields remain uninterpreted. Each complete extent must fit within `packet.payload_length`, which the packet model requires to equal `len(packet.payload)`. Excess Ethernet bytes cannot satisfy a missing prefix or declared extent.

The returned entries retain exact raw slices, declared byte lengths, Next Header values, and packet-relative offsets starting at 40. Each following offset advances by the previous validated length. Repeated types remain in observed order; there is no scan-ahead, reordering, deduplication, or option-body interpretation. Progress is at least eight bytes per iteration and is bounded by the represented payload. Failure raises the existing `IPv6DecodeError` without returning a partial chain. These insufficient-byte errors become `INCOMPLETE` outcomes with no partial analysis; existing structural-failure classification remains unchanged. Wrong input types raise `TypeError`, and unexpected errors propagate.

Any value outside 0, 43, 44, and 60 terminates traversal successfully, including unknown values, AH, ESP, and No Next Header (59). The derived `terminating_next_header` property returns the final entry's Next Header or the base packet's value for an empty chain. On directly constructed representations it merely projects supplied metadata and can be `None`. A validated empty chain means traversal stopped at the base Next Header. Bytes following No Next Header remain unchanged in the IPv6 payload and are not reparsed or rejected.

`decode_ipv6()` remains a base-header-only operation. `analyze_packet()` invokes validation and exposes the completed chain in `PacketAnalysis.ipv6_extension_headers`, retaining the exact IPv6 packet context. The extension validator leaves Fragment Header semantics to the separate fragmentation boundary below. Reassembly, ICMPv6, Neighbor Discovery, transport decoding, flow integration, feature extraction, detectors, and security interpretation remain outside this operation.

## IPv6 extension-header structural statistics

Feature 30 adds [ipv6_extension_header_statistics.py](ipv6_extension_header_statistics.py). The reducer consumes the exact validated `PacketAnalysis.ipv6_extension_headers` chain already produced by packet analysis for an admitted IPv6 TCP or UDP packet. IPv4 analyses return the existing empty aggregate, and ICMPv6 or unsupported IPv6 analyses never reach this flow-owned boundary because the existing flow identity contract admits only TCP and UDP.

`IPv6ExtensionHeaderStatistics` is a frozen aggregate. It records IPv6 packet count; packets containing one or more supported extension headers; minimum, maximum and total chain cardinality; sparse extension-type counts; sparse terminal Next Header counts; and duplicate extension-header occurrences. A duplicate is each occurrence of a header type after its first occurrence within one packet. Empty chains count as IPv6 packets and contribute their terminal Next Header without contributing an extension type. Direction follows the existing canonical `FlowDirection`; no client/server or initiator/responder role is inferred.

The extension-type and terminal Next Header distributions are immutable occupied `(wire_value, count)` tuples in ascending order, with 256 possible values each. `IPV6_EXTENSION_HEADER_MAX_COUNT` is 8,191 entries, derived from the minimum eight-byte supported extension extent within the bounded 65,535-byte IPv6 payload. The reducer validates chain identity, ordering, declared offsets and lengths, supported entry types and packet bounds before aggregation. It consumes the parser's validated structural model without reparsing packet bytes or retaining raw headers.

The directional result is stored in `CoordinatedFlowState.ipv6_extension_header_statistics` and exposed by `FlowObservationWindow.ipv6_extension_header_statistics`. Each admitted IPv6 packet contributes once during coordinator preparation; failed state construction or publication leaves the prior aggregate retryable. Repeated accepted packets count as separate packet observations, while window closure, inactivity, capacity eviction, explicit close, capture-session end and publication retry preserve already published values. The aggregate retains only counters, extrema and sparse tuples; it retains no packet, payload, chain, flow or capture reference.

Malformed or inconsistent public chain metadata raises the existing value/type failures and cannot produce a partial aggregate. Packet truncation and extension-length failures remain packet-analysis outcomes below this layer. This feature does not reassemble fragments, correlate packets, interpret option bodies, decode ICMPv6 subtypes, assign attack meaning, change `FlowFeatureSnapshot`, or run detection. Validation uses synthetic IPv4/IPv6 traffic through all four classic PCAP encodings and nine hash-seed/timezone combinations; no external corpus or fragmentation reassembly is claimed.

## IPv6 Fragment Header semantic analysis

`analysis` exports `IPv6FragmentHeader`, `IPv6Fragmentation`, and `analyze_ipv6_fragmentation(extension_headers: IPv6ExtensionHeaderChain) -> IPv6Fragmentation` from [ipv6_fragmentation.py](ipv6_fragmentation.py). This packet-local boundary follows [RFC 8200, Section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5). It retains the exact supplied chain and exposes its exact IPv6 packet through `packet`. Its immutable `headers` tuple contains one semantic view per observed type-44 entry, in chain order, including repeated Fragment Headers.

Because directly constructed extension chains do not certify packet structure, fragmentation analysis compares the supplied chain with the existing extension validator's result before creating any semantic views. This delegates traversal and payload bounds to the same validator, once per analysis, without a second structural parser. Missing packet bytes retain the existing `IPv6DecodeError` and `INCOMPLETE` outcome behavior. Incorrect argument types raise `TypeError`; inconsistent caller-supplied chain metadata raises `ValueError` and is not converted into packet evidence. Unexpected exceptions propagate, with no partial analysis.

Each frozen `IPv6FragmentHeader` retains its exact `extension_header`, including the original raw bytes and packet-relative offset. Its read-only properties derive these observed fields without storing redundant copies:

| Property | Wire representation |
| --- | --- |
| `next_header` | Byte 0, preserved as an unsigned eight-bit selector. |
| `reserved` | Byte 1, preserved as an unsigned eight-bit value. |
| `fragment_offset` | High thirteen bits of the network-order integer in bytes 2–3, retained in eight-octet units. |
| `reserved_bits` | Bits 2–1 of byte 3, preserved as a two-bit value. |
| `more_fragments` | Bit 0 of byte 3, exposed as an explicit boolean. |
| `identification` | Bytes 4–7, preserved as a network-order unsigned 32-bit integer. |

A directly constructed header view requires an exact `IPv6ExtensionHeader` of type 44, declared length eight, exactly eight immutable raw bytes, and matching Next Header metadata. Short and long byte sequences are rejected without truncation. This local view alone does not certify packet provenance; use the fragmentation analysis boundary to establish correspondence with the packet. Both reserved fields are preserved even when nonzero; RFC 8200 specifies that receivers ignore them. No reserved value, offset, or M flag produces a security interpretation.

The local predicates `is_whole_datagram`, `is_first_fragment`, `is_non_first_fragment`, `is_last_fragment`, and `is_intermediate_fragment` depend only on this header's offset and M flag. Whole-datagram means offset zero and M false; first means offset zero and M true; non-first means positive offset; intermediate means positive offset and M true. Last means M false, including the whole-datagram case. These predicates do not certify capture completeness, transport validity, or successful reassembly. Whole-datagram headers remain present, and no replacement packet is synthesized.

`PacketAnalysis.ipv6_fragmentation` retains the exact semantic analysis when at least one Fragment Header is present; it remains `None` on IPv4 and IPv6 paths without Fragment Headers. Explicit analysis of a validated chain without Fragment Headers returns `IPv6Fragmentation` with an empty `headers` tuple. Extension traversal and termination behavior remain unchanged, including after a nonzero fragment offset. Repeated headers are separate observations, not a reassembly sequence. Fragmentation analysis itself leaves following protocol selectors undecoded; packet analysis applies the TCP/UDP and ICMPv6 gates described below.

This fragmentation boundary performs no fragment reassembly, buffering, cross-packet state or correlation, overlap or duplicate detection, fragmentation attack detection, ICMPv6 decoding, transport decoding, IPv6 flow integration, or IPv6 detection. No detector or finding contract changes.

## ICMPv6 common-header analysis

`analysis` exports the frozen `ICMPv6Packet` and `decode_icmpv6(extension_headers: IPv6ExtensionHeaderChain) -> ICMPv6Packet` from [icmpv6.py](icmpv6.py). The model retains the exact supplied chain and exposes its exact IPv6 packet through `packet`. It derives `offset`, `raw_bytes`, `icmp_type`, `code`, `checksum`, and `body` from that context. Under [RFC 4443, Section 2.1](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1), terminal Next Header 58 selects ICMPv6; its common header contains eight-bit Type, eight-bit Code, and a network-order sixteen-bit Checksum. The remaining declared IPv6 payload is the opaque message body, including an empty body. `is_error_message` covers Types 0–127 and `is_informational_message` covers 128–255 without subtype or security interpretation.

Construction delegates chain certification to the existing fragmentation analysis boundary, which uses the existing extension validator. No extension traversal is duplicated. The ICMPv6 packet-relative offset is 40 without extensions, otherwise the final validated entry's offset plus length. `raw_bytes` preserves the four-byte header and entire remaining body within the already-bounded IPv6 payload. Neither Ethernet trailing bytes nor header-like body contents are examined for additional messages. Fields are derived during frozen construction; callers cannot supply inconsistent semantic fields or mutable byte containers.

Packet analysis appends `ipv6_icmpv6` while retaining previous positional arguments. It decodes only terminal selector 58 when no Fragment Header is present or every observed Fragment Header has offset zero and M false. First fragments with M true and all non-first fragments retain their existing IPv6 and fragmentation analysis with `ipv6_icmpv6=None`, even if four or more bytes follow. Repeated Fragment Headers must all satisfy the same local whole-datagram condition. The direct decoder rejects other terminal protocols or fragments requiring reassembly with the existing `IPv6DecodeError`; these messages are recognized as `UNSUPPORTED` by the outcome classifier. Invalid supplied chains and unexpected internal errors propagate. A safe ICMPv6 boundary with fewer than four bytes raises the existing `IPv6DecodeError` and yields `INCOMPLETE` without partial `PacketAnalysis`.

Checksum is preserved as observed, including zero and 65535; it is never calculated or validated and no validity field is added. Message subtype decoding, embedded packet parsing, Neighbor Discovery, cross-packet state, reassembly, flow integration, and detection/security interpretation remain outside this packet-local feature.

## IPv6 transport header analysis

The existing [TCP decoder](tcp.py) and [UDP decoder](udp.py) accept `Union[IPv4Packet, IPv6Fragmentation]` through their unchanged `packet` argument. They return the same frozen `TCPPacket` and `UDPPacket` models for either family. IPv6 callers supply `analyze_ipv6_fragmentation(validated_chain)`, including its empty-fragment result for unfragmented packets. This existing context certifies the supplied chain against the authoritative validator and exposes fragment position. A bare `IPv6Packet` or directly supplied chain is not accepted by these decoders. The decoders do not invoke extension validation or implement another traversal.

Following [RFC 8200, Section 4](https://www.rfc-editor.org/rfc/rfc8200.html#section-4), `terminating_next_header` selects TCP (6) or UDP (17). The packet-relative transport offset is 40 without extensions, otherwise the last validated extension's offset plus declared length. Decoding reads only the remaining already-bounded `IPv6Packet.payload`. There is no payload scan-ahead, signature search, use of Ethernet trailing bytes, or repeated IPv6 length validation. Original header bytes remain in the IPv6 packet; the semantic transport models do not add redundant offset or raw-header fields.

TCP applies its established structural rules to this slice: at least twenty bytes, data offset at least five, and the full indicated header including options must be present. All existing fields, control bits, options, and remaining packet-local payload are preserved. The header layout follows [RFC 9293, Section 3.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1), retaining the repository's existing nine-control-bit representation. UDP requires eight fixed header bytes, length at least eight, and the complete declared datagram within the upper-layer slice, as in the IPv4 path. Its length includes the header under [RFC 768](https://www.rfc-editor.org/rfc/rfc768.html). Bytes beyond the UDP length remain in the IPv6 packet but are excluded from `UDPPacket.payload`. Jumbo Payload options and UDP jumbograms remain unsupported.

Any non-first Fragment Header prevents TCP/UDP packet-analysis dispatch, even if later bytes resemble a complete transport header. The IPv6 and fragmentation results are retained with `ipv6_tcp=None` and `ipv6_udp=None`. Direct transport decoding of such a context raises the existing `TCPDecodeError` or `UDPDecodeError`. First and whole-datagram fragments may decode subject to the same structural byte requirements. A first TCP fragment carries only its own payload; successful decoding does not establish a complete segment. A first UDP fragment whose declared datagram exceeds available bytes is incomplete, even when its fixed header is present. No reassembly, fragment cache, cross-packet correlation, or synthesized transport header exists. Existing extension traversal behavior itself is unchanged.

`PacketAnalysis` appends `ipv6_tcp` and `ipv6_udp` after `ipv6_icmpv6`, preserving all earlier positional fields and their IPv4 meanings. Existing Fragment Header context is passed directly to the decoder; packets without Fragment Headers use an empty-fragment context internally while retaining `ipv6_fragmentation=None`. ICMPv6 retains its existing whole-datagram gate. No Next Header (59) and unsupported terminal selectors produce neither TCP nor UDP.

Incomplete fixed headers, TCP options, and UDP datagrams use the existing `INCOMPLETE` outcome classification. Invalid TCP data offsets and UDP lengths below eight use `STRUCTURAL_FAILURE`. No failed decode publishes partial `PacketAnalysis`, and unknown internal exceptions propagate. Checksum fields preserve observed values only; IPv6 transport checksum validation is not implemented, including for a zero UDP checksum. IPv4 checksum behavior is unchanged. Flow admission consumes these semantic results in the separate boundary below. IPv6 feature parity, IPv6 detection parity, and Flow Label semantics remain outside transport analysis.

## Bidirectional flow identity

`analysis` exports `flow_identity_from_packet(analysis: PacketAnalysis) -> FlowIdentity`, `FlowIdentity`, and `FlowIdentityError` from [flow_identity.py](flow_identity.py). The operation uses only decoded network addresses, transport ports, and protocol selectors. IPv4 uses `ipv4`, `tcp`/`udp`, and the IPv4 protocol number. IPv6 uses the exact packed addresses from `ipv6`, ports from `ipv6_tcp`/`ipv6_udp`, and `ipv6_extension_headers.terminating_next_header`. It supports TCP (6) and UDP (17); ICMPv4, ICMPv6, No Next Header, and other protocols are intentionally outside this boundary. Checksum results do not affect identity creation, and no checksum validation or raw-byte inspection is performed.

`FlowIdentity` is a frozen dataclass containing `source_address`, `destination_address`, `source_port`, `destination_port`, and `protocol`. Both addresses must be immutable packed bytes of the same family: four bytes for IPv4 or sixteen bytes for IPv6. The read-only `ip_version` property exposes 4 or 6 from that validated representation without storing redundant family state. Ports remain integers from 0 through 65535, and protocol remains exactly 6 or 17, independently of IP version. Wrong field types raise `TypeError`, including booleans in integer fields and mutable address containers; invalid lengths, mixed families, ports, or protocols raise `ValueError`.

`flow_identity_from_addresses(source_address: str, destination_address: str, source_port: int, destination_port: int, protocol: int) -> FlowIdentity` is the separate text construction boundary. It uses standard-library `ipaddress.ip_address()` validation and packed output before applying the same identity constructor. Compressed, expanded, and differently cased equivalent IPv6 addresses produce equal identities and equal hashes. IPv4-mapped IPv6 addresses remain IPv6 and do not alias IPv4 identities. Non-string inputs raise `TypeError`; malformed addresses, prefix notation, and scoped IPv6 text raise `ValueError`. Scope identifiers are rejected because this identity has no interface/zone field and must not silently discard one.

Packed storage preserves existing field types, exact supplied byte references, equality, hashing, and packet-direction comparisons. Valid IPv6 TCP/UDP analyses now enter the same `FlowTracker`, `FlowStateCoordinator`, and `FlowObservationWindowManager` paths as IPv4. Identity and direction share one internal semantic endpoint selector, with no byte parsing, extension traversal, fragmentation parsing, textual normalization, or second canonical ordering scheme. Volume detection supports IPv4/IPv6 TCP and UDP; TCP-control detection supports TCP in both families.

Construction orders the complete `(address, port)` endpoints lexicographically using bytes and integer comparison. The smaller endpoint occupies the source fields; the larger occupies the destination fields. This also applies to direct model construction. Equal addresses are ordered by port, and identical endpoints are valid. Forward and reverse packets produce equal identities; protocol remains part of equality. Canonical source/destination labels do not preserve packet direction or identify clients and servers.

Wrong top-level input raises `TypeError`. Missing network or required IPv6 context, unsupported protocol, missing corresponding TCP/UDP model, or conflicting transport models raises `FlowIdentityError(ValueError)`. No missing fields are inferred from observations or payloads. The value retains no analysis reference or capture metadata and modifies no existing model.

This is identity only: it maintains no flow state and performs no tracking, timeout handling, TCP connection tracking, stream or fragment reassembly, feature extraction, or detection.

IPv6 admission requires the retained extension chain to reference the exact IPv6 packet. Existing fragmentation context must reference that chain, and non-first fragment observations are rejected. PacketAnalysis remains responsible for model consistency and validated transport semantics. First and whole-datagram fragments participate only when packet analysis produced a TCP/UDP result; a Fragment Header alone never supplies ports. No fragment reassembly or cross-packet fragment correlation is performed, and Flow Label is not part of identity.

The shared lifecycle preserves canonical UTC capture times, directional raw accumulation, timeout boundaries, atomic publication, and application-session delivery. Its required TCP control accumulator selects `ipv6_tcp` for IPv6 while retaining the existing counters and formulas. No feature extractor or detector is invoked by admission; feature snapshot schemas and calculations are unchanged. Existing generic extractors remain separately callable and support both IPv4 and IPv6 TCP/UDP state. Applicable IPv4 and IPv6 detector evaluations remain separate explicit operations.

## Packet direction relative to flow identity

`analysis` exports `FlowDirection`, `FlowDirectionError`, and `flow_direction_from_packet(analysis: PacketAnalysis, identity: FlowIdentity) -> FlowDirection` from [flow_direction.py](flow_direction.py). The enum contains `FORWARD = "forward"` and `REVERSE = "reverse"`; the function returns an enum member, not a string.

`FlowIdentity` remains authoritative for canonical endpoint ordering. Each endpoint includes its packed address (four bytes for IPv4 or sixteen for IPv6) and transport port. For TCP (6) and UDP (17), the function compares both decoded packet endpoints directly with the supplied identity and requires the protocol to match. Canonical source-to-destination is `FORWARD`; the opposite pair is `REVERSE`. No new identity is constructed and no endpoints are sorted. If both canonical endpoints are identical, the forward match takes precedence and returns `FORWARD` deterministically.

Wrong argument types raise `TypeError`. Missing network or corresponding transport models, conflicting transport models, ICMP, and unsupported protocols retain the existing `FlowIdentityError` boundary. A supported packet with a different protocol or endpoint pair from the supplied identity raises `FlowDirectionError(ValueError)`. Inputs remain unchanged.

Direction is stateless and deterministic, independent of checksum results, timestamps, payload contents, TCP flags, and call order. Port values participate only in endpoint equality; no client/server or initiator/responder roles are inferred. The module does not calculate statistics or depend on `FlowTracker` or `FlowStatistics`. It supports IPv4/IPv6 TCP/UDP direction. ICMP direction, application parsing, TCP state, reassembly, and detection remain outside this boundary; tracking and window lifecycle are separate analysis operations.

## In-memory bidirectional flow tracking

`analysis` exports `FlowPacket`, `FlowSnapshot`, `FlowTracker`, and `FlowTrackingError` from [flow_tracker.py](flow_tracker.py). `FlowTracker()` starts empty and groups analyzed IPv4/IPv6 TCP/UDP packets through the authoritative `flow_identity_from_packet()` operation. Reverse-direction packets update the same bidirectional entry. Checksums are not inspected, and identity errors propagate unchanged; ICMP and unsupported traffic are not silently discarded.

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

`analysis` exports `FlowStatistics`, `FlowStatisticsError`, and `update_flow_statistics(current: Optional[FlowStatistics], analysis: PacketAnalysis, identity: FlowIdentity) -> FlowStatistics` from [flow_statistics.py](flow_statistics.py). The function is independent of `FlowTracker` and keeps no state. It verifies membership through `flow_identity_from_packet(analysis) == identity`, supporting the existing IPv4/IPv6 TCP/UDP boundary without inspecting checksums. Identity errors propagate unchanged; mismatched supplied or current identities raise `FlowStatisticsError(ValueError)`.

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

## Raw-statistics input for features

`analysis` exports `FlowFeatureInput`, `FlowFeatureInputError`, and `flow_feature_input_from_statistics(statistics: FlowStatistics, directional: DirectionalFlowStatistics) -> FlowFeatureInput` from [flow_feature_input.py](flow_feature_input.py). This is the explicit input contract consumed by volume feature extraction; it performs no feature extraction or detection and computes no derived metric.

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

`analysis` exports `FlowPacketSizeStatistics`, `FlowPacketSizeStatisticsError`, and `update_flow_packet_size_statistics(current: Optional[FlowPacketSizeStatistics], analysis: PacketAnalysis, identity: FlowIdentity) -> FlowPacketSizeStatistics` from [flow_packet_size_statistics.py](flow_packet_size_statistics.py). This independent, stateless update accumulates raw packet lengths for the separate packet-size feature extractor without changing existing trackers or feature models.

The frozen model contains exactly 28 fields: `identity`; global `packet_count`, `captured_bytes`, `original_bytes`, `min_captured_length`, `max_captured_length`, `sum_captured_length_squares`, `min_original_length`, `max_original_length`, and `sum_original_length_squares`; and nine fields for each of the `forward_` and `reverse_` prefixes: `packet_count`, `captured_bytes`, `min_captured_length`, `max_captured_length`, `sum_captured_length_squares`, `original_bytes`, `min_original_length`, `max_original_length`, and `sum_original_length_squares`.

Lengths come directly from `PacketObservation.captured_length` and `original_length`, never from raw bytes or protocol models. Unknown `original_length=None` raises `FlowPacketSizeStatisticsError(ValueError)`. Each update adds one to the global count, adds both lengths to byte totals, and adds each length multiplied by itself to the corresponding sum of squares using integer arithmetic. Global minima and maxima begin at the first packet's lengths and subsequently use `min`/`max`.

Direction and membership delegate once to `flow_direction_from_packet()`. Only the selected direction's aggregates change. Its first packet initializes minima and maxima to its lengths; an unused direction retains zero counters and aggregates. A genuine zero-length packet is valid and remains part of later minimum calculations. The result retains the exact supplied identity object; unequal current identities raise `FlowPacketSizeStatisticsError`, and existing direction/identity errors propagate unchanged. Failed updates preserve every input.

Direct construction requires a `FlowIdentity` and 27 exact nonnegative integers, rejecting booleans and other wrong types with `TypeError`. Global packet count must be at least one. Global and directional minima cannot exceed maxima; original-byte totals must cover captured-byte totals. A direction with zero packets must have all eight length aggregates zero. Invalid values raise `FlowPacketSizeStatisticsError`. Sums of squares are validated as nonnegative integers without reconstruction or reconciliation from other fields.

Only the identity and integers are retained: no packets, raw bytes, timestamps, packet collections, direction state, or previous statistics object. No floating-point accumulation, mean, variance, standard deviation, ratios, rates, duration, feature extraction, detection, machine learning, reassembly, persistence, or concurrency is added.

## Packet-size statistical features

`analysis` exports `PacketSizeFeatures`, `PacketSizeFeaturesError`, and `extract_packet_size_features(statistics: FlowPacketSizeStatistics) -> PacketSizeFeatures` from [packet_size_features.py](packet_size_features.py). `FlowPacketSizeStatistics` is the sole project-layer input boundary. Wrong input types raise `TypeError`; extraction is deterministic and leaves its input unchanged.

The frozen model contains fourteen fields: `min_captured_length`, `max_captured_length`, `mean_captured_length`, `variance_captured_length`, `standard_deviation_captured_length`, `min_original_length`, `max_original_length`, `mean_original_length`, `variance_original_length`, `standard_deviation_original_length`, `forward_mean_captured_length`, `reverse_mean_captured_length`, `forward_variance_captured_length`, and `reverse_variance_captured_length`. All four min/max values are copied directly as integers; the other ten fields are floats. Direct construction rejects booleans and incorrect types with `TypeError`, and rejects negative values, non-finite floats, or reversed min/max pairs with `PacketSizeFeaturesError(ValueError)`.

For each global length kind, mean is its byte total divided by `packet_count`; population variance is its sum of squared lengths divided by `packet_count`, minus mean squared: `E[X^2] - E[X]^2`. Global standard deviation is `math.sqrt(variance)`. Forward and reverse captured means and population variances use their own byte totals, squared-length totals, and packet counts. An unused direction produces exactly `0.0` for mean and variance. Global count is already positive under the accumulator contract. No sample-variance denominator, rounding, string conversion, or reconciliation of global and directional values is used.

Cancellation is detected using a deterministic floating-point error bound. With computed mean `m`, second moment `s`, squared mean `q = m*m`, and `u = math.ulp(m)`, the bound is `math.ulp(s) + math.ulp(q) + u * (2*abs(m) + u)`. When the magnitude of `s - q` is within this bound, variance is recovered from the exact integer moments as `(n * sum_of_squares - total * total) / (n * n)`. This preserves small positive variance and exact zero instead of losing differences or inventing positive variance through cancellation. A negative exact numerator is rejected; outside this cancellation region, existing floating-point arithmetic is unchanged and negative variance is rejected. Non-finite or overflowing moments still raise `PacketSizeFeaturesError`. The population formula, source aggregates, public fields and feature contract remain unchanged.

The result retains only integers and floats, with no identity, input object, packets, raw bytes, or timestamps. This family adds no directional standard deviations, duration/rate/inter-arrival features, ratios, medians, percentiles, histograms, entropy, other feature families, detection, machine learning, or generic framework.

## Flow duration feature

`analysis` exports `FlowDurationFeatures`, `FlowDurationFeaturesError`, and `extract_flow_duration_features(statistics: FlowStatistics) -> FlowDurationFeatures` from [flow_duration_features.py](flow_duration_features.py). `FlowStatistics` is the sole input boundary; the extractor requires its exact type and rejects subclasses and other inputs with `TypeError`.

The frozen result contains exactly one field, `duration_seconds: float`, calculated as `(statistics.last_captured_at - statistics.first_captured_at).total_seconds()`. Python datetime subtraction is used directly, with no wall-clock access, rounding, truncation, or timezone normalization. Zero duration produces exactly `0.0`; fractional seconds, including microseconds, are preserved by the ordinary `total_seconds()` calculation.

Direct construction requires an exact float, rejecting booleans, integers, strings, and other types with `TypeError`. Negative or non-finite values raise `FlowDurationFeaturesError(ValueError)` without coercion or clamping. Extraction is deterministic, leaves the source unchanged, and retains no input object, identity, timestamps, packets, raw bytes, or metadata. This family implements duration only and performs no detection or machine learning.

## Flow rate features

`analysis` exports `FlowRateFeatures`, `FlowRateFeaturesError`, and `extract_flow_rate_features(statistics: FlowStatistics) -> FlowRateFeatures` from [flow_rate_features.py](flow_rate_features.py). `FlowStatistics` is the sole project-layer input boundary. Its exact type is required; subclasses and unrelated objects raise `TypeError`. No duration feature object is used.

Duration is computed directly as `(statistics.last_captured_at - statistics.first_captured_at).total_seconds()`. For positive duration, the three frozen fields are `packets_per_second = packet_count / duration_seconds`, `captured_bytes_per_second = captured_bytes / duration_seconds`, and `original_bytes_per_second = original_bytes / duration_seconds`. Each uses its own authoritative numerator with ordinary floating-point division, without rounding, truncation, normalization, or transformation.

For zero duration, all-zero numerators produce exactly `0.0` for all three rates; any positive numerator makes extraction undefined and raises `FlowRateFeaturesError(ValueError)` for the entire operation. No infinity, NaN, or partial result is returned. Under the current `FlowStatistics` invariant `packet_count >= 1`, every normally constructed zero-duration input is therefore rejected; the all-zero policy remains explicit without weakening that model. Negative or non-finite duration and overflowing/non-finite rates are also rejected without clamping.

If converting an integer numerator for ordinary division overflows, extraction retries using the duration float's exact integer ratio. A finite quotient remains available even when the numerator alone exceeds float range; an unrepresentable quotient still raises `FlowRateFeaturesError`. Ordinary successful divisions retain their existing results.

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

Cancellation handling accounts for the rounded accumulation of nonnegative intervals and their squared values. For interval count `n`, let `e = n * math.ulp(mean)`. A negative variance is treated as zero only when its magnitude is at most `n * math.ulp(second_moment) + math.ulp(mean * mean) + e * (2 * abs(mean) + e)`. The count-scaled moment allowances cover accumulation rounding, and the final term propagates mean error through squaring. Unlike packet-size sums, inter-arrival sums are accumulated as floats. Omitting this accumulation allowance can reject valid periodic flows. More negative variance raises `InterArrivalFeaturesError`; overflow and non-finite derived values are rejected without normalization. Zero and positive variances remain unchanged. This bound does not recover precision lost to cancellation or reconstruct intervals.

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

For a direction with interval count `n > 0`, mean is its accumulated sum divided by `n`, population variance is its accumulated sum of squares divided by `n` minus the squared mean, standard deviation is the square root of that variance, and minimum and maximum are copied from the raw accumulator. A small negative variance caused by floating-point cancellation is clamped only within the same count-scaled ULP-derived bound used by global inter-arrival features, using that direction's own interval count. A materially negative or non-finite result raises `DirectionalInterArrivalFeaturesError`.

For a direction with no intervals, all five values are `None`. This applies when the direction is unseen and when exactly one packet has been observed in that direction. An observed zero-second interval instead produces real `0.0` values, preserving the distinction between available zero-valued data and unavailable statistics. Forward and reverse availability are independent for unidirectional and bidirectional flows.

Extraction uses only the fixed-size directional aggregates, is deterministic, and retains no packet or timestamp history. Global `InterArrivalFeatures` remain a separate family over adjacent packets regardless of direction. Counts, sums, durations, rates, ratios, percentiles, histograms, detection semantics, and machine-learning representations are not added. `FlowFeatureSnapshot` composes this established family from the directional statistics in its coordinated state without changing the standalone contract.

## Coordinated flow-state admission

[flow_state_coordinator.py](flow_state_coordinator.py) exports `FlowStateCoordinator`, `CoordinatedFlowState`, and `FlowCoordinationError(ValueError)`. A coordinator owns admission for one flow and starts with `state is None`. Its first successful `record(analysis: PacketAnalysis) -> CoordinatedFlowState` binds that flow; a supported packet from another flow raises `FlowCoordinationError`. The read-only `state` property returns the exact latest published object. There is no seed, restore, or externally supplied state argument.

Admission means that every applicable accumulator successfully accepts the same exact `PacketAnalysis` object. Successful packet analysis or `FlowTracker.record()` alone does not establish admission here. The fixed protocol-neutral participants are `FlowStatistics`, `DirectionalFlowStatistics`, `FlowPacketSizeStatistics`, `FlowInterArrivalStatistics`, and `DirectionalInterArrivalStatistics`. TCP flows additionally include `TCPControlStatistics`, optional `LDAPFlowStatistics`, `TCPStreamState`, optional `LDAPStreamState`, and optional `LDAPCorrelationState`; UDP flows carry explicit `None` in those fields. The first two protocol-neutral components provide volume and temporal extent inputs, packet-size statistics retain length moments, and the last two retain adjacent global and same-direction timing. Directional timing participates as complete raw state and supplies its directional feature family; it cannot be reconstructed from global aggregates.

`record()` requires exactly `PacketAnalysis`, raising `TypeError` otherwise. It derives membership through `flow_identity_from_packet()` and retains the first accepted packet's derived identity object for every subsequent accumulator update. Existing accumulator identity and direction helper calls remain unchanged. Unsupported analyses retain `FlowIdentityError`. No endpoint logic is duplicated.

Candidates are constructed in the participant order above using the previous published components and the same packet and canonical identity. TCP candidates use the established TCP control updater followed by the optional LDAP observation updater and bounded directional stream updater, then incremental LDAP framing/consumption and request/response correlation; UDP requires none of those candidates. Only after all applicable updates and the result construction succeed does one reference assignment publish the new state. Any exception propagates unchanged and leaves the previous state, every previous component, and packet inputs unchanged. Earlier successful candidates are discarded; no rollback, partial publication, automatic retry, or rejected-packet retention occurs. This is a synchronous contract for sequential, non-overlapping calls; it does not provide concurrent-writer or durable transaction guarantees.

The frozen `CoordinatedFlowState` has ten fields: `flow_statistics`, `directional_flow_statistics`, `flow_packet_size_statistics`, `flow_inter_arrival_statistics`, `directional_inter_arrival_statistics`, `tcp_control_statistics`, optional `ldap_statistics`, optional `tcp_stream_state`, optional `ldap_stream_state`, and optional `ldap_correlation_state`. The first five retain exact updater-produced objects. The TCP-control field retains the exact TCP updater result for protocol 6 and is `None` for protocol 17. The optional fields retain LDAP candidate statistics and bounded directional stream observations with matching TCP identities; all default to `None` for compatibility with earlier constructors. LDAP framing retains the exact TCP stream state in the bundle, including its consumption cursors; a different retained TCP state is rejected. Optional correlation retains that exact LDAP framing state and must be active at admission; finalized correlation is a window projection. Its read-only `identity` property returns `flow_statistics.identity`, without storing another identity or copying any numerical fields. Direct construction checks exact component types and equal flow identities. It also reconciles global packet counts, directional packet and interval counts, global and directional captured and original byte totals, the global first and last capture timestamps shared by the temporal accumulators, and TCP control total and directional packet counts when present. Wrong types raise `TypeError`; missing TCP state, TCP state on UDP, or any cross-component disagreement raises `FlowCoordinationError`.

The provenance guarantee belongs to the coordinator's construction protocol: every state it publishes represents the same ordered sequence of successfully admitted analysis objects in all applicable components. By induction, the empty owner starts the protocol-neutral components together and starts TCP control state only for TCP, each successful call advances every applicable component with one common packet, and a failed call advances none. Repeated successful calls with the same packet count separately in packet accumulators; the separate stream contract suppresses duplicate application bytes. State validation rejects observable cross-family contradictions but does not infer admission history from aggregates. Neither numerical equality, object equality, nor direct construction of a `CoordinatedFlowState` proves this history. Manually assembled or replaced bundles cannot be imported into a coordinator through its public API. References identify the retained sources but are not persistent provenance identifiers, and the packet sequence cannot be recovered from these aggregates.

The combined acceptance policy is the intersection of the existing accumulator contracts: original length must be known, globally out-of-order timestamps are rejected, and zero intervals are valid. A populated zero-duration flow is admitted as raw state; later rate extraction still raises `FlowRateFeaturesError`. Feature availability does not control admission. No rate, variance, or other feature is calculated or redefined here, and no missing-value policy is added.

Consumers can retain one published state and use its exact components with existing extractors. This provides coherent source inputs without binding arbitrary precomputed numerical features to a flow. The [feature snapshot boundary](flow_feature_snapshot.py) composes those extractors from the coordinated state retained by an observation window. The coordinator holds one current state, retains no packet objects, per-packet history, or timestamp history, and has a fixed number of retained objects regardless of packet count. Stream state retains at most one bounded payload prefix per direction. `FlowTracker` remains independent and retains its existing tracking API and semantics.

## Flow observation-window lifecycle

[flow_observation_window.py](flow_observation_window.py) exports `FlowObservationWindowKey`, `FlowObservationWindowClosureReason`, `FlowObservationWindow`, `FlowObservationWindowUpdate`, `FlowObservationWindowManager`, `DEFAULT_MAX_ACTIVE_WINDOWS`, and `FlowObservationWindowError(ValueError)`. A canonical `FlowIdentity` identifies an endpoint/protocol equivalence class rather than a lifetime. One identity may therefore produce multiple observation windows within one explicitly identified capture session. Every new window receives the next nonnegative session-scoped sequence number; failed admission never consumes a number.

`FlowObservationWindowManager(capture_session_id, inactivity_timeout, *, max_active_windows=1024)` bounds the number of retained active identities. The limit must be an exact positive integer: wrong types, including booleans and `None`, raise `TypeError`; nonpositive values raise `FlowObservationWindowError`. `DEFAULT_MAX_ACTIVE_WINDOWS` is 1,024. Existing two-argument calls use this finite default.

When a new identity arrives at capacity, the manager closes the window with the earliest last admitted capture timestamp for `CAPACITY` (`"capacity"`). Equal timestamps select the smallest creation sequence number, independent of address family, transport, hash order, or processing time. The closed window retains its exact prior coordinated state and actual first/last packet timestamps. The incoming packet starts a fresh window and the returned update contains exactly one capacity closure. Continuation at capacity does not evict; same-identity inactivity replacement keeps its `INACTIVITY` reason and leaves other identities untouched. Capacity closure does not infer inactivity or TCP termination. A later observation of an evicted identity starts new statistics, streams, framing, and correlation.

The manager accepts exactly `PacketAnalysis`, uses `flow_identity_from_packet()`, and delegates accumulation to one `FlowStateCoordinator` per active identity. For an identity with an active window, an equal or later canonical UTC capture timestamp continues that window exactly when its gap from the identity's last accepted packet is less than the configured positive `timedelta`. A gap equal to or greater than the timeout closes the old window for `INACTIVITY` and admits the current packet into a new window. The old duration and global and directional inter-arrival aggregates end at its actual last packet, so the boundary gap is never accumulated. TCP flags do not create or close windows, and UDP follows the same timing rule while retaining absent TCP control state. ICMP remains unsupported by the current flow identity contract.

The latest successfully admitted capture timestamp is a nondecreasing session frontier. Earlier timestamps raise `FlowObservationWindowError` without changing active state, consuming a sequence number, or advancing the frontier. The manager uses no processing time, timestamp conversion, buffering, reordering, watermark, timer, thread, or global inactivity sweep. It scans other identities only to select a capacity victim. A failed coordinator update likewise publishes no lifecycle transition.

Continuation prepares coordinated state and validates the returned window/update before advancing the existing coordinator. If that construction fails, active state and the session frontier remain unchanged; later closure includes only previously admitted packets.

Capacity admission constructs the closed window, candidate coordinator, new window, and update before replacing the active table. A shallow candidate table removes the victim and inserts the new entry before publication; allocation or validation failure leaves the original table, states, frontier, and sequence number unchanged. A caller can retry the rejected observation. There is no automatic retry or retained failed candidate. Successful closure uses existing LDAP finalization projection, so pending requests become unresolved rather than completed. Downstream consumer failure follows the existing session contract and does not roll back admission.

`close(identity)` emits an immutable window closed for `EXPLICIT_SEGMENTATION`, and a later packet with that identity creates a new window. `end_capture_session()` closes every active window for `CAPTURE_SESSION_END` in ascending sequence-number order, removes all active entries, and permanently rejects later recording. Repeated session end returns an empty tuple. `active_windows()` exposes freshly constructed immutable wrappers in sequence order without exposing coordinators or the active mapping. Closed windows are returned to callers and are not retained internally.

For limit `L`, the manager retains at most `L` active entries, each with existing bounded TCP/LDAP storage and accumulated statistics. Capacity admission scans at most `L` entries and copies at most `L` mapping references, giving `O(L)` work and temporary mapping space plus one candidate flow state. Ordinary admission below capacity, continuation, and explicit closure introduce no table scan/copy. There is no eviction heap, access history, second flow owner, or retained closed-window history. Enumeration and finalization retain their sequence-order sort. The default permits up to 128 MiB of active directional TCP bytes plus object/statistic overhead; it is a configurable flow-count budget, not a process byte limit. Caller-retained windows and pipeline findings can still grow with input. `FlowTracker` and `FlowFeatureInput` remain independent. The [application composition boundary](../application/README.md) connects source-session completion with lifecycle closure without moving capture ownership into analysis.

## Typed flow feature snapshots

[flow_feature_snapshot.py](flow_feature_snapshot.py) exports `FlowFeatureSnapshot`, `FlowFeatureSnapshotError(ValueError)`, and `extract_flow_feature_snapshot(window: FlowObservationWindow) -> FlowFeatureSnapshot`. The function requires exactly `FlowObservationWindow` and reads `window.coordinated_state` once as the source for every established extractor. Coordinators, bare states, subclasses, mocks, and caller-supplied feature combinations are rejected with `TypeError`. Direct snapshot construction and `dataclasses.replace()` are not supported; extraction is the sole public construction path.

IPv4 and IPv6 TCP/UDP windows share this schema and all existing feature formulas. Global and directional volume, packet sizes, duration, rates, and global and directional inter-arrival features consume the same coordinated aggregates. Exact capture lengths and canonical UTC timestamps retain their meanings for both families. Directional TCP control counters are available through `snapshot.coordinated_state.tcp_control_statistics`; UDP keeps that field `None`. No new TCP metrics or snapshot fields are added.

The IPv6 parity contract is covered by [focused feature tests](../../tests/test_ipv6_features.py), including equivalent IPv4/IPv6 semantic sequences, extension-header transport, fragment admission boundaries, and application closed-window consumers. Extraction does not read raw packet bytes, traverse extension headers, parse fragments, reassemble or correlate fragments, or invoke detectors. No IPv6 extension-header, fragmentation, or Flow Label metrics are defined, and ICMPv6 remains outside flow feature extraction. The existing detectors separately accept applicable IPv4 and IPv6 closed-flow inputs; extraction does not invoke them.

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

One-packet windows preserve zero duration, absent rates, zero global inter-arrival features, and unavailable directional inter-arrival groups. Equal packet timestamps and unused directions preserve their established interval and packet-size semantics. Closure reason does not alter any numerical formula. Mathematical definitions, population variances, rounding policy, and validation remain owned by the existing extractors. Eager typed composition avoids repeated lazy extraction and duplicate raw-state references. The flow-volume detector consumes this snapshot through the separate application boundary. It is not an ML vector: stored field order is preserved, but no flattened numerical ordering, serialization, or machine learning is defined, and extraction does not execute detection.

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

`analysis` exports `decode_tcp(packet: Union[IPv4Packet, IPv6Fragmentation]) -> TCPPacket`, `TCPPacket`, and `TCPDecodeError` from [tcp.py](tcp.py). The IPv4 path accepts `IPv4Packet`, requires protocol number 6, and rejects any nonzero IPv4 fragment offset before interpreting TCP bytes. An initial fragment may be decoded if the complete indicated TCP header is present, even when the IPv4 more-fragments flag is set. Its TCP payload includes only the bytes supplied by that fragment; successful header decoding does not imply a complete TCP segment.

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

`analysis` exports `decode_udp(packet: Union[IPv4Packet, IPv6Fragmentation]) -> UDPPacket`, `UDPPacket`, and `UDPDecodeError` from [udp.py](udp.py). The caller chooses this independent decoder explicitly; its IPv4 path requires protocol number 17 and fragment offset zero. Non-initial fragments are rejected. Initial fragments may proceed, but the complete declared UDP datagram must be present in the supplied IPv4 payload even when the more-fragments flag is set. No reassembly is attempted.

`UDPPacket` is a frozen dataclass with `source_port`, `destination_port`, `length`, `checksum`, and `payload`. Ports and checksum are unsigned 16-bit integers decoded in network byte order, without service mapping, checksum recalculation, or checksum validation. `length` is the unsigned 16-bit UDP datagram length including its fixed eight-byte header; its valid range is 8 through 65535.

The decoder requires at least eight bytes and validates that the declared length does not exceed the available IPv4 payload. UDP payload is exactly `packet.payload[8:length]` as immutable bytes, including an empty value when length is 8. Excess bytes remain in the unchanged IPv4 packet and are accessible as `packet.payload[udp.length:]`; they are not included in UDP payload or interpreted as padding or FCS. No payload bytes are inspected, transformed, padded, or invented.

Invalid protocol, fragment offset, header size, or declared length raises `UDPDecodeError`, an analysis-specific `ValueError`, never `CaptureError`. Wrong input types raise `TypeError`. Direct model construction requires exact integers, rejects booleans and mutable payload containers, checks numeric ranges, and enforces `length == 8 + len(payload)`. Invalid field types raise `TypeError`; invalid values raise `ValueError`.

This decoder performs no UDP application parsing, flow/session tracking, or detection. Bidirectional IPv4/IPv6 TCP/UDP flow tracking is provided separately by `FlowTracker`; live capture remains unimplemented. IPv6 transport decoding follows the validated-context contract above. TCP and UDP share no transport abstraction and do not dispatch to each other.

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

ICMP type/code-specific interpretation, fragment reassembly, and application protocols remain unimplemented. ICMP is not admitted to the TCP/UDP flow path and has no dedicated detector; the separate packet-integrity detector consumes packet-analysis outcomes.

## ICMPv4 checksum validation

`analysis` exports `validate_icmp_checksum(packet: IPv4Packet, message: ICMPMessage) -> bool` and `ICMPChecksumValidationError` from [icmp_checksum.py](icmp_checksum.py). The caller supplies both models explicitly. The validator never invokes `decode_icmp()`, and structural decoders and other checksum validators do not invoke it automatically.

Only the ICMP message participates in the checksum. The validator reconstructs type, code, a zero 16-bit checksum field, and the four unchanged `rest_of_header` bytes, followed by unchanged payload. It interprets no type-specific fields or payload content. There is no IPv4 pseudo-header: Ethernet bytes, IPv4 addresses, other IPv4 header fields, and IPv4 payload bytes outside the supplied message are excluded. The caller supplies the corresponding models; payloads are not compared.

The standard 16-bit one's-complement calculation processes network-order words, folds carries, and complements the sum. Odd input receives a temporary zero low-order byte without altering payload. The calculated checksum is compared directly with `message.checksum`: a match returns `True`, and a mismatch returns `False` without a decoding or capture error. Zero is an ordinary checksum value and can validate successfully; it is neither an omission indicator nor mapped to `0xFFFF`.

Wrong object types raise `TypeError`. IPv4 protocol other than 1 or a nonzero fragment offset raises `ICMPChecksumValidationError`, an analysis-specific `ValueError`. Initial fragments with more-fragments set may proceed using only the represented message bytes; the result does not establish integrity of a complete reassembled message. Both models and all byte fields remain unchanged. No fragment or stream reassembly, connection/flow tracking, application parsing, or detection is performed.

## Future analysis

Analysis consumes [capture](../capture/README.md) observations. Future structured observations and features will support [detection](../detection/README.md), enrichment, event processing, and persistence as needed. Transformations must retain provenance and distinguish malformed, unsupported, and incomplete inputs.

The current tracker owns only packet counts and first/latest packet references, with no session or TCP connection semantics. LDAP envelope analysis consumes the existing TCP payload through an explicit packet-local observation boundary. Existing feature extractors consume their documented aggregate models and do not independently parse traffic. Analysis does not assign threat verdicts or manage alerts. Additional protocol support, reassembly policies, and feature families remain future implementation decisions.


## Explicit feature contract version

`FeatureContractVersion(contract_id, contract_version)` is a frozen analysis value with two exact nonblank strings. The identity names a feature representation contract; the version names its explicitly declared revision. Wrong types raise `TypeError`; blank values raise `ValueError`. Caller-supplied references preserve whitespace, case, Unicode, and non-SemVer labels exactly. Equality compares both strings; there is no version ordering, normalization, coercion, generated identity, or automatic discovery.

`FlowFeatureSnapshot.feature_contract` is a read-only projection returning `FeatureContractVersion("flow-feature-snapshot", "1")`. These literals explicitly name the repository's current single snapshot contract. They are not inferred from packets, detector versions, Git, packages, or runtime state. The snapshot has one controlled extraction path, with no selectable implementation or caller-supplied contract field. Constructing a different standalone reference does not relabel a snapshot, select an extractor, establish compatibility, or migrate features.

Version `1` covers the existing seven snapshot fields in their existing order: `observation_window`, `flow_volume_features`, `packet_size_features`, `flow_duration_features`, `flow_rate_features`, `inter_arrival_features`, and `directional_inter_arrival_features`. It names their established typed composition, feature formulas and availability semantics, and window/coordinated-state projections; it does not duplicate an ordered schema or create a numerical feature vector. The snapshot retains its exact window and six feature-family values. TCP control and optional LDAP observations remain raw coordinated statistics reachable through the window, not added derived feature families. The read-only `ldap_statistics` snapshot property exposes the same retained LDAP statistics; the seven stored snapshot fields and numerical projection remain unchanged. UDP retains absent TCP-control state.

The same contract applies to IPv4/IPv6 TCP/UDP and both active and closed snapshots. Active provenance does not make a window eligible for closed-flow detection. Zero duration keeps rates absent; no global intervals produce zero global inter-arrival values; unavailable directional groups remain `None`; observed zero intervals remain zero. All formulas, precision, optionality, lifecycle behavior, and field order remain unchanged.

The reference is static provenance, not an additional per-instance semantic field. Existing snapshot equality continues to compare its original fields. This implementation cannot produce two snapshots under independently selected contracts; supporting alternative snapshot contracts and deciding their compatibility would require a separate explicit change. Reference objects with different identities or versions compare differently, but no new snapshot matching or equality channel is introduced.

Detector versions identify detector implementations, detector configurations hold operational settings, and `DetectionConfiguration` composes system settings. None selects or implies a feature version. Findings retain their existing schema; flow-volume evidence retains the snapshot through which this reference can be inspected. TCP-control evidence continues to consume raw windows, and packet findings gain no flow-feature provenance. Evaluation identities, ground truth, datasets, benchmark artifacts, and experiments retain their existing semantics and associations without new fields or automatic integration.

Construction and inspection perform no capture, parsing, analysis, feature extraction, detection, evaluation, metrics, benchmarking, experiment execution, external access, timing, or randomness. Feature Contract Versioning supplies representation/provenance only: no registry, schema discovery, loading, migration, serialization, storage, reporting, performance measurement, or ML infrastructure is introduced.


## LDAP protocol observations

[ldap.py](ldap.py) exports `analyze_ldap_payload(payload: bytes) -> LDAPPayloadObservation`, factory-only frozen `LDAPPayloadObservation` and `LDAPMessageObservation`, `LDAPMessageStatus`, and `LDAPOperation`. The parser expects an LDAP candidate beginning at offset zero. `PacketAnalysis.ldap` provides this analysis on demand for IPv4/IPv6 TCP payloads beginning with `0x30` when either port is 389 and neither is 636. Empty, non-SEQUENCE, other-port, and absent TCP payloads return `None`. Port and prefix selection identify candidates, not proof of protocol identity. Explicit callers can analyze known plaintext on other ports.

Each message retains its payload offset, total declared `message_length` including the SEQUENCE header, `message_id`, raw `operation_tag`, recognized `operation`, operation body length, and optional controls presence/body length when established. Unavailable fields are `None`. `envelope_complete` independently records whether all declared outer bytes are available. Status and a deterministic reason distinguish:

| Status | Meaning |
| --- | --- |
| `COMPLETE` | Supported message framing, identifier, operation envelope, and optional controls envelope are present within the outer boundary. This does not validate operation or control contents. |
| `INCOMPLETE` | Required bytes are unavailable; observed metadata remains available without filling missing fields. |
| `MALFORMED` | Observable framing contradicts its enclosing bounds, required SEQUENCE/INTEGER structure, identifier encoding/range, or BER length rules. |
| `UNSUPPORTED` | Unknown operation, high-tag-number encoding, indefinite length, length wider than four octets, oversized message, or unhandled trailing component. |

Framing follows the [RFC 4511 message envelope and encoding restrictions](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.1.1). Short lengths and definite long lengths of one through four octets are supported, including BER-permitted nonminimal length forms. Reserved length octet `0xff` is malformed. Message identifiers use minimally encoded nonnegative INTEGERs through 2147483647; zero is retained without inferring session semantics. Indefinite length is explicitly unsupported. Operation and controls bodies remain opaque, including nested BER inside them.

Recognized operations cover Bind, Unbind, SearchRequest, SearchResultEntry/Done/Reference, Modify, Add, Delete, ModifyDN, Compare, Abandon, Extended, and IntermediateResponse, with request/response variants where defined. Unknown tags remain raw tags with absent operation identity. SearchResultEntry is one search response form; it does not establish completion of a search. No authentication outcome, identity, attribute, filter, result code, or operation validity is inferred.

Parsing visits at most `LDAP_MAX_PAYLOAD_BYTES` (65536) bytes and emits at most `LDAP_MAX_MESSAGES` (128) observations per call. It never allocates from declared lengths, recurses into bodies, or scans for a replacement boundary. Multiple messages advance only by a fully available outer SEQUENCE envelope, including after a malformed or unsupported inner component. An unusable outer length stops parsing. `remaining_bytes` counts bytes from the first unconsumed frame/boundary to the input end; it can include an already inspected incomplete or rejected candidate. `limit_reached` exposes input-byte or observation-count clipping; oversized declared messages carry an unsupported reason.

In the packet-local LDAP API, TCP boundaries are observation boundaries, never assumed message ends. A prefix cut across segments remains incomplete. That API continues to analyze payloads independently. The separate incremental framing contract below consumes contiguous stream bytes through the same BER parser without changing packet-local results or counters. A continuation beginning with `0x30` can itself resemble a candidate; no stream alignment is claimed. Counts measure observed candidate frames, not unique messages on a reconstructed connection. Later packets cannot complete or mutate earlier observations.

[ldap_flow_statistics.py](ldap_flow_statistics.py) exports frozen `LDAPFlowStatistics` and `update_ldap_flow_statistics(current, analysis, identity)`. `CoordinatedFlowState.ldap_statistics` is an optional field defaulting to `None`, preserving existing constructor calls. The coordinator updates it only after existing TCP admission, retaining immutable publication and window-closure behavior. It remains `None` until a candidate is observed. Counts cover complete messages, incomplete/malformed/unsupported observations, complete recognized requests/responses, and payloads clipped by limits. Request plus response counts equal complete-message count; partial or unsupported observations do not enter those totals. Aggregates retain no payload or message history. Wrong public argument types raise `TypeError`, invalid statistics or mismatched updater identities raise `ValueError`, and coordinator identity conflicts retain `FlowCoordinationError`.

LDAP analysis is protocol observation, not attack classification. It adds no findings, detector changes, numerical projection columns, or research labels. It performs no LDAP authentication, enumeration, queries, networking, or persistence. LDAPS and TLS/SASL-protected LDAP cannot be semantically inspected without a separate decryption/security-layer facility; this implementation provides none and does not track StartTLS negotiation. Future work could use the incremental framing contract below and separate operation-body observations to support LDAP search-volume, reconnaissance, authentication-abuse, enumeration, operation-sequence, or response-behavior detectors. None is implemented here.


## Bounded directional TCP stream observation

[tcp_stream_observation.py](tcp_stream_observation.py) exports `TCPStreamObservation`, `TCPStreamState`, `TCPStreamStatus`, `TCPPayloadRelation`, `TCP_STREAM_MAX_BYTES`, `update_tcp_stream_state(current, analysis, identity)`, and `consume_tcp_stream(stream, byte_count)`. It consumes existing decoded `TCPPacket` data after normal flow admission. Each frozen directional observation uses the existing canonical `FlowIdentity` and `FlowDirection`; there are no new identifiers, endpoint normalization, timestamps, protocol guesses, or security decisions. The frozen state contains independent optional `forward` and `reverse` observations.

`FlowStateCoordinator` publishes this component through its existing prepare/commit boundary. It is reachable through `window.coordinated_state.tcp_stream_state` and `snapshot.coordinated_state.tcp_stream_state`. UDP has no stream state. Window closure, inactivity, explicit segmentation, and failed publication keep their existing ownership and atomicity. New windows start new observations; later packets cannot mutate older snapshots. Existing packet counts, TCP controls, numerical features, detector decisions, LDAP counters, and 49-column research projections are unchanged. A retained window now also retains its bounded stream bytes.

The payload is an observed contiguous prefix, not a reconstructed connection. TCP packet boundaries cannot delimit application messages, so directly contiguous payload is appended in observation order. The first accepted payload establishes `start_sequence`; a prior SYN can establish the expected position. Capture may start mid-connection, and this does not prove an application-message boundary. Sequence arithmetic wraps modulo 2**32; an exact half-space displacement is ambiguous. SYN occupies one sequence position before payload, FIN one after payload, following [RFC 9293 section 3.4](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.4). ACK numbers are not used to infer missing bytes.

`payload` retains the accepted bytes for inspection; `payload_length` and exclusive `end_sequence` describe that prefix. `next_sequence` is the expected TCP frontier, including an accepted SYN/FIN position. `syn_sequence` retains an observed SYN anchor. Latest-segment metadata records the raw sequence number, payload sequence start, payload length, relation, and signed displacement from the prior frontier. Displacement is `None` when there was no anchor, ordering is ambiguous, or comparison was not performed. Empty ACK observations do not anchor or advance the frontier.

| Observation | Policy |
| --- | --- |
| First / contiguous | Append exact payload within the bound; retain `FIRST` / `CONTIGUOUS` relation. |
| Forward gap | Set sticky `GAP`; append nothing. Late missing bytes do not repair it. |
| Fully contained, byte-identical range | Mark `DUPLICATE`; retain bytes and frontier unchanged, even across earlier segment boundaries. |
| Other overlap | Append nothing; known byte disagreement gives sticky `CONFLICT`, otherwise sticky `OVERLAP`. No prefix/suffix conflict resolution or prepending. |
| Half-space jump | Sticky `AMBIGUOUS`, without guessing ordering. |
| Capacity exceeded | Sticky `LIMIT_EXCEEDED`; retain the previous prefix, append none of the offending payload. |
| Initial IP fragment | Sticky `FRAGMENTED`; partial TCP segments cannot establish progression. IPv6 whole-datagram Fragment Headers remain usable. |
| Unexpected SYN after an anchor | Sticky `RESTART`; no connection-incarnation inference within one window. Repeated identical SYN anchors are allowed. |
| FIN / RST | Process safely located payload first, then freeze that direction as `FIN` / `RESET`. FIN requires the expected frontier; RST consumes no sequence position and takes precedence if both flags occur. |
| Payload or SYN after FIN/RST | Sticky `AFTER_CLOSE`; do not reopen or resolve retransmissions across the observed close. |

`contiguous_payload` exposes bytes only for `OPEN`, `FIN`, or `RESET`. Other statuses return `None`; `payload` remains the previously accepted prefix, not the rejected bytes. Terminal states never resume within a window. Later payload records an `UNAVAILABLE` relation; ordinary zero-length observations record `EMPTY` without inventing bytes. A gap/overlap caused by FIN may accompany `EMPTY`. Opposite directions are independent, including after RST; no full TCP connection state is inferred.

The fixed retained-buffer bound is **65536 bytes per direction**, enough for the LDAP parser's maximum message. `consume_tcp_stream` returns an immutable observation with an advanced `consumed_length`, leaving payload bytes and the TCP frontier unchanged. `buffer_offset` locates the retained buffer in the logical application stream; `consumed_offset` is their sum. `unconsumed_payload` exposes the suffix only while continuity is available. Consumed bytes remain available for existing retransmission comparisons until a contiguous append needs space. That append first removes consumed bytes and advances the buffer origin, then checks capacity before concatenation. Retransmissions reaching evicted history cannot be verified and follow the existing unavailable overlap policy. Without consumption, the original prefix-limit behavior is unchanged.

State holds one bounded byte buffer, no segment queue or predecessor chain. If the unconsumed suffix plus the next payload still exceeds the bound, the direction becomes `LIMIT_EXCEEDED`; it does not split the incoming packet or fabricate continuation. Active-flow counts and caller-retained historical windows retain the repository's existing ownership/resource limits; there is no new global tracker or quota system.

For explicit packet-parser inspection of the currently unconsumed plaintext suffix:

```python
stream = window.coordinated_state.tcp_stream_state.forward
payload = None if stream is None else stream.unconsumed_payload
ldap = None if not payload else analyze_ldap_payload(payload)
```

Packet-loss recovery, out-of-order queues, general TCP reassembly, SACK, congestion control, timers, TCP state-machine reconstruction, and attack detection remain outside scope. Consumption supplies a bounded foundation for other stream-oriented protocol framers without changing TCP sequence ownership.


## Incremental LDAP stream framing

[ldap_stream_framing.py](ldap_stream_framing.py) exports factory-only frozen `LDAPStreamObservation`, `LDAPStreamState`, `LDAPStreamStatus`, and `update_ldap_stream_state(current, streams)`. The coordinator invokes framing after TCP observation and publishes the resulting consumption cursors and LDAP state together through the existing flow/window failure boundary. `coordinated_state.ldap_stream_state` is optional. Its `tcp_stream_state` is the exact coordinated TCP state. Explicit callers must feed that returned TCP state into subsequent TCP updates.

Automatic framing uses the existing port-389 candidate scope, excluding port 636, and requires a leading SEQUENCE at the observed stream origin. Forward and reverse directions reuse canonical flow identity/direction and frame independently for IPv4 and IPv6. TCP owns continuity and retransmission suppression; LDAP maintains no sequence-number tracker or message-ID synchronization. Packet boundaries cannot delimit LDAP messages: one update may emit several messages, or complete a message begun in earlier updates.

Each direction exposes `messages`, an ordered tuple of **newly framed messages from the latest update**, cumulative complete/unsupported/malformed counts, `pending_message`, `status`, `consumed_offset`, and `retained_suffix`. Message offsets are absolute application-byte offsets from the observed directional origin, including after buffer reclamation; lengths include the outer BER envelope. Complete messages advance the consumption cursor by exactly their declared envelope length. Operation identification, identifiers, and controls metadata reuse the existing parser. Controls do not change the outer boundary. Previously consumed messages are never reparsed or re-emitted; duplicates, empty packets, and unchanged opposite directions emit empty batches.

| Framing state | Consumption policy |
| --- | --- |
| `READY` | Every available message was framed; no pending suffix. |
| `INCOMPLETE` | Retain the exact suffix until its envelope is available. A bounded message with an already known unsupported inner structure also waits for its outer envelope to complete. |
| `MALFORMED` | Retain the rejected boundary and stop permanently for this direction/window, even if its outer length is known. Never scan for a later SEQUENCE or discard malformed bytes to resume. |
| `UNSUPPORTED` | Stop when a supported bounded outer boundary cannot be established, including indefinite lengths or a message beyond the byte limit. Fully available unsupported messages with known bounded envelopes are instead emitted, counted, and consumed, permitting the next boundary. |
| `UNAVAILABLE` | TCP continuity is unavailable. Preserve pending metadata and the previously retained suffix for inspection, but parse nothing further. Gaps, conflicts, unresolved overlaps, or capacity failures never reconstruct a message across missing bytes. |

Only available bounded bytes are inspected, with no allocation from declared BER lengths or recursion. Known opaque incomplete bodies wait for completion without repeated parsing. Framing uses the existing TCP buffer and a cursor; it does not retain a second byte buffer. Many small messages can exceed 65536 cumulative bytes because consumed storage is reclaimed on demand. Emitted metadata is bounded by the latest buffer's message boundaries, not accumulated into an ever-growing history. Cumulative counts and pending state survive updates; callers needing every message must consume each published batch. Finalized windows retain the final batch, cumulative counts, and exact pending state. Later packets and failed publication cannot mutate earlier windows or advance their cursors; capture failure cannot finish missing bytes.

This is protocol framing, not attack detection or LDAP semantic decoding. Packet-local `LDAPFlowStatistics` remain unchanged and may count split candidates differently from logical stream messages. Operation-body interpretation, arbitrary resynchronization, encrypted LDAP inspection, and full TCP reassembly are intentionally absent. These message boundaries feed the bounded request/response correlation below.


## Bounded LDAP request/response correlation

[ldap_correlation.py](ldap_correlation.py) exports frozen factory-only `LDAPCorrelationState` and `LDAPCorrelationObservation`, `LDAPCorrelationStatus`, `LDAPCorrelationUnavailableReason`, `LDAP_MAX_PENDING_REQUESTS`, `update_ldap_correlation_state(current, framing)`, and `finalize_ldap_correlation_state(current)`. Framing remains responsible for message boundaries; correlation needs separate state because directional framing does not retain outstanding requests or associate opposite-direction messages. The coordinator calls correlation once after framing, within its existing atomic preparation/publication boundary. No parser, sequence tracker, or lifecycle is duplicated.

State belongs to one canonical flow and one observation window. Its pending key is `(FlowDirection, message_id)` inside that state, never a global identifier. Each record retains the flow identity, observed direction, exact framed message reference, status, and an optional request reference. `request_direction` identifies the retained request's canonical direction; it does not infer client/server roles. Requests can originate in either direction, and equal IDs in different flows or windows are independent. Explicit updater callers must provide successive framing updates from the same owner, in observation order; a batch containing new messages from both directions is rejected because their ordering cannot be established.

Only complete, recognized messages with nonzero IDs enter pairing. Compatible operation pairs cover Bind, Search, Modify, Add, Delete, ModifyDN, Compare, and Extended. A response requires an opposite-direction pending request with the same ID and compatible operation. Search entries/references match without retiring the request; SearchResultDone retires it. Other supported terminal response types retire their matching request. These are envelope/type associations, not operation-success claims. The rules follow [RFC 4511 message identifiers](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.1.1.1) and [Search results](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.5.2). The existing parser still preserves zero; correlation excludes it rather than inventing a request for an unsolicited notification. Unbind, Abandon, IntermediateResponse, and unsupported messages are non-correlatable under this deliberately limited pairing policy. No control/body semantics are decoded.

| Observation | Correlation policy |
| --- | --- |
| New request | `PENDING`; multiple distinct IDs coexist without FIFO pairing. |
| Compatible response | `MATCHED` with the exact request reference, in observed response order. |
| Missing request, wrong ID/direction/type | `UNMATCHED`, with no fabricated request. Earlier unmatched responses are never retroactively reassociated. |
| Reuse of an outstanding ID in the same direction | `AMBIGUOUS`; retain the first request as a bounded marker, never silently overwrite it or choose a unique response association. The marker remains for the window. Reuse after an observed terminal response can establish a new pending request. |
| Unsupported framed message | `NON_CORRELATABLE`, even if some request metadata exists. If its ID collides with an outstanding request in the same direction, that request becomes ambiguous rather than remaining falsely unique. |
| Incomplete message | No correlation event until framing completes it. |
| Malformed/unsupported framing stop or unavailable TCP prefix | Stop association for the flow/window with `STREAM_UNAVAILABLE`. Retained pending requests become `UNRESOLVED`; subsequent responses remain unmatched. Complete messages before a malformed framing boundary can still be observed, but no missing region is bridged. |

Controls remain on the original message reference and are not correlation keys. Exact retransmissions and empty packets yield no new framed messages, so they add no correlation events or counters. TCP owns retransmission suppression, and correlation never rescans bytes or uses identifiers for synchronization.

`requests` retains at most **128 outstanding keys per flow/window**, including ambiguous markers. This fixed metadata limit supports concurrent requests while bounding retained unresolved work independently of stream duration. On the next distinct request beyond capacity, `LIMIT_EXCEEDED` permanently disables association for that window; previous pending requests become unresolved, the new request is emitted as unresolved, and no eviction can enable a false match. Resolved requests normally release slots. No payload is copied or buffered for correlation.

`observations` contains only the latest ordered event batch, bounded by the existing 65536-byte framing input. Cumulative matched-response, unmatched-response, ambiguous-observation, and non-correlatable counters survive later updates; matched-response count counts individual response associations, including Search entries, not unique exchanges. There is no unbounded completed/unmatched message history. Consumers needing every record must read each active update's batch.

`CoordinatedFlowState.ldap_correlation_state` retains the exact active admission result. `FlowObservationWindow.ldap_correlation_state` returns that result for an active window and an immutable finalized projection for a closed window: pending records become `UNRESOLVED`, completed/unmatched/ambiguous records remain explicit, and counters are preserved. The original coordinated state and all previously published windows stay unchanged. Finalization performs no matching, adds no messages, and cannot turn capture failure into a successful association. Failed admission or window publication advances neither framing nor correlation state. New windows start with no correlation state.

Correlation is protocol observation only. It leaves packet-local LDAP analysis, TCP sequence policy, framing, numerical features, `DetectionFinding` semantics, detector decisions, evaluation, and research projections unchanged for IPv4 and IPv6. Authentication, authorization, credential extraction, LDAP attack detection, networking, and request/response content reconstruction are outside scope. Bounded request termination summaries now consume these decisions as described below, without interpreting operation bodies.


## Bounded LDAP request termination summaries

[ldap_request_summary.py](ldap_request_summary.py) exports factory-only frozen `LDAPRequestSummary` and `LDAPRequestSummaryStatus`. Each correlation request record exposes optional `request_summary`, containing only its canonical flow identity, request direction, exact request observation, response count, status, and optional terminal-response observation. Message IDs and operation types remain on the original observations; there is no second ID map, parser, payload copy, or correlation owner. Existing correlation records could retain individual associations but could not preserve a per-request count across event batches, so the summary extends those records rather than adding a parallel state tracker.

Read current outstanding summaries through `state.requests[i].request_summary`, where `state` is `window.ldap_correlation_state`. New request events also expose the initial summary. Each safely matched response increments only its selected request's count. Non-terminal Search entries/references update the outstanding summary and remain ordinary correlation events; their event records carry no separate summary snapshots. When correlation's existing terminal branch retires a request, its response event exposes the completed summary in `state.observations[i].request_summary`. The terminal reference is that exact response observation. No new terminal-operation mapping is introduced.

| Summary status | Meaning |
| --- | --- |
| `PENDING` | A complete correlated request is outstanding, with zero or more safely associated responses. Search remains pending until SearchResultDone. |
| `COMPLETED` | Correlation observed a terminal response. The count includes that response and the terminal reference is present. This does not claim LDAP operation success. |
| `AMBIGUOUS` | Correlation can no longer establish a unique association. Preserve the original request marker and counts established before ambiguity; do not assign later ambiguous responses or fabricate terminality. |
| `UNRESOLVED` | Correlation became unavailable, capacity was exhausted, or the window closed with the request outstanding. Preserve the observed count with no invented terminal response. |

Unmatched responses, incomplete/malformed messages, and non-correlatable operations create no request summary. A split request becomes summarizable only after framing and correlation admit it. Complete requests emitted as unresolved after correlation capacity exhaustion retain zero-count unresolved summaries in the latest batch, under the existing policy. TCP gaps and retransmissions remain authoritative upstream: missing or duplicate wire bytes cannot increase a summary's logical response count. Controls remain metadata, never summary keys. IPv4 and IPv6 use the same flow-scoped rules.

Storage remains bounded by the existing 128 outstanding correlation keys and latest framing/event batch. Each summary stores one request reference, an exact counter, and at most one terminal-response reference; it retains neither a response list nor predecessor summaries. Non-terminal response order remains available in the existing ordered correlation events. Completed summaries leave active storage with that event batch; consumers needing them later must consume each update. There is no completed-request archive or new response-reference limit to truncate counts.

The [offline summary export adapter](../integrations/README.md#offline-ldap-summary-export) consumes established summaries lazily as deterministic UTF-8 JSON Lines records. It preserves supplied order and metadata without changing analysis state or retaining an event history.

Updates occur at existing correlation decisions in constant work per associated response, without rescanning past events. The existing atomic coordinator publication includes the new summary; failed updates preserve previous counts and references. Closed-window correlation projection converts pending request summaries to unresolved, while completed and ambiguous summaries remain unchanged. Published summaries never mutate, and capture closure/failure cannot fabricate a terminal response.

Summaries are observational only. `FlowFeatureSnapshot`, numerical projections, `DetectionFinding`, evaluation, and research contracts are unchanged. No timing, LDAP body semantics, authentication analysis, credential storage, security interpretation, network communication, or attack detection is added.

## DNS message observation

`analyze_dns_message(payload: bytes) -> DNSMessageObservation` in [dns.py](dns.py) observes one already-delimited DNS message. It requires exactly `bytes`, has no port dependency, and performs no resolution or external lookup. `PacketAnalysis.dns` lazily delegates the exact decoded UDP payload when either port is 53, for IPv4 and IPv6 including supported extension headers. Other ports and TCP return `None`. Access does not cache observations or change flow admission. Transport truncation that prevents UDP decoding remains an existing packet-analysis failure; DNS parsing cannot recover bytes the transport boundary did not supply.

The existing TCP observation infrastructure supplies bounded directional bytes to [DNS-over-TCP framing](#dns-over-tcp-message-framing). Feature 22 handles split/coalesced frames and passes only complete message bytes to the same parser. A caller with an already-delimited TCP DNS message can still call the parser directly, excluding the two-byte prefix. `PacketAnalysis.dns` remains packet-local and UDP-only; automatic TCP framing belongs to the flow coordinator.

The parser produces immutable, factory-only `DNSHeader`, `DNSName`, `DNSQuestion`, `DNSResourceRecord`, and `DNSMessageObservation` values, exported with `DNSMessageStatus`. Headers preserve transaction ID, raw flags and four declared section counts, with derived request/response, opcode, header response-code and TC properties. Questions preserve type/class. Records preserve owner, type/class, unsigned TTL, RDLENGTH and exact opaque RDATA. Unknown types use this same opaque envelope. OPT/EDNS additionally exposes the bounded structural representation described [below](#edns0-protocol-analysis). COMPLETE validates the supported message and EDNS option-envelope structure, not individual option semantics, other record-specific RDATA semantics, DNSSEC, resolver behavior, or the truth of an answer. The response-code property contains only the header's four bits; it does not combine EDNS extended codes.

Names retain ordered binary labels and original case, encoded offsets/lengths and pointer-hop counts. Root is an empty label tuple. Iterative compression traversal accepts earlier proven label, root and pointer boundaries, including suffixes and mixed literal/compressed names. It checks message bounds, backward direction, visited positions, expanded length and hop limits. Targets in headers, label contents or structural metadata are malformed. RDATA-embedded names are deliberately not decoded: a target within earlier opaque RDATA, including EDNS option bytes, is UNSUPPORTED because its name boundary cannot be established. Extended label encodings are also unsupported; reserved encodings are malformed. No bytes are guessed or externally canonicalized.

COMPLETE requires all declared sections and exact message exhaustion. INCOMPLETE means a required field, label, pointer or RDATA extends past the supplied bytes. MALFORMED identifies invalid supported structure or trailing bytes. UNSUPPORTED identifies an unimplemented encoding/boundary or operational limit. The TC header flag is independent: a structurally complete message may have TC set. Parsing stops at the first failure, preserving only complete preceding entries in section order. `parsed_length` ends at the last complete entry (or header); `remaining_bytes` includes the unparsed suffix. `failure_offset` identifies the failed field or pointer, while static `reason` text contains no network bytes. A short header leaves `header=None`; oversized input is rejected before header parsing. `limit_reached` distinguishes resource stops. Wrong API types raise `TypeError`; infrastructure failures propagate and are never translated to malformed DNS.

Limits are explicit public constants: `DNS_MAX_MESSAGE_BYTES=65535`, `DNS_MAX_ENTRIES=128` across questions and all record sections, `DNS_MAX_LABEL_BYTES=63`, `DNS_MAX_NAME_BYTES=255` including length octets and root, and `DNS_MAX_POINTER_HOPS=32` per name. Label/name bounds follow [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html); compression validation also addresses the hazards described by [RFC 9267](https://www.rfc-editor.org/rfc/rfc9267). Entry and hop ceilings are operational bounds, not assertions that larger messages are invalid. Count fields never trigger count-sized allocation. A successful name contains at most 127 nonempty labels, 32 pointer hops and a root. Traversal rejects the first step exceeding either the expanded-name or pointer bound; no recursion is used. A target check may scan at most 128 opaque ranges. The local boundary index, visited positions, parsed entries and copied bytes all have limits derived from those ceilings. Aggregate retained RDATA cannot exceed the message-size limit; expanded names can additionally occupy up to 128 times 255 wire bytes. This is bounded per-message work and storage, not zero-copy or constant memory independent of configured structural limits.

Names and RDATA are excluded from generated representations, but remain explicitly accessible to callers and may contain sensitive data. No packet/source graph or full message buffer is retained by the result, and no serialization, history, archive, findings, DNS flow counters or attack claims are added. Caller-retained observations have caller-owned memory and data-handling costs. This protocol foundation can supply future flow consumers through the existing packet/flow boundaries without changing today's detector or feature contracts.

## Bounded DNS transaction correlation

`update_dns_correlation_state(current, message, identity, direction, captured_at)` consumes an existing immutable `DNSMessageObservation` (or `None`), existing `FlowIdentity`/`FlowDirection` and a canonical fixed-UTC capture timestamp. It returns an immutable `DNSCorrelationState`, or `None` before any COMPLETE DNS message is observed. The UDP coordinator calls it once per admitted packet using `PacketAnalysis.dns`; it does not reparse DNS or retain the packet. Malformed, incomplete, unsupported and absent observations create no transactions and leave pending requests intact, while clearing the latest output batch. DNS parsing remains responsible for reporting those input statuses.

The containing observation window scopes state to a capture session and window sequence. Within that context, a pending key is `(request_direction, transaction_id)` under the existing canonical address/port/IP-version/transport identity. QR determines request/response role; a response looks up the opposite direction. A unique candidate matches only when opcode and the ordered question sections agree: question names compare binary label sequences with ASCII case folding, and type/class must agree. Name compression offsets do not affect matching. These checks use the already-parsed fields; they do not assert authenticity or implement resolver acceptance policy. See [RFC 5452 section 9.1](https://www.rfc-editor.org/rfc/rfc5452.html#section-9.1) for the protocol attributes motivating response matching.

`DNSTransactionObservation` exposes identity, observed direction, the exact DNS message reference, capture timestamp, status, optional request reference/time and optional reason. Transaction ID is derived from the message. PENDING records an outstanding request. MATCHED records the first compatible observed response and retires its request. UNMATCHED records a response with no eligible candidate, including question/opcode mismatch; it does not consume an incompatible pending request. A response before a request is never retroactively associated. Later responses after completion remain separate UNMATCHED observations; no completed-ID history or deduplication is retained. Sequential ID reuse can begin a new transaction. A delayed old response indistinguishable from a current request's reply cannot be disambiguated by these fields; MATCHED describes the observed association, not proof of causality.

Repeated requests while the same key is outstanding make that key AMBIGUOUS, even if their bytes are equal. The state retains the first request as an ambiguity marker and exposes each new observation in its latest batch. Further responses for that key remain AMBIGUOUS without a claimed request association or duration until window closure. This avoids guessing between retransmission and independent ID reuse. No distinction between duplicate and multiple post-completion responses is inferred without retained history.

`DNS_MAX_PENDING_REQUESTS=128` applies across both directions, following the existing LDAP pending-state ceiling and conservative loss-of-correlation convention. On admission of a new key beyond that limit, all retained requests become UNRESOLVED in insertion order, followed by the incoming unresolved request, each with LIMIT_EXCEEDED. The request tuple is cleared and matching stays unavailable for the rest of the window. Later requests are UNRESOLVED; responses are UNMATCHED with the explicit LIMIT_EXCEEDED reason. This is deterministic capacity closure, not LRU replacement that might incorrectly associate late responses after eviction. Matching a response frees a slot before saturation; reuse of an existing key does not consume another slot. A new flow window starts with fresh state.

`finalize_dns_correlation_state()` clears outstanding requests and makes them UNRESOLVED with FLOW_CLOSED. It returns the same object when called on an already-finalized state; further updates are rejected. `FlowObservationWindow` finalizes DNS while constructing every closed window, before publication. Its stored coordinated state and `dns_correlation_state` property therefore contain no pending requests. The enclosing closure reason distinguishes inactivity, explicit segmentation, capture-session end and active-flow capacity. Previously published active snapshots remain immutable and caller-owned. Failed preparation or final publication leaves the owning manager/coordinator unchanged and allows an explicit retry through the existing lifecycle; there is no automatic retry or swallowed infrastructure failure. Capture/downstream failures retain the existing flow-session cleanup and delivery behavior, and cannot fabricate matched transactions.

`duration` is an exact `timedelta` only for MATCHED observations: response capture timestamp minus request capture timestamp. Zero is legal; decreasing timestamps are rejected, never clamped. No local or processing time is read. Standalone callers with already-delimited TCP DNS messages may use the same correlation primitive and their existing TCP identity/direction. Feature 22 also integrates complete TCP frames through this same correlation primitive; their timestamps are the capture times of the observations completing each frame.

State retains at most 128 outstanding keys and the latest observation batch, never a transaction history. Ordinary updates expose one observation (or none); capacity closure and finalization expose at most 129. Closed snapshots preserve the last non-PENDING batch plus final unresolved requests; they are snapshots, not a new delivery stream. Consumers retaining updates must distinguish those snapshots from new arrivals. At most 129 distinct bounded DNS message objects are referenced by one correlation state, with original name/RDATA ownership and privacy costs; no packet graph, source, previous-state link, clock, queue or archive is retained. Lookup/copy work is bounded by 128 pending entries; question comparison is bounded by the parser's question/name limits. Whole-operation memory combines this per-window bound with the existing active-window limit and any caller-retained windows/findings. There is no constant-memory claim for retained output histories.

The additive `CoordinatedFlowState.dns_correlation_state=None` field preserves previous constructors. Existing generic statistics, feature vectors, detector thresholds, finding fields, evaluation, metrics, LDAP and TCP stream behavior are unchanged. DNS transaction states are protocol observations for future consumers, not attack findings.

## DNS transaction-derived statistics

[dns_transaction_statistics.py](dns_transaction_statistics.py) exports immutable `DNSTransactionStatistics` and `update_dns_transaction_statistics(current, observation)`. The update consumes exactly one established, non-PENDING `DNSTransactionObservation`, with `current=None` meaning empty statistics. It returns a new value without retaining the observation or modifying the input. A PENDING observation raises `ValueError`; wrong argument types raise `TypeError`. Valid transactions originate only from COMPLETE DNS messages under the existing correlation factory. Malformed, incomplete, unsupported and absent DNS inputs produce no feature contributions.

The coordinator already provides a protocol-specific state boundary alongside generic flow accumulators. Its additive `dns_transaction_statistics` field defaults to an empty immutable result, preserving previous positional constructors. `FlowObservationWindow.dns_transaction_statistics` exposes that same value. No DNS fields are added to `FlowFeatureSnapshot`'s generic feature groups; `flow-feature-snapshot` version `1` and its 49-value ML projection retain their meaning. Consumers needing DNS statistics read the protocol-specific result from their existing flow window or coordinated state. No parallel feature framework or LDAP generalization is introduced.

### Counts and observation semantics

| Public statistic | Meaning |
| --- | --- |
| `total_transaction_count` | Sum of the four terminal status buckets below. Counts finalized observations, not unique wire IDs or inferred logical exchanges. |
| `matched_count` | MATCHED observations; also the latency sample count. |
| `unmatched_response_count`, `unmatched_count` | UNMATCHED observations. Feature 13 emits this status only for responses. |
| `ambiguous_count` | AMBIGUOUS observations, including repeated requests and responses to ambiguous outstanding IDs. |
| `unresolved_count` | UNRESOLVED observations from pending-request closure, capacity saturation or later requests while correlation is unavailable. |
| `question_count`, `answer_count`, `authority_count`, `additional_count` | Header section counts across contributing complete messages. |
| `opcode_counts` | Immutable 16-element tuple, index 0 through 15, counting every contributing message's opcode. |
| `response_code_counts` | Immutable 16-element tuple, index 0 through 15, counting only contributing response messages' four-bit header codes. EDNS extended response codes remain separate and do not enter this distribution. |

The accounting invariant is `total_transaction_count = matched_count + unmatched_count + ambiguous_count + unresolved_count`. There is no independent unmatched-request bucket: Feature 13 represents unanswered requests as UNRESOLVED, and relabeling them would change that contract. A duplicate request's AMBIGUOUS output counts once, and the original pending request later contributes its separate UNRESOLVED closure observation. Sequential ID reuse can produce multiple matches; no ID history or deduplication is inferred.

A MATCHED observation contributes its associated request and observed response once each. Every other terminal observation contributes only its observed `message`, ignoring any contextual `request` reference. This avoids recounting the original request on ambiguous duplicates. Section totals describe these message observations, including questions repeated in responses; they are not distinct-name or unique-record counts. Opcode bins sum to `total_transaction_count + matched_count`. Response-code bins count responses only, so request flags do not invent responses. Header counts require no record/name/RDATA traversal or reparsing. The parser's current maximum is 128 entries across sections per complete message, not the unsigned header field maximum.

### Exact latency and empty state

`min_matched_latency_microseconds`, `max_matched_latency_microseconds` and `total_matched_latency_microseconds` use Python integers derived directly from Feature 13's `duration` days, seconds and microseconds. `mean_matched_latency_microseconds` returns an exact standard-library `fractions.Fraction(total, matched_count)`. This DNS-specific rational result preserves fractional microseconds without altering existing generic floating-point feature conventions. No rounding or conversion to float occurs, even for counters beyond float range.

The timestamps remain the established canonical fixed-UTC capture timestamps. Zero duration is valid; decreasing timestamps are rejected by correlation/flow ownership, never clamped or reinterpreted here. No wall clock, runtime timer or local timezone is read. Classic PCAP nanosecond timestamps retain the capture layer's existing truncation to microseconds; this layer neither recovers nor further rounds the discarded precision.

`DNSTransactionStatistics()` defines the empty state: every counter and every distribution bin is zero; total latency is zero; minimum, maximum and mean latency are `None`. The same empty semantics apply to non-DNS windows and active windows containing only pending requests. No matched latency is inferred for other statuses.

### Ownership, publication and memory

`FlowStateCoordinator` folds every new non-PENDING correlation output into the existing window's result during atomic preparation. Closed-window construction first finalizes correlation, then consumes only its newly appended terminal suffix. Correlation deliberately retains the last non-PENDING output prefix at finalization; that prefix has already contributed and is skipped. Repeated construction from a closed window preserves the exact finalized statistics object. Failed aggregation or publication leaves the previous owner intact for explicit retry.

Flow identity, IP version, direction, admission, active capacity and release remain owned by existing flow/session abstractions. Interleaved IPv4/IPv6 and client-port flows remain separate; all closure reasons publish final statistics before releasing the owner. A newly admitted window starts empty, even for reused endpoints and IDs. Standalone callers own scope and must deliver each terminal observation once; the scalar reducer intentionally provides no transaction-ID map, history-based replay suppression or flow manager. Already-delimited TCP transaction observations can use the same reducer. The packet/session path also admits complete TCP frames through Feature 22; arbitrary port-53 payloads cannot bypass COMPLETE-message correlation admission.

One statistics result stores 11 scalar slots and two fixed tuples of 16 counters each, with no predecessor, transaction, message, name, RDATA, packet, PCAP or capture-source references. Updates use two temporary 16-bin lists and at most two message references; closure may slice at most 128 newly terminal observation references from the already-bounded correlation result. No collection grows with transaction count. Exact Python integer bit lengths grow logarithmically with accumulated counts/totals, so this is a bounded number of values, not a constant-byte memory claim. Aggregate memory also depends on the existing active-window ceiling and any snapshots retained by callers. Completed observations can be released when correlation's latest batch and callers no longer retain them; features add no retention.

Frozen dataclasses, exact integer validation and tuple-only distributions prevent ordinary caller mutation and mutable-container exposure. Exported copies can be changed without changing the result. These statistics create no findings or thresholds for unanswered requests, ambiguity, latency, opcodes, response codes or record counts. DNS parsing, matching, LDAP, packet/flow detectors, finding fields, collecting/streaming evaluation, metrics and historical NOT_EVALUABLE semantics remain unchanged.

## DNS query-name structural statistics

[dns_query_name_statistics.py](dns_query_name_statistics.py) exports frozen `DNSQueryNameStatistics` and `update_dns_query_name_statistics(current, observation)`. The reducer consumes an established non-PENDING `DNSTransactionObservation`, then measures only its contributing messages' parsed `DNSQuestion.name` values. `current=None` starts empty statistics. PENDING raises `ValueError`; wrong argument types raise `TypeError`. The parser and transaction factories remain the admission boundary: malformed, incomplete, unsupported and absent DNS messages cannot produce contributing transactions, even when an invalid message contains an already-parsed question prefix.

### Query-name accounting and units

Only question-section names are query names. Answer, authority and additional owner names and RDATA-embedded names never contribute. Accounting follows the established transaction-statistics convention: MATCHED contributes both the request and response message's question sections, including repeated response questions as separate observed message content. UNMATCHED, AMBIGUOUS and UNRESOLVED contribute only their observed `message`; contextual request references on ambiguous observations are ignored. The original outstanding request later contributes its own unresolved closure observation. There is no inferred logical-query identity or deduplication. In coordinator-produced states, `dns_query_name_statistics.query_name_count` equals `dns_transaction_statistics.question_count`.

`DNSName.labels` is an immutable tuple of nonempty binary labels, preserving case and bytes. No decoding, Unicode/IDNA interpretation, case folding or extra canonicalization occurs. Name length uses the existing `DNSName.expanded_length`: expanded wire octets, equal to label payload octets plus one length octet per label plus one terminal root octet. It does not use `encoded_length`, pointer hops or compression-pointer bytes. Label length is the number of payload octets in each existing label, excluding its length octet. These are byte-oriented structural measurements, not character counts or dotted presentation-string lengths. A dot or zero byte inside a parsed label remains a payload byte, not a new separator.

The root name is represented by `labels=()`: expanded length one, label count zero, and no fake empty label. The terminal root is included exactly once in name length and never in label count, label-length extrema or label-length means. The parser currently permits labels up to 63 octets, expanded names up to 255 octets and up to 127 nonempty labels per name.

### Public statistics

| Field/property | Meaning |
| --- | --- |
| `query_name_count` | Total contributing question-name observations, including roots and repetitions. |
| `label_count` | Total nonempty labels across all contributing names. |
| `min_name_length_bytes`, `max_name_length_bytes`, `total_name_length_bytes` | Expanded wire name-length extrema and sum. |
| `mean_name_length_bytes` | Exact `Fraction(total_name_length_bytes, query_name_count)`, or `None` without names. |
| `min_label_length_bytes`, `max_label_length_bytes`, `total_label_length_bytes` | Parsed label-payload length extrema and sum. |
| `mean_label_length_bytes` | Exact `Fraction(total_label_length_bytes, label_count)`, or `None` without labels. |
| `max_labels_per_name` | Maximum nonempty label count in an observed name. |
| `min_labels_per_non_root_name` | Minimum label count among non-root names only. |
| `root_name_count` | Number of root question-name observations. |
| `digit_name_count` | Names with at least one ASCII digit byte, 48 through 57 inclusive. |
| `hyphen_name_count` | Names with at least one byte 45 (`-`). |
| `underscore_name_count` | Names with at least one byte 95 (`_`). |
| `non_ascii_name_count` | Names with at least one byte 128 through 255 inclusive. |

Each byte-class counter increments at most once per name, regardless of repetitions or labels. Classes are independent and can overlap. Non-ASCII does not imply valid or invalid text; encoded non-ASCII digit characters do not become ASCII digit bytes. No entropy, unique-domain count, lexical score, heuristic threshold, reputation or maliciousness interpretation is added.

The aggregate identity is `total_name_length_bytes = total_label_length_bytes + label_count + query_name_count`. Counts, totals and extrema use exact Python integers. Both means use Feature 14's standard-library `fractions.Fraction` convention, without floating-point conversion, rounding or clamping. Structure is independent of capture timestamps and latency; this reducer neither stores nor reads them. Existing canonical UTC admission and decreasing-timestamp rejection remain upstream.

### Empty state, ownership and bounds

`DNSQueryNameStatistics()` has zero counts/totals and `None` for every minimum, maximum and mean. Root-only input differs: name extrema and mean are one, maximum labels per name is zero, label total is zero, and label extrema/mean and minimum non-root label count remain `None`. Non-DNS flows, messages with no questions and active windows with only pending requests have the same explicit empty statistics.

The additive `CoordinatedFlowState.dns_query_name_statistics` defaults to the immutable empty value; `FlowObservationWindow.dns_query_name_statistics` exposes the stored result. Existing flow identity, active capacity, admission, closure and release remain authoritative. IPv4/IPv6 and client-port interleaving stay isolated; endpoint/ID/name reuse in a new window starts fresh statistics. The UDP packet path supplies only established DNS observations. Already-delimited TCP transaction observations may use the reducer; automatic TCP framing follows the bounded Feature 22 contract below.

The DNS reducers run during the existing atomic coordinator preparation and closed-window publication. Closure consumes only correlation's newly terminal suffix; the retained completed prefix has already contributed. Reconstructing an already-closed window preserves the same feature value. Aggregation failure, including partway through a batch, leaves the old state intact; publication failure cannot double-count an explicit retry. Capture and parser infrastructure failures retain their existing propagation and cleanup behavior. Standalone callers remain responsible for flow scope and exactly-once delivery of terminal observations; no replay history or secondary lifecycle is stored.

The result stores exactly **15 scalar integer-or-`None` fields**. Its two mean properties construct exact rational values on access. There are no stored collections or source references: no names, labels, questions, messages, transactions, packets, flows, capture sources or PCAP data. Updating uses a fixed 15-entry local value mapping, at most two contributing message references and bounded traversal of existing question/name/label objects. The parser bounds input to at most 128 entries per message; a match contributes at most 256 questions, each with expanded length at most 255 octets. No name-sized copy, global name state, distinct-name set or history is created. Integer storage grows with bit length, so this is fixed scalar shape, not constant-byte memory. Total ownership costs also include the existing active-window ceiling and any immutable snapshots retained by callers.

Frozen dataclass validation rejects mutable containers and non-integer scalar inputs. Caller-owned constructor mappings and exported copies cannot mutate a recorded result. Retaining the feature result does not retain its source graph; completed observations can be reclaimed when correlation and callers release them. The existing `DNSTransactionStatistics` semantics, `FlowFeatureSnapshot` version 1, 49-value ML projection, LDAP, detectors, finding fields, evaluation and metrics remain unchanged. These measurements establish structural observations only and do not identify DGA activity, DNS tunneling or attacks.

## DNS resource-record structural statistics

[dns_resource_record_statistics.py](dns_resource_record_statistics.py) exports frozen `DNSResourceRecordStatistics` and `update_dns_resource_record_statistics(current, observation)`. The reducer consumes terminal `DNSTransactionObservation` values and their complete parsed messages. `current=None` starts empty. Wrong argument types raise `TypeError`; PENDING or invalid terminal statuses and incomplete contributing messages are rejected. Malformed, incomplete, unsupported and absent DNS cannot contribute through the established parser/correlation boundary; a valid record prefix inside an invalid message is excluded. Infrastructure failures propagate through the existing lifecycle.

### Record accounting and units

Only `DNSMessageObservation.answers`, `.authorities` and `.additionals` contribute. Questions are not resource records. MATCHED contributes request and response as separate observed messages, each with its own sections. UNMATCHED, AMBIGUOUS and UNRESOLVED contribute only their observed `message`; contextual request references do not contribute again. Pending requests contribute when they become terminal. Repeated records and repeated messages preserve multiplicity, without inferred records, logical-query deduplication or unique-record sets.

The parser supplies `DNSResourceRecord.rdlength`, `record_type` and `record_class`. RDATA length means opaque RDATA bytes only: no owner-name, envelope, compression-pointer decoding or textual/RDATA interpretation. Type and class are unsigned 16-bit wire values, including unknown values and OPT's structurally represented class field, without assigning special semantic meaning. TTL is not measured. The parser's 65,535-byte message ceiling permits at most 65,512 RDATA bytes in a complete message with one root-owned record and no questions; packet transport limits may be narrower. The reducer consumes that existing contract without parsing bytes or changing its limits.

| Field/property | Meaning |
| --- | --- |
| `resource_record_count` | Computed sum of the three section counts. |
| `answer_count`, `authority_count`, `additional_count` | Observed records in each corresponding message section. |
| `min_rdata_length_bytes`, `max_rdata_length_bytes`, `total_rdata_length_bytes` | RDATA byte-length extrema and exact sum. |
| `mean_rdata_length_bytes` | Exact `Fraction(total_rdata_length_bytes, resource_record_count)`, or `None` without records. |
| `type_counts`, `class_counts` | Fixed immutable distributions for all codes 0 through 65,535. |

Each distribution is a tuple of 256 tuple blocks, each containing 256 integer bins. Code `c` is read at `counts[c >> 8][c & 255]`. Outer and inner indices are always in ascending code order; no traffic-dependent keys or iteration order occur. Each distribution sums to `resource_record_count`, which equals `answer_count + authority_count + additional_count`. Coordinator-produced section counts agree with `DNSTransactionStatistics` section counts.

All counts and lengths use exact Python integers. The mean uses standard-library `fractions.Fraction` without floating point, rounding or clamping. Timestamps are neither read nor retained; canonical UTC capture-time validation and decreasing-timestamp rejection remain upstream. Empty state has zero section counts, total and every distribution bin; minimum, maximum and mean are `None`. Records with zero-length RDATA instead have measured zero extrema and mean, and positive record counts.

### Ownership, bounds and compatibility

`CoordinatedFlowState.dns_resource_record_statistics` has an immutable empty default; `FlowObservationWindow.dns_resource_record_statistics` publishes the stored value. It joins the existing atomic coordinator preparation and window publication alongside transaction and query-name statistics. Closure folds only newly terminal observations, skipping the already-consumed completed prefix. Failed aggregation, including partial record/transaction batches, preserves prior state; publication retry cannot double-count. Repeated closed-window construction is idempotent. Existing explicit/inactivity/capacity/session closure, readmission and source release remain authoritative; no second owner, flow manager or rollback system exists.

Each result has exactly **eight stored fields: six scalars and two fixed distributions**. The distributions contain 131,072 logical bin positions across at most 512 inner tuples and two outer tuples. Empty and unchanged blocks share immutable storage; updates copy affected blocks and never retain previous aggregate objects. Temporary aggregation uses a fixed six-entry scalar mapping, two 256-entry block lists and a 256-entry working block list per increment. Traversal retains at most two contributing message references during the call, with at most 128 parser entries per message (256 records per matched observation). There are no stored packets, observations, messages, questions, names, records, RDATA, transactions, flows, capture sources or history. Exact integer bit lengths can grow; fixed shape does not mean constant-byte memory. Existing active-flow limits and caller-retained snapshots determine the number of aggregate owners.

Frozen dataclass validation requires exact integers and immutable tuple blocks, enforcing distribution and section totals. Mutable input containers are rejected; mutation of caller-owned mappings cannot alter published results. Retained statistics allow their entire source graph to be collected after correlation and callers release it. Standalone reducer callers supply flow scope and exactly-once terminal delivery; repeated calls intentionally count repeated observations.

IPv4 and IPv6 share the existing UDP DNS packet path and stay isolated by established flow identity. Already-delimited TCP transaction observations can use the reducer; automatic TCP framing follows the bounded Feature 22 contract below. DNS parser/correlation, transaction/query-name statistics, generic `FlowFeatureSnapshot` version 1, the 49-value ML projection, LDAP, detectors, evaluation and metrics remain unchanged. These resource-record statistics do not detect attacks or classify any type, class, record or pattern as malicious.

## DNS message flag statistics

[dns_message_flag_statistics.py](dns_message_flag_statistics.py) exports frozen `DNSMessageFlagStatistics` and `update_dns_message_flag_statistics(current, observation)`. The reducer consumes established terminal transactions, then the existing complete message/header representation. It never reads raw payloads, the integer flag word, questions, resource records, names, RDATA, transaction IDs, timestamps, duration or flow identity.

### Supported properties and accounting

Feature 19 extends the existing Feature 17 statistics using all seven semantic properties established by the [Feature 18 header control-flag contract](#semantic-dns-header-control-flags). Flag decoding and the raw word remain parser-owned; the reducer reads only semantic booleans. Reserved information has no counter. Opcode and response-code distributions stay in `DNSTransactionStatistics` and are not duplicated.

| Field/property | Observation |
| --- | --- |
| `message_count` | Number of contributing complete DNS messages. |
| `response_count` | Messages whose parsed `is_response` property is true (QR set). |
| `query_count` | Derived `message_count - response_count`, representing QR-clear messages. |
| `truncated_count` | Messages whose parsed `truncated` property is true (TC set), including either queries or responses. |
| `authoritative_answer_count` | Messages with `authoritative_answer` true (AA set). |
| `recursion_desired_count` | Messages with `recursion_desired` true (RD set). |
| `recursion_available_count` | Messages with `recursion_available` true (RA set). |
| `authenticated_data_count` | Messages with `authenticated_data` true (AD set); no DNSSEC validation is performed. |
| `checking_disabled_count` | Messages with `checking_disabled` true (CD set). |

Each contributing message increments the total once and each supported set-flag counter at most once. MATCHED contributes its request and response messages separately. UNMATCHED, AMBIGUOUS and UNRESOLVED contribute only their observed `message`; contextual request references are ignored. The original pending request contributes when it becomes terminal under correlation's existing lifecycle. No flag is inferred from transaction status. RD in a request and RA in its response contribute independently. Repeated observations preserve multiplicity, without logical-query deduplication. Message counts do not depend on question or resource-record counts, including when every section is empty.

### Validation, empty state and bounds

`current=None` starts empty statistics. Wrong reducer argument types raise `TypeError`; PENDING and invalid transaction statuses raise `ValueError`. Contributing messages must be exact `DNSMessageObservation` objects with COMPLETE status and an established `DNSHeader`; semantic flag properties must return exact booleans. Invalid, incomplete, unsupported or absent DNS messages cannot produce contributions, even if they contain a valid parsed header or section prefix. Infrastructure exceptions propagate.

The result stores exactly **eight scalar integer fields**, with query count computed on access. Constructor validation requires exact non-negative integers, rejects booleans/floats/containers, and requires every set-flag count to be no greater than message count. Query plus response count consequently always equals message count; all supported flag counts can overlap independently, without restrictions on combinations. `DNSMessageFlagStatistics()` has all stored and derived counts zero. Arithmetic uses exact Python integers without floating point, ratios, rounding or clamping.

Storage has fixed scalar shape, with no collections, flag maps, message history, source objects or previous aggregates. Temporary reduction holds a fixed eight-entry counter mapping, seven fixed property pairs and at most two contributing messages; none are retained in the result. Integer storage grows in bit length as counts increase, so this does not imply constant-byte memory. Existing active-window limits and caller-retained snapshots determine aggregate ownership costs. Frozen values and exported copies cannot mutate prior results; retaining statistics does not keep headers, messages, transactions, packet analysis, packets or flow/window state alive.

### Lifecycle and compatibility

`CoordinatedFlowState.dns_message_flag_statistics` has an immutable empty default. `FlowObservationWindow.dns_message_flag_statistics` exposes the stored result through the existing protocol-specific boundary. Aggregation joins the same atomic preparation/publication used by Features 14–16. Closure processes only correlation's newly terminal suffix, skipping the already-counted completed prefix. Failure within a message or terminal-observation batch leaves the prior state intact and retryable; publication retry does not double-count, and repeated closed-window construction preserves the same result. Capture failures retain existing terminal publication and source cleanup behavior.

Flow identity, active capacity, eviction, inactivity, explicit closure, capture-session finalization and readmission remain authoritative. New owners start with empty statistics, and IPv4/IPv6 and client-port interleaving remain isolated. Standalone reducer callers provide flow scope and exactly-once terminal delivery. The UDP packet path delegates all parsing to existing analysis. Already-delimited TCP transactions may use the reducer; automatic TCP framing follows the bounded Feature 22 contract below.

The original three stored fields keep their positional order, names and semantics, and `query_count` remains derived. Five new fields follow them with zero defaults, preserving existing three-argument construction. Dataclass serialization and representation now include all eight fields. DNS parser/correlation and Features 14, 15, 16 and 18 retain their existing semantics. Generic `FlowFeatureSnapshot` version 1 and the 49-value ML projection are unchanged. No detector, threshold, alert, classification, score, LDAP behavior, evaluator or metrics change is added. These counts describe observed message controls only; they do not detect attacks or assign security meaning.

## Semantic DNS header control flags

`DNSHeader` in [dns.py](dns.py) is the canonical semantic boundary for DNS control flags. `analyze_dns_message(payload)` still constructs the same frozen header from the existing unsigned 16-bit flag word. Five new computed properties extend the established `is_response` / `truncated` pattern; they add no stored fields or parallel header model. Downstream consumers must use these semantic properties rather than decoding `header.flags` or packet bytes.

| Flag | Exact boolean property | Wire mask | Observation |
| --- | --- | --- | --- |
| QR | `is_response` | `0x8000` | Set means response; clear means query. Existing behavior unchanged. |
| AA | `authoritative_answer` | `0x0400` | Authoritative Answer bit as supplied by the sender. |
| TC | `truncated` | `0x0200` | Message truncation bit. Existing behavior unchanged; it does not determine structural completeness. |
| RD | `recursion_desired` | `0x0100` | Recursion Desired bit as supplied by the sender. |
| RA | `recursion_available` | `0x0080` | Recursion Available bit as supplied by the sender. |
| AD | `authenticated_data` | `0x0020` | AD (Authentic Data) bit as supplied by the sender; this parser performs no DNSSEC validation. |
| CD | `checking_disabled` | `0x0010` | Checking Disabled bit as supplied by the sender. |

The DNS header layout follows [RFC 1035 section 4.1.1](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1), with AD/CD defined by the DNSSEC header extensions described in [RFC 4035 section 3](https://www.rfc-editor.org/rfc/rfc4035#section-3). Each property reports its wire bit independently. No query/response normalization, inference from records or transaction status, or security interpretation is performed. A property being true is an observation only and does not detect an attack.

### Raw compatibility, reserved positions and construction

`DNSHeader.flags` continues to preserve every bit exactly, including unknown opcode/response-code values and the three historical Z positions (`0x0070`). AD (`0x0020`) and CD (`0x0010`) now have semantic accessors; the remaining reserved bit (`0x0040`) stays preserved in the raw word without an invented meaning or new parser rejection. No previously preserved information is discarded. Opcode and response-code accessors are unchanged.

All seven control properties return exact `bool` values computed from the parser-created integer. The public constructor remains factory-only: `DNSHeader()` and direct positional/keyword construction raise `TypeError`, as before. No boolean constructor parameters are introduced, so integers, strings, floats, `None` and arbitrary truthy/falsy objects cannot enter a new coercing construction path. `analyze_dns_message` retains its existing exact-`bytes` input contract and internal header construction. Frozen assignment/deletion behavior is unchanged.

The six stored header fields, equality, hashing, representation and dataclass serialization remain unchanged. Reading properties does not cache state or retain payload, packet analysis, packets, DNS messages, transactions or flows. Malformed, incomplete and unsupported messages preserve their existing statuses and partial-header behavior; a readable header does not admit an invalid message to correlation or statistics. Inputs shorter than the fixed header still expose no header, and infrastructure failures still propagate.

### Integration and compatibility

IPv4/IPv6 UDP packet analysis delegates to this same parser/header representation. Already-delimited TCP transaction observations expose the same properties; automatic TCP framing follows the bounded Feature 22 contract below. Header values are message-local; no identity, flow state, history or lifecycle is added.

Feature 18 established semantic header access without changing Feature 17 statistics. Feature 19 now aggregates all seven properties in the existing `DNSMessageFlagStatistics`, preserving its original message, response, truncation and derived query semantics. Features 12–16 retain their existing behavior. DNS transaction, query-name and resource-record statistics, generic `FlowFeatureSnapshot` version 1, the 49-value ML projection, detectors, evaluation, metrics, LDAP, capture and CLI behavior remain unchanged.


## EDNS(0) protocol analysis

`analyze_dns_message` in [dns.py](dns.py) remains the sole DNS wire parser. It uses the existing name and resource-record envelope decoders for OPT (TYPE 41), then parses option envelopes within that record's checked RDATA. There is no second DNS message model: the canonical result remains `DNSMessageObservation`.

### Public representation

`DNSResourceRecord.edns` is an additive optional `DNSEDNS` field. It is `None` for ordinary records and all records in non-COMPLETE messages. `DNSMessageObservation.edns` is a derived convenience property exposing the identical EDNS value for a complete message with OPT. `None` means no admitted EDNS value; callers must inspect message status to distinguish an absent OPT from invalid/incomplete input. The raw record fields remain unchanged, including CLASS, TTL and exact RDATA bytes. Record dataclass serialization now includes the additive `edns` field, including `None` for ordinary records.

| Value | Meaning |
| --- | --- |
| `DNSEDNS.udp_payload_size` | Exact unsigned 16-bit OPT CLASS value; no normalization or minimum-size clamping. |
| `DNSEDNS.extended_rcode` | Upper eight bits of OPT TTL, kept separate from `DNSHeader.response_code`. |
| `DNSEDNS.version` | Next eight TTL bits; zero and all nonzero versions are represented. |
| `DNSEDNS.flags` | Lower sixteen TTL bits, including reserved information, preserved exactly. |
| `DNSEDNS.dnssec_ok` | Exact derived boolean for the DO bit (`0x8000`); independent of DNS header AD. |
| `DNSEDNS.options` | Immutable tuple of options in wire order, preserving duplicate codes and observations. |
| `DNSEDNSOption.code` | Exact unsigned 16-bit option code, including unknown codes. |
| `DNSEDNSOption.data` | Immutable opaque payload bytes, excluded from representation strings. |
| `DNSEDNSOption.data_length` | Exact derived integer byte length, excluding the four-byte code/length envelope. |

Empty OPT RDATA gives an empty option tuple. A zero-length option has an entry with `data=b''` and `data_length=0`; it remains distinct from no options. No ECS, COOKIE, NSID, padding, EDE or other option-specific decoding is performed. DO is an observed request/control bit, not DNSSEC validation. The extended response code remains separate from the header's four-bit code. Semantic EDNS values feed the [structural statistics reducer](#dns-edns-option-structural-statistics).

The wire interpretation follows [RFC 6891 section 6](https://www.rfc-editor.org/rfc/rfc6891.html#section-6). OPT must have a root owner using the existing empty-label-tuple name representation. Existing name compression rules still apply, including a valid backward pointer to a proven root. OPT may appear anywhere in the additional section, with ordinary records before or after it. Non-root owners, OPT in answers/authorities and a second OPT are MALFORMED. A question with type 41 remains a question and is not an OPT record. Unknown versions and reserved flags do not cause rejection when the common structure is representable.

### Status and publication boundary

The record decoder checks that all declared RDATA bytes exist before EDNS parsing starts. Missing owner/envelope/RDATA bytes produce the existing INCOMPLETE status. Within fully available RDATA, fewer than four remaining option-header bytes or an option length exceeding the remaining envelope is MALFORMED, even if later record bytes could satisfy that length. Those bytes cannot cross the RDLENGTH boundary. Names within option data are never compression targets.

The parser publishes EDNS only after every declared section and the exact message-end boundary succeed. An invalid option sequence yields no valid option prefix. A later malformed, incomplete or unsupported record, duplicate OPT or trailing bytes also suppresses all semantic EDNS. The existing DNS observation keeps its completed raw record prefix, `parsed_length`, `remaining_bytes`, `failure_offset`, reason and limit metadata. The failing record is excluded. Existing correlation admits only COMPLETE messages, so these failures produce no new transaction/statistics contributions. Allocation and other infrastructure failures propagate; they are not converted to empty EDNS observations.

### Bounds and ownership

The public operational count bound is `DNS_MAX_EDNS_OPTIONS=128`, following the existing DNS entry-limit convention. Encountering another option after that bound returns UNSUPPORTED with `limit_reached=True`; option payloads are not allocated from unchecked lengths. The existing `DNS_MAX_MESSAGE_BYTES=65535` and `DNS_MAX_ENTRIES=128` still apply first.

`DNS_MAX_EDNS_OPTION_BYTES=65512` is the maximum total option-envelope bytes in one OPT, derived from the message ceiling minus the twelve-byte DNS header and eleven-byte root-owned record envelope. `DNS_MAX_EDNS_OPTION_DATA_BYTES=65508` subtracts one four-byte option header. A maximal single-option message reaches these bounds exactly. More questions, records or option headers reduce available payload bytes. Exceeding the total-byte bound necessarily exceeds the existing message ceiling and returns UNSUPPORTED before parsing; wire-declared lengths beyond available RDATA instead follow the structural failure rules above. Transport limits can be narrower. Option iteration advances at least four bytes and admits at most 128 options.

`DNSEDNS` stores four bounded integers and one option tuple; each option stores one bounded integer and immutable bytes. Both are frozen, factory-only values, like the existing DNS parser types. Direct construction, including invalid types/ranges or otherwise plausible keyword values, raises `TypeError`; callers use the exact-`bytes` parser API. Parsed values are exact integers and booleans without coercion.

Raw RDATA remains retained by its existing record, and option payloads are separate bounded byte slices: at most 65,508 added payload bytes plus 128 option objects/tuple entries per message. This is bounded storage, not zero-copy or constant memory independent of parser limits. Neither EDNS nor option values refer back to records, names, DNS messages, packets, analysis, transactions, flow state, timestamps or capture sources. Retaining an EDNS value therefore releases the surrounding source graph when its other owners release it. The existing flow/session lifecycle remains the only owner of message observations.

### Compatibility and transport

Features 12–19 retain their existing non-OPT parsing, header, correlation and statistics contracts. This feature intentionally makes formerly opaque invalid OPT structures malformed/incomplete/unsupported under the rules above. Valid OPT still contributes one additional record, its raw TYPE/CLASS bins and its full RDLENGTH to Feature 16. Option entries do not become separate resource records or query names. Feature 14 retains its four-bit response-code distribution and exact transaction latency. Features 17/19 flag counters and Feature 18 header properties are unchanged. Generic `FlowFeatureSnapshot` version 1 and the 49-value ML projection receive no EDNS fields.

IPv4 and IPv6 use the same established UDP analysis path. Already-delimited TCP DNS messages and their existing transaction observations may contain EDNS; automatic TCP framing follows the bounded Feature 22 contract below. No global EDNS state or new flow/transaction ownership is added. LDAP, detectors, evaluation, metrics, capture and CLI behavior are unchanged. This protocol-analysis foundation does not detect attacks, infer maliciousness or assign security classifications.

## DNS EDNS option structural statistics

Feature 21 exports the frozen `DNSEDNSStatistics` value and `update_dns_edns_statistics(current, observation)`. The reducer consumes terminal `DNSTransactionObservation` values and their already-parsed semantic `DNSEDNS` / `DNSEDNSOption` properties. It never reparses wire bytes, reads option payload contents, decodes option-specific semantics or creates an option registry. Unknown versions and codes remain structural values; reserved flags stay parser-owned without new statistics or interpretation.

### Stored fields and distribution domains

The result stores exactly twelve scalar fields and three immutable distributions:

| Field | Contract |
| --- | --- |
| `edns_message_count` | Number of contributing COMPLETE messages with an admitted OPT. |
| `option_count` | Number of observed options, including repeated codes and zero-length options. |
| `min_option_data_length` | Smallest option payload byte length, excluding its four-byte envelope; `None` without options. |
| `max_option_data_length` | Largest option payload byte length; `None` without options. |
| `total_option_data_length_bytes` | Sum of option payload byte lengths, excluding envelopes. |
| `zero_length_option_count` | Number of options whose payload length is zero. |
| `max_options_in_message` | Largest option count in a contributing EDNS message; `None` without EDNS messages. |
| `min_options_in_message` | Smallest option count in a contributing EDNS message; `None` without EDNS messages. |
| `udp_payload_size_min` | Smallest observed unsigned 16-bit advertised UDP size, without clamping; `None` without EDNS messages. |
| `udp_payload_size_max` | Largest observed advertised UDP size; `None` without EDNS messages. |
| `udp_payload_size_total` | Sum of advertised UDP sizes across contributing EDNS messages. |
| `extended_rcode_counts` | Fixed 256-element tuple indexed 0–255 by EDNS extended RCODE, separate from the header response code. |
| `version_counts` | Fixed 256-element tuple indexed 0–255 by EDNS version, including every nonzero version. |
| `option_code_counts` | Exactly 65,536 logical bins in 256 immutable blocks of 256 integers; code `c` uses `[c // 256][c % 256]`, for 0–65,535 inclusive. |
| `dnssec_ok_count` | Number of contributing EDNS messages with semantic DO set, independent of header AD. |

Three derived properties add no stored fields: `mean_option_data_length` is exact `Fraction(total_option_data_length_bytes, option_count)`, or `None` without options; `non_dnssec_ok_count` is `edns_message_count - dnssec_ok_count`; `unknown_option_count` equals `option_count`. Here **unknown means without decoded semantics under the current repository contract**. Feature 20 preserves every option as opaque bytes and has no recognized-option registry. The count includes familiar/assigned codes and does **not** claim codes are IANA-unassigned, invalid or malicious.

An empty aggregate has zero counts, totals and bins, with absent extrema and mean. An empty OPT counts as one EDNS message with zero options and measured zero per-message option extrema; a zero-length option instead has one option, measured zero data extrema and `Fraction(0)`. Messages without OPT change no EDNS measurements. Repeated options, repeated messages and sequential transaction-ID reuse preserve multiplicity.

Constructor validation requires exact nonnegative integers, rejecting booleans, floats, mutable distributions, invalid dimensions and inconsistent totals/extrema. Each version/extended-RCODE distribution sums to `edns_message_count`; option-code bins sum to `option_count`. DO and zero-length counts cannot exceed their corresponding populations. Extrema must be attained and ordered within parser bounds, positive-length options must fit the total, and total payload bytes plus four bytes per option cannot exceed the aggregate parser envelope bound. This validates aggregate constraints; it does not reconstruct individual source messages.

### Lifecycle and compatibility

MATCHED contributes the request and response separately, counting only those with EDNS. UNMATCHED, AMBIGUOUS and UNRESOLVED contribute their observed message once; a referenced earlier request in an ambiguous observation is not counted again there. The original pending request contributes separately when correlation terminalizes it. Direct PENDING reducer calls are rejected. Malformed, incomplete and unsupported messages are excluded upstream by existing correlation, and forged non-COMPLETE terminal inputs are rejected by the reducer.

The coordinator reduces newly terminal batches inside its existing prepare/commit boundary. Its appended `dns_edns_statistics` field defaults to an empty aggregate, preserving earlier positional constructors. The window property exposes the identical value. Explicit segmentation, inactivity, capacity eviction and capture end reduce only newly unresolved closure observations, after the already-counted terminal prefix. Repeated finalization adds nothing. Aggregation, partial-batch and publication failures leave the published state unchanged and retries count the successful contribution once. A new window begins with new empty statistics. The reducer itself has no deduplication history: deliberately feeding the same terminal observation twice counts it twice.

IPv4/IPv6 UDP, including supported extension headers, use the existing packet and flow path. Already-delimited TCP terminal observations can use the reducer directly; automatic TCP framing follows the bounded Feature 22 contract below. Features 14–20 semantics remain unchanged: OPT is still one additional record, EDNS extended RCODE stays separate from the header RCODE, and DO stays separate from AD. `FlowFeatureSnapshot` is unchanged, its contract remains `flow-feature-snapshot` version `1`, and its ML projection remains 49 values. LDAP, detectors, evaluation, capture and CLI implementations are unchanged. These are structural measurements and do not detect attacks.

### Memory and arithmetic bounds

One aggregate contains twelve scalar slots and 66,048 logical integer bins (65,536 + 256 + 256), with 256 additional block references in the option distribution. Its distributions require at most 259 tuple objects: two direct distributions, one outer code tuple and 256 code blocks. Empty blocks are shared, and updates replace affected immutable blocks. A fixed twelve-key temporary scalar mapping, three 256-entry working lists and one 256-entry option-block list support updates; no mapping grows with codes or messages. At most two source messages are traversed per transaction, each with at most 128 options, 65,512 total option-envelope bytes and 65,508 individual option payload bytes under Feature 20's parser bounds. Closure uses the existing bounded suffix of at most 128 newly terminal observations.

The result retains no predecessor, packets, messages, transactions, options, payload bytes, DNS names, timestamps or source observation graph. Weak-reference tests cover release both after closure and while a flow remains active. Bytes themselves do not support weak references; source-graph release and inspection of exclusively integer/tuple aggregate fields verify absence of payload retention. Exact Python integers are used throughout, with standard-library `Fraction` for the mean and no floating-point conversion. Integer bit lengths grow logarithmically with totals, so bounded field/bin count is not a constant-byte memory promise. Active-window limits and snapshots retained by callers still determine aggregate multiplicity.

## DNS-over-TCP message framing

Feature 22 adds [dns_stream_framing.py](dns_stream_framing.py) at the existing bounded TCP consumption boundary. `update_dns_stream_state(current: Optional[DNSStreamState], streams: TCPStreamState) -> Optional[DNSStreamUpdate]` observes complete two-byte network-order length prefixes and exactly the declared number of following DNS bytes. It accepts split prefixes, payloads split over many observations, one-byte fragments, coalesced frames and complete frames followed by an incomplete next frame. Packet boundaries have no DNS framing meaning.

### Public representation and ownership

All values are frozen and factory-only, following existing stream observation conventions:

| Value | Exact stored fields |
| --- | --- |
| `DNSStreamObservation` | `stream`, `prefix`, `declared_length`, `payload`, `status`, `unavailable_reason` |
| `DNSStreamState` | `tcp_stream_state`, `forward`, `reverse` |
| `DNSStreamUpdate` | `state`, `forward_frames`, `reverse_frames` |

`DNSStreamObservation.stream` is the same consumed `TCPStreamObservation` referenced by the state's `tcp_stream_state`. Derived `identity`, `direction` and `consumed_offset` delegate to it. `prefix` and `payload` are exact immutable bytes excluded from representation strings. `declared_length` is `None` until both prefix bytes arrive. `DNSStreamStatus` has only READY, INCOMPLETE and UNAVAILABLE; it is a framing status, not a DNS parser result. `unavailable_reason` is either absent or an existing `TCPStreamStatus` value.

The update's frame tuples contain only newly completed DNS payload bytes in directional order, excluding length prefixes. They are transient outputs for the caller to consume; the retained state has no frame/message history and no reference to its update. Keeping an update is explicit caller-owned retention. An empty `TCPStreamState` on eligible ports returns an empty framing state, with both directions absent; an observed empty direction is READY. Unchanged/empty observations and recognized retransmissions emit nothing again. Continuing from a different consumed offset, identity or lost established direction is rejected.

The coordinator appends `dns_stream_state=None` to preserve previous positional construction, then stores the returned consumed TCP state and framing state together. `FlowObservationWindow.dns_stream_state` exposes the latter. Each direction is independent under canonical IPv4/IPv6 flow identity, including interleaved client ports. Automatic dispatch requires TCP source or destination port 53. If either endpoint is port 389, the established LDAP consumer retains precedence and DNS framing is absent. Other TCP ports have no automatic DNS framing. This adds no second TCP owner, global cache or cross-flow byte state.

### Length, buffering and stream failures

The unsigned prefix excludes its own two bytes. `DNS_MAX_MESSAGE_BYTES` remains 65,535; there is no larger DNS limit. The maximum complete wire frame is therefore 65,537 bytes. Framing consumes available prefix/payload fragments through `consume_tcp_stream` immediately and retains only the incomplete frame fragment, allowing the unchanged TCP layer to reclaim consumed bytes when its 65,536-byte directional buffer needs space. This supports a maximum-size DNS message spanning TCP observations without increasing that buffer.

At publication, each direction retains either one incomplete prefix byte, or a known length with fewer than that many payload bytes: at most **65,534 incomplete DNS payload bytes**. A complete payload can transiently contain **65,535 bytes** before emission. Prefix assembly transiently uses at most two bytes. Prefix and payload accumulation never allocates the declared size in advance. Additional state contains only scalar metadata and shared stream references; no bytearray, packet, parsed DNS message, transaction, predecessor or arbitrary history is stored. The existing TCP buffer can retain consumed raw bytes until its normal reclamation, and correlation keeps its existing bounded pending/latest-output ownership.

Per direction, one call can emit at most 32,768 frames because every fresh frame needs a two-byte prefix; total emitted payload bytes are bounded by at most 65,536 new stream bytes plus at most 65,534 previously incomplete payload bytes. The public updater handles at most two directions. These are temporary output bounds, not additional retained framing history. Active-window capacity, snapshots retained by callers, and exact integer offset widths still affect total memory.

**A declaration one byte above `DNS_MAX_MESSAGE_BYTES` cannot be encoded:** 65,536 needs more than two bytes. `0xffff` legally declares 65,535 bytes. A defensive comparison against the parser limit stops framing before body consumption using UNAVAILABLE / `TCPStreamStatus.LIMIT_EXCEEDED` if that bound is ever narrower. Tests exercise this guard with an explicitly injected lower bound; they do not claim an oversized declaration exists under today's wire contract.

TCP remains authoritative for sequence numbers, retransmissions, overlap/conflict, gaps, fragmentation, SYN/FIN/RST and buffer limits. A stream whose contiguous payload is unavailable makes framing UNAVAILABLE with that existing TCP reason. The first failure remains sticky, and the bounded partial prefix/payload remains available for inspection. No missing bytes are guessed, no stream is reconstructed, and there is no resynchronization. FIN/RESET streams can supply their final contiguous bytes; payload after closure follows the TCP layer's AFTER_CLOSE semantics. Capture starting midstream assumes the first observed byte starts a prefix; the layer cannot prove this alignment or identify encrypted DNS.

### Parser, transactions and closure

The framer knows no DNS header, questions, resource records, flags or EDNS fields. The coordinator passes each complete payload exactly once to `analyze_dns_message`, without the prefix. A zero-length frame emits `b''`; the existing parser reports INCOMPLETE and subsequent frames can still be processed. A complete frame with malformed, incomplete or unsupported DNS/EDNS receives the existing `DNSMessageStatus`; its known framing boundary allows continuation. Partial framing bytes are never passed to the parser and receive no fabricated DNS status.

Complete parsed messages enter `update_dns_correlation_state` with the packet capture timestamp at which their frame completes. Multiple messages in one direction retain wire order and share the completing observation's timestamp. Every newly terminal correlation batch feeds all existing statistics before the next message advances correlation. The retained correlation output remains its existing latest-call batch, not a new complete-message archive. Requests/response matching, repeated IDs, sequential reuse, ambiguity, pending-capacity behavior and exact duration arithmetic are unchanged. Observations with no complete frame advance an existing correlation timestamp and clear its latest batch without inventing a message.

Infrastructure exceptions from TCP observation, framing allocation, parsing, correlation or aggregation propagate through the existing prepare/commit boundary. The candidate is not published, previously published messages/statistics are preserved, and retry uses the original stream consumption and aggregates. Failed window publication follows the same rule. Ordinary DNS parse statuses do not roll back earlier frames or prevent subsequent complete frames from being examined. No DNS-over-TCP rollback or alternative transaction failure model is introduced.

At inactivity, capacity, explicit segmentation or capture end, complete frames have already entered the parser. An incomplete prefix or payload stays INCOMPLETE in the closed window and is never converted into a DNS message. Existing finalization terminalizes only already-admitted pending requests; repeated finalization cannot recount the completed prefix. TCP FIN/RST does not itself replace the existing window closure policy. New windows begin with independent empty framing state. Capture failures retain established session cleanup and publication behavior.

Valid no-OPT and EDNS messages use exactly the same Features 12–21 parser, header, correlation and reducer contracts as already-delimited TCP messages and UDP DNS. Unknown EDNS codes/versions, DO, opaque options, malformed EDNS admission and Feature 21's unknown-option meaning are unchanged. `PacketAnalysis.dns` stays UDP-only because a packet-local accessor cannot own stream framing. Direct `analyze_dns_message` and correlation APIs remain available for already-delimited TCP input. `FlowFeatureSnapshot`, contract `flow-feature-snapshot` version `1`, the 49-value ML projection, LDAP, detectors, evaluation, metrics, capture and CLI are unchanged. DNS-over-TCP framing is protocol ingestion infrastructure and does not detect attacks.


## TLS record framing

Feature 23 adds [tls_record_framing.py](tls_record_framing.py). `update_tls_record_state(current: Optional[TLSRecordState], streams: TCPStreamState) -> Optional[TLSRecordUpdate]` consumes the existing ordered directional TCP byte boundary. The five-byte TLS record header contains an unsigned one-byte content type, two exact protocol-version bytes and an unsigned two-byte network-order length. The length excludes the header. Payloads are opaque exact bytes: arbitrary content types, versions, zero bytes and zero-length records are preserved without semantic validation.

Every header/payload split is supported, including one-byte observations, multiple records per observation and complete records followed by an incomplete suffix. Complete records are emitted in directional wire order; an arbitrary complete payload does not prevent subsequent records. Packet boundaries carry no record-framing meaning.

### Public values and ownership

All public values are frozen and factory-only. The analysis package exports the updater, bound, enum and these types:

| Value | Stored fields |
| --- | --- |
| `TLSRecordHeader` | `content_type`, `protocol_version`, `declared_length` |
| `TLSRecordObservation` | `stream`, `prefix`, `header`, `payload`, `status`, `unavailable_reason` |
| `TLSRecordState` | `tcp_stream_state`, `forward`, `reverse` |
| `TLSRecordUpdate` | `state`, `forward_records`, `reverse_records` |

The observation's `declared_length` derives from its optional header, avoiding duplicated length state. `identity`, `direction` and `consumed_offset` delegate to its shared `TCPStreamObservation`. Partial headers reside in `prefix`; after five bytes arrive, `prefix` is cleared and `header` stores their fields. Bytes and output tuples are immutable. Prefix/payload bytes are excluded from repr.

`TLSRecordStatus.READY` in retained directional state means an empty framing boundary with no current header or payload. INCOMPLETE means a partial header or body; UNAVAILABLE means an inherited TCP failure or oversized TLS declaration. These statuses describe framing, not TLS validity. A transient completed record is a READY observation with a non-None header and exactly its declared payload. An eligible empty TCP state has absent directions; an observed empty direction is READY and emits nothing.

`forward_records` and `reverse_records` contain only newly completed observations. Each references the same consumed directional TCP observation as the returned state, including the metadata of the observation that completed the record. All records completed in one call share that direction's stream reference and final consumption offset; this offset is not an individual record-end coordinate. TCP observations do not contain capture timestamps. A future consumer can use the completing packet/flow's existing capture-time context; this feature introduces no timestamp copy or wall clock.

Retained state has no reference to the update or completed record objects. Keeping updates or closed windows is explicit caller ownership. The coordinator prepares TLS consumption and publishes `tls_record_state` with the exact shared TCP state; the window exposes it as `tls_record_state`. The coordinator currently retains framing state only: no TLS semantic consumer, completed-record archive or external record-delivery API exists. Future analysis can consume the public update at the existing preparation boundary.

Automatic dispatch requires a TCP endpoint on port 443. A flow involving 389 preserves LDAP precedence; a flow involving 53 preserves DNS precedence. Non-443 ports do not create TLS state. Canonical IPv4/IPv6 identities, client ports and directions remain isolated within existing flow/window owners. There is no second TCP owner, global cache or application-stream abstraction. Starting at an already-consumed origin, changing identity/consumption externally, or losing an established direction raises an error.

### Exact bounds and failures

`TLS_RECORD_MAX_PAYLOAD_BYTES = 18432` uses the conservative TLS 1.2 TLSCiphertext ceiling of `2^14 + 2048` from [RFC 5246 section 6.2.3](https://www.rfc-editor.org/rfc/rfc5246.html#section-6.2.3). This is a framing envelope bound, not version-dependent validity checking. A complete bounded record contains at most 18,437 wire bytes. The length field can naturally encode 65,535; both 18,433 and 65,535 are representable declarations rejected by this implementation. The value 65,536 cannot be encoded in that two-byte field.

No declared-size preallocation occurs. Available fragments are consumed immediately through `consume_tcp_stream`. Per direction, retained TLS byte state is either at most **four incomplete header bytes**, or one decoded header and at most **18,431 incomplete payload bytes**. Header assembly transiently uses five bytes; a completed payload transiently uses at most **18,432 bytes**. The existing TCP layer separately retains at most **65,536 bytes per direction**, including consumed raw bytes until reclamation. Consuming fragments allows even a long sequence of maximum-sized records to reclaim TCP storage without retaining complete TLS history.

One update handles at most two directions. A direction can transiently emit at most 13,108 records: one previously partial record plus records using the remaining bounded input, each fresh record requiring at least five bytes. Transient emitted payload bytes are bounded above by 65,536 available TCP bytes plus 18,431 previously incomplete payload bytes. Object overhead, temporary immutable-byte copies, integer offset widths, window capacity and caller-retained snapshots are additional memory costs; this is not a constant process-memory guarantee. No packets, predecessor states, handshake histories, parsed messages or transaction graphs are retained by TLS framing.

A declaration above 18,432 consumes its five-byte header, retains its metadata and enters UNAVAILABLE with `TCPStreamStatus.LIMIT_EXCEEDED` before consuming or copying its body into TLS state. Any body already present remains within the existing bounded TCP buffer. Earlier complete records in that update are still emitted. No later bytes are framed in the failed direction. Inherited TCP failures use their existing reason; the first applicable failure is sticky, including when TCP later reports a different failure. The existing bounded partial fragment remains inspectable.

TCP alone owns sequence numbers, SYN/FIN/RST, retransmissions, wraparound, gaps, overlap/conflict, fragmentation, restart, buffer limits and after-close behavior. Recognized retransmissions and unchanged updates emit no duplicate records. FIN/RESET may provide final contiguous bytes; a partial suffix remains INCOMPLETE, while subsequent payload follows TCP AFTER_CLOSE. There is no gap repair, out-of-order reconstruction, stream resynchronization or guessed alignment. Framing starts at the observed origin; a midstream capture or new window does not prove that this origin is a TLS record boundary.

### Publication, closure and scope

Infrastructure exceptions during TCP updating, framing, allocation, record extraction or window construction abort the candidate before publication. Published state and consumption remain intact, and retry from that state reproduces the complete record batch. Tests also compose a failing future consumer at the preparation boundary; no TLS-specific rollback is introduced. This guarantees state atomicity, not rollback of arbitrary external consumer side effects. Existing closed-window delivery happens after publication and keeps its existing failure contract.

At explicit close, inactivity, capacity eviction or capture end, incomplete headers and payloads stay INCOMPLETE in the closed window and never become complete records. Previously extracted complete records are not re-emitted by closure. Repeated capture finalization returns no new windows; repeated explicit close keeps the existing missing-active-window error. New windows own independent framing. FIN/RST does not replace the existing window closure policy. Capture errors preserve already published state and existing cleanup behavior.

This feature performs no TLS semantic parsing, handshake/certificate analysis, decryption, cryptographic validation, fingerprinting, attack detection or encrypted-DNS analysis. Features 12–22, `FlowFeatureSnapshot`, `flow-feature-snapshot` version `1`, all 49 projected values, LDAP, detectors, evaluation, metrics, capture and CLI remain unchanged. Validation uses synthetic traffic through existing packet/capture/session helpers and all four classic PCAP encodings; no external corpus or submicrosecond timestamp preservation is claimed.


## TLS handshake-message framing

Feature 24 adds [tls_handshake_framing.py](tls_handshake_framing.py). `update_tls_handshake_state(current: Optional[TLSHandshakeState], records: TLSRecordUpdate) -> TLSHandshakeUpdate` consumes the existing TLS framer's complete record batches. It never reads raw TCP payloads, reconstructs record headers or invokes a semantic parser. Automatic flow integration calls it during preparation after Feature 23 and publishes the resulting state with the exact existing TLS record state.

### Wire format and record eligibility

The four-byte handshake header contains one unsigned opaque `handshake_type` byte and a three-byte unsigned network-order `declared_length`. The length excludes the header. Exactly that many following bytes form the opaque body. Zero-length messages are complete; arbitrary type values and binary bodies remain unchanged. No handshake-specific body structure is validated.

Only `TLSRecordHeader.content_type == 22` supplies handshake bytes. A message may span many records, including one-byte record payloads and split four-byte headers. A record may contain multiple messages or the end of one message followed by a partial next message. Complete messages retain directional wire order independently of both TLS record and TCP observation boundaries.

Other content types are ignored without changing the current partial header/body. Their bytes never enter handshake state. A zero-length ContentType 22 record similarly adds no bytes and emits nothing. This is a framing policy, not an inference about TLS session transitions or encryption state. Lower-layer observation metadata still advances, and lower-layer failures still propagate. No encrypted application data is interpreted as handshake content.

Automatic eligibility remains entirely owned by Feature 23: port 443, preserving LDAP port 389 and DNS port 53 precedence. Ineligible flows have no handshake state. An eligible empty TLS record state produces empty handshake state with absent directions; an observed direction with no handshake bytes is READY.

### Public representation and ownership

All values are frozen and factory-only, exported through the analysis package:

| Value | Stored fields |
| --- | --- |
| `TLSHandshakeHeader` | `handshake_type`, `declared_length` |
| `TLSHandshakeObservation` | `stream`, `prefix`, `header`, `payload`, `status`, `unavailable_reason` |
| `TLSHandshakeState` | `tls_record_state`, `forward`, `reverse` |
| `TLSHandshakeUpdate` | `state`, `forward_messages`, `reverse_messages` |

`prefix` contains an incomplete handshake header. Once its four bytes arrive, it is cleared and `header` stores the type and length. Observation `declared_length` derives from its optional header; identity, direction and consumed offset delegate to the shared TCP stream observation. Bytes and output tuples are immutable, with prefix/payload omitted from repr.

`TLSHandshakeStatus.READY` in retained state means no incomplete handshake remains. INCOMPLETE means a partial header or body. UNAVAILABLE means a sticky inherited failure or implementation-limit rejection. A transient complete message is READY with a non-None header and exactly its declared body. These statuses describe framing completeness only, not TLS protocol validity.

Each completed message's `stream` is the exact existing TCP observation referenced by the TLS record that supplied its final byte. Several messages completed in one observation share its metadata and final lower-layer consumption offset; this is not a per-handshake end offset. There is no timestamp copy or new clock. Existing completing packet/flow capture-time context remains available to future consumers.

Retained state references only the current TLS record state and current directional incomplete handshake observations. It retains no complete TLS record objects, handshake message objects, predecessor states, packets, certificates, protocol graphs or arbitrary history. `CoordinatedFlowState.tls_handshake_state` defaults to None and `FlowObservationWindow.tls_handshake_state` exposes it. The coordinator consumes transient updates during preparation and retains state only; this feature introduces no semantic consumer, message archive or external delivery API.

Callers must supply every TLS record update in order from the same observed origin. Reapplying an already consumed batch emits nothing; recognized TCP retransmissions likewise emit nothing again. Identity changes, backwards consumption and loss of an established direction are rejected. This API does not reconstruct updates omitted by a caller or establish missing alignment. It uses the lower-layer consumption coordinate and adds no second lower-layer cursor or ownership model.

### Bounds and failure semantics

`TLS_HANDSHAKE_MAX_MESSAGE_LENGTH = 262144` is a 256 KiB implementation ceiling. A maximum complete handshake frame has 262,148 bytes including its header. The three-byte wire field can represent 16,777,215; both 262,145 and 16,777,215 are representable declarations rejected by this implementation. The value 16,777,216 cannot be encoded in three bytes.

No declared-size allocation is made in advance. Only available ContentType 22 fragments are appended. Per direction, retained handshake bytes are either at most **three partial-header bytes**, or one decoded header and at most **262,143 incomplete body bytes**. Header assembly transiently uses four bytes; complete bodies transiently use at most **262,144 bytes**. The shared lower layers keep their existing separate limits: at most 18,431 incomplete TLS payload bytes (or four partial TLS header bytes) and a 65,536-byte TCP buffer per direction. Consumed TCP bytes remain reclaimable by the unchanged TCP mechanism, including during a maximum-size handshake spanning many records.

Temporary completed batches are also bounded by the existing record updater's bounded input plus a previously incomplete handshake. Keeping updates, windows or snapshots is explicit caller ownership. Immutable-byte copies, scalar/object metadata, integer offset widths and active-window capacity add memory costs; these byte limits are not a total process-memory guarantee.

An oversized handshake declaration records its header and transitions to UNAVAILABLE with `TCPStreamStatus.LIMIT_EXCEEDED` before copying or interpreting its body. The containing TLS record was already framed and consumed by Feature 23; handshake rejection does not undo lower-layer consumption. Remaining handshake bytes and later records in that direction are ignored. Earlier complete messages in the batch remain transient outputs. Failure in one direction does not disable the other.

Existing TCP/TLS record unavailability propagates using its existing reason after any earlier complete records in that update are processed. The first applicable handshake/lower-layer failure remains sticky, and incomplete bytes remain inspectable. TCP alone owns sequence numbers, retransmissions, wraparound, gaps, overlap/conflict, fragmentation, buffer limits, SYN/FIN/RST and after-close behavior. TLS record framing alone owns record headers, boundaries and eligibility. No lower-layer semantics are changed.

### Publication, closure and limitations

Allocation, framing, extraction, state-construction or publication exceptions abort the candidate through the existing prepare/publication boundary. Published TCP/TLS/handshake state remains intact, and retry reproduces the message batch without loss or duplicate successful emission. This is state atomicity; arbitrary external consumer side effects are not rolled back. Existing post-publication closed-window delivery semantics remain unchanged.

At explicit flow close, inactivity, capacity eviction or capture end, incomplete headers and bodies remain INCOMPLETE and are never emitted as messages. Complete messages have already been extracted. Repeated finalization produces no additional messages; repeated explicit close retains the existing missing-active-window error. New windows start independently. FIN/RESET may supply final contiguous bytes and leave an incomplete suffix; they do not replace window closure policy. Capture failures preserve earlier published state and existing cleanup.

Framing follows only the supplied record payload boundary and never scans for plausible headers. Midstream capture does not prove record or handshake alignment. An assumed origin can produce opaque complete framing without proving semantic validity; the layer does not guess missing bytes, recover gaps or resynchronize. No ClientHello/ServerHello/certificate parsing, SNI/ALPN/cipher interpretation, fingerprinting, decryption, cryptographic validation or detection is implemented by the handshake framer. Features 12–23, `FlowFeatureSnapshot`, contract version `1` and the 49-value ML projection remain unchanged.

Validation uses synthetic traffic through the existing real packet/capture/session path and four classic PCAP encodings. No external corpus, Authentication Header support beyond existing helpers, or submicrosecond capture-time preservation is claimed. Replay covers IPv4/IPv6, both directions, cross-record/segmented/coalesced messages, ignored records, TCP failure, capacity closure and weak-reference release under all nine required seed/timezone combinations.


## TLS handshake-message structural statistics

Feature 25 adds [tls_handshake_statistics.py](tls_handshake_statistics.py). The reducers consume completed `TLSHandshakeObservation` values from the existing Feature 24 batches. They use the decoded type, declared body length, exact payload length and existing `FlowDirection`; they do not parse headers, inspect payload contents, reconstruct messages or invent packet/timestamp relationships.

### Public representation and arithmetic

`TLSHandshakeStatistics` is a frozen, validated aggregate with these exact stored fields:

| Field | Contract |
| --- | --- |
| `total_message_count` | Number of completed messages |
| `zero_length_message_count` | Completed messages whose declared body length is zero |
| `min_message_length` | Minimum body length; None when empty |
| `max_message_length` | Maximum body length; None when empty |
| `total_message_length_bytes` | Exact sum of declared body lengths, excluding four-byte headers |
| `handshake_type_counts` | Exactly 256 immutable integer bins, indexed 0 through 255 |

Empty counts/totals and every type bin are zero. `mean_message_length` is a derived property: None when empty, otherwise `Fraction(total_message_length_bytes, total_message_count)`. For lengths 0, 2 and 3, the total is 5 and mean is exactly `Fraction(5, 3)`. Zero-length messages contribute to total count, zero-length count and their type bin, and participate in the mean. All 256 types are opaque numeric observations without a recognized-type registry or security classification.

Constructor validation requires exact nonnegative integers (not booleans), an exact tuple of 256 integer bins summing to the message count, ordered extrema within the existing 262,144-byte handshake body bound, consistent zero counts and an attainable length total. Empty aggregates require absent extrema and zero bytes. Totals and counters use arbitrary-precision integers; no float, Decimal, rounding or machine-word saturation is introduced.

`DirectionalTLSHandshakeStatistics` is a frozen validated pair with exactly `forward` and `reverse`, both `TLSHandshakeStatistics` values defaulting to empty. There is no merged directional aggregate, identity field, timestamp or retained source reference. The existing flow/window owner supplies identity and lifecycle.

The analysis package exports both representations and two focused reducers:

- `update_tls_handshake_statistics(current: Optional[TLSHandshakeStatistics], observation: TLSHandshakeObservation) -> TLSHandshakeStatistics` updates one caller-owned aggregate.
- `update_directional_tls_handshake_statistics(current: Optional[DirectionalTLSHandshakeStatistics], observation: TLSHandshakeObservation) -> DirectionalTLSHandshakeStatistics` selects exactly one aggregate using the observation's existing direction. The coordinator uses this directional reducer, preserving the other aggregate unchanged.

Both reducers require a complete READY observation with a decoded header, empty prefix, no unavailable reason, exact immutable payload bytes, and `declared_length == len(payload)`. Type/length metadata must lie within framing bounds. Partial observations, empty READY framing boundaries without a message header, unavailable observations and inconsistent forged values raise TypeError/ValueError as appropriate. No bytes are truncated, padded, normalized or repaired. The existing framer already enforces complete body length by construction and remains unchanged.

### Lifecycle and ownership

`CoordinatedFlowState.tls_handshake_statistics` defaults to an empty directional pair on every flow, including ineligible/non-TLS flows. `FlowObservationWindow.tls_handshake_statistics` exposes that exact immutable result. After the existing handshake updater emits its transient batches, the coordinator reduces each message during preparation, in directional wire order, before publishing any candidate state. It does not retain those batches.

For complete A, complete B and partial C, statistics count only A and B. A later completion counts C once. Empty updates, recognized retransmissions and non-handshake records emit no messages to count. Oversized or unavailable framing cannot fabricate a completed observation; earlier complete messages before a framing failure remain counted. Port 443 eligibility, LDAP 389/DNS 53 precedence, IPv4/IPv6 flow identity and directional ownership remain inherited from existing framing.

No statistics-specific finalizer is needed. Explicit close, inactivity, capacity eviction and capture end preserve already reduced counters and exclude incomplete suffixes. Repeated finalization does not reduce old batches again; repeated explicit close retains the existing missing-active-window error. New windows start from empty aggregates. FIN/RST and capture failures retain established framing and closure behavior.

Validation, aggregation, state-construction or publication exceptions abort the entire candidate. Previously published counters and lower-layer consumption remain intact; retry reproduces the same counts without loss or duplicate successful contribution. The standalone reducers are additive, so a caller that deliberately submits the same message twice counts it twice. Exactly-once lifecycle accounting comes from the existing incremental framing/publication boundary, not an added deduplication cache. Arbitrary external consumer side effects are outside this state-atomicity guarantee.

Per direction, retained statistics contain five scalar fields and one fixed 256-bin tuple. The directional pair therefore holds ten scalar fields and 512 type counters, with fixed object/container structure. Optional extrema are None only when empty. Mean fractions are computed on access and retain no source. There are no messages, payload bytes, TLS records, TCP observations, packets, certificates, graphs, predecessor states, unbounded dictionaries or histories in these aggregates. Integer storage grows with counter magnitude; total process memory also depends on the existing framing bounds, active-window capacity and caller-retained snapshots.

### Scope and validation limits

These are body-length/type measurements of completed framing, not TLS semantic validity, handshake state-machine interpretation or proof of attack. No ClientHello/ServerHello/certificate parsing, SNI/ALPN/cipher/extension analysis, fingerprints, JA3/JA4, decryption, detection, scoring or ML is implemented by the statistics layer. Features 12–24, `FlowFeatureSnapshot`, `flow-feature-snapshot` version `1` and all 49 projected values remain unchanged. No generic statistics framework or shared DNS/LDAP refactor is introduced.

Validation uses synthetic traffic through the existing real packet/capture/session path, all four classic PCAP encodings and all nine required hash-seed/timezone combinations. Replay includes exact means, all 256 type bins, both directions, IPv4/IPv6, segmented/cross-record/coalesced messages, zero-length messages, TCP failure, capacity closure and lifecycle release. No external corpus, semantic TLS validity, midstream alignment recovery or submicrosecond timestamp preservation is claimed.

## TLS ClientHello structural analysis

Feature 26 adds [tls_client_hello.py](tls_client_hello.py). `analyze_tls_client_hello(observation)` accepts an exact completed `TLSHandshakeObservation`. Framing remains authoritative: the parser validates the READY status, header, immutable bytes and declared-length/payload-length agreement before reading the body. Inconsistent source objects raise TypeError or ValueError; the parser does not repair them. The coordinator invokes it only for newly emitted handshake type 1 messages, after the existing structural-statistics reduction.

### Wire structure and public values

The body contains two legacy-version bytes, 32 random bytes, a one-byte session-ID length and its bytes, a two-byte cipher-suite byte length and ordered two-byte integers, then a one-byte compression-vector length and ordered one-byte integers. Remaining bytes require a two-byte extension-block length followed by exactly that block. Trailing bytes are MALFORMED. Lengths are checked against available bytes before slicing or allocating their representations. There is no scanning, padding, normalization or resynchronization.

The frozen, factory-only public values are:

- `TLSClientHello`: `legacy_version`, `random`, `session_id` as exact bytes; `cipher_suites`, `compression_methods`, `extensions` as ordered tuples; `extensions_present` distinguishes an absent block from an explicitly empty block.
- `TLSClientHelloExtension`: `extension_type`, exact opaque `data`, and optional tuple fields `supported_groups`, `signature_algorithms`, `alpn_protocols`. Only types 10, 13 and 16 populate their corresponding structural field. Other fields are None. Unknown extensions, including empty data, remain opaque without a registry.
- `TLSClientHelloObservation`: `stream`, `status`, `reason`, `client_hello`, `failure_offset`. Identity, direction and consumed offset delegate to the completing handshake's exact TCP stream observation. No independent timestamp is added. Failures expose no partial ClientHello object; offsets are measured from the body start.

Supported groups and signature algorithms each require a two-byte vector length, exact extension-data consumption and an even identifier byte count. Empty identifier vectors are representable structurally. ALPN requires an exact two-byte list length and one-byte lengths for nonempty opaque protocol names; empty lists/names and inconsistent boundaries are MALFORMED. Names retain exact bytes and order, including case and zero bytes. Every duplicate extension occurrence remains separately represented in wire order, with its own selected tuple. Values are never merged, deduplicated, named or assigned security meaning.

The layout follows [RFC 5246 section 7.4.1.2](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.2); nonempty ALPN names follow [RFC 7301 section 3.1](https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1). This bounded structural contract deliberately preserves the entire one-byte session-ID range through 255, without asserting compliance with the protocol's narrower session-ID constraints. Cipher suites must be nonempty and even; compression methods must be nonempty. Version values, random bytes, duplicate types and identifiers receive no semantic or cryptographic validation.

### Bounds and statuses

| Public constant | Maximum |
| --- | ---: |
| `TLS_CLIENT_HELLO_MAX_BODY_BYTES` | 262144, the existing handshake ceiling |
| `TLS_CLIENT_HELLO_MAX_SESSION_ID_BYTES` | 255 |
| `TLS_CLIENT_HELLO_MAX_CIPHER_SUITE_BYTES` | 65535 wire bytes; largest accepted even vector is 65534 |
| `TLS_CLIENT_HELLO_MAX_COMPRESSION_BYTES` | 255 |
| `TLS_CLIENT_HELLO_MAX_EXTENSION_BYTES` | 65535 including extension headers |
| `TLS_CLIENT_HELLO_MAX_EXTENSION_DATA_BYTES` | 65531 within the enclosing block |
| `TLS_CLIENT_HELLO_MAX_EXTENSIONS` | 1024 occurrences |

Each extension's length must fit inside its containing block. Selected vectors must fill their extension data exactly; ALPN names must fit their list. These bounds also bound tuple cardinalities: at most 32767 cipher identifiers, 255 compression methods, and 32764 identifiers or minimum-size ALPN names in one maximum-size selected extension. No allocation uses an unchecked declaration. The largest structurally representable body is 131619 bytes under these field bounds. An input of exactly 262144 bytes can arrive from handshake framing but cannot be a valid ClientHello layout; tests reject its excess instead of manufacturing a valid fixture.

`TLSClientHelloStatus` separates structural results:

- COMPLETE: every required field and vector is fully represented; this does not assert valid TLS negotiation.
- INCOMPLETE: the body lacks required outer field/vector bytes. A complete handshake envelope can contain an incomplete ClientHello structure.
- MALFORMED: an available length violates a structural constraint, an inner boundary contradicts its fully available container, or bytes trail the extension block.
- UNSUPPORTED: the direct API receives a non-ClientHello handshake, or more than 1024 extensions exceed the implementation count ceiling. Unknown extension types are supported opaque values.

Only these protocol parse results are caught. MemoryError and other infrastructure exceptions propagate, leaving the whole coordinator/window candidate unpublished for retry.

### Publication and ownership

`CoordinatedFlowState.tls_client_hellos` and `FlowObservationWindow.tls_client_hellos` expose an immutable tuple containing only ClientHello analyses newly produced by that packet update, in directional wire order. Each element retains the supplied direction; either direction is accepted without role inference. The next packet replaces the tuple, including with an empty tuple when no ClientHello completes. It is not an accumulated flow summary. Callers of the coordinator/window manager consume new batches from successful record updates, not by treating repeated snapshot access as new delivery.

A/B/partial-C publishes A and B; C appears once when its handshake later completes. Retransmissions and incomplete/unavailable framing do not create results. Malformed ClientHello input remains an ordinary published parser result and does not prevent subsequent complete messages from being analyzed. Preparation includes all messages and statistics; failure on a later parse, allocation, state construction or publication leaves previously published bytes, counts and analyses intact. Retrying the same packet reproduces the batch. No external side effect is performed during preparation.

Closure exposes the last published tuple without reparsing; it is not another emission. Capacity/inactivity/reopened windows remain independent. The existing session API delivers only closed-window snapshots, so it exposes only their latest batch, not all earlier ClientHellos. This feature does not add a session event callback or message archive. Tests observe successful manager publication while exercising the real capture/session path to verify all incremental results.

The parser is stateless. A retained flow owns only its latest bounded batch, not predecessor messages, TLS records, handshakes, packets or session history. Parsed structures hold only their immutable fields. Observation wrappers share the existing bounded TCP stream reference for source ownership; consumers retaining wrappers extend that reference's lifetime. Consumers retaining only `client_hello` do not retain the source handshake or stream. Old windows/results are released when callers release their snapshots, as verified with weak references. Wire bounds limit representation sizes, but Python object overhead is not claimed to equal a wire-byte ceiling.

Features 12–25 remain semantically unchanged. TLS port 443 eligibility, LDAP/DNS precedence, TCP/record/handshake failure behavior and the unproven alignment of midstream capture remain lower-layer contracts. No ServerHello/certificate parsing, SNI extraction, security classification, cryptographic validation, role inference, fingerprinting, JA3/JA4, decryption, detection or ML is added. `FlowFeatureSnapshot`, version 1 and all 49 projected values remain unchanged.

Validation uses synthetic IPv4/IPv6 traffic and existing supported extension chains through all four classic PCAP encodings, plus nine hash-seed/timezone replays. No external corpus, complete TLS semantic validity, arbitrary TCP reconstruction, new IPv6 extension support or submicrosecond timestamp preservation is claimed.

## TLS ServerHello structural statistics

Feature 29 adds [tls_server_hello_statistics.py](tls_server_hello_statistics.py). The reducers consume only the complete `TLSServerHelloObservation` values produced by Feature 28. They do not parse handshake bytes, retain ServerHello payloads or interpret fields as roles, fingerprints, negotiation decisions or security classifications.

`TLSServerHelloStatistics` is a frozen aggregate. It records the completed ServerHello count; legacy-version, cipher-suite, compression-method and extension-type distributions; legacy-version and session-ID extrema with session-ID byte totals; extension-block presence; extension-count extrema and totals; extension-data length extrema and totals; and duplicate extension occurrences. Extension data remains opaque and no extension registry or unknown-type label is introduced. Every extension occurrence contributes to its type bin and data totals, including duplicates.

The four distributions are immutable tuples of occupied `(wire_value, count)` pairs in ascending wire-value order. Two-byte values use the explicit 65,536-value domain and compression methods use the explicit 256-value domain; absent values are omitted, so empty and low-cardinality windows retain compact state. The number of occupied bins is bounded by the corresponding wire domain. Session IDs are bounded by 32 bytes, extension occurrences by 1,024 per message and extension data by the existing two-byte extension-length domain. Extrema are absent for empty aggregates and exact integer invariants reject inconsistent direct construction. Directional reduction selects the existing `FlowDirection` and does not infer client, server, initiator or responder roles. The directional pair is stored as `CoordinatedFlowState.tls_server_hello_statistics` and exposed by `FlowObservationWindow.tls_server_hello_statistics`.

Only `TLSServerHelloStatus.COMPLETE` observations contribute. Incomplete, malformed and unsupported analyses remain available in the current `tls_server_hellos` batch but do not enter the aggregate. Independently framed repeated messages count independently; retransmissions produce no new batch or count. The coordinator prepares each reduction with the existing atomic state boundary, so allocation, construction and publication failures preserve the prior aggregate and retries contribute once. Closure, FIN/RST, inactivity, capacity eviction and explicit close preserve already published statistics.

The aggregate retains only bounded tuples, counters and extrema. It retains no ServerHello, handshake, record, packet, stream, flow or capture references and has no archive, cache or deduplication history. Existing current-batch publication remains separate and transient. Generic flow features, contract version 1, ML projection and detectors remain unchanged. Validation uses synthetic IPv4/IPv6 traffic through all four classic PCAP encodings and nine hash-seed/timezone combinations; no external corpus or complete TLS semantic validity is claimed.

## TLS ClientHello structural statistics

Feature 27 adds [tls_client_hello_statistics.py](tls_client_hello_statistics.py). The reducers consume the completed `TLSClientHelloObservation` values produced by Feature 26. They do not parse handshake bytes, retain ClientHello payloads or interpret values as identities, fingerprints or security decisions.

`TLSClientHelloStatistics` is a frozen aggregate. It records the total completed ClientHello count; legacy-version extrema and a fixed 65,536-bin distribution; session-ID length extrema and total bytes; cipher-suite count extrema, total count and a fixed 65,536-bin distribution; compression-method count extrema, total count and a fixed 256-bin distribution; extension count extrema, total count and a fixed 65,536-bin distribution; unknown-extension occurrences; and duplicate-extension occurrences. A duplicate is each extension occurrence after the first occurrence of that type within one ClientHello. Every occurrence contributes to total extension count and its type bin, including duplicates and types not decoded by this implementation.

Selected Feature 26 structures add extension occurrence counts, per-extension minimum and maximum vector cardinalities and total inner-item counts for supported groups, signature algorithms and ALPN. Empty supported-groups or signature-algorithm vectors are represented with a zero cardinality. ALPN names are counted as opaque protocol entries; their bytes are not retained. No selected value receives a name, strength, client-library meaning or security classification.

All distributions are immutable tuples with explicit wire-domain bounds: 65,536 bins for two-byte values and 256 bins for one-byte values. Counters use exact integers and extrema are absent for empty aggregates. Directional reduction selects the existing `FlowDirection`; it never infers client, server, initiator or responder. The directional pair is stored as `CoordinatedFlowState.tls_client_hello_statistics` and exposed by `FlowObservationWindow.tls_client_hello_statistics`.

Only `TLSClientHelloStatus.COMPLETE` observations contribute. INCOMPLETE, MALFORMED and UNSUPPORTED results are excluded, and repeated identical messages are counted as independent observations. Existing parser statuses, TLS port 443 eligibility and DNS/LDAP precedence remain unchanged. The coordinator reduces each newly emitted ClientHello during candidate preparation, so state construction or publication failure leaves the previous aggregate intact and retry contributes exactly once. Closure, FIN, RST, capacity eviction, inactivity and explicit close preserve already published counters without recounting.

The aggregate retains only bounded tuples, counters and extrema. It retains no ClientHello, handshake, record, packet, stream, flow or capture references and has no archive, cache or deduplication history. Existing current-batch `tls_client_hellos` publication remains a separate transient result. The implementation is deterministic across hash seeds, time zones, directions, IPv4/IPv6 paths and classic PCAP encodings. Validation uses synthetic fixtures through the real capture/session path; no external corpus or semantic TLS validity is claimed.

## TLS ServerHello structural analysis

Feature 28 adds [tls_server_hello.py](tls_server_hello.py). `analyze_tls_server_hello(observation)` consumes only a completed `TLSHandshakeObservation` and only analyzes handshake type 2. TLS record framing, handshake framing, TCP ordering, eligibility and flow direction remain owned by the existing lower layers.

`TLSServerHello` is a frozen structural value containing the exact two-byte `legacy_version`, 32-byte `random`, bounded session ID bytes, two-byte `cipher_suite`, one-byte `compression_method`, optional declared `extensions_length`, ordered extension tuples and an `extensions_present` distinction between an absent block and an explicitly empty block. `session_id_length` and `extension_count` are derived properties. `TLSServerHelloExtension` preserves each two-byte extension type and bounded opaque data bytes in wire order; `data_length` is derived. Duplicate and unknown types remain ordinary structural observations.

The session ID is limited to 32 bytes, the extension block to the existing two-byte length domain, and extension occurrences to 1024. Every field length is checked before slicing. A complete enclosing handshake with missing structure produces `INCOMPLETE`; contradictory inner boundaries or an oversized session ID produce `MALFORMED`; a non-ServerHello handshake or an extension count beyond the implementation bound produces `UNSUPPORTED`. Infrastructure exceptions propagate through the existing atomic coordinator boundary.

`TLSServerHelloObservation` retains only immutable flow identity, existing direction, consumed offset, status, reason, failure offset and the bounded structural value. It does not retain the TCP stream, handshake observation, record, packet, capture session or message history. `CoordinatedFlowState.tls_server_hellos` and `FlowObservationWindow.tls_server_hellos` expose only the current packet's newly completed ServerHello batch. Repeated retransmissions emit no new batch; independently framed repeated messages remain separate observations. Closure, FIN/RST, inactivity, capacity, explicit close and publication retry follow the existing window semantics.

IPv4 and IPv6 traffic use the same TCP/TLS path, including existing IPv6 extension-header handling. Validation uses deterministic synthetic traffic through all four classic PCAP encodings and nine hash-seed/timezone combinations. No TLS version negotiation, role inference, certificate parsing, cryptographic validation, decryption, fingerprinting, statistics, detection or security classification is implemented. No external corpus or complete TLS semantic validity is claimed.

## TCP option structural statistics

`CoordinatedFlowState.tcp_option_statistics` and `FlowObservationWindow.tcp_option_statistics` expose immutable `DirectionalTCPOptionStatistics` for admitted IPv4/IPv6 TCP observations. The existing `FlowFeatureSnapshot.coordinated_state` provides the same aggregate. UDP leaves it empty. The coordinator prepares this aggregate with the other candidates and publishes it atomically; failed publication can be retried without counting the failed attempt. Repeated successfully admitted packets, including retransmissions, count again, as in TCP-control statistics. Closure preserves the aggregate without reprocessing bytes; a new window starts empty.

The reducer reuses the decoded `TCPPacket.options`, data-offset contract and existing option-envelope validator. It measures packet counts, complete packets with nonempty option areas, total option-area bytes (including padding), ordered option-kind occurrence counts, duplicate non-padding kinds within each packet, MSS wire-value frequencies, raw window-scale byte frequencies, and SACK block counts. Timestamp and SACK-permitted occurrence counts are projections of the kind distribution. EOL is counted once and ends parsing; following zero padding is not another option. NOP occurrences are counted but excluded from duplicate counts. Option order determines traversal and EOL termination; aggregate distributions are sorted numerically. Duplicate MSS/scale options contribute every occurrence without choosing an effective value.

MSS, window-scale, SACK-permitted and timestamp options require lengths 4, 3, 2 and 10 respectively. SACK requires one to four eight-byte blocks after its two-byte prefix. These layouts follow [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html), [RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html) and [RFC 2018](https://www.rfc-editor.org/rfc/rfc2018.html). An invalid known layout increments `malformed_option_packet_count` and contributes no option bytes, kinds or values, including from an earlier valid prefix. It does not change the pre-existing packet outcome/admission contract: lower-layer envelope failures still produce structural failures, truncated TCP/IP headers remain incomplete, checksum failures remain authoritative, and non-initial fragments retain existing transport/admission behavior. Direct reducer calls with invalid envelope or inconsistent header metadata raise before publication. Unknown option kinds are counted by their validated envelope; their semantics and bodies remain opaque.

This is observed structure, not negotiated TCP state. MSS zero, raw scale values 15–255, duplicate options and options on non-SYN packets remain observable. No window scaling, timestamp RTT/PAWS, SACK sequence-edge interpretation, fingerprint classification, attack labels or new detector predicates are inferred. The existing numerical feature contract and 49-column ML projection remain unchanged. The measurements support future transport-profile comparisons and explicitly defined detection/evaluation predicates.

Resource bounds are explicit: at most 40 input option bytes, 40 one-byte entries and four total SACK blocks per packet; flat traversal with no recursion or nesting. Invalid types, a byte area over 40, or a mismatch with the 5–15-word data offset fail before scanning. The parser uses at most 40 temporary kind/value entries and retains no raw bytes, option bodies, timestamp values, sequence edges, packets, observations or source objects. Per direction, sorted immutable sparse distributions have at most 256 kind bins, 65,536 MSS bins and 256 raw-scale bins (66,048 entries total); cardinality is checked before iteration on public construction. Merging and validation require bounded linear temporary storage in those domains, with sorting bounded by the same cardinalities. There is no packet history. Integer counter magnitude grows with observation count, following existing exact statistics conventions; this is a collection-cardinality bound, not a fixed byte ceiling on arbitrary-precision counters. Active-window count remains governed by the existing manager capacity.

## IP hop-limit statistics

`CoordinatedFlowState.ip_hop_limit_statistics` and `FlowObservationWindow.ip_hop_limit_statistics` expose frozen `DirectionalIPHopLimitStatistics`. Each direction contains an `IPHopLimitStatistics` with a sorted sparse `hop_limit_counts` tuple of `(value, count)` pairs. `packet_count`, `distinct_hop_limit_count`, `min_hop_limit`, `max_hop_limit`, `total_hop_limit`, `mean_hop_limit` and `zero_hop_limit_packet_count` derive from that single distribution. Empty extrema and mean are `None`; the populated mean is an exact `Fraction`. No redundant summary metadata can disagree with the distribution.

`update_directional_ip_hop_limit_statistics(current, analysis, identity)` consumes `IPv4Packet.ttl` or `IPv6Packet.hop_limit` for the existing admitted TCP/UDP flow domain. It requires exact public input/model types, validates the decoded IP version and eight-bit lifetime value, and delegates identity/direction checks to the existing flow contract. Packet lengths, options and payload validation remain owned by the decoders; the reducer does not access those fields or rerun model construction. It never reparses raw bytes or recalculates checksums. The field retains its entire 0–255 wire domain, including zero. Unknown upper-layer protocols, ICMP and non-initial fragments keep existing flow-admission behavior. Malformed/truncated packets and integrity failures remain owned by packet analysis/outcomes; the detection pipeline admits only successful analyses. Direct reducers consume the supplied decoded analysis just as other statistics do, without imposing a second checksum policy on the standalone observation session.

This records observed IPv4 TTL and IPv6 Hop Limit values, not inferred initial lifetimes or measured route lengths. A flow identity fixes its IP family; the two families are not mixed in one window. Directional distributions expose lifetime-field variation for traffic-profile comparison and later explicit detection/evaluation work. They infer no attack, operating system, endpoint role, routing change or severity. Reordering admitted observations changes neither the histogram nor its derived summaries; the manager's existing timestamp ordering still applies.

Bounds: one decoded eight-bit value per update, zero raw payload bytes examined or retained, at most 256 occupied bins per direction and 512 per flow. There is no parser, nesting or recursion. The existing packet layer bounds represented IPv4 total lengths and IPv6 payload lengths at 65,535 bytes; the reducer reads only decoded scalar metadata and endpoints. The sparse merge is linear in at most 256 bins, using one temporary list of at most 256 pairs and one resulting tuple of at most 256 pair references. No dictionary, set, packet history, source reference or predecessor aggregate is retained. Public construction rejects more than 256 bins before iteration, invalid types, values outside 0–255, nonpositive counts, duplicate values and unsorted values. Counter integers and derived rational arithmetic follow existing exact statistics conventions: collection cardinality is bounded, while integer magnitude grows with the observation count. Active-flow memory remains subject to the existing window-capacity limit; externally retained snapshots remain caller-owned.

The coordinator prepares the new aggregate with existing candidates and publishes it atomically. Failed preparation/publication does not count; a successful retry counts once. A repeated successful observation, including a TCP retransmission, counts as another packet observation. There is no additional deduplication or retry history. All closure reasons preserve the exact aggregate without reading packets again; replacement windows start empty. Frozen snapshots retain their previous values and expose this result through their existing coordinated-state property. The generic version-1 feature contract, numerical feature fields, ML projection, protocol-specific results and detector/evaluator behavior remain unchanged. Legacy positional construction leaves the appended aggregate empty rather than reconstructing missing history.
