# Traffic analysis boundary

This directory implements Ethernet II, IPv4, TCP, UDP, and generic ICMPv4 decoding and checksum validation, IPv6 base-header, extension, fragmentation, ICMPv6, and structural TCP/UDP analysis, single-packet analysis and failure-preserving analysis outcomes, canonical IPv4/IPv6 identity values and TCP/UDP packet direction for both families, in-memory tracking, and explicit raw accumulation and feature boundaries. Raw accumulation includes global and directional volume, packet-size statistics, global and directional inter-arrival statistics, and directional TCP control observations. Implemented features cover volume and directional balance, packet sizes, duration, rates, and global and directional inter-arrival statistics. Each module's exact scope is documented below.

Additional link formats, fragment and stream reassembly, TCP connection state, and application parsing remain unimplemented. Observation-driven inactivity closure is implemented by `FlowObservationWindowManager`; there is no background expiration timer.

## Single-packet analysis

`analysis` exports `analyze_packet(observation: PacketObservation) -> PacketAnalysis`, `PacketAnalysis`, and `PacketAnalysisError` from [packet_analysis.py](packet_analysis.py). This synchronous operation analyzes exactly one captured observation without keeping state across packets. It requires Ethernet `LinkType(1)` and dispatches IPv4 EtherType `0x0800` or IPv6 EtherType `0x86DD`; unknown or other link types and unsupported EtherTypes raise `PacketAnalysisError(ValueError)`. Wrong input types raise `TypeError`.

On the IPv4 path, the operation delegates Ethernet and IPv4 decoding to the existing decoders, validates the option envelope, then explicitly validates the IPv4 checksum. It selects the existing TCP, UDP, or ICMPv4 decoder for IPv4 protocols 6, 17, or 1 respectively and validates the corresponding checksum when fragment offset is zero. Other IPv4 protocol numbers retain the Ethernet and IPv4 results without further decoding. Decoder failures propagate unchanged; no partial result is returned after a failure.

IPv4 packet analysis validates options only within the IHL-declared option area. End of Option List (0) requires zero padding; No Operation (1) occupies one byte. Other types retain opaque data and require an available length byte, a length of at least two, and an extent within the option area. Violations raise `IPv4DecodeError` and become `STRUCTURAL_FAILURE` outcomes without partial transport or flow admission. Capture truncation remains `INCOMPLETE`. The base `IPv4Packet` and `decode_ipv4()` representation contracts remain unchanged; neither interprets option-specific semantics.

TCP packet analysis validates the option envelope in both families after decoding the complete data-offset-declared header and before IPv4 TCP checksum validation. End of Option List (0) requires zero padding, No Operation (1) occupies one byte, and other kinds require a length byte of at least two with an extent inside the option area. Malformed envelopes raise `TCPDecodeError` and yield `STRUCTURAL_FAILURE` without partial analysis or flow admission; an unavailable declared TCP header remains `INCOMPLETE`. Option-specific bodies remain opaque. The base `TCPPacket` and `decode_tcp()` representation contracts are unchanged. IPv4 and TCP use the same bounded envelope validator without sharing protocol-specific interpretation.

`PacketAnalysis` is a frozen dataclass retaining the exact original `observation` and the exact decoder-produced model references in `ethernet`, `ipv4`, `tcp`, `udp`, `icmp`, and `ipv6`. The optional `ipv6`, `ipv6_extension_headers`, `ipv6_fragmentation`, `ipv6_icmpv6`, `ipv6_tcp`, and `ipv6_udp` fields are appended after the existing fields to preserve positional construction. The IPv6 path decodes the base header, validates the supported extension-header chain, and retains both results. When Fragment Headers are present, it also retains their packet-local semantic analysis. Terminal selectors 6 and 17 dispatch the existing TCP and UDP decoders at the validated boundary when no fragment offset is nonzero. Their results populate `ipv6_tcp` and `ipv6_udp`. A terminal selector of 58 dispatches the common ICMPv6 decoder when fragmentation permits a whole message within this packet. A supplied chain must retain the exact `ipv6` packet, and supplied fragmentation or ICMPv6 analysis must retain the exact extension-header chain. Direct construction rejects combining IPv6 with IPv4, the IPv4 `tcp`/`udp`/`icmp` fields, or checksum results. IPv6 TCP/UDP results require IPv6 and extension context, matching terminal protocol, exactly one upper-layer model, and initial-fragment semantics when Fragment Headers are present. Unused optional model fields are `None`. Its four optional boolean fields are `ipv4_checksum_valid`, `tcp_checksum_valid`, `udp_checksum_valid`, and `icmp_checksum_valid`. Direct construction checks model types and requires checksum results to be booleans or `None`.

A checksum result of `True` or `False` is preserved directly from its validator; `None` means not applicable or not performed. The IPv4 header checksum is always checked on successful IPv4 analysis, and a failed checksum does not stop subsequent structural decoding. UDP checksum zero retains `False` (integrity not validated), while a valid ICMP checksum of zero can retain `True`. No result is normalized or converted into an exception.

On the IPv4 path, transport/ICMP decoders are called before their checksum guards. The current decoders reject non-initial fragments, so those existing decode errors propagate and no transport/ICMP checksum validator runs. If a decoder returns a model for such a fragment, its checksum result remains `None`. Initial fragments with MF set may be checked subject to existing decoder requirements; checks cover only the represented bytes, without fragment reassembly.

This boundary contains orchestration only. It does not alter observations or packet bytes, perform stream reassembly, connection/flow tracking, application parsing, feature extraction, or detection, or assign threat verdicts, severity, or alerts. Capture remains responsible for acquisition. IPv6 Next Header values dispatch supported structural extension validation, then TCP, UDP, or the common ICMPv6 header at the appropriate safe terminal boundary. No detector runs on this path.

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

Continuation prepares coordinated state and validates the returned window/update before advancing the existing coordinator. If that construction fails, active state and the session frontier remain unchanged; later closure includes only previously admitted packets.

`close(identity)` emits an immutable window closed for `EXPLICIT_SEGMENTATION`, and a later packet with that identity creates a new window. `end_capture_session()` closes every active window for `CAPTURE_SESSION_END` in ascending sequence-number order, removes all active entries, and permanently rejects later recording. Repeated session end returns an empty tuple. `active_windows()` exposes freshly constructed immutable wrappers in sequence order without exposing coordinators or the active mapping. Closed windows are returned to callers and are not retained internally.

The manager retains a fixed coordinator, key, and mapping entry per active identity plus scalar session state, giving `O(A)` retained state for `A` active identities and `O(1)` state per window independent of packet count. It retains no packet, closed-window, feature, flag, or payload history. `FlowTracker` and `FlowFeatureInput` remain independent. The [application composition boundary](../application/README.md) connects source-session completion with lifecycle closure without moving capture ownership into analysis.

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

The current tracker owns only packet counts and first/latest packet references, with no session or TCP connection semantics. Future application analysis will consume explicit analysis boundaries. Existing feature extractors consume their documented aggregate models and do not independently parse traffic. Analysis does not assign threat verdicts or manage alerts. Additional protocol support, reassembly policies, and feature families remain future implementation decisions.


## Explicit feature contract version

`FeatureContractVersion(contract_id, contract_version)` is a frozen analysis value with two exact nonblank strings. The identity names a feature representation contract; the version names its explicitly declared revision. Wrong types raise `TypeError`; blank values raise `ValueError`. Caller-supplied references preserve whitespace, case, Unicode, and non-SemVer labels exactly. Equality compares both strings; there is no version ordering, normalization, coercion, generated identity, or automatic discovery.

`FlowFeatureSnapshot.feature_contract` is a read-only projection returning `FeatureContractVersion("flow-feature-snapshot", "1")`. These literals explicitly name the repository's current single snapshot contract. They are not inferred from packets, detector versions, Git, packages, or runtime state. The snapshot has one controlled extraction path, with no selectable implementation or caller-supplied contract field. Constructing a different standalone reference does not relabel a snapshot, select an extractor, establish compatibility, or migrate features.

Version `1` covers the existing seven snapshot fields in their existing order: `observation_window`, `flow_volume_features`, `packet_size_features`, `flow_duration_features`, `flow_rate_features`, `inter_arrival_features`, and `directional_inter_arrival_features`. It names their established typed composition, feature formulas and availability semantics, and window/coordinated-state projections; it does not duplicate an ordered schema or create a numerical feature vector. The snapshot retains its exact window and six feature-family values. TCP control remains raw coordinated statistics reachable through the window, not an added derived feature family. UDP retains absent TCP-control state.

The same contract applies to IPv4/IPv6 TCP/UDP and both active and closed snapshots. Active provenance does not make a window eligible for closed-flow detection. Zero duration keeps rates absent; no global intervals produce zero global inter-arrival values; unavailable directional groups remain `None`; observed zero intervals remain zero. All formulas, precision, optionality, lifecycle behavior, and field order remain unchanged.

The reference is static provenance, not an additional per-instance semantic field. Existing snapshot equality continues to compare its original fields. This implementation cannot produce two snapshots under independently selected contracts; supporting alternative snapshot contracts and deciding their compatibility would require a separate explicit change. Reference objects with different identities or versions compare differently, but no new snapshot matching or equality channel is introduced.

Detector versions identify detector implementations, detector configurations hold operational settings, and `DetectionConfiguration` composes system settings. None selects or implies a feature version. Findings retain their existing schema; flow-volume evidence retains the snapshot through which this reference can be inspected. TCP-control evidence continues to consume raw windows, and packet findings gain no flow-feature provenance. Evaluation identities, ground truth, datasets, benchmark artifacts, and experiments retain their existing semantics and associations without new fields or automatic integration.

Construction and inspection perform no capture, parsing, analysis, feature extraction, detection, evaluation, metrics, benchmarking, experiment execution, external access, timing, or randomness. Feature Contract Versioning supplies representation/provenance only: no registry, schema discovery, loading, migration, serialization, storage, reporting, performance measurement, or ML infrastructure is introduced.
