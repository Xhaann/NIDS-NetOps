# Packet capture boundary

This directory owns the packet observation and capture-source contracts, synchronous packet ingestion, local acquisition from caller-supplied byte records, and incremental classic PCAP file ingestion. Network-interface capture is not implemented.

## Packet observation contract

`capture` exports `PacketObservation`, `CaptureSource`, and `LinkType` from [packet_observation.py](packet_observation.py). These are typed, frozen dataclasses with value equality and construction-time validation, using only the Python standard library.

| Field | Type | Contract |
| --- | --- | --- |
| `captured_at` | `datetime` | Required exact built-in `datetime` with a fixed `datetime.timezone` and zero UTC offset. Naive timestamps, nonzero offsets, and custom timezone implementations are rejected. The supplied timestamp and microsecond precision are preserved; no clock reading or timezone conversion is performed. |
| `link_type` | `Optional[LinkType]` | Portable LINKTYPE code, or `None` when unavailable. |
| `captured_length` | `int` | Nonnegative byte count exactly equal to `len(raw_bytes)`. |
| `original_length` | `Optional[int]` | Original byte count before capture truncation, at least `captured_length`, or `None` when unavailable. |
| `raw_bytes` | `bytes` | Immutable packet data preserved exactly, without copying, padding, truncating, or decoding. Mutable buffers and other input types are rejected. Omitted from the generated representation. |
| `source` | `CaptureSource` | Required observation provenance, identified by a nonblank string. |

All constructor arguments are explicit, including `None` for unavailable metadata. Zero-length and truncated observations are valid. Wrong types raise `TypeError`; invalid values raise `ValueError`. Lengths and link codes reject booleans and numeric coercion.

`CaptureSource.identifier` is an opaque, case-sensitive identity assigned by the caller. The caller must keep it stable for the same source and distinct across sources used together. It is preserved without trimming and does not imply an interface name, file path, operating system, or capture implementation.

`LinkType.value` accepts integer codes from 0 through 65535 in the portable [LINKTYPE namespace](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcaplinktype-16.html). A value object preserves unrecognized codes without claiming decoding support. Future adapters must translate platform-specific identifiers into this namespace; numeric zero is a valid code, not a missing-value sentinel. This identifier convention does not select a capture library or storage format.

Everything except `raw_bytes` is capture observation metadata. No field represents decoded packet contents. Timestamps are required and never inferred; producers with higher timestamp precision must explicitly handle conversion to Python `datetime` before construction.

## Capture-source contract

`capture` exports `PacketSource` and `CaptureError` from [packet_source.py](packet_source.py). `PacketSource` is a structural `Protocol`: implementations provide the methods below without inheriting from it. It owns acquisition lifecycle and delivery of existing `PacketObservation` values. `CaptureSource` remains the observation's identity value, not an acquisition interface. The observation model does not depend on this protocol.

| Operation | Contract |
| --- | --- |
| `start() -> None` | Begin one acquisition session. Only one start attempt is allowed per instance; repeated starts raise `RuntimeError`. |
| `__iter__() -> Iterator[PacketObservation]` | Supply observations in acquisition order through a single-pass stream. Iterating again resumes the stream and never replays it. Iteration before start raises `RuntimeError`. |
| `stop() -> None` | Release acquisition resources and end delivery, including after partial startup, completion, failure, or early consumer exit. Safe before start and repeatable; a stopped instance cannot be restarted. Existing and subsequent iterators are exhausted after stop. |

Normal completion uses Python iterator exhaustion (`StopIteration`), including a source with zero observations. Exhaustion is permanent and does not mean a temporary lack of traffic. Acquisition failures during startup, iteration, or cleanup raise `CaptureError`; implementations must not disguise them as exhaustion, packet observations, or security findings. Backend exceptions should be chained as causes. A failed session must be stopped, not retried on the same instance. Incorrect lifecycle use raises `RuntimeError` and is distinct from acquisition failure.

Consumers must call `stop()` in a `finally` block whose `try` includes `start()`, so cleanup is attempted even when startup fails. Cleanup failures must remain visible; Python exception chaining retains an earlier failure when cleanup also raises. Iteration completion alone does not replace the consumer's cleanup responsibility.

Calls are synchronous and intended for one consumer making serialized calls. The contract does not specify threads, processes, asyncio, timeouts, or interruption of a blocking acquisition call. A protocol describes required behavior; it does not enforce lifecycle semantics at runtime. Deterministic implementations in the contract tests demonstrate these obligations without network access.

## Packet ingestion

`capture` exports `consume(source: PacketSource, consumer: Callable[[PacketObservation], None]) -> None` from [packet_ingestion.py](packet_ingestion.py). Each call executes one source session and delivers every observation directly to the supplied callback in source order. The exact existing objects are passed through without copying, mutation, filtering, or buffering. An empty or normally exhausted source returns `None`.

Ingestion owns the consumer-side lifecycle obligation above: `start()` and delivery run inside a `try` whose `finally` calls `stop()`. Cleanup is attempted after normal completion, startup failure, iteration failure, or a callback exception. Further delivery stops at the first failure.

Source `CaptureError` and lifecycle errors propagate unchanged. Callback exceptions retain their original type and are not classified as capture failures. If cleanup also raises, its exception propagates with the earlier failure retained through Python's normal exception context. No failure is logged, suppressed, or converted into a security finding.

The function depends only on the capture contracts and standard-library typing. Callers provide the source and callback; no analysis implementation is selected. The API adds no persistent state, concurrency, retries, or completion records. The application [capture execution boundary](../application/README.md#capture-execution) composes `consume()` with one analysis-outcome call per observation; capture sources and ingestion remain independent of analysis and detection.

## Iterable packet source

`capture` exports `IterablePacketSource(records: Iterable[bytes], *, source: CaptureSource = CaptureSource("local-iterable"), link_type: Optional[LinkType] = None)` from [iterable_packet_source.py](iterable_packet_source.py). It structurally implements `PacketSource` and works directly with `consume(source, consumer)`.

Each iterable item is one complete, already-delimited packet record. Only immutable `bytes` values are accepted, including empty records. Each record produces a distinct `PacketObservation` with the same bytes object and both lengths equal to `len(record)`. Binary contents are never decoded, split, filtered, or transformed. Repeated records produce separate observations.

The optional `link_type` describes the link-layer format of every complete record supplied by this source. The same immutable `LinkType` object is attached to each observation without inspecting or decoding the bytes. Generic records may omit it or supply `None`; the source never infers a type. Packet interpretation remains the responsibility of the separate analysis package. Invalid metadata types raise `TypeError` at source construction, including for empty input, before any acquisition. This configuration check uses the existing model's type rule; link-code validation remains owned by `LinkType`.

Capture time is read with `datetime.now(timezone.utc)` when each observation is created. Record order and contents are deterministic for a deterministic iterable; timestamps reflect observation creation time and are not replay timestamps. The default identity is `CaptureSource("local-iterable")`. Callers can supply an explicit identity to distinguish multiple local sources; the same identity object is retained for every observation in the session.

Construction retains the input without iterating it. `start()` obtains its iterator without reading a record. Iteration advances one record at a time and follows the single-session lifecycle above. Exhaustion is permanent, and further start attempts raise `RuntimeError`. After an acquisition or validation failure, further iteration raises `RuntimeError` until `stop()` ends the session. Stopping is repeatable, ends existing iterators, and releases the adapter's input references. The supplied iterable remains caller-owned: the adapter does not invoke optional `close()` methods or drain remaining records; callers remain responsible for any resources their iterable owns.

An `OSError` from obtaining or advancing the iterator becomes `CaptureError` with the original exception chained as its cause. Existing `CaptureError` and other exceptions propagate unchanged. Invalid record types raise `TypeError`, consistent with `PacketObservation`; the adapter stops delivery instead of skipping the record. This adapter adds no file format or packet-capture dependency.

## Classic PCAP packet source

`capture` exports `PcapPacketSource(path, *, source=CaptureSource("local-pcap"))` from [pcap_packet_source.py](pcap_packet_source.py). It accepts a filesystem path to a regular classic PCAP file and implements the existing single-session `PacketSource` contract. Construction performs no acquisition; `start()` opens the file read-only and validates its entire 24-byte global header before iteration. The caller can supply an explicit `CaptureSource` identity; the same object is retained by every observation. The path does not become an inferred source identity.

Startup checks the path's file type before opening, then checks the acquired descriptor before reading. Nonregular paths, including FIFOs and symlinks to FIFOs, raise `CaptureError` without opening them. Symlinks to regular files remain accepted. Where `os.O_NONBLOCK` is available, acquisition uses that flag so a regular path replaced by a FIFO between the checks does not wait for a writer; descriptor validation then rejects it. Metadata I/O failures retain their original causes. The existing cleanup obligation closes any acquired handle even when descriptor validation fails. This is a local file-acquisition guarantee, not a general filesystem timeout, immutable-file snapshot, or denial-of-service guarantee.

Supported inputs are classic PCAP version 2.4, in either byte order, with microsecond or nanosecond magic numbers. Format handling follows the [PCAP format description](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-06.html), an Internet-Draft. Historical timezone and significant-figures fields are decoded but ignored as reserved values, including nonzero values. Snaplen must be positive. The network field must fit the existing 16-bit portable `LinkType`; unknown codes remain unchanged. Nonzero upper bits, including additional FCS metadata, are explicitly unsupported rather than silently discarded. PCAPNG, modified/older PCAP variants, compressed captures, and live interfaces are not supported.

Each record has one 16-byte header followed by its exact captured bytes, without padding. Captured length must not exceed snaplen or original length, and the complete payload must exist within the file extent established at startup. Truncated headers and payloads, invalid fractional timestamps, and impossible lengths raise `CaptureError`; no record is repaired or skipped. Zero-byte records are valid and remain distinct from a zero-record capture. Original length is preserved separately, including capture truncation. Link type does not trigger Ethernet or other protocol decoding in the source.

Timestamp seconds are unsigned seconds since the UTC Unix epoch. Integer `timedelta` arithmetic produces the existing canonical `datetime.timezone.utc` representation without a wall-clock read or local timezone conversion. Microsecond values are exact. Nanosecond values are truncated toward the beginning of the microsecond using integer division by 1000; the remainder cannot be represented by the existing timestamp type. Fractions must be below 1,000,000 or 1,000,000,000 for their respective resolutions. All unsigned 32-bit seconds values are representable. Record order is preserved even when timestamps repeat or decrease; any downstream monotonicity rejection remains owned by flow observation.

The reader consumes only the current header and packet payload. Declared lengths are checked against the remaining file extent before payload allocation, and short reads still fail explicitly. Memory scales with one captured packet rather than the complete capture. The input must remain unchanged during execution; appended bytes beyond the startup extent are not part of that session. The reader does not write, sort, deduplicate, retain packet history, or reopen an exhausted file. Repeatable reads use fresh instances and the same stable source identity.

`consume()` starts and stops the source once, including on startup, record, analysis-callback, or downstream failure. Direct callers retain the same `try`/`finally` cleanup obligation. `stop()` closes the owned handle, releases parser references, and is safe before startup and on repeated calls. Iteration before successful startup or after failure raises `RuntimeError`; stopped/exhausted sources never replay records. I/O failures become `CaptureError` with their original causes; other exceptions propagate unchanged. Cleanup errors retain normal exception precedence. Valid records already delivered before later corruption remain in the caller's memory, but ingestion raises rather than reporting successful completion or returning a repaired capture.

The source works with unchanged `consume()`, flow observation, and the explicit detection pipeline. Packet analysis owns protocol interpretation; flow observation, feature extraction, and detection retain their existing ownership. No automatic detector execution, reassembly, live capture, correlation, evidence retention, or persistence is added.

## Future acquisition

Live interfaces and virtual-lab adapters are deferred. They will supply the same observation contract through `PacketSource`. Packet-loss reporting remains a future concern separate from acquisition exceptions and security findings.

Capture does not parse protocols, track flows, evaluate threats, or own evidence-file retention. The [application composition boundary](../application/README.md) uses `consume()` unchanged to connect one source run to analysis and observation-window lifecycle. Future consumers also include [storage](../storage/README.md); the capture contracts do not import those subsystems. Source permissions, filtering, buffering, and implementation-specific shutdown behavior must be specified before real capture is enabled.
