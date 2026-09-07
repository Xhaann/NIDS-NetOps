# Application composition

The `application` package composes implemented subsystem contracts without taking ownership of their internal state. It does not define packet acquisition, protocol decoding, flow identity, accumulation, feature extraction, detection, persistence, or user interfaces.

## Flow observation sessions

[flow_observation_session.py](flow_observation_session.py) exports `run_flow_observation_session(source, *, capture_session_id, inactivity_timeout, closed_window_consumer) -> None`. One invocation constructs one `FlowObservationWindowManager`, runs the source exactly once through `consume()`, analyzes each delivered `PacketObservation` with `analyze_packet()`, and passes the resulting `PacketAnalysis` unchanged to the manager.

The caller selects `capture_session_id` and owns its uniqueness outside the invocation. The function passes it unchanged to the manager and does not generate identifiers from time, flow identity, process state, or object identity.

Inactivity-closed windows are delivered synchronously in the order returned by `record()` before the source can produce the next observation. Active windows are not delivered. After `consume()` has attempted `source.stop()`, `end_capture_session()` closes the remaining active windows and those windows are delivered in the manager's returned order. Empty sessions produce no windows.

Delivery is ordered and at most once. A downstream failure is not retried, an attempted window is not re-emitted, and no further calls are made to a failed consumer. Remaining active windows are still finalized. The function retains no closed-window history or output queue. Synchronous delivery supplies backpressure by preventing the next source observation until the consumer returns.

Existing source, decoding, analysis, identity, coordination, lifecycle, and downstream exceptions propagate without translation. Source cleanup follows `consume()`: a `stop()` failure can supersede an active failure while retaining it as exception context. Lifecycle finalization is attempted after source cleanup even when source start, iteration, analysis, identity, coordination, lifecycle, or stop fails. A later finalization or final-delivery failure follows normal Python exception precedence.

TCP and UDP use the same path. TCP flags do not control lifecycle, UDP has no transaction inference, and TCP control state remains absent for UDP. ICMP packet analysis exists, but the current flow identity contract rejects ICMP and that error propagates. Skipping invalid or unsupported packets is **UNDEFINED POLICY**.

The application boundary continues to emit exact `FlowObservationWindow` objects and does not perform feature extraction. Downstream consumers may independently pass an emitted closed window to `extract_flow_feature_snapshot()`, which retains that exact window as provenance. Active windows are also valid provisional extraction inputs through the analysis API. Explicit segmentation during a running source, durable delivery, retries, rejected-packet routing, live capture, packet-loss accounting, ML vectorization, and serialization are not part of this layer.
