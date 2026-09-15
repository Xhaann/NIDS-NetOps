from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from analysis.dns_correlation import DNSCorrelationState, DNSCorrelationStatus, finalize_dns_correlation_state
from analysis.dns_transaction_statistics import DNSTransactionStatistics, update_dns_transaction_statistics
from analysis.dns_query_name_statistics import DNSQueryNameStatistics, update_dns_query_name_statistics
from analysis.dns_resource_record_statistics import DNSResourceRecordStatistics, update_dns_resource_record_statistics
from analysis.dns_message_flag_statistics import DNSMessageFlagStatistics, update_dns_message_flag_statistics
from analysis.dns_edns_statistics import DNSEDNSStatistics, update_dns_edns_statistics
from analysis.dns_stream_framing import DNSStreamState
from analysis.tls_record_framing import TLSRecordState
from analysis.tls_handshake_framing import TLSHandshakeState
from analysis.tls_handshake_statistics import DirectionalTLSHandshakeStatistics
from analysis.flow_identity import FlowIdentity, flow_identity_from_packet
from analysis.flow_state_coordinator import CoordinatedFlowState, FlowStateCoordinator
from analysis.packet_analysis import PacketAnalysis
from analysis.ldap_correlation import LDAPCorrelationState, finalize_ldap_correlation_state


DEFAULT_MAX_ACTIVE_WINDOWS = 1024


class FlowObservationWindowError(ValueError):
    pass


@dataclass(frozen=True)
class FlowObservationWindowKey:
    capture_session_id: str
    sequence_number: int

    def __post_init__(self) -> None:
        if type(self.capture_session_id) is not str:
            raise TypeError("capture_session_id must be exactly a string")
        if not self.capture_session_id.strip():
            raise FlowObservationWindowError("capture_session_id must not be blank")
        if type(self.sequence_number) is not int:
            raise TypeError("sequence_number must be exactly an integer")
        if self.sequence_number < 0:
            raise FlowObservationWindowError("sequence_number must not be negative")


class FlowObservationWindowClosureReason(Enum):
    INACTIVITY = "inactivity"
    CAPTURE_SESSION_END = "capture_session_end"
    EXPLICIT_SEGMENTATION = "explicit_segmentation"
    CAPACITY = "capacity"


@dataclass(frozen=True)
class FlowObservationWindow:
    key: FlowObservationWindowKey
    coordinated_state: CoordinatedFlowState
    closure_reason: Optional[FlowObservationWindowClosureReason]

    def __post_init__(self) -> None:
        if type(self.key) is not FlowObservationWindowKey:
            raise TypeError("key must be exactly a FlowObservationWindowKey")
        if type(self.coordinated_state) is not CoordinatedFlowState:
            raise TypeError("coordinated_state must be exactly a CoordinatedFlowState")
        if self.closure_reason is not None and type(
            self.closure_reason
        ) is not FlowObservationWindowClosureReason:
            raise TypeError(
                "closure_reason must be exactly a FlowObservationWindowClosureReason or None"
            )
        if self.coordinated_state.flow_statistics.packet_count < 1:
            raise FlowObservationWindowError(
                "coordinated_state must contain at least one accepted packet"
            )

        dns = self.coordinated_state.dns_correlation_state
        if dns is not None:
            if self.closure_reason is None and dns.finalized:
                raise FlowObservationWindowError("active windows require active DNS correlation")
            if self.closure_reason is not None and not dns.finalized:
                finalized = finalize_dns_correlation_state(dns)
                retained_count = sum(item.status is not DNSCorrelationStatus.PENDING for item in dns.observations)
                statistics = self.coordinated_state.dns_transaction_statistics
                names = self.coordinated_state.dns_query_name_statistics
                records = self.coordinated_state.dns_resource_record_statistics
                flags = self.coordinated_state.dns_message_flag_statistics
                edns = self.coordinated_state.dns_edns_statistics
                for observation in finalized.observations[retained_count:]:
                    statistics = update_dns_transaction_statistics(statistics, observation)
                    names = update_dns_query_name_statistics(names, observation)
                    records = update_dns_resource_record_statistics(records, observation)
                    flags = update_dns_message_flag_statistics(flags, observation)
                    edns = update_dns_edns_statistics(edns, observation)
                object.__setattr__(self, "coordinated_state", replace(
                    self.coordinated_state, dns_correlation_state=finalized,
                    dns_transaction_statistics=statistics,
                    dns_query_name_statistics=names,
                    dns_resource_record_statistics=records,
                    dns_message_flag_statistics=flags,
                    dns_edns_statistics=edns,
                ))

    @property
    def tls_handshake_statistics(self) -> DirectionalTLSHandshakeStatistics:
        return self.coordinated_state.tls_handshake_statistics

    @property
    def tls_handshake_state(self) -> Optional[TLSHandshakeState]:
        return self.coordinated_state.tls_handshake_state

    @property
    def tls_record_state(self) -> Optional[TLSRecordState]:
        return self.coordinated_state.tls_record_state

    @property
    def dns_stream_state(self) -> Optional[DNSStreamState]:
        return self.coordinated_state.dns_stream_state

    @property
    def dns_edns_statistics(self) -> DNSEDNSStatistics:
        return self.coordinated_state.dns_edns_statistics

    @property
    def dns_message_flag_statistics(self) -> DNSMessageFlagStatistics:
        return self.coordinated_state.dns_message_flag_statistics

    @property
    def dns_resource_record_statistics(self) -> DNSResourceRecordStatistics:
        return self.coordinated_state.dns_resource_record_statistics

    @property
    def dns_query_name_statistics(self) -> DNSQueryNameStatistics:
        return self.coordinated_state.dns_query_name_statistics

    @property
    def dns_transaction_statistics(self) -> DNSTransactionStatistics:
        return self.coordinated_state.dns_transaction_statistics

    @property
    def dns_correlation_state(self) -> Optional[DNSCorrelationState]:
        return self.coordinated_state.dns_correlation_state

    @property
    def identity(self) -> FlowIdentity:
        return self.coordinated_state.identity

    @property
    def ldap_correlation_state(self) -> Optional[LDAPCorrelationState]:
        state = self.coordinated_state.ldap_correlation_state
        if state is None or self.closure_reason is None:
            return state
        return finalize_ldap_correlation_state(state)

    @property
    def first_captured_at(self) -> datetime:
        return self.coordinated_state.flow_statistics.first_captured_at

    @property
    def last_captured_at(self) -> datetime:
        return self.coordinated_state.flow_statistics.last_captured_at


@dataclass(frozen=True)
class FlowObservationWindowUpdate:
    active_window: FlowObservationWindow
    closed_windows: tuple[FlowObservationWindow, ...]

    def __post_init__(self) -> None:
        if type(self.active_window) is not FlowObservationWindow:
            raise TypeError("active_window must be exactly a FlowObservationWindow")
        if self.active_window.closure_reason is not None:
            raise FlowObservationWindowError("active_window must be active")
        if type(self.closed_windows) is not tuple:
            raise TypeError("closed_windows must be exactly a tuple")
        keys = set()
        for window in self.closed_windows:
            if type(window) is not FlowObservationWindow:
                raise TypeError("closed_windows members must be exactly FlowObservationWindow values")
            if window.closure_reason is None:
                raise FlowObservationWindowError("closed_windows members must be closed")
            if window.key in keys or window.key == self.active_window.key:
                raise FlowObservationWindowError("window updates must not contain duplicate windows")
            keys.add(window.key)


class FlowObservationWindowManager:
    def __init__(
        self, capture_session_id: str, inactivity_timeout: timedelta,
        *, max_active_windows: int = DEFAULT_MAX_ACTIVE_WINDOWS,
    ) -> None:
        if type(capture_session_id) is not str:
            raise TypeError("capture_session_id must be exactly a string")
        if not capture_session_id.strip():
            raise FlowObservationWindowError("capture_session_id must not be blank")
        if type(inactivity_timeout) is not timedelta:
            raise TypeError("inactivity_timeout must be exactly a timedelta")
        if inactivity_timeout <= timedelta(0):
            raise FlowObservationWindowError("inactivity_timeout must be positive")
        if type(max_active_windows) is not int:
            raise TypeError("max_active_windows must be exactly an integer")
        if max_active_windows < 1:
            raise FlowObservationWindowError("max_active_windows must be positive")
        self._capture_session_id = capture_session_id
        self._inactivity_timeout = inactivity_timeout
        self._max_active_windows = max_active_windows
        self._next_sequence_number = 0
        self._active: dict[
            FlowIdentity, tuple[FlowObservationWindowKey, FlowStateCoordinator]
        ] = {}
        self._latest_accepted_capture_time: Optional[datetime] = None
        self._ended = False

    def record(self, analysis: PacketAnalysis) -> FlowObservationWindowUpdate:
        if self._ended:
            raise FlowObservationWindowError("capture session has ended")
        if type(analysis) is not PacketAnalysis:
            raise TypeError("analysis must be exactly a PacketAnalysis")
        identity = flow_identity_from_packet(analysis)
        captured_at = analysis.observation.captured_at
        if (
            self._latest_accepted_capture_time is not None
            and captured_at < self._latest_accepted_capture_time
        ):
            raise FlowObservationWindowError(
                "capture timestamp must not precede the latest accepted capture time"
            )
        existing = self._active.get(identity)
        if existing is None:
            if len(self._active) == self._max_active_windows:
                key, coordinator = min(
                    self._active.values(),
                    key=lambda value: (
                        self._coordinated_state(value[1]).flow_statistics.last_captured_at,
                        value[0].sequence_number,
                    ),
                )
                closed = FlowObservationWindow(
                    key, self._coordinated_state(coordinator),
                    FlowObservationWindowClosureReason.CAPACITY,
                )
                return self._record_new(identity, analysis, (closed,))
            return self._record_new(identity, analysis, ())
        key, coordinator = existing
        state = coordinator.state
        if type(state) is not CoordinatedFlowState:
            raise FlowObservationWindowError("active coordinator must have a published state")
        delta = captured_at - state.flow_statistics.last_captured_at
        if delta >= self._inactivity_timeout:
            closed = FlowObservationWindow(
                key,
                state,
                FlowObservationWindowClosureReason.INACTIVITY,
            )
            return self._record_new(identity, analysis, (closed,))
        updated_state = coordinator._prepare_record(analysis)
        active = FlowObservationWindow(key, updated_state, None)
        update = FlowObservationWindowUpdate(active, ())
        coordinator._commit_record(updated_state)
        self._latest_accepted_capture_time = captured_at
        return update

    def close(self, identity: FlowIdentity) -> FlowObservationWindow:
        if self._ended:
            raise FlowObservationWindowError("capture session has ended")
        if type(identity) is not FlowIdentity:
            raise TypeError("identity must be exactly a FlowIdentity")
        existing = self._active.get(identity)
        if existing is None:
            raise FlowObservationWindowError("identity has no active observation window")
        key, coordinator = existing
        state = coordinator.state
        if type(state) is not CoordinatedFlowState:
            raise FlowObservationWindowError("active coordinator must have a published state")
        closed = FlowObservationWindow(
            key,
            state,
            FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION,
        )
        del self._active[identity]
        return closed

    def end_capture_session(self) -> tuple[FlowObservationWindow, ...]:
        if self._ended:
            return ()
        closed = tuple(
            FlowObservationWindow(
                key,
                self._coordinated_state(coordinator),
                FlowObservationWindowClosureReason.CAPTURE_SESSION_END,
            )
            for key, coordinator in sorted(
                self._active.values(), key=lambda value: value[0].sequence_number
            )
        )
        self._active = {}
        self._ended = True
        return closed

    def active_windows(self) -> tuple[FlowObservationWindow, ...]:
        return tuple(
            FlowObservationWindow(key, self._coordinated_state(coordinator), None)
            for key, coordinator in sorted(
                self._active.values(), key=lambda value: value[0].sequence_number
            )
        )

    def _record_new(
        self,
        identity: FlowIdentity,
        analysis: PacketAnalysis,
        closed_windows: tuple[FlowObservationWindow, ...],
    ) -> FlowObservationWindowUpdate:
        coordinator = FlowStateCoordinator()
        state = coordinator.record(analysis)
        key = FlowObservationWindowKey(
            self._capture_session_id,
            self._next_sequence_number,
        )
        active_window = FlowObservationWindow(key, state, None)
        update = FlowObservationWindowUpdate(active_window, closed_windows)
        next_sequence_number = self._next_sequence_number + 1
        if closed_windows and closed_windows[0].closure_reason is FlowObservationWindowClosureReason.CAPACITY:
            active = self._active.copy()
            del active[closed_windows[0].identity]
            active[identity] = (key, coordinator)
            self._active = active
        else:
            self._active[identity] = (key, coordinator)
        self._next_sequence_number = next_sequence_number
        self._latest_accepted_capture_time = analysis.observation.captured_at
        return update

    @staticmethod
    def _coordinated_state(coordinator: FlowStateCoordinator) -> CoordinatedFlowState:
        state = coordinator.state
        if type(state) is not CoordinatedFlowState:
            raise FlowObservationWindowError("active coordinator must have a published state")
        return state
