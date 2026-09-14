from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from analysis.flow_identity import FlowIdentity, flow_identity_from_packet
from analysis.flow_state_coordinator import CoordinatedFlowState, FlowStateCoordinator
from analysis.packet_analysis import PacketAnalysis
from analysis.ldap_correlation import LDAPCorrelationState, finalize_ldap_correlation_state


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
    def __init__(self, capture_session_id: str, inactivity_timeout: timedelta) -> None:
        if type(capture_session_id) is not str:
            raise TypeError("capture_session_id must be exactly a string")
        if not capture_session_id.strip():
            raise FlowObservationWindowError("capture_session_id must not be blank")
        if type(inactivity_timeout) is not timedelta:
            raise TypeError("inactivity_timeout must be exactly a timedelta")
        if inactivity_timeout <= timedelta(0):
            raise FlowObservationWindowError("inactivity_timeout must be positive")
        self._capture_session_id = capture_session_id
        self._inactivity_timeout = inactivity_timeout
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
        self._active[identity] = (key, coordinator)
        self._next_sequence_number += 1
        self._latest_accepted_capture_time = analysis.observation.captured_at
        return update

    @staticmethod
    def _coordinated_state(coordinator: FlowStateCoordinator) -> CoordinatedFlowState:
        state = coordinator.state
        if type(state) is not CoordinatedFlowState:
            raise FlowObservationWindowError("active coordinator must have a published state")
        return state
