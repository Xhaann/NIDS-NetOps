from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from analysis.flow_observation_window import DEFAULT_MAX_ACTIVE_WINDOWS

from detection.flow_volume_threshold import FlowVolumeThresholdConfiguration
from detection.packet_integrity import PacketIntegrityConfiguration
from detection.tcp_control_threshold import TCPControlThresholdConfiguration


@dataclass(frozen=True)
class DetectionConfiguration:
    packet_configuration: PacketIntegrityConfiguration
    flow_volume_configuration: FlowVolumeThresholdConfiguration
    inactivity_timeout: timedelta
    tcp_control_configuration: Optional[TCPControlThresholdConfiguration] = None
    max_active_windows: int = DEFAULT_MAX_ACTIVE_WINDOWS

    def __post_init__(self) -> None:
        if type(self.packet_configuration) is not PacketIntegrityConfiguration:
            raise TypeError("packet_configuration must be exactly a PacketIntegrityConfiguration")
        if type(self.flow_volume_configuration) is not FlowVolumeThresholdConfiguration:
            raise TypeError("flow_volume_configuration must be exactly a FlowVolumeThresholdConfiguration")
        if type(self.inactivity_timeout) is not timedelta:
            raise TypeError("inactivity_timeout must be exactly a timedelta")
        if self.inactivity_timeout <= timedelta(0):
            raise ValueError("inactivity_timeout must be positive")
        if type(self.max_active_windows) is not int:
            raise TypeError("max_active_windows must be exactly an integer")
        if self.max_active_windows < 1:
            raise ValueError("max_active_windows must be positive")
        if self.tcp_control_configuration is not None and type(
            self.tcp_control_configuration
        ) is not TCPControlThresholdConfiguration:
            raise TypeError("tcp_control_configuration must be exactly a TCPControlThresholdConfiguration or None")
