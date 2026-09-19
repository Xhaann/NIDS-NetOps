from dataclasses import dataclass
from typing import Optional

from analysis.directional_flow_statistics import DirectionalFlowStatistics, update_directional_flow_statistics
from analysis.directional_inter_arrival_statistics import (
    DirectionalInterArrivalStatistics,
    update_directional_inter_arrival_statistics,
)
from analysis.dns_correlation import DNSCorrelationState, DNSCorrelationStatus, update_dns_correlation_state
from analysis.dns_transaction_statistics import DNSTransactionStatistics, update_dns_transaction_statistics
from analysis.dns_query_name_statistics import DNSQueryNameStatistics, update_dns_query_name_statistics
from analysis.dns_resource_record_statistics import DNSResourceRecordStatistics, update_dns_resource_record_statistics
from analysis.dns_message_flag_statistics import DNSMessageFlagStatistics, update_dns_message_flag_statistics
from analysis.dns_edns_statistics import DNSEDNSStatistics, update_dns_edns_statistics
from analysis.dns import analyze_dns_message
from analysis.dns_stream_framing import DNSStreamState, update_dns_stream_state
from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity, flow_identity_from_packet
from analysis.flow_inter_arrival_statistics import FlowInterArrivalStatistics, update_flow_inter_arrival_statistics
from analysis.flow_packet_size_statistics import FlowPacketSizeStatistics, update_flow_packet_size_statistics
from analysis.flow_statistics import FlowStatistics, update_flow_statistics
from analysis.ldap_flow_statistics import LDAPFlowStatistics, update_ldap_flow_statistics
from analysis.ldap_correlation import LDAPCorrelationState, update_ldap_correlation_state
from analysis.ldap_stream_framing import LDAPStreamState, update_ldap_stream_state
from analysis.packet_analysis import PacketAnalysis
from analysis.tcp_stream_observation import TCPStreamState, update_tcp_stream_state
from analysis.tls_client_hello import TLSClientHelloObservation, TLSClientHelloStatus, analyze_tls_client_hello
from analysis.tls_client_hello_statistics import (
    DirectionalTLSClientHelloStatistics,
    update_directional_tls_client_hello_statistics,
)
from analysis.tls_server_hello import TLSServerHelloObservation, TLSServerHelloStatus, analyze_tls_server_hello
from analysis.tls_server_hello_statistics import (
    DirectionalTLSServerHelloStatistics,
    update_directional_tls_server_hello_statistics,
)
from analysis.tls_handshake_statistics import DirectionalTLSHandshakeStatistics, update_directional_tls_handshake_statistics
from analysis.tls_handshake_framing import TLSHandshakeState, update_tls_handshake_state
from analysis.tls_record_framing import TLSRecordState, update_tls_record_state
from analysis.tcp_control_statistics import TCPControlStatistics, update_tcp_control_statistics


class FlowCoordinationError(ValueError):
    pass


@dataclass(frozen=True)
class CoordinatedFlowState:
    flow_statistics: FlowStatistics
    directional_flow_statistics: DirectionalFlowStatistics
    flow_packet_size_statistics: FlowPacketSizeStatistics
    flow_inter_arrival_statistics: FlowInterArrivalStatistics
    directional_inter_arrival_statistics: DirectionalInterArrivalStatistics
    tcp_control_statistics: Optional[TCPControlStatistics]
    ldap_statistics: Optional[LDAPFlowStatistics] = None
    tcp_stream_state: Optional[TCPStreamState] = None
    ldap_stream_state: Optional[LDAPStreamState] = None
    ldap_correlation_state: Optional[LDAPCorrelationState] = None
    dns_correlation_state: Optional[DNSCorrelationState] = None
    dns_transaction_statistics: DNSTransactionStatistics = DNSTransactionStatistics()
    dns_query_name_statistics: DNSQueryNameStatistics = DNSQueryNameStatistics()
    dns_resource_record_statistics: DNSResourceRecordStatistics = DNSResourceRecordStatistics()
    dns_message_flag_statistics: DNSMessageFlagStatistics = DNSMessageFlagStatistics()
    dns_edns_statistics: DNSEDNSStatistics = DNSEDNSStatistics()
    dns_stream_state: Optional[DNSStreamState] = None
    tls_record_state: Optional[TLSRecordState] = None
    tls_handshake_state: Optional[TLSHandshakeState] = None
    tls_handshake_statistics: DirectionalTLSHandshakeStatistics = DirectionalTLSHandshakeStatistics()
    tls_client_hellos: tuple[TLSClientHelloObservation, ...] = ()
    tls_client_hello_statistics: DirectionalTLSClientHelloStatistics = DirectionalTLSClientHelloStatistics()
    tls_server_hellos: tuple[TLSServerHelloObservation, ...] = ()
    tls_server_hello_statistics: DirectionalTLSServerHelloStatistics = DirectionalTLSServerHelloStatistics()

    def __post_init__(self) -> None:
        for name, value, expected in (
            ("flow_statistics", self.flow_statistics, FlowStatistics),
            ("directional_flow_statistics", self.directional_flow_statistics, DirectionalFlowStatistics),
            ("flow_packet_size_statistics", self.flow_packet_size_statistics, FlowPacketSizeStatistics),
            ("flow_inter_arrival_statistics", self.flow_inter_arrival_statistics, FlowInterArrivalStatistics),
            ("directional_inter_arrival_statistics", self.directional_inter_arrival_statistics,
             DirectionalInterArrivalStatistics),
        ):
            if type(value) is not expected:
                raise TypeError(f"{name} must be exactly a {expected.__name__}")
        if type(self.dns_transaction_statistics) is not DNSTransactionStatistics:
            raise TypeError("dns_transaction_statistics must be exactly a DNSTransactionStatistics")
        if type(self.dns_query_name_statistics) is not DNSQueryNameStatistics:
            raise TypeError("dns_query_name_statistics must be exactly a DNSQueryNameStatistics")
        if type(self.dns_resource_record_statistics) is not DNSResourceRecordStatistics:
            raise TypeError("dns_resource_record_statistics must be exactly a DNSResourceRecordStatistics")
        if type(self.dns_message_flag_statistics) is not DNSMessageFlagStatistics:
            raise TypeError("dns_message_flag_statistics must be exactly a DNSMessageFlagStatistics")
        if type(self.dns_edns_statistics) is not DNSEDNSStatistics:
            raise TypeError("dns_edns_statistics must be exactly a DNSEDNSStatistics")
        if type(self.tls_handshake_statistics) is not DirectionalTLSHandshakeStatistics:
            raise TypeError("tls_handshake_statistics must be exactly a DirectionalTLSHandshakeStatistics")
        if type(self.tls_client_hello_statistics) is not DirectionalTLSClientHelloStatistics:
            raise TypeError("tls_client_hello_statistics must be exactly a DirectionalTLSClientHelloStatistics")
        if type(self.tls_server_hello_statistics) is not DirectionalTLSServerHelloStatistics:
            raise TypeError("tls_server_hello_statistics must be exactly a DirectionalTLSServerHelloStatistics")
        if type(self.tls_server_hellos) is not tuple:
            raise TypeError("tls_server_hellos must be exactly a tuple")
        if type(self.tls_client_hellos) is not tuple:
            raise TypeError("tls_client_hellos must be exactly a tuple")
        for hello in self.tls_client_hellos:
            if type(hello) is not TLSClientHelloObservation:
                raise TypeError("tls_client_hellos must contain exact TLSClientHelloObservation values")
            if self.tls_handshake_state is None or hello.identity != self.identity:
                raise FlowCoordinationError("ClientHello observations must belong to the TLS handshake flow")
        for hello in self.tls_server_hellos:
            if type(hello) is not TLSServerHelloObservation:
                raise TypeError("tls_server_hellos must contain exact TLSServerHelloObservation values")
            if self.tls_handshake_state is None or hello.identity != self.identity:
                raise FlowCoordinationError("ServerHello observations must belong to the TLS handshake flow")
        dns = self.dns_correlation_state
        if dns is not None:
            if type(dns) is not DNSCorrelationState:
                raise TypeError("dns_correlation_state must be exactly a DNSCorrelationState or None")
            if dns.identity != self.identity or (self.identity.protocol != 17 and self.dns_stream_state is None):
                raise FlowCoordinationError("DNS correlation must belong to the UDP or framed TCP flow")
            if dns.last_captured_at != self.flow_statistics.last_captured_at:
                raise FlowCoordinationError("DNS correlation timestamp must match the flow")
        framing = self.ldap_stream_state
        if framing is not None:
            if type(framing) is not LDAPStreamState:
                raise TypeError("ldap_stream_state must be exactly an LDAPStreamState or None")
            if framing.tcp_stream_state is not self.tcp_stream_state:
                raise FlowCoordinationError("LDAP framing must retain the exact TCP stream state")
        dns_framing = self.dns_stream_state
        if dns_framing is not None:
            if type(dns_framing) is not DNSStreamState:
                raise TypeError("dns_stream_state must be exactly a DNSStreamState or None")
            if dns_framing.tcp_stream_state is not self.tcp_stream_state or framing is not None:
                raise FlowCoordinationError("DNS framing requires exclusive ownership of the exact TCP stream state")
        correlation = self.ldap_correlation_state
        if correlation is not None:
            if type(correlation) is not LDAPCorrelationState:
                raise TypeError("ldap_correlation_state must be exactly an LDAPCorrelationState or None")
            if correlation.framing is not framing or correlation.finalized:
                raise FlowCoordinationError("active correlation must retain the exact LDAP framing state")
        streams = self.tcp_stream_state
        if streams is not None:
            if type(streams) is not TCPStreamState:
                raise TypeError("tcp_stream_state must be exactly a TCPStreamState or None")
            if streams.identity != self.identity:
                raise FlowCoordinationError("TCP stream identity must match")
        tls = self.tls_record_state
        if tls is not None:
            if type(tls) is not TLSRecordState:
                raise TypeError("tls_record_state must be exactly a TLSRecordState or None")
            if tls.tcp_stream_state is not self.tcp_stream_state or framing is not None or dns_framing is not None:
                raise FlowCoordinationError("TLS framing requires exclusive ownership of the exact TCP stream state")
        handshake = self.tls_handshake_state
        if handshake is not None:
            if type(handshake) is not TLSHandshakeState:
                raise TypeError("tls_handshake_state must be exactly a TLSHandshakeState or None")
            if handshake.tls_record_state is not tls:
                raise FlowCoordinationError("handshake framing must retain the exact TLS record state")
        ldap = self.ldap_statistics
        if ldap is not None:
            if type(ldap) is not LDAPFlowStatistics:
                raise TypeError("ldap_statistics must be exactly an LDAPFlowStatistics or None")
            if ldap.identity != self.identity:
                raise FlowCoordinationError("LDAP statistics identity must match")
        tcp_control = self.tcp_control_statistics
        if tcp_control is not None and type(tcp_control) is not TCPControlStatistics:
            raise TypeError("tcp_control_statistics must be exactly a TCPControlStatistics or None")
        if self.identity.protocol == 6 and tcp_control is None:
            raise FlowCoordinationError("TCP coordinated state requires TCP control statistics")
        if self.identity.protocol == 17 and tcp_control is not None:
            raise FlowCoordinationError("UDP coordinated state requires absent TCP control statistics")
        if tcp_control is not None and tcp_control.identity.protocol != 6:
            raise FlowCoordinationError("TCP control statistics must represent TCP protocol 6")
        for value in (
            self.directional_flow_statistics,
            self.flow_packet_size_statistics,
            self.flow_inter_arrival_statistics,
            self.directional_inter_arrival_statistics,
        ):
            if value.identity != self.identity:
                raise FlowCoordinationError("all accumulator identities must match")
        if tcp_control is not None and tcp_control.identity != self.identity:
            raise FlowCoordinationError("TCP control statistics identity must match")
        packet_count = self.flow_statistics.packet_count
        if any(value.packet_count != packet_count for value in (
            self.flow_packet_size_statistics,
            self.flow_inter_arrival_statistics,
            self.directional_inter_arrival_statistics,
        )):
            raise FlowCoordinationError("all accumulator packet counts must match")
        if tcp_control is not None and tcp_control.packet_count != packet_count:
            raise FlowCoordinationError("TCP control packet count must match")
        directional = self.directional_flow_statistics
        packet_sizes = self.flow_packet_size_statistics
        directional_intervals = self.directional_inter_arrival_statistics
        if directional.forward_packet_count + directional.reverse_packet_count != packet_count:
            raise FlowCoordinationError("directional packet counts must sum to packet_count")
        for direction in ("forward", "reverse"):
            directional_packet_count = getattr(directional, f"{direction}_packet_count")
            if getattr(packet_sizes, f"{direction}_packet_count") != directional_packet_count:
                raise FlowCoordinationError("packet-size directional counts must match directional flow counts")
            if tcp_control is not None and getattr(
                tcp_control, f"{direction}_packet_count"
            ) != directional_packet_count:
                raise FlowCoordinationError("TCP control directional counts must match directional flow counts")
            interval_count = getattr(directional_intervals, f"{direction}_inter_arrival_count")
            observed = int(getattr(directional_intervals, f"last_{direction}_captured_at") is not None)
            if interval_count + observed != directional_packet_count:
                raise FlowCoordinationError("directional interval counts must match directional packet counts")
        for length in ("captured", "original"):
            total_name = f"{length}_bytes"
            total = getattr(self.flow_statistics, total_name)
            if getattr(packet_sizes, total_name) != total:
                raise FlowCoordinationError(f"global {length}-byte totals must match")
            directional_total = (
                getattr(directional, f"forward_{length}_bytes")
                + getattr(directional, f"reverse_{length}_bytes")
            )
            if directional_total != total:
                raise FlowCoordinationError(f"directional {length}-byte totals must sum to the global total")
            for direction in ("forward", "reverse"):
                if getattr(packet_sizes, f"{direction}_{length}_bytes") != getattr(
                    directional, f"{direction}_{length}_bytes",
                ):
                    raise FlowCoordinationError(
                        f"packet-size {direction} {length}-byte totals must match directional flow totals"
                    )
        for name in ("first_captured_at", "last_captured_at"):
            timestamp = getattr(self.flow_statistics, name)
            if any(getattr(value, name) != timestamp for value in (
                self.flow_inter_arrival_statistics,
                directional_intervals,
            )):
                raise FlowCoordinationError(f"all accumulator {name} values must match")

    @property
    def identity(self) -> FlowIdentity:
        return self.flow_statistics.identity


class FlowStateCoordinator:
    def __init__(self) -> None:
        self._state: Optional[CoordinatedFlowState] = None

    @property
    def state(self) -> Optional[CoordinatedFlowState]:
        return self._state

    def record(self, analysis: PacketAnalysis) -> CoordinatedFlowState:
        candidate = self._prepare_record(analysis)
        self._commit_record(candidate)
        return candidate

    def _prepare_record(self, analysis: PacketAnalysis) -> CoordinatedFlowState:
        if type(analysis) is not PacketAnalysis:
            raise TypeError("analysis must be exactly a PacketAnalysis")
        derived_identity = flow_identity_from_packet(analysis)
        current = self._state
        if current is not None and current.identity != derived_identity:
            raise FlowCoordinationError("analysis must belong to the coordinator's flow")
        identity = derived_identity if current is None else current.identity
        values = dict(
            flow_statistics=update_flow_statistics(
                None if current is None else current.flow_statistics, analysis, identity,
            ),
            directional_flow_statistics=update_directional_flow_statistics(
                None if current is None else current.directional_flow_statistics, analysis, identity,
            ),
            flow_packet_size_statistics=update_flow_packet_size_statistics(
                None if current is None else current.flow_packet_size_statistics, analysis, identity,
            ),
            flow_inter_arrival_statistics=update_flow_inter_arrival_statistics(
                None if current is None else current.flow_inter_arrival_statistics, analysis, identity,
            ),
            directional_inter_arrival_statistics=update_directional_inter_arrival_statistics(
                None if current is None else current.directional_inter_arrival_statistics, analysis, identity,
            ),
            tcp_control_statistics=update_tcp_control_statistics(
                None if current is None else current.tcp_control_statistics, analysis, identity,
            ) if identity.protocol == 6 else None,
            ldap_statistics=update_ldap_flow_statistics(
                None if current is None else current.ldap_statistics, analysis, identity,
            ) if identity.protocol == 6 else None,
            tcp_stream_state=update_tcp_stream_state(
                None if current is None else current.tcp_stream_state, analysis, identity,
            ) if identity.protocol == 6 else None,
        )

        streams = values["tcp_stream_state"]
        framing = None if streams is None else update_ldap_stream_state(
            None if current is None else current.ldap_stream_state, streams,
        )
        if framing is not None:
            values["tcp_stream_state"] = framing.tcp_stream_state
        correlation = None if framing is None else update_ldap_correlation_state(
            None if current is None else current.ldap_correlation_state, framing,
        )
        dns_update = None if streams is None else update_dns_stream_state(
            None if current is None else current.dns_stream_state, streams,
        )
        if dns_update is not None:
            values["tcp_stream_state"] = dns_update.state.tcp_stream_state
        tls_update = None if streams is None else update_tls_record_state(
            None if current is None else current.tls_record_state, streams,
        )
        if tls_update is not None:
            values["tcp_stream_state"] = tls_update.state.tcp_stream_state
        handshake_update = None if tls_update is None else update_tls_handshake_state(
            None if current is None else current.tls_handshake_state, tls_update,
        )
        handshake_statistics = DirectionalTLSHandshakeStatistics() if current is None else current.tls_handshake_statistics
        client_hello_statistics = (
            DirectionalTLSClientHelloStatistics() if current is None else current.tls_client_hello_statistics
        )
        server_hello_statistics = (
            DirectionalTLSServerHelloStatistics() if current is None else current.tls_server_hello_statistics
        )
        client_hellos = []
        server_hellos = []
        if handshake_update is not None:
            for observation in handshake_update.forward_messages + handshake_update.reverse_messages:
                handshake_statistics = update_directional_tls_handshake_statistics(handshake_statistics, observation)
                if observation.header.handshake_type == 1:
                    client_hello = analyze_tls_client_hello(observation)
                    client_hellos.append(client_hello)
                    if client_hello.status is TLSClientHelloStatus.COMPLETE:
                        client_hello_statistics = update_directional_tls_client_hello_statistics(
                            client_hello_statistics, client_hello,
                        )
                elif observation.header.handshake_type == 2:
                    server_hello = analyze_tls_server_hello(observation)
                    server_hellos.append(server_hello)
                    if server_hello.status is TLSServerHelloStatus.COMPLETE:
                        server_hello_statistics = update_directional_tls_server_hello_statistics(
                            server_hello_statistics, server_hello,
                        )
        direction = flow_direction_from_packet(analysis, identity)
        if identity.protocol == 17:
            messages = ((direction, analysis.dns),)
        elif dns_update is not None and (dns_update.forward_frames or dns_update.reverse_frames):
            messages = ((frame_direction, analyze_dns_message(payload))
                        for frame_direction, frames in ((FlowDirection.FORWARD, dns_update.forward_frames),
                                                        (FlowDirection.REVERSE, dns_update.reverse_frames))
                        for payload in frames)
        else:
            messages = () if dns_update is None else ((direction, None),)
        dns = None if current is None else current.dns_correlation_state
        dns_statistics = DNSTransactionStatistics() if current is None else current.dns_transaction_statistics
        dns_names = DNSQueryNameStatistics() if current is None else current.dns_query_name_statistics
        dns_records = DNSResourceRecordStatistics() if current is None else current.dns_resource_record_statistics
        dns_flags = DNSMessageFlagStatistics() if current is None else current.dns_message_flag_statistics
        dns_edns = DNSEDNSStatistics() if current is None else current.dns_edns_statistics
        for message_direction, message in messages:
            dns = update_dns_correlation_state(dns, message, identity, message_direction, analysis.observation.captured_at)
            if dns is None:
                continue
            for observation in dns.observations:
                if observation.status is not DNSCorrelationStatus.PENDING:
                    dns_statistics = update_dns_transaction_statistics(dns_statistics, observation)
                    dns_names = update_dns_query_name_statistics(dns_names, observation)
                    dns_records = update_dns_resource_record_statistics(dns_records, observation)
                    dns_flags = update_dns_message_flag_statistics(dns_flags, observation)
                    dns_edns = update_dns_edns_statistics(dns_edns, observation)
        return CoordinatedFlowState(**values, ldap_stream_state=framing,
                                    ldap_correlation_state=correlation, dns_correlation_state=dns,
                                    dns_transaction_statistics=dns_statistics, dns_query_name_statistics=dns_names,
                                    dns_resource_record_statistics=dns_records, dns_message_flag_statistics=dns_flags,
                                    dns_edns_statistics=dns_edns,
                                    dns_stream_state=None if dns_update is None else dns_update.state,
                                    tls_record_state=None if tls_update is None else tls_update.state,
                                    tls_handshake_state=None if handshake_update is None else handshake_update.state,
                                    tls_handshake_statistics=handshake_statistics,
                                    tls_client_hello_statistics=client_hello_statistics,
                                    tls_client_hellos=tuple(client_hellos),
                                    tls_server_hellos=tuple(server_hellos),
                                    tls_server_hello_statistics=server_hello_statistics)

    def _commit_record(self, state: CoordinatedFlowState) -> None:
        self._state = state
