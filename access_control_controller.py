"""
SDN Access Control System - Ryu Controller
Project #11 | UE24CS252B Computer Networks
Dhanush S | PES1UG24AM360
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, icmp
from ryu.lib.packet import ether_types
import logging
import datetime


class AccessControlController(app_manager.RyuApp):
    """Ryu controller - allows only whitelisted hosts to communicate."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # only these IPs can communicate - h4 (10.0.0.4) is not listed = blocked
    WHITELIST = {
        '10.0.0.1',
        '10.0.0.2',
        '10.0.0.3',
    }

    def __init__(self, *args, **kwargs):
        super(AccessControlController, self).__init__(*args, **kwargs)

        # MAC learning table: { dpid: { mac_addr: port_number } }
        self.mac_to_port = {}

        # Counters for statistics / demo
        self.allowed_packets  = 0
        self.blocked_packets  = 0
        self.blocked_hosts    = set()   # track unique blocked IPs

        self.logger.setLevel(logging.INFO)
        self.logger.info("Access Control Controller started")
        self.logger.info("Whitelist: %s", self.WHITELIST)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install table-miss rule when switch connects."""
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        # Match ALL packets (empty match)
        match   = parser.OFPMatch()
        # Action: send to controller, no buffering on switch
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

        self.logger.info("[SWITCH] Switch DPID=%s connected. "
                         "Table-miss rule installed.", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle packets with no matching flow rule - apply access control."""
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        # Parse the incoming packet
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src
        dpid    = datapath.id
        ts      = datetime.datetime.now().strftime("%H:%M:%S")

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)

        # allow ARP through for host discovery
        if arp_pkt:
            src_ip = arp_pkt.src_ip
            if src_ip not in self.WHITELIST:
                self.logger.warning("[%s][ARP ] Unauthorized host %s ARP (allowed for discovery)", ts, src_ip)
            else:
                self.logger.info("[%s][ARP ] %s ARP request/reply", ts, src_ip)
            self._send_packet_out(datapath, msg, in_port, dst_mac, dpid)
            return

        # IPv4 - check whitelist
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            # --- UNAUTHORIZED: install DROP rule ---
            if src_ip not in self.WHITELIST:
                self.blocked_packets += 1
                self.blocked_hosts.add(src_ip)

                self.logger.warning(
                    "[%s][DROP] UNAUTHORIZED: %s --> %s  "
                    "| Total blocked pkts: %d  | Unique blocked hosts: %s",
                    ts, src_ip, dst_ip,
                    self.blocked_packets, self.blocked_hosts)

                # Install a drop rule so future packets don't hit controller
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip
                )
                self._drop_flow(datapath, priority=10, match=match, idle_timeout=30)
                return

            # --- AUTHORIZED: forward and install rule ---
            self.allowed_packets += 1
            self.logger.info(
                "[%s][FWRD] AUTHORIZED : %s --> %s  "
                "| Total allowed pkts: %d",
                ts, src_ip, dst_ip, self.allowed_packets)

            # If we know the destination port, install a precise rule
            if dst_mac in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst_mac]
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip
                )
                actions = [parser.OFPActionOutput(out_port)]
                self._add_flow(datapath, priority=5, match=match,
                               actions=actions, idle_timeout=20)

        # Forward packet (flood if dst unknown, direct if learned)
        self._send_packet_out(datapath, msg, in_port, dst_mac, dpid)

    # -----------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        """Push a forwarding flow rule to the switch."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        instructions = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(flow_mod)

    def _drop_flow(self, datapath, priority, match,
                   idle_timeout=30, hard_timeout=0):
        """Push a drop rule (empty action list = discard)."""
        parser = datapath.ofproto_parser

        instructions = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, [])]  # empty = drop

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(flow_mod)

    def _send_packet_out(self, datapath, msg, in_port, dst_mac, dpid):
        """Forward packet out - direct if MAC known, flood if not."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        out_port = (self.mac_to_port[dpid].get(dst_mac)
                    or ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        packet_out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(packet_out)
