from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
import json


class ThreePath33_33_33(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ThreePath33_33_33, self).__init__(*args, **kwargs)
        self.arp_table = {}
        self.arp_table["10.0.0.1"] = "00:00:00:00:00:01"
        self.arp_table["10.0.0.2"] = "00:00:00:00:00:02"

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 0, match, inst, 0)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth_pkt.ethertype
        eth_dst = eth_pkt.dst
        eth_src = eth_pkt.src
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        in_port = msg.match['in_port']

        if (ethertype == ether.ETH_TYPE_ARP):
            self.handle_arp(datapath, in_port, pkt)

        if (ethertype == ether.ETH_TYPE_IP):
            self.handle_ip(datapath, in_port, pkt, dpid)

    def core_switch(self, datapath, ipv4_dst, proto, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ipv4_dst, ip_proto=proto)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 10, match, inst, 0)

    def add_flow(self, datapath, priority, match, inst, table):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        buffer_id = ofproto.OFP_NO_BUFFER
        mod = parser.OFPFlowMod(
            datapath=datapath, table_id=table, priority=priority,
            match=match, instructions=inst
        )
        datapath.send_msg(mod)

    def send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        action = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=action, data=data)
        datapath.send_msg(out)

    def handle_arp(self, datapath, port, pkt):
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)

        if (pkt_arp.opcode != arp.ARP_REQUEST) or (self.arp_table.get(pkt_arp.dst_ip) == None):
            return

        get_mac = self.arp_table[pkt_arp.dst_ip]
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether.ETH_TYPE_ARP,
            dst=pkt_ethernet.src,
            src=get_mac))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=get_mac,
            src_ip=pkt_arp.dst_ip,
            dst_mac=pkt_arp.src_mac,
            dst_ip=pkt_arp.src_ip))
        self.send_packet(datapath, port, pkt)

    # distribute flows based on remainder of  number divided by 3.
    # remainder=0, goes to switch1
    # remainder=1, goes to switch2
    # remainder=2, goes to switch3
    def handle_ip(self, datapath, port, pkt, dpid):
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        flag = 2;

        # The flag is used to switch between the two ports so that both switch 1,2  and 3 can be effectively utilized as per ecmp.
        # Initially the value of flag is 2 which corresponds to port 2.
        # We alternate between ports 2 and 3 to route traffic to switch 1 and 2.
        if (dpid == 4 or dpid == 5) and ipv4_pkt.proto == 6:
            if flag == 2:
                flag = 3
            elif flag == 3:
                flag = 4
            else:
                flag = 2

        if (dpid == 1):
            self.core_switch(datapath, '10.0.0.1', inet.IPPROTO_TCP, 1 )
            self.core_switch(datapath, '10.0.0.2', inet.IPPROTO_TCP, 2 )

        if (dpid == 2):
            self.core_switch(datapath, '10.0.0.1', inet.IPPROTO_TCP, 1 )
            self.core_switch(datapath, '10.0.0.2', inet.IPPROTO_TCP, 2 )

        if (dpid == 3):
            self.core_switch(datapath, '10.0.0.1', inet.IPPROTO_TCP, 1 )
            self.core_switch(datapath, '10.0.0.2', inet.IPPROTO_TCP, 2 )

        if (flag == 2):
            if (dpid == 4):
                self.core_switch(datapath, '10.0.0.1', inet.IPPROTO_TCP, 1 )
                self.core_switch(datapath, '10.0.0.2', inet.IPPROTO_TCP, 2 )
            if (dpid == 5):
                self.core_switch(datapath, '10.0.0.1', inet.IPPROTO_TCP, 2 )
                self.core_switch(datapath, '10.0.0.2', inet.IPPROTO_TCP, 1 )

        if (flag == 3):
            if (dpid == 4):
                self.core_switch(datapath, '10.0.0.1', inet.IPPROTO_TCP, 1 )
                self.core_switch(datapath, '10.0.0.2', inet.IPPROTO_TCP, 3 )
            if (dpid == 5):
                self.core_switch(datapath, '10.0.0.1', inet.IPPROTO_TCP, 3 )
                self.core_switch(datapath, '10.0.0.2', inet.IPPROTO_TCP, 1 )

        if (flag == 4):
            if (dpid == 4):
                self.core_switch(datapath, '10.0.0.1', inet.IPPROTO_TCP, 1 )
                self.core_switch(datapath, '10.0.0.2', inet.IPPROTO_TCP, 4 )
            if (dpid == 5):
                self.core_switch(datapath, '10.0.0.1', inet.IPPROTO_TCP, 4 )
                self.core_switch(datapath, '10.0.0.2', inet.IPPROTO_TCP, 1 )

