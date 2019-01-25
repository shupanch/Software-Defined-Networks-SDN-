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


class SinglePath(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # hardcoded arp table
    def __init__(self, *args, **kwargs):
        super(myRyu3, self).__init__(*args, **kwargs)

        self.arp_table = {}
        self.arp_table["10.0.0.1"] = "00:00:00:00:00:01"
        self.arp_table["10.0.0.2"] = "00:00:00:00:00:02"


    # Switch Features Handler where reactive rules are installed
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 0, match, inst, 0)
        dpid = datapath.id

        # add reactive flow for switches 4,5 since it's single path
        if (dpid == 4):
            self.edge_flow(datapath, '10.0.0.1', inet.IPPROTO_TCP, 1)
            self.edge_flow(datapath, '10.0.0.2', inet.IPPROTO_TCP, 2)

        if (dpid == 5):
            self.edge_flow(datapath, '10.0.0.1', inet.IPPROTO_TCP, 2)
            self.edge_flow(datapath, '10.0.0.2', inet.IPPROTO_TCP, 1)

        # General functions for rules and output packets
    def add_flow(self, datapath, priority, match, inst, table):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        buffer_id = ofproto.OFP_NO_BUFFER
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def output_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        action = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                                  actions=action, data=data)
        datapath.send_msg(out)


        # Switch specific functions
    def edge_flow(self, datapath, ipv4_dst, proto, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ipv4_dst, ip_proto=proto)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 10, match, inst, 0)


    def core_flow(self, datapath, ipv4_dst, proto, out_port, tcp_dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ipv4_dst, ip_proto=proto, tcp_dst=tcp_dst)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 12, match, inst, 0)

    #Packet In_handler for IP and ARP
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth_pkt.ethertype
        eth_dst = eth_pkt.dst
        eth_src = eth_pkt.src
        tcp_pkt = pkt.get_protocol(tcp.tcp)


        # process ARP
        if (ethertype == ether.ETH_TYPE_ARP):
            self.handle_arp(datapath, in_port, pkt)

        #process IP/TCP
        if (ethertype == ether.ETH_TYPE_IP):
            self.handle_ip(datapath, in_port, pkt, dpid)


    #Handle ARP
    def handle_arp(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        # obtain the MAC of dst IP
        arp_resolv_mac = self.arp_table[arp_pkt.dst_ip]


        ether_hd = ethernet.ethernet(dst=eth_pkt.src,src=arp_resolv_mac,ethertype=ether.ETH_TYPE_ARP)
        arp_hd = arp.arp(hwtype=1, proto=2048, hlen=6, plen=4,opcode=2, src_mac=arp_resolv_mac,src_ip=arp_pkt.dst_ip, dst_mac=eth_pkt.src,dst_ip=arp_pkt.src_ip)

        arp_reply = packet.Packet()
        arp_reply.add_protocol(ether_hd)
        arp_reply.add_protocol(arp_hd)


        self.output_packet(datapath, port, pkt)


        #Handle IP
    def handle_ip(self, datapath, port, pkt, dpid):
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        dst_port = tcp_pkt.dst_port

        if (dpid == 1):
            self.core_flow(datapath, '10.0.0.1', inet.IPPROTO_TCP, 1, dst_port)
            self.core_flow(datapath, '10.0.0.2', inet.IPPROTO_TCP, 2, dst_port)




