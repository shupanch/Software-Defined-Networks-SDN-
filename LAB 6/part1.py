from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib import hub
from operator import attrgetter
import json
import matplotlib.pyplot as plt

#Store link loads of each switch for every 10s interval.
link_load = {1:{1:[],2:[],3:[]}, 2:{1:[],2:[],3:[]}, 3:{1:[],2:[],3:[]}, 4:{1:[],2:[],3:[]}, 5:{1:[],2:[],3:[]}}
counter= 0
time=[]

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # hardcoded arp table
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)

        self.arp_table = {}
        self.arp_table["10.0.0.1"] = "00:00:00:00:00:01"
        self.arp_table["10.0.0.2"] = "00:00:00:00:00:02"
        self.arp_table["10.0.0.3"] = "00:00:00:00:00:03"

        #Added to monitor
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        for x in range(60):
            time.append(x*10)
        #self.logger.info(time)

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
        if (dpid == 3):
            self.edge_flow(datapath, '10.0.0.2', inet.IPPROTO_UDP, 2)
            self.edge_flow(datapath, '10.0.0.3', inet.IPPROTO_UDP, 2)

        if (dpid == 4):
            self.edge_flow(datapath, '10.0.0.3', inet.IPPROTO_UDP, 2)


    #Added to monitor
    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    #Added to monitor
    def _monitor(self):
        counter = 0
        final_load = {1:{1:[],2:[],3:[]}, 2:{1:[],2:[],3:[]}, 3:{1:[],2:[],3:[]}, 4:{1:[],2:[],3:[]}, 5:{1:[],2:[],3:[]}}
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
            self.logger.info("here..")
            self.logger.info((counter))

            if counter ==60:
                switch_list1_1 = link_load[1][1]
                switch_list1_2 = link_load[1][2]
                switch_list1_3 = link_load[1][3]
                switch_list2_1 = link_load[2][1]
                switch_list2_2 = link_load[2][2]
                switch_list2_3 = link_load[2][3]
                switch_list3_1 = link_load[3][1]
                switch_list3_2 = link_load[3][2]
                switch_list3_3 = link_load[3][3]
                switch_list4_1 = link_load[4][1]
                switch_list4_2 = link_load[4][2]
                switch_list4_3 = link_load[4][3]
                switch_list5_1 = link_load[5][1]
                switch_list5_2 = link_load[5][2]
                switch_list5_3 = link_load[5][3]

                switch_diff1_1 = self.pairwiseDifference(switch_list1_1, 60)
                switch_diff1_2 = self.pairwiseDifference(switch_list1_2, 60)
                switch_diff1_3 = self.pairwiseDifference(switch_list1_3, 60)
                switch_diff2_1 = self.pairwiseDifference(switch_list2_1, 60)
                switch_diff2_1 = self.pairwiseDifference(switch_list2_1, 60)
                switch_diff2_1 = self.pairwiseDifference(switch_list2_1, 60)
                switch_diff2_2 = self.pairwiseDifference(switch_list2_2, 60)
                switch_diff2_3 = self.pairwiseDifference(switch_list2_3, 60)
                switch_diff3_1 = self.pairwiseDifference(switch_list3_1, 60)
                switch_diff3_2 = self.pairwiseDifference(switch_list3_2, 60)
                switch_diff3_3 = self.pairwiseDifference(switch_list3_3, 60)
                switch_diff4_1 = self.pairwiseDifference(switch_list4_1, 60)
                switch_diff4_2 = self.pairwiseDifference(switch_list4_2, 60)
                switch_diff4_3 = self.pairwiseDifference(switch_list4_3, 60)
                switch_diff5_1 = self.pairwiseDifference(switch_list5_1, 60)
                switch_diff5_2 = self.pairwiseDifference(switch_list5_2, 60)
                switch_diff5_3 = self.pairwiseDifference(switch_list5_3, 60)

                self.logger.info('Here in pair')
                self.logger.info(switch_diff3_1)
            #if counter ==3:

                plt.figure(1)
                plt.plot(time, switch_diff1_1)
                plt.show()
                plt.savefig('1_1.png')
                plt.plot(time, switch_diff1_2)
                plt.show()
                plt.savefig('1_2.png')
                plt.plot(time, switch_diff1_3)
                plt.show()
                plt.savefig('1_3.png')
                plt.plot(time, switch_diff2_1)
                plt.show()
                plt.savefig('2_1.png')
                plt.plot(time, switch_diff2_2)
                plt.show()
                plt.savefig('2_2.png')
                plt.plot(time, switch_diff2_3)
                plt.show()
                plt.savefig('2_3.png')
                plt.plot(time, switch_diff3_1)
                plt.show()
                plt.savefig('3_1.png')
                plt.plot(time, switch_diff3_2)
                plt.show()
                plt.savefig('3_2.png')
                plt.plot(time, switch_diff3_3)
                plt.show()
                plt.savefig('3_3.png')
                plt.plot(time, switch_diff4_1)
                plt.show()
                plt.savefig('4_1.png')
                plt.plot(time, switch_diff4_2)
                plt.show()
                plt.savefig('4_2.png')
                plt.plot(time, switch_diff4_3)
                plt.show()
                plt.savefig('4_3.png')
                plt.plot(time, switch_diff5_1)
                plt.show()
                plt.savefig('5_1.png')
                plt.plot(time, switch_diff5_2)
                plt.show()
                plt.savefig('5_2.png')
                plt.plot(time, switch_diff5_3)
                plt.show()
                plt.savefig('5_3.png')

                self.logger.info("Plotting!!")
            counter = counter +1


    #Added to monitor
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    #Added to monitor
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

    #Added to monitor
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)

            if ev.msg.datapath.id ==3:
                if stat.port_no ==1:
                    link_load[3][1].append(stat.rx_bytes + stat.tx_bytes)
                    self.logger.info("IN D3")
                    self.logger.info(link_load[3][1])
                if stat.port_no ==2:
                    link_load[3][2].append(stat.tx_bytes + stat.tx_bytes)
                if stat.port_no ==3:
                    link_load[3][3].append(stat.tx_bytes + stat.tx_bytes)
            if ev.msg.datapath.id ==1:
                if stat.port_no ==1:
                    link_load[1][1].append(stat.rx_bytes + stat.tx_bytes)
                if stat.port_no ==2:
                    link_load[1][2].append((stat.rx_bytes + stat.tx_bytes))
                if stat.port_no ==3:
                    link_load[1][3].append(stat.tx_bytes + stat.tx_bytes)
            if ev.msg.datapath.id ==2:
                if stat.port_no ==1:
                    link_load[2][1].append(stat.rx_bytes + stat.tx_bytes)
                if stat.port_no ==2:
                    link_load[2][2].append(stat.rx_bytes + stat.tx_bytes)
                if stat.port_no ==3:
                    link_load[2][3].append(stat.rx_bytes + stat.tx_bytes)
            if ev.msg.datapath.id ==4:
                if stat.port_no ==1:
                    link_load[4][1].append(stat.rx_bytes + stat.tx_bytes)
                if stat.port_no ==2:
                    link_load[4][2].append((stat.rx_bytes + stat.tx_bytes))
                if stat.port_no ==3:
                    link_load[4][3].append(stat.tx_bytes + stat.tx_bytes)
            if ev.msg.datapath.id ==5:
                if stat.port_no ==1:
                    link_load[5][1].append(stat.rx_bytes + stat.tx_bytes)
                if stat.port_no ==2:
                    link_load[5][2].append(stat.rx_bytes + stat.tx_bytes)
                if stat.port_no ==3:
                    link_load[5][3].append(stat.rx_bytes + stat.tx_bytes)

    def drop_udp_flow(self, dpath, ipv4_dst, ip_proto, actions):
        ofproto = dpath.ofproto
        parser = dpath.ofproto_parser
        actions = actions
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ipv4_dst, ip_proto=ip_proto)
        action = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        inst = [action]
        self.add_flow(dpath, 10, match, inst, 0)

        # General functions for rules and output packets
    def add_flow(self, datapath, priority, match, inst, table):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        buffer_id = ofproto.OFP_NO_BUFFER
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

        # Switch specific functions
    def edge_flow(self, datapath, ipv4_dst, proto, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ipv4_dst, ip_proto=proto)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 10, match, inst, 0)


    def core_flow(self, datapath, ipv4_dst, proto, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ipv4_dst, ip_proto=proto)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 10, match, inst, 0)

    def pairwiseDifference(self, arr, n):
        list = []
        for i in range(n - 1):
            # absolute difference between
            # consecutive numbers
            diff = (abs(arr[i + 1] - arr[i]))/10
            list.append(diff)
        return list

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
            self.handle_ip(datapath, in_port, pkt, dpid,)


    #Handle ARP
    def handle_arp(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # parse out the ethernet and arp packet
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        # obtain the MAC of dst IP
        arp_resolv_mac = self.arp_table[arp_pkt.dst_ip]

        ### generate the ARP reply msg, please refer RYU documentation
        ### the packet library section

        ether_hd = ethernet.ethernet(dst=eth_pkt.src,
                                     src=arp_resolv_mac,
                                     ethertype=ether.ETH_TYPE_ARP)
        arp_hd = arp.arp(hwtype=1, proto=2048, hlen=6, plen=4,
                         opcode=2, src_mac=arp_resolv_mac,
                         src_ip=arp_pkt.dst_ip, dst_mac=eth_pkt.src,
                         dst_ip=arp_pkt.src_ip)
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ether_hd)
        arp_reply.add_protocol(arp_hd)
        arp_reply.serialize()

        # send the Packet Out mst to back to the host who is initilaizing the ARP
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                  ofproto.OFPP_CONTROLLER, actions,
                                  arp_reply.data)
        datapath.send_msg(out)


        #Handle IP
    def handle_ip(self, datapath, port, pkt, dpid):
        #tcp_pkt = pkt.get_protocol(tcp.tcp)
        #dst_port = tcp_pkt.dst_port

        if (dpid == 1):
            self.core_flow(datapath, '10.0.0.2', inet.IPPROTO_UDP, 2)
            self.core_flow(datapath, '10.0.0.3', inet.IPPROTO_UDP, 3)
