from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
import json



class Shortest_Path_SDN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Shortest_Path_SDN, self).__init__(*args, **kwargs)

                                                     # arp table: for searching
        self.arp_table={}
                                                     # hard-coded MAC table

        self.arp_table["10.0.0.1"] = "00:00:00:00:00:01"
        self.arp_table["10.0.0.2"] = "00:00:00:00:00:02"
        self.arp_table["10.0.0.3"] = "00:00:00:00:00:03"
        self.arp_table["10.0.0.4"] = "00:00:00:00:00:04"

                                                    #Initial handshake between switch and controller

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dpath = ev.msg.datapath
        ofproto = dpath.ofproto
        parser = dpath.ofproto_parser


                        # Insert static flow , default packets sent to the controller , default flows and match

        match = parser.OFPMatch()
        action = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,[parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)])
        inst = [action]
        self.add_flow(dpath, match, inst, 0, 0)




                                                         # Installing static rules to process TCP/UDP and ICMP and ACL
        dpid = dpath.id  # classifying the switch ID
        if (dpid == 1):  # switch S1
                                                    # 10.0.0.1 is dst ip address, 1 is switch port number
                                         # for switch 1, what port number should choose to forward that dst address

                                                                ### implementing Tcp

            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.1', 10, 1)
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.4', 10, 3)

                                                            ### implement icmp fwding


            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 1)
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.4', 10, 3)



                                                            # ### implement udp fwding
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.3', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.4', 10, 3)

                                                                # # udp drop
            self.drop_udp_flow(dpath, '10.0.0.4', inet.IPPROTO_UDP, [])









        elif (dpid == 2): # switch S2
                                                            #10.0.0.1 is dst ip address, 2 is switch port number
                                    # for switch 2, what port number should choose to forward that dst address ### implementing Tcp
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.1', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.2', 10, 1)
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.4', 10, 2)


            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 1)
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.4', 10, 2)

                                                                 ### implement udp fwding
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.1', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.2', 10, 1)
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.4', 10, 3)


                                            #http traffic

            self.drop_http_traffic(dpath,'10.0.0.2','10.0.0.4',inet.IPPROTO_TCP, 80)






        elif (dpid == 3):
                                    #switch S3  10.0.0.1 is dst ip address, 2 is switch port number  for switch 3, what port number should choose to forward that dst address
                                                                        ### implementing Tcp
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.1', 10, 3)
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.3', 10, 1)
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.4', 10, 3)

                                                                ### implement icmp fwding
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 3)
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 1)
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.4', 10, 3)

                                                                ### implement udp fwding
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.1', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.3', 10, 1)
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.4', 10, 3)




        elif (dpid == 4):                                                 # switch S4 ### implement tcp fwding

            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.1', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(dpath, inet.IPPROTO_TCP, '10.0.0.4', 10, 1)

                                                                         ## implement icmp fwding
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(dpath, inet.IPPROTO_ICMP, '10.0.0.4', 10, 1)
                                                                        ### implement udp fwding
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.1', 10,2)
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.2', 10,3)
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.3', 10,3)
            self.add_layer4_rules(dpath, inet.IPPROTO_UDP, '10.0.0.4', 10,1)


                                                                                # # udp drop

            self.drop_udp_flow(dpath, '10.0.0.1', inet.IPPROTO_UDP, [])

                                                                    ## http traffic
            self.drop_http_traffic(dpath, '10.0.0.4', '10.0.0.2', inet.IPPROTO_TCP, 80)


        else:
            print("wrong switch")


    def add_layer4_rules(self, dpath, ip_proto, ipv4_dst, priority, fwd_port):
        ofproto = dpath.ofproto
        parser = dpath.ofproto_parser
        # actions = [parser.OFPActionOutput(fwd_port)]
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=ip_proto,ipv4_dst=ipv4_dst)
        action = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,[parser.OFPActionOutput(fwd_port)])
        inst = [action]
        self.add_flow(dpath, match, inst, 0, priority)


    def drop_udp_flow(self, dpath, ipv4_dst, ip_proto, actions):
        ofproto = dpath.ofproto
        parser = dpath.ofproto_parser
        actions = actions
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ipv4_dst, ip_proto=ip_proto)
        action = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        inst = [action]
        self.add_flow(dpath, match, inst, 0, 30)


    def drop_http_traffic(self, dpath, ipv4_src, ipv4_dst, ip_proto, tcp_dst):
        ofproto = dpath.ofproto
        parser = dpath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, ip_proto=ip_proto,tcp_dst=tcp_dst)
        action = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                              [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)])
        inst = [action]
        self.add_flow(dpath, match, inst, 0, 20)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dpath = msg.datapath
        ofproto = dpath.ofproto
        parser = dpath.ofproto_parser

        dpid = dpath.id                         # to idetify OpenFLow switches
        in_port = msg.match['in_port']
                                        #analyze recived packets from packet processing library
        pkt = packet.Packet(msg.data)
        self.logger.info("This is packet in message!")
        self.logger.info(pkt)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ethtype = eth_pkt.ethertype
        eth_dst = eth_pkt.dst
        eth_src = eth_pkt.src

        self.logger.info("This is packet_in from switch id %s",dpid)
        #self.logger.info("packet in ether_type = %s dpid = %s, src =  %s, dst =  %s, in_port =  %s ",ethertype, dpid, eth_src, eth_dst, in_port)
                                                                # process ARP
        if (ethtype == ether.ETH_TYPE_ARP):
            self.handle_arp(dpath,in_port, pkt)
            return
                                                                    # process IP
        if (ethtype == ether.ETH_TYPE_IP):
            self.handle_ip(dpath,in_port, pkt)
            return

        else:
            return

                                # Member methods you can call to install TCP/UDP/ICMP fwding rules


    def add_flow(self, dpath, match, inst, table, priority):
        ofproto = dpath.ofproto
        parser = dpath.ofproto_parser
        buffer_id = ofproto.OFP_NO_BUFFER
        #inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath=dpath, table_id=table,priority=priority,match=match, instructions=inst)
        self.logger.info("Here are flows")
        self.logger.info(mod)
        dpath.send_msg(mod)

    def packet_output(self, dpath, in_port, pkt):
        ofproto = dpath.ofproto
        parser = dpath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(dpath,ofproto.OFP_NO_BUFFER,ofproto.OFPP_CONTROLLER,actions,data)
        dpath.send_msg(out)


    def handle_arp(self, dpath, in_port, pkt):
        ofproto = dpath.ofproto
        parser = dpath.ofproto_parser
                                                            # parse out the ethernet and arp packet
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        # obtain the MAC of dst IP
        arp_resolv_mac = self.arp_table[arp_pkt.dst_ip]
                                                    # generate the ARP reply msg
                                                                 # the packet library section
        ether_hd = ethernet.ethernet(ethertype = ether.ETH_TYPE_ARP,dst = eth_pkt.src,src = arp_resolv_mac)
        arp_hd = arp.arp(hwtype=1, proto = 2048, hlen = 6, plen = 4,opcode = 2, src_mac = arp_resolv_mac, src_ip = arp_pkt.dst_ip, dst_mac = arp_pkt.src_mac,dst_ip = arp_pkt.src_ip)
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ether_hd)
        arp_reply.add_protocol(arp_hd)
        self.packet_output(dpath,in_port,pkt)


    def handle_ip(self, dpath, in_port, pkt):
        ofproto = dpath.ofproto
        parser = dpath.ofproto_parser
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4) # parse out the IPv4 pkt
        tcp_pkt = pkt.get_protocol(tcp.tcp)  # parser out the TCP pkt
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ip_src = ipv4_pkt.src
        ip_dst = ipv4_pkt.dst
        ip_proto = ipv4_pkt.proto
        dst_port = tcp_pkt.dst_port



        if ip_src == "10.0.0.2" and ip_dst == "10.0.0.4" and ip_proto == inet.IPPROTO_TCP and dst_port == 80:
            tcp_hd = tcp.tcp(ack=tcp_pkt.seq + 1, src_port=tcp_pkt.dst_port, dst_port=tcp_pkt.src_port, bits=20)
            ip_hd = ipv4.ipv4(dst=ipv4_pkt.src, src=ipv4_pkt.dst, proto=ipv4_pkt.proto)
            ether_hd = ethernet.ethernet(ethertype=ether.ETH_TYPE_IP, dst=eth_pkt.src, src=eth_pkt.dst)

            tcp_rst_ack = packet.Packet()
            tcp_rst_ack.add_protocol(ether_hd)
            tcp_rst_ack.add_protocol(ip_hd)
            tcp_rst_ack.add_protocol(tcp_hd)

            self.packet_output(dpath,in_port,tcp_rst_ack)



        elif ip_src == "10.0.0.4" and ip_dst == "10.0.0.2" and ip_proto == inet.IPPROTO_TCP and dst_port == 80:

            tcp_hd = tcp.tcp(ack=tcp_pkt.seq + 1, src_port=tcp_pkt.dst_port, dst_port=tcp_pkt.src_port, bits=20)
            ip_hd = ipv4.ipv4(dst=ipv4_pkt.src, src=ipv4_pkt.dst, proto=ipv4_pkt.proto)
            ether_hd = ethernet.ethernet(ethertype=ether.ETH_TYPE_IP, dst=eth_pkt.src, src=eth_pkt.dst)

            tcp_rst_ack = packet.Packet()
            tcp_rst_ack.add_protocol(ether_hd)
            tcp_rst_ack.add_protocol(ip_hd)
            tcp_rst_ack.add_protocol(tcp_hd)

            self.packet_output(dpath,in_port,tcp_rst_ack)


        else:
            return