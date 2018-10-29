# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

####################################
#####>>>>TODO<<<<###################
# Neigbor discovery cache
# # Problem: We need to probe for activity, once a neighbor is known the traffic wont go over the controller again
# Write handlers for different packet types, plus fallback if different packet is matched
# # Handlers can print messages first, just for structure.
# Normal learning has to be retained
# Find out what exactly should be done with the router advertisements
# Find out how to test ipv6 functionality (friendly tests)
# Write wrappers for scapy for convenient answer generation.
# Create custom topology with mininet for  scripting and maybe a makefile or something like that for starting
# tests etc.


###################################
from scapy import all as scapy
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types, ethernet, packet, ipv6
from ryu.ofproto import ofproto_v1_3

from config import router_mac
from helpers import mac2ipv6
from nc.neighbor_cache import NeighborCache

ICMPv6_CODES = {133: 'Router Solicitation',
                134: 'Router Advertisement',
                135: 'Neighbor Solicitation',
                136: 'Neighbor Advertisement',
                137: 'Redirect'
                }


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.neighbor_cache = NeighborCache()
        self.logger.info("Neighbor Cache Created")

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Install match for all ICMPv6 messages
        for icmp_code in range(133, 137 + 1):
            match = parser.OFPMatch(eth_type=0x86dd, ip_proto=58, icmpv6_type=icmp_code)
            self.add_flow(datapath, 10, match, actions, cookie=icmp_code)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, cookie=0):
        print("Added flow for: " + str(match))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, cookie=cookie)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, cookie=cookie)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if msg.reason == ofproto.OFPR_NO_MATCH:
            reason = "NO MATCH"
        else:
            reason = msg.reason

        if msg.cookie in ICMPv6_CODES.keys():
            self._ndp_packet_handler(dpid, src, dst, in_port, msg.cookie, msg)
        else:
            self.logger.info("Another Message: %s %s %s %s reason=%s match=%s cookie=%d ether=%d", dpid, src, dst,
                             in_port, reason, msg.match, msg.cookie, eth.ethertype)
            self._learn_mac_send(dpid, src, dst, in_port, msg)

    def _learn_mac(self, dpid, src, in_port):
        self.mac_to_port[dpid][src] = in_port

    # Normal behaviour outsourced to function so we can control what happens to ICMPv6 packets
    def _learn_mac_send(self, dpid, src, dst, in_port, msg, forward_packet=True):
        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # learn a mac address to avoid FLOOD next time.
        self._learn_mac(dpid, src, in_port)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # If we do not forward the packet (because we send our own NS back i.e.)
            if forward_packet == False:
                self.add_flow(datapath, 1, match, actions)
                return
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _ndp_packet_handler(self, dpid, src, dst, in_port, cookie, msg):
        if cookie == 133:
            self._rs_handler(dpid, src, dst, in_port, cookie, msg)

        if cookie == 134:
            self._ra_handler(dpid, src, dst, in_port, cookie, msg)

        if cookie == 135:
            self._ns_handler(dpid, src, dst, in_port, cookie, msg)

        if cookie == 136:
            self._na_handler(dpid, src, dst, in_port, cookie, msg)

        if cookie == 137:
            self._rm_handler(dpid, src, dst, in_port, cookie, msg)

    def _rs_handler(self, dpid, src, dst, in_port, cookie, msg):
        # Respond with router advertisement immediately
        # Send to all or only to node asking?
        # Send to port or flood?
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)
        self._send_ra_s(dpid, src)

    def _ra_handler(self, dpid, src, dst, in_port, cookie, msg):
        # Do nothing, controller is the only one emitting advertisements.
        # Probably log and do not forward
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)

    def _ns_handler(self, dpid, src, dst, in_port, cookie, msg):
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)
        pkt = packet.Packet(msg.data)
        ipv6_header = pkt.get_protocol(ipv6.ipv6)
        ipv6_dst = ipv6_header.dst
        self.logger.info("Handling NS, DST IS: %s", ipv6_dst)
        cache_entry = self._addr_in_cache(ipv6_dst)
        if cache_entry:
            self.logger.info("Cache hit, responding with our own NA.")
            self._learn_mac_send(dpid, src, dst, in_port, msg, forward_packet=False)

            na = self._create_na(ipv6_header.src, ipv6_header.dst, src, dst)
            self._send_packet(na, dpid)
        else:
            # TODO: Implement logic as in email
            self.logger.info("Cache miss, forwarding NS, we need to change this.")
            self._learn_mac_send(dpid, src, dst, in_port, msg, forward_packet=True)

    def _na_handler(self, dpid, src, dst, in_port, cookie, msg):
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)
        pkt = packet.Packet(msg.data)
        ip6_header = pkt.get_protocol(ipv6.ipv6)
        self.neighbor_cache.add_entry(ip6_header.src, src)
        print(self.neighbor_cache)
        self._learn_mac_send(dpid, src, dst, in_port, msg)

    def _rm_handler(self, dpid, src, dst, in_port, cookie, msg):
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)

    # TODO: Implement ONE send_ra function that takes arguments
    # like solicited true false etc
    def _send_ra_s(self, dpid, dst):
        self.logger.info('Sent sol RA on dp: %016x to %s', dpid, dst)
        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        e = scapy.Ether(src=router_mac, dst=dst)
        h = scapy.IPv6()
        h.dest = 'ff02::1'
        h.src = mac2ipv6(router_mac)
        i = scapy.ICMPv6ND_RA()
        o = scapy.ICMPv6NDOptPrefixInfo()
        o.prefix = '2001:db8:1::'
        o.prefixlen = 64
        p = (e / h / i / o)
        print(p.show())
        ps = bytes(p)
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ps)
        datapath.send_msg(out)

    def _addr_in_cache(self, ip):
        return self.neighbor_cache.get_entry(ip)

    def _create_na(self, src_ip, dst_ip, src_mac, dst_mac):
        # Advertisement
        ether_head = scapy.Ether(dst=dst_mac, src=src_mac)
        ipv6_head = scapy.IPv6(src=src_ip, dst=dst_ip)
        icmpv6_ns = scapy.ICMPv6ND_NA(tgt=src_ip, R='0')
        icmpv6_opt_pref = scapy.ICMPv6NDOptPrefixInfo()
        # Is this the address the answer will be sent to?
        llSrcAdd = scapy.ICMPv6NDOptSrcLLAddr(lladdr=src_mac)

        adv = (ether_head / ipv6_head / icmpv6_ns / icmpv6_opt_pref/ llSrcAdd)
        print(adv.show())

        return adv

    def _send_packet(self, pkt, dpid):
        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        ps = bytes(pkt)
        if pkt.ether.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][pkt.ether.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ps)
        datapath.send_msg(out)


