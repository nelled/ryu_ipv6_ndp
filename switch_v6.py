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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types, ethernet, icmpv6, packet, ipv6
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

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
        parser = datapath.ofproto_parser
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
            self._ndp_packet_handler(dpid, src, dst, in_port, reason, msg.match, msg.cookie, eth.ethertype, pkt)
        else:
            self.logger.info("Another Message: %s %s %s %s reason=%s match=%s cookie=%d ether=%d", dpid, src, dst,
                             in_port, reason, msg.match, msg.cookie, eth.ethertype)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
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

    def _ndp_packet_handler(self, dpid, src, dst, in_port, reason, match, cookie, ethertype, pkt):
        if cookie == 135:
            self._ns_handler(dpid, src, dst, in_port, reason, match, cookie, ethertype, pkt)

        if cookie == 136:
            self._na_handler(dpid, src, dst, in_port, reason, match, cookie, ethertype, pkt)

    def _ra_handler(self):
        # Do nothing, controller is the only one emitting advertisements.
        # Probably log and do not forward
        pass

    def _rs_handler(self):
        # Respond with router advertisement immediately
        pass

    def _na_handler(self, dpid, src, dst, in_port, reason, match, cookie, ethertype, pkt):
        print("NA handler invoked")
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s reason=%s match=%s cookie=%d ether=%d",
                         dpid, src, dst, in_port, reason,
                         match, cookie, ethertype)
        ip6_header = pkt.get_protocol(ipv6.ipv6)
        self.neighbor_cache.add_entry(ip6_header.src, src)
        print(self.neighbor_cache)

    def _ns_handler(self, dpid, src, dst, in_port, reason, match, cookie, ethertype, pkt):
        print("NS handler invoked")
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s reason=%s match=%s cookie=%d ether=%d",
                         dpid, src, dst, in_port, reason,
                         match, cookie, ethertype)