# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
#from scapy.all import Ether,IPv6,ICMPv6ND_RA,ICMPv6NDOptPrefixInfo
from scapy import all as scapy
from ryu.lib import hub

# Application that uses simple_switch_13 for packet switching
# it runs a separate thread that sends a IPv6 RouterAdvertisement
# every 30 seconds.
# The RouterAdvertisement is build using scapy

class SimpleV6nd13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleV6nd13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.ra_thread = hub.spawn(self._cyclic_ra)

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

    def _cyclic_ra(self):
        while True:
            for dp in self.datapaths.values():
                self._send_ra(dp)
            hub.sleep(30)

    def _send_ra(self, datapath):
        self.logger.info('send IPv6_RA on Datapath: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        e = scapy.Ether (src="70:01:02:03:04:05", dst="33:33:00:00:00:01")
        h = scapy.IPv6()
        h.dest = "ff02::1"
        i = scapy.ICMPv6ND_RA()
        o = scapy.ICMPv6NDOptPrefixInfo()
        o.prefix = "2001:db8:1::"
        o.prefixlen = 64
        p = (e/h/i/o)
        ps = bytes(p)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath,    
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ps)
        datapath.send_msg(out)

    def _request_stats(self, datapath):
        self.logger.info('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)


