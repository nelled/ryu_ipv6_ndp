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

from ryu.lib import hub
from scapy import all as scapy

from cache_manager import CacheManager


# Application that uses simple_switch_13 for packet switching
# it runs a separate thread that sends a IPv6 RouterAdvertisement
# every 30 seconds.
# The RouterAdvertisement is build using scapy

class SimpleV6nd13(CacheManager):

    def __init__(self, *args, **kwargs):
        super(SimpleV6nd13, self).__init__(*args, **kwargs)
        self.ra_thread = hub.spawn(self._cyclic_ra)

    def _cyclic_ra(self):
        while True:
            for dp in self.datapaths.values():
                self._send_ra(dp)
                print("RA sent")
            hub.sleep(5)

    def _send_ra(self, datapath):
        self.logger.info('sent IPv6_RA on Datapath: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        e = scapy.Ether(src="70:01:02:03:04:05", dst="33:33:00:00:00:01")
        h = scapy.IPv6()
        h.dest = "ff02::1"
        i = scapy.ICMPv6ND_RA()
        o = scapy.ICMPv6NDOptPrefixInfo()
        o.prefix = "2001:db8:1::"
        o.prefixlen = 64
        p = (e / h / i / o)
        ps = bytes(p)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ps)
        datapath.send_msg(out)



