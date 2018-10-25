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
from ipaddress import IPv6Address
from switch_v6 import SimpleSwitch13

REACHABLE_TIME = 30
# TODO: What to do here?
CONTROLLER_NC_SOURCE = '33:33:00:00:00:01'


class CacheManager(SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(CacheManager, self).__init__(*args, **kwargs)
        self.ra_thread = hub.spawn(self._cache_check)

    # Wrapper for cyclic polling
    def _cache_check(self):
        while True:
            self._check_entries()
            print("Cache:")
            print(self.neighbor_cache)
            hub.sleep(5)

    # Checks cache entries and updates state depending on timer
    def _check_entries(self):
        to_delete = []
        for k, v in self.neighbor_cache.entries.items():
            age = v.get_age()
            if age <= REACHABLE_TIME:
                v.set_reachable()
            if age > REACHABLE_TIME:
                v.set_stale()
            if age > 1.2 * REACHABLE_TIME:
                # Get suffix from entry
                self._send_ns(v.ip, CONTROLLER_NC_SOURCE)
                v.set_probe()
            if age > 3 * REACHABLE_TIME:
                v.set_delete()
                to_delete.append(k)

        # Do deletion here to avoid exception
        for i in to_delete:
            self.neighbor_cache.entries.pop(i, None)

    # Create solicited node multicast
    def _make_sn_mc(self, addr):
        snmc_prefix = 'FF02:0:0:0:0:1:FF'
        suffix = self._get_snmc_suffix(addr)
        return snmc_prefix + suffix

    def _get_snmc_suffix(self, addr):
        ip = IPv6Address(addr).exploded
        return ip[-7:]

    # Todo: Create something like a packet factory
    # TODO: refactor functions, we do not need to pass a src here if we always use one MAC
    # TODO: Look at actions and parser in _send_ra, need todo this as well
    def _create_ns(self, dst, src):
        # Solicitation
        head = scapy.IPv6()
        head.dst = self._make_sn_mc(dst)

        ns = scapy.ICMPv6ND_NS(tgt=dst)
        llSrcAdd = scapy.ICMPv6NDOptSrcLLAddr(lladdr=src)

        sol = head / ns / llSrcAdd

        return sol

    def _send_ns(self, dst, src):
        pkt = self._create_ns(dst, src)
        self._send_all(pkt)

    def _send_all(self, pkt):
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            ofproto = dp.ofproto

            ps = bytes(pkt)

            # TODO: Overdo, use mac_to_port table to avoid flood,
            # Need to pass mac from table aswell
            """
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
            """
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=dp,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ps)
            dp.send_msg(out)