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
################################
################################
# TODO: Look into meter tables in order to prevent flooding https://github.com/vanhauser-thc/thc-ipv6

from collections import defaultdict, deque, Iterable
from time import time, ctime

from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types, ethernet, packet, ipv6
from ryu.ofproto import ofproto_v1_3

from config import router_mac, rule_idle_timeout, max_msg_buf_len, ndp_proxy_instance_name, max_rate
from nc.neighbor_cache import NeighborCache
from ndp_proxy_controller import NdpProxyController
from ndp_proxy_pcap_writer import NdpProxyPcapWriter
from packet_creator import create_na, create_ns, create_ra

ICMPv6_CODES = {133: 'Router Solicitation',
                134: 'Router Advertisement',
                135: 'Neighbor Solicitation',
                136: 'Neighbor Advertisement',
                137: 'Redirect'
                }


class NdpProxy(app_manager.RyuApp):
    """
    Ryu App implementing a NDP proxy. Acts as sink and source of all NDP messages and maintains its own
    neighbor cache. Flows with a short timeout are installed for known neighbors and flow deleted messages
    are used to notify the proxy that a host has not received traffic in a while. Such neighbors are marked
    as stale.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Needed for REST
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(NdpProxy, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.neighbor_cache = NeighborCache()
        self.logger.info("Neighbor Cache reated.")
        self.statistics = {'cache_miss_count': 0,
                           133: defaultdict(lambda: defaultdict(lambda: deque(maxlen=max_msg_buf_len))),
                           134: defaultdict(lambda: defaultdict(lambda: deque(maxlen=max_msg_buf_len))),
                           135: defaultdict(lambda: defaultdict(lambda: deque(maxlen=max_msg_buf_len))),
                           136: defaultdict(lambda: defaultdict(lambda: deque(maxlen=max_msg_buf_len))),
                           137: defaultdict(lambda: defaultdict(lambda: deque(maxlen=max_msg_buf_len)))
                           }

        self.pcap_writer = NdpProxyPcapWriter(self.logger)

        # Needed for REST
        wsgi = kwargs['wsgi']
        wsgi.register(NdpProxyController,
                      {ndp_proxy_instance_name: self})

        self.logger.info("NDP proxy running...")

    @staticmethod
    def _is_for_router(dst):
        if dst == router_mac:
            return True
        else:
            return False

    # Takes msg and returns src, dst, and icmpv6 tgt
    @staticmethod
    def _extract_addr(msg):
        pkt = packet.Packet(msg.data)
        ipv6_header = pkt.get_protocol(ipv6.ipv6)
        # TODO: make this safer, is there a possibility that data is of wrong format or pkt does not have the element?
        icmpv6_header = pkt[2].data
        ipv6_dst = ipv6_header.dst
        ipv6_src = ipv6_header.src
        icmpv6_tgt = icmpv6_header.dst

        return ipv6_dst, ipv6_src, icmpv6_tgt

    def get_stats_dict(self):
        return self._to_dict(self.statistics)

    def _to_dict(self, data):
        d = {}
        for k, v in data.items():
            if not isinstance(v, dict):
                if not isinstance(v, Iterable):
                    d[k] = v
                else:
                    d[k] = list(v)
            else:
                d[k] = self._to_dict(v)
        return d

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
        self.add_flow(datapath, 0, match, actions, timeout=0)

        # Create band
        bands = [parser.OFPMeterBandDrop(rate=max_rate, burst_size=10)]
        # Install meter request
        req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_PKTPS, meter_id=1,
                                 bands=bands)

        datapath.send_msg(req)

        # Additional instruction to apply meter
        inst = [parser.OFPInstructionMeter(1)]
        # inst = None
        # Install match for all ICMPv6 messages
        for icmp_code in range(133, 137 + 1):
            match = parser.OFPMatch(eth_type=0x86dd, ip_proto=58, icmpv6_type=icmp_code)
            self.add_flow(datapath, 10, match, actions, instructions=inst, cookie=icmp_code, timeout=0)

    def add_flow(self, datapath, priority, match, actions, instructions=None, buffer_id=None, cookie=0,
                 timeout=rule_idle_timeout):
        self.logger.debug("Added flow for: " + str(match))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if instructions:
            inst = inst + instructions

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, cookie=cookie,
                                    hard_timeout=0, idle_timeout=timeout,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, cookie=cookie,
                                    hard_timeout=0, idle_timeout=timeout,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        # Write to pcap if flag set
        self.pcap_writer.write_pcap_all(msg)

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

        # Trigger icmpv6 handling
        if msg.cookie in ICMPv6_CODES.keys():
            self._ndp_packet_handler(dpid, src, dst, in_port, msg.cookie, msg)
        else:
            # Other messages do not concern us
            self.logger.debug("Another Message: %s %s %s %s reason=%s match=%s cookie=%d ether=%d", dpid, src, dst,
                              in_port, reason, msg.match, msg.cookie, eth.ethertype)
            self._learn_mac_send(dpid, src, dst, in_port, msg, timeout=0)

    def _learn_mac(self, dpid, src, in_port):
        self.mac_to_port[dpid][src] = in_port

    # Forward and learn MAC, this is for non icmpv6 traffic
    def _learn_mac_send(self, dpid, src, dst, in_port, msg, cookie=0, forward_packet=True, timeout=rule_idle_timeout):
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

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # If we do not forward the packet (because we send our own NS back i.e.)
            if forward_packet == False:
                self.add_flow(datapath, 1, match, actions, cookie=cookie, timeout=timeout)
                return
            # Verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, buffer_id=msg.buffer_id, cookie=cookie, timeout=timeout)
                return
            else:
                self.add_flow(datapath, 1, match, actions, cookie=cookie, timeout=timeout)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'
        self.logger.debug('OFPFlowRemoved received: '
                          'cookie=%d priority=%d reason=%s table_id=%d '
                          'duration_sec=%d duration_nsec=%d '
                          'idle_timeout=%d hard_timeout=%d '
                          'packet_count=%d byte_count=%d match.fields=%s',
                          msg.cookie, msg.priority, reason, msg.table_id,
                          msg.duration_sec, msg.duration_nsec,
                          msg.idle_timeout, msg.hard_timeout,
                          msg.packet_count, msg.byte_count, msg.match)
        try:
            self.neighbor_cache.set_stale(msg.cookie)
            self.logger.info(str(self.neighbor_cache))
        except AttributeError:
            self.logger.info("Flow removed message does not concern cache.")

    def _ndp_packet_handler(self, dpid, src, dst, in_port, cookie, msg):
        if cookie == 133:
            self.statistics[cookie][dpid][in_port].append((src, ctime(time())))
            self._rs_handler(dpid, src, dst, in_port, cookie, msg)

        if cookie == 134:
            self.statistics[cookie][dpid][in_port].append((src, ctime(time())))
            self._ra_handler(dpid, src, dst, in_port, cookie, msg)

        if cookie == 135:
            self.statistics[cookie][dpid][in_port].append((src, ctime(time())))
            self._ns_handler(dpid, src, dst, in_port, cookie, msg)

        if cookie == 136:
            self.statistics[cookie][dpid][in_port].append((src, ctime(time())))
            self._na_handler(dpid, src, dst, in_port, cookie, msg)

        if cookie == 137:
            self.statistics[cookie][dpid][in_port].append((src, ctime(time())))
            self._rm_handler(dpid, src, dst, in_port, cookie, msg)

    def _rs_handler(self, dpid, src, dst, in_port, cookie, msg):
        # Respond with router advertisement immediately
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)
        self._send_ra(dpid=dpid, dst=src)

    def _ra_handler(self, dpid, src, dst, in_port, cookie, msg):
        # Log and do not forward, only controller emits RAs
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)

    def _ns_handler(self, dpid, src, dst, in_port, cookie, msg):
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)
        ipv6_dst, ipv6_src, icmpv6_tgt = self._extract_addr(msg)
        self.logger.info("Handling NS, DST IS: %s", ipv6_dst)
        cache_entry = self._addr_in_cache(ipv6_dst)
        is_for_router = self._is_for_router(dst)
        if cache_entry:
            self.logger.info("Cache hit, responding with our own NA.")
            na = create_na(ipv6_src, ipv6_dst, src, dst)
            self.logger.debug("NA looks like this:\n " + na.show(dump=True))
            self._send_packet(na, dpid=dpid)
        if is_for_router:
            self.logger.info("Received NS for router, responding with our own NA.")
            # Reverse src and dst in signature here
            na = create_na(ipv6_dst, ipv6_src, dst, src, r=1)
            self.logger.debug("NA looks like this:\n " + na.show(dump=True))
            self._send_packet(na, dpid=dpid)
        else:
            self.logger.info("Cache miss, sending NS.")
            self.statistics['cache_miss_count'] += 1
            ns = create_ns(ipv6_dst, dst, src_ip=ipv6_src, src_mac=src, tgt_ip=icmpv6_tgt)
            self.logger.debug("NS looks like this:\n " + ns.show(dump=True))
            self._send_packet(ns, dpid=dpid)

    def _na_handler(self, dpid, src, dst, in_port, cookie, msg):
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)
        pkt = packet.Packet(msg.data)
        ip6_header = pkt.get_protocol(ipv6.ipv6)
        cache_id_cookie = self.neighbor_cache.add_entry(ip6_header.src, src)
        self.logger.info(str(self.neighbor_cache))
        self._learn_mac_send(dpid, src, dst, in_port, msg, cache_id_cookie)

    def _rm_handler(self, dpid, src, dst, in_port, cookie, msg):
        # Redirect messages only concern us when there are several routers
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)

    def _addr_in_cache(self, ip):
        return self.neighbor_cache.get_entry(ip)

    def _send_ra(self, dpid=None, dst=None):
        if not dst:
            # Send to all
            dst = '33:33:00:00:00:01'
        self.logger.info('Sending RA to: %s', dst)
        ra = create_ra(dst=dst)
        self.logger.debug("RA looks like this:\n " + ra.show(dump=True))
        self._send_packet(ra, dpid)

    def _send_packet(self, pkt, dpid=None):
        # If specific dpid
        if dpid:
            datapaths = [dpid]

        # Send on all
        else:
            datapaths = self.datapaths.keys()

        for dp in datapaths:
            self._send_on_dp(pkt, dp)

        self.pcap_writer.write_pcap_generated(pkt)

    def _send_on_dp(self, pkt, dpid):
        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        ps = bytes(pkt)
        try:
            if pkt['Ether'].dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][pkt['Ether'].dst]
            else:
                out_port = ofproto.OFPP_FLOOD
        except KeyError:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ps)
        datapath.send_msg(out)
