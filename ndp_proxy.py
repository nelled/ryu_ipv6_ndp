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

from config import router_mac, rule_idle_timeout, max_msg_buf_len, ndp_proxy_instance_name, max_rate, meter_flag
from nc.neighbor_cache import NeighborCache
from ndp_proxy_controller import NdpProxyController
from ndp_proxy_pcap_writer import NdpProxyPcapWriter
from packet_creator import create_na, create_ra

ICMPv6_CODES = {133: 'Router Solicitation',
                134: 'Router Advertisement',
                135: 'Neighbor Solicitation',
                136: 'Neighbor Advertisement',
                137: 'Redirect'
                }
ALL_NODES_MC = '33:33:00:00:00:01'


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

        inst = None
        if meter_flag:
            # Create band
            bands = [parser.OFPMeterBandDrop(rate=max_rate, burst_size=10)]
            # Install meter request
            req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_PKTPS,
                                     meter_id=1,
                                     bands=bands)
            # Send request
            datapath.send_msg(req)

            # Additional instruction to apply meter
            inst = [parser.OFPInstructionMeter(1)]

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
            self.logger.info("Another Message: %s %s %s %s reason=%s match=%s cookie=%d ether=%d", dpid, src, dst,
                             in_port, reason, msg.match, msg.cookie, eth.ethertype)
            self._learn_mac_send(dpid, src, dst, in_port, msg, timeout=0)

    def _learn_mac(self, dpid, src, in_port):
        self.mac_to_port[dpid][src] = in_port

    # Forward and learn MAC
    def _learn_mac_send(self, dpid, src, dst, in_port, msg, cookie=0, forward_packet=True, timeout=rule_idle_timeout,
                        patch_through=False):
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

        if not patch_through:
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

    def _dud_handler(self, dpid, src, dst, in_port, cookie, msg):
        self.logger.info('This is a DUD message')
        ipv6_dst, ipv6_src, icmpv6_tgt = self._extract_addr(msg)
        self.logger.info('Tentative addr is: %s', icmpv6_tgt)
        ip_entry = self.neighbor_cache.get_entry(icmpv6_tgt)
        if ip_entry:
            self.logger.info("Collision, sending NA to notify configuring host...")
            # TODO: Which address should be advertised??? tentative?
            # Need to send NA to notify of collision, how should this packet look like
            # TODO: In case of collision with STALE entry, a last check would be good
            na = create_na(ipv6_src, ipv6_dst, src, dst)
            self.logger.debug("NA looks like this:\n " + na.show(dump=True))
            self._send_packet(na, dpid=dpid)
        else:
            # We do not need to forward this NS, because DUD does not create an entry in neighbor cache of host
            '''
            - The Target Address is a "tentative" address on which Duplicate
             Address Detection is being performed [ADDRCONF].
            '''
            # Add to NC
            cache_id_cookie = self.neighbor_cache.add_entry(icmpv6_tgt, src)
            self.logger.info(str(self.neighbor_cache))

    def _ns_handler(self, dpid, src, dst, in_port, cookie, msg):
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)
        ipv6_dst, ipv6_src, icmpv6_tgt = self._extract_addr(msg)
        self.logger.info("Handling NS, DST IS: %s", ipv6_dst)
        is_for_router = self._is_for_router(dst)
        if is_for_router:
            self.logger.info("Received NS for router, responding with our own NA.")
            # Reverse src and dst in signature here
            na = create_na(ipv6_dst, ipv6_src, dst, src, r=1)
            self.logger.debug("NA looks like this:\n " + na.show(dump=True))
            self._send_packet(na, dpid=dpid)
            return

        # TODO: Learn from all Neighbor solicitations, with state created
        # TODO: patch them through, NAs then received set status to active
        # TODO: updates via unsolicited NAs still have to be considered
        # If NS is DUD...
        if ipv6_src == '::':
            # TODO: If we have a collision with an entry marked as inactive, need to perform check as well?
            # Could also be via status
            self._dud_handler(dpid, src, dst, in_port, cookie, msg)
        else:
            # UNSOLICITED NA will be ignored if there is no entry for the host. If there is an entry
            #   we will first CHECK if there is more than one response to NS (kind of like DUD)
            cache_entry = self._addr_in_cache(icmpv6_tgt)
            # TODO: Refactor this
            cache_id_cookie = 0
            if cache_entry:
                self.logger.info("Cache hit, setting status to pending and patching through.")
                cache_entry.set_pending()
                cache_id_cookie = cache_entry.get_cookie()
            else:
                self.logger.info("Cache miss, no DUD has been performed on address %s.", icmpv6_tgt)
                # TODO: THIS DOES NOT WORK!!! DST MAC IS MULTICAST!
                # Will need to account for that! Maybe set MAC field do unknown or smth
                #self.logger.info("Cache miss, creating entry and patching through.")
                #self.statistics['cache_miss_count'] += 1
                # Add to NC
                #cache_id_cookie = self.neighbor_cache.add_entry(icmpv6_tgt, dst, 'PENDING')

            self._learn_mac_send(dpid, src, dst, in_port, msg, cache_id_cookie, patch_through=True)
            self.logger.info(str(self.neighbor_cache))

    def _na_handler(self, dpid, src, dst, in_port, cookie, msg):
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)

        ipv6_dst, ipv6_src, icmpv6_tgt = self._extract_addr(msg)
        cache_entry = self.neighbor_cache.get_entry(icmpv6_tgt)
        if cache_entry:
            self.logger.info("Entry exists...")
            # If entry corresponds to info in packet, we forward the NA and create a flow rule
            # Communication is now possible
            if icmpv6_tgt in cache_entry.get_ips() and src == cache_entry.get_mac():
                self.logger.info("Entry info corresponds to cache, setting active and allowing communication...")
                cache_entry.set_active()
                self._learn_mac_send(dpid, src, dst, in_port, msg, cache_entry.get_cookie())
                self.logger.info(str(self.neighbor_cache))
            else:
                # TODO: Set existing to pending and send out NS
                # TODO: Either will be set to active or will be removed after a while
                self.logger.info("Entry info does not correspond to cache, discarding")
        else:
            self.logger.info("No entry in cache, discarding...")

    def _rm_handler(self, dpid, src, dst, in_port, cookie, msg):
        # Redirect messages only concern us when there are several routers
        self.logger.info(ICMPv6_CODES[cookie] + ": %s %s %s %s cookie=%d", dpid, src, dst, in_port, cookie)

    def _addr_in_cache(self, ip):
        return self.neighbor_cache.get_entry(ip)

    def _send_ra(self, dpid=None, dst=None):
        if not dst:
            # Send to all
            dst = ALL_NODES_MC
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
