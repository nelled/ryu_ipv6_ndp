from scapy import all as scapy

from config import router_mac, router_dns, ipv6_nd_prefix
from helpers import mac2ipv6, make_sn_mc

"""
Some functions to create NDP packets using Scapy.
"""


def create_na(src_ip, dst_ip, src_mac, dst_mac, r=0, s=0):
    # Advertisement
    ether_head = scapy.Ether(dst=dst_mac, src=src_mac)
    ipv6_head = scapy.IPv6(src=src_ip, dst=dst_ip)
    icmpv6_ns = scapy.ICMPv6ND_NA(tgt=src_ip, R=r, S=s)
    if not r:
        ll_dst_add = scapy.ICMPv6NDOptDstLLAddr(lladdr=src_mac)
        adv = (ether_head / ipv6_head / icmpv6_ns / ll_dst_add)
    else:
        icmpv6_opt_pref = scapy.ICMPv6NDOptPrefixInfo()
        ll_src_add = scapy.ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
        adv = (ether_head / ipv6_head / icmpv6_ns / icmpv6_opt_pref / ll_src_add)

    return adv


def create_ns(dst_ip, dst_mac, src_ip=None, src_mac=None, tgt_ip=None):
    # Solicitation
    if src_ip is None:
        src_ip = mac2ipv6(router_mac)
    if src_mac is None:
        src_mac = router_mac
    if tgt_ip is None:
        tgt_ip = dst_ip
    ether_head = scapy.Ether(dst=dst_mac, src=src_mac)
    # With solicited node multicast
    ipv6_head = scapy.IPv6(src=src_ip, dst=make_sn_mc(dst_ip))
    # Global address
    icmpv6_ns = scapy.ICMPv6ND_NS(tgt=tgt_ip)
    icmpv6_opt_pref = scapy.ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    sol = (ether_head / ipv6_head / icmpv6_ns / icmpv6_opt_pref)

    return sol


def create_ra(dst=None):
    ether_head = scapy.Ether(src=router_mac, dst=dst)
    ipv6_head = scapy.IPv6()
    ipv6_head.dest = 'ff02::1'
    ipv6_head.src = mac2ipv6(router_mac)
    ipv6_ra = scapy.ICMPv6ND_RA()
    ipv6_nd_pref = scapy.ICMPv6NDOptPrefixInfo()
    ipv6_nd_pref.prefix = ipv6_nd_prefix
    ipv6_nd_pref.prefixlen = 64
    ipv6_nd_pref.validlifetime = 7200  # Valid-Lifetime 2h
    ipv6_nd_pref.preferredlifetime = 1800  # Preferred-Lifetime 30min
    o_route = scapy.ICMPv6NDOptRouteInfo()  # ICMPv6-Option: Route Information
    o_route.prefix = '::'  # Default Route
    o_route.plen = 0  # Prefix length in bit
    o_route.rtlifetime = 1800  # Same value as the Preferred-Lifetime of the Router
    o_rdns = scapy.ICMPv6NDOptRDNSS()  # ICMPv6-Option: Recursive DNS Server
    o_rdns.dns = router_dns  # List of DNS Server Addresses
    o_rdns.lifetime = 1800  # Same value as the Preferred-Lifetime of the Router

    o_mac = scapy.ICMPv6NDOptSrcLLAddr()  # ICMPv6-Option: Source Link Layer Address
    o_mac.lladdr = router_mac  # MAC address

    ra = (ether_head / ipv6_head / ipv6_ra / ipv6_nd_pref / o_route / o_rdns / o_mac)
    return ra