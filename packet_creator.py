from ipaddress import IPv6Address

from scapy import all as scapy

from config import router_mac, router_dns, ipv6_nd_prefix


def create_router_na(src_ip, dst_ip, src_mac, dst_mac, r=1, s=0):
    # Advertisement
    ether_head = scapy.Ether(dst=dst_mac, src=src_mac)
    ipv6_head = scapy.IPv6(src=src_ip, dst=dst_ip)
    icmpv6_ns = scapy.ICMPv6ND_NA(tgt=src_ip, R=r, S=s)
    icmpv6_opt_pref = scapy.ICMPv6NDOptPrefixInfo()
    llSrcAdd = scapy.ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    adv = (ether_head / ipv6_head / icmpv6_ns / icmpv6_opt_pref / llSrcAdd)

    return adv


def create_na(src_ip, dst_ip, src_mac, dst_mac, r=0, s=0):
    # Advertisement
    ether_head = scapy.Ether(dst=dst_mac, src=src_mac)
    ipv6_head = scapy.IPv6(src=src_ip, dst=dst_ip)
    icmpv6_ns = scapy.ICMPv6ND_NA(tgt=src_ip, R=r, S=s)
    llDstAdd = scapy.ICMPv6NDOptDstLLAddr(lladdr=src_mac)
    adv = (ether_head / ipv6_head / icmpv6_ns / llDstAdd)

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
    ipv6_nd_pref.preferredlifetime = 1800  # Prefered-Lifetime 30min
    o_route = scapy.ICMPv6NDOptRouteInfo()  # ICMPv6-Option: Route Information
    o_route.prefix = '::'  # Default Route
    o_route.plen = 0  # Prefix length in bit
    o_route.rtlifetime = 1800  # Same value as the Prefered-Lifetime of the Router
    o_rdns = scapy.ICMPv6NDOptRDNSS()  # ICMPv6-Option: Recursive DNS Server
    o_rdns.dns = router_dns  # List of DNS Server Addresses
    o_rdns.lifetime = 1800  # Same value as the Prefered-Lifetime of the Router

    o_mac = scapy.ICMPv6NDOptSrcLLAddr()  # ICMPv6-Option: Source Link Layer Address
    o_mac.lladdr = router_mac  # MAC address

    ra = (ether_head / ipv6_head / ipv6_ra / ipv6_nd_pref / o_route / o_rdns / o_mac)
    return ra


def mac2ipv6(mac):
    # only accept MACs separated by a colon
    parts = mac.split(":")

    # modify parts to match IPv6 value
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = "%x" % (int(parts[0], 16) ^ 2)

    # format output
    ipv6_parts = []
    for i in range(0, len(parts), 2):
        ipv6_parts.append("".join(parts[i:i + 2]))
    ipv6 = IPv6Address("fe80::%s" % (":".join(ipv6_parts))).exploded

    return ipv6


# Create solicited node multicast
def make_sn_mc(addr):
    snmc_prefix = 'FF02:0:0:0:0:1:FF'
    suffix = get_snmc_suffix(addr)
    return snmc_prefix + suffix


def get_snmc_suffix(addr):
    ip = IPv6Address(addr).exploded
    return ip[-7:]
