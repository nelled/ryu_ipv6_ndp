from ipaddress import IPv6Address

"""
Some helpers for dealing with addresses.
"""


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
    res = snmc_prefix + suffix
    sn_mc = IPv6Address(res).exploded
    return sn_mc


def get_snmc_suffix(addr):
    ip = IPv6Address(addr).exploded
    return ip[-7:]
