from ipaddress import IPv6Address

"""
Some helpers for dealing with addresses.
"""

# Create a link local IP from a MAC
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

# Make solicited node multicast MAC
def make_snmc_mac(addr):
    snmc_mac_prefix_str = '33:33'
    suffix_str = get_snmc_mac_suffix(addr)
    full = snmc_mac_prefix_str + suffix_str
    full = full.replace(':', '')
    return str_to_mac(full)


def str_to_mac(s):
    mac_str = ":".join(s[i:i + 2] for i in range(0, len(s), 2))
    return mac_str


def mac_to_int(mac):
    return int('0x' + mac.replace(':', ''), 16)


# Create solicited node multicast IP
def make_sn_mc(addr):
    snmc_prefix = 'FF02:0:0:0:0:1:FF'
    suffix = get_snmc_suffix(addr)
    res = snmc_prefix + suffix
    sn_mc = IPv6Address(res).exploded
    return sn_mc


def get_snmc_suffix(addr):
    ip = IPv6Address(addr).exploded
    return ip[-7:]


def get_snmc_mac_suffix(addr):
    ip = IPv6Address(addr).exploded
    return ip[-9:]
