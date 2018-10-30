# from https://stackoverflow.com/questions/37140846/how-to-convert-ipv6-link-local-address-to-mac-address-in-python
# TODO: Check if scapy has this method, it has several other tools for validity checking etc.
from ipaddress import IPv6Address


def mac2ipv6(mac):
    # only accept MACs separated by a colon
    parts = mac.split(":")

    # modify parts to match IPv6 value
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = "%x" % (int(parts[0], 16) ^ 2)

    # format output
    ipv6Parts = []
    for i in range(0, len(parts), 2):
        ipv6Parts.append("".join(parts[i:i + 2]))
    ipv6 = IPv6Address("fe80::%s" % (":".join(ipv6Parts))).exploded

    return ipv6


# Create solicited node multicast
def make_sn_mc(addr):
    snmc_prefix = 'FF02:0:0:0:0:1:FF'
    suffix = get_snmc_suffix(addr)
    return snmc_prefix + suffix


def get_snmc_suffix(addr):
    ip = IPv6Address(addr).exploded
    return ip[-7:]


# TODO: implement
def create_ra():
    pass


# TODO: implement
def create_ns():
    pass


# TODO: implement
def create_na():
    pass


if __name__ == "__main__":
    print(mac2ipv6('70:01:02:03:04:05'))
