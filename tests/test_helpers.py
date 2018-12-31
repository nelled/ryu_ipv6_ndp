import unittest
from ipaddress import IPv6Address

from helpers import mac2ipv6, make_sn_mc


class TestHelpers(unittest.TestCase):

    def test_mac2ipv6(self):
        mac_ips = {'00:00:00:00:00:00': 'fe80::200:00ff:fe00:0000',
                   '52:74:f2:b1:a8:7f': 'fe80::5074:f2ff:feb1:a87f',
                   'FF:FF:FF:FF:FF:FF': 'fe80::fdff:ffff:feff:ffff'}
        for k, v in mac_ips.items():
            converted = mac2ipv6(k)
            expected = IPv6Address(v).exploded
            self.assertEqual(converted, expected)

    def test_make_sn_mc(self):
        ips = {'fe80::2aa:ff:fe28:9c5a': 'ff02::1:ff28:9c5a',
               '2001:db8:aaaa:1::1111:777f': 'FF02::1:FF11:777F'}
        for k, v in ips.items():
            converted = make_sn_mc(k)
            expected = IPv6Address(v).exploded
            self.assertEqual(converted, expected)
