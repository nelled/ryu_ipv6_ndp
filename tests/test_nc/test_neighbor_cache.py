import unittest

from nc.neighbor_cache import NeighborCache


class TestNeighborCache(unittest.TestCase):

    def test_add_entry(self):
        nc = NeighborCache()
        ip, mac = '127.0.0.1', '00:00:00:00:00:00'
        nc.add_entry(ip, mac)
        assert nc.entries[ip]
        assert nc.entries[mac]

    def test_get_entry(self):
        nc = NeighborCache()
        ip, mac = '127.0.0.1', '00:00:00:00:00:00'
        nc.add_entry(ip, mac)
        assert nc.get_entry(ip)
        assert nc.get_entry(mac)
        self.assertEqual(nc.get_entry('0.0.0.0'), None)

    def test_delete_entry_by_key(self):
        nc = NeighborCache()
        ip, mac = '127.0.0.1', '00:00:00:00:00:00'
        nc.add_entry(ip, mac)
        entry = nc.get_entry(mac)
        nc.delete_entry_by_key(mac)
        self.assertEqual(nc.get_entry(mac), None)
        self.assertEqual(nc.get_entry(ip), None)
        with self.assertRaises(KeyError):
            assert nc.entries.values[entry]

    def test_delete_entry_by_entry(self):
        nc = NeighborCache()
        ip, mac = '127.0.0.1', '00:00:00:00:00:00'
        nc.add_entry(ip, mac)
        entry = nc.get_entry(mac)
        nc.delete_entry_by_entry(entry)
        self.assertEqual(nc.get_entry(mac), None)
        self.assertEqual(nc.get_entry(ip), None)
        with self.assertRaises(KeyError):
            assert nc.entries.values[entry]

    def test_add_existing(self):
        nc = NeighborCache()
        ip, mac = '127.0.0.1', '00:00:00:00:00:00'
        nc.add_entry(ip, mac)
        entry_a = nc.get_entry(ip)
        ip2 = '111.111.111.111'
        nc.add_entry(ip2, mac)
        entry_b = nc.get_entry(ip2)
        self.assertEqual(entry_a, entry_b)
        self.assertTrue(entry_a.has_ip(ip))
        self.assertTrue(entry_a.has_ip(ip2))
