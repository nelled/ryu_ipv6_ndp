import unittest

from nc.cache_entry import CacheEntry
from nc.multi_dict import MultiDict


class MultiDictTest(unittest.TestCase):

    def test_add_entry_simple(self):
        d = MultiDict()
        d[1] = 2
        self.assertEqual(d[1], 2)

    def test_add_entry_object(self):
        d = MultiDict()
        ip, mac, cookie = '127.0.0.1', '00:00:00:00:00:00', 0
        e = CacheEntry(ip, mac, cookie)
        k, v = (ip, mac, cookie), e
        d[k] = v
        self.assertEqual(d[k], e)

    def test_add_sequentially(self):
        d = MultiDict()
        ip, mac, cookie = '127.0.0.1', '00:00:00:00:00:00', 0
        e = CacheEntry(ip, mac, cookie)
        d[ip] = e
        d[mac] = e
        d[cookie] = e
        assert d[ip] == d[mac] == d[cookie]

    def test_iterload_entry_multi(self):
        d = MultiDict()
        k, v = [1, 2, 3], [1]
        d.iterload(k, v)
        self.assertEqual(d[1], 1)
        self.assertEqual(d[2], 1)
        self.assertEqual(d[3], 1)

    def test_iterload_entry_object(self):
        d = MultiDict()
        ip, mac, cookie = '127.0.0.1', '00:00:00:00:00:00', 0
        e = CacheEntry(ip, mac, cookie)
        k, v = [ip, mac, cookie], [e]
        d.iterload(k,v)
        self.assertEqual(d[ip], e)
        self.assertEqual(d[mac], e)
        self.assertEqual(d[cookie], e)

    def test_delete_entry(self):
        d = MultiDict()
        ip, mac, cookie = '127.0.0.1', '00:00:00:00:00:00', 0
        e = CacheEntry(ip, mac, cookie)
        k, v = [ip, mac, cookie], [e]
        d.iterload(k, v)

        del d[ip]
        with self.assertRaises(KeyError):
            assert d[ip]
        self.assertEqual(d[mac], e)
        self.assertEqual(d[cookie], e)

        del d[mac]
        with self.assertRaises(KeyError):
            assert d[mac]
        self.assertEqual(d[cookie], e)

        del d[cookie]
        with self.assertRaises(KeyError):
            assert d[cookie]
            assert d.values[e]

