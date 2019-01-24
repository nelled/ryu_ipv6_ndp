import copy

from tabulate import tabulate

from helpers import mac_to_int
from nc.cache_entry import CacheEntry
from nc.multi_dict import MultiDict


class NeighborCache:
    """
    Class representing a neighbor cache. All IPs are combined into one entry.
    """

    # MAC_MASK = 0xFFFFFFFFFFFF
    # COUNTER_MASK = 0xFFFF000000000000

    def __init__(self):
        self.entries = MultiDict()
        self.cookie_counter = 0

    def __str__(self):
        headers = ['MAC', 'IP', 'Total Age', 'Last Updated', 'Cookie', 'Status']
        data = [[v.mac, '\n'.join(v.ips), v.get_total_age(), v.get_age(), v.get_cookie(), v.status] for v in
                self.entries.get_entries_list()]
        return tabulate(data, headers=headers, tablefmt='fancy_grid')

    def add_entry(self, ip, mac, status='CREATED'):
        entry = self.get_entry(mac)
        if not entry:
            cookie = self._gen_cookie(mac)
            self.entries.iterload([mac, ip, cookie], [CacheEntry(ip, mac, cookie, status)])
        else:
            entry.reset_updated()
            if not entry.has_ip(ip):
                entry.add_ip(ip)
                self.entries[ip] = entry
            cookie = entry.cookie

        return cookie

    def get_entry(self, key):
        # Key can be ip, mac, cookie
        return self.entries.get(key, None)

    def delete_entry_by_key(self, key):
        entry = self.get_entry(key)
        if entry:
            keys = copy.copy(self.entries.values[entry])
            for k in keys:
                del self.entries[k]
        return entry

    def delete_entry_by_entry(self, entry):
        keys = copy.copy(self.entries.values[entry])
        for k in keys:
            del self.entries[k]

        return entry

    def set_stale(self, key):
        entry = self.get_entry(key)
        entry.set_stale()

    def get_all_dict(self):
        return self._to_dict(self.entries.get_entries_list())

    def get_active_dict(self):
        return self._to_dict(self._get_active())

    def _gen_cookie(self, mac):
        # Cookie is Counter ORed with MAC
        int_mac = mac_to_int(mac)
        print(int_mac)
        cookie = (self.cookie_counter << 48) | int_mac
        self.cookie_counter = (self.cookie_counter + 1 & 0xFFFF)
        return cookie

    @staticmethod
    def _to_dict(l):
        nc_dict = {v.mac: {
            'mac': v.mac,
            'ips': v.ips,
            'tot_age': v.get_total_age(),
            'age': v.get_age(),
            'cookie': v.get_cookie(),
            'status': v.status} for v in l}
        return nc_dict

    def _get_active(self):
        entries_list = self.entries.get_entries_list()
        active_entries = [v for v in entries_list if v.status == 'ACTIVE']
        return active_entries


