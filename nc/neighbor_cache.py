from tabulate import tabulate

from nc.cache_entry import CacheEntry


class NeighborCache:
    def __init__(self):
        self.entries = {}

    def add_entry(self, ip, mac):
        self.entries[ip] = CacheEntry(ip, mac)

    def get_entry(self, ip):
        if self.entries[ip]:
            return self.entries[ip]
        else:
            return None

    def __str__(self):
        headers = ['IP', 'MAC', 'State', 'Age']
        data = [[v.ip, v.mac, v.state, v.get_age()] for k, v in self.entries.items()]
        return tabulate(data, headers=headers, tablefmt='fancy_grid')
