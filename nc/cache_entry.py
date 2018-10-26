from time import time
from ipaddress import IPv6Address

# Todo: IP address format. Save as IPv6Address or always
# simply do preprocessing ensuring exploded format?
class CacheEntry:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.state = 'REACHABLE'
        self.last_updated = time()

    def get_age(self):
        return time() - self.last_updated

    def get_ip(self):
        return self.ip

    def get_mac(self):
        return self.mac

    def get_state(self):
        return self.state

    def set_reachable(self):
        self.state = 'REACHABLE'

    def set_stale(self):
        self.state = 'STALE'

    def set_probe(self):
        self.state = 'PROBE'

    def set_delete(self):
        self.state = 'DELETE'
