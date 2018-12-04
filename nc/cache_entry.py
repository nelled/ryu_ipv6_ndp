from time import time
from ipaddress import IPv6Address

# Todo: IP address format. Save as IPv6Address or always
# simply do preprocessing ensuring exploded format?
class CacheEntry:
    """
    Class representing an entry in our neighbor cache. Status is set to ACTIVE on creation.
    If a flow deleted message concerning this entry is received, the status is set to STALE.
    If new traffic for an entry is received, the status is sent so ACTIVE again.
    """
    def __init__(self, ip, mac, cookie):
        self.ips = [ip]
        self.mac = mac
        self.cookie = cookie
        self.status = 'ACTIVE'
        self.last_updated = time()
        self.created_at = time()

    def get_age(self):
        return time() - self.last_updated

    def reset_updated(self):
        self.last_updated = time()

    def set_stale(self):
        self.status = 'STALE'

    def set_active(self):
        self.status = 'ACTIVE'

    def get_ips(self):
        return self.ips

    def get_mac(self):
        return self.mac

    def get_cookie(self):
        return self.cookie

    def has_ip(self, ip):
        if ip in self.ips:
            return True
        else:
            return False

    def add_ip(self, ip):
        self.ips.append(ip)



