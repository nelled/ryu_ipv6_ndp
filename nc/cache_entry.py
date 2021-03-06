from time import time


# Todo: IP address format. Save as IPv6Address or always
# simply do preprocessing ensuring exploded format?
class CacheEntry:
    """
    Class representing an entry in our neighbor cache. Status is set to STALE on creation.
    If a flow deleted message concerning this entry is received, the status is set to STALE.
    If new traffic for an entry is received, the status is sent so ACTIVE. Should the entry be stale for
    more than cache_entry_timeout it is set to PENDING and max_poll_count NS messages are sent to poll the host.
    """

    def __init__(self, ip, mac, cookie, status='STALE'):
        self.ips = [ip]
        self.mac = mac
        self.cookie = cookie
        self.status = status
        self.last_updated = time()
        self.created_at = time()
        self.poll_count = 0

    def get_total_age(self):
        return time() - self.created_at

    def get_age(self):
        return time() - self.last_updated

    def reset_updated(self):
        self.last_updated = time()

    def set_stale(self):
        self.status = 'STALE'
        self.reset_updated()
        self.poll_count = 0

    def set_active(self):
        self.status = 'ACTIVE'
        self.reset_updated()
        self.poll_count = 0

    def set_pending(self):
        self.status = 'PENDING'
        self.reset_updated()

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

    # Gets link layer address if present.
    def get_ll(self):
        # Maybe not safe enough...
        for ip in self.ips:
            if ip.startswith('fe80'):
                return ip
        return None

    def add_ip(self, ip):
        self.ips.append(ip)
