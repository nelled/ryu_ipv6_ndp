from ryu.lib import hub

from cache_manager import CacheManager


class RaSender(CacheManager):
    """
    Class used for emitting router advertisements in a regular interval.
    It runs a separate thread that sends a IPv6 RA every 30 seconds.
    The RA is build using scapy.
    """

    def __init__(self, *args, **kwargs):
        super(RaSender, self).__init__(*args, **kwargs)
        self.ra_thread = hub.spawn(self._cyclic_ra)
        self.logger.info("Ra sender running...")

    def _cyclic_ra(self):
        while True:
            print(self.neighbor_cache)
            self._send_ra()
            hub.sleep(30)
