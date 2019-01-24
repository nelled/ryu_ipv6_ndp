from ryu.lib import hub

from cache_manager import CacheManager
from config import ra_interval


class RaSender(CacheManager):
    """
    Class used for emitting router advertisements in a regular interval.
    It runs a separate thread that sends a IPv6 RA every config.ra_interval seconds.
    """

    def __init__(self, *args, **kwargs):
        super(RaSender, self).__init__(*args, **kwargs)
        self.ra_thread = hub.spawn(self._cyclic_ra)
        self.logger.info("Ra sender running...")

    def _cyclic_ra(self):
        while True:
            self._send_ra()
            hub.sleep(ra_interval)
