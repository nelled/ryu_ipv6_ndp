import time

from ryu.lib import hub

from config import flood_warn_rate
from ra_sender import RaSender


class FloodCheck(RaSender):
    """
    Class used for emitting router advertisements in a regular interval.
    It runs a separate thread that sends a IPv6 RA every config.ra_interval seconds.
    """

    def __init__(self, *args, **kwargs):
        super(FloodCheck, self).__init__(*args, **kwargs)
        self.ra_thread = hub.spawn(self._cyclic_check)
        self.logger.info("Flood checker running...")
        self.last_check = time.time()

    def _cyclic_check(self):
        while True:
            self._check_flood()
            hub.sleep(1)

    def _check_flood(self):
        for k, v in self.port_requests.items():
            v[1] = v[0]
            v[0] = 0
            if v[1] >= flood_warn_rate:
                self.logger.info("Warning, port %s is being flooded with %s requests during the last %s /s...",
                                 k, v[1], time.time() - self.last_check)
        self.last_check = time.time()

