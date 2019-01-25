from flood_check import FloodCheck
from ra_sender import RaSender


class NdpProxyRunner(FloodCheck):

    def __init__(self, *args, **kwargs):
        super(NdpProxyRunner, self).__init__(*args, **kwargs)
        self.logger.info("Starting...")

