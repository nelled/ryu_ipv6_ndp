from flood_checker import FloodChecker
from ra_sender import RaSender


class NdpProxyRunner(FloodChecker):
    """
    Wrapper to start inheritance cascade and ultimately the app.
    """

    def __init__(self, *args, **kwargs):
        super(NdpProxyRunner, self).__init__(*args, **kwargs)
        self.logger.info("Starting...")

