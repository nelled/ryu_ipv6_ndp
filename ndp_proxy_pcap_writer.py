from time import strftime, gmtime

from ryu.lib import pcaplib
from scapy.utils import PcapWriter

from config import pcap_path


class NdpProxyPcapWriter:

    def __init__(self):
        self.pcap_all_path = self._make_pcap_path('all_')
        self.pcap_generated_path = self._make_pcap_path('generated_')
        self.write_pcap_all_handle = None
        self.write_pcap_all_writer = None
        self.write_pcap_generated_writer = None

    @staticmethod
    def _make_pcap_path(prefix):
        time_string = strftime('%Y%m%d_%H%M%S', gmtime())
        return pcap_path + '/' + prefix + time_string + '.pcap'

    def toggle_write_pcap(self, flags):
        self._toggle_write_pcap_all(bool(flags['all']))
        self._toggle_write_pcap_generated(bool(flags['generated']))

    def _toggle_write_pcap_all(self, flag):
        if flag:
            if not self.write_pcap_all_writer:
                self.write_pcap_all_handle = open(self.pcap_all_path, 'ab')
                self.write_pcap_all_writer = pcaplib.Writer(self.write_pcap_all_handle)
        else:
            try:
                self.write_pcap_all_handle.close()
                self.write_pcap_all_writer = None
            except AttributeError:
                pass

    def _toggle_write_pcap_generated(self, flag):
        if flag:
            if not self.write_pcap_generated_writer:
                self.write_pcap_generated_writer = PcapWriter(self.pcap_generated_path, append=True, sync=True)
        else:
            try:
                self.write_pcap_generated_writer.close()
                self.write_pcap_generated_writer = None
            except AttributeError:
                pass

    def write_pcap_all(self, msg):
        if self.write_pcap_all_writer:
            print("Writing a received packet")
            self.write_pcap_all_writer.write_pkt(msg.data)
            self.write_pcap_all_handle.flush()

    def write_pcap_generated(self, msg):
        if self.write_pcap_generated_writer:
            print("Writing a generated packet")
            self.write_pcap_generated_writer.write(msg)
