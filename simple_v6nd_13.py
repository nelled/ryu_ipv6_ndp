# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.lib import hub
from scapy import all as scapy



# Application that uses simple_switch_13 for packet switching
# it runs a separate thread that sends a IPv6 RouterAdvertisement
# every 30 seconds.
# The RouterAdvertisement is build using scapy
from switch_v6 import SimpleSwitch13
from config import router_mac
from helpers import mac2ipv6


class SimpleV6nd13(SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleV6nd13, self).__init__(*args, **kwargs)
        self.ra_thread = hub.spawn(self._cyclic_ra)

    def _cyclic_ra(self):
        while True:
            print(self.neighbor_cache)
            self._send_ra()
            hub.sleep(30)




