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



# Application that uses ndp_proxy for packet switching
# it runs a separate thread that sends a IPv6 RouterAdvertisement
# every 30 seconds.
# The RouterAdvertisement is build using scapy
from cache_manager import CacheManager


class RaSender(CacheManager):

    def __init__(self, *args, **kwargs):
        super(RaSender, self).__init__(*args, **kwargs)
        self.ra_thread = hub.spawn(self._cyclic_ra)
        self.logger.info("Ra sender running...")

    def _cyclic_ra(self):
        while True:
            print(self.neighbor_cache)
            self._send_ra()
            hub.sleep(30)




