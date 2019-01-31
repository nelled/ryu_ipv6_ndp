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

from config import cache_entry_timeout, max_poll_count, cache_check_interval
from ndp_proxy import NdpProxy
from packet_creator import create_ns


class CacheManager(NdpProxy):
    """
    Class used to manage the neighbor cache.
    Iterates over the cache regularly and triggers actions depending on entry state.
    """

    def __init__(self, *args, **kwargs):
        super(CacheManager, self).__init__(*args, **kwargs)
        self.ra_thread = hub.spawn(self._cache_check)
        self.cache_entry_timeout = cache_entry_timeout
        self.logger.info("Cache manager running...")

    # Wrapper for cyclic checking for dead entries
    def _cache_check(self):
        while True:
            hub.sleep(cache_check_interval)
            self._checker()

    def _checker(self):
        to_delete = []
        for entry in self.neighbor_cache.entries.values.keys():
            if entry.status == 'PENDING':
                if entry.poll_counter >= max_poll_count:
                    to_delete.append(entry)
                else:
                    ns = create_ns(entry.get_ips()[0], entry.get_mac())
                    self._send_packet(ns)
                    entry.poll_counter += 1
            elif entry.status == 'STALE':
                if entry.get_age() >= self.cache_entry_timeout:
                    entry.set_pending()
                    ns = create_ns(entry.get_ips()[0], entry.get_mac())
                    self._send_packet(ns)
                    entry.poll_counter += 1

        for entry in to_delete:
            self.neighbor_cache.delete_entry_by_entry(entry)

        self.logger.info(str(self.neighbor_cache))
