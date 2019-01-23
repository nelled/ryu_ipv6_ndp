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

from config import cache_entry_timeout
from ndp_proxy import NdpProxy
from packet_creator import create_ns


class CacheManager(NdpProxy):

    def __init__(self, *args, **kwargs):
        super(CacheManager, self).__init__(*args, **kwargs)
        self.ra_thread = hub.spawn(self._cache_check)
        self.cache_entry_timeout = cache_entry_timeout
        self.logger.info("Cache manager running...")

    # Wrapper for cyclic checking for dead entries
    def _cache_check(self):
        # TODO: Check timings
        while True:
            hub.sleep(5)
            self._check_entries()
            self._delete_entries()
            self._delete_pending()

    def _check_entries(self):
        self.logger.debug("Checking old entries...")
        for entry in self.neighbor_cache.entries.values.keys():
            if entry.get_age() >= self.cache_entry_timeout / 2 and entry.status == 'STALE':
                self.logger.debug("Probing entry: %s %s", entry.get_ips()[0], entry.get_mac())
                entry.set_inactive()
                ns = create_ns(entry.get_ips()[0], entry.get_mac())
                self._send_packet(ns)

    # Checks cache entries and updates state depending on timer
    def _delete_entries(self):
        self.logger.debug("Deleting old entries...")
        to_delete = []
        for entry in self.neighbor_cache.entries.values.keys():
            if entry.get_age() >= self.cache_entry_timeout / 2 and entry.status == 'INACTIVE':
                to_delete.append(entry)
        for entry in to_delete:
            self.neighbor_cache.delete_entry_by_entry(entry)

    def _delete_pending(self):
        self.logger.debug("Deleting pending entries...")
        to_delete = []
        for entry in self.neighbor_cache.entries.values.keys():
            if entry.get_age() >= 5 and entry.status == 'PENDING':
                to_delete.append(entry)
        for entry in to_delete:
            self.neighbor_cache.delete_entry_by_entry(entry)
        self.logger.info(str(self.neighbor_cache))
