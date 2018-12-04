
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
from switch_v6 import SimpleSwitch13



class CacheManager(SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(CacheManager, self).__init__(*args, **kwargs)
        self.ra_thread = hub.spawn(self._cache_check)

    # Wrapper for cyclic checking for dead entries
    def _cache_check(self):
        while True:
            self._check_entries()
            print(self.neighbor_cache)
            hub.sleep(cache_entry_timeout)

    # Checks cache entries and updates state depending on timer
    def _check_entries(self):
        self.logger.info("Deleting old entries...")
        to_delete = []
        for entry in self.neighbor_cache.entries.values.keys():
            if entry.last_updated >= cache_entry_timeout and entry.status == 'STALE':
                to_delete.append(entry)
        for entry in to_delete:
            self.neighbor_cache.delete_entry_by_entry(entry)
