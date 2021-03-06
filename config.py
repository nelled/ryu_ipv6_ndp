# Prefix
ipv6_nd_prefix = '2001:db8:1::'

# Use metering
meter_flag = False

# Flag to determine whether to insert an entry for the router into the neighbor cache on startup
insert_router = False

# Router IP
router_ip = ['fe80::7201:2ff:fe03:405']

# MAC of router to be used in RAs
router_mac = '70:01:02:03:04:05'

# DNS server used in Ras
router_dns = ['2001:db8:1::1']

# Timeout for flow rules associated with cache entries.
# Entries are set to STALE on reception of flow removed message
rule_idle_timeout = 15

# Hard timeout for cache entries, will be polled for max_poll_count times each cache_check_interval seconds afterwards
cache_entry_timeout = 20#7200

# Max length of statistics deque to prevent flooding
max_msg_buf_len = 1000

# Path for recorded packets
pcap_path = './pcap'

# Base url for REST interface
rest_base_url = '/ndp-proxy'

# Instance name, can be whatever
ndp_proxy_instance_name = 'ndp_proxy'

# Rate for meter at which packets will get dropped
max_rate = 100

# Router advertisement interval
ra_interval = 30

# Flood warning rate
flood_warn_rate = 100

# Polling attempts before host is considered offline
max_poll_count = 3

# Interval at which cache_manager iterates over cache
cache_check_interval = 2
