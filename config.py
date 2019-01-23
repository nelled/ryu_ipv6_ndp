# Prefix
ipv6_nd_prefix = '2001:db8:1::'

# Use metering
meter_flag = True

# MAC of router to be used in RAs
router_mac = '70:01:02:03:04:05'

# DNS server used in Ras
router_dns = ['2001:db8:1::1']

# Timeout for flow rules associated with cache entries.
# Entries are set to STALE on reception of flow removed message
rule_idle_timeout = 15

# Hard timeout for cache entries, will be deleted if STALE for more then timeout
cache_entry_timeout = 30  # 7200

# Time for which an address will be tentative in the cache
tenative_time = 1

# Max length of statistics deque to prevent flooding
max_msg_buf_len = 1000

# Path for recorded packets
pcap_path = './pcap'

# Base url for REST interface
rest_base_url = '/ndp-proxy'

# Instance name, can be whatever
ndp_proxy_instance_name = 'ndp_proxy'

# Rate for meter at which packets will get dropped
max_rate = 5
