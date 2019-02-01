# Running the app
The app is started via 
```bash
ryu-manager ndp_proxy_runner.py
```
Providing the `--verbose` flag to `ryu-manager` results in (a lot) more output.

# Creating a topology with Mininet
Using `sudo mn --topo single,3 --mac --controller remote --switch ovsk` 
or a similar command to start minnet from the command line is discouraged, as hosts are added to fast.
It is best to use the `simple_topo.py` script via
```bash
sudo python simple_topo.py <node_count>
```
as it adds a delay between the addition of each host. If the `insert_router` flag is set in the `config`
file, a router host is added as well. This can be uncommented safely.

# Checking the flow table
To verify which flow rules are present in the switch `sudo ovs-ofctl -O Openflow13 dump-flows s1
`can be used.

# The REST interface
The following URLs can be used to access the REST interface. It can be extended at
will in `ndp_proxy_controller.py` following the pattern of the other routes. Keep in mind that
the IP and port might be different.

Get the neighbor cache: `http://0.0.0.0:8080/ndp-proxy/all-hosts`

All hosts currently set to active: `http://0.0.0.0:8080/ndp-proxy/active-hosts
`
Statistics: 
`http://0.0.0.0:8080/ndp-proxy/statistics`

The current rate a port is receiving ICMPv6 packets at: 
`http://0.0.0.0:8080/ndp-proxy/flood-info`

In order to toggle packets being written to a `.pcap` file in `./pcap`,
```bash
curl -X PUT -d '{"all": 0, "generated": 0}' http://0.0.0.0:8080/ndp-proxy/write-pcap
```
can be used.

# Structure of the project
```bash
.
├── cache_manager.py  // Manages the cache
├── config.py         // Set parameters           
├── flood_checker.py  // Calculates rate at which packets arrive at each port
├── helpers.py        // Some misc functions
├── __init__.py
├── nc
│   ├── cache_entry.py  // Representation of a cache entry
│   ├── __init__.py
│   ├── multi_dict.py   // Data structure holding the cache
│   ├── neighbor_cache.py  // Class representing the cache
├── ndp_proxy_controller.py // Class exposing the REST interface
├── ndp_proxy_pcap_writer.py // Class enabling the writing of *.pcap traces
├── ndp_proxy.py  // The main app, processes incoming packets
├── ndp_proxy_runner.py  // Wrapper script starting the whole app
├── packet_creator.py    // Functions to create packets with scapy
├── pcap  // Directory *.pcap files are written to
│   ├── generated_20181211_114711.pcap
├── perf_test.py  // Script enabling performance testing
├── ra_sender.py  // Class sending RAs at regular intervals
├── readme.md
├── requirements.txt  // Requirements for the app to run
├── simple_switch_13.py  // Standard L2 switching application shipped with Ryu
├── simple_topo.py  // Script for topology creation with delay
└── tests  // Some tests, inexhaustive and not particularly good
    ├── __init__.py
    ├── runner.py
    ├── test_helpers.py
    └── test_nc
        ├── __init__.py
        ├── test_multi_dict.py
        └── test_neighbor_cache.py

```