
import time
import sys
from mininet.topo import Topo

import re

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

from mininet.node import RemoteController, OVSKernelSwitch

# Traffic Control
from mininet.link import TCLink

import subprocess

REMOTE_CONTROLLER_IP = "127.0.0.1"

class SingleSwitchTopo(Topo):
    # Single switch connected to n hosts
    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        switch = self.addSwitch('s1', protocols='OpenFlow13', cls=OVSKernelSwitch)
        # Python's range(N) generates 0..N-1

def run_test(size):
# Tell mininet to print(useful information
    setLogLevel('info')

    subprocess.call(["ryu-manager", "ndp_proxy_runner.py"])




    topo = SingleSwitchTopo()

    net = Mininet(topo=topo, link=TCLink,
                  controller=None,
                  autoStaticArp=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    net.start()
    switch = net['s1']


    for h in range(size):

        host = net.addHost('h%s' % (h + 1),
                           mac='00:00:00:00:00:%02x' % (h+1))

        link = net.addLink(host, switch)
        switch.attach(link.intf2)
        host.configDefault()
        time.sleep(0.05)


    time.sleep(5)

    p = re.compile('time=(.*?)\sms')

    h1 = net.get('h1')
    result = h1.cmd('ping6 -c1 2001:db8:1:0:200:ff:fe00:2')
    print(result)
    return p.findall(result)[0]


if __name__ == '__main__':
    print(run_test(3))