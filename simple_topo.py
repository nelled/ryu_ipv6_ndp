#!/usr/bin/python
import random
import time

from mininet.topo import Topo

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

from mininet.node import RemoteController, OVSKernelSwitch

# Traffic Control
from mininet.link import TCLink

REMOTE_CONTROLLER_IP = "127.0.0.1"

class SingleSwitchTopo(Topo):
    # Single switch connected to n hosts
    def __init__(self, n=2, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        switch = self.addSwitch('s1', protocols='OpenFlow13', cls=OVSKernelSwitch)
        # Python's range(N) generates 0..N-1
        for h in range(n):
            host = self.addHost('h%s' % (h + 1))
            delay = random.randint(1, 100)
            delay = '%sms' % delay
            self.addLink(host, switch, bw=10, delay=delay)
            #self.addLink(host, switch, bw=10)


topos = {'singleswitchtopo': SingleSwitchTopo}


if __name__ == '__main__':
    # Tell mininet to print(useful information
    setLogLevel('info')

    topo = SingleSwitchTopo(n=5)

    net = Mininet(topo=topo, link=TCLink,
                  controller=None,
                  autoStaticArp=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    CLI(net)
    net.stop()

# sudo mn --custom ./single_switch.py --topo singleswitchtopo --controller=remote,ip=127.0.0.1