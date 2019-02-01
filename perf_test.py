import re
import subprocess
import time
from collections import defaultdict

# Traffic Control
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.topo import Topo

REMOTE_CONTROLLER_IP = "127.0.0.1"


class SingleSwitchTopo(Topo):
    # Single switch connected to n hosts
    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        switch = self.addSwitch('s1', protocols='OpenFlow13', cls=OVSKernelSwitch)


def run_test(size):
    # Tell mininet to print(useful information
    setLogLevel('info')

    proc = subprocess.Popen(["ryu-manager", "ndp_proxy_runner.py"])

    # Sleep time to give ryu time to start up. Might work with less than 5 seconds
    time.sleep(5)

    topo = SingleSwitchTopo()

    net = Mininet(topo=topo, link=TCLink,
                  controller=None,
                  autoStaticArp=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    net.start()
    switch = net['s1']

    for h in range(size):
        host = net.addHost('h%s' % (h + 1),
                           mac='00:00:00:00:00:%02x' % (h + 1))

        link = net.addLink(host, switch)
        switch.attach(link.intf2)
        host.configDefault()
        print('added host')
        time.sleep(0.05)

    # Time to let DUD take place. Might work with less than 5
    time.sleep(5)
    # Regular expression used to catch the time from output
    p = re.compile('time=(.*?)\sms')

    h1 = net.get('h1')
    result = h1.cmd('ping6 -c1 fe80::200:ff:fe00:2 -I h1-eth0')
    print(result)
    proc.terminate()
    net.stop()
    return p.findall(result)[0]


if __name__ == '__main__':
    # List of topology sizes
    sizes = [100]
    # Number of iterations
    n = 25
    res = defaultdict(lambda: [])
    for size in sizes:
        for i in range(0, 25):
            print(i)
            try:
                res[size].append(run_test(size))
            except IndexError:
                res[size].append(0)

    print(res)
