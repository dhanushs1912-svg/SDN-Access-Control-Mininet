"""
Mininet Topology - SDN Access Control System
Project #11 | UE24CS252B Computer Networks
Dhanush S | PES1UG24AM360

Topology: 1 switch, 4 hosts
  h1 (10.0.0.1), h2 (10.0.0.2), h3 (10.0.0.3) - authorized
  h4 (10.0.0.4) - unauthorized, gets blocked by controller
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


class AccessControlTopo(Topo):
    """Single switch, 4 hosts - h1/h2/h3 authorized, h4 unauthorized."""

    def build(self):
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')

        h1 = self.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254')
        h2 = self.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')
        h3 = self.addHost('h3', ip='10.0.0.3/24', defaultRoute='via 10.0.0.254')
        h4 = self.addHost('h4', ip='10.0.0.4/24', defaultRoute='via 10.0.0.254')

        self.addLink(h1, s1, bw=100, delay='5ms')
        self.addLink(h2, s1, bw=100, delay='5ms')
        self.addLink(h3, s1, bw=100, delay='5ms')
        self.addLink(h4, s1, bw=100, delay='5ms')


def run_network():
    topo = AccessControlTopo()

    net = Mininet(
        topo=topo,
        controller=RemoteController('c0', ip='127.0.0.1', port=6653),
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False   # We want to see real ARP traffic
    )

    net.start()

    # Print topology summary
    info("\n" + "=" * 55 + "\n")
    info("  SDN Access Control Topology\n")
    info("=" * 55 + "\n")
    info("  AUTHORIZED  (whitelisted):\n")
    info("    h1 → 10.0.0.1\n")
    info("    h2 → 10.0.0.2\n")
    info("    h3 → 10.0.0.3\n")
    info("  UNAUTHORIZED (will be BLOCKED by controller):\n")
    info("    h4 → 10.0.0.4\n")
    info("=" * 55 + "\n\n")
    info("  Ryu controller must be running before this script.\n")
    info("  Start controller with:\n")
    info("  ryu-manager access_control_controller.py\n\n")
    info("  Suggested test commands inside Mininet CLI:\n")
    info("    h1 ping h2        # Should SUCCEED (both authorized)\n")
    info("    h4 ping h1        # Should FAIL    (h4 unauthorized)\n")
    info("    h1 iperf -s &; h2 iperf -c 10.0.0.1  # Throughput\n")
    info("=" * 55 + "\n\n")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_network()
