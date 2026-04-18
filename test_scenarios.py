#!/usr/bin/env python3
"""
Test Scenarios - SDN Access Control System
Project #11 | UE24CS252B Computer Networks
Dhanush S | PES1UG24AM360

Runs automated tests:
  Scenario 1 - Authorized vs Unauthorized (allowed vs blocked)
  Scenario 2 - Flow table inspection
  Scenario 3 - iperf throughput
  Regression  - Policy consistency
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info, error
from mininet.topo import Topo
import time
import subprocess


class AccessControlTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        for h in [h1, h2, h3, h4]:
            self.addLink(h, s1, bw=100, delay='5ms')


def print_section(title):
    info("\n" + "=" * 60 + "\n")
    info(f"  {title}\n")
    info("=" * 60 + "\n")


def dump_flow_table(switch_name="s1"):
    """Show current flow rules on the switch."""
    info(f"\n[FLOW TABLE] {switch_name}:\n")
    result = subprocess.run(
        ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch_name],
        capture_output=True, text=True
    )
    info(result.stdout + "\n")


def run_tests():
    topo = AccessControlTopo()
    net = Mininet(
        topo=topo,
        controller=RemoteController('c0', ip='127.0.0.1', port=6653),
        link=TCLink,
        autoSetMacs=True
    )
    net.start()
    time.sleep(2)   # wait for controller to register switch

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    # ================================================================
    # SCENARIO 1 – Authorized vs Unauthorized (Allowed vs Blocked)
    # ================================================================
    print_section("SCENARIO 1: Authorized vs Unauthorized Traffic")

    info("\n[TEST 1a] h1 (auth) --> h2 (auth)  — Expected: REACHABLE\n")
    result = h1.cmd('ping -c 4 10.0.0.2')
    info(result)
    passed = "0% packet loss" in result or "bytes from" in result
    info(f"  RESULT: {'✓ PASS – packets delivered' if passed else '✗ FAIL'}\n")

    info("\n[TEST 1b] h1 (auth) --> h3 (auth)  — Expected: REACHABLE\n")
    result = h1.cmd('ping -c 4 10.0.0.3')
    info(result)
    passed = "0% packet loss" in result or "bytes from" in result
    info(f"  RESULT: {'✓ PASS – packets delivered' if passed else '✗ FAIL'}\n")

    info("\n[TEST 1c] h4 (UNAUTH) --> h1 (auth)  — Expected: BLOCKED\n")
    result = h4.cmd('ping -c 4 10.0.0.1')
    info(result)
    blocked = "100% packet loss" in result or "0 received" in result
    info(f"  RESULT: {'✓ PASS – traffic BLOCKED by controller' if blocked else '✗ FAIL – traffic leaked through'}\n")

    info("\n[TEST 1d] h4 (UNAUTH) --> h2 (auth)  — Expected: BLOCKED\n")
    result = h4.cmd('ping -c 4 10.0.0.2')
    info(result)
    blocked = "100% packet loss" in result or "0 received" in result
    info(f"  RESULT: {'✓ PASS – traffic BLOCKED by controller' if blocked else '✗ FAIL – traffic leaked through'}\n")

    # ================================================================
    # SCENARIO 2 – Flow table inspection (Performance & Validation)
    # ================================================================
    print_section("SCENARIO 2: Flow Table Inspection")

    info("[INFO] Flow table BEFORE traffic from authorized hosts:\n")
    dump_flow_table("s1")

    info("\n[ACTION] Generating authorized traffic (h1 <--> h2)...\n")
    h1.cmd('ping -c 2 10.0.0.2 > /dev/null 2>&1')
    time.sleep(1)

    info("[INFO] Flow table AFTER authorized traffic:\n")
    dump_flow_table("s1")

    info("\n[ACTION] Generating unauthorized traffic (h4 --> h1)...\n")
    h4.cmd('ping -c 2 10.0.0.1 > /dev/null 2>&1')
    time.sleep(1)

    info("[INFO] Flow table AFTER unauthorized traffic (drop rule installed):\n")
    dump_flow_table("s1")

    # ================================================================
    # SCENARIO 3 – iperf Throughput (Authorized path)
    # ================================================================
    print_section("SCENARIO 3: Throughput Measurement (h1 → h2)")

    info("[ACTION] Starting iperf server on h2...\n")
    h2.cmd('iperf -s -u &')
    time.sleep(1)

    info("[ACTION] Running iperf client from h1 to h2 (UDP, 5 sec)...\n")
    result = h1.cmd('iperf -c 10.0.0.2 -u -t 5')
    info(result)

    h2.cmd('kill %iperf')

    # ================================================================
    # REGRESSION TEST – Policy consistency check
    # ================================================================
    print_section("REGRESSION TEST: Verify Policy Consistency")

    info("[INFO] Verifying h4 remains blocked after flow table update...\n")
    result = h4.cmd('ping -c 3 10.0.0.3')
    info(result)
    blocked = "100% packet loss" in result or "0 received" in result
    info(f"  REGRESSION RESULT: "
         f"{'✓ PASS – h4 still blocked (policy consistent)' if blocked else '✗ FAIL – policy violated'}\n")

    info("[INFO] Verifying h1→h2 still works after policy re-check...\n")
    result = h1.cmd('ping -c 3 10.0.0.2')
    info(result)
    passed = "0% packet loss" in result or "bytes from" in result
    info(f"  REGRESSION RESULT: "
         f"{'✓ PASS – authorized traffic unaffected' if passed else '✗ FAIL'}\n")

    print_section("ALL TESTS COMPLETE")
    info("Check controller terminal for detailed ALLOWED/BLOCKED logs.\n\n")

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_tests()
