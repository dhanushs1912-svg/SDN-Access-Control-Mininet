# SDN-Based Access Control System

**Course:** UE24CS252B – Computer Networks  
**Project:** #11 – SDN Mininet (Orange Problem)  
**Author:** Dhanush S | **SRN:** PES1UG24AM360  
**Controller:** Ryu + OpenFlow 1.3 | **Emulator:** Mininet

---

## Problem Statement

Design and implement an SDN-based Access Control System using Mininet and the Ryu OpenFlow controller. Only **authorized (whitelisted)** hosts may communicate within the network. Any traffic originating from an **unauthorized host** must be detected and **dropped** via explicit OpenFlow flow rules. The system must log every allow/deny decision and be validated through live test scenarios.

---

## Network Topology

```
          ┌────────────────────────────────────┐
          │        OVS Switch  s1              │
          │  (Controlled by Ryu – OF 1.3)      │
          └──┬──────┬──────┬──────┬────────────┘
             │      │      │      │
            h1     h2     h3     h4
        10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4
        (AUTH)   (AUTH)   (AUTH)   (UNAUTH ✗)
```

| Host | IP         | Status            |
|------|------------|-------------------|
| h1   | 10.0.0.1   | ✅ Authorized      |
| h2   | 10.0.0.2   | ✅ Authorized      |
| h3   | 10.0.0.3   | ✅ Authorized      |
| h4   | 10.0.0.4   | ❌ Unauthorized   |

---

## SDN Logic & Flow Rule Design

### Controller Decision Flow

```
Packet arrives at switch → no matching rule → packet_in sent to controller
        │
        ├─ ARP?  → Allow through (needed for host discovery)
        │
        └─ IPv4?
               │
               ├─ src_ip IN whitelist?
               │       YES → install forwarding rule (priority=5, idle=20s)
               │              forward packet normally
               │
               └─ src_ip NOT in whitelist?
                       NO  → install DROP rule (priority=10, idle=30s)
                              discard packet silently
```

### OpenFlow Rule Priority Table

| Priority | Match                    | Action  | Purpose                    |
|----------|--------------------------|---------|----------------------------|
| 0        | (any)                    | → ctrl  | Table-miss / catch-all     |
| 5        | ip_src=auth, ip_dst=auth | forward | Authorized forwarding rule |
| 10       | ip_src=unauthorized      | DROP    | Block unauthorized host    |

> **Drop rules use an empty action list** — OpenFlow interprets no actions as discard.

---

## Setup & Execution Steps

### Prerequisites
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install mininet -y
sudo apt install python3-pip -y
pip3 install ryu --break-system-packages
```

### Step 1 — Start the Ryu Controller
Open **Terminal 1**:
```bash
ryu-manager access_control_controller.py
```
You should see:
```
SDN Access Control Controller Started
Authorized hosts : {'10.0.0.1', '10.0.0.2', '10.0.0.3'}
```

### Step 2 — Start the Mininet Topology
Open **Terminal 2**:
```bash
sudo python3 topology.py
```
The Mininet CLI (`mininet>`) will appear.

### Step 3 — Clean up between runs
```bash
sudo mn -c
```

---

## Test Scenarios & Expected Output

### Scenario 1 — Authorized vs Unauthorized Traffic

**Inside Mininet CLI:**

```bash
# Test 1: Authorized hosts communicate (SHOULD SUCCEED)
mininet> h1 ping -c 4 h2
# Expected: 0% packet loss

# Test 2: Unauthorized host blocked (SHOULD FAIL / 100% loss)
mininet> h4 ping -c 4 h1
# Expected: 100% packet loss  ← blocked by drop rule
```

**Controller terminal output (Scenario 1):**
```
[FWRD] AUTHORIZED : 10.0.0.1 --> 10.0.0.2 | Total allowed pkts: 1
[DROP] UNAUTHORIZED: 10.0.0.4 --> 10.0.0.1 | Total blocked pkts: 1
```

### Scenario 2 — Flow Table Inspection

```bash
# View installed flow rules on switch s1
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

**Expected output after scenario 1:**
```
cookie=0x0, priority=10, ip,nw_src=10.0.0.4  actions=drop
cookie=0x0, priority=5,  ip,nw_src=10.0.0.1,nw_dst=10.0.0.2  actions=output:2
cookie=0x0, priority=0   actions=CONTROLLER:65535
```

### Scenario 3 — Throughput (iperf)

```bash
mininet> h2 iperf -s &
mininet> h1 iperf -c 10.0.0.2 -t 5
# Expected: ~Mbps throughput shown

mininet> h4 iperf -c 10.0.0.1 -t 5
# Expected: connection refused / 0 transfer (blocked)
```

### Regression Test — Policy Consistency

Run the automated test script:
```bash
sudo python3 test_scenarios.py
```

---

## Proof of Execution

*(Add screenshots here)*

### Required Screenshots / Logs

- [ ] `h1 ping h2` → 0% packet loss (authorized)
- [ ] `h4 ping h1` → 100% packet loss (blocked)
- [ ] `ovs-ofctl dump-flows s1` → shows DROP rule for 10.0.0.4
- [ ] Controller terminal → ALLOWED / BLOCKED log lines
- [ ] iperf throughput result between h1 and h2

---

## Performance Observations

| Metric        | h1 ↔ h2 (authorized) | h4 → h1 (unauthorized) |
|---------------|-----------------------|------------------------|
| Latency (ping)| ~5–10 ms              | N/A (blocked)          |
| Throughput    | ~90–95 Mbps           | 0 Mbps (dropped)       |
| Flow rule     | forward (priority 5)  | DROP (priority 10)     |
| 1st packet    | via controller        | via controller         |
| 2nd+ packets  | match in flow table   | match DROP rule        |

---

## File Structure

```
sdn_access_control/
├── access_control_controller.py   # Ryu OpenFlow controller
├── topology.py                    # Mininet custom topology
├── test_scenarios.py              # Automated test runner
└── README.md                      # This file
```

---

## References

1. Ryu SDN Framework – https://ryu.readthedocs.io/en/latest/
2. OpenFlow 1.3 Specification – https://opennetworking.org/software-defined-standards/specifications/
3. Mininet Walkthrough – https://mininet.org/walkthrough/
4. Open vSwitch Documentation – https://docs.openvswitch.org/
5. Mininet GitHub – https://github.com/mininet/mininet
