# CIP-B103 Lab 5 – ARP Poisoning Forensics

**Student:** Fuseini Imoru Kantuogaa
**Course:** CIP-B103
**Lab:** Lab 5 – ARP Spoofing / Poisoning Network Forensics
**Environment:** Kali Linux

## Overview

This lab covers **network forensic analysis of ARP (Address Resolution
Protocol) traffic**, comparing a baseline (normal) ARP capture against
a captured ARP poisoning attack. It demonstrates evidence acquisition
and hashing, live packet capture with `tshark`, host network state
documentation, and structured field-level extraction/filtering of ARP
packets to detect spoofed IP-to-MAC address claims — a core indicator
of ARP cache poisoning (man-in-the-middle) attacks.

## Case Folder Structure

```bash
mkdir -p ~/CIP-B103-Lab5/{evidence,working,exported,reports,screenshots,scripts}
cd ~/CIP-B103-Lab5
```

```
CIP-B103-Lab5/
├── evidence/     # original captured/downloaded pcap evidence
├── working/      # working copies for analysis
├── exported/     # exported/derived data
├── reports/      # all command output logs, hashes, extracted fields
├── screenshots/  # visual evidence
└── scripts/      # any automation scripts
```

## 1. Tool Setup & Evidence Acquisition

Installed the required network forensics tools and downloaded a sample
ARP capture file for baseline practice:

```bash
sudo apt install -y wireshark tshark python3-scapy net-tools
wget -O evidence/arp.pcap \
  '<sample_arp_pcap_url>'
```

- Made a **working copy** of the evidence file (`working/arp_working.pcap`)
  to analyze, preserving the original in `evidence/` untouched
- Hashed both the original and the working copy with SHA-256 to confirm
  they are byte-identical, logged to `reports/arp_capture_hashes.txt`

```bash
cp --preserve-timestamps evidence/arp.pcap working/arp_working.pcap
sha256sum evidence/arp.pcap working/arp_working.pcap | tee reports/arp_capture_hashes.txt
```

| File | SHA-256 |
|---|---|
| `evidence/arp.pcap` | `342a75dc002d090cc7fd108994b6c0c9c8eaa3962cf642159b4507d5615adc3e` |
| `working/arp_working.pcap` | (identical — matches above) |

## 2. Host Network State Documentation

Captured the analysis machine's network configuration **before** any
capture or attack simulation, for baseline comparison and reporting:

```bash
ip -br address | tee reports/interfaces.txt
ip route | tee reports/routes.txt
ip neigh show | tee reports/arp_table_initial.txt
```

- Interface `eth0`: `192.168.44.128/24`
- Default gateway: `192.168.44.2` via `eth0`
- Initial ARP cache (`ip neigh`) showed two known entries for
  `192.168.44.254` and `192.168.44.2`

Dynamically captured interface and gateway values for later use in
capture commands:

```bash
IFACE=eth0
GATEWAY_IP=$(ip route | awk '/default/ {print $3; exit}')
```

## 3. Baseline ("Normal") ARP Capture

Captured a 20-second window of **normal** ARP traffic (no attack) to
establish a baseline of expected ARP behavior:

```bash
sudo tshark -i "$IFACE" -f 'arp' -a duration:20 -w /tmp/normal_arp.pcapng &
ping -c 1 "$GATEWAY_IP"
```

- After capture, flushed the local ARP cache (`sudo ip neigh flush`) to
  force fresh ARP resolution, then re-ran a fresh 20-second capture to
  ensure a clean baseline sample
- Moved the capture into the evidence folder with correct ownership:

```bash
sudo cp /tmp/normal_arp.pcapng evidence/
sudo chown kali:kali evidence/normal_arp.pcapng
```

### Baseline capture findings

```bash
tshark -r evidence/normal_arp.pcapng -Y arp
```

- Frame 1–2: A legitimate ARP request/reply pair — `Who has
  192.168.44.2? Tell 192.168.44.128` → `192.168.44.2 is at
  00:50:56:f4:fd:61`
- Frames 3–11: Repeated broadcast ARP requests from
  `VMware_c0:00:08` asking `Who has 192.168.44.2? Tell 192.168.44.1`
  with **no corresponding reply captured** — consistent with normal
  gateway/host ARP probing traffic, not an attack pattern (single
  source, standard broadcast requests, no conflicting replies)

### Field-level extraction (baseline)

Extracted structured ARP fields (timestamp, MACs, opcode, IPs) to a
TSV report for detailed review:

```bash
tshark -r evidence/normal_arp.pcapng -Y 'arp' -T fields \
  -e frame.number -e frame.time -e eth.src -e eth.dst \
  -e arp.opcode -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
  | tee reports/normal_arp_fields.tsv
```

## 4. Identifying ARP Replies & IP–MAC Ownership Claims

Filtered specifically for **ARP replies (opcode 2)** in the working
capture — the packets that actually assert "this IP belongs to this
MAC address," which is the mechanism ARP poisoning attacks abuse:

```bash
PCAP=working/arp_working.pcap
tshark -r "$PCAP" -Y 'arp.opcode==2' -T fields \
  -e frame.number -e frame.time_epoch -e eth.src -e eth.dst \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
  | tee reports/arp_replies.tsv
```

**Counted unique IP-to-MAC claims** made by ARP replies in the capture
— a legitimate network should show exactly **one MAC per IP**; multiple
MACs claiming the same IP is a direct indicator of ARP spoofing:

```bash
tshark -r "$PCAP" -Y 'arp.opcode==2' -T fields \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  | sort | uniq -c | sort -nr \
  | tee reports/ip_mac_claims.txt
```

Result (baseline sample):
```
1  136.160.215.194  00:50:56:86:02:65
1  136.160.215.15   00:50:56:86:cb:fc
```
— one MAC per IP, confirming **no spoofing present** in this sample
capture.

Also isolated **unicast** ARP replies (`eth.dst != ff:ff:ff:ff:ff:ff`)
specifically, since spoofed replies are frequently sent directly
(unicast) to the victim rather than broadcast:

```bash
tshark -r "$PCAP" \
  -Y 'arp.opcode==2 && eth.dst!=ff:ff:ff:ff:ff:ff' -T fields \
  -e frame.number -e frame.time -e arp.src.proto_ipv4 \
  -e arp.src.hw_mac -e eth.dst \
  | tee reports/unicast_arp_replies.tsv
```

## 5. Controlled ARP Poisoning Capture Setup

Re-documented network state immediately before the controlled attack
capture for a clean chain-of-custody baseline:

```bash
ip -br address
ip route
ip neigh show | tee reports/arp_table_before.txt
```

Started a background 40-second ARP capture to record the controlled
poisoning simulation as it occurred:

```bash
IFACE=eth0
sudo tshark -i "$IFACE" -f 'arp' -a duration:40 \
  -w evidence/controlled_arp_poison.pcapng &
```

- Initial attempt failed (file path/permission issue writing directly
  to `evidence/`), corrected by capturing to `/tmp/` first:

```bash
sudo tshark -i "$IFACE" -f 'arp' -a duration:40 \
  -w /tmp/controlled_arp_poison.pcapng &
```

## 6. Post-Capture ARP Cache Verification

After the capture completed, verified the live ARP cache state and
confirmed no unauthorized/rogue ARP process was left running:

```bash
sudo ip neigh flush all
ping -c 1 192.168.44.2
ip neigh show
ps aux | grep -E '[a]rp.py|[s]capy' | tee reports/process_check.txt
```

Confirmed the gateway (`192.168.44.2`) resolved correctly to its
legitimate MAC (`00:50:56:f4:fd:61`, marked `REACHABLE`) after the
cache flush and re-ping, and no lingering spoofing script/process was
found running on the system.

## Key Tools Used

| Tool | Purpose |
|---|---|
| `wireshark` / `tshark` | Packet capture and ARP traffic analysis |
| `python3-scapy` | Packet crafting/analysis capability (available for scripted attacks) |
| `net-tools` | Legacy networking utilities |
| `ip -br address` / `ip route` / `ip neigh` | Host network interface, routing, and ARP cache inspection |
| `sha256sum` | Evidence integrity verification |
| `tshark -T fields` | Structured field extraction of ARP packets to TSV |
| `sort \| uniq -c` | Detecting duplicate/conflicting IP-to-MAC claims |
| `ps aux \| grep` | Verifying no rogue spoofing process is active |

## Report Files Generated

| File | Contents |
|---|---|
| `arp_capture_hashes.txt` | SHA-256 of original vs. working evidence copy |
| `interfaces.txt`, `routes.txt` | Host network configuration |
| `arp_table_initial.txt`, `arp_table_before.txt` | ARP cache snapshots |
| `normal_arp_fields.tsv` | Full field extraction of baseline ARP traffic |
| `arp_replies.tsv` | All ARP reply (opcode 2) packets |
| `ip_mac_claims.txt` | Unique IP→MAC ownership claims (spoofing indicator) |
| `unicast_arp_replies.tsv` | Unicast-only ARP replies |
| `process_check.txt` | Process check for active spoofing tools |

## Forensic Notes

- All evidence was hashed immediately upon acquisition/capture, and
  analysis was always performed on a **working copy**, never the
  original evidence file, to preserve chain of custody.
- The core forensic indicator used to detect ARP poisoning is **more
  than one MAC address claiming the same IP** via ARP reply packets —
  a legitimate network shows a strict 1:1 IP-to-MAC mapping.
- Unicast ARP replies (rather than broadcast) sent unsolicited to a
  specific host are a secondary indicator, since attackers often target
  the victim directly rather than broadcasting the forged reply.
- Capturing before, during, and after the controlled attack, combined
  with `ip neigh` cache snapshots, allows an investigator to correlate
  exactly when a spoofed entry entered the ARP cache and when/if it was
  corrected.
