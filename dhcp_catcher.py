#!/usr/bin/env python3
"""
dhcp_catcher.py
Simple DHCP attack catcher using Scapy.
Run with: sudo python3 dhcp_catcher.py -i <interface>
"""

import argparse
import time
import threading
from collections import deque, defaultdict
from scapy.all import sniff, DHCP, BOOTP, UDP, Ether, IP

WINDOW_SECONDS = 10
DISCOVER_THRESHOLD = 60
UNIQUE_MAC_THRESHOLD = 40
OFFER_PER_SERVER_THRESHOLD = 20
CHECK_INTERVAL = 2
VERBOSE = True

discover_timestamps = deque()
discover_client_macs = defaultdict(lambda: deque())
offer_from_server = defaultdict(lambda: deque())

lock = threading.Lock()

def now_ts():
    return time.time()

def prune_deques():
    """Remove timestamps older than WINDOW_SECONDS from all deques."""
    cutoff = now_ts() - WINDOW_SECONDS
    with lock:
        while discover_timestamps and discover_timestamps[0] < cutoff:
            discover_timestamps.popleft()

        for mac, dq in list(discover_client_macs.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del discover_client_macs[mac]

        for srv, dq in list(offer_from_server.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del offer_from_server[srv]

def alert(msg, details=None):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"[ALERT] {ts} - {msg}")
    if details:
        print("  details:", details)

def periodic_check():
    """Periodically evaluate the counters and raise alerts if thresholds exceeded."""
    prune_deques()
    with lock:
        total_discovers = len(discover_timestamps)
        unique_macs = len(discover_client_macs)
        if total_discovers >= DISCOVER_THRESHOLD:
            alert("High DHCPDISCOVER rate detected", {
                "discover_count": total_discovers,
                "window_s": WINDOW_SECONDS,
            })
        if unique_macs >= UNIQUE_MAC_THRESHOLD:
            alert("Many unique client MACs seen (possible DHCP starvation)", {
                "unique_client_macs": unique_macs,
                "window_s": WINDOW_SECONDS,
            })
        for server_ip, dq in offer_from_server.items():
            if len(dq) >= OFFER_PER_SERVER_THRESHOLD:
                alert("High number of DHCPOFFERs from single server (possible rogue DHCP)",
                      {"server": server_ip, "offers": len(dq), "window_s": WINDOW_SECONDS})
    threading.Timer(CHECK_INTERVAL, periodic_check).start()

def get_dhcp_message_type(dhcp_options):
    """Extract DHCP message type (int) from DHCP options list (Scapy style)."""
    if not dhcp_options:
        return None
    for opt in dhcp_options:
        if isinstance(opt, tuple) and opt[0] == 'message-type':
            return opt[1]
    return None

def handle_pkt(pkt):
    """Scapy callback for each sniffed packet."""
    if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
        return

    ts = now_ts()
    dhcp_opts = pkt[DHCP].options
    mtype = get_dhcp_message_type(dhcp_opts)
    client_mac = None
    try:
        chaddr = pkt[BOOTP].chaddr
        if chaddr:
            if isinstance(chaddr, bytes):
                client_mac = ':'.join(f"{b:02x}" for b in chaddr[:6])
            else:
                client_mac = str(chaddr).replace('\x00', '')[:17]
    except Exception:
        pass
    if not client_mac:
        client_mac = pkt[Ether].src if pkt.haslayer(Ether) else "unknown"

    server_ip = None
    try:
        if pkt.haslayer(IP):
            server_ip = pkt[IP].src
    except Exception:
        server_ip = None

    with lock:
        if mtype == 1:
            discover_timestamps.append(ts)
            discover_client_macs[client_mac].append(ts)
            if VERBOSE:
                print(f"[{time.strftime('%H:%M:%S')}] DHCPDISCOVER from client_mac={client_mac}")
        elif mtype == 2:
            if server_ip:
                offer_from_server[server_ip].append(ts)
                if VERBOSE:
                    print(f"[{time.strftime('%H:%M:%S')}] DHCPOFFER from server={server_ip}")

def main():
    parser = argparse.ArgumentParser(description="Simple DHCP attack catcher")
    parser.add_argument("-i", "--iface", required=True, help="Interface to sniff (e.g., eth0 or br0)")
    parser.add_argument("--window", type=int, default=WINDOW_SECONDS, help="sliding window seconds")
    parser.add_argument("--verbose", action="store_true", help="verbose output")
    args = parser.parse_args()

    global WINDOW_SECONDS, VERBOSE
    WINDOW_SECONDS = args.window
    VERBOSE = args.verbose or VERBOSE

    print("Starting DHCP catcher on interface", args.iface)
    periodic_check()
    sniff(iface=args.iface, filter="udp and (port 67 or 68)", prn=handle_pkt, store=0)

if __name__ == "__main__":
    main()
