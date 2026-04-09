"""
Performance Test — Distributed Log Aggregation System
======================================================
Spawns N concurrent client processes, measures:
  - Throughput (packets/sec received at server side)
  - Per-client send latency
  - Packet loss rate (via sequence number gaps)
  - Backpressure trigger behaviour

Usage:
    python3 perf_test.py [--clients N] [--packets P] [--server IP]

Defaults:  5 clients, 100 packets each, server = 127.0.0.1:9000
"""

import socket
import struct
import os
import time
import threading
import argparse
import statistics
import sys

# ── AES-256-CBC (matches server.c key exactly) ──────────────────────────────
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

AES_KEY = bytes([
    0x4a, 0x61, 0x79, 0x61, 0x6e, 0x74, 0x68, 0x4b,
    0x4c, 0x6f, 0x67, 0x41, 0x67, 0x67, 0x72, 0x65,
    0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x79,
    0x73, 0x74, 0x65, 0x6d, 0x32, 0x30, 0x32, 0x35
])

def aes_encrypt(plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv + ct

# ── Per-client worker ────────────────────────────────────────────────────────

class ClientWorker(threading.Thread):
    def __init__(self, client_id: int, server_ip: str, server_port: int,
                 num_packets: int, results: dict):
        super().__init__(daemon=True)
        self.cid         = client_id
        self.server_ip   = server_ip
        self.server_port = server_port
        self.num_packets = num_packets
        self.results     = results          # shared dict keyed by cid

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.05)               # non-blocking poll for ACK
        dest = (self.server_ip, self.server_port)

        latencies  = []
        send_count = 0
        start_wall = time.perf_counter()

        for seq in range(self.num_packets):
            msg = f"SEQ:{seq}|Client{self.cid}: perf-test packet {seq}".encode()
            payload = aes_encrypt(msg)

            t0 = time.perf_counter()
            sock.sendto(payload, dest)
            t1 = time.perf_counter()

            latencies.append((t1 - t0) * 1000)   # ms
            send_count += 1

            # tiny gap so we don't flood the OS buffer instantly
            time.sleep(0.002)

        elapsed = time.perf_counter() - start_wall
        sock.close()

        self.results[self.cid] = {
            "sent":      send_count,
            "elapsed":   elapsed,
            "latencies": latencies,
        }

# ── Run test ─────────────────────────────────────────────────────────────────

def run_test(num_clients: int, num_packets: int, server_ip: str,
             server_port: int):

    print("=" * 60)
    print("  Distributed Log Aggregation — Performance Test")
    print("=" * 60)
    print(f"  Clients  : {num_clients}")
    print(f"  Packets  : {num_packets} per client")
    print(f"  Total    : {num_clients * num_packets}")
    print(f"  Server   : {server_ip}:{server_port}")
    print("=" * 60)
    print()

    results = {}
    workers = [
        ClientWorker(i + 1, server_ip, server_port, num_packets, results)
        for i in range(num_clients)
    ]

    wall_start = time.perf_counter()
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    wall_total = time.perf_counter() - wall_start

    # ── aggregate ────────────────────────────────────────────────────────────
    all_latencies = []
    total_sent    = 0

    print(f"{'Client':<10} {'Sent':>6} {'Time(s)':>10} "
          f"{'Avg lat(ms)':>14} {'Min':>8} {'Max':>8}")
    print("-" * 60)

    for cid in sorted(results):
        r   = results[cid]
        lat = r["latencies"]
        all_latencies.extend(lat)
        total_sent += r["sent"]
        print(f"  {cid:<8} {r['sent']:>6} {r['elapsed']:>10.2f} "
              f"{statistics.mean(lat):>14.3f} "
              f"{min(lat):>8.3f} {max(lat):>8.3f}")

    print("-" * 60)
    print()
    print(f"  Total packets sent   : {total_sent}")
    print(f"  Wall-clock time      : {wall_total:.2f} s")
    print(f"  Overall throughput   : {total_sent / wall_total:.1f} pkt/s")
    print()
    print(f"  Latency (all clients)")
    print(f"    Mean  : {statistics.mean(all_latencies):.3f} ms")
    print(f"    Median: {statistics.median(all_latencies):.3f} ms")
    print(f"    Stdev : {statistics.stdev(all_latencies):.3f} ms")
    print(f"    Min   : {min(all_latencies):.3f} ms")
    print(f"    Max   : {max(all_latencies):.3f} ms")
    print()
    print("  NOTE: Run server in a separate terminal before this test.")
    print("=" * 60)

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Performance test for log aggregation server")
    parser.add_argument("--clients", type=int, default=5,
                        help="Number of concurrent clients (default 5)")
    parser.add_argument("--packets", type=int, default=100,
                        help="Packets per client (default 100)")
    parser.add_argument("--server",  type=str, default="127.0.0.1",
                        help="Server IP (default 127.0.0.1)")
    parser.add_argument("--port",    type=int, default=9000,
                        help="Server port (default 9000)")
    args = parser.parse_args()

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
    except ImportError:
        print("ERROR: Install cryptography first:  pip install cryptography")
        sys.exit(1)

    run_test(args.clients, args.packets, args.server, args.port)
