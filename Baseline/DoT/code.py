"""
dot_google_batch.py
---------------------------------
Measure DNS-over-TLS (DoT) latency and performance using Google's DoT endpoint.
Logs results in a CSV format identical to your Do53 experiments.
"""

import socket
import ssl
import struct
import time
import csv
import os
from datetime import datetime, timezone
from dnslib import DNSRecord

# -------- Configuration --------
DOMAINS_FILE = "/Users/tejasmacipad/Desktop/final_CN_project/CN_Project/Report/top30003050.txt"          # Input: one domain per line
OUTPUT_CSV   = "dns_google_dot_bot50.csv" # Output file
DOT_SERVER   = "8.8.8.8"            # Google Public DNS
DOT_HOSTNAME = "dns.google"         # Required for SNI
DOT_PORT     = 853
TIMEOUT      = 5.0
RUNS_PER_DOMAIN = 1


# -------- Helper Functions --------
def load_domains(path):
    """Read up to 50 unique cleaned domains."""
    seen, keep = set(), []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            d = line.strip().rstrip(".").lower()
            d = d.replace("https://", "").replace("http://", "")
            if not d or d in seen:
                continue
            seen.add(d)
            keep.append(d)
            if len(keep) == 50:
                break
    return keep


def ensure_csv(path):
    """Ensure output CSV file has headers."""
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                "timestamp_utc", "domain", "protocol", "status",
                "rcode", "tls_version", "cipher_suite",
                "tcp_connect_ms", "tls_handshake_ms",
                "query_rtt_ms", "bytes_out", "bytes_in"
            ])


def append_row(path, row):
    """Append one result row to CSV."""
    with open(path, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(row)


def recvn(sock, n):
    """Receive exactly n bytes from socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def query_dot(domain):
    """Perform one DNS-over-TLS query to Google DoT."""
    q = DNSRecord.question(domain).pack()

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    tcp_start = time.perf_counter()
    try:
        raw_sock = socket.create_connection((DOT_SERVER, DOT_PORT), timeout=TIMEOUT)
    except Exception:
        raise ConnectionError("TCP_CONNECT_ERROR")
    tcp_time = (time.perf_counter() - tcp_start) * 1000.0

    try:
        tls_start = time.perf_counter()
        with ctx.wrap_socket(raw_sock, server_hostname=DOT_HOSTNAME) as tls_sock:
            tls_time = (time.perf_counter() - tls_start) * 1000.0
            tls_version = tls_sock.version()
            cipher_suite = tls_sock.cipher()[0]

            # Send DNS query
            t0 = time.perf_counter()
            tls_sock.sendall(struct.pack("!H", len(q)) + q)
            bytes_out = len(q) + 2

            # Receive response
            resp_len_bytes = recvn(tls_sock, 2)
            if not resp_len_bytes:
                raise RuntimeError("No response length received.")
            resp_len = struct.unpack("!H", resp_len_bytes)[0]
            resp_data = recvn(tls_sock, resp_len)
            if not resp_data:
                raise RuntimeError("No response data received.")

            bytes_in = len(resp_data) + 2
            t1 = time.perf_counter()
            query_rtt_ms = (t1 - t0) * 1000.0

            try:
                rcode = int(DNSRecord.parse(resp_data).header.rcode)
            except Exception:
                rcode = ""

            return (
                round(query_rtt_ms, 3), bytes_out, bytes_in, rcode,
                tls_version, cipher_suite, round(tcp_time, 3), round(tls_time, 3)
            )

    except ssl.SSLError as e:
        raise RuntimeError(f"TLS_ERROR: {e}")
    finally:
        raw_sock.close()


# -------- Main --------
def main():
    domains = load_domains(DOMAINS_FILE)
    if not domains:
        print(f"[!] No domains found in {DOMAINS_FILE}")
        return

    print(f"[i] Loaded {len(domains)} domains (max 50)")
    ensure_csv(OUTPUT_CSV)

    for domain in domains:
        for _ in range(RUNS_PER_DOMAIN):
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            try:
                rtt_ms, bout, bin_, rcode, tls_ver, cipher, tcp_ms, tls_ms = query_dot(domain)
                row = [
                    ts, domain, "DoT", "SUCCESS", rcode, tls_ver, cipher,
                    tcp_ms, tls_ms, rtt_ms, bout, bin_
                ]
            except socket.timeout:
                row = [ts, domain, "DoT", "TIMEOUT", "", "", "", "", "", "", "", ""]
            except ConnectionError as e:
                row = [ts, domain, "DoT", "ERROR", "", "", "", "", "", "", "", str(e)]
            except Exception as e:
                row = [ts, domain, "DoT", "ERROR", "", "", "", "", "", "", "", str(e)]

            append_row(OUTPUT_CSV, row)
            print(row)


if __name__ == "__main__":
    main()
