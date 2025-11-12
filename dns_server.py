#!/usr/bin/env python3
"""
dns_server_threaded_nocache.py

Concurrent UDP DNS resolver with iterative resolution (via utils.py),
but **without caching** — designed for low-latency benchmarking when
the local listener already has a cache.

This is functionally equivalent to the cached version except that
all cache-related code and locks have been removed.
"""

import socket, threading, time
from dnslib import DNSRecord, DNSHeader, RCODE
from utils import perform_iterative_resolution, save_log_json

# ---------------- Configuration ----------------
HOST = "0.0.0.0"
PORT = 8853
JSON_LOGFILE = "dns.json"

# ---------------- Worker ----------------
def handle_query(data, addr, sock):
    try:
        req = DNSRecord.parse(data)
        qname = str(req.q.qname).rstrip('.')
    except Exception:
        qname = "<parse-error>"

    print(f"[+] Query from {addr} → {qname}")

    # ---- Perform iterative resolution ----
    try:
        response, details, duration_ms, queried_name = perform_iterative_resolution(data)
        status = "SUCCESS" if response else "FAILED"
    except TypeError:
        # For compatibility with your utils.py older signature
        response, details, duration_ms, queried_name = perform_iterative_resolution(data, is_subquery=False)
        status = "SUCCESS" if response else "FAILED"
    except Exception as e:
        print(f"[!] Resolution error for {qname}: {e}")
        response = None
        details = []
        duration_ms = 0
        status = "FAILED"

    # ---- Handle SERVFAIL fallback ----
    if not response:
        try:
            req = DNSRecord.parse(data)
            fail_resp = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=1, rcode=RCODE.SERVFAIL), q=req.q)
            reply_bytes = fail_resp.pack()
        except Exception:
            fallback = DNSRecord(DNSHeader(id=0, qr=1, aa=1, ra=1, rcode=RCODE.SERVFAIL))
            reply_bytes = fallback.pack()
    else:
        reply_bytes = response

    # ---- Send reply ----
    try:
        sock.sendto(reply_bytes, addr)
        print(f"[✓] Replied to {addr} for {qname} ({status}, {duration_ms} ms)")
    except Exception as e:
        print(f"[!] Failed to send reply: {e}")

    # ---- Log result ----
    record = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "client_ip": addr[0],
        "queried_domain": queried_name or qname,
        "resolution_steps": details,
        "total_time_ms": duration_ms,
        "status": status
    }
    try:
        save_log_json(JSON_LOGFILE, record)
    except Exception as e:
        print("Failed to save log:", e)


# ---------------- Main UDP server ----------------
def server_main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, PORT))
    print(f"[*] DNS UDP resolver listening on udp://{HOST}:{PORT}")

    while True:
        try:
            data, addr = s.recvfrom(4096)
            threading.Thread(target=handle_query, args=(data, addr, s), daemon=True).start()
        except Exception as e:
            print("[!] Main loop error:", e)


# ---------------- Entrypoint ----------------
if __name__ == "__main__":
    try:
        server_main()
    except KeyboardInterrupt:
        print("\n[*] Shutting down DNS resolver.")