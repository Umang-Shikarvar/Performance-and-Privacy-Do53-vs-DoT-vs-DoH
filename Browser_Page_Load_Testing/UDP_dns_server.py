#!/usr/bin/env python3
"""
Optimized dns_server.py
- Thread-pooled UDP listener (bounded concurrency)
- TTL-aware in-memory cache (simple)
- Queue-based JSON logger (background writer, append-only newline JSON)
- Uses utils_fast.perform_iterative_resolution() for resolution
"""
import socket
import threading
import time
import json
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
from dnslib import DNSRecord, DNSHeader, RCODE
import utils_fast as utils

# ---------------- Configuration ----------------
HOST = "0.0.0.0"
PORT = 8863
LOGFILE = "dns.jsonl"  # newline-delimited JSON records (append-only)
MAX_WORKERS = 50        # thread pool size for incoming queries
CACHE_DEFAULT_TTL = 60  # seconds when no TTL info is available

# ---------------- Simple TTL cache ----------------
class TTLCache:
    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            value, expires = entry
            if time.time() >= expires:
                del self._store[key]
                return None
            return value

    def set(self, key, value, ttl=CACHE_DEFAULT_TTL):
        with self._lock:
            self._store[key] = (value, time.time() + ttl)

    def clear(self):
        with self._lock:
            self._store.clear()

cache = TTLCache()

# ---------------- Queue-based logger ----------------
log_queue = Queue()

def logger_thread(logfile):
    """Background thread that flushes records to append-only JSON lines."""
    with open(logfile, "a", buffering=1) as f:
        while True:
            try:
                rec = log_queue.get(timeout=15)
            except Empty:
                continue
            if rec is None:  # sentinel to exit
                break
            try:
                f.write(json.dumps(rec) + "\n")
            except Exception:
                pass

# start logger
threading.Thread(target=logger_thread, args=(LOGFILE,), daemon=True).start()

# ---------------- Worker that handles queries ----------------
def make_servfail(req_id=0):
    try:
        hdr = DNSHeader(id=req_id, qr=1, aa=1, ra=1, rcode=RCODE.SERVFAIL)
        return DNSRecord(hdr).pack()
    except Exception:
        return b""

def handle_query(data, addr, sock):
    try:
        req = DNSRecord.parse(data)
        qname = str(req.q.qname).rstrip('.')
    except Exception:
        qname = "<parse-error>"

    # 1) Check cache
    cached = cache.get(qname)
    if cached:
        try:
            sock.sendto(cached, addr)
            print(f"[CACHE] Replied to {addr} for {qname}")
            # log cache hit
            log_queue.put({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": addr[0],
                "queried_domain": qname,
                "status": "CACHE_HIT"
            })
            return
        except Exception as e:
            print("[!] Failed to send cached reply:", e)

    # 2) Perform iterative resolution (may be slow)
    try:
        response, details, duration_ms, queried_name = utils.perform_iterative_resolution(data)
        status = "SUCCESS" if response else "FAILED"
    except Exception as e:
        print(f"[!] Resolution error for {qname}: {e}")
        response = None
        details = []
        duration_ms = 0
        status = "FAILED"

    # 3) If no response, send SERVFAIL
    try:
        req_id = req.header.id if 'req' in locals() and hasattr(req, 'header') else 0
    except Exception:
        req_id = 0

    if not response:
        try:
            sock.sendto(make_servfail(req_id), addr)
        except Exception as e:
            print("[!] Failed to send SERVFAIL:", e)
    else:
        # Optionally cache response using a TTL extracted from the response
        try:
            parsed = DNSRecord.parse(response)
            min_ttl = CACHE_DEFAULT_TTL
            if parsed.rr:
                ttls = []
                for rr in parsed.rr:
                    # dnslib RR may expose .ttl, or rr.rdata may have .ttl — check both safely
                    ttl = getattr(rr, 'ttl', None)
                    if ttl is None:
                        ttl = getattr(rr.rdata, 'ttl', None) if hasattr(rr, 'rdata') else None
                    if ttl:
                        try:
                            ttls.append(int(ttl))
                        except Exception:
                            pass
                if ttls:
                    min_ttl = max(1, min(ttls))
            cache.set(qname, response, ttl=min_ttl)
        except Exception:
            pass

        try:
            sock.sendto(response, addr)
            print(f"[✓] Replied to {addr} for {qname} ({status}, {duration_ms} ms)")
        except Exception as e:
            print(f"[!] Failed to send reply: {e}")

    # 4) Log result (non-blocking via queue)
    record = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "client_ip": addr[0],
        "queried_domain": queried_name or qname,
        "resolution_steps": details,
        "total_time_ms": duration_ms,
        "status": status
    }
    try:
        log_queue.put(record)
    except Exception:
        pass

# ---------------- Main UDP server (thread-pooled) ----------------
def server_main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"[*] DNS UDP resolver listening on udp://{HOST}:{PORT}")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                # submit to threadpool
                executor.submit(handle_query, data, addr, sock)
            except KeyboardInterrupt:
                print("\n[*] Shutting down DNS resolver.")
                break
            except Exception as e:
                print("[!] Main loop error:", e)

if __name__ == "__main__":
    server_main()
