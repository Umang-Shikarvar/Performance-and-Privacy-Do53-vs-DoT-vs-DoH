#!/usr/bin/env python3
"""
doh_server.py

- Minimal, threaded HTTPS server that implements DoH (RFC8484) POST /dns-query
  expecting body = raw DNS wire-format ("application/dns-message").
- Uses your utils_fast.perform_iterative_resolution(...) to perform iterative resolution
  (keeps your optimizations/threading/resolver logic intact).
- Adds a small cache and background logging (append JSON lines).
- Requires: server.crt.pem and server.key.pem files in the same directory (or update paths).
"""

import socket
import ssl
import threading
import time
import json
import os
from concurrent.futures import ThreadPoolExecutor
from dnslib import DNSRecord, DNSHeader, RCODE
import utils_fast as utils

# ---------- Config ----------
HOST = "0.0.0.0"
PORT = 8453
CERTFILE = "server.crt.pem"
KEYFILE = "server.key.pem"
LOGFILE = "doh.jsonl"
MAX_CONN_WORKERS = 50
RESOLVE_TIMEOUT = 15.0
CACHE_TTL = 60  # seconds
# ----------------------------

# Simple TTL cache
class TTLCache:
    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            v = self._store.get(key)
            if not v:
                return None
            val, exp = v
            if time.time() > exp:
                del self._store[key]
                return None
            return val

    def set(self, key, val, ttl=CACHE_TTL):
        with self._lock:
            self._store[key] = (val, time.time() + ttl)

cache = TTLCache()

# Simple JSON logger (append-only)
def log_record(rec):
    try:
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass

def make_servfail(req_bytes):
    try:
        req = DNSRecord.parse(req_bytes)
        fail = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=1, rcode=RCODE.SERVFAIL), q=req.q)
        return fail.pack()
    except Exception:
        return b""

def handle_connection(conn, addr):
    """
    Handle TLS connection; parse HTTP POST /dns-query, call resolver, return application/dns-message response.
    Expects standard TLS (the forwarder uses ssl.wrap/socket).
    """
    try:
        conn.settimeout(30)
        # Read request (headers first)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break

        if b"\r\n\r\n" not in data:
            conn.close()
            return

        header_bytes, body_start = data.split(b"\r\n\r\n", 1)
        header_lines = header_bytes.decode(errors="ignore").split("\r\n")
        first_line = header_lines[0] if header_lines else ""
        parts = first_line.split()
        if len(parts) < 2:
            conn.close()
            return
        method, path = parts[0], parts[1]

        # find content-length
        content_length = 0
        content_type = ""
        for h in header_lines[1:]:
            if ":" not in h: continue
            k, v = h.split(":", 1)
            if k.strip().lower() == "content-length":
                try:
                    content_length = int(v.strip())
                except:
                    content_length = 0
            if k.strip().lower() == "content-type":
                content_type = v.strip().lower()

        # read rest of body if needed
        body = body_start
        while len(body) < content_length:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body += chunk

        # We only support POST /dns-query with application/dns-message (wire)
        if method.upper() != "POST" or path not in ("/dns-query", "/dns-query/"):
            # simple 404
            resp = b"HTTP/1.1 404 Not Found\r\nContent-Length:0\r\nConnection: close\r\n\r\n"
            conn.sendall(resp)
            conn.close()
            return

        # If content-type is not application/dns-message we still try to parse bytes as DNS
        dns_query_bytes = body

        # Basic parse for logging
        try:
            req = DNSRecord.parse(dns_query_bytes)
            qname = str(req.q.qname).rstrip(".")
        except Exception:
            qname = "<parse-error>"

        print(f"[<] DoH query from {addr} -> {qname}")

        # Check cache
        cached = cache.get(qname)
        if cached:
            resp_bytes = cached
            print(f"[CACHE] hit for {qname}")
        else:
            # Call the resolver (blocking) - use utils.perform_iterative_resolution
            try:
                # The utils_fast.perform_iterative_resolution signature returns (response, logs, duration_ms, qname)
                response, logs, dur_ms, q = utils.perform_iterative_resolution(dns_query_bytes)
            except Exception as e:
                print(f"[!] Resolver error: {e}")
                response, logs, dur_ms, q = None, [], 0, qname

            if not response:
                resp_bytes = make_servfail(dns_query_bytes)
                status = "FAILED"
            else:
                resp_bytes = response
                status = "SUCCESS"
                # cache best-effort (you could parse TTLs from response if needed)
                cache.set(qname, resp_bytes, ttl=CACHE_TTL)

            # Log (JSON)
            record = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": addr[0],
                "queried_domain": q or qname,
                "status": status,
                "total_time_ms": dur_ms,
                "steps": logs
            }
            log_record(record)

        # Build HTTP response
        http_headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/dns-message\r\n"
            f"Content-Length: {len(resp_bytes)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        conn.sendall(http_headers + resp_bytes)
        print(f"[→] Replied DoH {qname} -> {len(resp_bytes)} bytes")

    except Exception as e:
        print(f"[!] Connection handler error: {e}")
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()


def main():
    if not os.path.exists(CERTFILE) or not os.path.exists(KEYFILE):
        print(f"[!] TLS cert or key missing: {CERTFILE}, {KEYFILE}")
        return

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    # Optional: configure ciphers / TLS versions if you need to match the client
    # context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    bindsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsock.bind((HOST, PORT))
    bindsock.listen(200)
    print(f"[*] DoH server listening on https://{HOST}:{PORT}/dns-query")

    with ThreadPoolExecutor(max_workers=MAX_CONN_WORKERS) as ex:
        while True:
            try:
                conn, addr = bindsock.accept()
                # wrap socket in TLS
                try:
                    tls_conn = context.wrap_socket(conn, server_side=True)
                except Exception as e:
                    print(f"[!] TLS wrap error: {e}")
                    conn.close()
                    continue
                # dispatch
                ex.submit(handle_connection, tls_conn, addr)
            except KeyboardInterrupt:
                print("\n[*] Shutting down DoH server.")
                break
            except Exception as e:
                print("[!] Accept loop error:", e)


if __name__ == "__main__":
    main()
