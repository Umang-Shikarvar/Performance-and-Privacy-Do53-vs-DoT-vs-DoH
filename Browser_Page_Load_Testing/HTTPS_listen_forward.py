#!/usr/bin/env python3
"""
doh_forwarder.py

- Listens for incoming UDP DNS queries (like your old threaded_listen_forward.py).
- Forwards each DNS query to an upstream DoH server (HTTPS POST /dns-query).
- Sends the binary DNS response back to the original UDP client.
- Threaded: uses ThreadPoolExecutor to handle concurrent clients.
- Keeps the local proxy (SOCKS) and other files unchanged.

Configure:
 - LISTEN_IP/LISTEN_PORT: where your local components (local_socks5_proxy) send UDP queries.
 - DOH_SERVER_HOST/DOH_SERVER_PORT: hostname/IP and port of the DoH server.
 - VERIFY_TLS: If False, TLS verification is skipped (useful for self-signed server certificates).
"""

import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dnslib import DNSRecord

# ---------- Configuration ----------
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 5533      # same as your earlier forwarder UDP listener
DOH_SERVER_HOST = "10.7.46.109"  # IP or hostname of your DoH server
DOH_SERVER_PORT = 8453
DOH_PATH = "/dns-query"
DOH_TIMEOUT = 10.0     # seconds for TLS/connect/read
MAX_WORKERS = 50
VERIFY_TLS = False     # set True if server has a valid CA-signed cert
# -----------------------------------

def doh_post(dns_query: bytes) -> bytes | None:
    """Send a DoH POST to DOH_SERVER_HOST:DOH_SERVER_PORT and return DNS wire response bytes or None."""
    # Build HTTP/1.1 POST
    headers = (
        f"POST {DOH_PATH} HTTP/1.1\r\n"
        f"Host: {DOH_SERVER_HOST}\r\n"
        "Content-Type: application/dns-message\r\n"
        "Accept: application/dns-message\r\n"
        f"Content-Length: {len(dns_query)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")
    payload = headers + dns_query

    # TLS context
    if VERIFY_TLS:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl._create_unverified_context()

    try:
        with socket.create_connection((DOH_SERVER_HOST, DOH_SERVER_PORT), timeout=DOH_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=(DOH_SERVER_HOST if VERIFY_TLS else None)) as ssock:
                ssock.settimeout(DOH_TIMEOUT)
                ssock.sendall(payload)

                # Read response headers first until header-body sep
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 65536:  # header too large
                        break

                if b"\r\n\r\n" not in data:
                    return None

                header_bytes, body_start = data.split(b"\r\n\r\n", 1)
                headers = header_bytes.decode(errors="ignore").split("\r\n")
                # find content-length
                content_length = None
                for h in headers:
                    if ":" in h:
                        k, v = h.split(":", 1)
                        if k.strip().lower() == "content-length":
                            try:
                                content_length = int(v.strip())
                            except:
                                content_length = None
                # If content-length present, read the remaining bytes
                body = body_start
                to_read = (content_length - len(body)) if (content_length is not None) else None
                if to_read is not None and to_read > 0:
                    while len(body) < content_length:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        body += chunk
                else:
                    # If no content-length, read until close
                    while True:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        body += chunk

                # Return the body (should be DNS wire bytes when content-type is application/dns-message)
                return body

    except Exception as e:
        print(f"[!] DoH post error: {e}")
        return None


def handle_udp_query(data: bytes, addr, udp_sock):
    """Worker: forward DNS query bytes via DoH and return response to UDP client."""
    try:
        # Basic sanity parse (not required but helpful for logging)
        try:
            req = DNSRecord.parse(data)
            qname = str(req.q.qname)
        except Exception:
            qname = "<parse-error>"

        print(f"[<] UDP query from {addr} -> {qname}")

        dns_resp = doh_post(data)
        if dns_resp:
            udp_sock.sendto(dns_resp, addr)
            print(f"[→] Sent DoH response to {addr} (len={len(dns_resp)})")
        else:
            # Optionally send SERVFAIL if you want; here we simply don't respond (like earlier forwarder sometimes)
            print(f"[!] No response for {qname} (DoH failure)")

    except Exception as e:
        print(f"[!] handle_udp_query error: {e}")


def main():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[*] DoH forwarder listening on udp://{LISTEN_IP}:{LISTEN_PORT} -> https://{DOH_SERVER_HOST}:{DOH_SERVER_PORT}{DOH_PATH}")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        while True:
            try:
                data, addr = udp_sock.recvfrom(4096)
                ex.submit(handle_udp_query, data, addr, udp_sock)
            except KeyboardInterrupt:
                print("\n[*] Exiting DoH forwarder.")
                break
            except Exception as e:
                print("[!] Main loop error:", e)


if __name__ == "__main__":
    main()
