#!/usr/bin/env python3
"""
tls_server_resolver_pooled.py

TLS1.2-like resolver server (your custom TLS protocol).
 - Uses utils_fast.perform_iterative_resolution for actual DNS resolution
 - ThreadPoolExecutor to bound connection handling concurrency
 - Simple TTLCache for cached DNS responses (uses TTLs from answers)
 - Append-only JSONL logging (save_log_json)
"""

import socket
import threading
import os
import struct
import json
import binascii
import time
import hashlib
import hmac
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty

from dnslib import DNSRecord, DNSHeader, RCODE
import utils_fast as utils  # uses perform_iterative_resolution

from cryptography.hazmat.primitives import serialization, hashes, constant_time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509

# ---------------- Configuration ----------------
HOST = "127.0.0.1"
PORT = 8853                 # TLS resolver port (matches forwarder)
RT_HANDSHAKE = 22
RT_CHANGE_CIPHER_SPEC = 20
RT_APPLICATION_DATA = 23
TLS_VERSION = (3, 3)

LOGFILE = "doh_tls_server.jsonl"
JSON_LOGFILE = "doh_tls_resolver_logs.jsonl"
MAX_WORKERS = 50
CACHE_DEFAULT_TTL = 60

# Load certificates (must exist)
with open("server.key.pem", "rb") as f:
    SERVER_KEY = serialization.load_pem_private_key(f.read(), password=None)
with open("server.crt.pem", "rb") as f:
    SERVER_CERT = x509.load_pem_x509_certificate(f.read())
with open("ca.crt.pem", "rb") as f:
    CA_CERT = x509.load_pem_x509_certificate(f.read())

# ---------------- TLS helpers ----------------
def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            return None
        buf += part
    return buf

def tls_record_pack(content_type, version_tuple, payload: bytes):
    ver = (version_tuple[0] << 8) | version_tuple[1]
    header = struct.pack("!BHH", content_type, ver, len(payload))
    return header + payload

def tls_record_unwrap(sock):
    hdr = recvn(sock, 5)
    if not hdr:
        return None, None
    content_type = hdr[0]
    length = struct.unpack("!H", hdr[3:5])[0]
    data = recvn(sock, length)
    return content_type, data

def p_hash(secret, seed, out_len, hashmod=hashlib.sha256):
    A = seed
    result = b""
    while len(result) < out_len:
        A = hmac.new(secret, A, hashmod).digest()
        result += hmac.new(secret, A + seed, hashmod).digest()
    return result[:out_len]

def tls_prf(secret, label, seed, out_len):
    return p_hash(secret, label + seed, out_len, hashlib.sha256)

def make_nonce(iv12: bytes, seq: int) -> bytes:
    seq_bytes = seq.to_bytes(4, "big")
    nb = bytearray(iv12)
    for i in range(4):
        nb[8 + i] ^= seq_bytes[i]
    return bytes(nb)

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

cache = TTLCache()

# ---------------- Logger (background writer) ----------------
log_queue = Queue()

def save_log_json(filename, rec):
    # append a JSON line
    try:
        with open(filename, "a", buffering=1) as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        pass

def logger_thread(fname):
    while True:
        try:
            rec = log_queue.get(timeout=15)
        except Empty:
            continue
        if rec is None:
            break
        try:
            with open(fname, "a", buffering=1) as f:
                f.write(json.dumps(rec, default=str) + "\n")
        except Exception:
            pass

threading.Thread(target=logger_thread, args=(LOGFILE,), daemon=True).start()

# ---------------- Connection handler ----------------
def handle_connection(conn, addr):
    t_conn_start = time.time()
    transcript = bytearray()
    try:
        # 1) ClientHello
        ct, data = tls_record_unwrap(conn)
        if ct != RT_HANDSHAKE or data is None:
            conn.close(); return
        transcript.extend(data)
        client_hello = json.loads(data.decode("utf-8"))
        client_random = binascii.unhexlify(client_hello["client_random"])

        # 2) ServerHello
        server_random = os.urandom(32)
        sh = {"server_random": binascii.hexlify(server_random).decode()}
        sh_bytes = json.dumps(sh, separators=(",", ":"), sort_keys=True).encode()
        transcript.extend(sh_bytes)
        conn.sendall(tls_record_pack(RT_HANDSHAKE, TLS_VERSION, sh_bytes))

        # 3) Certificate
        cert_pem = SERVER_CERT.public_bytes(serialization.Encoding.PEM)
        cert_msg = {"cert_pem": cert_pem.decode()}
        cert_bytes = json.dumps(cert_msg, separators=(",", ":"), sort_keys=True).encode()
        transcript.extend(cert_bytes)
        conn.sendall(tls_record_pack(RT_HANDSHAKE, TLS_VERSION, cert_bytes))

        # 4) ServerHelloDone
        shd = b"SERVER_HELLO_DONE"
        transcript.extend(shd)
        conn.sendall(tls_record_pack(RT_HANDSHAKE, TLS_VERSION, shd))

        # 5) ClientKeyExchange
        ct, cke = tls_record_unwrap(conn)
        if ct != RT_HANDSHAKE or cke is None:
            conn.close(); return
        transcript.extend(cke)
        ckej = json.loads(cke.decode())
        encrypted_pms = binascii.unhexlify(ckej["enc_pms"])
        premaster = SERVER_KEY.decrypt(encrypted_pms, padding.PKCS1v15())
        if len(premaster) < 48:
            conn.close(); return

        # Derive keys
        master_secret = tls_prf(premaster, b"master secret", client_random + server_random, 48)
        key_block = tls_prf(master_secret, b"key expansion", server_random + client_random, 64)
        idx = 0
        client_write_key = key_block[idx:idx+16]; idx+=16
        server_write_key = key_block[idx:idx+16]; idx+=16
        client_iv = key_block[idx:idx+12]; idx+=12
        server_iv = key_block[idx:idx+12]; idx+=12
        client_aes = AESGCM(client_write_key)
        server_aes = AESGCM(server_write_key)
        client_seq = 0
        server_seq = 0

        # 6) ChangeCipherSpec
        ct, ccs = tls_record_unwrap(conn)
        if ct != RT_CHANGE_CIPHER_SPEC:
            conn.close(); return

        # 7) Client Finished (encrypted)
        ct, encfin = tls_record_unwrap(conn)
        if ct != RT_HANDSHAKE or encfin is None:
            conn.close(); return
        j = json.loads(encfin.decode())
        nonce = binascii.unhexlify(j["nonce"])
        ctext = binascii.unhexlify(j["ct"])
        plain_finished = client_aes.decrypt(nonce, ctext, None)

        # Verify Finished
        h = hashlib.sha256(); h.update(transcript)
        handshake_hash = h.digest()
        expected_verify = tls_prf(master_secret, b"client finished", handshake_hash, 12)
        if not constant_time.bytes_eq(expected_verify, plain_finished):
            conn.close(); return
        transcript.extend(plain_finished)

        # 8) Send Server Finished
        server_verify = tls_prf(master_secret, b"server finished", handshake_hash, 12)
        server_nonce = make_nonce(server_iv, server_seq)
        server_ct = server_aes.encrypt(server_nonce, server_verify, None)
        out = {"nonce": binascii.hexlify(server_nonce).decode(), "ct": binascii.hexlify(server_ct).decode()}
        conn.sendall(tls_record_pack(RT_HANDSHAKE, TLS_VERSION, json.dumps(out).encode("utf-8")))
        server_seq += 1

        # TLS handshake complete
        handshake_ms = round((time.time() - t_conn_start) * 1000, 2)

        # =====================================================
        # Application Data (encrypted) - one request per connection in this design
        # =====================================================
        ct, app = tls_record_unwrap(conn)
        if ct != RT_APPLICATION_DATA or app is None:
            conn.close(); return
        j = json.loads(app.decode())
        nonce = binascii.unhexlify(j["nonce"])
        ctext = binascii.unhexlify(j["ct"])
        plain = client_aes.decrypt(nonce, ctext, None)

        dns_query_bytes = None
        is_http = False
        qname = "<parse-error>"

        try:
            # Detect HTTP POST for DoH
            if plain.startswith(b"POST") or plain.startswith(b"GET"):
                sep = b"\r\n\r\n"
                header_end = plain.find(sep)
                if header_end == -1:
                    conn.close(); return
                headers = plain[:header_end].decode(errors="ignore")
                body_bytes = plain[header_end + len(sep):]
                print("[DoH HTTP headers]\n", headers)

                if b"application/dns-message" in plain.lower():
                    dns_query_bytes = body_bytes
                else:
                    try:
                        dns_query_bytes = binascii.a2b_base64(body_bytes.strip())
                    except Exception:
                        dns_query_bytes = body_bytes

                req = DNSRecord.parse(dns_query_bytes)
                qname = str(req.q.qname).rstrip('.')
            else:
                # raw DNS-over-TLS payload
                req = DNSRecord.parse(plain)
                qname = str(req.q.qname).rstrip('.')
                dns_query_bytes = plain
        except Exception:
            dns_query_bytes = plain

        # Quick cache check
        cached = cache.get(qname)
        if cached:
            reply_bytes = cached
            status = "CACHE_HIT"
            duration_ms = 0
            details = []
        else:
            # perform iterative resolution (fast utils)
            t0 = time.time()
            try:
                response, details, duration_ms, queried_name = utils.perform_iterative_resolution(dns_query_bytes)
            except Exception:
                response, details, duration_ms, queried_name = None, [], 0, qname
            t1 = time.time()
            resolver_wall_ms = round((t1 - t0) * 1000, 2)

            if response:
                reply_bytes = response
                status = "SUCCESS"
                # extract TTL and cache
                try:
                    parsed = DNSRecord.parse(reply_bytes)
                    ttls = []
                    for rr in parsed.rr:
                        t = getattr(rr, "ttl", None)
                        if t is None and hasattr(rr, "rdata") and hasattr(rr.rdata, "ttl"):
                            t = rr.rdata.ttl
                        if t:
                            try:
                                ttls.append(int(t))
                            except:
                                pass
                    if ttls:
                        ttl_chosen = max(1, min(ttls))
                    else:
                        ttl_chosen = CACHE_DEFAULT_TTL
                except Exception:
                    ttl_chosen = CACHE_DEFAULT_TTL
                cache.set(qname, reply_bytes, ttl=ttl_chosen)
            else:
                # create SERVFAIL reply
                try:
                    reqtmp = DNSRecord.parse(dns_query_bytes)
                    fail_resp = DNSRecord(DNSHeader(id=reqtmp.header.id, qr=1, aa=1, ra=1, rcode=RCODE.SERVFAIL), q=reqtmp.q)
                    reply_bytes = fail_resp.pack()
                except Exception:
                    fallback = DNSRecord(DNSHeader(id=0, qr=1, aa=1, ra=1, rcode=RCODE.SERVFAIL))
                    reply_bytes = fallback.pack()
                status = "FAILED"

        # Log asynchronously
        record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "client_ip": addr[0],
            "queried_domain": qname,
            "status": status,
            "handshake_ms": handshake_ms,
            "resolver_duration_ms": duration_ms,
            "resolution_steps": details
        }
        try:
            log_queue.put(record)
        except Exception:
            pass

        # Build HTTP response if DoH request was sent
        is_http_resp = False
        if plain.startswith(b"POST") or plain.startswith(b"GET"):
            # send HTTP response (application/dns-message)
            http_resp = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/dns-message\r\n"
                f"Content-Length: {len(reply_bytes)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode() + reply_bytes
            payload = http_resp
            is_http_resp = True
        else:
            payload = reply_bytes

        # encrypt & send application data
        resp_nonce = make_nonce(server_iv, server_seq)
        resp_ct = server_aes.encrypt(resp_nonce, payload, None)
        outp = {"nonce": binascii.hexlify(resp_nonce).decode(), "ct": binascii.hexlify(resp_ct).decode()}
        conn.sendall(tls_record_pack(RT_APPLICATION_DATA, TLS_VERSION, json.dumps(outp).encode()))
        server_seq += 1

    except Exception as e:
        print("[!] Server error:", e)
    finally:
        try:
            conn.close()
        except:
            pass

# ---------------- Server main with executor ----------------
def server_main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(200)
    print(f"[*] TLS resolver server listening on {HOST}:{PORT}")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while True:
            try:
                conn, addr = s.accept()
                executor.submit(handle_connection, conn, addr)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print("[!] Accept loop error:", e)
                time.sleep(0.1)

if __name__ == "__main__":
    server_main()
