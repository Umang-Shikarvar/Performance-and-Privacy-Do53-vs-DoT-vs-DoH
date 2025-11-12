#!/usr/bin/env python3
"""
dns_over_tls_forwarder_pooled.py

Local UDP DNS forwarder that forwards queries over your custom TLS1.2-like
protocol to the remote TLS resolver. Uses:
 - a small pool of persistent TLS connections (reused across queries)
 - TTL-aware caching (uses TTLs from DNS response)
 - ThreadPoolExecutor to handle UDP queries concurrently
 - lightweight metrics/log prints

Requires:
 - dnslib
 - cryptography
 - utils_fast.py (perform_iterative_resolution not required here; server uses it)
"""

import socket
import threading
import time
import struct
import json
import os
import binascii
import hashlib
import hmac
from concurrent.futures import ThreadPoolExecutor

from dnslib import DNSRecord, DNSHeader, RCODE
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.hazmat.primitives import serialization, constant_time

# ---------------- Configuration ----------------
UPSTREAM_HOST = "127.0.0.1"   # remote TLS resolver (your server)
UPSTREAM_PORT = 8853          # remote TLS port (matches server)
LISTEN_ADDR = "127.0.0.1"     # local listen address
LISTEN_PORT = 8053            # local UDP port for test (use 53 if privileged / needed)
POOL_SIZE = 3                 # number of persistent TLS connections to keep
WORKER_THREADS = 50           # threadpool for handling incoming UDP queries
CONNECT_TIMEOUT = 10          # seconds for TCP connect/handshake
OPS_TIMEOUT = 15              # socket operations timeout
CACHE_DEFAULT_TTL = 60        # fallback TTL (sec)
IDLE_CONN_CLOSE = 30          # close pooled connections idle > seconds

# TLS / record constants (match your server)
RT_HANDSHAKE = 22
RT_CHANGE_CIPHER_SPEC = 20
RT_APPLICATION_DATA = 23
TLS_VERSION = (3, 3)

# Path to CA (optional verification)
CA_PEM = "ca.crt.pem"

# ---------------- Helpers (TLS record utilities) ----------------
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
    """TLS1.2 GCM nonce = fixed_iv XOR seq on last 4 bytes."""
    seq_bytes = seq.to_bytes(4, "big")
    nb = bytearray(iv12)
    for i in range(4):
        nb[8 + i] ^= seq_bytes[i]
    return bytes(nb)

# ---------------- Simple TTL cache ----------------
_cache = {}
_cache_lock = threading.Lock()
def cache_get(qname):
    with _cache_lock:
        ent = _cache.get(qname)
        if not ent:
            return None
        if ent['expiry'] < time.time():
            del _cache[qname]
            return None
        return ent['response']
def cache_set(qname, reply_bytes):
    ttl = CACHE_DEFAULT_TTL
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
                except Exception:
                    pass
        if ttls:
            ttl = max(1, min(ttls))
    except Exception:
        ttl = CACHE_DEFAULT_TTL
    with _cache_lock:
        _cache[qname] = {'response': reply_bytes, 'expiry': time.time() + ttl}
    return ttl

# ---------------- Persistent TLS Client ----------------
class PersistentTLSClient:
    def __init__(self, upstream_ip, upstream_port, timeout=CONNECT_TIMEOUT):
        self.upstream_ip = upstream_ip
        self.upstream_port = upstream_port
        self.timeout = timeout
        self.lock = threading.Lock()
        self.sock = None
        self.client_aes = None
        self.server_aes = None
        self.client_iv = None
        self.server_iv = None
        self.client_seq = 0
        self.server_seq = 0
        self.alive = False
        self.last_used = 0.0
        self.last_handshake_ms = None

    def _connect_and_handshake(self):
        start = time.time()
        s = socket.create_connection((self.upstream_ip, self.upstream_port), timeout=self.timeout)
        s.settimeout(OPS_TIMEOUT)
        transcript = bytearray()

        # 1) ClientHello
        client_random = os.urandom(32)
        ch = {"client_random": binascii.hexlify(client_random).decode()}
        ch_b = json.dumps(ch, separators=(",", ":"), sort_keys=True).encode()
        s.sendall(tls_record_pack(RT_HANDSHAKE, TLS_VERSION, ch_b))
        transcript.extend(ch_b)

        # 2) ServerHello
        ct, sh_b = tls_record_unwrap(s)
        if not sh_b:
            s.close(); raise RuntimeError("No ServerHello")
        transcript.extend(sh_b)
        server_random = binascii.unhexlify(json.loads(sh_b.decode())["server_random"])

        # 3) Certificate
        ct, cert_b = tls_record_unwrap(s)
        transcript.extend(cert_b)
        cert_msg = json.loads(cert_b.decode())
        server_cert = x509.load_pem_x509_certificate(cert_msg["cert_pem"].encode())

        # 4) ServerHelloDone
        ct, shdone = tls_record_unwrap(s)
        transcript.extend(shdone)

        # 5) ClientKeyExchange (encrypt premaster with server pubkey)
        premaster = b"\x03\x03" + os.urandom(46)
        enc = server_cert.public_key().encrypt(premaster, padding.PKCS1v15())
        cke = {"enc_pms": binascii.hexlify(enc).decode()}
        cke_b = json.dumps(cke, separators=(",", ":"), sort_keys=True).encode()
        s.sendall(tls_record_pack(RT_HANDSHAKE, TLS_VERSION, cke_b))
        transcript.extend(cke_b)

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

        # 7) ChangeCipherSpec
        s.sendall(tls_record_pack(RT_CHANGE_CIPHER_SPEC, TLS_VERSION, b"\x01"))

        # 8) Finished (send encrypted finished)
        h = hashlib.sha256(); h.update(transcript)
        handshake_hash = h.digest()
        verify_data = tls_prf(master_secret, b"client finished", handshake_hash, 12)
        nonce = make_nonce(client_iv, client_seq)
        enc_fin = client_aes.encrypt(nonce, verify_data, None)
        s.sendall(tls_record_pack(RT_HANDSHAKE, TLS_VERSION,
                                 json.dumps({"nonce": binascii.hexlify(nonce).decode(),
                                             "ct": binascii.hexlify(enc_fin).decode()}).encode()))
        transcript.extend(verify_data)
        client_seq += 1

        # 9) Server Finished
        ct, srv_fin = tls_record_unwrap(s)
        if not srv_fin:
            s.close(); raise RuntimeError("No Server Finished")
        j = json.loads(srv_fin.decode())
        srv_nonce = binascii.unhexlify(j["nonce"])
        srv_ct = binascii.unhexlify(j["ct"])
        srv_plain = server_aes.decrypt(srv_nonce, srv_ct, None)
        expected_srv = tls_prf(master_secret, b"server finished", handshake_hash, 12)
        if not constant_time.bytes_eq(srv_plain, expected_srv):
            s.close(); raise RuntimeError("Server finished mismatch")

        # store
        self.sock = s
        self.client_aes = client_aes
        self.server_aes = server_aes
        self.client_iv = client_iv
        self.server_iv = server_iv
        self.client_seq = client_seq
        self.server_seq = server_seq
        self.alive = True
        self.last_used = time.time()
        self.last_handshake_ms = round((time.time() - start) * 1000, 2)
        # handshake done

    def send_query(self, query_bytes):
        with self.lock:
            if not self.alive or not self.sock:
                try:
                    self._connect_and_handshake()
                except Exception as e:
                    # ensure closed
                    try: self.sock.close()
                    except: pass
                    self.alive = False
                    self.sock = None
                    raise

            try:
                n = make_nonce(self.client_iv, self.client_seq)
                enc = self.client_aes.encrypt(n, query_bytes, None)
                out = {"nonce": binascii.hexlify(n).decode(), "ct": binascii.hexlify(enc).decode()}
                self.sock.sendall(tls_record_pack(RT_APPLICATION_DATA, TLS_VERSION, json.dumps(out).encode()))
                self.client_seq += 1

                ct, app = tls_record_unwrap(self.sock)
                if not app:
                    raise RuntimeError("No application data from upstream")
                j = json.loads(app.decode())
                sn = binascii.unhexlify(j["nonce"]); sc = binascii.unhexlify(j["ct"])
                resp = self.server_aes.decrypt(sn, sc, None)
                self.last_used = time.time()
                return resp
            except Exception as e:
                # close and mark dead -> caller can retry
                try: self.sock.close()
                except: pass
                self.alive = False
                self.sock = None
                raise

# ---------------- Pool manager ----------------
class TLSClientPool:
    def __init__(self, host, port, size=3):
        self.clients = [PersistentTLSClient(host, port) for _ in range(size)]
        self.lock = threading.Lock()
        self.idx = 0
        self.size = size

    def acquire(self):
        with self.lock:
            c = self.clients[self.idx % self.size]
            self.idx += 1
            return c

    def reaper(self, idle=IDLE_CONN_CLOSE):
        # close idle connections periodically
        while True:
            now = time.time()
            for c in self.clients:
                with c.lock:
                    if c.alive and (now - c.last_used) > idle:
                        try:
                            c.sock.close()
                        except:
                            pass
                        c.alive = False
                        c.sock = None
            time.sleep(5)

# ---------------- UDP request handler ----------------
pool = TLSClientPool(UPSTREAM_HOST, UPSTREAM_PORT, size=POOL_SIZE)
threading.Thread(target=pool.reaper, daemon=True).start()
executor = ThreadPoolExecutor(max_workers=WORKER_THREADS)

def handle_request(data, client_addr, udp_sock):
    tstart = time.time()
    # parse query name for logging & cache key
    try:
        req = DNSRecord.parse(data)
        qname = str(req.q.qname).rstrip('.')
    except Exception:
        qname = "<parse-error>"

    # cache check
    cached = cache_get(qname)
    if cached:
        try:
            udp_sock.sendto(cached, client_addr)
            print(f"[CACHE] Served {qname} to {client_addr}")
            return
        except Exception as e:
            print("[!] Failed to send cached reply:", e)

    client = pool.acquire()
    # try once, if fails attempt a reconnect once
    try:
        t0 = time.time()
        reply = client.send_query(data)
        t1 = time.time()
        tls_ms = round((t1 - t0) * 1000, 2)
    except Exception as e:
        # try force reconnect once
        try:
            with client.lock:
                try:
                    if client.sock:
                        client.sock.close()
                except:
                    pass
                client.alive = False
                client.sock = None
            t0 = time.time()
            client._connect_and_handshake()
            reply = client.send_query(data)
            t1 = time.time()
            tls_ms = round((t1 - t0) * 1000, 2)
        except Exception as e2:
            print(f"[!] TLS forward failed for {qname}: {e2}")
            # send SERVFAIL back to client
            try:
                req = DNSRecord.parse(data)
                fail_resp = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=1, rcode=RCODE.SERVFAIL), q=req.q)
                udp_sock.sendto(fail_resp.pack(), client_addr)
            except Exception:
                pass
            return

    # cache reply using TTL from DNS response
    try:
        cache_ttl = cache_set(qname, reply)
    except Exception:
        cache_ttl = CACHE_DEFAULT_TTL

    # send response
    try:
        udp_sock.sendto(reply, client_addr)
    except Exception as e:
        print(f"[!] Failed to send reply to {client_addr}: {e}")

    tend = time.time()
    wall_ms = round((tend - tstart) * 1000, 2)
    print(f"[→] Replied {qname} to {client_addr} (tls_ms={tls_ms} ms, wall_ms={wall_ms} ms, ttl={cache_ttl})")

# ---------------- UDP listener ----------------
def udp_listener(listen_addr=LISTEN_ADDR, listen_port=LISTEN_PORT):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind((listen_addr, listen_port))
    print(f"[*] Local UDP forwarder listening on udp://{listen_addr}:{listen_port}")
    print(f"[*] Forwarding queries to tls://{UPSTREAM_HOST}:{UPSTREAM_PORT} (pool size={POOL_SIZE})")

    while True:
        try:
            data, client_addr = udp_sock.recvfrom(4096)
        except Exception as e:
            print(f"[!] UDP recv error: {e}")
            continue
        executor.submit(handle_request, data, client_addr, udp_sock)

if __name__ == "__main__":
    try:
        udp_listener()
    except PermissionError:
        print("[!] Permission denied binding to port — try different port or run elevated.")
    except Exception as e:
        print("[!] Fatal error:", e)
