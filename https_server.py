# tls12_server_resolver.py
import socket, threading, os, struct, json, binascii, time
from dnslib import DNSRecord, RR, QTYPE, RCODE, A, DNSHeader
from cryptography.hazmat.primitives import serialization, hashes, constant_time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
import hashlib, hmac
from utils import perform_iterative_resolution, save_log_json

# ---------------- Configuration ----------------
HOST = "0.0.0.0"
PORT = 8453                # Standard HTTPS port for DoH
RT_HANDSHAKE = 22         # Record type: Handshake
RT_CHANGE_CIPHER_SPEC = 20  # Record type: ChangeCipherSpec
RT_APPLICATION_DATA = 23  # Record type: Application Data

TLS_VERSION = (3, 3)      # Actual TLS 1.2 record-layer version
HTTPS_VERSION = TLS_VERSION  # Alias for readability in HTTPS context

# Logging filename (utils.perform_iterative_resolution also logs by default;
# we also call save_log_json here to ensure client IP is recorded)
JSON_LOGFILE = "doh.json"

# Load certificates
with open("server.key.pem", "rb") as f:
    SERVER_KEY = serialization.load_pem_private_key(f.read(), password=None)
with open("server.crt.pem", "rb") as f:
    SERVER_CERT = x509.load_pem_x509_certificate(f.read())
with open("ca.crt.pem", "rb") as f:
    CA_CERT = x509.load_pem_x509_certificate(f.read())

# =====================================================
#                PRF + TLS UTILITIES
# =====================================================
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
    """TLS1.2 GCM nonce = fixed_iv XOR seq on last 4 bytes"""
    seq_bytes = seq.to_bytes(4, "big")
    nb = bytearray(iv12)
    for i in range(4):
        nb[8 + i] ^= seq_bytes[i]
    return bytes(nb)

# =====================================================
#             MAIN CONNECTION HANDLER
# =====================================================
def handle_connection(conn, addr):
    print("[+] connection", addr)
    transcript = bytearray()
    try:
        # 1) ClientHello
        ct, data = tls_record_unwrap(conn)
        if ct != RT_HANDSHAKE or data is None:
            print("expected ClientHello")
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
            print("expected ClientKeyExchange")
            conn.close(); return
        transcript.extend(cke)
        ckej = json.loads(cke.decode())
        encrypted_pms = binascii.unhexlify(ckej["enc_pms"])
        premaster = SERVER_KEY.decrypt(encrypted_pms, padding.PKCS1v15())
        if len(premaster) < 48:
            print("invalid premaster")
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
            print("Expected ChangeCipherSpec")
            conn.close(); return

        # 7) Client Finished
        ct, encfin = tls_record_unwrap(conn)
        if ct != RT_HANDSHAKE or encfin is None:
            print("Expected encrypted Finished")
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
            print("Finished mismatch")
            conn.close(); return
        transcript.extend(plain_finished)

        # 8) Send Server Finished
        server_verify = tls_prf(master_secret, b"server finished", handshake_hash, 12)
        server_nonce = make_nonce(server_iv, server_seq)
        server_ct = server_aes.encrypt(server_nonce, server_verify, None)
        out = {"nonce": binascii.hexlify(server_nonce).decode(), "ct": binascii.hexlify(server_ct).decode()}
        conn.sendall(tls_record_pack(RT_HANDSHAKE, TLS_VERSION, json.dumps(out).encode("utf-8")))
        server_seq += 1

        print("[*] HTTPS handshake complete (TLS1.2) (server)")

        # =====================================================
        #              DNS / DoH REQUEST HANDLING
        # =====================================================
        ct, app = tls_record_unwrap(conn)
        if ct != RT_APPLICATION_DATA or app is None:
            print("Expected application data"); conn.close(); return
        j = json.loads(app.decode())
        nonce = binascii.unhexlify(j["nonce"])
        ctext = binascii.unhexlify(j["ct"])
        plain = client_aes.decrypt(nonce, ctext, None)

        dns_query_bytes = None
        is_http = True

        try:
            # Detect HTTP POST for DoH
            if plain.startswith(b"POST") or plain.startswith(b"GET"):
                # Find header/body split safely using bytes
                sep = b"\r\n\r\n"
                header_end = plain.find(sep)
                if header_end == -1:
                    print("Malformed HTTP request")
                    conn.close()
                    return

                headers = plain[:header_end].decode(errors="ignore")
                body_bytes = plain[header_end + len(sep):]

                print("\n===== HTTP request received =====")
                print(headers)
                print("=================================\n")

                if b"application/dns-message" in plain.lower():
                    dns_query_bytes = body_bytes  # RAW binary DNS message
                else:
                    # Base64 fallback
                    try:
                        dns_query_bytes = binascii.a2b_base64(body_bytes.strip())
                    except Exception:
                        dns_query_bytes = body_bytes

                # Parse actual DNS query now
                req = DNSRecord.parse(dns_query_bytes)
                qname = str(req.q.qname)
                print(f"[DoH] Extracted DNS query for: {qname}")
            else:
                # Regular DNS-over-TLS
                req = DNSRecord.parse(plain)
                qname = str(req.q.qname)
                dns_query_bytes = plain

        except Exception as e:
            print("Failed to parse query:", e)
            qname = "<parse-error>"
            dns_query_bytes = plain

        print(f"→ Query for: {qname} -- resolving via utils.perform_iterative_resolution")

        # =====================================================
        #      DNS Resolution via utils.perform_iterative_resolution
        # =====================================================
        try:
            # Use the extracted binary DNS payload for resolution (not the full HTTP message)
            response, details, duration_ms, queried_name = perform_iterative_resolution(dns_query_bytes)
        except TypeError:
            # fallback for older signature
            response, details, duration_ms, queried_name = perform_iterative_resolution(
                dns_query_bytes, is_subquery=False
            )

        status = "SUCCESS" if response else "FAILED"

        # If resolver failed, generate SERVFAIL response
        if not response:
            try:
                req = DNSRecord.parse(dns_query_bytes)
                fail_resp = DNSRecord(
                    DNSHeader(
                        id=req.header.id, qr=1, aa=1, ra=1, rcode=RCODE.SERVFAIL
                    ),
                    q=req.q,
                )
                reply_bytes = fail_resp.pack()
            except Exception:
                fallback = DNSRecord(
                    DNSHeader(id=0, qr=1, aa=1, ra=1, rcode=RCODE.SERVFAIL)
                )
                reply_bytes = fallback.pack()
        else:
            reply_bytes = response

        # Save enriched JSON log (with step-by-step trace)
        record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "client_ip": addr[0],
            "queried_domain": queried_name if queried_name else qname,
            "resolution_steps": details,
            "total_time_ms": duration_ms,
            "status": status,
        }

        try:
            save_log_json(JSON_LOGFILE, record)
        except Exception as e:
            print("Failed to save log:", e)

        print(f"[LOGGED] {record['queried_domain']} ({status}, {duration_ms} ms)")

        # =====================================================
        # Build response (HTTP if DoH)
        # =====================================================
        if is_http:
            http_resp = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/dns-message\r\n"
                f"Content-Length: {len(reply_bytes)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode() + reply_bytes
            payload = http_resp
        else:
            payload = reply_bytes

        # Encrypt and send
        resp_nonce = make_nonce(server_iv, server_seq)
        resp_ct = server_aes.encrypt(resp_nonce, payload, None)
        out = {"nonce": binascii.hexlify(resp_nonce).decode(), "ct": binascii.hexlify(resp_ct).decode()}
        conn.sendall(tls_record_pack(RT_APPLICATION_DATA, TLS_VERSION, json.dumps(out).encode("utf-8")))
        server_seq += 1

    except Exception as e:
        print("Server error:", e)
    finally:
        conn.close()
        print("[-] closed", addr)

# =====================================================
#                   MAIN SERVER LOOP
# =====================================================
def server_main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"HTTPS (TLS1.2) DNS resolver server listening on https://{HOST}:{PORT}")
    while True:
        c, a = s.accept()
        threading.Thread(target=handle_connection, args=(c, a), daemon=True).start()

if __name__ == "__main__":
    server_main()