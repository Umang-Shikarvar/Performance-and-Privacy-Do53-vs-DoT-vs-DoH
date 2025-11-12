import socket, struct, json, os, binascii, time, hashlib, hmac
from dnslib import DNSRecord
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509

# ---------------- Configuration ----------------
HOST = "10.7.10.247"   # DoH server (your TLS server)
PORT = 8453           # DoH port
RT_HANDSHAKE = 22
RT_CHANGE_CIPHER_SPEC = 20
RT_APPLICATION_DATA = 23
TLS_VERSION = (3, 3)
LOG_FILE = "doh_log_top30003050.json"
CA_CERT_PATH = "ca.crt.pem"  # adjust path to your CA cert if needed
DOMAINS_FILE = "top30003050.txt"  # set path to your domains file

# ---------------- Packet Size Tracker ----------------
bytes_sent = 0
bytes_recv = 0


def tracked_send(sock, data: bytes):
    """Send data and increment sent counter"""
    global bytes_sent
    sock.sendall(data)
    bytes_sent += len(data)


def tracked_recv(sock, n: int) -> bytes:
    """Receive up to n bytes and increment recv counter"""
    global bytes_recv
    data = sock.recv(n)
    bytes_recv += len(data)
    return data


# ---------------- Helpers ----------------
def recvn(sock, n):
    """Read exactly n bytes using tracked_recv"""
    buf = b""
    while len(buf) < n:
        chunk = tracked_recv(sock, n - len(buf))
        if not chunk:
            return None
        buf += chunk
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
    """TLS1.2 GCM nonce = fixed_iv XOR seq (on last 4 bytes)."""
    if len(iv12) != 12:
        raise ValueError("IV must be 12 bytes")
    seq_bytes = seq.to_bytes(4, "big")
    nb = bytearray(iv12)
    for i in range(4):
        nb[8 + i] ^= seq_bytes[i]
    return bytes(nb)


# ---------------- Main Client ----------------
def client_run(domain="example.com"):
    """
    Run one DoH query over your custom TLS1.2-like record protocol and log timings.
    """
    global bytes_sent, bytes_recv
    bytes_sent = 0
    bytes_recv = 0
    total_start = time.time()

    # --- TCP handshake timing ---
    tcp_start = time.time()
    try:
        s = socket.create_connection((HOST, PORT))
    except Exception as e:
        print(f"[!] TCP connection failed: {e}")
        return
    tcp_end = time.time()

    # --- TLS handshake phases ---
    transcript = bytearray()
    tls_phases = {}
    tls_start = time.time()

    # 1) ClientHello
    client_random = os.urandom(32)
    ch = {"client_random": binascii.hexlify(client_random).decode()}
    ch_bytes = json.dumps(ch, separators=(",", ":"), sort_keys=True).encode()
    transcript.extend(ch_bytes)
    tracked_send(s, tls_record_pack(RT_HANDSHAKE, TLS_VERSION, ch_bytes))
    tls_phases["client_hello_sent"] = time.time()

    # 2) ServerHello
    ct, sh_bytes = tls_record_unwrap(s)
    tls_phases["server_hello_received"] = time.time()
    if not sh_bytes:
        print("[!] No ServerHello")
        s.close()
        return
    transcript.extend(sh_bytes)
    sh = json.loads(sh_bytes.decode())
    server_random = binascii.unhexlify(sh.get("server_random", ""))

    # 3) Certificate
    ct, cert_bytes = tls_record_unwrap(s)
    tls_phases["certificate_received"] = time.time()
    if not cert_bytes:
        print("[!] No Certificate")
        s.close()
        return
    transcript.extend(cert_bytes)
    cert_msg = json.loads(cert_bytes.decode())
    server_cert = x509.load_pem_x509_certificate(cert_msg["cert_pem"].encode())

    # Verify certificate with configured CA (best-effort)
    try:
        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        ca_cert.public_key().verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server_cert.signature_hash_algorithm,
        )
        print("[✓] Server cert verified by CA")
    except Exception as e:
        print("[!] Certificate verification failed (continuing):", e)

    # 4) ServerHelloDone
    ct, shdone = tls_record_unwrap(s)
    tls_phases["server_hello_done"] = time.time()
    transcript.extend(shdone or b"")

    # 5) ClientKeyExchange
    premaster = b"\x03\x03" + os.urandom(46)
    server_pub = server_cert.public_key()
    enc = server_pub.encrypt(premaster, padding.PKCS1v15())
    cke = {"enc_pms": binascii.hexlify(enc).decode()}
    cke_b = json.dumps(cke, separators=(",", ":"), sort_keys=True).encode()
    transcript.extend(cke_b)
    tracked_send(s, tls_record_pack(RT_HANDSHAKE, TLS_VERSION, cke_b))

    # 6) Key derivation
    master_secret = tls_prf(premaster, b"master secret", client_random + server_random, 48)
    key_block = tls_prf(master_secret, b"key expansion", server_random + client_random, 64)
    idx = 0
    client_write_key = key_block[idx:idx + 16]; idx += 16
    server_write_key = key_block[idx:idx + 16]; idx += 16
    client_iv = key_block[idx:idx + 12]; idx += 12
    server_iv = key_block[idx:idx + 12]; idx += 12

    client_aes = AESGCM(client_write_key)
    server_aes = AESGCM(server_write_key)
    client_seq = 0
    server_seq = 0

    # 7) ChangeCipherSpec
    tracked_send(s, tls_record_pack(RT_CHANGE_CIPHER_SPEC, TLS_VERSION, b"\x01"))

    # 8) Finished (send)
    h = hashlib.sha256()
    h.update(transcript)
    handshake_hash = h.digest()
    verify_data = tls_prf(master_secret, b"client finished", handshake_hash, 12)
    nonce = make_nonce(client_iv, client_seq)
    ct_bytes = client_aes.encrypt(nonce, verify_data, None)
    msg = {"nonce": binascii.hexlify(nonce).decode(), "ct": binascii.hexlify(ct_bytes).decode()}
    tracked_send(s, tls_record_pack(RT_HANDSHAKE, TLS_VERSION, json.dumps(msg, separators=(",", ":"), sort_keys=True).encode()))
    client_seq += 1
    transcript.extend(verify_data)

    # 9) Server Finished (recv)
    ct_type, srv_fin = tls_record_unwrap(s)
    if not srv_fin:
        print("[!] No Server Finished")
        s.close()
        return
    j = json.loads(srv_fin.decode())
    srv_nonce = binascii.unhexlify(j["nonce"])
    srv_ct = binascii.unhexlify(j["ct"])
    srv_plain = server_aes.decrypt(srv_nonce, srv_ct, None)
    expected_srv = tls_prf(master_secret, b"server finished", handshake_hash, 12)
    if srv_plain != expected_srv:
        print("[!] Server Finished mismatch!")
        s.close()
        return
    tls_phases["server_finished_received"] = time.time()
    tls_end = tls_phases["server_finished_received"]
    print("[*] TLS handshake complete (client)")

    # --- Build DoH HTTP POST carrying DNS wire format ---
    q = DNSRecord.question(domain)
    dns_query = q.pack()
    http_req = (
        f"POST /dns-query HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Content-Type: application/dns-message\r\n"
        f"Accept: application/dns-message\r\n"
        f"User-Agent: CustomDoHClient/1.0\r\n"
        f"Content-Length: {len(dns_query)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + dns_query

    # encrypt and send as application data
    send_time = time.time()
    nonce = make_nonce(client_iv, client_seq)
    enc_http = client_aes.encrypt(nonce, http_req, None)
    out_msg = {"nonce": binascii.hexlify(nonce).decode(), "ct": binascii.hexlify(enc_http).decode()}
    tracked_send(s, tls_record_pack(RT_APPLICATION_DATA, TLS_VERSION, json.dumps(out_msg, separators=(",", ":"), sort_keys=True).encode()))
    client_seq += 1

    # receive application data (DoH response)
    query_start = time.time()
    ct_type, app = tls_record_unwrap(s)
    query_end = time.time()
    recv_time = query_end

    if not app:
        print("[!] No Application Data received")
        s.close()
        return

    j = json.loads(app.decode())
    srv_nonce = binascii.unhexlify(j["nonce"])
    srv_ct = binascii.unhexlify(j["ct"])
    plain_resp = server_aes.decrypt(srv_nonce, srv_ct, None)

    # Try to parse HTTP headers + body
    try:
        parts = plain_resp.split(b"\r\n\r\n", 1)
        if len(parts) == 2:
            headers_bytes, body_bytes = parts
            headers_text = headers_bytes.decode(errors="ignore")
            print("\n========= Decrypted HTTPS Headers =========\n")
            print(headers_text)
            print("===========================================\n")
            if b"application/dns-message" in headers_bytes.lower():
                resp = DNSRecord.parse(body_bytes)
                print("[DNS Response - DoH body]\n", resp)
            else:
                print("Non-DNS HTTP response:")
                print(plain_resp.decode(errors="ignore"))
        else:
            resp = DNSRecord.parse(plain_resp)
            print("[DNS Response - raw DNS bytes]\n", resp)
    except Exception as e:
        print("Failed to parse DoH response:", e)

    # --- Timing & bandwidth calculations ---
    tcp_handshake_ms = (tcp_end - tcp_start) * 1000
    tls_handshake_ms = (tls_end - tls_start) * 1000
    query_time_ms = (query_end - query_start) * 1000
    total_time_ms = (recv_time - total_start) * 1000
    total_bytes = bytes_sent + bytes_recv

    log = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "domain": domain,
        "protocol": "DoH",
        "tcp_handshake_ms": tcp_handshake_ms,
        "tls_handshake_ms": tls_handshake_ms,
        "query_time_ms": query_time_ms,
        "total_time_ms": total_time_ms,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "total_bytes": total_bytes,
        "query_size_bytes": len(http_req),
        "response_size_bytes": len(plain_resp),
        "status": "SUCCESS"
    }

    # append to log file
    try:
        with open(LOG_FILE, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []
    data.append(log)
    with open(LOG_FILE, "w") as f:
        json.dump(data, f, indent=4)

    print(f"[✓] Logged result for {domain}: total {total_time_ms:.2f} ms")
    s.close()


# ---------------- Batch Mode ----------------
def client_run_from_file(domains_file=DOMAINS_FILE):
    """
    Reads domain lines from a text file and queries them sequentially (no threading).
    Each line may be a hostname or a URL starting with https://
    """
    if not os.path.exists(domains_file):
        print(f"[!] '{domains_file}' not found.")
        return

    with open(domains_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    # extract clean domains
    domains = []
    for u in urls:
        if u.startswith("https://"):
            u = u[len("https://"):]
        if "/" in u:
            u = u.split("/")[0]
        domains.append(u)

    print(f"\n=== Starting DoH queries for {len(domains)} domains ===\n")
    for i, domain in enumerate(domains, 1):
        print(f"({i}/{len(domains)}) Querying: {domain}")
        try:
            client_run(domain)
        except Exception as e:
            print(f"[!] Error for {domain}: {e}")
        time.sleep(0.3)

    print("\n✅ All DoH queries completed successfully!\n")


if __name__ == "__main__":
    # adjust DOMAINS_FILE or pass a different file name when calling
    client_run_from_file()