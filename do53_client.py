import socket
import time
import json
import os
from dnslib import DNSRecord

# ---------------- Configuration ----------------
HOST = "10.7.10.247"  # DNS server IP
PORT = 8853           # Server port
TIMEOUT = 3           # seconds
LOG_FILE = "do53_log_top30003050.json"
DOMAINS_FILE = "top30003050.txt"  # set path to your domains file

# ---------------- Main Client ----------------
def client_run(domain="example.com"):
    """Send a DNS query and log metrics (same schema as DoT/DoH)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    q = DNSRecord.question(domain)
    qbytes = q.pack()

    print(f"[*] Sending DNS query for {domain} to udp://{HOST}:{PORT}")

    bytes_sent = 0
    bytes_recv = 0

    start_total = time.time()

    try:
        # Send query
        sock.sendto(qbytes, (HOST, PORT))
        bytes_sent = len(qbytes)

        # Receive response
        data, _ = sock.recvfrom(2048)
        bytes_recv = len(data)
        end_total = time.time()

        latency_ms = (end_total - start_total) * 1000
        resp = DNSRecord.parse(data)

        print(f"[✓] Response received for {domain} in {latency_ms:.2f} ms")

        # ---------------- Log Entry ----------------
        log = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "domain": domain,
            "protocol": "Do53",             # use "Do53" to match plot labels
            "tcp_handshake_ms": 0.0,
            "tls_handshake_ms": 0.0,
            "query_time_ms": latency_ms,
            "total_time_ms": latency_ms,
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "total_bytes": bytes_sent + bytes_recv,
            "query_size_bytes": len(qbytes),
            "response_size_bytes": len(data),
            "status": "SUCCESS"
        }

        # Append to log file
        try:
            with open(LOG_FILE, "r") as f:
                data_existing = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data_existing = []

        data_existing.append(log)
        with open(LOG_FILE, "w") as f:
            json.dump(data_existing, f, indent=4)

    except socket.timeout:
        print(f"[!] Timeout for {domain}")
        log = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "domain": domain,
            "protocol": "Do53",
            "tcp_handshake_ms": 0.0,
            "tls_handshake_ms": 0.0,
            "query_time_ms": None,
            "total_time_ms": None,
            "bytes_sent": len(qbytes),
            "bytes_recv": 0,
            "total_bytes": len(qbytes),
            "query_size_bytes": len(qbytes),
            "response_size_bytes": 0,
            "status": "TIMEOUT"
        }
        try:
            with open(LOG_FILE, "r") as f:
                data_existing = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data_existing = []
        data_existing.append(log)
        with open(LOG_FILE, "w") as f:
            json.dump(data_existing, f, indent=4)

    except Exception as e:
        print(f"[!] Error for {domain}: {e}")

    finally:
        sock.close()


# ---------------- Batch Mode ----------------
def client_run_from_file():
    """Sequentially query domains from text file."""
    if not os.path.exists(DOMAINS_FILE):
        print(f"[!] '{DOMAINS_FILE}' not found.")
        return

    with open(DOMAINS_FILE, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    # Clean domain names
    domains = []
    for u in urls:
        if u.startswith("https://"):
            u = u[len("https://"):]
        if "/" in u:
            u = u.split("/")[0]
        domains.append(u)

    print(f"\n=== Starting DNS-over-UDP (Do53) queries for {len(domains)} domains ===\n")

    for i, domain in enumerate(domains, 1):
        print(f"({i}/{len(domains)}) Querying: {domain}")
        client_run(domain)
        time.sleep(0.3)

    print("\n✅ All DNS-over-UDP queries completed!\n")


# ---------------- Entry Point ----------------
if __name__ == "__main__":
    client_run_from_file()