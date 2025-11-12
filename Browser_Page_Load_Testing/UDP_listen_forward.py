import socket
import threading
from dnslib import DNSRecord

# ---------------- Configuration ----------------
LISTEN_IP = '127.0.0.1'
LISTEN_PORT = 5533        # Local listener for the SOCKS proxy
UPSTREAM_IP = '10.7.46.109'  # Your actual resolver (dns_server.py)
UPSTREAM_PORT = 8863         # Resolver’s UDP port
TIMEOUT = 15                  # shorter for faster failover

# ---------------- Forward function ----------------
def forward_to_upstream(data):
    """Send query to upstream UDP DNS server and get response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(data, (UPSTREAM_IP, UPSTREAM_PORT))
        print(f"[→] Forwarded query to upstream {UPSTREAM_IP}:{UPSTREAM_PORT}")
        resp, _ = sock.recvfrom(2048)
        return resp
    except socket.timeout:
        print(f"[!] Timeout waiting for response from upstream {UPSTREAM_IP}")
        return None
    except Exception as e:
        print(f"[!] Error forwarding to upstream: {e}")
        return None
    finally:
        sock.close()

# ---------------- Worker function ----------------
def handle_query(data, addr, sock):
    """Handle each DNS query in its own thread."""
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        print(f"[<] Received query from {addr}: {qname}")

        # Forward to upstream server
        response_data = forward_to_upstream(data)
        if response_data:
            sock.sendto(response_data, addr)
            try:
                resp_record = DNSRecord.parse(response_data)
                answers = ", ".join(str(a.rdata) for a in resp_record.rr)
            except Exception:
                answers = "<could not parse answers>"
            print(f"[→] Sent response to {addr} (answers: {answers})")
        else:
            print(f"[!] Upstream failed, no response sent for {qname}")
    except Exception as e:
        print(f"[!] Error handling query from {addr}: {e}")

# ---------------- Main server ----------------
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[*] UDP threaded DNS forwarder listening on {LISTEN_IP}:{LISTEN_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(2048)
            threading.Thread(target=handle_query, args=(data, addr, sock), daemon=True).start()
        except Exception as e:
            print(f"[!] Main loop error: {e}")

if __name__ == "__main__":
    main()
