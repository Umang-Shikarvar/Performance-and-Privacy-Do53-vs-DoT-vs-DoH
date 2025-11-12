import socket
import struct
import threading
import re
from dnslib import DNSRecord

# ===== CONFIG =====
DNS_LISTENER_IP = "127.0.0.1"
DNS_LISTENER_PORT = 8053
PROXY_IP = "127.0.0.1"
PROXY_PORT = 1080
DNS_TIMEOUT = 12
# ==================


def is_ip_address(hostname):
    """Check if string is already an IP (IPv4 or IPv6)."""
    ipv4_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    ipv6_pattern = r"^[0-9a-fA-F:]+$"
    return re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname)


def resolve_via_listener(hostname):
    if is_ip_address(hostname):
        print(f"[DNS] {hostname} is already an IP.")
        return hostname

    q = DNSRecord.question(hostname)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(DNS_TIMEOUT)
    try:
        sock.sendto(q.pack(), (DNS_LISTENER_IP, DNS_LISTENER_PORT))
        data, _ = sock.recvfrom(2048)
        reply = DNSRecord.parse(data)

        # Follow CNAMEs
        for rr in reply.rr:
            if rr.rtype == 5:  # CNAME
                cname = str(rr.rdata)
                print(f"[DNS] {hostname} is a CNAME → {cname}")
                return resolve_via_listener(cname)

        # Return A or AAAA records
        for rr in reply.rr:
            if rr.rtype in (1, 28):  # A or AAAA
                ip = str(rr.rdata)
                print(f"[DNS] {hostname} → {ip}")
                return ip

        print(f"[DNS] No A/AAAA record found for {hostname}")
        return None

    except Exception as e:
        print(f"[DNS] Resolution failed for {hostname}: {e}")
        return None
    finally:
        sock.close()



def pipe(src, dst):
    """Bidirectional data relay."""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            src.close()
        except Exception:
            pass
        try:
            dst.close()
        except Exception:
            pass


def handle_client(client_sock):
    try:
        # SOCKS5 handshake
        client_sock.recv(2)
        client_sock.recv(1)
        client_sock.sendall(b"\x05\x00")

        # SOCKS5 request
        ver, cmd, _, atyp = client_sock.recv(4)
        if atyp == 3:  # domain name
            domain_len = client_sock.recv(1)[0]
            domain = client_sock.recv(domain_len).decode()
            port = struct.unpack(">H", client_sock.recv(2))[0]
            print(f"[>] SOCKS request for {domain}:{port}")

            ip = resolve_via_listener(domain)
            if not ip:
                print(f"[!] Could not resolve {domain}, closing.")
                client_sock.close()
                return

            try:
                family = socket.AF_INET6 if ":" in ip else socket.AF_INET
                remote_sock = socket.socket(family, socket.SOCK_STREAM)
                remote_sock.settimeout(10)
                remote_sock.connect((ip, port))
                print(f"[✓] Connected to {domain} at {ip}:{port}")
            except Exception as e:
                print(f"[!] Connect failed to {ip}:{port} — {e}")
                client_sock.close()
                return

            # Send success response to browser
            try:
                client_sock.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", port))
            except Exception:
                pass

            # Pipe traffic
            threading.Thread(target=pipe, args=(client_sock, remote_sock), daemon=True).start()
            pipe(remote_sock, client_sock)

        else:
            print("[!] Unsupported address type.")
    except Exception as e:
        print(f"[!] SOCKS client error: {e}")
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


def main():
    """Main SOCKS5 loop."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((PROXY_IP, PROXY_PORT))
    server.listen(100)
    print(f"[*] SOCKS5 proxy listening on {PROXY_IP}:{PROXY_PORT}")

    while True:
        client_sock, addr = server.accept()
        print(f"[+] New connection from {addr}")
        threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()


if __name__ == "__main__":
    main()
