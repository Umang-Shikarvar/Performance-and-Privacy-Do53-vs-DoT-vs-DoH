# """
# https_google_doh.py
# ---------------------------------
# Measure DNS-over-HTTPS (DoH) latency and performance using Google's DoH endpoint.
# Logs results in the same CSV format as DoT and Do53 tests.
# """

# import time
# import csv
# import os
# import requests
# from datetime import datetime, timezone
# from dnslib import DNSRecord

# # -------- Configuration --------
# DOMAINS_FILE = "/Users/tejasmacipad/Desktop/final_CN_project/CN_Project/Report/top30003050.txt"          # Input: one domain per line
# OUTPUT_CSV   = "dns_google_dot_bot50.csv" # Output file
# DOH_URL      = "https://dns.google/dns-query"
# TIMEOUT      = 5.0
# RUNS_PER_DOMAIN = 1
# DOH_HOST = "dns.google"
# DOH_PORT = 443

# # -------- Helper Functions --------
# def load_domains(path):
#     """Read up to 50 unique cleaned domains."""
#     seen, keep = set(), []
#     with open(path, "r", encoding="utf-8") as f:
#         for line in f:
#             d = line.strip().rstrip(".").lower()
#             d = d.replace("https://", "").replace("http://", "")
#             if not d or d in seen:
#                 continue
#             seen.add(d)
#             keep.append(d)
#             if len(keep) == 50:
#                 break
#     return keep


# def ensure_csv(path):
#     """Ensure output CSV file has headers."""
#     if not os.path.exists(path):
#         with open(path, "w", newline="", encoding="utf-8") as f:
#             w = csv.writer(f)
#             w.writerow([
#                 "timestamp_utc", "domain", "protocol", "status",
#                 "rcode", "tls_version", "cipher_suite",
#                 "tcp_connect_ms", "tls_handshake_ms",
#                 "query_rtt_ms", "bytes_out", "bytes_in"
#             ])


# def append_row(path, row):
#     """Append one row to CSV."""
#     with open(path, "a", newline="", encoding="utf-8") as f:
#         csv.writer(f).writerow(row)


# def query_doh(domain):
#     """Perform a DNS-over-HTTPS query to Google's endpoint."""
#     q = DNSRecord.question(domain, qtype="A").pack()
#     headers = {
#         "Content-Type": "application/dns-message",
#         "Accept": "application/dns-message"
#     }

#     session = requests.Session()

#     # Measure connect + TLS + total RTT
#     start_total = time.perf_counter()
#     try:
#         response = session.post(DOH_URL, data=q, headers=headers, timeout=TIMEOUT)
#         end_total = time.perf_counter()
#     except requests.exceptions.ConnectTimeout:
#         raise TimeoutError("TCP_CONNECT_TIMEOUT")
#     except requests.exceptions.SSLError as e:
#         raise RuntimeError(f"TLS_ERROR: {e}")
#     except requests.exceptions.RequestException as e:
#         raise RuntimeError(f"HTTPS_ERROR: {e}")

#     query_rtt_ms = (end_total - start_total) * 1000.0
#     bytes_out = len(q)
#     bytes_in = len(response.content)

#     # Extract RCODE if possible
#     try:
#         resp_parsed = DNSRecord.parse(response.content)
#         rcode = int(resp_parsed.header.rcode)
#     except Exception:
#         rcode = ""

#     # Extract TLS info (requests doesn’t expose directly)
#     tls_version = "TLS"
#     cipher_suite = "HTTPS"

#     # Approximation: TCP+TLS connect time not directly exposed — measure via timing breakdown
#     tcp_connect_ms = ""
#     tls_handshake_ms = ""

#     return (
#         round(query_rtt_ms, 3),
#         bytes_out,
#         bytes_in,
#         rcode,
#         tls_version,
#         cipher_suite,
#         tcp_connect_ms,
#         tls_handshake_ms
#     )


# # -------- Main --------
# def main():
#     domains = load_domains(DOMAINS_FILE)
#     if not domains:
#         print(f"[!] No domains found in {DOMAINS_FILE}")
#         return

#     print(f"[i] Loaded {len(domains)} domains (max 50)")
#     ensure_csv(OUTPUT_CSV)

#     for domain in domains:
#         for _ in range(RUNS_PER_DOMAIN):
#             ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
#             try:
#                 rtt_ms, bout, bin_, rcode, tls_ver, cipher, tcp_ms, tls_ms = query_doh(domain)
#                 row = [
#                     ts, domain, "DoH", "SUCCESS", rcode,
#                     tls_ver, cipher, tcp_ms, tls_ms,
#                     rtt_ms, bout, bin_
#                 ]
#             except TimeoutError:
#                 row = [ts, domain, "DoH", "TIMEOUT", "", "", "", "", "", "", "", ""]
#             except Exception as e:
#                 row = [ts, domain, "DoH", "ERROR", "", "", "", "", "", "", "", str(e)]

#             append_row(OUTPUT_CSV, row)
#             print(row)


# if __name__ == "__main__":
#     main()


"""
https_google_doh.py
---------------------------------
Measure DNS-over-HTTPS (DoH) latency and performance using Google's DoH endpoint.
Logs results in the same CSV format as DoT and Do53 tests.
"""

import time
import csv
import os
import requests
import socket
import ssl
from datetime import datetime, timezone
from dnslib import DNSRecord

# -------- Configuration --------
DOMAINS_FILE = "/Users/tejasmacipad/Desktop/final_CN_project/CN_Project/Report/top50.txt"          # Input: one domain per line
OUTPUT_CSV   = "dns_google_dot_top50.csv" # Output file
DOH_URL      = "https://dns.google/dns-query"
TIMEOUT      = 5.0
RUNS_PER_DOMAIN = 1
DOH_HOST = "dns.google"
DOH_PORT = 443

# -------- Helper Functions --------
def load_domains(path):
    """Read up to 50 unique cleaned domains."""
    seen, keep = set(), []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            d = line.strip().rstrip(".").lower()
            d = d.replace("https://", "").replace("http://", "")
            if not d or d in seen:
                continue
            seen.add(d)
            keep.append(d)
            if len(keep) == 50:
                break
    return keep

def ensure_csv(path):
    """Ensure output CSV file has headers."""
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                "timestamp_utc", "domain", "protocol", "status",
                "rcode", "tls_version", "cipher_suite",
                "tcp_connect_ms", "tls_handshake_ms",
                "query_rtt_ms", "bytes_out", "bytes_in"
            ])

def append_row(path, row):
    """Append one row to CSV."""
    with open(path, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(row)

def measure_connect_tls(host: str, port: int, timeout: float):
    """
    Lightweight probe to measure TCP connect and TLS handshake times.
    Returns (tcp_connect_ms, tls_handshake_ms, tls_version, cipher_suite).
    """
    # TCP connect timing
    t0 = time.perf_counter()
    s = socket.create_connection((host, port), timeout=timeout)
    t1 = time.perf_counter()
    tcp_connect_ms = (t1 - t0) * 1000.0

    # TLS handshake timing
    ctx = ssl.create_default_context()
    t2 = time.perf_counter()
    ssock = ctx.wrap_socket(s, server_hostname=host)
    t3 = time.perf_counter()
    tls_handshake_ms = (t3 - t2) * 1000.0

    # TLS details
    tls_version = ssock.version() or "TLS"
    try:
        cipher = ssock.cipher()
        cipher_suite = cipher[0] if isinstance(cipher, tuple) else str(cipher)
    except Exception:
        cipher_suite = "HTTPS"

    # Close TLS socket (requests will open its own connection)
    try:
        ssock.close()
    except Exception:
        pass

    return (
        round(tcp_connect_ms, 3),
        round(tls_handshake_ms, 3),
        tls_version,
        cipher_suite
    )

def query_doh(domain):
    """Perform a DNS-over-HTTPS query to Google's endpoint."""
    q = DNSRecord.question(domain, qtype="A").pack()
    headers = {
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message"
    }

    # 1) Measure TCP connect and TLS handshake to dns.google
    try:
        tcp_connect_ms, tls_handshake_ms, tls_version, cipher_suite = measure_connect_tls(
            DOH_HOST, DOH_PORT, TIMEOUT
        )
    except socket.timeout:
        raise TimeoutError("TCP_CONNECT_TIMEOUT")
    except ssl.SSLError as e:
        raise RuntimeError(f"TLS_ERROR: {e}")
    except Exception as e:
        # Keep behavior consistent with the rest of the code: surface a generic HTTPS error
        raise RuntimeError(f"HTTPS_ERROR: {e}")

    # 2) Measure total POST RTT for the actual DoH query
    session = requests.Session()
    start_total = time.perf_counter()
    try:
        response = session.post(DOH_URL, data=q, headers=headers, timeout=TIMEOUT)
        end_total = time.perf_counter()
    except requests.exceptions.ConnectTimeout:
        raise TimeoutError("TCP_CONNECT_TIMEOUT")
    except requests.exceptions.SSLError as e:
        raise RuntimeError(f"TLS_ERROR: {e}")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"HTTPS_ERROR: {e}")

    query_rtt_ms = (end_total - start_total) * 1000.0
    bytes_out = len(q)
    bytes_in = len(response.content)

    # Extract RCODE if possible
    try:
        resp_parsed = DNSRecord.parse(response.content)
        rcode = int(resp_parsed.header.rcode)
    except Exception:
        rcode = ""

    # Return values with the exact variable names used by the caller
    return (
        round(query_rtt_ms, 3),
        bytes_out,
        bytes_in,
        rcode,
        tls_version,
        cipher_suite,
        tcp_connect_ms,
        tls_handshake_ms
    )

# -------- Main --------
def main():
    domains = load_domains(DOMAINS_FILE)
    if not domains:
        print(f"[!] No domains found in {DOMAINS_FILE}")
        return

    print(f"[i] Loaded {len(domains)} domains (max 50)")
    ensure_csv(OUTPUT_CSV)

    for domain in domains:
        for _ in range(RUNS_PER_DOMAIN):
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            try:
                rtt_ms, bout, bin_, rcode, tls_ver, cipher, tcp_ms, tls_ms = query_doh(domain)
                row = [
                    ts, domain, "DoH", "SUCCESS", rcode,
                    tls_ver, cipher, tcp_ms, tls_ms,
                    rtt_ms, bout, bin_
                ]
            except TimeoutError:
                row = [ts, domain, "DoH", "TIMEOUT", "", "", "", "", "", "", "", ""]
            except Exception as e:
                row = [ts, domain, "DoH", "ERROR", "", "", "", "", "", "", "", str(e)]

            append_row(OUTPUT_CSV, row)
            print(row)

if __name__ == "__main__":
    main()
