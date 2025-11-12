import socket, time, csv, os
from datetime import datetime
from dnslib import DNSRecord

# -------- Config --------
DOMAINS_FILE = "/Users/tejasmacipad/Desktop/CN/FinalProject/CN_Project/CN project/top30003050.txt"      # input file, one domain per line
# DOMAINS_FILE = "/Users/tejasmacipad/Desktop/CN/FinalProject/CN_Project/CN project/top50.txt" 
OUTPUT_CSV   = "dns_cf_do53_bot50d.csv"  # results
# OUTPUT_CSV   = "dns_cf_do53_top.csv"  # results
UPSTREAM     = ("8.8.8.8", 53)    # Cloudflare Do53
TIMEOUT      = 3.0                # seconds
RUNS_PER_DOMAIN = 1               # set >1 if you want repeated measures per domain

# -------- Helpers --------
def load_top50(path):
    """Read up to first 50 unique domains (order-preserving)."""
    seen, keep = set(), []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            d = line.strip().rstrip(".").lower()
            if not d: 
                continue
            if d in seen:
                continue
            seen.add(d)
            keep.append(d)
            if len(keep) == 50:
                break
    return keep

def ensure_csv(path):
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                "timestamp_utc", "domain", "qtype", "status", "rcode",
                "rtt_ms", "bytes_out", "bytes_in"
            ])

def append_row(path, row):
    with open(path, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(row)

def query_once(domain: str):
    """Send one UDP DNS A query to Cloudflare and measure RTT + byte sizes."""
    q = DNSRecord.question(domain, qtype="A").pack()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        t0 = time.perf_counter()
        bytes_out = s.sendto(q, UPSTREAM)
        resp, _ = s.recvfrom(65535)
        t1 = time.perf_counter()
    rtt_ms = (t1 - t0) * 1000.0
    bytes_in = len(resp)
    # Best-effort extract RCODE; keep lightweight to avoid overhead
    try:
        rcode = int(DNSRecord.parse(resp).header.rcode)
    except Exception:
        rcode = ""
    return rtt_ms, bytes_out, bytes_in, rcode

# -------- Main --------
def main():
    domains = load_top50(DOMAINS_FILE)
    if not domains:
        print(f"[!] No domains found in {DOMAINS_FILE}")
        return
    print(f"[i] Loaded {len(domains)} domains (max 50)")

    ensure_csv(OUTPUT_CSV)

    for d in domains:
        for _ in range(RUNS_PER_DOMAIN):
            ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
            try:
                rtt_ms, bout, bin_, rcode = query_once(d)
                row = [ts, d, "A", "SUCCESS", rcode, round(rtt_ms, 3), bout, bin_]
            except socket.timeout:
                row = [ts, d, "A", "TIMEOUT", 2, round(TIMEOUT * 1000.0, 3), "", ""]
            except Exception:
                row = [ts, d, "A", "ERROR", "", "", "", ""]
            append_row(OUTPUT_CSV, row)
            print(row)

if __name__ == "__main__":
    main()
