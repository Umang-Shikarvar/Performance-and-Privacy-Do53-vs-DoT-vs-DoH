#!/usr/bin/env python3
"""
utils_fast.py
- Parallelized iterative resolution helper.
- Keeps core logic from your original utils, but:
  * resolves NS lookups in parallel using ThreadPoolExecutor
  * returns (response_bytes, logs, total_time_ms, qname)
  * exposes ROOT_SERVERS constant for reuse
"""
import socket
import time
from dnslib import DNSRecord, QTYPE
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------- Root DNS server list ----------------
ROOT_SERVERS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33"
]

# timeout per UDP query (shorter for faster failover)
UDP_TIMEOUT = 5
MAX_NS_WORKERS = 6

def ret_step(resp, step):
    if step == 1:
        return "Root"
    elif len(resp.auth) > 0 and not resp.rr:
        return "TLD"
    else:
        return "Authoritative"

def _udp_query(server, query_bytes, timeout=UDP_TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        start = time.time()
        s.sendto(query_bytes, (server, 53))
        data, _ = s.recvfrom(4096)
        rtt = (time.time() - start) * 1000
        return data, rtt
    except Exception:
        return None, None
    finally:
        s.close()

def _resolve_ns_name_parallel(ns_names, visited):
    """Given a list of NS hostnames, resolve them in parallel and return IP list."""
    ips = []
    # We resolve NS names using the same perform_iterative_resolution function (subqueries).
    # Use a small threadpool to parallelize these subqueries.
    with ThreadPoolExecutor(max_workers=MAX_NS_WORKERS) as ex:
        futures = {ex.submit(perform_iterative_resolution, bytes(DNSRecord.question(ns).pack()), True, visited.copy()): ns for ns in ns_names}
        for fut in as_completed(futures):
            try:
                new_resp, _, _, _ = fut.result()
                if new_resp:
                    parsed = DNSRecord.parse(new_resp)
                    for rr in parsed.rr:
                        if rr.rtype == 1:
                            ips.append(str(rr.rdata))
            except Exception:
                continue
    return ips

# ---------------- Core Resolver ----------------
def perform_iterative_resolution(query_bytes, log_file=None, is_subquery=False, visited=None):
    query_packet = DNSRecord.parse(query_bytes)
    qname = str(query_packet.q.qname)

    if visited is None:
        visited = set()
    # Prevent infinite recursion / loops
    if qname in visited:
        return None, [], 0, qname
    visited.add(qname)

    logs = []
    start_time = time.time()
    servers = ROOT_SERVERS.copy()
    response = None
    step = 0

    while True:
        step += 1
        if not servers:
            break
        server = servers[0]

        data, rtt = _udp_query(server, query_bytes)
        if data is None:
            logs.append({
                "step": step,
                "mode": "Iterative",
                "stage_resolution": "Timeout",
                "server": server,
                "rtt_ms": None,
                "response": ["No response (timeout)"]
            })
            # try next server in the list
            servers = servers[1:] if len(servers) > 1 else []
            continue

        resp = DNSRecord.parse(data)
        stage = ret_step(resp, step)

        out_summary = []
        records = resp.rr or resp.auth or []
        if records:
            for rr in records:
                out_summary.append(f"{rr.rname} :: {rr.rtype} :: {rr.rdata}")
        else:
            out_summary.append("empty response")

        logs.append({
            "step": step,
            "stage_resolution": stage,
            "server": server,
            "rtt_ms": round(rtt, 2) if rtt else None,
            "response": out_summary
        })

        # Final answer found
        if resp.rr:
            response = data
            break

        # Build ip_list from additional section first
        ip_list = [str(rr.rdata) for rr in resp.ar if rr.rtype == 1]

        if not ip_list:
            # get NS names from authority section
            ns_names = [str(rr.rdata) for rr in resp.auth if rr.rtype == 2]
            if ns_names:
                # resolve NS names in parallel
                ip_list = _resolve_ns_name_parallel(ns_names, visited)

        if not ip_list:
            # nothing else to try
            servers = servers[1:] if len(servers) > 1 else []
        else:
            servers = ip_list

    total_time = 1000 * (time.time() - start_time)
    return response, logs, round(total_time, 2), qname
