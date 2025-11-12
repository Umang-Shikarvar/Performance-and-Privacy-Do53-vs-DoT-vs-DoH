

"""
firefox_nav_resource_metrics.py

- Copies your real Firefox profile to a temporary directory (avoids "profile in use")
- Launches Firefox (plain Selenium) with the copied profile
- Records Navigation Timing + Resource Timing (per-page)
- Aggregates counts and byte totals (best-effort using Resource Timing fields)
- Saves results to CSV.

Requirements:
- Python 3.11
- selenium (4.x)
- pandas
- geckodriver on PATH
"""

import os
import shutil
import tempfile
import time
import json
import traceback
from datetime import datetime
import pandas as pd

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

# ---------------- CONFIG ----------------
# Path to your real Firefox profile (replace with your path)
PROFILE_PATH = r"C:\Users\ASUS\AppData\Roaming\Mozilla\Firefox\Profiles\ozseq0t3.default-release"

# Input & output
URLS_FILE = "urls.txt"          # one URL per line
OUTPUT_CSV = "DOT_nav_resource_metrics.csv"
RUNS_PER_URL = 1

# Optional: headless mode
HEADLESS = False

# ---------------- HELPERS ----------------
def copy_profile_to_temp(src_profile_path):
    """Copy a Firefox profile directory to a temp dir and return that path."""
    if not os.path.isdir(src_profile_path):
        raise FileNotFoundError(f"Profile path not found: {src_profile_path}")
    tmpdir = tempfile.mkdtemp(prefix="ff_profile_copy_")
    # copytree with dirs_exist_ok for Python 3.8+
    shutil.copytree(src_profile_path, os.path.join(tmpdir, "profile"), dirs_exist_ok=True)
    return os.path.join(tmpdir, "profile"), tmpdir  # return profile path and the tmp root

def extract_nav_and_resources(driver):
    """
    Returns a dict with:
      - navigation metrics (dns_ms, tcp_ms, tls_ms, request_ms, response_ms, dom_content_loaded_ms, load_event_ms, total_ms)
      - resources: list of resource timing entries (with transferSize etc when present)
    """
    # Navigation entry
    nav = driver.execute_script("""
    let p = performance.getEntriesByType('navigation')[0];
    if (!p) return null;
    return {
      navigation: {
        domainLookupStart: p.domainLookupStart,
        domainLookupEnd: p.domainLookupEnd,
        connectStart: p.connectStart,
        connectEnd: p.connectEnd,
        secureConnectionStart: p.secureConnectionStart || 0,
        requestStart: p.requestStart,
        responseStart: p.responseStart,
        responseEnd: p.responseEnd,
        domContentLoadedEventEnd: p.domContentLoadedEventEnd || 0,
        loadEventEnd: p.loadEventEnd || 0,
        duration: p.duration || 0,
        startTime: p.startTime || 0
      }
    };
    """)

    # Resource entries: modern browsers expose transferSize / encodedBodySize / decodedBodySize
    resources = driver.execute_script("""
    let entries = performance.getEntriesByType('resource') || [];
    // Map important fields only to keep payload small
    return entries.map(e => ({
      name: e.name,
      initiatorType: e.initiatorType,
      transferSize: (typeof e.transferSize !== 'undefined') ? e.transferSize : -1,
      encodedBodySize: (typeof e.encodedBodySize !== 'undefined') ? e.encodedBodySize : -1,
      decodedBodySize: (typeof e.decodedBodySize !== 'undefined') ? e.decodedBodySize : -1,
      startTime: e.startTime || 0,
      duration: e.duration || 0
    }));
    """)

    return nav, resources

def aggregate_metrics(nav_obj, resources):
    """Aggregate into easy CSV fields."""
    def safe(v): return float(v) if v is not None else 0.0

    nav = nav_obj.get("navigation") if nav_obj else None
    if not nav:
        # empty/failed navigation
        nav_metrics = {
            "dns_ms": 0.0,
            "tcp_ms": 0.0,
            "tls_ms": 0.0,
            "request_ms": 0.0,
            "response_ms": 0.0,
            "dom_content_loaded_ms": 0.0,
            "load_event_ms": 0.0,
            "total_ms": 0.0,
        }
    else:
        dns_ms = safe(nav.get("domainLookupEnd", 0)) - safe(nav.get("domainLookupStart", 0))
        tcp_ms = safe(nav.get("connectEnd", 0)) - safe(nav.get("connectStart", 0))
        sec_start = safe(nav.get("secureConnectionStart", 0))
        tls_ms = (safe(nav.get("connectEnd", 0)) - sec_start) if sec_start > 0 else 0.0
        request_ms = safe(nav.get("responseStart", 0)) - safe(nav.get("requestStart", 0))
        response_ms = safe(nav.get("responseEnd", 0)) - safe(nav.get("responseStart", 0))
        dom_content_loaded_ms = safe(nav.get("domContentLoadedEventEnd", 0)) - safe(nav.get("startTime", 0))
        load_event_ms = safe(nav.get("loadEventEnd", 0)) - safe(nav.get("startTime", 0))
        total_ms = safe(nav.get("duration", 0))

        nav_metrics = {
            "dns_ms": round(dns_ms, 2),
            "tcp_ms": round(tcp_ms, 2),
            "tls_ms": round(tls_ms, 2),
            "request_ms": round(request_ms, 2),
            "response_ms": round(response_ms, 2),
            "dom_content_loaded_ms": round(dom_content_loaded_ms, 2),
            "load_event_ms": round(load_event_ms, 2),
            "total_ms": round(total_ms, 2)
        }

    # Resource-level aggregates
    num_resources = len(resources)
    num_cross_origin = 0
    total_transfer_size = 0   # transferSize when available (includes headers+body)
    total_encoded = 0         # encodedBodySize fallback
    unknown_size_count = 0

    for r in resources:
        ts = int(r.get("transferSize", -1))
        enc = int(r.get("encodedBodySize", -1))
        # If transferSize available and > 0, use it. Otherwise fallback to encodedBodySize.
        if ts > 0:
            total_transfer_size += ts
        elif enc > 0:
            total_encoded += enc
        else:
            unknown_size_count += 1

        # classify cross-origin: resource name host differs from navigation host? (best effort)
        # We'll increment num_cross_origin when transferSize/encodedBodySize are -1 (often cross-origin blocked)
        if ts <= 0 and enc <= 0:
            num_cross_origin += 1

    # Use transferSize if present else encodedBodySize
    total_bytes_in = total_transfer_size if total_transfer_size > 0 else total_encoded

    res_metrics = {
        "num_requests": num_resources,
        "total_bytes_in": int(total_bytes_in),
        "unknown_size_count": unknown_size_count,
        "num_cross_origin_size_hidden": num_cross_origin
    }

    return nav_metrics, res_metrics

# ---------------- MAIN ----------------
def main():
    # Read URLs
    if not os.path.exists(URLS_FILE):
        raise FileNotFoundError(f"URLs file not found: {URLS_FILE}")
    with open(URLS_FILE, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    # Prepare CSV results list
    results = []

    # Create a temporary copy of your real profile
    try:
        profile_copy_path, tmp_root = copy_profile_to_temp(PROFILE_PATH)
        print(f"[i] Copied profile to temp: {profile_copy_path}")
    except Exception as e:
        raise RuntimeError(f"Failed to copy profile: {e}")

    # Setup Selenium Firefox options
    options = Options()
    if HEADLESS:
        options.add_argument("-headless")

    # Use the copied profile
    options.add_argument("-profile")
    options.add_argument(profile_copy_path)

    # Disable cache for consistent runs
    options.set_preference("browser.cache.disk.enable", False)
    options.set_preference("browser.cache.memory.enable", False)
    options.set_preference("network.http.use-cache", False)

    # Launch driver (plain Selenium, no selenium-wire)
    service = Service()  # uses geckodriver in PATH
    driver = None
    try:
        driver = webdriver.Firefox(service=service, options=options)
        time.sleep(1)  # let browser settle

        for url in urls:
            for run in range(1, RUNS_PER_URL + 1):
                print(f"\n[i] Loading {url} (run {run}) ...")
                # Clear performance entries via JS between runs (so resource list is fresh)
                try:
                    driver.execute_script("performance.clearResourceTimings();")
                except Exception:
                    pass

                start_wall = time.time()
                success = False
                try:
                    driver.get(url)
                    # Wait a bit for resources / load event. Adjust if pages are heavy.
                    time.sleep(1.0)
                    nav_obj, resources = extract_nav_and_resources(driver)
                    success = True
                except Exception as e:
                    print("[!] Error loading:", e)
                    nav_obj, resources = None, []

                end_wall = time.time()
                wall_time_s = round(end_wall - start_wall, 3)

                # Aggregate metrics
                nav_metrics, res_metrics = aggregate_metrics(nav_obj, resources)

                row = {
                    "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
                    "url": url,
                    "run": run,
                    "status": "SUCCESS" if success else "FAILED",
                    "wall_time_s": wall_time_s,
                    # nav metrics
                    **nav_metrics,
                    # resource metrics
                    **res_metrics,
                    "raw_resource_count_reported": len(resources)
                }
                results.append(row)
                print(row)

    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        # Clean up temporary profile copy
        try:
            shutil.rmtree(tmp_root)
        except Exception:
            pass

    # Save results to CSV
    df = pd.DataFrame(results)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\nSaved results to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
