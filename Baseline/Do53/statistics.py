import os, re
import numpy as np
import pandas as pd
from urllib.parse import urlparse

# ------------ INPUT PATHS ------------
CSV_PATHS = [
    "/Users/tejasmacipad/Desktop/CN/FinalProject/CN_Project/Report/Direct_query/dns_cf_do53.csv",
    "/Users/tejasmacipad/Desktop/CN/FinalProject/CN_Project/Report/Direct_query/dns_cf_do53_top.csv",
]

OUT_DIR = "./research_out"
os.makedirs(OUT_DIR, exist_ok=True)

# ------------ HELPERS ------------
def extract_host(s: str) -> str:
    """
    Accepts domain strings that may be plain hosts or Markdown URLs like
    [https://www.ex.co](https://www.ex.co) and returns a lowercase host.
    """
    if s is None:
        return ""
    t = str(s).strip()
    # Markdown [url](url) → take inside []
    m = re.search(r"\[(.*?)\]", t)
    if m:
        t = m.group(1)
    # If scheme present, parse; else treat as host
    if "://" in t:
        p = urlparse(t)
        host = p.netloc
    else:
        host = t
    host = host.split("@")[-1].split(":")[0].strip().strip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except Exception:
        pass
    return host

def load_and_clean(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["dataset"] = os.path.basename(path)
    # Normalize domain column
    df["domain_clean"] = df["domain"].apply(extract_host)
    # Numeric coercions
    for c in ["rtt_ms", "bytes_out", "bytes_in", "rcode"]:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df[df["domain_clean"] != ""]
    return df

def pct(series: pd.Series, q):
    s = series.dropna().values
    return float(np.percentile(s, q)) if len(s) else np.nan

def summarize_dataset(df: pd.DataFrame) -> pd.DataFrame:
    total = len(df)
    by_status = df["status"].value_counts(dropna=False)
    succ = by_status.get("SUCCESS", 0)
    tout = by_status.get("TIMEOUT", 0)
    err  = by_status.get("ERROR", 0)
    succ_rate = (succ / total) * 100.0 if total else 0.0

    succ_df = df[(df["status"] == "SUCCESS") & (df["rtt_ms"].notna())]
    med = pct(succ_df["rtt_ms"], 50)
    p90 = pct(succ_df["rtt_ms"], 90)
    p95 = pct(succ_df["rtt_ms"], 95)
    p99 = pct(succ_df["rtt_ms"], 99)

    # Bytes stats on successful queries
    bout_med = pct(succ_df["bytes_out"], 50)
    bin_med  = pct(succ_df["bytes_in"], 50)

    # RCODE breakdown on successes (0=NOERROR, 3=NXDOMAIN, 2=SERVFAIL, etc.)
    rcode_counts = succ_df["rcode"].value_counts(dropna=False).to_dict()

    return pd.DataFrame([{
        "dataset": df["dataset"].iloc[0] if len(df) else "",
        "total_rows": total,
        "success": succ,
        "timeout": tout,
        "error": err,
        "success_rate_pct": round(succ_rate, 2),
        "rtt_p50_ms": round(med, 3) if pd.notna(med) else "",
        "rtt_p90_ms": round(p90, 3) if pd.notna(p90) else "",
        "rtt_p95_ms": round(p95, 3) if pd.notna(p95) else "",
        "rtt_p99_ms": round(p99, 3) if pd.notna(p99) else "",
        "bytes_out_p50": round(bout_med, 3) if pd.notna(bout_med) else "",
        "bytes_in_p50": round(bin_med, 3) if pd.notna(bin_med) else "",
        "rcode_counts": rcode_counts,
    }])

def per_domain_stats(df: pd.DataFrame) -> pd.DataFrame:
    # Only successful queries for latency ranking
    sdf = df[(df["status"] == "SUCCESS") & (df["rtt_ms"].notna())].copy()
    if sdf.empty:
        return pd.DataFrame(columns=[
            "dataset","domain","count","success_rate_pct",
            "rtt_p50_ms","rtt_p90_ms","rtt_p95_ms","rtt_p99_ms"
        ])

    # Compute per-domain counts over full dataset (success + others)
    total_counts = df.groupby("domain_clean")["status"].count().rename("count_total")
    success_counts = df[df["status"] == "SUCCESS"].groupby("domain_clean")["status"].count().rename("count_success")

    g = sdf.groupby("domain_clean")["rtt_ms"]
    out = pd.DataFrame({
        "rtt_p50_ms": g.median(),
        "rtt_p90_ms": g.quantile(0.90),
        "rtt_p95_ms": g.quantile(0.95),
        "rtt_p99_ms": g.quantile(0.99)
    }).reset_index()

    out = out.merge(total_counts, on="domain_clean", how="left").merge(success_counts, on="domain_clean", how="left")
    out["success_rate_pct"] = (out["count_success"] / out["count_total"] * 100.0).round(2)
    out["dataset"] = df["dataset"].iloc[0] if len(df) else ""
    out = out.rename(columns={"domain_clean": "domain"})
    # Order by median rtt
    out = out.sort_values(["rtt_p50_ms","domain"])
    return out

# ------------ MAIN ------------
def main():
    frames = []
    for p in CSV_PATHS:
        if os.path.exists(p):
            frames.append(load_and_clean(p))
        else:
            print(f"[!] Missing file: {p}")
    if not frames:
        print("[!] No input files found")
        return

    big = pd.concat(frames, ignore_index=True)

    # Write one-line summaries per dataset
    summaries = pd.concat([summarize_dataset(df) for _, df in big.groupby("dataset")], ignore_index=True)
    summaries.to_csv(os.path.join(OUT_DIR, "summary_by_dataset.csv"), index=False)

    # RCODE breakdown per dataset (tabular)
    rcode_rows = []
    for name, df in big.groupby("dataset"):
        s = df[(df["status"] == "SUCCESS") & (df["rcode"].notna())]["rcode"].value_counts(dropna=False)
        for code, cnt in s.items():
            rcode_rows.append({"dataset": name, "rcode": int(code), "count": int(cnt)})
    pd.DataFrame(rcode_rows).to_csv(os.path.join(OUT_DIR, "rcode_breakdown.csv"), index=False)

    # Per-domain stats per dataset
    domain_tables = []
    for name, df in big.groupby("dataset"):
        domain_tables.append(per_domain_stats(df))
    per_domain = pd.concat(domain_tables, ignore_index=True)
    per_domain.to_csv(os.path.join(OUT_DIR, "per_domain_stats.csv"), index=False)

    # Print concise summary for the paper
    print("\n=== Summary by dataset ===")
    print(summaries.to_string(index=False))

    print("\n=== Top 10 slowest domains by median (per dataset) ===")
    for name, df in per_domain.groupby("dataset"):
        print(f"\n[{name}]")
        print(df.sort_values("rtt_p50_ms", ascending=False).head(10)[
            ["domain","count_total","success_rate_pct","rtt_p50_ms","rtt_p90_ms","rtt_p95_ms","rtt_p99_ms"]
        ].to_string(index=False))

    print(f"\nWrote: {os.path.join(OUT_DIR,'summary_by_dataset.csv')}")
    print(f"Wrote: {os.path.join(OUT_DIR,'rcode_breakdown.csv')}")
    print(f"Wrote: {os.path.join(OUT_DIR,'per_domain_stats.csv')}")

if __name__ == "__main__":
    main()
