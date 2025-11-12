import json
import pandas as pd
import os

# ---------------- CONFIGURATION ----------------
base_path = "/Users/tejasmacipad/Desktop/final_CN_project/CN_Project/Report_2_new"

# ---------------- FILE PATHS ----------------
paths = {
    "Do53": [f"{base_path}/do53_log_top50.json", f"{base_path}/do53_log_top30003050.json"],
    "DoH": [f"{base_path}/doh_log_top50.json", f"{base_path}/doh_log_top30003050.json"],
    "DoT": [f"{base_path}/dot_log_top50.json", f"{base_path}/dot_log_top30003050.json"],
}

# ---------------- LOAD FILES ----------------
def load_json_file(path, protocol, quality):
    with open(path, "r") as f:
        data = json.load(f)
    df = pd.DataFrame(data)
    df["protocol"] = protocol
    df["quality"] = quality
    # Only first 50 queries
    df = df.head(50)
    return df

dfs = []
for proto, files in paths.items():
    dfs.append(load_json_file(files[0], proto, "Top50"))
    dfs.append(load_json_file(files[1], proto, "Bottom50"))

df = pd.concat(dfs, ignore_index=True)

# ---------------- ENSURE NUMERIC FIELDS ----------------
numeric_cols = [
    "tcp_handshake_ms",
    "tls_handshake_ms",
    "query_time_ms",
    "total_time_ms",
    "bytes_sent",
    "bytes_recv",
    "query_size_bytes",
    "response_size_bytes",
]

for col in numeric_cols:
    if col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")

# Compute total bytes if not already present
if "total_bytes" not in df.columns:
    df["total_bytes"] = df["bytes_sent"] + df["bytes_recv"]

# ---------------- COMPUTE BASIC METRICS ----------------
summary = (
    df.groupby(["protocol", "quality"])
    .agg({
        "tcp_handshake_ms": "mean",
        "tls_handshake_ms": "mean",
        "query_time_ms": "mean",
        "total_time_ms": "mean",
        "bytes_sent": "mean",
        "bytes_recv": "mean",
        "total_bytes": "mean",
        "query_size_bytes": "mean",
        "response_size_bytes": "mean"
    })
    .reset_index()
)

# Round for neatness
summary = summary.round(2)

# ---------------- DISPLAY ----------------
print("\n===== Average Metrics per Protocol and Quality =====\n")
print(summary.to_string(index=False))