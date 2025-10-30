import re
import matplotlib.pyplot as plt
from collections import defaultdict
import pandas as pd

# List log file yang akan diproses
log_files = {
    "T1": "bench_t1.log",
    "T2": "bench_t2.log",
    "T4": "bench_t4.log"
}

# Regex untuk parsing log
pattern = re.compile(
    r"\[(\d{2}:\d{2}:\d{2})\] \[Worker \d+\] processed=(\d+) dropped=\d+ avg_lat=([\d\.]+)"
)

def parse_log(filename):
    throughput = defaultdict(int)   # total per detik (gabung semua worker)
    latency = defaultdict(list)     # list latencies per detik

    with open(filename, "r") as f:
        for line in f:
            m = pattern.search(line)
            if not m:
                continue
            ts, processed, avg_lat = m.groups()
            processed = int(processed)
            avg_lat = float(avg_lat)

            throughput[ts] += processed
            latency[ts].append(avg_lat)

    # Gabungkan rata-rata latency tiap detik
    latency_avg = {t: sum(vals) / len(vals) for t, vals in latency.items()}
    return throughput, latency_avg

# Simpan semua data ke Excel
excel_writer = pd.ExcelWriter("results.xlsx", engine="xlsxwriter")

for label, filename in log_files.items():
    throughput, latency = parse_log(filename)

    # Sort by time
    times = sorted(throughput.keys())
    thr_values = [throughput[t] for t in times]
    lat_values = [latency[t] for t in times]

    # Simpan ke DataFrame
    df = pd.DataFrame({
        "Time": times,
        "Throughput (events/s)": thr_values,
        "Latency (µs)": lat_values
    })
    df.to_excel(excel_writer, sheet_name=label, index=False)

    # Plot throughput
    plt.figure(figsize=(8,4))
    plt.plot(times, thr_values, marker="o")
    plt.xticks(rotation=45)
    plt.title(f"Throughput vs Time ({label})")
    plt.xlabel("Time (HH:MM:SS)")
    plt.ylabel("Events processed per second")
    plt.tight_layout()
    plt.savefig(f"{label}_throughput.png")

    # Plot latency
    plt.figure(figsize=(8,4))
    plt.plot(times, lat_values, marker="o", color="orange")
    plt.xticks(rotation=45)
    plt.title(f"Latency vs Time ({label})")
    plt.xlabel("Time (HH:MM:SS)")
    plt.ylabel("Average Latency (µs)")
    plt.tight_layout()
    plt.savefig(f"{label}_latency.png")

# Simpan Excel
excel_writer.close()
print("Grafik & Excel (results.xlsx) sudah dibuat.")
