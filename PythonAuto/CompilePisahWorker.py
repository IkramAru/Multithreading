import re
import pandas as pd

def parse_log(filename):
    pattern = re.compile(
        r"\[(\d{2}:\d{2}:\d{2})\] \[Worker (\d+)\] processed=(\d+) dropped=(\d+) avg_lat=([\d.]+) us max_lat=(\d+) us"
    )
    rows = []
    with open(filename, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                ts, worker, processed, dropped, avg_lat, max_lat = match.groups()
                rows.append({
                    "Time": ts,
                    "Worker": int(worker),
                    "Processed": int(processed),
                    "Dropped": int(dropped),
                    "AvgLatency(us)": float(avg_lat),
                    "MaxLatency(us)": int(max_lat)
                })
    return pd.DataFrame(rows)

# Parse semua log
df_t1 = parse_log("bench_t1.log")
df_t2 = parse_log("bench_t2.log")
df_t4 = parse_log("bench_t4.log")

# Pivot agar tiap worker jadi kolom
t1_pivot = df_t1.pivot(index="Time", columns="Worker", values="Processed")
t2_pivot = df_t2.pivot(index="Time", columns="Worker", values="Processed")
t4_pivot = df_t4.pivot(index="Time", columns="Worker", values="Processed")

# Simpan ke Excel
with pd.ExcelWriter("Hasil_V2.xlsx", engine="openpyxl") as writer:
    t1_pivot.to_excel(writer, sheet_name="t1")
    t2_pivot.to_excel(writer, sheet_name="t2")
    t4_pivot.to_excel(writer, sheet_name="t4")

print("File 'Hasil_V2.xlsx' sudah dibuat dengan worker terpisah per kolom.")
