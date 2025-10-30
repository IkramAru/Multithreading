import re
import pandas as pd
import os

print(os.listdir("."))

# Baca file log mentah
with open("./PythonAuto/newbench1.log", "r") as f:
    lines = f.readlines()

pattern = re.compile(
    r"\[(\d+:\d+:\d+)\]\s+\[Worker (\d+)\]\s+processed=(\d+)\s+dropped=(\d+)\s+avg_lat=([\d\.]+)\s+us\s+max_lat=(\d+)\s+us"
)

data = []
for line in lines:
    match = pattern.search(line)
    if match:
        ts, worker, processed, dropped, avg_lat, max_lat = match.groups()
        data.append({
            "Timestamp": ts,
            "Worker": int(worker),
            "Processed": int(processed),
            "Dropped": int(dropped),
            "AvgLat_us": float(avg_lat),
            "MaxLat_us": int(max_lat)
        })

# Jadi DataFrame
df = pd.DataFrame(data)

# Simpan ke Excel (tiap worker jadi sheet sendiri)
with pd.ExcelWriter("./PythonAuto/bench1.xlsx") as writer:
    for worker_id, group in df.groupby("Worker"):
        group.to_excel(writer, sheet_name=f"Worker{worker_id}", index=False)

print("Log telah dirapikan")
