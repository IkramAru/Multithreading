# eBPF Multithreaded Flow Monitor

This project implements a high-performance network flow monitoring tool using eBPF (XDP) and a multithreaded user-space collector. It is designed to capture packet events efficiently from the kernel, aggregate flow statistics (latency, packet counts), and process them in parallel using worker threads.

## Features

-   **eBPF/XDP Data Plane**: Fast packet parsing and event generation directly in the kernel driver hook.
-   **Multithreaded Processing**: Configurable number of worker threads to handle high event rates.
-   **Flow Aggregation**: Aggregates packets into flows (5-tuple) and tracks active flows.
-   **Latency Measurement**: Calculates packet processing latency from kernel timestamp to user-space processing.
-   **Multi-Interface Support**: Monitors multiple network interfaces simultaneously with direction tagging (IN/OUT).
-   **CSV Logging**: Optional logging of flow data and worker statistics to CSV files.

## Project Structure

-   `src/bpf/`: Contains the eBPF/XDP source code (`flow_xdp.bpf.c`).
-   `src/user/`: Contains the user-space application code (`flow_user.c`, `worker.c`).
-   `include/`: Shared header files (`flow_common.h`, etc.).
-   `Makefile`: Build script.

## Prerequisites

-   Clang/LLVM
-   libbpf (and development headers)
-   Make
-   Linux kernel with XDP support

## Building

To build the application, simply run:

```bash
make
```

This will produce the `flow_user` binary.

## Usage

The program requires `root` privileges (or `CAP_BPF` capability).

```bash
sudo ./flow_user -i <interface_list> [mode] [-t <num_threads>]
```

### Arguments

-   `-i <interface_list>`: Comma-separated list of interfaces to monitor. You can optionally specify the direction (`:in` or `:out`) for each interface.
    -   Example: `eth0:in,eth1:out`
-   `[mode]`: Operation mode (optional, default is `debug`).
    -   `debug`: Prints aggregated stats to stderr.
    -   `bench`: Benchmark mode (similar to debug but intended for performance testing).
    -   `csv`: Logs detailed flow events to `result.csv` and worker stats to `worker_stats.csv`.
-   `-t <num_threads>`: Number of worker threads to spawn (default: 1).

### Examples

**Basic monitoring on `eth0` with 4 worker threads:**

```bash
sudo ./flow_user -i eth0 -t 4
```

**Monitoring ingress on `eth0` and egress on `eth1` in CSV mode:**

```bash
sudo ./flow_user -i eth0:in,eth1:out csv -t 8
```

## Output

The program outputs periodic statistics to standard error, including:
-   Active flow count
-   Packet count per interval
-   Average and maximum latency
-   Dropped packet count (from ring buffer)

In `csv` mode, it generates:
-   `result.csv`: Individual flow events (timestamp, interface, direction, IPs, ports, length).
-   `worker_stats.csv`: Periodic performance metrics per worker thread.
