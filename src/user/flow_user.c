#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "flow_xdp.skel.h"
#include "worker.h"

// Global variables
int g_num_workers = 1;
atomic_uint_fast64_t g_dropped = 0;

static struct bpf_link *g_link = NULL;
static enum { MODE_DEBUG, MODE_BENCH, MODE_CSV } g_mode = MODE_DEBUG;
static FILE *csv_file = NULL;
static volatile sig_atomic_t exiting = 0;

static void sigint_handler(int signo) {
    (void)signo;
    exiting = 1;
    if (g_link) {
        bpf_link__destroy(g_link);
        g_link = NULL;
        fprintf(stderr, "\n[!] XDP program detached automatically\n");
    }
}

static int handle_event(void *ctx, void *data, size_t len) {
    if (len < sizeof(struct flow_event))
        return 0;

    struct flow_event *e = malloc(sizeof(*e));
    if (!e) return 0;

    memcpy(e, data, sizeof(*e));
    push_event_to_worker(e);
    return 0;
}

int main(int argc, char **argv) {
    struct flow_xdp_bpf *skel = NULL;
    struct bpf_program *prog;
    struct ring_buffer *rb = NULL;
    int ifindex, err;

    if (argc < 3 || strcmp(argv[1], "-i") != 0) {
        fprintf(stderr, "Usage: %s -i <ifname> [debug|bench|csv] [-t num_threads]\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[2]);
    if (!ifindex) {
        fprintf(stderr, "Invalid ifname: %s\n", argv[2]);
        return 1;
    }

    if (argc > 3 && argv[3][0] != '-') {
        if (strcmp(argv[3], "bench") == 0) g_mode = MODE_BENCH;
        else if (strcmp(argv[3], "csv") == 0) g_mode = MODE_CSV;
    }

    g_num_workers = 1;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            g_num_workers = atoi(argv[i + 1]);
            if (g_num_workers <= 0) g_num_workers = 1;
        }
    }

    fprintf(stderr, "[*] mode=%s, workers=%d\n",
        g_mode == MODE_BENCH ? "bench" :
        g_mode == MODE_CSV   ? "csv"   : "debug",
        g_num_workers);

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    signal(SIGINT, sigint_handler);

    skel = flow_xdp_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    prog = skel->progs.xdp_flow;
    g_link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(g_link)) {
        fprintf(stderr, "Failed to attach XDP: %ld\n", libbpf_get_error(g_link));
        g_link = NULL;
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    if (g_mode == MODE_CSV) {
        csv_file = fopen("result.csv", "w");
        if (csv_file)
            fprintf(csv_file, "timestamp,worker,avg_lat_us,max_lat_us,throughput_flows,drop_count\n");
    }

    start_workers(g_num_workers, &exiting);

    while (!exiting) {
        err = ring_buffer__poll(rb, 500);
        if (err == -EINTR || exiting) break;
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                    (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    uint64_t dropped = atomic_load(&g_dropped);

    fprintf(stderr, "\n[SUMMARY] Total runtime: %.3f seconds\n", elapsed);
    fprintf(stderr, "[SUMMARY] Total dropped packets: %lu\n", dropped);
    fprintf(stderr, "[SUMMARY] Threads used: %d\n", g_num_workers);


    cleanup:
        stop_workers();
        if (rb) ring_buffer__free(rb);
        if (g_link) bpf_link__destroy(g_link);
        if (skel) flow_xdp_bpf__destroy(skel);
        if (csv_file) {
            fclose(csv_file);
            fprintf(stderr, "[*] CSV log saved to result.csv\n");
        }
        if (csv_file) fclose(csv_file);

    fprintf(stderr, "\n[*] Program exited cleanly\n");
    return 0;
}
