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

/* --- collector globals --- */
#define COLLECTOR_MAX_EVENTS 200000   /* ukuran buffer maksimal */
static pthread_t collector_thread;
static pthread_mutex_t collector_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  collector_cond  = PTHREAD_COND_INITIALIZER;

struct ev_copy { struct flow_event ev; };
static struct ev_copy *collector_buf = NULL;
static size_t collector_len = 0;
static size_t collector_cap = 0;

/* flush interval (ms) */
static const unsigned collector_interval_ms = 100;

/* --- forward declarations --- */
static void *collector_fn(void *arg);
static void flush_collector_to_csv(FILE *out, struct ev_copy *arr, size_t n);

/* --- Signal Handler --- */
static void sigint_handler(int signo) {
    (void)signo;
    exiting = 1;
    if (g_link) {
        bpf_link__destroy(g_link);
        g_link = NULL;
        fprintf(stderr, "\n[!] XDP program detached automatically\n");
    }
}

/* --- Callback dari ring buffer --- */
static int handle_event(void *ctx, void *data, size_t len) {
    if (len < sizeof(struct flow_event))
        return 0;

    /* salin event */
    struct flow_event tmp;
    memcpy(&tmp, data, sizeof(tmp));

    /* push ke worker */
    struct flow_event *wev = malloc(sizeof(tmp));
    if (wev) {
        memcpy(wev, &tmp, sizeof(tmp));
        push_event_to_worker(wev);
    }

    /* simpan ke collector buffer */
    pthread_mutex_lock(&collector_lock);
    if (collector_len >= collector_cap) {
        size_t newcap = (collector_cap == 0) ? 8192 : collector_cap * 2;
        if (newcap > COLLECTOR_MAX_EVENTS) newcap = COLLECTOR_MAX_EVENTS;
        if (newcap > collector_cap) {
            struct ev_copy *nb = realloc(collector_buf, newcap * sizeof(*nb));
            if (nb) {
                collector_buf = nb;
                collector_cap = newcap;
            }
        }
    }
    if (collector_len < collector_cap) {
        collector_buf[collector_len++].ev = tmp;
    }
    if (collector_len >= collector_cap || collector_len % 1024 == 0)
        pthread_cond_signal(&collector_cond);
    pthread_mutex_unlock(&collector_lock);

    return 0;
}

/* --- Sorting & Flush ke CSV --- */
static int cmp_ev_ts(const void *a, const void *b) {
    const struct ev_copy *x = a;
    const struct ev_copy *y = b;
    if (x->ev.ts_ns < y->ev.ts_ns) return -1;
    if (x->ev.ts_ns > y->ev.ts_ns) return 1;
    return 0;
}

static void flush_collector_to_csv(FILE *out, struct ev_copy *arr, size_t n) {
    if (!out || !arr || n == 0) return;

    qsort(arr, n, sizeof(arr[0]), cmp_ev_ts);

    for (size_t i = 0; i < n; ++i) {
        struct flow_event *e = &arr[i].ev;
        fprintf(out, "%llu,%d,%u,%u,%u,%u,%u\n",
            (unsigned long long)e->ts_ns,
            e->ifindex,
            (unsigned)e->direction,
            (unsigned)e->ip_version,
            (unsigned)e->sport,
            (unsigned)e->dport,
            (unsigned)e->pkt_len);
    }
    fflush(out);
}

/* --- Thread collector --- */
static void *collector_fn(void *arg) {
    FILE *out = (FILE *)arg;

    while (!exiting) {
        struct ev_copy *local_buf = NULL;
        size_t local_len = 0;

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += (collector_interval_ms % 1000) * 1000000;
        ts.tv_sec  += collector_interval_ms / 1000;

        pthread_mutex_lock(&collector_lock);
        if (!collector_len) {
            pthread_cond_timedwait(&collector_cond, &collector_lock, &ts);
        }

        if (collector_len > 0) {
            local_buf = malloc(collector_len * sizeof(*local_buf));
            if (local_buf) {
                memcpy(local_buf, collector_buf, collector_len * sizeof(*local_buf));
                local_len = collector_len;
                collector_len = 0;
            }
        }
        pthread_mutex_unlock(&collector_lock);

        if (local_len > 0) {
            flush_collector_to_csv(out ? out : stdout, local_buf, local_len);
            free(local_buf);
        }
    }

    /* flush leftover */
    pthread_mutex_lock(&collector_lock);
    if (collector_len > 0) {
        struct ev_copy *left = malloc(collector_len * sizeof(*left));
        if (left) {
            memcpy(left, collector_buf, collector_len * sizeof(*left));
            size_t left_n = collector_len;
            collector_len = 0;
            pthread_mutex_unlock(&collector_lock);
            flush_collector_to_csv(out ? out : stdout, left, left_n);
            free(left);
        } else {
            pthread_mutex_unlock(&collector_lock);
        }
    } else pthread_mutex_unlock(&collector_lock);

    return NULL;
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
            fprintf(csv_file, "timestamp,ifindex,direction,ip_version,sport,dport,pkt_len\n");
    }

    if (g_mode == MODE_CSV && csv_file) {
        if (pthread_create(&collector_thread, NULL, collector_fn, (void*)csv_file) != 0) {
            perror("pthread_create collector");
        }
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
    exiting = 1;
    pthread_cond_signal(&collector_cond);
    if (collector_thread) pthread_join(collector_thread, NULL);
    stop_workers();
    if (rb) ring_buffer__free(rb);
    if (g_link) bpf_link__destroy(g_link);
    if (skel) flow_xdp_bpf__destroy(skel);
    if (csv_file) {
        fclose(csv_file);
        fprintf(stderr, "[*] CSV log saved to result.csv\n");
    }

    fprintf(stderr, "\n[*] Program exited cleanly\n");
    return 0;
}