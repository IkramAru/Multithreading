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
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "flow_xdp.skel.h"
#include "worker.h"

/* ------------------ Global Variables ------------------ */
int g_num_workers = 1;
atomic_uint_fast64_t g_dropped = 0;

static struct bpf_link **g_links = NULL;
static int link_count = 0;

/* mapping ifindex -> ifname + direction (0=IN, 1=OUT) */
static int *g_ifindexes = NULL;
static char **g_ifnames = NULL;
static int *g_ifdirs = NULL;

static enum { MODE_DEBUG, MODE_BENCH, MODE_CSV } g_mode = MODE_DEBUG;
static FILE *csv_file = NULL;
static volatile sig_atomic_t exiting = 0;

/* ------------------ Collector Globals ------------------ */
#define COLLECTOR_MAX_EVENTS 200000
static pthread_t collector_thread;
static pthread_mutex_t collector_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  collector_cond  = PTHREAD_COND_INITIALIZER;

struct ev_copy { struct flow_event ev; };
static struct ev_copy *collector_buf = NULL;
static size_t collector_len = 0;
static size_t collector_cap = 0;
static const unsigned collector_interval_ms = 100;

/* ------------------ Signal Handler ------------------ */
static void sigint_handler(int signo) {
    (void)signo;
    exiting = 1;
    fprintf(stderr, "\n[!] SIGINT received, shutting down...\n");
}

/* ------------------ Parse ifnames like ens3f0np0:in,ens3f1np1:out ------------------ */
static int parse_ifnames(const char *s)
{
    if (!s) return -1;
    int max = 1;
    for (const char *p = s; *p; ++p)
        if (*p == ',') ++max;

    g_ifindexes = calloc(max, sizeof(int));
    g_ifnames   = calloc(max, sizeof(char *));
    g_ifdirs    = calloc(max, sizeof(int));
    if (!g_ifindexes || !g_ifnames || !g_ifdirs)
        return -1;

    char *copy = strdup(s);
    if (!copy) return -1;

    int cur = 0;
    char *tok = strtok(copy, ",");
    while (tok && cur < max) {
        /* Trim whitespace */
        while (*tok && (*tok == ' ' || *tok == '\t')) tok++;
        char *end = tok + strlen(tok) - 1;
        while (end > tok && (*end == ' ' || *end == '\t')) *end-- = '\0';
        if (!*tok) { tok = strtok(NULL, ","); continue; }

        /* Split direction */
        char *dirpart = strchr(tok, ':');
        if (dirpart) *dirpart++ = '\0';

        int idx = if_nametoindex(tok);
        if (idx == 0) {
            fprintf(stderr, "Invalid ifname: %s\n", tok);
            tok = strtok(NULL, ",");
            continue;
        }

        g_ifindexes[cur] = idx;
        g_ifnames[cur] = strdup(tok);
        g_ifdirs[cur] = (dirpart && strcasecmp(dirpart, "out") == 0) ? 1 : 0;
        fprintf(stderr, "[+] Parsed interface %s (ifindex=%d) direction=%s\n",
                tok, idx, g_ifdirs[cur] ? "OUT" : "IN");
        cur++;
        tok = strtok(NULL, ",");
    }

    free(copy);
    return cur;
}

/* ------------------ Ring Buffer Callback ------------------ */
static int handle_event(void *ctx, void *data, size_t len) {
    (void)ctx;
    if (len < sizeof(struct flow_event))
        return 0;

    struct flow_event tmp;
    memcpy(&tmp, data, sizeof(tmp));

    struct flow_event *wev = malloc(sizeof(tmp));
    if (wev) {
        memcpy(wev, &tmp, sizeof(tmp));
        push_event_to_worker(wev);
    }

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
    if (collector_len < collector_cap)
        collector_buf[collector_len++].ev = tmp;
    if (collector_len >= collector_cap || (collector_len % 1024) == 0)
        pthread_cond_signal(&collector_cond);
    pthread_mutex_unlock(&collector_lock);

    return 0;
}

/* ------------------ CSV Collector ------------------ */
static int cmp_ev_ts(const void *a, const void *b) {
    const struct ev_copy *x = a;
    const struct ev_copy *y = b;
    if (x->ev.ts_ns < y->ev.ts_ns) return -1;
    if (x->ev.ts_ns > y->ev.ts_ns) return 1;
    return 0;
}

static int lookup_ifmeta(int ifidx, const char **out_name, const char **out_dirstr) {
    if (!g_ifindexes || !g_ifnames || !g_ifdirs)
        return -1;
    for (int i = 0; i < link_count; ++i) {
        if (g_ifindexes[i] == ifidx) {
            if (out_name) *out_name = g_ifnames[i];
            if (out_dirstr) *out_dirstr = g_ifdirs[i] ? "OUT" : "IN";
            return 0;
        }
    }
    return -1;
}

static void flush_collector_to_csv(FILE *out, struct ev_copy *arr, size_t n) {
    if (!out || !arr || n == 0) return;
    qsort(arr, n, sizeof(arr[0]), cmp_ev_ts);
    for (size_t i = 0; i < n; ++i) {
        struct flow_event *e = &arr[i].ev;
        const char *ifname = "unknown";
        const char *dirstr = "IN";
        lookup_ifmeta(e->ifindex, &ifname, &dirstr);
        fprintf(out, "%llu,%s,%s,%u,%u,%u,%u\n",
            (unsigned long long)e->ts_ns,
            ifname, dirstr,
            (unsigned)e->ip_version,
            (unsigned)e->sport,
            (unsigned)e->dport,
            (unsigned)e->pkt_len);
    }
    fflush(out);
}

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
        if (!collector_len)
            pthread_cond_timedwait(&collector_cond, &collector_lock, &ts);

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
        } else pthread_mutex_unlock(&collector_lock);
    } else pthread_mutex_unlock(&collector_lock);
    return NULL;
}

/* ------------------ main() ------------------ */
int main(int argc, char **argv) {
    struct flow_xdp_bpf *skel = NULL;
    struct bpf_program *prog;
    struct ring_buffer *rb = NULL;
    int ret;

    if (argc < 3 || strcmp(argv[1], "-i") != 0) {
        fprintf(stderr, "Usage: %s -i <if1[:in|out][,if2[:in|out]]> [debug|bench|csv] [-t num_threads]\n", argv[0]);
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

    link_count = parse_ifnames(argv[2]);
    if (link_count <= 0) {
        fprintf(stderr, "Failed to parse interfaces from: %s\n", argv[2]);
        return 1;
    }

    fprintf(stderr, "[*] mode=%s, workers=%d, interfaces=%d\n",
        g_mode == MODE_BENCH ? "bench" :
        g_mode == MODE_CSV   ? "csv"   : "debug",
        g_num_workers, link_count);

    signal(SIGINT, sigint_handler);

    /* Check for custom BTF path */
    const char *btf_file = getenv("BTF_FILE");
    struct bpf_object_open_opts open_opts = { sizeof(struct bpf_object_open_opts) };
    if (btf_file) {
        fprintf(stderr, "[*] Using custom BTF file: %s\n", btf_file);
        open_opts.btf_custom_path = btf_file;
    }

    skel = flow_xdp_bpf__open_opts(&open_opts);
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    if (flow_xdp_bpf__load(skel)) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        flow_xdp_bpf__destroy(skel);
        return 1;
    }

    if (skel && skel->maps.ifdir_map) {
        int fd = bpf_map__fd(skel->maps.ifdir_map);
        if (fd >= 0) {
            for (int i = 0; i < link_count; ++i) {
                __u32 idx = (uint32_t) g_ifindexes[i];
                __u32 dir = g_ifdirs ? (uint32_t) g_ifdirs[i] : 0;
                if (bpf_map_update_elem(fd, &idx, &dir, BPF_ANY) != 0) {
                    fprintf(stderr, "warn: failed set ifdir %u -> %u: %s\n", idx, dir, strerror(errno));
                } else {
                    fprintf(stderr, "[+] set ifindex %u -> dir=%u\n", idx, dir);
                }
            }
        }
    }

    g_links = calloc(link_count, sizeof(*g_links));
    if (!g_links) { flow_xdp_bpf__destroy(skel); return 1; }

    prog = skel->progs.xdp_flow;
    for (int i = 0; i < link_count; ++i) {
        int ifidx = g_ifindexes[i];
        struct bpf_link *l = bpf_program__attach_xdp(prog, ifidx);
        if (libbpf_get_error(l)) {
            fprintf(stderr, "Failed to attach XDP on index %d\n", ifidx);
            g_links[i] = NULL;
        } else {
            g_links[i] = l;
            fprintf(stderr, "Attached XDP on %s (ifindex=%d, dir=%s)\n",
                    g_ifnames[i], ifidx, g_ifdirs[i] ? "OUT" : "IN");
        }
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) fprintf(stderr, "Failed to create ring buffer\n");

    if (g_mode == MODE_CSV) {
        csv_file = fopen("result.csv", "w");
        if (csv_file)
            fprintf(csv_file, "timestamp,ifname,direction,ip_version,sport,dport,len\n");
    }

    if (g_mode == MODE_CSV && csv_file)
        pthread_create(&collector_thread, NULL, collector_fn, (void*)csv_file);

    start_workers(g_num_workers, &exiting);

    while (!exiting) {
        ret = ring_buffer__poll(rb, 500);
        if (ret == -EINTR || exiting) break;
    }

    stop_workers();
    if (rb) ring_buffer__free(rb);

    for (int i = 0; i < link_count; ++i)
        if (g_links && g_links[i]) bpf_link__destroy(g_links[i]);

    if (skel) flow_xdp_bpf__destroy(skel);
    if (csv_file) {
        fclose(csv_file);
        fprintf(stderr, "[*] CSV log saved to result.csv\n");
    }

    fprintf(stderr, "\n[*] Program exited cleanly\n");
    return 0;
}