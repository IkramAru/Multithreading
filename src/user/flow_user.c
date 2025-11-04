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

// Global variables
int g_num_workers = 1;
atomic_uint_fast64_t g_dropped = 0;

static struct bpf_link **g_links = NULL;
static int link_count = 0;

/* mapping ifindex -> ifname + direction */
static int *g_ifindexes = NULL;
static char **g_ifnames = NULL;
static int *g_ifdirs = NULL;

static enum { MODE_DEBUG, MODE_BENCH, MODE_CSV } g_mode = MODE_DEBUG;
static FILE *csv_file = NULL;
static volatile sig_atomic_t exiting = 0;

/* --- collector globals --- */
#define COLLECTOR_MAX_EVENTS 200000
static pthread_t collector_thread;
static pthread_mutex_t collector_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  collector_cond  = PTHREAD_COND_INITIALIZER;
struct ev_copy { struct flow_event ev; };
static struct ev_copy *collector_buf = NULL;
static size_t collector_len = 0;
static size_t collector_cap = 0;
static const unsigned collector_interval_ms = 100;

/* --- signal handler --- */
static void sigint_handler(int signo) {
    (void)signo;
    exiting = 1;
    fprintf(stderr, "\n[!] SIGINT received, shutting down...\n");
}

/* --- helper: parse comma-separated ifnames with optional :in/:out --- */
static int parse_ifnames(const char *s, int out_ifindexes, int out_dirs, char ***out_names)
{
    if (!s  !out_ifindexes  !out_dirs || !out_names)
        return -1;

    int max = 1;
    for (const char *p = s; *p; ++p)
        if (*p == ',') ++max;

    int *arr_idx = calloc(max, sizeof(int));
    int *arr_dir = calloc(max, sizeof(int));
    char **arr_name = calloc(max, sizeof(char *));
    if (!arr_idx  !arr_dir  !arr_name)
        return -1;

    char *copy = strdup(s);
    if (!copy)
        return -1;

    int cur = 0;
    char *tok = strtok(copy, ",");
    while (tok && cur < max) {
        // Trim spaces
        while (*tok && (*tok == ' ' || *tok == '\t')) tok++;
        char *end = tok + strlen(tok) - 1;
        while (end > tok && (*end == ' ' || *end == '\t')) { *end = '\0'; end--; }
        if (!*tok) { tok = strtok(NULL, ","); continue; }

        // Split by ':' if direction is provided
        char *dirpart = strchr(tok, ':');
        if (dirpart) *dirpart++ = '\0';

        int idx = if_nametoindex(tok);
        if (idx == 0) {
            fprintf(stderr, "Invalid ifname: %s\n", tok);
            free(copy);
            free(arr_idx); free(arr_dir); free(arr_name);
            return -1;
        }

        arr_idx[cur] = idx;
        arr_name[cur] = strdup(tok);
        arr_dir[cur] = (dirpart && strcasecmp(dirpart, "out") == 0) ? 1 : 0; // default IN if not specified
        cur++;

        tok = strtok(NULL, ",");
    }

    free(copy);
    *out_ifindexes = arr_idx;
    *out_dirs = arr_dir;
    *out_names = arr_name;
    return cur;
}

/* --- ring buffer callback  --- */
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
    if (collector_len < collector_cap) {
        collector_buf[collector_len++].ev = tmp;
    }
    if (collector_len >= collector_cap || (collector_len % 1024) == 0)
        pthread_cond_signal(&collector_cond);
    pthread_mutex_unlock(&collector_lock);

    return 0;
}

/* --- collector utilities --- */
static int cmp_ev_ts(const void *a, const void *b) {
    const struct ev_copy *x = a;
    const struct ev_copy *y = b;
    if (x->ev.ts_ns < y->ev.ts_ns) return -1;
    if (x->ev.ts_ns > y->ev.ts_ns) return 1;
    return 0;
}

static const char *dir_str(int d) { return d ? "OUT" : "IN"; }

/* helper: lookup ifname + dir by ifindex; returns 0 on success */
static int lookup_ifmeta(int ifidx, const char **out_name, int *out_dir) {
    if (!g_ifindexes || !g_ifnames || !g_ifdirs) return -1;
    for (int i = 0; i < link_count; ++i) {
        if (g_ifindexes[i] == ifidx) {
            if (out_name) *out_name = g_ifnames[i];
            if (out_dir)  *out_dir  = g_ifdirs[i];
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

        const char *ifname = NULL;
        int dir = 0;
        if (lookup_ifmeta(e->ifindex, &ifname, &dir) != 0) {
            /* unknown interface: use numeric ifindex and default IN */
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "if%u", e->ifindex);
            ifname = strdup(tmp);
            dir = 0;
        }

        /* Writes output */
        fprintf(out, "%llu,%s,%s,%u,%u,%u,%u\n",
            (unsigned long long)e->ts_ns,
            ifname ? ifname : "unknown",
            dir ? "OUT" : "IN",
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

int main(int argc, char **argv) {
    struct flow_xdp_bpf *skel = NULL;
    struct bpf_program *prog;
    struct ring_buffer *rb = NULL;
    int *ifindexes = NULL;
    int ret;

    if (argc < 3 || strcmp(argv[1], "-i") != 0) {
        fprintf(stderr, "Usage: %s -i <if1[,if2,...]> [debug|bench|csv] [-t num_threads]\n", argv[0]);
        return 1;
    }

    /* parse mode */
    if (argc > 3 && argv[3][0] != '-') {
        if (strcmp(argv[3], "bench") == 0) g_mode = MODE_BENCH;
        else if (strcmp(argv[3], "csv") == 0) g_mode = MODE_CSV;
    }

    /* parse threads */
    g_num_workers = 1;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            g_num_workers = atoi(argv[i + 1]);
            if (g_num_workers <= 0) g_num_workers = 1;
        }
    }

    /* parse ifnames (separated by comma) */
    link_count = parse_ifnames(argv[2], &g_ifindexes, &g_ifdirs, &g_ifnames);
    if (link_count <= 0) {
        fprintf(stderr, "No valid interfaces parsed from: %s\n", argv[2]);
        return 1;
    }

    g_ifindexes = ifindexes;

    /* allocate names + directions */
    g_ifnames = calloc(link_count, sizeof(char*));
    g_ifdirs  = calloc(link_count, sizeof(int));
    if (!g_ifnames || !g_ifdirs) {
        perror("calloc ifname/ifdir");
        free(ifindexes);
        return 1;
    }

    /* populate names (if_indextoname) and directions: index 0 = IN, index 1 = OUT*/
    for (int i = 0; i < link_count; ++i) {
        char buf[IF_NAMESIZE];
        if (if_indextoname(ifindexes[i], buf) != NULL) {
            g_ifnames[i] = strdup(buf);
        } else {
            /* fallback to numeric string */
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "if%d", ifindexes[i]);
            g_ifnames[i] = strdup(tmp);
        }
        g_ifdirs[i] = (link_count == 2 && i == 1) ? 1 : 0;
    }

    fprintf(stderr, "[*] mode=%s, workers=%d, interfaces=%d\n",
        g_mode == MODE_BENCH ? "bench" :
        g_mode == MODE_CSV   ? "csv"   : "debug",
        g_num_workers, link_count);

    signal(SIGINT, sigint_handler);

    skel = flow_xdp_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        free(ifindexes);
        return 1;
    }

    /* attach XDP program to each interface and store links */
    g_links = calloc(link_count, sizeof(*g_links));
    if (!g_links) { flow_xdp_bpf__destroy(skel); free(ifindexes); return 1; }

    prog = skel->progs.xdp_flow;
    for (int i = 0; i < link_count; ++i) {
        int ifidx = ifindexes[i];
        struct bpf_link *l = bpf_program__attach_xdp(prog, ifidx);
        if (libbpf_get_error(l)) {
            fprintf(stderr, "Failed to attach XDP on index %d\n", ifidx);
            g_links[i] = NULL;
        } else {
            g_links[i] = l;
            fprintf(stderr, "Attached XDP on ifindex=%d\n", ifidx);
        }
    }

    /* ring buffer (single map) */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
    }

    if (g_mode == MODE_CSV) {
        csv_file = fopen("result.csv", "w");
        if (csv_file)
            fprintf(csv_file, "timestamp,ifindex,direction,ip_version,sport,dport,len\n");
    }

    /* start collector thread if CSV mode */
    if (g_mode == MODE_CSV && csv_file) {
        if (pthread_create(&collector_thread, NULL, collector_fn, (void*)csv_file) != 0) {
            perror("pthread_create collector");
        }
    }

    start_workers(g_num_workers, &exiting);

    while (!exiting) {
        ret = ring_buffer__poll(rb, 500);
        if (ret == -EINTR || exiting) break;
    }

    /* cleanup/free resources */
    stop_workers();
    if (rb) ring_buffer__free(rb);

    for (int i = 0; i < link_count; ++i) {
        if (g_links && g_links[i]) bpf_link__destroy(g_links[i]);
    }
    free(g_links);
    g_links = NULL;

    if (skel) flow_xdp_bpf__destroy(skel);
    if (csv_file) {
        fclose(csv_file);
        fprintf(stderr, "[*] CSV log saved to result.csv\n");
    }
    if (g_ifnames) {
        for (int i = 0; i < link_count; ++i) if (g_ifnames[i]) free(g_ifnames[i]);
        free(g_ifnames);
        g_ifnames = NULL;
    }
    if (g_ifdirs) { free(g_ifdirs); g_ifdirs = NULL; }
    g_ifindexes = NULL;
    free(ifindexes);

    fprintf(stderr, "\n[*] Program exited cleanly\n");
    return 0;
}