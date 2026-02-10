#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>

#include "flow_common.h"
#include "queue.h"
#include "worker.h"

#ifndef MAX_WORKERS
#define MAX_WORKERS 64
#endif

/* internal globals */
static struct event_queue g_queues[MAX_WORKERS];
static pthread_t g_threads[MAX_WORKERS];
static int g_actual_workers = 0;
volatile sig_atomic_t *g_exiting = NULL;
static atomic_uint_fast64_t g_total_latency_sum = 0;
static atomic_uint_fast64_t g_total_latency_max = 0;
static atomic_uint_fast64_t g_total_events = 0;
extern atomic_uint_fast64_t g_dropped;
extern int g_num_workers;
static atomic_uint_fast64_t g_total_processed = 0;
static FILE *csv_log = NULL;

/* implementasi flow table */
#define HASH_SIZE 65536

typedef struct {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t  proto;
    uint8_t  ip_ver;
    uint8_t  _pad[2];
    uint8_t  saddr_v6[16];
    uint8_t  daddr_v6[16];
} flow_key_t;

typedef struct flow_node {
    flow_key_t key;
    uint64_t last_seen_ns;
    struct flow_node *next;
} flow_node_t;

static uint32_t hash_flow_key(const flow_key_t *k) {
    uint32_t h = 0x811c9dc5;
    const uint8_t *p = (const uint8_t *)k;
    for (size_t i = 0; i < sizeof(*k); i++) {
        h ^= p[i];
        h *= 0x01000193;
    }
    return h;
}

static int compare_flow_key(const flow_key_t *a, const flow_key_t *b) {
    return memcmp(a, b, sizeof(flow_key_t));
}

/* worker */
static void *worker_thread_fn(void *arg)
{
    int worker_id = *(int *)arg;
    free(arg);
    struct event_queue *q = &g_queues[worker_id];

    /* local flow table */
    flow_node_t **buckets = calloc(HASH_SIZE, sizeof(flow_node_t *));
    if (!buckets) {
        perror("calloc buckets");
        return NULL;
    }

    uint64_t latency_sum = 0;
    uint64_t latency_max = 0;
    uint64_t event_count = 0;
    uint64_t last_print_us = 0;

    /* Init last_print_us */
    struct timespec ts_start;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    last_print_us = (uint64_t)ts_start.tv_sec * 1000000ULL + ts_start.tv_nsec / 1000ULL;

    while (1) {
        if (g_exiting && *g_exiting) break;

        struct flow_event *e = queue_pop(q, g_exiting);

        if (!e) {
            if (g_exiting && *g_exiting) break;
            continue;
        }

        /* Hitung latency */
        struct timespec ts_now;
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        uint64_t now_ns = (uint64_t)ts_now.tv_sec * 1000000000ULL + ts_now.tv_nsec;
        uint64_t latency_us = (now_ns > e->ts_ns) ? (now_ns - e->ts_ns) / 1000ULL : 0ULL;
        
        atomic_fetch_add(&g_total_latency_sum, latency_us);
        atomic_fetch_add(&g_total_events, 1);

        uint64_t old_max = atomic_load(&g_total_latency_max);
        if (latency_us > old_max)
            atomic_store(&g_total_latency_max, latency_us);

        /* Aggregasi flow */
        flow_key_t key;
        memset(&key, 0, sizeof(key));
        key.ip_ver = e->ip_version;
        key.proto = e->l4_proto;
        key.sport = e->sport;
        key.dport = e->dport;
        
        if (e->ip_version == 4) {
            key.saddr = e->saddr_v4;
            key.daddr = e->daddr_v4;
        } else if (e->ip_version == 6) {
            memcpy(key.saddr_v6, e->saddr_v6, 16);
            memcpy(key.daddr_v6, e->daddr_v6, 16);
        }

        uint32_t h = hash_flow_key(&key) % HASH_SIZE;
        flow_node_t *node = buckets[h];
        flow_node_t *found = NULL;
        while (node) {
            if (compare_flow_key(&node->key, &key) == 0) {
                found = node;
                break;
            }
            node = node->next;
        }

        if (found) {
            found->last_seen_ns = now_ns;
        } else {
            flow_node_t *new_node = malloc(sizeof(flow_node_t));
            if (new_node) {
                new_node->key = key;
                new_node->last_seen_ns = now_ns;
                new_node->next = buckets[h];
                buckets[h] = new_node;
            }
        }

        free(e);

        event_count++;
        atomic_fetch_add(&g_total_processed, 1);
        latency_sum += latency_us;
        if (latency_us > latency_max) latency_max = latency_us;

        uint64_t now_us = now_ns / 1000ULL;

        /* print setiap 50ms */
        if (now_us - last_print_us >= 50000ULL) {
            /* Hitung flow aktif */
            uint64_t active_flows = 0;
            uint64_t cutoff_ns = last_print_us * 1000ULL; // Convert back to ns
            
            /* Prune flow idle*/
            uint64_t prune_cutoff_ns = (now_us > 5000000ULL) ? (now_us - 5000000ULL) * 1000ULL : 0;

            for (int i = 0; i < HASH_SIZE; i++) {
                flow_node_t *curr = buckets[i];
                flow_node_t *prev = NULL;
                while (curr) {
                    if (curr->last_seen_ns >= cutoff_ns) {
                        active_flows++;
                    }
                    
                    if (curr->last_seen_ns < prune_cutoff_ns) {
                        flow_node_t *to_free = curr;
                        if (prev) prev->next = curr->next;
                        else buckets[i] = curr->next;
                        curr = curr->next;
                        free(to_free);
                    } else {
                        prev = curr;
                        curr = curr->next;
                    }
                }
            }

            double avg_lat = (event_count > 0) ? ((double)latency_sum / (double)event_count) : 0.0;
            uint64_t dropped = atomic_load(&g_dropped);

            struct tm tm_info;
            time_t sec = ts_now.tv_sec;
            localtime_r(&sec, &tm_info);

            /* Throughput per flow aktif */
            double throughput = (double)active_flows; 
            
            int cpu_id = sched_getcpu();

            fprintf(stderr,
                "[%02d:%02d:%02d.%03lu] [Worker %d (Core %d)] packets=%lu active_flows=%lu dropped=%lu avg_lat=%.2f us max_lat=%lu us\n",
                tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec,
                (unsigned long)(ts_now.tv_nsec / 1000000ULL),
                worker_id, cpu_id, event_count, active_flows, dropped, avg_lat, latency_max);

            if (csv_log) {
                fprintf(csv_log, "%lu,%d,%.2f,%.2f,%lu,%lu\n",
                    now_us, worker_id, throughput, avg_lat, latency_max, dropped);
                fflush(csv_log);
            }

            if (worker_id == 0) {
                uint64_t total_lat = atomic_load(&g_total_latency_sum);
                uint64_t total_evt = atomic_load(&g_total_events);
                uint64_t total_max = atomic_load(&g_total_latency_max);
                double global_avg = (total_evt > 0) ? ((double)total_lat / total_evt) : 0.0;

                fprintf(stderr, "   >> [GLOBAL] avg_lat=%.2f us  max_lat=%lu us (from %lu total events)\n",
                        global_avg, total_max, total_evt);
            }

            /* reset counters untuk interval selanjutnya */
            event_count = 0;
            latency_sum = 0;
            latency_max = 0;
            last_print_us = now_us;
        }
    }
    
    /* Cleanup */
    for (int i = 0; i < HASH_SIZE; i++) {
        flow_node_t *curr = buckets[i];
        while (curr) {
            flow_node_t *to_free = curr;
            curr = curr->next;
            free(to_free);
        }
    }
    free(buckets);

    fprintf(stderr, "[Worker %d] Finished/Exited on Core %d\n", worker_id, sched_getcpu());
    return NULL;
}

/* summon pthreads and init queues */
void start_workers(int num_workers, volatile sig_atomic_t *exiting)
{
    if (num_workers <= 0) return;
    if (num_workers > MAX_WORKERS) num_workers = MAX_WORKERS;

    g_exiting = exiting;
    g_actual_workers = num_workers;

    for (int i = 0; i < g_actual_workers; i++) {
        queue_init(&g_queues[i]);
    }

    for (int i = 0; i < g_actual_workers; i++) {
        int *wid = malloc(sizeof(int));
        if (!wid) { perror("malloc"); exit(1); }
        *wid = i;
        if (pthread_create(&g_threads[i], NULL, worker_thread_fn, wid) != 0) {
            perror("pthread_create");
            free(wid);
            g_actual_workers = i;
            break;
        }
    }

    /* save ke CSV */
    csv_log = fopen("worker_stats.csv", "w");
    if (csv_log) {
        fprintf(csv_log, "# Worker benchmark results (Flow-based)\n");
        fprintf(csv_log, "timestamp_us,worker_id,throughput_flow_per_s,avg_latency_us,max_latency_us,dropped\n");
        fflush(csv_log);
    } else {
        perror("fopen csv_log");
    }

    /* main summon stop_workers() */
    fprintf(stderr, "Started %d worker threads (pthreads)\n", g_actual_workers);
}

/* set exiting & join */
void stop_workers(void)
{
    if (g_exiting) *g_exiting = 1;

    for (int i = 0; i < g_actual_workers; i++) {
        pthread_mutex_lock(&g_queues[i].lock);
        pthread_cond_broadcast(&g_queues[i].not_empty);
        pthread_mutex_unlock(&g_queues[i].lock);
    }

    /* Menunggu workers exit loop */
    usleep(200000);
    fflush(stderr);

    fprintf(stderr, "\n[SUMMARY] Joining %d workers...\n", g_actual_workers);

    for (int i = 0; i < g_actual_workers; i++) {
        pthread_join(g_threads[i], NULL);
        fprintf(stderr, "[SUMMARY] Worker %d joined successfully\n", i);
    }

    if (csv_log) {
        fclose(csv_log);
        csv_log = NULL;
    }

    fprintf(stderr, "[SUMMARY] All worker threads joined cleanly\n");
}

/* Algoritma Round-Robin */
void push_event_to_worker(struct flow_event *ev)
{
    static atomic_uint rr_index = 0;
    unsigned int idx = atomic_fetch_add(&rr_index, 1u) % (unsigned int)g_actual_workers;
    queue_push(&g_queues[idx], ev);
}
