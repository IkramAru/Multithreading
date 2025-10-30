#include "worker.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>

#ifndef MAX_WORKERS
#define MAX_WORKERS 8
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

/* worker routine */
static void *worker_thread_fn(void *arg)
{
    int worker_id = *(int *)arg;
    free(arg);
    struct event_queue *q = &g_queues[worker_id];

    uint64_t count = 0;
    uint64_t latency_sum = 0;
    uint64_t latency_max = 0;
    uint64_t last_print_us = 0;

    while (1) {
        if (g_exiting && *g_exiting) break;

        /* measure queue_pop wait time */
        struct timespec ts_wait_start, ts_wait_end;
        clock_gettime(CLOCK_MONOTONIC, &ts_wait_start);

        struct flow_event *e = queue_pop(q, g_exiting);

        clock_gettime(CLOCK_MONOTONIC, &ts_wait_end);
        uint64_t wait_ns = (uint64_t)(ts_wait_end.tv_sec - ts_wait_start.tv_sec) * 1000000000ULL +
                        (ts_wait_end.tv_nsec - ts_wait_start.tv_nsec);

        if (wait_ns > 1000000ULL && (!g_exiting || !*g_exiting)) {
            fprintf(stderr, "[Worker %d] Queue wait: %.3f ms\n", worker_id, wait_ns / 1e6);
        }

        if (!e) {
            if (g_exiting && *g_exiting) break;
            /* spurious wake or exiting, continue */
            continue;
        }

        /* compute latency using CLOCK_MONOTONIC */
        struct timespec ts_now;
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        uint64_t now_ns = (uint64_t)ts_now.tv_sec * 1000000000ULL + ts_now.tv_nsec;
        uint64_t latency_us = (now_ns > e->ts_ns) ? (now_ns - e->ts_ns) / 1000ULL : 0ULL;
        atomic_fetch_add(&g_total_latency_sum, latency_us);
        atomic_fetch_add(&g_total_events, 1);

        uint64_t old_max = atomic_load(&g_total_latency_max);
        if (latency_us > old_max)
            atomic_store(&g_total_latency_max, latency_us);

        free(e);

        count++;
        atomic_fetch_add(&g_total_processed, 1);
        latency_sum += latency_us;
        if (latency_us > latency_max) latency_max = latency_us;

        uint64_t now_us = now_ns / 1000ULL;

        /* print every 50ms (50000 us) — ubah jika mau */
        if (now_us - last_print_us >= 50000ULL) {
            double avg_lat = (count > 0) ? ((double)latency_sum / (double)count) : 0.0;
            uint64_t dropped = atomic_load(&g_dropped);

            struct tm tm_info;
            time_t sec = ts_now.tv_sec;
            localtime_r(&sec, &tm_info);

            double throughput = (count * 1e6) / (now_us - last_print_us); // flows per detik

            fprintf(stderr,
                "[%02d:%02d:%02d.%03lu] [Worker %d] processed=%lu dropped=%lu avg_lat=%.2f us max_lat=%lu us thpt=%.2f flow/s\n",
                tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec,
                (unsigned long)(ts_now.tv_nsec / 1000000ULL),
                worker_id, count, dropped, avg_lat, latency_max, throughput);

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

            /* reset counters for next interval */
            count = 0;
            latency_sum = 0;
            latency_max = 0;
            last_print_us = now_us;
        }
    }

    return NULL;
}

/* start_workers: spawn pthreads and init queues */
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
            /* mark fewer workers */
            g_actual_workers = i;
            break;
        }
    }

    // buka file CSV untuk simpan hasil
    csv_log = fopen("worker_stats.csv", "w");
    if (csv_log) {
        fprintf(csv_log, "# Worker benchmark results\n");
        fprintf(csv_log, "timestamp_us,worker_id,throughput_flow_per_s,avg_latency_us,max_latency_us,dropped\n");
        fflush(csv_log);
    } else {
        perror("fopen csv_log");
    }

    /* don't join here — main will call stop_workers() */
    fprintf(stderr, "Started %d worker threads (pthreads)\n", g_actual_workers);
}

/* stop_workers: set exiting and join */
void stop_workers(void)
{
    if (g_exiting) *g_exiting = 1;

    // Wake semua worker agar tidak stuck di queue_pop
    for (int i = 0; i < g_actual_workers; i++) {
        pthread_mutex_lock(&g_queues[i].lock);
        pthread_cond_broadcast(&g_queues[i].not_empty);
        pthread_mutex_unlock(&g_queues[i].lock);
    }

    // Tunggu sebentar biar worker sempat keluar loop-nya
    usleep(200000); // 0.2 detik
    fflush(stderr); // pastikan semua log worker sudah keluar

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

/* push_event_to_worker: round-robin */
void push_event_to_worker(struct flow_event *ev)
{
    static atomic_uint rr_index = 0;
    unsigned int idx = atomic_fetch_add(&rr_index, 1u) % (unsigned int)g_actual_workers;
    queue_push(&g_queues[idx], ev);
}
