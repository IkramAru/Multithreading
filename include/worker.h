#ifndef WORKER_H
#define WORKER_H

#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <stdio.h> 
#include "queue.h"
#include "flow_common.h"

#define MAX_WORKERS 64

extern int g_num_workers;
extern atomic_uint_fast64_t g_dropped;
extern volatile sig_atomic_t *g_exiting;

/* kontrol worker */
void start_workers(int num_workers, volatile sig_atomic_t *exiting);
void stop_workers(void);

/* kirim event ke salah satu worker */
void push_event_to_worker(struct flow_event *ev);

void set_log_file(FILE *f);

#endif
