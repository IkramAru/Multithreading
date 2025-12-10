#ifndef FLOW_QUEUE_H
#define FLOW_QUEUE_H

#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include "flow_common.h"

#define QUEUE_SIZE 1024

#include <stdatomic.h>

extern atomic_uint_fast64_t g_dropped;

struct event_queue {
    struct flow_event *events[QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
};

static inline void queue_init(struct event_queue *q) {
    q->head = q->tail = q->count = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

static inline void queue_push(struct event_queue *q, struct flow_event *ev) {
    pthread_mutex_lock(&q->lock);
    if (q->count == QUEUE_SIZE) {
        // Queue penuh, anggap drop
        atomic_fetch_add(&g_dropped, 1);
        pthread_mutex_unlock(&q->lock);
        free(ev);
        return;
    }

    q->events[q->tail] = ev;
    q->tail = (q->tail + 1) % QUEUE_SIZE;
    q->count++;

    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

static inline struct flow_event *queue_pop(struct event_queue *q, volatile sig_atomic_t *exiting) {
    pthread_mutex_lock(&q->lock);
    while (q->count == 0 && !*exiting){
        pthread_cond_wait(&q->not_empty, &q->lock);
    }
    if (*exiting && q->count == 0) {
        pthread_mutex_unlock(&q->lock);
        return NULL;
    }

    struct flow_event *ev = q->events[q->head];
    q->head = (q->head + 1) % QUEUE_SIZE;
    q->count--;

    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return ev;
}

#endif
