/*  Copyright 2016 Netflix.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 */

/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "memcached.h"
#include "memcached_sgx_out.h"
#include "storage.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <poll.h>

#define LARGEST_ID POWER_LARGEST

typedef struct
{
    void *c;       /* original connection structure. still with source thread attached. */
    int sfd;       /* client fd. */
    bipbuf_t *buf; /* output buffer */
    char *cbuf;    /* current buffer */
} crawler_client_t;

typedef struct _crawler_module_t crawler_module_t;

typedef void (*crawler_eval_func)(crawler_module_t *cm, item *it, uint32_t hv, int slab_cls);
typedef int (*crawler_init_func)(crawler_module_t *cm, void *data); // TODO: init args?
typedef void (*crawler_deinit_func)(crawler_module_t *cm);          // TODO: extra args?
typedef void (*crawler_doneclass_func)(crawler_module_t *cm, int slab_cls);
typedef void (*crawler_finalize_func)(crawler_module_t *cm);

typedef struct
{
    crawler_init_func init;           /* run before crawl starts */
    crawler_eval_func eval;           /* runs on an item. */
    crawler_doneclass_func doneclass; /* runs once per sub-crawler completion. */
    crawler_finalize_func finalize;   /* runs once when all sub-crawlers are done. */
    bool needs_lock;                  /* whether or not we need the LRU lock held when eval is called */
    bool needs_client;                /* whether or not to grab onto the remote client */
} crawler_module_reg_t;

struct _crawler_module_t
{
    void *data; /* opaque data pointer */
    crawler_client_t c;
    crawler_module_reg_t *mod;
};

static int crawler_expired_init(crawler_module_t *cm, void *data);
static void crawler_expired_doneclass(crawler_module_t *cm, int slab_cls);
static void crawler_expired_finalize(crawler_module_t *cm);
static void crawler_expired_eval(crawler_module_t *cm, item *search, uint32_t hv, int i);

crawler_module_reg_t crawler_expired_mod = {
    .init = crawler_expired_init,
    .eval = crawler_expired_eval,
    .doneclass = crawler_expired_doneclass,
    .finalize = crawler_expired_finalize,
    .needs_lock = true,
    .needs_client = false};

static void crawler_metadump_eval(crawler_module_t *cm, item *search, uint32_t hv, int i);
static void crawler_metadump_finalize(crawler_module_t *cm);

crawler_module_reg_t crawler_metadump_mod = {
    .init = NULL,
    .eval = crawler_metadump_eval,
    .doneclass = NULL,
    .finalize = crawler_metadump_finalize,
    .needs_lock = false,
    .needs_client = true};

crawler_module_reg_t *crawler_mod_regs[3] = {
    &crawler_expired_mod,
    &crawler_expired_mod,
    &crawler_metadump_mod};

static int lru_crawler_client_getbuf(crawler_client_t *c);
crawler_module_t active_crawler_mod;
enum crawler_run_type active_crawler_type;

static crawler crawlers[LARGEST_ID];

static int crawler_count = 0;
static volatile int do_run_lru_crawler_thread = 0;
static int lru_crawler_initialized = 0;
static pthread_mutex_t lru_crawler_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t lru_crawler_cond = PTHREAD_COND_INITIALIZER;
#ifdef EXTSTORE
/* TODO: pass this around */
static void *storage;
#endif

/* Will crawl all slab classes a minimum of once per hour */
#define MAX_MAINTCRAWL_WAIT 60 * 60

/*** LRU CRAWLER THREAD ***/

#define LRU_CRAWLER_WRITEBUF 8192

static void lru_crawler_close_client(crawler_client_t *c)
{
    //fprintf(stderr, "CRAWLER: Closing client\n");
    sidethread_conn_close(c->c);
    c->c = NULL;
    c->cbuf = NULL;
    bipbuf_free(c->buf);
    c->buf = NULL;
}

static void lru_crawler_release_client(crawler_client_t *c)
{
    //fprintf(stderr, "CRAWLER: Closing client\n");
    redispatch_conn(c->c);
    c->c = NULL;
    c->cbuf = NULL;
    bipbuf_free(c->buf);
    c->buf = NULL;
}

static int crawler_expired_init(crawler_module_t *cm, void *data)
{
    struct crawler_expired_data *d;
    if (data != NULL)
    {
        d = data;
        d->is_external = true;
        cm->data = data;
    }
    else
    {
        // allocate data.
        d = calloc(1, sizeof(struct crawler_expired_data));
        if (d == NULL)
        {
            return -1;
        }
        // init lock.
        pthread_mutex_init(&d->lock, NULL);
        d->is_external = false;
        d->start_time = current_time;

        cm->data = d;
    }
    pthread_mutex_lock(&d->lock);
    memset(&d->crawlerstats, 0, sizeof(crawlerstats_t) * POWER_LARGEST);
    for (int x = 0; x < POWER_LARGEST; x++)
    {
        d->crawlerstats[x].start_time = current_time;
        d->crawlerstats[x].run_complete = false;
    }
    pthread_mutex_unlock(&d->lock);
    return 0;
}

static void crawler_expired_doneclass(crawler_module_t *cm, int slab_cls)
{
    struct crawler_expired_data *d = (struct crawler_expired_data *)cm->data;
    pthread_mutex_lock(&d->lock);
    d->crawlerstats[slab_cls].end_time = current_time;
    d->crawlerstats[slab_cls].run_complete = true;
    pthread_mutex_unlock(&d->lock);
}

static void crawler_expired_finalize(crawler_module_t *cm)
{
    struct crawler_expired_data *d = (struct crawler_expired_data *)cm->data;
    pthread_mutex_lock(&d->lock);
    d->end_time = current_time;
    d->crawl_complete = true;
    pthread_mutex_unlock(&d->lock);

    if (!d->is_external)
    {
        free(d);
    }
}

static void crawler_metadump_finalize(crawler_module_t *cm)
{
    if (cm->c.c != NULL)
    {
        // Ensure space for final message.
        lru_crawler_client_getbuf(&cm->c);
        memcpy(cm->c.cbuf, "END\r\n", 5);
        bipbuf_push(cm->c.buf, 5);
    }
}

static int lru_crawler_poll(crawler_client_t *c)
{
    unsigned char *data;
    unsigned int data_size = 0;
    struct pollfd to_poll[1];
    to_poll[0].fd = c->sfd;
    to_poll[0].events = POLLOUT;

    int ret = poll(to_poll, 1, 1000);

    if (ret < 0)
    {
        // fatal.
        return -1;
    }

    if (ret == 0)
        return 0;

    if (to_poll[0].revents & POLLIN)
    {
        char buf[1];
        int res = ((conn *)c->c)->read(c->c, buf, 1);
        if (res == 0 || (res == -1 && (errno != EAGAIN && errno != EWOULDBLOCK)))
        {
            lru_crawler_close_client(c);
            return -1;
        }
    }
    if ((data = bipbuf_peek_all(c->buf, &data_size)) != NULL)
    {
        if (to_poll[0].revents & (POLLHUP | POLLERR))
        {
            lru_crawler_close_client(c);
            return -1;
        }
        else if (to_poll[0].revents & POLLOUT)
        {
            int total = ((conn *)c->c)->write(c->c, data, data_size);
            if (total == -1)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    lru_crawler_close_client(c);
                    return -1;
                }
            }
            else if (total == 0)
            {
                lru_crawler_close_client(c);
                return -1;
            }
            else
            {
                bipbuf_poll(c->buf, total);
            }
        }
    }
    return 0;
}

/* Grab some space to work with, if none exists, run the poll() loop and wait
 * for it to clear up or close.
 * Return NULL if closed.
 */
static int lru_crawler_client_getbuf(crawler_client_t *c)
{
    void *buf = NULL;
    if (c->c == NULL)
        return -1;
    /* not enough space. */
    while ((buf = bipbuf_request(c->buf, LRU_CRAWLER_WRITEBUF)) == NULL)
    {
        // TODO: max loops before closing.
        int ret = lru_crawler_poll(c);
        if (ret < 0)
            return ret;
    }

    c->cbuf = buf;
    return 0;
}

static pthread_t item_crawler_tid;

int stop_item_crawler_thread(bool wait)
{
    int ret;
    pthread_mutex_lock(&lru_crawler_lock);
    if (do_run_lru_crawler_thread == 0)
    {
        pthread_mutex_unlock(&lru_crawler_lock);
        return 0;
    }
    do_run_lru_crawler_thread = 0;
    pthread_cond_signal(&lru_crawler_cond);
    pthread_mutex_unlock(&lru_crawler_lock);
    if (wait && (ret = pthread_join(item_crawler_tid, NULL)) != 0)
    {
        fprintf(stderr, "Failed to stop LRU crawler thread: %s\n", strerror(ret));
        return -1;
    }
    return 0;
}

/* Lock dance to "block" until thread is waiting on its condition:
 * caller locks mtx. caller spawns thread.
 * thread blocks on mutex.
 * caller waits on condition, releases lock.
 * thread gets lock, sends signal.
 * caller can't wait, as thread has lock.
 * thread waits on condition, releases lock
 * caller wakes on condition, gets lock.
 * caller immediately releases lock.
 * thread is now safely waiting on condition before the caller returns.
 * 
 * pyuhala: the crawler thread does its job in the enclave so perform an
 * ecall.
 */

int sgx_start_item_crawler_thread(void)
{
    int ret;

    if (settings.lru_crawler)
        return -1;
    pthread_mutex_lock(&lru_crawler_lock);
    do_run_lru_crawler_thread = 1;
    if ((ret = pthread_create(&item_crawler_tid, NULL,
                              e_item_crawler_thread, NULL)) != 0)
    {
        fprintf(stderr, "Can't create LRU crawler thread: %s\n",
                strerror(ret));
        pthread_mutex_unlock(&lru_crawler_lock);
        return -1;
    }
    /* Avoid returning until the crawler has actually started */
    //pthread_cond_wait(&lru_crawler_cond, &lru_crawler_lock);
    pthread_mutex_unlock(&lru_crawler_lock);

    return 0;
}

/**
 * Transition into the enclave for assoc maintenance.
 */
void *e_item_crawler_thread(void *input)
{

    ecall_start_item_crawler(global_eid);
}

/* If we hold this lock, crawler can't wake up or move */
void lru_crawler_pause(void)
{
    pthread_mutex_lock(&lru_crawler_lock);
}

void lru_crawler_resume(void)
{
    pthread_mutex_unlock(&lru_crawler_lock);
}

int init_lru_crawler(void *arg)
{
    if (lru_crawler_initialized == 0)
    {
#ifdef EXTSTORE
        storage = arg;
#endif
        active_crawler_mod.c.c = NULL;
        active_crawler_mod.mod = NULL;
        active_crawler_mod.data = NULL;
        lru_crawler_initialized = 1;
    }
    return 0;
}

/*
 * Also only clear the crawlerstats once per sid.
 */
enum crawler_result_type lru_crawler_crawl(char *slabs, const enum crawler_run_type type,
                                           void *c, const int sfd, unsigned int remaining)
{
    char *b = NULL;
    uint32_t sid = 0;
    int starts = 0;
    uint8_t tocrawl[POWER_LARGEST];
    bool hash_crawl = false;

    /* FIXME: I added this while debugging. Don't think it's needed? */
    memset(tocrawl, 0, sizeof(uint8_t) * POWER_LARGEST);
    if (strcmp(slabs, "all") == 0)
    {
        for (sid = 0; sid < POWER_LARGEST; sid++)
        {
            tocrawl[sid] = 1;
        }
    }
    else if (strcmp(slabs, "hash") == 0)
    {
        hash_crawl = true;
    }
    else
    {
        for (char *p = strtok_r(slabs, ",", &b);
             p != NULL;
             p = strtok_r(NULL, ",", &b))
        {

            if (!safe_strtoul(p, &sid) || sid < POWER_SMALLEST || sid >= MAX_NUMBER_OF_SLAB_CLASSES)
            {
                return CRAWLER_BADCLASS;
            }
            tocrawl[sid | TEMP_LRU] = 1;
            tocrawl[sid | HOT_LRU] = 1;
            tocrawl[sid | WARM_LRU] = 1;
            tocrawl[sid | COLD_LRU] = 1;
        }
    }

    starts = lru_crawler_start(hash_crawl ? NULL : tocrawl, remaining, type, NULL, c, sfd);
    if (starts == -1)
    {
        return CRAWLER_RUNNING;
    }
    else if (starts == -2)
    {
        return CRAWLER_ERROR; /* FIXME: not very helpful. */
    }
    else if (starts)
    {
        return CRAWLER_OK;
    }
    else
    {
        return CRAWLER_NOTSTARTED;
    }
}

/* Lock dance to "block" until thread is waiting on its condition:
 * caller locks mtx. caller spawns thread.
 * thread blocks on mutex.
 * caller waits on condition, releases lock.
 * thread gets lock, sends signal.
 * caller can't wait, as thread has lock.
 * thread waits on condition, releases lock
 * caller wakes on condition, gets lock.
 * caller immediately releases lock.
 * thread is now safely waiting on condition before the caller returns.
 */
int start_item_crawler_thread(void)
{
    int ret;

    if (settings.lru_crawler)
        return -1;
    pthread_mutex_lock(&lru_crawler_lock);
    do_run_lru_crawler_thread = 1;
    if ((ret = pthread_create(&item_crawler_tid, NULL,
                              item_crawler_thread, NULL)) != 0)
    {
        fprintf(stderr, "Can't create LRU crawler thread: %s\n",
                strerror(ret));
        pthread_mutex_unlock(&lru_crawler_lock);
        return -1;
    }
    /* Avoid returning until the crawler has actually started */
    pthread_cond_wait(&lru_crawler_cond, &lru_crawler_lock);
    pthread_mutex_unlock(&lru_crawler_lock);

    return 0;
}

void *item_crawler_thread(void *arg)
{
    //pyuhala: removed --> see enclave version
}
static void crawler_expired_eval(crawler_module_t *cm, item *search, uint32_t hv, int i)
{
    //pyuhala:u removed --> see enclave version
}

static void crawler_metadump_eval(crawler_module_t *cm, item *it, uint32_t hv, int i)
{
    //pyuhala:u removed --> see enclave version
}

int lru_crawler_start(uint8_t *ids, uint32_t remaining,
                      const enum crawler_run_type type, void *data,
                      void *c, const int sfd)
{

    //pyuhala:u removed --> see enclave version
}