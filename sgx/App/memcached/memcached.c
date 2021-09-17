/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *  memcached - memory caching daemon
 *
 *       https://www.memcached.org/
 *
 *  Copyright 2003 Danga Interactive, Inc.  All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      Anatoly Vorobey <mellon@pobox.com>
 *      Brad Fitzpatrick <brad@danga.com>
 */
#include "memcached.h"
#include "storage.h"
#include "authfile.h"
#include "restart.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <ctype.h>
#include <stdarg.h>

//pyuhala: added function logging to routines

/* some POSIX systems need the following definition
 * to get mlockall flags out of sys/mman.h.  */
#ifndef _P1003_1B_VISIBLE
#define _P1003_1B_VISIBLE
#endif
#include <pwd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <sysexits.h>
#include <stddef.h>

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif

#ifdef TLS
#include "tls.h"
#endif

#include "proto_text.h"
#include "proto_bin.h"

#if defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif

/*
 * forward declarations
 */
static void drive_machine(conn *c);
static int new_socket(struct addrinfo *ai);
static ssize_t tcp_read(conn *arg, void *buf, size_t count);
static ssize_t tcp_sendmsg(conn *arg, struct msghdr *msg, int flags);
static ssize_t tcp_write(conn *arg, void *buf, size_t count);

enum try_read_result
{
    READ_DATA_RECEIVED,
    READ_NO_DATA_RECEIVED,
    READ_ERROR,       /** an error occurred (on the socket) (or client closed connection) */
    READ_MEMORY_ERROR /** failed to allocate more memory */
};

static int try_read_command_negotiate(conn *c);
static int try_read_command_udp(conn *c);

static enum try_read_result try_read_network(conn *c);
static enum try_read_result try_read_udp(conn *c);

static int start_conn_timeout_thread();

/* stats */
static void stats_init(void);
static void conn_to_str(const conn *c, char *addr, char *svr_addr);

/* defaults */
static void settings_init(void);

/* event handling, network IO */
static void event_handler(const evutil_socket_t fd, const short which, void *arg);
static void conn_close(conn *c);
static void conn_init(void);
static bool update_event(conn *c, const int new_flags);
static void complete_nread(conn *c);

static void conn_free(conn *c);

/** exported globals **/
struct stats stats;
struct stats_state stats_state;
struct settings settings;
time_t process_started; /* when the process was started */
conn **conns;

struct slab_rebalance slab_rebal;
volatile int slab_rebalance_signal;
#ifdef EXTSTORE
/* hoping this is temporary; I'd prefer to cut globals, but will complete this
 * battle another day.
 */
void *ext_storage = NULL;
#endif
/** file scope variables **/
static conn *listen_conn = NULL;
static int max_fds;
static struct event_base *main_base;

enum transmit_result
{
    TRANSMIT_COMPLETE,   /** All done writing. */
    TRANSMIT_INCOMPLETE, /** More data remaining to write. */
    TRANSMIT_SOFT_ERROR, /** Can't write any more right now. */
    TRANSMIT_HARD_ERROR  /** Can't write (c->state is set to conn_closing) */
};

/* Default methods to read from/ write to a socket */
ssize_t tcp_read(conn *c, void *buf, size_t count)
{
    log_routine(__func__);
    assert(c != NULL);
    return read(c->sfd, buf, count);
}

ssize_t tcp_sendmsg(conn *c, struct msghdr *msg, int flags)
{
    log_routine(__func__);
    assert(c != NULL);
    return sendmsg(c->sfd, msg, flags);
}

ssize_t tcp_write(conn *c, void *buf, size_t count)
{
    log_routine(__func__);
    assert(c != NULL);
    return write(c->sfd, buf, count);
}

static enum transmit_result transmit(conn *c);

/* This reduces the latency without adding lots of extra wiring to be able to
 * notify the listener thread of when to listen again.
 * Also, the clock timer could be broken out into its own thread and we
 * can block the listener via a condition.
 */
static volatile bool allow_new_conns = true;
static int stop_main_loop = NOT_STOP;
static struct event maxconnsevent;
static void maxconns_handler(const evutil_socket_t fd, const short which, void *arg)
{
    log_routine(__func__);
    struct timeval t = {.tv_sec = 0, .tv_usec = 10000};

    if (fd == -42 || allow_new_conns == false)
    {
        /* reschedule in 10ms if we need to keep polling */
        evtimer_set(&maxconnsevent, maxconns_handler, 0);
        event_base_set(main_base, &maxconnsevent);
        evtimer_add(&maxconnsevent, &t);
    }
    else
    {
        evtimer_del(&maxconnsevent);
        accept_new_conns(true);
    }
}

/*
 * given time value that's either unix time or delta from current unix time, return
 * unix time. Use the fact that delta can't exceed one month (and real time value can't
 * be that low).
 */
rel_time_t realtimexxx(const time_t exptime)
{
    log_routine(__func__);
    /* no. of seconds in 30 days - largest possible delta exptime */

    if (exptime == 0)
        return 0; /* 0 means never expire */

    if (exptime > REALTIME_MAXDELTA)
    {
        /* if item expiration is at/before the server started, give it an
           expiration time of 1 second after the server started.
           (because 0 means don't expire).  without this, we'd
           underflow and wrap around to some large value way in the
           future, effectively making items expiring in the past
           really expiring never */
        if (exptime <= process_started)
            return (rel_time_t)1;
        return (rel_time_t)(exptime - process_started);
    }
    else
    {
        return (rel_time_t)(exptime + current_time);
    }
}

static void stats_init(void)
{
    log_routine(__func__);
    memset(&stats, 0, sizeof(struct stats));
    memset(&stats_state, 0, sizeof(struct stats_state));
    stats_state.accepting_conns = true; /* assuming we start in this state. */

    /* make the time we started always be 2 seconds before we really
       did, so time(0) - time.started is never zero.  if so, things
       like 'settings.oldest_live' which act as booleans as well as
       values are now false in boolean context... */
    process_started = time(0) - ITEM_UPDATE_INTERVAL - 2;
    stats_prefix_init(settings.prefix_delimiter);
}

void stats_reset(void)
{
    log_routine(__func__);
    STATS_LOCK();
    memset(&stats, 0, sizeof(struct stats));
    stats_prefix_clear();
    STATS_UNLOCK();
    threadlocal_stats_reset();
    item_stats_reset();
}

static void settings_init(void)
{
    log_routine(__func__);
    settings.use_cas = true;
    settings.access = 0700;
    settings.port = 11211;
    settings.udpport = 0;
#ifdef TLS
    settings.ssl_enabled = false;
    settings.ssl_ctx = NULL;
    settings.ssl_chain_cert = NULL;
    settings.ssl_key = NULL;
    settings.ssl_verify_mode = SSL_VERIFY_NONE;
    settings.ssl_keyformat = SSL_FILETYPE_PEM;
    settings.ssl_ciphers = NULL;
    settings.ssl_ca_cert = NULL;
    settings.ssl_last_cert_refresh_time = current_time;
    settings.ssl_wbuf_size = 16 * 1024; // default is 16KB (SSL max frame size is 17KB)
    settings.ssl_session_cache = false;
#endif
    /* By default this string should be NULL for getaddrinfo() */
    settings.inter = NULL;
    settings.maxbytes = 64 * 1024 * 1024; /* default is 64MB */
    settings.maxconns = 1024;             /* to limit connections-related memory to about 5MB */
    settings.verbose = 0;
    settings.oldest_live = 0;
    settings.oldest_cas = 0;    /* supplements accuracy of oldest_live */
    settings.evict_to_free = 1; /* push old items out of cache when memory runs out */
    settings.socketpath = NULL; /* by default, not using a unix socket */
    settings.auth_file = NULL;  /* by default, not using ASCII authentication tokens */
    settings.factor = 1.25;
    settings.chunk_size = 48; /* space for a modest key and value */
    settings.num_threads = 2; /* N workers */
    settings.num_threads_per_udp = 0;
    settings.prefix_delimiter = ':';
    settings.detail_enabled = 0;
    settings.reqs_per_event = 20;
    settings.backlog = 1024;
    settings.binding_protocol = negotiating_prot;
    settings.item_size_max = 1024 * 1024;  /* The famous 1MB upper limit. */
    settings.slab_page_size = 1024 * 1024; /* chunks are split from 1MB pages. */
    settings.slab_chunk_size_max = settings.slab_page_size / 2;
    settings.sasl = false;
    settings.maxconns_fast = true;
    settings.lru_crawler = false;
    settings.lru_crawler_sleep = 100;
    settings.lru_crawler_tocrawl = 0;
    settings.lru_maintainer_thread = false;
    settings.lru_segmented = true;
    settings.hot_lru_pct = 20;
    settings.warm_lru_pct = 40;
    settings.hot_max_factor = 0.2;
    settings.warm_max_factor = 2.0;
    settings.temp_lru = false;
    settings.temporary_ttl = 61;
    settings.idle_timeout = 0; /* disabled */
    settings.hashpower_init = 0;
    settings.slab_reassign = true;
    settings.slab_automove = 1;
    settings.slab_automove_ratio = 0.8;
    settings.slab_automove_window = 30;
    settings.shutdown_command = false;
    settings.tail_repair_time = TAIL_REPAIR_TIME_DEFAULT;
    settings.flush_enabled = true;
    settings.dump_enabled = true;
    settings.crawls_persleep = 1000;
    settings.logger_watcher_buf_size = LOGGER_WATCHER_BUF_SIZE;
    settings.logger_buf_size = LOGGER_BUF_SIZE;
    settings.drop_privileges = false;
    settings.watch_enabled = true;
    settings.read_buf_mem_limit = 0;
#ifdef MEMCACHED_DEBUG
    settings.relaxed_privileges = false;
#endif
    settings.num_napi_ids = 0;
    settings.memory_file = NULL;
}

extern pthread_mutex_t conn_lock;

/* Connection timeout thread bits */
static pthread_t conn_timeout_tid;
static int do_run_conn_timeout_thread;
static pthread_cond_t conn_timeout_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t conn_timeout_lock = PTHREAD_MUTEX_INITIALIZER;

#define CONNS_PER_SLICE 100
#define TIMEOUT_MSG_SIZE (1 + sizeof(int))
static void *conn_timeout_thread(void *arg)
{
    log_routine(__func__);
    int i;
    conn *c;
    char buf[TIMEOUT_MSG_SIZE];
    rel_time_t oldest_last_cmd;
    int sleep_time;
    int sleep_slice = max_fds / CONNS_PER_SLICE;
    if (sleep_slice == 0)
        sleep_slice = CONNS_PER_SLICE;

    useconds_t timeslice = 1000000 / sleep_slice;

    mutex_lock(&conn_timeout_lock);
    while (do_run_conn_timeout_thread)
    {
        if (settings.verbose > 2)
            fprintf(stderr, "idle timeout thread at top of connection list\n");

        oldest_last_cmd = current_time;

        for (i = 0; i < max_fds; i++)
        {
            if ((i % CONNS_PER_SLICE) == 0)
            {
                if (settings.verbose > 2)
                    fprintf(stderr, "idle timeout thread sleeping for %ulus\n",
                            (unsigned int)timeslice);
                usleep(timeslice);
            }

            if (!conns[i])
                continue;

            c = conns[i];

            if (!IS_TCP(c->transport))
                continue;

            if (c->state != conn_new_cmd && c->state != conn_read)
                continue;

            if ((current_time - c->last_cmd_time) > settings.idle_timeout)
            {
                buf[0] = 't';
                memcpy(&buf[1], &i, sizeof(int));
                if (write(c->thread->notify_send_fd, buf, TIMEOUT_MSG_SIZE) != TIMEOUT_MSG_SIZE)
                    perror("Failed to write timeout to notify pipe");
            }
            else
            {
                if (c->last_cmd_time < oldest_last_cmd)
                    oldest_last_cmd = c->last_cmd_time;
            }
        }

        /* This is the soonest we could have another connection time out */
        sleep_time = settings.idle_timeout - (current_time - oldest_last_cmd) + 1;
        if (sleep_time <= 0)
            sleep_time = 1;

        if (settings.verbose > 2)
            fprintf(stderr,
                    "idle timeout thread finished pass, sleeping for %ds\n",
                    sleep_time);

        struct timeval now;
        struct timespec to_sleep;
        gettimeofday(&now, NULL);
        to_sleep.tv_sec = now.tv_sec + sleep_time;
        to_sleep.tv_nsec = 0;

        pthread_cond_timedwait(&conn_timeout_cond, &conn_timeout_lock, &to_sleep);
    }

    mutex_unlock(&conn_timeout_lock);
    return NULL;
}

static int start_conn_timeout_thread()
{
    log_routine(__func__);
    int ret;

    if (settings.idle_timeout == 0)
        return -1;

    do_run_conn_timeout_thread = 1;
    if ((ret = pthread_create(&conn_timeout_tid, NULL,
                              conn_timeout_thread, NULL)) != 0)
    {
        fprintf(stderr, "Can't create idle connection timeout thread: %s\n",
                strerror(ret));
        return -1;
    }

    return 0;
}

int stop_conn_timeout_thread(void)
{
    log_routine(__func__);
    if (!do_run_conn_timeout_thread)
        return -1;
    mutex_lock(&conn_timeout_lock);
    do_run_conn_timeout_thread = 0;
    pthread_cond_signal(&conn_timeout_cond);
    mutex_unlock(&conn_timeout_lock);
    pthread_join(conn_timeout_tid, NULL);
    return 0;
}

/*
 * read buffer cache helper functions
 */
static void rbuf_release(conn *c)
{
    log_routine(__func__);
    if (c->rbuf != NULL && c->rbytes == 0 && !IS_UDP(c->transport))
    {
        if (c->rbuf_malloced)
        {
            free(c->rbuf);
            c->rbuf_malloced = false;
        }
        else
        {
            do_cache_free(c->thread->rbuf_cache, c->rbuf);
        }
        c->rsize = 0;
        c->rbuf = NULL;
        c->rcurr = NULL;
    }
}

static bool rbuf_alloc(conn *c)
{
    log_routine(__func__);
    if (c->rbuf == NULL)
    {
        c->rbuf = do_cache_alloc(c->thread->rbuf_cache);
        if (!c->rbuf)
        {
            THR_STATS_LOCK(c);
            c->thread->stats.read_buf_oom++;
            THR_STATS_UNLOCK(c);
            return false;
        }
        c->rsize = READ_BUFFER_SIZE;
        c->rcurr = c->rbuf;
    }
    return true;
}

// Just for handling huge ASCII multigets.
// The previous system was essentially the same; realloc'ing until big enough,
// then realloc'ing back down after the request finished.
bool rbuf_switch_to_malloc(conn *c)
{
    log_routine(__func__);
    // Might as well start with x2 and work from there.
    size_t size = c->rsize * 2;
    char *tmp = malloc(size);
    if (!tmp)
        return false;

    do_cache_free(c->thread->rbuf_cache, c->rbuf);
    memcpy(tmp, c->rcurr, c->rbytes);

    c->rcurr = c->rbuf = tmp;
    c->rsize = size;
    c->rbuf_malloced = true;
    return true;
}

/*
 * Initializes the connections array. We don't actually allocate connection
 * structures until they're needed, so as to avoid wasting memory when the
 * maximum connection count is much higher than the actual number of
 * connections.
 *
 * This does end up wasting a few pointers' worth of memory for FDs that are
 * used for things other than connections, but that's worth it in exchange for
 * being able to directly index the conns array by FD.
 */
static void conn_init(void)
{
    log_routine(__func__);
    /* We're unlikely to see an FD much higher than maxconns. */
    int next_fd = dup(1);
    if (next_fd < 0)
    {
        perror("Failed to duplicate file descriptor\n");
        exit(1);
    }
    int headroom = 10; /* account for extra unexpected open FDs */
    struct rlimit rl;

    max_fds = settings.maxconns + headroom + next_fd;

    /* But if possible, get the actual highest FD we can possibly ever see. */
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
    {
        max_fds = rl.rlim_max;
    }
    else
    {
        fprintf(stderr, "Failed to query maximum file descriptor; "
                        "falling back to maxconns\n");
    }

    close(next_fd);

    if ((conns = calloc(max_fds, sizeof(conn *))) == NULL)
    {
        fprintf(stderr, "Failed to allocate connection structures\n");
        /* This is unrecoverable so bail out early. */
        exit(1);
    }
}

static const char *prot_text(enum protocol prot)
{
    log_routine(__func__);
    char *rv = "unknown";
    switch (prot)
    {
    case ascii_prot:
        rv = "ascii";
        break;
    case binary_prot:
        rv = "binary";
        break;
    case negotiating_prot:
        rv = "auto-negotiate";
        break;
    }
    return rv;
}

void conn_close_idle(conn *c)
{
    log_routine(__func__);
    if (settings.idle_timeout > 0 &&
        (current_time - c->last_cmd_time) > settings.idle_timeout)
    {
        if (c->state != conn_new_cmd && c->state != conn_read)
        {
            if (settings.verbose > 1)
                fprintf(stderr,
                        "fd %d wants to timeout, but isn't in read state", c->sfd);
            return;
        }

        if (settings.verbose > 1)
            fprintf(stderr, "Closing idle fd %d\n", c->sfd);

        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.idle_kicks++;
        pthread_mutex_unlock(&c->thread->stats.mutex);

        conn_set_state(c, conn_closing);
        drive_machine(c);
    }
}

/* bring conn back from a sidethread. could have had its event base moved. */
void conn_worker_readd(conn *c)
{
    log_routine(__func__);
    if (c->state == conn_io_queue)
    {
        c->io_queues_submitted--;
        // If we're still waiting for other queues to return, don't re-add the
        // connection yet.
        if (c->io_queues_submitted != 0)
        {
            return;
        }
    }
    c->ev_flags = EV_READ | EV_PERSIST;
   
    event_set(&c->event, c->sfd, c->ev_flags, event_handler, (void *)c);
    event_base_set(c->thread->base, &c->event);

    // TODO: call conn_cleanup/fail/etc
    if (event_add(&c->event, 0) == -1)
    {
        perror("event_add");
    }

    // side thread wanted us to close immediately.
    if (c->state == conn_closing)
    {
        drive_machine(c);
        return;
    }
    else if (c->state == conn_io_queue)
    {
        // machine will know how to return based on secondary state.
        drive_machine(c);
    }
    else
    {
        conn_set_state(c, conn_new_cmd);
    }
}

void conn_io_queue_add(conn *c, int type, void *ctx, io_queue_stack_cb cb, io_queue_stack_cb com_cb, io_queue_cb fin_cb)
{
    log_routine(__func__);
    io_queue_t *q = c->io_queues;
    while (q->type != IO_QUEUE_NONE)
    {
        q++;
    }
    q->type = type;
    q->ctx = ctx;
    q->stack_ctx = NULL;
    q->submit_cb = cb;
    q->complete_cb = com_cb;
    q->finalize_cb = fin_cb;
    return;
}

io_queue_t *conn_io_queue_get(conn *c, int type)
{
    log_routine(__func__);
    io_queue_t *q = c->io_queues;
    while (q->type != IO_QUEUE_NONE)
    {
        if (q->type == type)
        {
            return q;
        }
        q++;
    }
    return NULL;
}

// called after returning to the main worker thread.
// users of the queue need to distinguish if the IO was actually consumed or
// not and handle appropriately.
static void conn_io_queue_complete(conn *c)
{
    log_routine(__func__);
    io_queue_t *q = c->io_queues;
    while (q->type != IO_QUEUE_NONE)
    {
        // Reuse the same submit stack. We zero it out first so callbacks can
        // queue new IO's if necessary.
        if (q->stack_ctx)
        {
            void *tmp = q->stack_ctx;
            q->stack_ctx = NULL;
            q->complete_cb(q->ctx, tmp);
        }
        q++;
    }
}

conn *conn_newxxx(const int sfd, enum conn_states init_state,
               const int event_flags,
               const int read_buffer_size, enum network_transport transport,
               struct event_base *base, void *ssl)
{

    log_routine(__func__);
    conn *c;

    assert(sfd >= 0 && sfd < max_fds);
    c = conns[sfd];

    if (NULL == c)
    {
        if (!(c = (conn *)calloc(1, sizeof(conn))))
        {
            STATS_LOCK();
            stats.malloc_fails++;
            STATS_UNLOCK();
            fprintf(stderr, "Failed to allocate connection object\n");
            return NULL;
        }
        MEMCACHED_CONN_CREATE(c);
        c->read = NULL;
        c->sendmsg = NULL;
        c->write = NULL;
        c->rbuf = NULL;

        c->rsize = read_buffer_size;

        // UDP connections use a persistent static buffer.
        if (c->rsize)
        {
            c->rbuf = (char *)malloc((size_t)c->rsize);
        }

        if (c->rsize && c->rbuf == NULL)
        {
            conn_free(c);
            STATS_LOCK();
            stats.malloc_fails++;
            STATS_UNLOCK();
            fprintf(stderr, "Failed to allocate buffers for connection\n");
            return NULL;
        }

        STATS_LOCK();
        stats_state.conn_structs++;
        STATS_UNLOCK();

        c->sfd = sfd;
        conns[sfd] = c;
    }

    c->transport = transport;
    c->protocol = settings.binding_protocol;

    /* unix socket mode doesn't need this, so zeroed out.  but why
     * is this done for every command?  presumably for UDP
     * mode.  */
    if (!settings.socketpath)
    {
        c->request_addr_size = sizeof(c->request_addr);
    }
    else
    {
        c->request_addr_size = 0;
    }

    if (transport == tcp_transport && init_state == conn_new_cmd)
    {
        if (getpeername(sfd, (struct sockaddr *)&c->request_addr,
                        &c->request_addr_size))
        {
            perror("getpeername");
            memset(&c->request_addr, 0, sizeof(c->request_addr));
        }
    }

    if (settings.verbose > 1)
    {
        if (init_state == conn_listening)
        {
            fprintf(stderr, "<%d server listening (%s)\n", sfd,
                    prot_text(c->protocol));
        }
        else if (IS_UDP(transport))
        {
            fprintf(stderr, "<%d server listening (udp)\n", sfd);
        }
        else if (c->protocol == negotiating_prot)
        {
            fprintf(stderr, "<%d new auto-negotiating client connection\n",
                    sfd);
        }
        else if (c->protocol == ascii_prot)
        {
            fprintf(stderr, "<%d new ascii client connection.\n", sfd);
        }
        else if (c->protocol == binary_prot)
        {
            fprintf(stderr, "<%d new binary client connection.\n", sfd);
        }
        else
        {
            fprintf(stderr, "<%d new unknown (%d) client connection\n",
                    sfd, c->protocol);
            assert(false);
        }
    }

#ifdef TLS
    c->ssl = NULL;
    c->ssl_wbuf = NULL;
    c->ssl_enabled = false;
#endif
    c->state = init_state;
    c->rlbytes = 0;
    c->cmd = -1;
    c->rbytes = 0;
    c->rcurr = c->rbuf;
    c->ritem = 0;
    c->rbuf_malloced = false;
    c->item_malloced = false;
    c->sasl_started = false;
    c->set_stale = false;
    c->mset_res = false;
    c->close_after_write = false;
    c->last_cmd_time = current_time; /* initialize for idle kicker */
    // wipe all queues.
    memset(c->io_queues, 0, sizeof(c->io_queues));
    c->io_queues_submitted = 0;

    c->item = 0;

    c->noreply = false;

#ifdef TLS
    if (ssl)
    {
        c->ssl = (SSL *)ssl;
        c->read = ssl_read;
        c->sendmsg = ssl_sendmsg;
        c->write = ssl_write;
        c->ssl_enabled = true;
        SSL_set_info_callback(c->ssl, ssl_callback);
    }
    else
#else
    // This must be NULL if TLS is not enabled.
    assert(ssl == NULL);
#endif
    {
        c->read = tcp_read;
        c->sendmsg = tcp_sendmsg;
        c->write = tcp_write;
    }

    if (IS_UDP(transport))
    {
        c->try_read_command = try_read_command_udp;
    }
    else
    {
        switch (c->protocol)
        {
        case ascii_prot:
            if (settings.auth_file == NULL)
            {
                c->authenticated = true;
                c->try_read_command = try_read_command_ascii;
            }
            else
            {
                c->authenticated = false;
                c->try_read_command = try_read_command_asciiauth;
            }
            break;
        case binary_prot:
            // binprot handles its own authentication via SASL parsing.
            c->authenticated = false;
            c->try_read_command = try_read_command_binary;
            break;
        case negotiating_prot:
            c->try_read_command = try_read_command_negotiate;
            break;
        }
    }

    event_set(&c->event, sfd, event_flags, NULL, (void *)c);
    event_set(&c->event, sfd, event_flags, event_handler, (void *)c);
    event_base_set(base, &c->event);
    c->ev_flags = event_flags;

    if (event_add(&c->event, 0) == -1)
    {
        perror("event_add");
        return NULL;
    }

    STATS_LOCK();
    stats_state.curr_conns++;
    stats.total_conns++;
    STATS_UNLOCK();

    MEMCACHED_CONN_ALLOCATE(c->sfd);

    return c;
}

void conn_release_items(conn *c)
{
    log_routine(__func__);
    assert(c != NULL);

    if (c->item)
    {
        if (c->item_malloced)
        {
            free(c->item);
            c->item_malloced = false;
        }
        else
        {
            item_remove(c->item);
        }
        c->item = 0;
    }

    // Cull any unsent responses.
    if (c->resp_head)
    {
        mc_resp *resp = c->resp_head;
        // r_f() handles the chain maintenance.
        while (resp)
        {
            // temporary by default. hide behind a debug flag in the future:
            // double free detection. Transmit loops can drop out early, but
            // here we could infinite loop.
            if (resp->free)
            {
                fprintf(stderr, "ERROR: double free detected during conn_release_items(): [%d] [%s]\n",
                        c->sfd, c->protocol == binary_prot ? "binary" : "ascii");
                // Since this is a critical failure, just leak the memory.
                // If these errors are seen, an abort() can be used instead.
                c->resp_head = NULL;
                c->resp = NULL;
                break;
            }
            resp = resp_finish(c, resp);
        }
    }
}

static void conn_cleanup(conn *c)
{
    log_routine(__func__);
    assert(c != NULL);

    conn_release_items(c);

    if (c->sasl_conn)
    {
        assert(settings.sasl);
        sasl_dispose(&c->sasl_conn);
        c->sasl_conn = NULL;
    }

    if (IS_UDP(c->transport))
    {
        conn_set_state(c, conn_read);
    }
}

/*
 * Frees a connection.
 */
void conn_free(conn *c)
{
    log_routine(__func__);
    if (c)
    {
        assert(c != NULL);
        assert(c->sfd >= 0 && c->sfd < max_fds);

        MEMCACHED_CONN_DESTROY(c);
        conns[c->sfd] = NULL;
        if (c->rbuf)
            free(c->rbuf);
#ifdef TLS
        if (c->ssl_wbuf)
            c->ssl_wbuf = NULL;
#endif

        free(c);
    }
}

static void conn_close(conn *c)
{
    log_routine(__func__);
    assert(c != NULL);

    /* delete the event, the socket and the conn */
    event_del(&c->event);

    if (settings.verbose > 1)
        fprintf(stderr, "<%d connection closed.\n", c->sfd);

    conn_cleanup(c);

    // force release of read buffer.
    if (c->thread)
    {
        c->rbytes = 0;
        rbuf_release(c);
    }

    MEMCACHED_CONN_RELEASE(c->sfd);
    conn_set_state(c, conn_closed);
#ifdef TLS
    if (c->ssl)
    {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
#endif
    close(c->sfd);
    pthread_mutex_lock(&conn_lock);
    allow_new_conns = true;
    pthread_mutex_unlock(&conn_lock);

    STATS_LOCK();
    stats_state.curr_conns--;
    STATS_UNLOCK();

    return;
}

// Since some connections might be off on side threads and some are managed as
// listeners we need to walk through them all from a central point.
// Must be called with all worker threads hung or in the process of closing.
void conn_close_allxxx(void)
{
    log_routine(__func__);
    int i;
    for (i = 0; i < max_fds; i++)
    {
        if (conns[i] && conns[i]->state != conn_closed)
        {
            conn_close(conns[i]);
        }
    }
}

/**
 * Convert a state name to a human readable form.
 */
static const char *state_text(enum conn_states state)
{
    log_routine(__func__);
    const char *const statenames[] = {"conn_listening",
                                      "conn_new_cmd",
                                      "conn_waiting",
                                      "conn_read",
                                      "conn_parse_cmd",
                                      "conn_write",
                                      "conn_nread",
                                      "conn_swallow",
                                      "conn_closing",
                                      "conn_mwrite",
                                      "conn_closed",
                                      "conn_watch",
                                      "conn_io_queue"};
    return statenames[state];
}

/*
 * Sets a connection's current state in the state machine. Any special
 * processing that needs to happen on certain state transitions can
 * happen here.
 */
void conn_set_state(conn *c, enum conn_states state)
{
    log_routine(__func__);
    assert(c != NULL);
    assert(state >= conn_listening && state < conn_max_state);

    if (state != c->state)
    {
        if (settings.verbose > 2)
        {
            fprintf(stderr, "%d: going from %s to %s\n",
                    c->sfd, state_text(c->state),
                    state_text(state));
        }

        if (state == conn_write || state == conn_mwrite)
        {
            MEMCACHED_PROCESS_COMMAND_END(c->sfd, c->resp->wbuf, c->resp->wbytes);
        }
        c->state = state;
    }
}

/*
 * response object helper functions
 */
void resp_reset(mc_resp *resp)
{
    log_routine(__func__);
    if (resp->item)
    {
        item_remove(resp->item);
        resp->item = NULL;
    }
    if (resp->write_and_free)
    {
        free(resp->write_and_free);
        resp->write_and_free = NULL;
    }
    resp->wbytes = 0;
    resp->tosend = 0;
    resp->iovcnt = 0;
    resp->chunked_data_iov = 0;
    resp->chunked_total = 0;
    resp->skip = false;
}

void resp_add_iov(mc_resp *resp, const void *buf, int len)
{
    log_routine(__func__);
    assert(resp->iovcnt < MC_RESP_IOVCOUNT);
    int x = resp->iovcnt;
    resp->iov[x].iov_base = (void *)buf;
    resp->iov[x].iov_len = len;
    resp->iovcnt++;
    resp->tosend += len;
}

// Notes that an IOV should be handled as a chunked item header.
// TODO: I'm hoping this isn't a permanent abstraction while I learn what the
// API should be.
void resp_add_chunked_iov(mc_resp *resp, const void *buf, int len)
{
    log_routine(__func__);
    resp->chunked_data_iov = resp->iovcnt;
    resp->chunked_total = len;
    resp_add_iov(resp, buf, len);
}

// resp_allocate and resp_free are a wrapper around read buffers which makes
// read buffers the only network memory to track.
// Normally this would be too excessive. In this case it allows end users to
// track a single memory limit for ephemeral connection buffers.
// Fancy bit twiddling tricks are avoided to help keep this straightforward.
static mc_resp *resp_allocate(conn *c)
{
    log_routine(__func__);
    LIBEVENT_THREAD *th = c->thread;
    mc_resp *resp = NULL;
    mc_resp_bundle *b = th->open_bundle;

    if (b != NULL)
    {
        for (int i = 0; i < MAX_RESP_PER_BUNDLE; i++)
        {
            // loop around starting from the most likely to be free
            int x = (i + b->next_check) % MAX_RESP_PER_BUNDLE;
            if (b->r[x].free)
            {
                resp = &b->r[x];
                b->next_check = x + 1;
                break;
            }
        }

        if (resp != NULL)
        {
            b->refcount++;
            resp->free = false;
            if (b->refcount == MAX_RESP_PER_BUNDLE)
            {
                assert(b->prev == NULL);
                // We only allocate off the head. Assign new head.
                th->open_bundle = b->next;
                // Remove ourselves from the list.
                if (b->next)
                {
                    b->next->prev = 0;
                    b->next = 0;
                }
            }
        }
    }

    if (resp == NULL)
    {
        assert(th->open_bundle == NULL);
        b = do_cache_alloc(th->rbuf_cache);
        if (b)
        {
            THR_STATS_LOCK(c);
            c->thread->stats.response_obj_bytes += READ_BUFFER_SIZE;
            THR_STATS_UNLOCK(c);
            b->next_check = 1;
            b->refcount = 1;
            for (int i = 0; i < MAX_RESP_PER_BUNDLE; i++)
            {
                b->r[i].bundle = b;
                b->r[i].free = true;
            }
            b->next = 0;
            b->prev = 0;
            th->open_bundle = b;
            resp = &b->r[0];
            resp->free = false;
        }
        else
        {
            return NULL;
        }
    }

    return resp;
}

static void resp_free(conn *c, mc_resp *resp)
{
    log_routine(__func__);
    LIBEVENT_THREAD *th = c->thread;
    mc_resp_bundle *b = resp->bundle;

    resp->free = true;
    b->refcount--;
    if (b->refcount == 0)
    {
        if (b == th->open_bundle && b->next == 0)
        {
            // This is the final bundle. Just hold and reuse to skip init loop
            assert(b->prev == 0);
            b->next_check = 0;
        }
        else
        {
            // Assert that we're either in the list or at the head.
            assert((b->next || b->prev) || b == th->open_bundle);

            // unlink from list.
            mc_resp_bundle **head = &th->open_bundle;
            if (*head == b)
                *head = b->next;
            // Not tracking the tail.
            assert(b->next != b && b->prev != b);

            if (b->next)
                b->next->prev = b->prev;
            if (b->prev)
                b->prev->next = b->next;

            // Now completely done with this buffer.
            do_cache_free(th->rbuf_cache, b);
            THR_STATS_LOCK(c);
            c->thread->stats.response_obj_bytes -= READ_BUFFER_SIZE;
            THR_STATS_UNLOCK(c);
        }
    }
    else
    {
        mc_resp_bundle **head = &th->open_bundle;
        // NOTE: since we're not tracking tail, latest free ends up in head.
        if (b == th->open_bundle || (b->prev || b->next))
        {
            // If we're already linked, leave it in place to save CPU.
        }
        else
        {
            // Non-zero refcount, need to link into the freelist.
            b->prev = 0;
            b->next = *head;
            if (b->next)
                b->next->prev = b;
            *head = b;
        }
    }
}

bool resp_start(conn *c)
{
    log_routine(__func__);
    mc_resp *resp = resp_allocate(c);
    if (!resp)
    {
        THR_STATS_LOCK(c);
        c->thread->stats.response_obj_oom++;
        THR_STATS_UNLOCK(c);
        return false;
    }
    // handling the stats counters here to simplify testing
    THR_STATS_LOCK(c);
    c->thread->stats.response_obj_count++;
    THR_STATS_UNLOCK(c);
    // Skip zeroing the bundle pointer at the start.
    // TODO: this line is here temporarily to make the code easy to disable.
    // when it's more mature, move the memset into resp_allocate() and have it
    // set the bundle pointer on allocate so this line isn't as complex.
    memset((char *)resp + sizeof(mc_resp_bundle *), 0, sizeof(*resp) - sizeof(mc_resp_bundle *));
    // TODO: this next line works. memset _does_ show up significantly under
    // perf reports due to zeroing out the entire resp->wbuf. before swapping
    // the lines more validation work should be done to ensure wbuf's aren't
    // accidentally reused without being written to.
    //memset((char *)resp + sizeof(mc_resp_bundle*), 0, offsetof(mc_resp, wbuf));
    if (!c->resp_head)
    {
        c->resp_head = resp;
    }
    if (!c->resp)
    {
        c->resp = resp;
    }
    else
    {
        c->resp->next = resp;
        c->resp = resp;
    }
    if (IS_UDP(c->transport))
    {
        // need to hold on to some data for async responses.
        c->resp->request_id = c->request_id;
        c->resp->request_addr = c->request_addr;
        c->resp->request_addr_size = c->request_addr_size;
    }
    return true;
}

// returns next response in chain.
mc_resp *resp_finish(conn *c, mc_resp *resp)
{
    log_routine(__func__);
    mc_resp *next = resp->next;
    if (resp->item)
    {
        // TODO: cache hash value in resp obj?
        item_remove(resp->item);
        resp->item = NULL;
    }
    if (resp->write_and_free)
    {
        free(resp->write_and_free);
    }
    if (resp->io_pending)
    {
        // If we had a pending IO, tell it to internally clean up then return
        // the main object back to our thread cache.
        resp->io_pending->q->finalize_cb(resp->io_pending);
        do_cache_free(c->thread->io_cache, resp->io_pending);
        resp->io_pending = NULL;
    }
    if (c->resp_head == resp)
    {
        c->resp_head = next;
    }
    if (c->resp == resp)
    {
        c->resp = NULL;
    }
    resp_free(c, resp);
    THR_STATS_LOCK(c);
    c->thread->stats.response_obj_count--;
    THR_STATS_UNLOCK(c);
    return next;
}

// tells if connection has a depth of response objects to process.
bool resp_has_stack(conn *c)
{
    log_routine(__func__);
    return c->resp_head->next != NULL ? true : false;
}

void out_string(conn *c, const char *str)
{
    log_routine(__func__);
    size_t len;
    assert(c != NULL);
    mc_resp *resp = c->resp;

    // if response was original filled with something, but we're now writing
    // out an error or similar, have to reset the object first.
    // TODO: since this is often redundant with allocation, how many callers
    // are actually requiring it be reset? Can we fast test by just looking at
    // tosend and reset if nonzero?
    resp_reset(resp);

    if (c->noreply)
    {
        // TODO: just invalidate the response since nothing's been attempted
        // to send yet?
        resp->skip = true;
        if (settings.verbose > 1)
            fprintf(stderr, ">%d NOREPLY %s\n", c->sfd, str);
        conn_set_state(c, conn_new_cmd);
        return;
    }

    if (settings.verbose > 1)
        fprintf(stderr, ">%d %s\n", c->sfd, str);

    // Fill response object with static string.

    len = strlen(str);
    if ((len + 2) > WRITE_BUFFER_SIZE)
    {
        /* ought to be always enough. just fail for simplicity */
        str = "SERVER_ERROR output line too long";
        len = strlen(str);
    }

    memcpy(resp->wbuf, str, len);
    memcpy(resp->wbuf + len, "\r\n", 2);
    resp_add_iov(resp, resp->wbuf, len + 2);

    conn_set_state(c, conn_new_cmd);
    return;
}

// For metaget-style ASCII commands. Ignores noreply, ensuring clients see
// protocol level errors.
void out_errstring(conn *c, const char *str)
{
    log_routine(__func__);
    c->noreply = false;
    out_string(c, str);
}

/*
 * Outputs a protocol-specific "out of memory" error. For ASCII clients,
 * this is equivalent to out_string().
 */
void out_of_memory(conn *c, char *ascii_error)
{
    log_routine(__func__);
    const static char error_prefix[] = "SERVER_ERROR ";
    const static int error_prefix_len = sizeof(error_prefix) - 1;

    if (c->protocol == binary_prot)
    {
        /* Strip off the generic error prefix; it's irrelevant in binary */
        if (!strncmp(ascii_error, error_prefix, error_prefix_len))
        {
            ascii_error += error_prefix_len;
        }
        write_bin_error(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, ascii_error, 0);
    }
    else
    {
        out_string(c, ascii_error);
    }
}

static void append_bin_stats(const char *key, const uint16_t klen,
                             const char *val, const uint32_t vlen,
                             conn *c)
{
    log_routine(__func__);
    char *buf = c->stats.buffer + c->stats.offset;
    uint32_t bodylen = klen + vlen;
    protocol_binary_response_header header = {
        .response.magic = (uint8_t)PROTOCOL_BINARY_RES,
        .response.opcode = PROTOCOL_BINARY_CMD_STAT,
        .response.keylen = (uint16_t)htons(klen),
        .response.datatype = (uint8_t)PROTOCOL_BINARY_RAW_BYTES,
        .response.bodylen = htonl(bodylen),
        .response.opaque = c->opaque};

    memcpy(buf, header.bytes, sizeof(header.response));
    buf += sizeof(header.response);

    if (klen > 0)
    {
        memcpy(buf, key, klen);
        buf += klen;

        if (vlen > 0)
        {
            memcpy(buf, val, vlen);
        }
    }

    c->stats.offset += sizeof(header.response) + bodylen;
}

static void append_ascii_stats(const char *key, const uint16_t klen,
                               const char *val, const uint32_t vlen,
                               conn *c)
{
    log_routine(__func__);
    char *pos = c->stats.buffer + c->stats.offset;
    uint32_t nbytes = 0;
    int remaining = c->stats.size - c->stats.offset;
    int room = remaining - 1;

    if (klen == 0 && vlen == 0)
    {
        nbytes = snprintf(pos, room, "END\r\n");
    }
    else if (vlen == 0)
    {
        nbytes = snprintf(pos, room, "STAT %s\r\n", key);
    }
    else
    {
        nbytes = snprintf(pos, room, "STAT %s %s\r\n", key, val);
    }

    c->stats.offset += nbytes;
}

static bool grow_stats_buf(conn *c, size_t needed)
{
    log_routine(__func__);
    size_t nsize = c->stats.size;
    size_t available = nsize - c->stats.offset;
    bool rv = true;

    /* Special case: No buffer -- need to allocate fresh */
    if (c->stats.buffer == NULL)
    {
        nsize = 1024;
        available = c->stats.size = c->stats.offset = 0;
    }

    while (needed > available)
    {
        assert(nsize > 0);
        nsize = nsize << 1;
        available = nsize - c->stats.offset;
    }

    if (nsize != c->stats.size)
    {
        char *ptr = realloc(c->stats.buffer, nsize);
        if (ptr)
        {
            c->stats.buffer = ptr;
            c->stats.size = nsize;
        }
        else
        {
            STATS_LOCK();
            stats.malloc_fails++;
            STATS_UNLOCK();
            rv = false;
        }
    }

    return rv;
}

void append_stats(const char *key, const uint16_t klen,
                  const char *val, const uint32_t vlen,
                  const void *cookie)
{
    log_routine(__func__);
    /* value without a key is invalid */
    if (klen == 0 && vlen > 0)
    {
        return;
    }

    conn *c = (conn *)cookie;

    if (c->protocol == binary_prot)
    {
        size_t needed = vlen + klen + sizeof(protocol_binary_response_header);
        if (!grow_stats_buf(c, needed))
        {
            return;
        }
        append_bin_stats(key, klen, val, vlen, c);
    }
    else
    {
        size_t needed = vlen + klen + 10; // 10 == "STAT = \r\n"
        if (!grow_stats_buf(c, needed))
        {
            return;
        }
        append_ascii_stats(key, klen, val, vlen, c);
    }

    assert(c->stats.offset <= c->stats.size);
}

static void reset_cmd_handler(conn *c)
{
    log_routine(__func__);
    c->cmd = -1;
    c->substate = bin_no_state;
    if (c->item != NULL)
    {
        // TODO: Any other way to get here?
        // SASL auth was mistakenly using it. Nothing else should?
        if (c->item_malloced)
        {
            free(c->item);
            c->item_malloced = false;
        }
        else
        {
            item_remove(c->item);
        }
        c->item = NULL;
    }
    if (c->rbytes > 0)
    {
        conn_set_state(c, conn_parse_cmd);
    }
    else if (c->resp_head)
    {
        conn_set_state(c, conn_mwrite);
    }
    else
    {
        conn_set_state(c, conn_waiting);
    }
}

static void complete_nread(conn *c)
{
    log_routine(__func__);
    assert(c != NULL);
    assert(c->protocol == ascii_prot || c->protocol == binary_prot);

    if (c->protocol == ascii_prot)
    {
        complete_nread_ascii(c);
    }
    else if (c->protocol == binary_prot)
    {
        complete_nread_binary(c);
    }
}

/* Destination must always be chunked */
/* This should be part of item.c */
static int _store_item_copy_chunks(item *d_it, item *s_it, const int len)
{
    log_routine(__func__);
    item_chunk *dch = (item_chunk *)ITEM_schunk(d_it);
    /* Advance dch until we find free space */
    while (dch->size == dch->used)
    {
        if (dch->next)
        {
            dch = dch->next;
        }
        else
        {
            break;
        }
    }

    if (s_it->it_flags & ITEM_CHUNKED)
    {
        int remain = len;
        item_chunk *sch = (item_chunk *)ITEM_schunk(s_it);
        int copied = 0;
        /* Fills dch's to capacity, not straight copy sch in case data is
         * being added or removed (ie append/prepend)
         */
        while (sch && dch && remain)
        {
            assert(dch->used <= dch->size);
            int todo = (dch->size - dch->used < sch->used - copied)
                           ? dch->size - dch->used
                           : sch->used - copied;
            if (remain < todo)
                todo = remain;
            memcpy(dch->data + dch->used, sch->data + copied, todo);
            dch->used += todo;
            copied += todo;
            remain -= todo;
            assert(dch->used <= dch->size);
            if (dch->size == dch->used)
            {
                item_chunk *tch = do_item_alloc_chunk(dch, remain);
                if (tch)
                {
                    dch = tch;
                }
                else
                {
                    return -1;
                }
            }
            assert(copied <= sch->used);
            if (copied == sch->used)
            {
                copied = 0;
                sch = sch->next;
            }
        }
        /* assert that the destination had enough space for the source */
        assert(remain == 0);
    }
    else
    {
        int done = 0;
        /* Fill dch's via a non-chunked item. */
        while (len > done && dch)
        {
            int todo = (dch->size - dch->used < len - done)
                           ? dch->size - dch->used
                           : len - done;
            //assert(dch->size - dch->used != 0);
            memcpy(dch->data + dch->used, ITEM_data(s_it) + done, todo);
            done += todo;
            dch->used += todo;
            assert(dch->used <= dch->size);
            if (dch->size == dch->used)
            {
                item_chunk *tch = do_item_alloc_chunk(dch, len - done);
                if (tch)
                {
                    dch = tch;
                }
                else
                {
                    return -1;
                }
            }
        }
        assert(len == done);
    }
    return 0;
}

static int _store_item_copy_data(int comm, item *old_it, item *new_it, item *add_it)
{
    log_routine(__func__);
    if (comm == NREAD_APPEND)
    {
        if (new_it->it_flags & ITEM_CHUNKED)
        {
            if (_store_item_copy_chunks(new_it, old_it, old_it->nbytes - 2) == -1 ||
                _store_item_copy_chunks(new_it, add_it, add_it->nbytes) == -1)
            {
                return -1;
            }
        }
        else
        {
            memcpy(ITEM_data(new_it), ITEM_data(old_it), old_it->nbytes);
            memcpy(ITEM_data(new_it) + old_it->nbytes - 2 /* CRLF */, ITEM_data(add_it), add_it->nbytes);
        }
    }
    else
    {
        /* NREAD_PREPEND */
        if (new_it->it_flags & ITEM_CHUNKED)
        {
            if (_store_item_copy_chunks(new_it, add_it, add_it->nbytes - 2) == -1 ||
                _store_item_copy_chunks(new_it, old_it, old_it->nbytes) == -1)
            {
                return -1;
            }
        }
        else
        {
            memcpy(ITEM_data(new_it), ITEM_data(add_it), add_it->nbytes);
            memcpy(ITEM_data(new_it) + add_it->nbytes - 2 /* CRLF */, ITEM_data(old_it), old_it->nbytes);
        }
    }
    return 0;
}

/*
 * Stores an item in the cache according to the semantics of one of the set
 * commands. Protected by the item lock.
 *
 * Returns the state of storage.
 */
enum store_item_type do_store_item(item *it, int comm, conn *c, const uint32_t hv)
{
    log_routine(__func__);
    char *key = ITEM_key(it);
    item *old_it = do_item_get(key, it->nkey, hv, c, DONT_UPDATE);
    enum store_item_type stored = NOT_STORED;

    enum cas_result
    {
        CAS_NONE,
        CAS_MATCH,
        CAS_BADVAL,
        CAS_STALE,
        CAS_MISS
    };

    item *new_it = NULL;
    uint32_t flags;

    /* Do the CAS test up front so we can apply to all store modes */
    enum cas_result cas_res = CAS_NONE;

    bool do_store = false;
    if (old_it != NULL)
    {
        // Most of the CAS work requires something to compare to.
        uint64_t it_cas = ITEM_get_cas(it);
        uint64_t old_cas = ITEM_get_cas(old_it);
        if (it_cas == 0)
        {
            cas_res = CAS_NONE;
        }
        else if (it_cas == old_cas)
        {
            cas_res = CAS_MATCH;
        }
        else if (c->set_stale && it_cas < old_cas)
        {
            cas_res = CAS_STALE;
        }
        else
        {
            cas_res = CAS_BADVAL;
        }

        switch (comm)
        {
        case NREAD_ADD:
            /* add only adds a nonexistent item, but promote to head of LRU */
            do_item_update(old_it);
            break;
        case NREAD_CAS:
            if (cas_res == CAS_MATCH)
            {
                // cas validates
                // it and old_it may belong to different classes.
                // I'm updating the stats for the one that's getting pushed out
                pthread_mutex_lock(&c->thread->stats.mutex);
                c->thread->stats.slab_stats[ITEM_clsid(old_it)].cas_hits++;
                pthread_mutex_unlock(&c->thread->stats.mutex);
                do_store = true;
            }
            else if (cas_res == CAS_STALE)
            {
                // if we're allowed to set a stale value, CAS must be lower than
                // the current item's CAS.
                // This replaces the value, but should preserve TTL, and stale
                // item marker bit + token sent if exists.
                it->exptime = old_it->exptime;
                it->it_flags |= ITEM_STALE;
                if (old_it->it_flags & ITEM_TOKEN_SENT)
                {
                    it->it_flags |= ITEM_TOKEN_SENT;
                }

                pthread_mutex_lock(&c->thread->stats.mutex);
                c->thread->stats.slab_stats[ITEM_clsid(old_it)].cas_hits++;
                pthread_mutex_unlock(&c->thread->stats.mutex);
                do_store = true;
            }
            else
            {
                // NONE or BADVAL are the same for CAS cmd
                pthread_mutex_lock(&c->thread->stats.mutex);
                c->thread->stats.slab_stats[ITEM_clsid(old_it)].cas_badval++;
                pthread_mutex_unlock(&c->thread->stats.mutex);

                if (settings.verbose > 1)
                {
                    fprintf(stderr, "CAS:  failure: expected %llu, got %llu\n",
                            (unsigned long long)ITEM_get_cas(old_it),
                            (unsigned long long)ITEM_get_cas(it));
                }
                stored = EXISTS;
            }
            break;
        case NREAD_APPEND:
        case NREAD_PREPEND:
            if (cas_res != CAS_NONE && cas_res != CAS_MATCH)
            {
                stored = EXISTS;
                break;
            }
#ifdef EXTSTORE
            if ((old_it->it_flags & ITEM_HDR) != 0)
            {
                /* block append/prepend from working with extstore-d items.
                     * leave response code to NOT_STORED default */
                break;
            }
#endif
            /* we have it and old_it here - alloc memory to hold both */
            FLAGS_CONV(old_it, flags);
            new_it = do_item_alloc(key, it->nkey, flags, old_it->exptime, it->nbytes + old_it->nbytes - 2 /* CRLF */);

            // OOM trying to copy.
            if (new_it == NULL)
                break;
            /* copy data from it and old_it to new_it */
            if (_store_item_copy_data(comm, old_it, new_it, it) == -1)
            {
                // failed data copy
                break;
            }
            else
            {
                // refcount of new_it is 1 here. will end up 2 after link.
                // it's original ref is managed outside of this function
                it = new_it;
                do_store = true;
            }
            break;
        case NREAD_REPLACE:
        case NREAD_SET:
            do_store = true;
            break;
        }

        if (do_store)
        {
            STORAGE_delete(c->thread->storage, old_it);
            item_replace(old_it, it, hv);
            stored = STORED;
        }

        do_item_remove(old_it); /* release our reference */
        if (new_it != NULL)
        {
            // append/prepend end up with an extra reference for new_it.
            do_item_remove(new_it);
        }
    }
    else
    {
        /* No pre-existing item to replace or compare to. */
        if (ITEM_get_cas(it) != 0)
        {
            /* Asked for a CAS match but nothing to compare it to. */
            cas_res = CAS_MISS;
        }

        switch (comm)
        {
        case NREAD_ADD:
        case NREAD_SET:
            do_store = true;
            break;
        case NREAD_CAS:
            // LRU expired
            stored = NOT_FOUND;
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.cas_misses++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
            break;
        case NREAD_REPLACE:
        case NREAD_APPEND:
        case NREAD_PREPEND:
            /* Requires an existing item. */
            break;
        }

        if (do_store)
        {
            do_item_link(it, hv);
            stored = STORED;
        }
    }

    if (stored == STORED)
    {
        c->cas = ITEM_get_cas(it);
    }
    LOGGER_LOG(c->thread->l, LOG_MUTATIONS, LOGGER_ITEM_STORE, NULL,
               stored, comm, ITEM_key(it), it->nkey, it->exptime, ITEM_clsid(it), c->sfd);

    return stored;
}

/* set up a connection to write a buffer then free it, used for stats */
void write_and_free(conn *c, char *buf, int bytes)
{
    log_routine(__func__);
    if (buf)
    {
        mc_resp *resp = c->resp;
        resp->write_and_free = buf;
        resp_add_iov(resp, buf, bytes);
        conn_set_state(c, conn_new_cmd);
    }
    else
    {
        out_of_memory(c, "SERVER_ERROR out of memory writing stats");
    }
}

void append_stat(const char *name, ADD_STAT add_stats, conn *c,
                 const char *fmt, ...)
{
    log_routine(__func__);
    char val_str[STAT_VAL_LEN];
    int vlen;
    va_list ap;

    assert(name);
    assert(add_stats);
    assert(c);
    assert(fmt);

    va_start(ap, fmt);
    vlen = vsnprintf(val_str, sizeof(val_str) - 1, fmt, ap);
    va_end(ap);

    add_stats(name, strlen(name), val_str, vlen, c);
}

/* return server specific stats only */
void server_stats(ADD_STAT add_stats, conn *c)
{
    log_routine(__func__);
    pid_t pid = getpid();
    rel_time_t now = current_time;

    struct thread_stats thread_stats;
    threadlocal_stats_aggregate(&thread_stats);
    struct slab_stats slab_stats;
    slab_stats_aggregate(&thread_stats, &slab_stats);
#ifndef WIN32
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
#endif /* !WIN32 */

    STATS_LOCK();

    APPEND_STAT("pid", "%lu", (long)pid);
    APPEND_STAT("uptime", "%u", now - ITEM_UPDATE_INTERVAL);
    APPEND_STAT("time", "%ld", now + (long)process_started);
    APPEND_STAT("version", "%s", VERSION);
    APPEND_STAT("libevent", "%s", event_get_version());
    APPEND_STAT("pointer_size", "%d", (int)(8 * sizeof(void *)));

#ifndef WIN32
    append_stat("rusage_user", add_stats, c, "%ld.%06ld",
                (long)usage.ru_utime.tv_sec,
                (long)usage.ru_utime.tv_usec);
    append_stat("rusage_system", add_stats, c, "%ld.%06ld",
                (long)usage.ru_stime.tv_sec,
                (long)usage.ru_stime.tv_usec);
#endif /* !WIN32 */

    APPEND_STAT("max_connections", "%d", settings.maxconns);
    APPEND_STAT("curr_connections", "%llu", (unsigned long long)stats_state.curr_conns - 1);
    APPEND_STAT("total_connections", "%llu", (unsigned long long)stats.total_conns);
    if (settings.maxconns_fast)
    {
        APPEND_STAT("rejected_connections", "%llu", (unsigned long long)stats.rejected_conns);
    }
    APPEND_STAT("connection_structures", "%u", stats_state.conn_structs);
    APPEND_STAT("response_obj_oom", "%llu", (unsigned long long)thread_stats.response_obj_oom);
    APPEND_STAT("response_obj_count", "%llu", (unsigned long long)thread_stats.response_obj_count);
    APPEND_STAT("response_obj_bytes", "%llu", (unsigned long long)thread_stats.response_obj_bytes);
    APPEND_STAT("read_buf_count", "%llu", (unsigned long long)thread_stats.read_buf_count);
    APPEND_STAT("read_buf_bytes", "%llu", (unsigned long long)thread_stats.read_buf_bytes);
    APPEND_STAT("read_buf_bytes_free", "%llu", (unsigned long long)thread_stats.read_buf_bytes_free);
    APPEND_STAT("read_buf_oom", "%llu", (unsigned long long)thread_stats.read_buf_oom);
    APPEND_STAT("reserved_fds", "%u", stats_state.reserved_fds);
    APPEND_STAT("cmd_get", "%llu", (unsigned long long)thread_stats.get_cmds);
    APPEND_STAT("cmd_set", "%llu", (unsigned long long)slab_stats.set_cmds);
    APPEND_STAT("cmd_flush", "%llu", (unsigned long long)thread_stats.flush_cmds);
    APPEND_STAT("cmd_touch", "%llu", (unsigned long long)thread_stats.touch_cmds);
    APPEND_STAT("cmd_meta", "%llu", (unsigned long long)thread_stats.meta_cmds);
    APPEND_STAT("get_hits", "%llu", (unsigned long long)slab_stats.get_hits);
    APPEND_STAT("get_misses", "%llu", (unsigned long long)thread_stats.get_misses);
    APPEND_STAT("get_expired", "%llu", (unsigned long long)thread_stats.get_expired);
    APPEND_STAT("get_flushed", "%llu", (unsigned long long)thread_stats.get_flushed);
#ifdef EXTSTORE
    if (c->thread->storage)
    {
        APPEND_STAT("get_extstore", "%llu", (unsigned long long)thread_stats.get_extstore);
        APPEND_STAT("get_aborted_extstore", "%llu", (unsigned long long)thread_stats.get_aborted_extstore);
        APPEND_STAT("get_oom_extstore", "%llu", (unsigned long long)thread_stats.get_oom_extstore);
        APPEND_STAT("recache_from_extstore", "%llu", (unsigned long long)thread_stats.recache_from_extstore);
        APPEND_STAT("miss_from_extstore", "%llu", (unsigned long long)thread_stats.miss_from_extstore);
        APPEND_STAT("badcrc_from_extstore", "%llu", (unsigned long long)thread_stats.badcrc_from_extstore);
    }
#endif
    APPEND_STAT("delete_misses", "%llu", (unsigned long long)thread_stats.delete_misses);
    APPEND_STAT("delete_hits", "%llu", (unsigned long long)slab_stats.delete_hits);
    APPEND_STAT("incr_misses", "%llu", (unsigned long long)thread_stats.incr_misses);
    APPEND_STAT("incr_hits", "%llu", (unsigned long long)slab_stats.incr_hits);
    APPEND_STAT("decr_misses", "%llu", (unsigned long long)thread_stats.decr_misses);
    APPEND_STAT("decr_hits", "%llu", (unsigned long long)slab_stats.decr_hits);
    APPEND_STAT("cas_misses", "%llu", (unsigned long long)thread_stats.cas_misses);
    APPEND_STAT("cas_hits", "%llu", (unsigned long long)slab_stats.cas_hits);
    APPEND_STAT("cas_badval", "%llu", (unsigned long long)slab_stats.cas_badval);
    APPEND_STAT("touch_hits", "%llu", (unsigned long long)slab_stats.touch_hits);
    APPEND_STAT("touch_misses", "%llu", (unsigned long long)thread_stats.touch_misses);
    APPEND_STAT("auth_cmds", "%llu", (unsigned long long)thread_stats.auth_cmds);
    APPEND_STAT("auth_errors", "%llu", (unsigned long long)thread_stats.auth_errors);
    if (settings.idle_timeout)
    {
        APPEND_STAT("idle_kicks", "%llu", (unsigned long long)thread_stats.idle_kicks);
    }
    APPEND_STAT("bytes_read", "%llu", (unsigned long long)thread_stats.bytes_read);
    APPEND_STAT("bytes_written", "%llu", (unsigned long long)thread_stats.bytes_written);
    APPEND_STAT("limit_maxbytes", "%llu", (unsigned long long)settings.maxbytes);
    APPEND_STAT("accepting_conns", "%u", stats_state.accepting_conns);
    APPEND_STAT("listen_disabled_num", "%llu", (unsigned long long)stats.listen_disabled_num);
    APPEND_STAT("time_in_listen_disabled_us", "%llu", stats.time_in_listen_disabled_us);
    APPEND_STAT("threads", "%d", settings.num_threads);
    APPEND_STAT("conn_yields", "%llu", (unsigned long long)thread_stats.conn_yields);
    APPEND_STAT("hash_power_level", "%u", stats_state.hash_power_level);
    APPEND_STAT("hash_bytes", "%llu", (unsigned long long)stats_state.hash_bytes);
    APPEND_STAT("hash_is_expanding", "%u", stats_state.hash_is_expanding);
    if (settings.slab_reassign)
    {
        APPEND_STAT("slab_reassign_rescues", "%llu", stats.slab_reassign_rescues);
        APPEND_STAT("slab_reassign_chunk_rescues", "%llu", stats.slab_reassign_chunk_rescues);
        APPEND_STAT("slab_reassign_evictions_nomem", "%llu", stats.slab_reassign_evictions_nomem);
        APPEND_STAT("slab_reassign_inline_reclaim", "%llu", stats.slab_reassign_inline_reclaim);
        APPEND_STAT("slab_reassign_busy_items", "%llu", stats.slab_reassign_busy_items);
        APPEND_STAT("slab_reassign_busy_deletes", "%llu", stats.slab_reassign_busy_deletes);
        APPEND_STAT("slab_reassign_running", "%u", stats_state.slab_reassign_running);
        APPEND_STAT("slabs_moved", "%llu", stats.slabs_moved);
    }
    if (settings.lru_crawler)
    {
        APPEND_STAT("lru_crawler_running", "%u", stats_state.lru_crawler_running);
        APPEND_STAT("lru_crawler_starts", "%u", stats.lru_crawler_starts);
    }
    if (settings.lru_maintainer_thread)
    {
        APPEND_STAT("lru_maintainer_juggles", "%llu", (unsigned long long)stats.lru_maintainer_juggles);
    }
    APPEND_STAT("malloc_fails", "%llu",
                (unsigned long long)stats.malloc_fails);
    APPEND_STAT("log_worker_dropped", "%llu", (unsigned long long)stats.log_worker_dropped);
    APPEND_STAT("log_worker_written", "%llu", (unsigned long long)stats.log_worker_written);
    APPEND_STAT("log_watcher_skipped", "%llu", (unsigned long long)stats.log_watcher_skipped);
    APPEND_STAT("log_watcher_sent", "%llu", (unsigned long long)stats.log_watcher_sent);
    STATS_UNLOCK();
#ifdef EXTSTORE
    storage_stats(add_stats, c);
#endif
#ifdef TLS
    if (settings.ssl_enabled)
    {
        if (settings.ssl_session_cache)
        {
            APPEND_STAT("ssl_new_sessions", "%llu", (unsigned long long)stats.ssl_new_sessions);
        }
        APPEND_STAT("ssl_handshake_errors", "%llu", (unsigned long long)stats.ssl_handshake_errors);
        APPEND_STAT("time_since_server_cert_refresh", "%u", now - settings.ssl_last_cert_refresh_time);
    }
#endif
    APPEND_STAT("unexpected_napi_ids", "%llu", (unsigned long long)stats.unexpected_napi_ids);
    APPEND_STAT("round_robin_fallback", "%llu", (unsigned long long)stats.round_robin_fallback);
}

void process_stat_settings(ADD_STAT add_stats, void *c)
{
    assert(add_stats);
    APPEND_STAT("maxbytes", "%llu", (unsigned long long)settings.maxbytes);
    APPEND_STAT("maxconns", "%d", settings.maxconns);
    APPEND_STAT("tcpport", "%d", settings.port);
    APPEND_STAT("udpport", "%d", settings.udpport);
    APPEND_STAT("inter", "%s", settings.inter ? settings.inter : "NULL");
    APPEND_STAT("verbosity", "%d", settings.verbose);
    APPEND_STAT("oldest", "%lu", (unsigned long)settings.oldest_live);
    APPEND_STAT("evictions", "%s", settings.evict_to_free ? "on" : "off");
    APPEND_STAT("domain_socket", "%s",
                settings.socketpath ? settings.socketpath : "NULL");
    APPEND_STAT("umask", "%o", settings.access);
    APPEND_STAT("shutdown_command", "%s",
                settings.shutdown_command ? "yes" : "no");
    APPEND_STAT("growth_factor", "%.2f", settings.factor);
    APPEND_STAT("chunk_size", "%d", settings.chunk_size);
    APPEND_STAT("num_threads", "%d", settings.num_threads);
    APPEND_STAT("num_threads_per_udp", "%d", settings.num_threads_per_udp);
    APPEND_STAT("stat_key_prefix", "%c", settings.prefix_delimiter);
    APPEND_STAT("detail_enabled", "%s",
                settings.detail_enabled ? "yes" : "no");
    APPEND_STAT("reqs_per_event", "%d", settings.reqs_per_event);
    APPEND_STAT("cas_enabled", "%s", settings.use_cas ? "yes" : "no");
    APPEND_STAT("tcp_backlog", "%d", settings.backlog);
    APPEND_STAT("binding_protocol", "%s",
                prot_text(settings.binding_protocol));
    APPEND_STAT("auth_enabled_sasl", "%s", settings.sasl ? "yes" : "no");
    APPEND_STAT("auth_enabled_ascii", "%s", settings.auth_file ? settings.auth_file : "no");
    APPEND_STAT("item_size_max", "%d", settings.item_size_max);
    APPEND_STAT("maxconns_fast", "%s", settings.maxconns_fast ? "yes" : "no");
    APPEND_STAT("hashpower_init", "%d", settings.hashpower_init);
    APPEND_STAT("slab_reassign", "%s", settings.slab_reassign ? "yes" : "no");
    APPEND_STAT("slab_automove", "%d", settings.slab_automove);
    APPEND_STAT("slab_automove_ratio", "%.2f", settings.slab_automove_ratio);
    APPEND_STAT("slab_automove_window", "%u", settings.slab_automove_window);
    APPEND_STAT("slab_chunk_max", "%d", settings.slab_chunk_size_max);
    APPEND_STAT("lru_crawler", "%s", settings.lru_crawler ? "yes" : "no");
    APPEND_STAT("lru_crawler_sleep", "%d", settings.lru_crawler_sleep);
    APPEND_STAT("lru_crawler_tocrawl", "%lu", (unsigned long)settings.lru_crawler_tocrawl);
    APPEND_STAT("tail_repair_time", "%d", settings.tail_repair_time);
    APPEND_STAT("flush_enabled", "%s", settings.flush_enabled ? "yes" : "no");
    APPEND_STAT("dump_enabled", "%s", settings.dump_enabled ? "yes" : "no");
    APPEND_STAT("hash_algorithm", "%s", settings.hash_algorithm);
    APPEND_STAT("lru_maintainer_thread", "%s", settings.lru_maintainer_thread ? "yes" : "no");
    APPEND_STAT("lru_segmented", "%s", settings.lru_segmented ? "yes" : "no");
    APPEND_STAT("hot_lru_pct", "%d", settings.hot_lru_pct);
    APPEND_STAT("warm_lru_pct", "%d", settings.warm_lru_pct);
    APPEND_STAT("hot_max_factor", "%.2f", settings.hot_max_factor);
    APPEND_STAT("warm_max_factor", "%.2f", settings.warm_max_factor);
    APPEND_STAT("temp_lru", "%s", settings.temp_lru ? "yes" : "no");
    APPEND_STAT("temporary_ttl", "%u", settings.temporary_ttl);
    APPEND_STAT("idle_timeout", "%d", settings.idle_timeout);
    APPEND_STAT("watcher_logbuf_size", "%u", settings.logger_watcher_buf_size);
    APPEND_STAT("worker_logbuf_size", "%u", settings.logger_buf_size);
    APPEND_STAT("read_buf_mem_limit", "%u", settings.read_buf_mem_limit);
    APPEND_STAT("track_sizes", "%s", item_stats_sizes_status() ? "yes" : "no");
    APPEND_STAT("inline_ascii_response", "%s", "no"); // setting is dead, cannot be yes.
#ifdef HAVE_DROP_PRIVILEGES
    APPEND_STAT("drop_privileges", "%s", settings.drop_privileges ? "yes" : "no");
#endif
#ifdef EXTSTORE
    APPEND_STAT("ext_item_size", "%u", settings.ext_item_size);
    APPEND_STAT("ext_item_age", "%u", settings.ext_item_age);
    APPEND_STAT("ext_low_ttl", "%u", settings.ext_low_ttl);
    APPEND_STAT("ext_recache_rate", "%u", settings.ext_recache_rate);
    APPEND_STAT("ext_wbuf_size", "%u", settings.ext_wbuf_size);
    APPEND_STAT("ext_compact_under", "%u", settings.ext_compact_under);
    APPEND_STAT("ext_drop_under", "%u", settings.ext_drop_under);
    APPEND_STAT("ext_max_frag", "%.2f", settings.ext_max_frag);
    APPEND_STAT("slab_automove_freeratio", "%.3f", settings.slab_automove_freeratio);
    APPEND_STAT("ext_drop_unread", "%s", settings.ext_drop_unread ? "yes" : "no");
#endif
#ifdef TLS
    APPEND_STAT("ssl_enabled", "%s", settings.ssl_enabled ? "yes" : "no");
    APPEND_STAT("ssl_chain_cert", "%s", settings.ssl_chain_cert);
    APPEND_STAT("ssl_key", "%s", settings.ssl_key);
    APPEND_STAT("ssl_verify_mode", "%d", settings.ssl_verify_mode);
    APPEND_STAT("ssl_keyformat", "%d", settings.ssl_keyformat);
    APPEND_STAT("ssl_ciphers", "%s", settings.ssl_ciphers ? settings.ssl_ciphers : "NULL");
    APPEND_STAT("ssl_ca_cert", "%s", settings.ssl_ca_cert ? settings.ssl_ca_cert : "NULL");
    APPEND_STAT("ssl_wbuf_size", "%u", settings.ssl_wbuf_size);
    APPEND_STAT("ssl_session_cache", "%s", settings.ssl_session_cache ? "yes" : "no");
#endif
    APPEND_STAT("num_napi_ids", "%s", settings.num_napi_ids);
    APPEND_STAT("memory_file", "%s", settings.memory_file);
}

static int nz_strcmp(int nzlength, const char *nz, const char *z)
{
    int zlength = strlen(z);
    return (zlength == nzlength) && (strncmp(nz, z, zlength) == 0) ? 0 : -1;
}

bool get_stats(const char *stat_type, int nkey, ADD_STAT add_stats, void *c)
{
    log_routine(__func__);
    bool ret = true;

    if (add_stats != NULL)
    {
        if (!stat_type)
        {
            /* prepare general statistics for the engine */
            STATS_LOCK();
            APPEND_STAT("bytes", "%llu", (unsigned long long)stats_state.curr_bytes);
            APPEND_STAT("curr_items", "%llu", (unsigned long long)stats_state.curr_items);
            APPEND_STAT("total_items", "%llu", (unsigned long long)stats.total_items);
            STATS_UNLOCK();
            APPEND_STAT("slab_global_page_pool", "%u", global_page_pool_size(NULL));
            item_stats_totals(add_stats, c);
        }
        else if (nz_strcmp(nkey, stat_type, "items") == 0)
        {
            item_stats(add_stats, c);
        }
        else if (nz_strcmp(nkey, stat_type, "slabs") == 0)
        {
            slabs_stats(add_stats, c);
        }
        else if (nz_strcmp(nkey, stat_type, "sizes") == 0)
        {
            item_stats_sizes(add_stats, c);
        }
        else if (nz_strcmp(nkey, stat_type, "sizes_enable") == 0)
        {
            item_stats_sizes_enable(add_stats, c);
        }
        else if (nz_strcmp(nkey, stat_type, "sizes_disable") == 0)
        {
            item_stats_sizes_disable(add_stats, c);
        }
        else
        {
            ret = false;
        }
    }
    else
    {
        ret = false;
    }

    return ret;
}

static inline void get_conn_text(const conn *c, const int af,
                                 char *addr, struct sockaddr *sock_addr)
{
    log_routine(__func__);
    char addr_text[MAXPATHLEN];
    addr_text[0] = '\0';
    const char *protoname = "?";
    unsigned short port = 0;

    switch (af)
    {
    case AF_INET:
        (void)inet_ntop(af,
                        &((struct sockaddr_in *)sock_addr)->sin_addr,
                        addr_text,
                        sizeof(addr_text) - 1);
        port = ntohs(((struct sockaddr_in *)sock_addr)->sin_port);
        protoname = IS_UDP(c->transport) ? "udp" : "tcp";
        break;

    case AF_INET6:
        addr_text[0] = '[';
        addr_text[1] = '\0';
        if (inet_ntop(af,
                      &((struct sockaddr_in6 *)sock_addr)->sin6_addr,
                      addr_text + 1,
                      sizeof(addr_text) - 2))
        {
            strcat(addr_text, "]");
        }
        port = ntohs(((struct sockaddr_in6 *)sock_addr)->sin6_port);
        protoname = IS_UDP(c->transport) ? "udp6" : "tcp6";
        break;

#ifndef DISABLE_UNIX_SOCKET
    case AF_UNIX:
    {
        size_t pathlen = 0;
        // this strncpy call originally could piss off an address
        // sanitizer; we supplied the size of the dest buf as a limiter,
        // but optimized versions of strncpy could read past the end of
        // *src while looking for a null terminator. Since buf and
        // sun_path here are both on the stack they could even overlap,
        // which is "undefined". In all OSS versions of strncpy I could
        // find this has no effect; it'll still only copy until the first null
        // terminator is found. Thus it's possible to get the OS to
        // examine past the end of sun_path but it's unclear to me if this
        // can cause any actual problem.
        //
        // We need a safe_strncpy util function but I'll punt on figuring
        // that out for now.
        pathlen = sizeof(((struct sockaddr_un *)sock_addr)->sun_path);
        if (MAXPATHLEN <= pathlen)
        {
            pathlen = MAXPATHLEN - 1;
        }
        strncpy(addr_text,
                ((struct sockaddr_un *)sock_addr)->sun_path,
                pathlen);
        addr_text[pathlen] = '\0';
        protoname = "unix";
    }
    break;
#endif /* #ifndef DISABLE_UNIX_SOCKET */
    }

    if (strlen(addr_text) < 2)
    {
        /* Most likely this is a connected UNIX-domain client which
         * has no peer socket address, but there's no portable way
         * to tell for sure.
         */
        sprintf(addr_text, "<AF %d>", af);
    }

    if (port)
    {
        sprintf(addr, "%s:%s:%u", protoname, addr_text, port);
    }
    else
    {
        sprintf(addr, "%s:%s", protoname, addr_text);
    }
}

static void conn_to_str(const conn *c, char *addr, char *svr_addr)
{
    log_routine(__func__);
    if (!c)
    {
        strcpy(addr, "<null>");
    }
    else if (c->state == conn_closed)
    {
        strcpy(addr, "<closed>");
    }
    else
    {
        struct sockaddr_in6 local_addr;
        struct sockaddr *sock_addr = (void *)&c->request_addr;

        /* For listen ports and idle UDP ports, show listen address */
        if (c->state == conn_listening ||
            (IS_UDP(c->transport) &&
             c->state == conn_read))
        {
            socklen_t local_addr_len = sizeof(local_addr);

            if (getsockname(c->sfd,
                            (struct sockaddr *)&local_addr,
                            &local_addr_len) == 0)
            {
                sock_addr = (struct sockaddr *)&local_addr;
            }
        }
        get_conn_text(c, sock_addr->sa_family, addr, sock_addr);

        if (c->state != conn_listening && !(IS_UDP(c->transport) &&
                                            c->state == conn_read))
        {
            struct sockaddr_storage svr_sock_addr;
            socklen_t svr_addr_len = sizeof(svr_sock_addr);
            getsockname(c->sfd, (struct sockaddr *)&svr_sock_addr, &svr_addr_len);
            get_conn_text(c, svr_sock_addr.ss_family, svr_addr, (struct sockaddr *)&svr_sock_addr);
        }
    }
}

void process_stats_conns(ADD_STAT add_stats, void *c)
{
    log_routine(__func__);
    int i;
    char key_str[STAT_KEY_LEN];
    char val_str[STAT_VAL_LEN];
    size_t extras_len = sizeof("unix:") + sizeof("65535");
    char addr[MAXPATHLEN + extras_len];
    char svr_addr[MAXPATHLEN + extras_len];
    int klen = 0, vlen = 0;

    assert(add_stats);

    for (i = 0; i < max_fds; i++)
    {
        if (conns[i])
        {
            /* This is safe to do unlocked because conns are never freed; the
             * worst that'll happen will be a minor inconsistency in the
             * output -- not worth the complexity of the locking that'd be
             * required to prevent it.
             */
            if (IS_UDP(conns[i]->transport))
            {
                APPEND_NUM_STAT(i, "UDP", "%s", "UDP");
            }
            if (conns[i]->state != conn_closed)
            {
                conn_to_str(conns[i], addr, svr_addr);

                APPEND_NUM_STAT(i, "addr", "%s", addr);
                if (conns[i]->state != conn_listening &&
                    !(IS_UDP(conns[i]->transport) && conns[i]->state == conn_read))
                {
                    APPEND_NUM_STAT(i, "listen_addr", "%s", svr_addr);
                }
                APPEND_NUM_STAT(i, "state", "%s",
                                state_text(conns[i]->state));
                APPEND_NUM_STAT(i, "secs_since_last_cmd", "%d",
                                current_time - conns[i]->last_cmd_time);
            }
        }
    }
}

#define IT_REFCOUNT_LIMIT 60000
item *limited_get(char *key, size_t nkey, conn *c, uint32_t exptime, bool should_touch, bool do_update, bool *overflow)
{
    log_routine(__func__);
    item *it;
    if (should_touch)
    {
        it = item_touch(key, nkey, exptime, c);
    }
    else
    {
        it = item_get(key, nkey, c, do_update);
    }
    if (it && it->refcount > IT_REFCOUNT_LIMIT)
    {
        item_remove(it);
        it = NULL;
        *overflow = true;
    }
    else
    {
        *overflow = false;
    }
    return it;
}

// Semantics are different than limited_get; since the item is returned
// locked, caller can directly change what it needs.
// though it might eventually be a better interface to sink it all into
// items.c.
item *limited_get_locked(char *key, size_t nkey, conn *c, bool do_update, uint32_t *hv, bool *overflow)
{
    log_routine(__func__);
    item *it;
    it = item_get_locked(key, nkey, c, do_update, hv);
    if (it && it->refcount > IT_REFCOUNT_LIMIT)
    {
        do_item_remove(it);
        it = NULL;
        item_unlock(*hv);
        *overflow = true;
    }
    else
    {
        *overflow = false;
    }
    return it;
}

/*
 * adds a delta value to a numeric item.
 *
 * c     connection requesting the operation
 * it    item to adjust
 * incr  true to increment value, false to decrement
 * delta amount to adjust value by
 * buf   buffer for response string
 *
 * returns a response string to send back to the client.
 */
enum delta_result_type do_add_delta(conn *c, const char *key, const size_t nkey,
                                    const bool incr, const int64_t delta,
                                    char *buf, uint64_t *cas,
                                    const uint32_t hv,
                                    item **it_ret)
{
    log_routine(__func__);
    char *ptr;
    uint64_t value;
    int res;
    item *it;

    it = do_item_get(key, nkey, hv, c, DONT_UPDATE);
    if (!it)
    {
        return DELTA_ITEM_NOT_FOUND;
    }

    /* Can't delta zero byte values. 2-byte are the "\r\n" */
    /* Also can't delta for chunked items. Too large to be a number */
#ifdef EXTSTORE
    if (it->nbytes <= 2 || (it->it_flags & (ITEM_CHUNKED | ITEM_HDR)) != 0)
    {
#else
    if (it->nbytes <= 2 || (it->it_flags & (ITEM_CHUNKED)) != 0)
    {
#endif
        do_item_remove(it);
        return NON_NUMERIC;
    }

    if (cas != NULL && *cas != 0 && ITEM_get_cas(it) != *cas)
    {
        do_item_remove(it);
        return DELTA_ITEM_CAS_MISMATCH;
    }

    ptr = ITEM_data(it);

    if (!safe_strtoull(ptr, &value))
    {
        do_item_remove(it);
        return NON_NUMERIC;
    }

    if (incr)
    {
        value += delta;
        MEMCACHED_COMMAND_INCR(c->sfd, ITEM_key(it), it->nkey, value);
    }
    else
    {
        if (delta > value)
        {
            value = 0;
        }
        else
        {
            value -= delta;
        }
        MEMCACHED_COMMAND_DECR(c->sfd, ITEM_key(it), it->nkey, value);
    }

    pthread_mutex_lock(&c->thread->stats.mutex);
    if (incr)
    {
        c->thread->stats.slab_stats[ITEM_clsid(it)].incr_hits++;
    }
    else
    {
        c->thread->stats.slab_stats[ITEM_clsid(it)].decr_hits++;
    }
    pthread_mutex_unlock(&c->thread->stats.mutex);

    itoa_u64(value, buf);
    res = strlen(buf);
    /* refcount == 2 means we are the only ones holding the item, and it is
     * linked. We hold the item's lock in this function, so refcount cannot
     * increase. */
    if (res + 2 <= it->nbytes && it->refcount == 2)
    { /* replace in-place */
        /* When changing the value without replacing the item, we
           need to update the CAS on the existing item. */
        /* We also need to fiddle it in the sizes tracker in case the tracking
         * was enabled at runtime, since it relies on the CAS value to know
         * whether to remove an item or not. */
        item_stats_sizes_remove(it);
        ITEM_set_cas(it, (settings.use_cas) ? get_cas_id() : 0);
        item_stats_sizes_add(it);
        memcpy(ITEM_data(it), buf, res);
        memset(ITEM_data(it) + res, ' ', it->nbytes - res - 2);
        do_item_update(it);
    }
    else if (it->refcount > 1)
    {
        item *new_it;
        uint32_t flags;
        FLAGS_CONV(it, flags);
        new_it = do_item_alloc(ITEM_key(it), it->nkey, flags, it->exptime, res + 2);
        if (new_it == 0)
        {
            do_item_remove(it);
            return EOM;
        }
        memcpy(ITEM_data(new_it), buf, res);
        memcpy(ITEM_data(new_it) + res, "\r\n", 2);
        item_replace(it, new_it, hv);
        // Overwrite the older item's CAS with our new CAS since we're
        // returning the CAS of the old item below.
        ITEM_set_cas(it, (settings.use_cas) ? ITEM_get_cas(new_it) : 0);
        do_item_remove(new_it); /* release our reference */
    }
    else
    {
        /* Should never get here. This means we somehow fetched an unlinked
         * item. TODO: Add a counter? */
        if (settings.verbose)
        {
            fprintf(stderr, "Tried to do incr/decr on invalid item\n");
        }
        if (it->refcount == 1)
            do_item_remove(it);
        return DELTA_ITEM_NOT_FOUND;
    }

    if (cas)
    {
        *cas = ITEM_get_cas(it); /* swap the incoming CAS value */
    }
    if (it_ret != NULL)
    {
        *it_ret = it;
    }
    else
    {
        do_item_remove(it); /* release our reference */
    }
    return OK;
}

static int try_read_command_negotiate(conn *c)
{
    log_routine(__func__);
    assert(c->protocol == negotiating_prot);
    assert(c != NULL);
    assert(c->rcurr <= (c->rbuf + c->rsize));
    assert(c->rbytes > 0);

    if ((unsigned char)c->rbuf[0] == (unsigned char)PROTOCOL_BINARY_REQ)
    {
        c->protocol = binary_prot;
        c->try_read_command = try_read_command_binary;
    }
    else
    {
        // authentication doesn't work with negotiated protocol.
        c->protocol = ascii_prot;
        c->try_read_command = try_read_command_ascii;
    }

    if (settings.verbose > 1)
    {
        fprintf(stderr, "%d: Client using the %s protocol\n", c->sfd,
                prot_text(c->protocol));
    }

    return c->try_read_command(c);
}

static int try_read_command_udp(conn *c)
{
    log_routine(__func__);
    assert(c != NULL);
    assert(c->rcurr <= (c->rbuf + c->rsize));
    assert(c->rbytes > 0);

    if ((unsigned char)c->rbuf[0] == (unsigned char)PROTOCOL_BINARY_REQ)
    {
        c->protocol = binary_prot;
        return try_read_command_binary(c);
    }
    else
    {
        c->protocol = ascii_prot;
        return try_read_command_ascii(c);
    }
}

/*
 * read a UDP request.
 */
static enum try_read_result try_read_udp(conn *c)
{
    log_routine(__func__);
    int res;

    assert(c != NULL);

    c->request_addr_size = sizeof(c->request_addr);
    res = recvfrom(c->sfd, c->rbuf, c->rsize,
                   0, (struct sockaddr *)&c->request_addr,
                   &c->request_addr_size);
    if (res > 8)
    {
        unsigned char *buf = (unsigned char *)c->rbuf;
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.bytes_read += res;
        pthread_mutex_unlock(&c->thread->stats.mutex);

        /* Beginning of UDP packet is the request ID; save it. */
        c->request_id = buf[0] * 256 + buf[1];

        /* If this is a multi-packet request, drop it. */
        if (buf[4] != 0 || buf[5] != 1)
        {
            return READ_NO_DATA_RECEIVED;
        }

        /* Don't care about any of the rest of the header. */
        res -= 8;
        memmove(c->rbuf, c->rbuf + 8, res);

        c->rbytes = res;
        c->rcurr = c->rbuf;
        return READ_DATA_RECEIVED;
    }
    return READ_NO_DATA_RECEIVED;
}

/*
 * read from network as much as we can, handle buffer overflow and connection
 * close.
 * before reading, move the remaining incomplete fragment of a command
 * (if any) to the beginning of the buffer.
 *
 * To protect us from someone flooding a connection with bogus data causing
 * the connection to eat up all available memory, break out and start looking
 * at the data I've got after a number of reallocs...
 *
 * @return enum try_read_result
 */
static enum try_read_result try_read_network(conn *c)
{
    log_routine(__func__);
    enum try_read_result gotdata = READ_NO_DATA_RECEIVED;
    int res;
    int num_allocs = 0;
    assert(c != NULL);

    if (c->rcurr != c->rbuf)
    {
        if (c->rbytes != 0) /* otherwise there's nothing to copy */
            memmove(c->rbuf, c->rcurr, c->rbytes);
        c->rcurr = c->rbuf;
    }

    while (1)
    {
        // TODO: move to rbuf_* func?
        if (c->rbytes >= c->rsize && c->rbuf_malloced)
        {
            if (num_allocs == 4)
            {
                return gotdata;
            }
            ++num_allocs;
            char *new_rbuf = realloc(c->rbuf, c->rsize * 2);
            if (!new_rbuf)
            {
                STATS_LOCK();
                stats.malloc_fails++;
                STATS_UNLOCK();
                if (settings.verbose > 0)
                {
                    fprintf(stderr, "Couldn't realloc input buffer\n");
                }
                c->rbytes = 0; /* ignore what we read */
                out_of_memory(c, "SERVER_ERROR out of memory reading request");
                c->close_after_write = true;
                return READ_MEMORY_ERROR;
            }
            c->rcurr = c->rbuf = new_rbuf;
            c->rsize *= 2;
        }

        int avail = c->rsize - c->rbytes;
        res = c->read(c, c->rbuf + c->rbytes, avail);
        if (res > 0)
        {
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.bytes_read += res;
            pthread_mutex_unlock(&c->thread->stats.mutex);
            gotdata = READ_DATA_RECEIVED;
            c->rbytes += res;
            if (res == avail && c->rbuf_malloced)
            {
                // Resize rbuf and try a few times if huge ascii multiget.
                continue;
            }
            else
            {
                break;
            }
        }
        if (res == 0)
        {
            return READ_ERROR;
        }
        if (res == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                break;
            }
            return READ_ERROR;
        }
    }
    return gotdata;
}

static bool update_event(conn *c, const int new_flags)
{
    log_routine(__func__);
    assert(c != NULL);

    struct event_base *base = c->event.ev_base;
    if (c->ev_flags == new_flags)
        return true;
    if (event_del(&c->event) == -1)
        return false;
    event_set(&c->event, c->sfd, new_flags, event_handler, (void *)c);
    event_base_set(base, &c->event);
    c->ev_flags = new_flags;
    if (event_add(&c->event, 0) == -1)
        return false;
    return true;
}

/*
 * Sets whether we are listening for new connections or not.
 */
void do_accept_new_conns(const bool do_accept)
{
    log_routine(__func__);
    conn *next;

    for (next = listen_conn; next; next = next->next)
    {
        if (do_accept)
        {
            update_event(next, EV_READ | EV_PERSIST);
            if (listen(next->sfd, settings.backlog) != 0)
            {
                perror("listen");
            }
        }
        else
        {
            update_event(next, 0);
            if (listen(next->sfd, 0) != 0)
            {
                perror("listen");
            }
        }
    }

    if (do_accept)
    {
        struct timeval maxconns_exited;
        uint64_t elapsed_us;
        gettimeofday(&maxconns_exited, NULL);
        STATS_LOCK();
        elapsed_us =
            (maxconns_exited.tv_sec - stats.maxconns_entered.tv_sec) * 1000000 + (maxconns_exited.tv_usec - stats.maxconns_entered.tv_usec);
        stats.time_in_listen_disabled_us += elapsed_us;
        stats_state.accepting_conns = true;
        STATS_UNLOCK();
    }
    else
    {
        STATS_LOCK();
        stats_state.accepting_conns = false;
        gettimeofday(&stats.maxconns_entered, NULL);
        stats.listen_disabled_num++;
        STATS_UNLOCK();
        allow_new_conns = false;
        maxconns_handler(-42, 0, 0);
    }
}

#define TRANSMIT_ONE_RESP true
#define TRANSMIT_ALL_RESP false
static int _transmit_pre(conn *c, struct iovec *iovs, int iovused, bool one_resp)
{
    log_routine(__func__);
    mc_resp *resp = c->resp_head;
    while (resp && iovused + resp->iovcnt < IOV_MAX - 1)
    {
        if (resp->skip)
        {
            // Don't actually unchain the resp obj here since it's singly-linked.
            // Just let the post function handle it linearly.
            resp = resp->next;
            continue;
        }
        if (resp->chunked_data_iov)
        {
            // Handle chunked items specially.
            // They spend much more time in send so we can be a bit wasteful
            // in rebuilding iovecs for them.
            item_chunk *ch = (item_chunk *)ITEM_schunk((item *)resp->iov[resp->chunked_data_iov].iov_base);
            int x;
            for (x = 0; x < resp->iovcnt; x++)
            {
                // This iov is tracking how far we've copied so far.
                if (x == resp->chunked_data_iov)
                {
                    int done = resp->chunked_total - resp->iov[x].iov_len;
                    // Start from the len to allow binprot to cut the \r\n
                    int todo = resp->iov[x].iov_len;
                    while (ch && todo > 0 && iovused < IOV_MAX - 1)
                    {
                        int skip = 0;
                        if (!ch->used)
                        {
                            ch = ch->next;
                            continue;
                        }
                        // Skip parts we've already sent.
                        if (done >= ch->used)
                        {
                            done -= ch->used;
                            ch = ch->next;
                            continue;
                        }
                        else if (done)
                        {
                            skip = done;
                            done = 0;
                        }
                        iovs[iovused].iov_base = ch->data + skip;
                        // Stupid binary protocol makes this go negative.
                        iovs[iovused].iov_len = ch->used - skip > todo ? todo : ch->used - skip;
                        iovused++;
                        todo -= ch->used - skip;
                        ch = ch->next;
                    }
                }
                else
                {
                    iovs[iovused].iov_base = resp->iov[x].iov_base;
                    iovs[iovused].iov_len = resp->iov[x].iov_len;
                    iovused++;
                }
                if (iovused >= IOV_MAX - 1)
                    break;
            }
        }
        else
        {
            memcpy(&iovs[iovused], resp->iov, sizeof(struct iovec) * resp->iovcnt);
            iovused += resp->iovcnt;
        }

        // done looking at first response, walk down the chain.
        resp = resp->next;
        // used for UDP mode: UDP cannot send multiple responses per packet.
        if (one_resp)
            break;
    }
    return iovused;
}

/*
 * Decrements and completes responses based on how much data was transmitted.
 * Takes the connection and current result bytes.
 */
static void _transmit_post(conn *c, ssize_t res)
{
    log_routine(__func__);
    // We've written some of the data. Remove the completed
    // responses from the list of pending writes.
    mc_resp *resp = c->resp_head;
    while (resp)
    {
        int x;
        if (resp->skip)
        {
            resp = resp_finish(c, resp);
            continue;
        }

        // fastpath check. all small responses should cut here.
        if (res >= resp->tosend)
        {
            res -= resp->tosend;
            resp = resp_finish(c, resp);
            continue;
        }

        // it's fine to re-check iov's that were zeroed out before.
        for (x = 0; x < resp->iovcnt; x++)
        {
            struct iovec *iov = &resp->iov[x];
            if (res >= iov->iov_len)
            {
                resp->tosend -= iov->iov_len;
                res -= iov->iov_len;
                iov->iov_len = 0;
            }
            else
            {
                // Dumb special case for chunked items. Currently tracking
                // where to inject the chunked item via iov_base.
                // Extra not-great since chunked items can't be the first
                // index, so we have to check for non-zero c_d_iov first.
                if (!resp->chunked_data_iov || x != resp->chunked_data_iov)
                {
                    iov->iov_base = (char *)iov->iov_base + res;
                }
                iov->iov_len -= res;
                resp->tosend -= res;
                res = 0;
                break;
            }
        }

        // are we done with this response object?
        if (resp->tosend == 0)
        {
            resp = resp_finish(c, resp);
        }
        else
        {
            // Jammed up here. This is the new head.
            break;
        }
    }
}

/*
 * Transmit the next chunk of data from our list of msgbuf structures.
 *
 * Returns:
 *   TRANSMIT_COMPLETE   All done writing.
 *   TRANSMIT_INCOMPLETE More data remaining to write.
 *   TRANSMIT_SOFT_ERROR Can't write any more right now.
 *   TRANSMIT_HARD_ERROR Can't write (c->state is set to conn_closing)
 */
static enum transmit_result transmit(conn *c)
{
    log_routine(__func__);
    assert(c != NULL);
    struct iovec iovs[IOV_MAX];
    struct msghdr msg;
    int iovused = 0;

    // init the msg.
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_iov = iovs;

    iovused = _transmit_pre(c, iovs, iovused, TRANSMIT_ALL_RESP);
    if (iovused == 0)
    {
        // Avoid the syscall if we're only handling a noreply.
        // Return the response object.
        _transmit_post(c, 0);
        return TRANSMIT_COMPLETE;
    }

    // Alright, send.
    ssize_t res;
    msg.msg_iovlen = iovused;
    res = c->sendmsg(c, &msg, 0);
    if (res >= 0)
    {
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.bytes_written += res;
        pthread_mutex_unlock(&c->thread->stats.mutex);

        // Decrement any partial IOV's and complete any finished resp's.
        _transmit_post(c, res);

        if (c->resp_head)
        {
            return TRANSMIT_INCOMPLETE;
        }
        else
        {
            return TRANSMIT_COMPLETE;
        }
    }

    if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        if (!update_event(c, EV_WRITE | EV_PERSIST))
        {
            if (settings.verbose > 0)
                fprintf(stderr, "Couldn't update event\n");
            conn_set_state(c, conn_closing);
            return TRANSMIT_HARD_ERROR;
        }
        return TRANSMIT_SOFT_ERROR;
    }
    /* if res == -1 and error is not EAGAIN or EWOULDBLOCK,
       we have a real error, on which we close the connection */
    if (settings.verbose > 0)
        perror("Failed to write, and not due to blocking");

    conn_set_state(c, conn_closing);
    return TRANSMIT_HARD_ERROR;
}

static void build_udp_header(unsigned char *hdr, mc_resp *resp)
{
    log_routine(__func__);
    // We need to communicate the total number of packets
    // If this isn't set, it's the first time this response is building a udp
    // header, so "tosend" must be static.
    if (!resp->udp_total)
    {
        uint32_t total;
        total = resp->tosend / UDP_DATA_SIZE;
        if (resp->tosend % UDP_DATA_SIZE)
            total++;
        // The spec doesn't really say what we should do here. It's _probably_
        // better to bail out?
        if (total > USHRT_MAX)
        {
            total = USHRT_MAX;
        }
        resp->udp_total = total;
    }

    // TODO: why wasn't this hto*'s and casts?
    // this ends up sending UDP hdr data specifically in host byte order.
    *hdr++ = resp->request_id / 256;
    *hdr++ = resp->request_id % 256;
    *hdr++ = resp->udp_sequence / 256;
    *hdr++ = resp->udp_sequence % 256;
    *hdr++ = resp->udp_total / 256;
    *hdr++ = resp->udp_total % 256;
    *hdr++ = 0;
    *hdr++ = 0;
    resp->udp_sequence++;
}

/*
 * UDP specific transmit function. Uses its own function rather than check
 * IS_UDP() five times. If we ever implement sendmmsg or similar support they
 * will diverge even more.
 * Does not use TLS.
 *
 * Returns:
 *   TRANSMIT_COMPLETE   All done writing.
 *   TRANSMIT_INCOMPLETE More data remaining to write.
 *   TRANSMIT_SOFT_ERROR Can't write any more right now.
 *   TRANSMIT_HARD_ERROR Can't write (c->state is set to conn_closing)
 */
static enum transmit_result transmit_udp(conn *c)
{
    log_routine(__func__);
    assert(c != NULL);
    struct iovec iovs[IOV_MAX];
    struct msghdr msg;
    mc_resp *resp;
    int iovused = 0;
    unsigned char udp_hdr[UDP_HEADER_SIZE];

    // We only send one UDP packet per call (ugh), so we can only operate on a
    // single response at a time.
    resp = c->resp_head;

    if (!resp)
    {
        return TRANSMIT_COMPLETE;
    }

    if (resp->skip)
    {
        resp = resp_finish(c, resp);
        return TRANSMIT_INCOMPLETE;
    }

    // clear the message and initialize it.
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_iov = iovs;

    // the UDP source to return to.
    msg.msg_name = &resp->request_addr;
    msg.msg_namelen = resp->request_addr_size;

    // First IOV is the custom UDP header.
    iovs[0].iov_base = (void *)udp_hdr;
    iovs[0].iov_len = UDP_HEADER_SIZE;
    build_udp_header(udp_hdr, resp);
    iovused++;

    // Fill the IOV's the standard way.
    // TODO: might get a small speedup if we let it break early with a length
    // limit.
    iovused = _transmit_pre(c, iovs, iovused, TRANSMIT_ONE_RESP);

    // Clip the IOV's to the max UDP packet size.
    // If we add support for send_mmsg, this can be where we split msg's.
    {
        int x = 0;
        int len = 0;
        for (x = 0; x < iovused; x++)
        {
            if (len + iovs[x].iov_len >= UDP_MAX_PAYLOAD_SIZE)
            {
                iovs[x].iov_len = UDP_MAX_PAYLOAD_SIZE - len;
                x++;
                break;
            }
            else
            {
                len += iovs[x].iov_len;
            }
        }
        iovused = x;
    }

    ssize_t res;
    msg.msg_iovlen = iovused;
    // NOTE: uses system sendmsg since we have no support for indirect UDP.
    res = sendmsg(c->sfd, &msg, 0);
    if (res >= 0)
    {
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.bytes_written += res;
        pthread_mutex_unlock(&c->thread->stats.mutex);

        // Ignore the header size from forwarding the IOV's
        res -= UDP_HEADER_SIZE;

        // Decrement any partial IOV's and complete any finished resp's.
        _transmit_post(c, res);

        if (c->resp_head)
        {
            return TRANSMIT_INCOMPLETE;
        }
        else
        {
            return TRANSMIT_COMPLETE;
        }
    }

    if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        if (!update_event(c, EV_WRITE | EV_PERSIST))
        {
            if (settings.verbose > 0)
                fprintf(stderr, "Couldn't update event\n");
            conn_set_state(c, conn_closing);
            return TRANSMIT_HARD_ERROR;
        }
        return TRANSMIT_SOFT_ERROR;
    }
    /* if res == -1 and error is not EAGAIN or EWOULDBLOCK,
       we have a real error, on which we close the connection */
    if (settings.verbose > 0)
        perror("Failed to write, and not due to blocking");

    conn_set_state(c, conn_read);
    return TRANSMIT_HARD_ERROR;
}

/* Does a looped read to fill data chunks */
/* TODO: restrict number of times this can loop.
 * Also, benchmark using readv's.
 */
static int read_into_chunked_item(conn *c)
{
    log_routine(__func__);
    int total = 0;
    int res;
    assert(c->rcurr != c->ritem);

    while (c->rlbytes > 0)
    {
        item_chunk *ch = (item_chunk *)c->ritem;
        if (ch->size == ch->used)
        {
            // FIXME: ch->next is currently always 0. remove this?
            if (ch->next)
            {
                c->ritem = (char *)ch->next;
            }
            else
            {
                /* Allocate next chunk. Binary protocol needs 2b for \r\n */
                c->ritem = (char *)do_item_alloc_chunk(ch, c->rlbytes +
                                                               ((c->protocol == binary_prot) ? 2 : 0));
                if (!c->ritem)
                {
                    // We failed an allocation. Let caller handle cleanup.
                    total = -2;
                    break;
                }
                // ritem has new chunk, restart the loop.
                continue;
                //assert(c->rlbytes == 0);
            }
        }

        int unused = ch->size - ch->used;
        /* first check if we have leftovers in the conn_read buffer */
        if (c->rbytes > 0)
        {
            total = 0;
            int tocopy = c->rbytes > c->rlbytes ? c->rlbytes : c->rbytes;
            tocopy = tocopy > unused ? unused : tocopy;
            if (c->ritem != c->rcurr)
            {
                memmove(ch->data + ch->used, c->rcurr, tocopy);
            }
            total += tocopy;
            c->rlbytes -= tocopy;
            c->rcurr += tocopy;
            c->rbytes -= tocopy;
            ch->used += tocopy;
            if (c->rlbytes == 0)
            {
                break;
            }
        }
        else
        {
            /*  now try reading from the socket */
            res = c->read(c, ch->data + ch->used,
                          (unused > c->rlbytes ? c->rlbytes : unused));
            if (res > 0)
            {
                pthread_mutex_lock(&c->thread->stats.mutex);
                c->thread->stats.bytes_read += res;
                pthread_mutex_unlock(&c->thread->stats.mutex);
                ch->used += res;
                total += res;
                c->rlbytes -= res;
            }
            else
            {
                /* Reset total to the latest result so caller can handle it */
                total = res;
                break;
            }
        }
    }

    /* At some point I will be able to ditch the \r\n from item storage and
       remove all of these kludges.
       The above binprot check ensures inline space for \r\n, but if we do
       exactly enough allocs there will be no additional chunk for \r\n.
     */
    if (c->rlbytes == 0 && c->protocol == binary_prot && total >= 0)
    {
        item_chunk *ch = (item_chunk *)c->ritem;
        if (ch->size - ch->used < 2)
        {
            c->ritem = (char *)do_item_alloc_chunk(ch, 2);
            if (!c->ritem)
            {
                total = -2;
            }
        }
    }
    return total;
}

static void drive_machine(conn *c)
{
    log_routine(__func__);
    bool stop = false;
    int sfd;
    socklen_t addrlen;
    struct sockaddr_storage addr;
    int nreqs = settings.reqs_per_event;
    int res;
    const char *str;
#ifdef HAVE_ACCEPT4
    static int use_accept4 = 1;
#else
    static int use_accept4 = 0;
#endif

    assert(c != NULL);

    while (!stop)
    {

        switch (c->state)
        {
        case conn_listening:

            addrlen = sizeof(addr);
#ifdef HAVE_ACCEPT4
            if (use_accept4)
            {
                sfd = accept4(c->sfd, (struct sockaddr *)&addr, &addrlen, SOCK_NONBLOCK);
            }
            else
            {
                sfd = accept(c->sfd, (struct sockaddr *)&addr, &addrlen);
            }
#else
            sfd = accept(c->sfd, (struct sockaddr *)&addr, &addrlen);
#endif
            if (sfd == -1)
            {
                if (use_accept4 && errno == ENOSYS)
                {
                    use_accept4 = 0;
                    continue;
                }
                perror(use_accept4 ? "accept4()" : "accept()");
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    /* these are transient, so don't log anything */
                    stop = true;
                }
                else if (errno == EMFILE)
                {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Too many open connections\n");
                    accept_new_conns(false);
                    stop = true;
                }
                else
                {
                    perror("accept()");
                    stop = true;
                }
                break;
            }
            if (!use_accept4)
            {
                if (fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK) < 0)
                {
                    perror("setting O_NONBLOCK");
                    close(sfd);
                    break;
                }
            }

            bool reject;
            if (settings.maxconns_fast)
            {
                reject = sfd >= settings.maxconns - 1;
                if (reject)
                {
                    STATS_LOCK();
                    stats.rejected_conns++;
                    STATS_UNLOCK();
                }
            }
            else
            {
                reject = false;
            }

            if (reject)
            {
                str = "ERROR Too many open connections\r\n";
                res = write(sfd, str, strlen(str));
                close(sfd);
            }
            else
            {
                void *ssl_v = NULL;
#ifdef TLS
                SSL *ssl = NULL;
                if (c->ssl_enabled)
                {
                    assert(IS_TCP(c->transport) && settings.ssl_enabled);

                    if (settings.ssl_ctx == NULL)
                    {
                        if (settings.verbose)
                        {
                            fprintf(stderr, "SSL context is not initialized\n");
                        }
                        close(sfd);
                        break;
                    }
                    SSL_LOCK();
                    ssl = SSL_new(settings.ssl_ctx);
                    SSL_UNLOCK();
                    if (ssl == NULL)
                    {
                        if (settings.verbose)
                        {
                            fprintf(stderr, "Failed to created the SSL object\n");
                        }
                        close(sfd);
                        break;
                    }
                    SSL_set_fd(ssl, sfd);
                    int ret = SSL_accept(ssl);
                    if (ret <= 0)
                    {
                        int err = SSL_get_error(ssl, ret);
                        if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
                        {
                            if (settings.verbose)
                            {
                                fprintf(stderr, "SSL connection failed with error code : %d : %s\n", err, strerror(errno));
                            }
                            SSL_free(ssl);
                            close(sfd);
                            STATS_LOCK();
                            stats.ssl_handshake_errors++;
                            STATS_UNLOCK();
                            break;
                        }
                    }
                }
                ssl_v = (void *)ssl;
#endif

                dispatch_conn_new(sfd, conn_new_cmd, EV_READ | EV_PERSIST,
                                  READ_BUFFER_CACHED, c->transport, ssl_v);
            }

            stop = true;
            break;

        case conn_waiting:

            rbuf_release(c);
            if (!update_event(c, EV_READ | EV_PERSIST))
            {
                if (settings.verbose > 0)
                    fprintf(stderr, "Couldn't update event\n");
                conn_set_state(c, conn_closing);
                break;
            }

            conn_set_state(c, conn_read);
            stop = true;
            break;

        case conn_read:

            if (!IS_UDP(c->transport))
            {
                // Assign a read buffer if necessary.
                if (!rbuf_alloc(c))
                {
                    // TODO: Some way to allow for temporary failures.
                    conn_set_state(c, conn_closing);
                    break;
                }
                res = try_read_network(c);
            }
            else
            {
                // UDP connections always have a static buffer.
                res = try_read_udp(c);
            }

            switch (res)
            {
            case READ_NO_DATA_RECEIVED:

                conn_set_state(c, conn_waiting);
                break;
            case READ_DATA_RECEIVED:

                conn_set_state(c, conn_parse_cmd);
                break;
            case READ_ERROR:

                conn_set_state(c, conn_closing);
                break;
            case READ_MEMORY_ERROR: /* Failed to allocate more memory */
                /* State already set by try_read_network */
                break;
            }
            break;

        case conn_parse_cmd:

            c->noreply = false;
            if (c->try_read_command(c) == 0)
            {
                /* wee need more data! */
                if (c->resp_head)
                {
                    // Buffered responses waiting, flush in the meantime.
                    conn_set_state(c, conn_mwrite);
                }
                else
                {
                    conn_set_state(c, conn_waiting);
                }
            }

            break;

        case conn_new_cmd:

            /* Only process nreqs at a time to avoid starving other
               connections */

            --nreqs;
            if (nreqs >= 0)
            {
                reset_cmd_handler(c);
            }
            else if (c->resp_head)
            {
                // flush response pipe on yield.
                conn_set_state(c, conn_mwrite);
            }
            else
            {
                pthread_mutex_lock(&c->thread->stats.mutex);
                c->thread->stats.conn_yields++;
                pthread_mutex_unlock(&c->thread->stats.mutex);
                if (c->rbytes > 0)
                {
                    /* We have already read in data into the input buffer,
                       so libevent will most likely not signal read events
                       on the socket (unless more data is available. As a
                       hack we should just put in a request to write data,
                       because that should be possible ;-)
                    */
                    if (!update_event(c, EV_WRITE | EV_PERSIST))
                    {
                        if (settings.verbose > 0)
                            fprintf(stderr, "Couldn't update event\n");
                        conn_set_state(c, conn_closing);
                        break;
                    }
                }
                stop = true;
            }
            break;

        case conn_nread:

            if (c->rlbytes == 0)
            {
                complete_nread(c);
                break;
            }

            /* Check if rbytes < 0, to prevent crash */
            if (c->rlbytes < 0)
            {
                if (settings.verbose)
                {
                    fprintf(stderr, "Invalid rlbytes to read: len %d\n", c->rlbytes);
                }
                conn_set_state(c, conn_closing);
                break;
            }

            if (c->item_malloced || ((((item *)c->item)->it_flags & ITEM_CHUNKED) == 0))
            {
                /* first check if we have leftovers in the conn_read buffer */
                if (c->rbytes > 0)
                {
                    int tocopy = c->rbytes > c->rlbytes ? c->rlbytes : c->rbytes;
                    memmove(c->ritem, c->rcurr, tocopy);
                    c->ritem += tocopy;
                    c->rlbytes -= tocopy;
                    c->rcurr += tocopy;
                    c->rbytes -= tocopy;
                    if (c->rlbytes == 0)
                    {
                        break;
                    }
                }

                /*  now try reading from the socket */
                res = c->read(c, c->ritem, c->rlbytes);
                if (res > 0)
                {
                    pthread_mutex_lock(&c->thread->stats.mutex);
                    c->thread->stats.bytes_read += res;
                    pthread_mutex_unlock(&c->thread->stats.mutex);
                    if (c->rcurr == c->ritem)
                    {
                        c->rcurr += res;
                    }
                    c->ritem += res;
                    c->rlbytes -= res;
                    break;
                }
            }
            else
            {
                res = read_into_chunked_item(c);
                if (res > 0)
                    break;
            }

            if (res == 0)
            { /* end of stream */
                conn_set_state(c, conn_closing);
                break;
            }

            if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            {
                if (!update_event(c, EV_READ | EV_PERSIST))
                {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Couldn't update event\n");
                    conn_set_state(c, conn_closing);
                    break;
                }
                stop = true;
                break;
            }

            /* Memory allocation failure */
            if (res == -2)
            {
                out_of_memory(c, "SERVER_ERROR Out of memory during read");
                c->sbytes = c->rlbytes;
                conn_set_state(c, conn_swallow);
                // Ensure this flag gets cleared. It gets killed on conn_new()
                // so any conn_closing is fine, calling complete_nread is
                // fine. This swallow semms to be the only other case.
                c->set_stale = false;
                c->mset_res = false;
                break;
            }
            /* otherwise we have a real error, on which we close the connection */
            if (settings.verbose > 0)
            {
                fprintf(stderr, "Failed to read, and not due to blocking:\n"
                                "errno: %d %s \n"
                                "rcurr=%p ritem=%p rbuf=%p rlbytes=%d rsize=%d\n",
                        errno, strerror(errno),
                        (void *)c->rcurr, (void *)c->ritem, (void *)c->rbuf,
                        (int)c->rlbytes, (int)c->rsize);
            }
            conn_set_state(c, conn_closing);
            break;

        case conn_swallow:

            /* we are reading sbytes and throwing them away */
            if (c->sbytes <= 0)
            {
                conn_set_state(c, conn_new_cmd);
                break;
            }

            /* first check if we have leftovers in the conn_read buffer */
            if (c->rbytes > 0)
            {
                int tocopy = c->rbytes > c->sbytes ? c->sbytes : c->rbytes;
                c->sbytes -= tocopy;
                c->rcurr += tocopy;
                c->rbytes -= tocopy;
                break;
            }

            /*  now try reading from the socket */
            res = c->read(c, c->rbuf, c->rsize > c->sbytes ? c->sbytes : c->rsize);
            if (res > 0)
            {
                pthread_mutex_lock(&c->thread->stats.mutex);
                c->thread->stats.bytes_read += res;
                pthread_mutex_unlock(&c->thread->stats.mutex);
                c->sbytes -= res;
                break;
            }
            if (res == 0)
            { /* end of stream */
                conn_set_state(c, conn_closing);
                break;
            }
            if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            {
                if (!update_event(c, EV_READ | EV_PERSIST))
                {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Couldn't update event\n");
                    conn_set_state(c, conn_closing);
                    break;
                }
                stop = true;
                break;
            }
            /* otherwise we have a real error, on which we close the connection */
            if (settings.verbose > 0)
                fprintf(stderr, "Failed to read, and not due to blocking\n");
            conn_set_state(c, conn_closing);
            break;

        case conn_write:
        case conn_mwrite:

            /* have side IO's that must process before transmit() can run.
             * remove the connection from the worker thread and dispatch the
             * IO queue
             */
            if (c->io_queues[0].type != IO_QUEUE_NONE)
            {
                assert(c->io_queues_submitted == 0);
                bool hit = false;

                for (io_queue_t *q = c->io_queues; q->type != IO_QUEUE_NONE; q++)
                {
                    if (q->count != 0)
                    {
                        assert(q->stack_ctx != NULL);
                        hit = true;
                        q->submit_cb(q->ctx, q->stack_ctx);
                        c->io_queues_submitted++;
                    }
                }
                if (hit)
                {
                    conn_set_state(c, conn_io_queue);
                    event_del(&c->event);

                    stop = true;
                    break;
                }
            }

            switch (!IS_UDP(c->transport) ? transmit(c) : transmit_udp(c))
            {
            case TRANSMIT_COMPLETE:
                if (c->state == conn_mwrite)
                {
                    // Free up IO wraps and any half-uploaded items.
                    conn_release_items(c);
                    conn_set_state(c, conn_new_cmd);
                    if (c->close_after_write)
                    {
                        conn_set_state(c, conn_closing);
                    }
                }
                else
                {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Unexpected state %d\n", c->state);
                    conn_set_state(c, conn_closing);
                }
                break;

            case TRANSMIT_INCOMPLETE:
            case TRANSMIT_HARD_ERROR:
                break; /* Continue in state machine. */

            case TRANSMIT_SOFT_ERROR:
                stop = true;
                break;
            }
            break;

        case conn_closing:
            if (IS_UDP(c->transport))
                conn_cleanup(c);
            else
                conn_close(c);
            stop = true;
            break;

        case conn_closed:
            /* This only happens if dormando is an idiot. */
            abort();
            break;

        case conn_watch:
            /* We handed off our connection to the logger thread. */
            stop = true;
            break;
        case conn_io_queue:
            /* Complete our queued IO's from within the worker thread. */
            conn_io_queue_complete(c);
            conn_set_state(c, conn_mwrite);
            break;
        case conn_max_state:
            assert(false);
            break;
        }
    }

    return;
}

void event_handler(const evutil_socket_t fd, const short which, void *arg)
{
    log_routine(__func__);
    conn *c;

    c = (conn *)arg;
    assert(c != NULL);

    c->which = which;

    /* sanity */
    if (fd != c->sfd)
    {
        if (settings.verbose > 0)
            fprintf(stderr, "Catastrophic: event fd doesn't match conn fd!\n");
        conn_close(c);
        return;
    }

    drive_machine(c);

    /* wait for next event */
    return;
}

static int new_socket(struct addrinfo *ai)
{
    log_routine(__func__);
    int sfd;
    int flags;

    if ((sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1)
    {
        return -1;
    }

    if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
        fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("setting O_NONBLOCK");
        close(sfd);
        return -1;
    }
    return sfd;
}

/*
 * Sets a socket's send buffer size to the maximum allowed by the system.
 */
static void maximize_sndbuf(const int sfd)
{
    log_routine(__func__);
    socklen_t intsize = sizeof(int);
    int last_good = 0;
    int min, max, avg;
    int old_size;

    /* Start with the default size. */
#ifdef _WIN32
    if (getsockopt((SOCKET)sfd, SOL_SOCKET, SO_SNDBUF, (char *)&old_size, &intsize) != 0)
    {
#else
    if (getsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &old_size, &intsize) != 0)
    {
#endif /* #ifdef _WIN32 */
        if (settings.verbose > 0)
            perror("getsockopt(SO_SNDBUF)");
        return;
    }

    /* Binary-search for the real maximum. */
    min = old_size;
    max = MAX_SENDBUF_SIZE;

    while (min <= max)
    {
        avg = ((unsigned int)(min + max)) / 2;
        if (setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, (void *)&avg, intsize) == 0)
        {
            last_good = avg;
            min = avg + 1;
        }
        else
        {
            max = avg - 1;
        }
    }

    if (settings.verbose > 1)
        fprintf(stderr, "<%d send buffer was %d, now %d\n", sfd, old_size, last_good);
}

/**
 * Create a socket and bind it to a specific port number
 * @param interface the interface to bind to
 * @param port the port number to bind to
 * @param transport the transport protocol (TCP / UDP)
 * @param portnumber_file A filepointer to write the port numbers to
 *        when they are successfully added to the list of ports we
 *        listen on.
 */
static int server_socket(const char *interface,
                         int port,
                         enum network_transport transport,
                         FILE *portnumber_file, bool ssl_enabled)
{
    log_routine(__func__);
    int sfd;
    struct linger ling = {0, 0};
    struct addrinfo *ai;
    struct addrinfo *next;
    struct addrinfo hints = {.ai_flags = AI_PASSIVE,
                             .ai_family = AF_UNSPEC};
    char port_buf[NI_MAXSERV];
    int error;
    int success = 0;
    int flags = 1;

    hints.ai_socktype = IS_UDP(transport) ? SOCK_DGRAM : SOCK_STREAM;

    if (port == -1)
    {
        port = 0;
    }
    snprintf(port_buf, sizeof(port_buf), "%d", port);
    error = getaddrinfo(interface, port_buf, &hints, &ai);
    if (error != 0)
    {
        if (error != EAI_SYSTEM)
            fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(error));
        else
            perror("getaddrinfo()");
        return 1;
    }

    for (next = ai; next; next = next->ai_next)
    {
        conn *listen_conn_add;
        if ((sfd = new_socket(next)) == -1)
        {
            /* getaddrinfo can return "junk" addresses,
             * we make sure at least one works before erroring.
             */
            if (errno == EMFILE)
            {
                /* ...unless we're out of fds */
                perror("server_socket");
                exit(EX_OSERR);
            }
            continue;
        }

        if (settings.num_napi_ids)
        {
            socklen_t len = sizeof(socklen_t);
            int napi_id;
            error = getsockopt(sfd, SOL_SOCKET, SO_INCOMING_NAPI_ID, &napi_id, &len);
            if (error != 0)
            {
                fprintf(stderr, "-N <num_napi_ids> option not supported\n");
                exit(EXIT_FAILURE);
            }
        }

#ifdef IPV6_V6ONLY
        if (next->ai_family == AF_INET6)
        {
            error = setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&flags, sizeof(flags));
            if (error != 0)
            {
                perror("setsockopt");
                close(sfd);
                continue;
            }
        }
#endif

        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
        if (IS_UDP(transport))
        {
            maximize_sndbuf(sfd);
        }
        else
        {
            error = setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
            if (error != 0)
                perror("setsockopt");

            error = setsockopt(sfd, SOL_SOCKET, SO_LINGER, (void *)&ling, sizeof(ling));
            if (error != 0)
                perror("setsockopt");

            error = setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));
            if (error != 0)
                perror("setsockopt");
        }

        if (bind(sfd, next->ai_addr, next->ai_addrlen) == -1)
        {
            if (errno != EADDRINUSE)
            {
                perror("bind()");
                close(sfd);
                freeaddrinfo(ai);
                return 1;
            }
            close(sfd);
            continue;
        }
        else
        {
            success++;
            if (!IS_UDP(transport) && listen(sfd, settings.backlog) == -1)
            {
                perror("listen()");
                close(sfd);
                freeaddrinfo(ai);
                return 1;
            }
            if (portnumber_file != NULL &&
                (next->ai_addr->sa_family == AF_INET ||
                 next->ai_addr->sa_family == AF_INET6))
            {
                union
                {
                    struct sockaddr_in in;
                    struct sockaddr_in6 in6;
                } my_sockaddr;
                socklen_t len = sizeof(my_sockaddr);
                if (getsockname(sfd, (struct sockaddr *)&my_sockaddr, &len) == 0)
                {
                    if (next->ai_addr->sa_family == AF_INET)
                    {
                        fprintf(portnumber_file, "%s INET: %u\n",
                                IS_UDP(transport) ? "UDP" : "TCP",
                                ntohs(my_sockaddr.in.sin_port));
                    }
                    else
                    {
                        fprintf(portnumber_file, "%s INET6: %u\n",
                                IS_UDP(transport) ? "UDP" : "TCP",
                                ntohs(my_sockaddr.in6.sin6_port));
                    }
                }
            }
        }

        if (IS_UDP(transport))
        {
            int c;

            for (c = 0; c < settings.num_threads_per_udp; c++)
            {
                /* Allocate one UDP file descriptor per worker thread;
                 * this allows "stats conns" to separately list multiple
                 * parallel UDP requests in progress.
                 *
                 * The dispatch code round-robins new connection requests
                 * among threads, so this is guaranteed to assign one
                 * FD to each thread.
                 */
                int per_thread_fd;
                if (c == 0)
                {
                    per_thread_fd = sfd;
                }
                else
                {
                    per_thread_fd = dup(sfd);
                    if (per_thread_fd < 0)
                    {
                        perror("Failed to duplicate file descriptor");
                        exit(EXIT_FAILURE);
                    }
                }
                dispatch_conn_new(per_thread_fd, conn_read,
                                  EV_READ | EV_PERSIST,
                                  UDP_READ_BUFFER_SIZE, transport, NULL);
            }
        }
        else
        {
            if (!(listen_conn_add = conn_new(sfd, conn_listening,
                                             EV_READ | EV_PERSIST, 1,
                                             transport, main_base, NULL)))
            {
                fprintf(stderr, "failed to create listening connection\n");
                exit(EXIT_FAILURE);
            }
#ifdef TLS
            listen_conn_add->ssl_enabled = ssl_enabled;
#else
            assert(ssl_enabled == false);
#endif
            listen_conn_add->next = listen_conn;
            listen_conn = listen_conn_add;
        }
    }

    freeaddrinfo(ai);

    /* Return zero iff we detected no errors in starting up connections */
    return success == 0;
}

static int server_sockets(int port, enum network_transport transport,
                          FILE *portnumber_file)
{
    log_routine(__func__);
    bool ssl_enabled = false;

#ifdef TLS
    const char *notls = "notls";
    ssl_enabled = settings.ssl_enabled;
#endif

    if (settings.inter == NULL)
    {
        return server_socket(settings.inter, port, transport, portnumber_file, ssl_enabled);
    }
    else
    {
        // tokenize them and bind to each one of them..
        char *b;
        int ret = 0;
        char *list = strdup(settings.inter);

        if (list == NULL)
        {
            fprintf(stderr, "Failed to allocate memory for parsing server interface string\n");
            return 1;
        }
        for (char *p = strtok_r(list, ";,", &b);
             p != NULL;
             p = strtok_r(NULL, ";,", &b))
        {
            int the_port = port;
#ifdef TLS
            ssl_enabled = settings.ssl_enabled;
            // "notls" option is valid only when memcached is run with SSL enabled.
            if (strncmp(p, notls, strlen(notls)) == 0)
            {
                if (!settings.ssl_enabled)
                {
                    fprintf(stderr, "'notls' option is valid only when SSL is enabled\n");
                    free(list);
                    return 1;
                }
                ssl_enabled = false;
                p += strlen(notls) + 1;
            }
#endif

            char *h = NULL;
            if (*p == '[')
            {
                // expecting it to be an IPv6 address enclosed in []
                // i.e. RFC3986 style recommended by RFC5952
                char *e = strchr(p, ']');
                if (e == NULL)
                {
                    fprintf(stderr, "Invalid IPV6 address: \"%s\"", p);
                    free(list);
                    return 1;
                }
                h = ++p; // skip the opening '['
                *e = '\0';
                p = ++e; // skip the closing ']'
            }

            char *s = strchr(p, ':');
            if (s != NULL)
            {
                // If no more semicolons - attempt to treat as port number.
                // Otherwise the only valid option is an unenclosed IPv6 without port, until
                // of course there was an RFC3986 IPv6 address previously specified -
                // in such a case there is no good option, will just send it to fail as port number.
                if (strchr(s + 1, ':') == NULL || h != NULL)
                {
                    *s = '\0';
                    ++s;
                    if (!safe_strtol(s, &the_port))
                    {
                        fprintf(stderr, "Invalid port number: \"%s\"", s);
                        free(list);
                        return 1;
                    }
                }
            }

            if (h != NULL)
                p = h;

            if (strcmp(p, "*") == 0)
            {
                p = NULL;
            }
            ret |= server_socket(p, the_port, transport, portnumber_file, ssl_enabled);
        }
        free(list);
        return ret;
    }
}

#ifndef DISABLE_UNIX_SOCKET
static int new_socket_unix(void)
{
    log_routine(__func__);
    int sfd;
    int flags;

    if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
        perror("socket()");
        return -1;
    }

    if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
        fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("setting O_NONBLOCK");
        close(sfd);
        return -1;
    }
    return sfd;
}

static int server_socket_unix(const char *path, int access_mask)
{
    log_routine(__func__);
    int sfd;
    struct linger ling = {0, 0};
    struct sockaddr_un addr;
    struct stat tstat;
    int flags = 1;
    int old_umask;

    if (!path)
    {
        return 1;
    }

    if ((sfd = new_socket_unix()) == -1)
    {
        return 1;
    }

    /*
     * Clean up a previous socket file if we left it around
     */
    if (lstat(path, &tstat) == 0)
    {
        if (S_ISSOCK(tstat.st_mode))
            unlink(path);
    }

    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
    setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
    setsockopt(sfd, SOL_SOCKET, SO_LINGER, (void *)&ling, sizeof(ling));

    /*
     * the memset call clears nonstandard fields in some implementations
     * that otherwise mess things up.
     */
    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    assert(strcmp(addr.sun_path, path) == 0);
    old_umask = umask(~(access_mask & 0777));
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("bind()");
        close(sfd);
        umask(old_umask);
        return 1;
    }
    umask(old_umask);
    if (listen(sfd, settings.backlog) == -1)
    {
        perror("listen()");
        close(sfd);
        return 1;
    }
    if (!(listen_conn = conn_new(sfd, conn_listening,
                                 EV_READ | EV_PERSIST, 1,
                                 local_transport, main_base, NULL)))
    {
        fprintf(stderr, "failed to create listening connection\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
#else
#define server_socket_unix(path, access_mask) -1
#endif /* #ifndef DISABLE_UNIX_SOCKET */

/*
 * We keep the current time of day in a global variable that's updated by a
 * timer event. This saves us a bunch of time() system calls (we really only
 * need to get the time once a second, whereas there can be tens of thousands
 * of requests a second) and allows us to use server-start-relative timestamps
 * rather than absolute UNIX timestamps, a space savings on systems where
 * sizeof(time_t) > sizeof(unsigned int).
 */
volatile rel_time_t current_time;
static struct event clockevent;
#ifdef MEMCACHED_DEBUG
volatile bool is_paused;
volatile int64_t delta;
#endif
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
static bool monotonic = false;
static int64_t monotonic_start;
#endif

/* libevent uses a monotonic clock when available for event scheduling. Aside
 * from jitter, simply ticking our internal timer here is accurate enough.
 * Note that users who are setting explicit dates for expiration times *must*
 * ensure their clocks are correct before starting memcached. */
static void clock_handler(const evutil_socket_t fd, const short which, void *arg)
{
    //log_routine(__func__);
    struct timeval t = {.tv_sec = 1, .tv_usec = 0};
    static bool initialized = false;

    if (initialized)
    {
        /* only delete the event if it's actually there. */
        evtimer_del(&clockevent);
    }
    else
    {
        initialized = true;
    }

    // While we're here, check for hash table expansion.
    // This function should be quick to avoid delaying the timer.
    assoc_start_expand(stats_state.curr_items);
    // also, if HUP'ed we need to do some maintenance.
    // for now that's just the authfile reload.
    if (settings.sig_hup)
    {
        settings.sig_hup = false;

        authfile_load(settings.auth_file);
    }

    evtimer_set(&clockevent, clock_handler, 0);
    event_base_set(main_base, &clockevent);
    evtimer_add(&clockevent, &t);

#ifdef MEMCACHED_DEBUG
    if (is_paused)
        return;
#endif

#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
    if (monotonic)
    {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
            return;
#ifdef MEMCACHED_DEBUG
        current_time = (rel_time_t)(ts.tv_sec - monotonic_start + delta);
#else
        current_time = (rel_time_t)(ts.tv_sec - monotonic_start);
#endif
        return;
    }
#endif
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
#ifdef MEMCACHED_DEBUG
        current_time = (rel_time_t)(tv.tv_sec - process_started + delta);
#else
        current_time = (rel_time_t)(tv.tv_sec - process_started);
#endif
    }
}

static const char *flag_enabled_disabled(bool flag)
{
    return (flag ? "enabled" : "disabled");
}

static void verify_default(const char *param, bool condition)
{
    if (!condition)
    {
        printf("Default value of [%s] has changed."
               " Modify the help text and default value check.\n",
               param);
        exit(EXIT_FAILURE);
    }
}

static void usage(void)
{

    printf(PACKAGE " " VERSION "\n");
    printf("-p, --port=<num>          TCP port to listen on (default: %d)\n"
           "-U, --udp-port=<num>      UDP port to listen on (default: %d, off)\n",
           settings.port, settings.udpport);
#ifndef DISABLE_UNIX_SOCKET
    printf("-s, --unix-socket=<file>  UNIX socket to listen on (disables network support)\n");
    printf("-a, --unix-mask=<mask>    access mask for UNIX socket, in octal (default: %o)\n",
           settings.access);
#endif /* #ifndef DISABLE_UNIX_SOCKET */
    printf("-A, --enable-shutdown     enable ascii \"shutdown\" command\n");
    printf("-l, --listen=<addr>       interface to listen on (default: INADDR_ANY)\n");
#ifdef TLS
    printf("                          if TLS/SSL is enabled, 'notls' prefix can be used to\n"
           "                          disable for specific listeners (-l notls:<ip>:<port>) \n");
#endif
    printf("-d, --daemon              run as a daemon\n"
           "-r, --enable-coredumps    maximize core file limit\n"
           "-u, --user=<user>         assume identity of <username> (only when run as root)\n"
           "-m, --memory-limit=<num>  item memory in megabytes (default: %lu)\n"
           "-M, --disable-evictions   return error on memory exhausted instead of evicting\n"
           "-c, --conn-limit=<num>    max simultaneous connections (default: %d)\n"
           "-k, --lock-memory         lock down all paged memory\n"
           "-v, --verbose             verbose (print errors/warnings while in event loop)\n"
           "-vv                       very verbose (also print client commands/responses)\n"
           "-vvv                      extremely verbose (internal state transitions)\n"
           "-h, --help                print this help and exit\n"
           "-i, --license             print memcached and libevent license\n"
           "-V, --version             print version and exit\n"
           "-P, --pidfile=<file>      save PID in <file>, only used with -d option\n"
           "-f, --slab-growth-factor=<num> chunk size growth factor (default: %2.2f)\n"
           "-n, --slab-min-size=<bytes> min space used for key+value+flags (default: %d)\n",
           (unsigned long)settings.maxbytes / (1 << 20),
           settings.maxconns, settings.factor, settings.chunk_size);
    verify_default("udp-port", settings.udpport == 0);
    printf("-L, --enable-largepages  try to use large memory pages (if available)\n");
    printf("-D <char>     Use <char> as the delimiter between key prefixes and IDs.\n"
           "              This is used for per-prefix stats reporting. The default is\n"
           "              \"%c\" (colon). If this option is specified, stats collection\n"
           "              is turned on automatically; if not, then it may be turned on\n"
           "              by sending the \"stats detail on\" command to the server.\n",
           settings.prefix_delimiter);
    printf("-t, --threads=<num>       number of threads to use (default: %d)\n", settings.num_threads);
    printf("-R, --max-reqs-per-event  maximum number of requests per event, limits the\n"
           "                          requests processed per connection to prevent \n"
           "                          starvation (default: %d)\n",
           settings.reqs_per_event);
    printf("-C, --disable-cas         disable use of CAS\n");
    printf("-b, --listen-backlog=<num> set the backlog queue limit (default: %d)\n", settings.backlog);
    printf("-B, --protocol=<name>     protocol - one of ascii, binary, or auto (default: %s)\n",
           prot_text(settings.binding_protocol));
    printf("-I, --max-item-size=<num> adjusts max item size\n"
           "                          (default: %dm, min: %dk, max: %dm)\n",
           settings.item_size_max / (1 << 20), ITEM_SIZE_MAX_LOWER_LIMIT / (1 << 10), ITEM_SIZE_MAX_UPPER_LIMIT / (1 << 20));
#ifdef ENABLE_SASL
    printf("-S, --enable-sasl         turn on Sasl authentication\n");
#endif
    printf("-F, --disable-flush-all   disable flush_all command\n");
    printf("-X, --disable-dumping     disable stats cachedump and lru_crawler metadump\n");
    printf("-W  --disable-watch       disable watch commands (live logging)\n");
    printf("-Y, --auth-file=<file>    (EXPERIMENTAL) enable ASCII protocol authentication. format:\n"
           "                          user:pass\\nuser2:pass2\\n\n");
    printf("-e, --memory-file=<file>  (EXPERIMENTAL) mmap a file for item memory.\n"
           "                          use only in ram disks or persistent memory mounts!\n"
           "                          enables restartable cache (stop with SIGUSR1)\n");
#ifdef TLS
    printf("-Z, --enable-ssl          enable TLS/SSL\n");
#endif
    printf("-o, --extended            comma separated list of extended options\n"
           "                          most options have a 'no_' prefix to disable\n"
           "   - maxconns_fast:       immediately close new connections after limit (default: %s)\n"
           "   - hashpower:           an integer multiplier for how large the hash\n"
           "                          table should be. normally grows at runtime. (default starts at: %d)\n"
           "                          set based on \"STAT hash_power_level\"\n"
           "   - tail_repair_time:    time in seconds for how long to wait before\n"
           "                          forcefully killing LRU tail item.\n"
           "                          disabled by default; very dangerous option.\n"
           "   - hash_algorithm:      the hash table algorithm\n"
           "                          default is murmur3 hash. options: jenkins, murmur3, xxh3\n"
           "   - no_lru_crawler:      disable LRU Crawler background thread.\n"
           "   - lru_crawler_sleep:   microseconds to sleep between items\n"
           "                          default is %d.\n"
           "   - lru_crawler_tocrawl: max items to crawl per slab per run\n"
           "                          default is %u (unlimited)\n",
           flag_enabled_disabled(settings.maxconns_fast), settings.hashpower_init,
           settings.lru_crawler_sleep, settings.lru_crawler_tocrawl);
    printf("   - read_buf_mem_limit:  limit in megabytes for connection read/response buffers.\n"
           "                          do not adjust unless you have high (20k+) conn. limits.\n"
           "                          0 means unlimited (default: %u)\n",
           settings.read_buf_mem_limit);
    verify_default("read_buf_mem_limit", settings.read_buf_mem_limit == 0);
    printf("   - no_lru_maintainer:   disable new LRU system + background thread.\n"
           "   - hot_lru_pct:         pct of slab memory to reserve for hot lru.\n"
           "                          (requires lru_maintainer, default pct: %d)\n"
           "   - warm_lru_pct:        pct of slab memory to reserve for warm lru.\n"
           "                          (requires lru_maintainer, default pct: %d)\n"
           "   - hot_max_factor:      items idle > cold lru age * drop from hot lru. (default: %.2f)\n"
           "   - warm_max_factor:     items idle > cold lru age * this drop from warm. (default: %.2f)\n"
           "   - temporary_ttl:       TTL's below get separate LRU, can't be evicted.\n"
           "                          (requires lru_maintainer, default: %d)\n"
           "   - idle_timeout:        timeout for idle connections. (default: %d, no timeout)\n",
           settings.hot_lru_pct, settings.warm_lru_pct, settings.hot_max_factor, settings.warm_max_factor,
           settings.temporary_ttl, settings.idle_timeout);
    printf("   - slab_chunk_max:      (EXPERIMENTAL) maximum slab size in kilobytes. use extreme care. (default: %d)\n"
           "   - watcher_logbuf_size: size in kilobytes of per-watcher write buffer. (default: %u)\n"
           "   - worker_logbuf_size:  size in kilobytes of per-worker-thread buffer\n"
           "                          read by background thread, then written to watchers. (default: %u)\n"
           "   - track_sizes:         enable dynamic reports for 'stats sizes' command.\n"
           "   - no_hashexpand:       disables hash table expansion (dangerous)\n"
           "   - modern:              enables options which will be default in future.\n"
           "                          currently: nothing\n"
           "   - no_modern:           uses defaults of previous major version (1.4.x)\n",
           settings.slab_chunk_size_max / (1 << 10), settings.logger_watcher_buf_size / (1 << 10),
           settings.logger_buf_size / (1 << 10));
    verify_default("tail_repair_time", settings.tail_repair_time == TAIL_REPAIR_TIME_DEFAULT);
    verify_default("lru_crawler_tocrawl", settings.lru_crawler_tocrawl == 0);
    verify_default("idle_timeout", settings.idle_timeout == 0);
#ifdef HAVE_DROP_PRIVILEGES
    printf("   - drop_privileges:     enable dropping extra syscall privileges\n"
           "   - no_drop_privileges:  disable drop_privileges in case it causes issues with\n"
           "                          some customisation.\n"
           "                          (default is no_drop_privileges)\n");
    verify_default("drop_privileges", !settings.drop_privileges);
#ifdef MEMCACHED_DEBUG
    printf("   - relaxed_privileges:  running tests requires extra privileges. (default: %s)\n",
           flag_enabled_disabled(settings.relaxed_privileges));
#endif
#endif
#ifdef EXTSTORE
    printf("\n   - External storage (ext_*) related options (see: https://memcached.org/extstore)\n");
    printf("   - ext_path:            file to write to for external storage.\n"
           "                          ie: ext_path=/mnt/d1/extstore:1G\n"
           "   - ext_page_size:       size in megabytes of storage pages. (default: %u)\n"
           "   - ext_wbuf_size:       size in megabytes of page write buffers. (default: %u)\n"
           "   - ext_threads:         number of IO threads to run. (default: %u)\n"
           "   - ext_item_size:       store items larger than this (bytes, default %u)\n"
           "   - ext_item_age:        store items idle at least this long (seconds, default: no age limit)\n"
           "   - ext_low_ttl:         consider TTLs lower than this specially (default: %u)\n"
           "   - ext_drop_unread:     don't re-write unread values during compaction (default: %s)\n"
           "   - ext_recache_rate:    recache an item every N accesses (default: %u)\n"
           "   - ext_compact_under:   compact when fewer than this many free pages\n"
           "                          (default: 1/4th of the assigned storage)\n"
           "   - ext_drop_under:      drop COLD items when fewer than this many free pages\n"
           "                          (default: 1/4th of the assigned storage)\n"
           "   - ext_max_frag:        max page fragmentation to tolerate (default: %.2f)\n"
           "   - slab_automove_freeratio: ratio of memory to hold free as buffer.\n"
           "                          (see doc/storage.txt for more info, default: %.3f)\n",
           settings.ext_page_size / (1 << 20), settings.ext_wbuf_size / (1 << 20), settings.ext_io_threadcount,
           settings.ext_item_size, settings.ext_low_ttl,
           flag_enabled_disabled(settings.ext_drop_unread), settings.ext_recache_rate,
           settings.ext_max_frag, settings.slab_automove_freeratio);
    verify_default("ext_item_age", settings.ext_item_age == UINT_MAX);
#endif
#ifdef TLS
    printf("   - ssl_chain_cert:      certificate chain file in PEM format\n"
           "   - ssl_key:             private key, if not part of the -ssl_chain_cert\n"
           "   - ssl_keyformat:       private key format (PEM, DER or ENGINE) (default: PEM)\n");
    printf("   - ssl_verify_mode:     peer certificate verification mode, default is 0(None).\n"
           "                          valid values are 0(None), 1(Request), 2(Require)\n"
           "                          or 3(Once)\n");
    printf("   - ssl_ciphers:         specify cipher list to be used\n"
           "   - ssl_ca_cert:         PEM format file of acceptable client CA's\n"
           "   - ssl_wbuf_size:       size in kilobytes of per-connection SSL output buffer\n"
           "                          (default: %u)\n",
           settings.ssl_wbuf_size / (1 << 10));
    printf("   - ssl_session_cache:   enable server-side SSL session cache, to support session\n"
           "                          resumption\n");
    verify_default("ssl_keyformat", settings.ssl_keyformat == SSL_FILETYPE_PEM);
    verify_default("ssl_verify_mode", settings.ssl_verify_mode == SSL_VERIFY_NONE);
#endif
    printf("-N, --napi_ids            number of napi ids. see doc/napi_ids.txt for more details\n");
    return;
}

static void usage_license(void)
{
    printf(PACKAGE " " VERSION "\n\n");
    printf(
        "Copyright (c) 2003, Danga Interactive, Inc. <http://www.danga.com/>\n"
        "All rights reserved.\n"
        "\n"
        "Redistribution and use in source and binary forms, with or without\n"
        "modification, are permitted provided that the following conditions are\n"
        "met:\n"
        "\n"
        "    * Redistributions of source code must retain the above copyright\n"
        "notice, this list of conditions and the following disclaimer.\n"
        "\n"
        "    * Redistributions in binary form must reproduce the above\n"
        "copyright notice, this list of conditions and the following disclaimer\n"
        "in the documentation and/or other materials provided with the\n"
        "distribution.\n"
        "\n"
        "    * Neither the name of the Danga Interactive nor the names of its\n"
        "contributors may be used to endorse or promote products derived from\n"
        "this software without specific prior written permission.\n"
        "\n"
        "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
        "\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
        "LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
        "A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n"
        "OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
        "SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
        "LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
        "DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
        "THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
        "(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
        "OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
        "\n"
        "\n"
        "This product includes software developed by Niels Provos.\n"
        "\n"
        "[ libevent ]\n"
        "\n"
        "Copyright 2000-2003 Niels Provos <provos@citi.umich.edu>\n"
        "All rights reserved.\n"
        "\n"
        "Redistribution and use in source and binary forms, with or without\n"
        "modification, are permitted provided that the following conditions\n"
        "are met:\n"
        "1. Redistributions of source code must retain the above copyright\n"
        "   notice, this list of conditions and the following disclaimer.\n"
        "2. Redistributions in binary form must reproduce the above copyright\n"
        "   notice, this list of conditions and the following disclaimer in the\n"
        "   documentation and/or other materials provided with the distribution.\n"
        "3. All advertising materials mentioning features or use of this software\n"
        "   must display the following acknowledgement:\n"
        "      This product includes software developed by Niels Provos.\n"
        "4. The name of the author may not be used to endorse or promote products\n"
        "   derived from this software without specific prior written permission.\n"
        "\n"
        "THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR\n"
        "IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES\n"
        "OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.\n"
        "IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,\n"
        "INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT\n"
        "NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
        "DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
        "THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
        "(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF\n"
        "THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n");

    return;
}

static void save_pid(const char *pid_file)
{
    log_routine(__func__);
    FILE *fp;
    if (access(pid_file, F_OK) == 0)
    {
        if ((fp = fopen(pid_file, "r")) != NULL)
        {
            char buffer[1024];
            if (fgets(buffer, sizeof(buffer), fp) != NULL)
            {
                unsigned int pid;
                if (safe_strtoul(buffer, &pid) && kill((pid_t)pid, 0) == 0)
                {
                    fprintf(stderr, "WARNING: The pid file contained the following (running) pid: %u\n", pid);
                }
            }
            fclose(fp);
        }
    }

    /* Create the pid file first with a temporary name, then
     * atomically move the file to the real name to avoid a race with
     * another process opening the file to read the pid, but finding
     * it empty.
     */
    char tmp_pid_file[1024];
    snprintf(tmp_pid_file, sizeof(tmp_pid_file), "%s.tmp", pid_file);

    if ((fp = fopen(tmp_pid_file, "w")) == NULL)
    {
        vperror("Could not open the pid file %s for writing", tmp_pid_file);
        return;
    }

    fprintf(fp, "%ld\n", (long)getpid());
    if (fclose(fp) == -1)
    {
        vperror("Could not close the pid file %s", tmp_pid_file);
    }

    if (rename(tmp_pid_file, pid_file) != 0)
    {
        vperror("Could not rename the pid file from %s to %s",
                tmp_pid_file, pid_file);
    }
}

static void remove_pidfile(const char *pid_file)
{
    log_routine(__func__);
    if (pid_file == NULL)
        return;

    if (unlink(pid_file) != 0)
    {
        vperror("Could not remove the pid file %s", pid_file);
    }
}

static void sig_handler(const int sig)
{
    stop_main_loop = EXIT_NORMALLY;
    printf("Signal handled: %s.\n", strsignal(sig));
}

static void sighup_handler(const int sig)
{
    settings.sig_hup = true;
}

static void sig_usrhandler(const int sig)
{
    printf("Graceful shutdown signal handled: %s.\n", strsignal(sig));
    stop_main_loop = GRACE_STOP;
}

/*
 * On systems that supports multiple page sizes we may reduce the
 * number of TLB-misses by using the biggest available page size
 */
static int enable_large_pages(void)
{
#if defined(HAVE_GETPAGESIZES) && defined(HAVE_MEMCNTL)
    int ret = -1;
    size_t sizes[32];
    int avail = getpagesizes(sizes, 32);
    if (avail != -1)
    {
        size_t max = sizes[0];
        struct memcntl_mha arg = {0};
        int ii;

        for (ii = 1; ii < avail; ++ii)
        {
            if (max < sizes[ii])
            {
                max = sizes[ii];
            }
        }

        arg.mha_flags = 0;
        arg.mha_pagesize = max;
        arg.mha_cmd = MHA_MAPSIZE_BSSBRK;

        if (memcntl(0, 0, MC_HAT_ADVISE, (caddr_t)&arg, 0, 0) == -1)
        {
            fprintf(stderr, "Failed to set large pages: %s\n",
                    strerror(errno));
            fprintf(stderr, "Will use default page size\n");
        }
        else
        {
            ret = 0;
        }
    }
    else
    {
        fprintf(stderr, "Failed to get supported pagesizes: %s\n",
                strerror(errno));
        fprintf(stderr, "Will use default page size\n");
    }

    return ret;
#elif defined(__linux__) && defined(MADV_HUGEPAGE)
    /* check if transparent hugepages is compiled into the kernel */
    struct stat st;
    int ret = stat("/sys/kernel/mm/transparent_hugepage/enabled", &st);
    if (ret || !(st.st_mode & S_IFREG))
    {
        fprintf(stderr, "Transparent huge pages support not detected.\n");
        fprintf(stderr, "Will use default page size.\n");
        return -1;
    }
    return 0;
#elif defined(__FreeBSD__)
    int spages;
    size_t spagesl = sizeof(spages);

    if (sysctlbyname("vm.pmap.pg_ps_enabled", &spages,
                     &spagesl, NULL, 0) != 0)
    {
        fprintf(stderr, "Could not evaluate the presence of superpages features.");
        return -1;
    }
    if (spages != 1)
    {
        fprintf(stderr, "Superpages support not detected.\n");
        fprintf(stderr, "Will use default page size.\n");
        return -1;
    }
    return 0;
#else
    return -1;
#endif
}

/**
 * Do basic sanity check of the runtime environment
 * @return true if no errors found, false if we can't use this env
 */
static bool sanitycheck(void)
{
    /* One of our biggest problems is old and bogus libevents */
    const char *ever = event_get_version();
    if (ever != NULL)
    {
        if (strncmp(ever, "1.", 2) == 0)
        {
            fprintf(stderr, "You are using libevent %s.\nPlease upgrade to 2.x"
                            " or newer\n",
                    event_get_version());
            return false;
        }
    }

    return true;
}

static bool _parse_slab_sizes(char *s, uint32_t *slab_sizes)
{
    log_routine(__func__);
    char *b = NULL;
    uint32_t size = 0;
    int i = 0;
    uint32_t last_size = 0;

    if (strlen(s) < 1)
        return false;

    for (char *p = strtok_r(s, "-", &b);
         p != NULL;
         p = strtok_r(NULL, "-", &b))
    {
        if (!safe_strtoul(p, &size) || size < settings.chunk_size || size > settings.slab_chunk_size_max)
        {
            fprintf(stderr, "slab size %u is out of valid range\n", size);
            return false;
        }
        if (last_size >= size)
        {
            fprintf(stderr, "slab size %u cannot be lower than or equal to a previous class size\n", size);
            return false;
        }
        if (size <= last_size + CHUNK_ALIGN_BYTES)
        {
            fprintf(stderr, "slab size %u must be at least %d bytes larger than previous class\n",
                    size, CHUNK_ALIGN_BYTES);
            return false;
        }
        slab_sizes[i++] = size;
        last_size = size;
        if (i >= MAX_NUMBER_OF_SLAB_CLASSES - 1)
        {
            fprintf(stderr, "too many slab classes specified\n");
            return false;
        }
    }

    slab_sizes[i] = 0;
    return true;
}

struct _mc_meta_data
{
    void *mmap_base;
    uint64_t old_base;
    char *slab_config; // string containing either factor or custom slab list.
    int64_t time_delta;
    uint64_t process_started;
    uint32_t current_time;
};

