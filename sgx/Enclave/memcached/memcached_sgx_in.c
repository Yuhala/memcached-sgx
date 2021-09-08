/*
 * Created on Mon Sep 06 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * This file contains routines which interface with routines outside to correctly
 * run memcached inside the enclave.
 */

#include "memcached_sgx_in.h"
#include "Enclave.h"
#include "memcached.h"
#include "hash.h"
#include "storage.h"
#include "items.h"
#include "slabs.h"
#include "assoc.h"
#include "crawler.h"
#include "slabs.h"
#include "util.h"

#include <sgx/sysexits.h>

/**
 * Some global variables used for initialisation.
 * These are local in the normal main fxn but since we initialise in 
 * different steps via ecalls, we need to have global visibility.
 */
int c;
bool lock_memory = false;
bool do_daemonize = false;
bool preallocate = false;
int maxcore = 0;
char *username = NULL;
char *pid_file = NULL;
struct passwd *pw;
struct rlimit rlim;
char *buf;
char unit = '\0';
int size_max = 0;
int retval = EXIT_SUCCESS;
bool protocol_specified = false;
bool tcp_specified = false;
bool udp_specified = false;
bool start_lru_maintainer = true;
bool start_lru_crawler = true;
bool start_assoc_maint = true;
enum hashfunc_type hash_type = MURMUR3_HASH;
uint32_t tocrawl;
uint32_t slab_sizes[MAX_NUMBER_OF_SLAB_CLASSES];
bool use_slab_sizes = false;
char *slab_sizes_unparsed = NULL;
bool slab_chunk_size_changed = false;

/**
 * Prototypes of routines defined in other files
 */

void settings_init();

/*
 * forward declarations
 */
static void drive_machine(conn *c);
static int new_socket(struct addrinfo *ai);
static ssize_t tcp_read(conn *arg, void *buf, size_t count);
static ssize_t tcp_sendmsg(conn *arg, struct msghdr *msg, int flags);
static ssize_t tcp_write(conn *arg, void *buf, size_t count);

//pyuhala: custom logging
#define LOG_FUNC_IN 1

void log_routine(const char *func)
{
#ifdef LOG_FUNC_IN
     printf("Enclave memcached function: %s\n", func);
#else
//do nothing: important to avoid needless ocalls when integrating sgx
#endif
}

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
     settings.num_threads = 4; /* N workers */
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

void ecall_init_settings()
{
     log_routine(__func__);
     /* init settings */
     settings_init();
     //verify_default("hash_algorithm", hash_type == MURMUR3_HASH);
#ifdef EXTSTORE
     void *storage = NULL;
     void *storage_cf = storage_init_config(&settings);
     bool storage_enabled = false;
     if (storage_cf == NULL)
     {
          fprintf(stderr, "failed to allocate extstore config\n");
          return 1;
     }
#endif

     /* Run regardless of initializing it later */
     init_lru_maintainer();

     //pyuhala: process arguments here

     if (settings.item_size_max > 1024 * 1024)
     {
          if (!slab_chunk_size_changed)
          {
               // Ideal new default is 16k, but needs stitching.
               settings.slab_chunk_size_max = settings.slab_page_size / 2;
          }
     }

#ifdef EXTSTORE
     switch (storage_check_config(storage_cf))
     {
     case 0:
          storage_enabled = true;
          break;
     case 1:
          exit(EX_USAGE);
          break;
     }
#endif
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

     // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
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












void ecall_init_hash()
{
     enum hashfunc_type hash_type = MURMUR3_HASH;
     if (hash_init(hash_type) != 0)
     {
          fprintf(stderr, "Failed to initialize hash_algorithm!\n");
          exit(EX_USAGE);
     }
}

void ecall_stats_init()
{
     stats_init();
}

void ecall_init_hashtable()
{
     bool reuse_mem = false;
     void *mem_base = NULL;
     bool prefill = false;

     // Initialize the hash table _after_ checking restart metadata.
     // We override the hash table start argument with what was live
     // previously, to avoid filling a huge set of items into a tiny hash
     // table.
     assoc_init(settings.hashpower_init);

     slabs_init(settings.maxbytes, settings.factor, preallocate,
                use_slab_sizes ? slab_sizes : NULL, mem_base, reuse_mem);

     if (prefill)
          slabs_prefill_global();
}

void ecall_start_assoc_maintenance()
{
     assoc_maintenance_thread(NULL);
}

void ecall_start_item_crawler()
{
     item_crawler_thread(NULL);
}

void ecall_start_slab_rebalance(){
     slab_rebalance_thread(NULL);
}

void ecall_assoc_start_expand(){
     assoc_start_expand(stats_state.curr_items);
}

void ecall_drive_machine(conn *c){
     drive_machine(c);
}

void ecall_uriencode_init(){
     uriencode_init();
}