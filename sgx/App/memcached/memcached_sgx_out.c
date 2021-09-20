/*
 * Created on Mon Sep 06 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * 
 *  Copyright 2003 Danga Interactive, Inc.  All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  
 * 
 * Contains routines to interface in-enclave memcached with the untrusted world.
 * The aim of this work is to have a MINIMAL working memcached for the enclave. Much functionality 
 * not required for this minimal version have been removed: eg logging, option parsing, extstore etc. We use default settings. 
 * All we want is something to get/set/update kv pairs in an enclave memcached.
 * More info on extstore: https://github-wiki-see.page/m/memcached/memcached/wiki/Extstore
 */

#include "memcached_sgx_out.h"
#include <stdbool.h>

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
#include <sys/time.h>
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

static bool sanitycheck(void);

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

struct _mc_meta_data
{
    void *mmap_base;
    uint64_t old_base;
    char *slab_config; // string containing either factor or custom slab list.
    int64_t time_delta;
    uint64_t process_started;
    uint32_t current_time;
};

static int try_read_command_negotiate(conn *c);
static int try_read_command_udp(conn *c);

static enum try_read_result try_read_network(conn *c);
static enum try_read_result try_read_udp(conn *c);

static int start_conn_timeout_thread();

/* stats */
//static void stats_init(void);
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

extern pthread_mutex_t conn_lock;

/* Connection timeout thread bits */
static pthread_t conn_timeout_tid;
static int do_run_conn_timeout_thread;
//static pthread_cond_t conn_timeout_cond = PTHREAD_COND_INITIALIZER;
//static pthread_mutex_t conn_timeout_lock = PTHREAD_MUTEX_INITIALIZER;

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

//pyuhala: used to manage cross-enclave connections and libevent threads
struct event *event_array[MAX_ENC_CONNS];
LIBEVENT_THREAD *event_thread_array[MAX_ENC_CONNS];
conn *my_conn_array[MAX_ENC_CONNS];
static int conn_count = 0;

void setConn(conn *c, int conn_id)
{
    my_conn_array[conn_id] = c;
}

//the conn_id is the sfd
conn *getConn(int conn_id)
{
    return my_conn_array[conn_id];
}

void setEventThread(LIBEVENT_THREAD *lt, int conn_id)
{
    event_thread_array[conn_id] = lt;
    printf("setEventThread: %d <==> Connection: %d\n", lt->libevent_tid, conn_id);
}
LIBEVENT_THREAD *getEventThread(int conn_id)
{
    printf("getEventThread for conn: %d\n", conn_id);
    return event_thread_array[conn_id];
}

//set event structure for enclave conn variable
void setConnEvent(struct event *ev, int conn_id)
{
    event_array[conn_id] = ev;
}

//get event structure for enclave conn variable
struct event *getConnEvent(int conn_id)
{
    return event_array[conn_id];
}

/**
 * Do basic sanity check of the runtime environment
 * @return true if no errors found, false if we can't use this env
 */
static bool sanitycheck(void)
{
    log_routine(__func__);
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

//add new routines here

static void save_pid(const char *pid_file)
{
    log_routine(__func__);
    SGX_FILE fp;
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

conn *conn_new(const int sfd, enum conn_states init_state,
               const int event_flags,
               const int read_buffer_size, enum network_transport transport,
               struct event_base *base, void *ssl)
{

    log_routine(__func__);
    void *ret;
    int fd = sfd;
    int flags = event_flags;
    int bufsz = read_buffer_size;
    ecall_conn_new(global_eid, &ret, fd, init_state, flags, bufsz, transport, base, ssl);
    if (ret == NULL)
    {
        printf("ecall_conn_new: ret is NULL >>>>>>>>>>>>\n");
    }
    //setConn((conn *)ret, fd);
    return (conn *)ret;

    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
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
rel_time_t realtime(const time_t exptime)
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
    settings.maxbytes = 16 * 1024 * 1024; /* default is 64MB */
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

    ecall_assoc_start_expand(global_eid);

    //assoc_start_expand(stats_state.curr_items);

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
void conn_close_all(void)
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

void event_handler(const evutil_socket_t fd, const short which, void *arg)
{
    log_routine(__func__);

    evutil_socket_t sfd = fd;
    short wch = which;

    ecall_event_handler(global_eid, sfd, wch, arg);
    return;

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

    //pyuhala: ecall into the enclave

    ecall_drive_machine(global_eid, (void *)c);

    /* wait for next event */
    return;
}

static void sig_handler(const int sig)
{
    log_routine(__func__);
    stop_main_loop = EXIT_NORMALLY;
    printf("Signal handled: %s.\n", strsignal(sig));
}

static void sighup_handler(const int sig)
{
    log_routine(__func__);
    settings.sig_hup = true;
}

static void sig_usrhandler(const int sig)
{
    log_routine(__func__);
    printf("Graceful shutdown signal handled: %s.\n", strsignal(sig));
    stop_main_loop = GRACE_STOP;
}

// >>>>>>>>>>>>>>>>>>>>>>>>> memcached ocalls start >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

void mcd_ocall_do_cache_free(int conn_id, int lvt_thread_id, void *ptr)
{

    log_routine(__func__);

    LIBEVENT_THREAD *lthread = getEventThread(conn_id);
    if (lthread == NULL)
    {
        printf("lthread is NULL >>>>>>>>>>>>>>>>>>>>>>\n");
    }
    //pyuhala: memory leaks outside..not a big deal for now..
    do_cache_free(lthread->rbuf_cache, ptr);
}
void *mcd_ocall_do_cache_alloc(int conn_id, int lvt_thread_id)
{
    log_routine(__func__);

    LIBEVENT_THREAD *lthread = getEventThread(conn_id);
    if (lthread == NULL)
    {
        printf("lthread is NULL >>>>>>>>>>>>>>>>>>>>>>\n");
    }
    /**
     * pyuhala: this should have been allocated already but for some reason I receive segfaults which says its NULL
     * todo: check why it is null at this point. For now I reallocate
     */
    if (lthread->rbuf_cache == NULL)
    {
        lthread->rbuf_cache = cache_create("rbuf", READ_BUFFER_SIZE, sizeof(char *), NULL, NULL);
        if (lthread->rbuf_cache == NULL)
        {
            fprintf(stderr, "Failed to create read buffer cache\n");
            exit(EXIT_FAILURE);
        }
    }
    return do_cache_alloc(lthread->rbuf_cache);
}

void mcd_ocall_dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags, int read_buffer_size, enum network_transport transport, void *ssl)
{
    log_routine(__func__);
    dispatch_conn_new(sfd, init_state, event_flags, read_buffer_size, transport, ssl);
}

/**
 * pyuhala: sets up the event structures for a connection
 */
int mcd_ocall_setup_conn_event(int fd, int flags, struct event_base *base, void *conn_ptr, int conn_id)
{
    log_routine(__func__);
    const int sfd = fd;
    const int event_flags = flags;
    struct event *ev = (struct event *)malloc(sizeof(struct event));
    //TODO: if base is always main_base, remove the base param

    //conn *c = getConn(fd);

    conn *c = (conn *)conn_ptr;

    /**
     * pyuhala: this connection's event base should be the same as that of its lthread
     */
    LIBEVENT_THREAD *lth = getEventThread(conn_id);

    if (c == NULL)
    {
        printf("mcd_ocall_setup_conn_event:: conn_ptr is NULL >>>>>>>>>>>>>>>>\n");
    }

    event_set(ev, sfd, event_flags, NULL, (void *)c);
    event_set(ev, sfd, event_flags, event_handler, (void *)c);

    if (lth == NULL)
    {
        event_base_set(main_base, ev);
    }
    else
    {
        event_base_set(lth->base, ev);
    }

    if (event_add(ev, 0) == -1)
    {

        perror("event_add");
        return OCALL_FAILED;
    }
    //printf("ocall_setup_conn_event:: event_add passed >>>>>>>>> \n");

    setConnEvent(ev, conn_id);
    return 0;
}

void mcd_ocall_update_conn_event(int fd, int new_flags, struct event_base *base, void *conn_ptr, int conn_id)
{
    log_routine(__func__);
    const int sfd = fd;
    const int event_flags = new_flags;
    conn *c = (conn *)conn_ptr;

    struct event *ev = getConnEvent(conn_id);
    LIBEVENT_THREAD *lth = getEventThread(conn_id);
    event_set(ev, sfd, event_flags, event_handler, (void *)c);
    event_base_set(lth->base, ev);
}

int mcd_ocall_event_del(int conn_id)
{
    log_routine(__func__);
    struct event *ev = getConnEvent(conn_id);
    if (event_del(ev) == -1)
        return -1;

    return 0;
}
int mcd_ocall_event_add(int conn_id)
{
    log_routine(__func__);
    struct event *ev = getConnEvent(conn_id);
    if (event_add(ev, 0) == -1)
        return -1;
    return 0;
}

void mcd_ocall_event_base_loopexit()
{
    log_routine(__func__);
    event_base_loopexit(main_base, NULL);
}

void mcd_ocall_mutex_lock_lthread_stats(int conn_id)
{
    log_routine(__func__);
    LIBEVENT_THREAD *lthread = getEventThread(conn_id);

    if (lthread == NULL)
    {
        printf("mcd_ocall_mutex_lock_lthread: NULL libevent thread >>>>>>>>>>>>>>>\n");
        return;
    }
    pthread_mutex_lock(&lthread->stats.mutex);
}

void mcd_ocall_mutex_unlock_lthread_stats(int conn_id)
{
    log_routine(__func__);
    LIBEVENT_THREAD *lthread = getEventThread(conn_id);
    if (lthread == NULL)
    {
        printf("mcd_ocall_mutex_unlock_lthread: NULL libevent thread >>>>>>>>>>>>>>>\n");
        return;
    }
    pthread_mutex_unlock(&lthread->stats.mutex);
}

// >>>>>>>>>>>>>>>>>>>>>>>>> memcached ocalls end >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

/**
 * Initializes secure memcached: partitioned version of the memcached main routine
 * In-enclave: settings init, binary/ASCII handling, slab/cache management, hash fxns
 * Outside: thread init, libevent, signal handlers, socket init
 */

void init_memcached()
{
    log_routine(__func__);
    printf(" =============== pyuhala: init_memcached_out ==================\n");
    printf(" Do: telnet 127.0.0.1 11211 in terminal\n");
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

    struct _mc_meta_data *meta = malloc(sizeof(struct _mc_meta_data));
    meta->slab_config = NULL;

    if (!sanitycheck())
    {
        free(meta);
        return EX_OSERR;
    }

    /* handle SIGINT, SIGTERM */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, sighup_handler);
    signal(SIGUSR1, sig_usrhandler);

    /**
      * Init settings: the settings structure is used both inside and outside. So initialise
      * this struct in and out of the enclave.
      */
    settings_init();
    ecall_init_settings(global_eid);

    /* set stderr non-buffering (for running under, say, daemontools) */
    setbuf(stderr, NULL);

    ecall_init_hash(global_eid);

    /*
     * Use one workerthread to serve each UDP port if the user specified
     * multiple ports
     */
    if (settings.inter != NULL && strchr(settings.inter, ','))
    {
        settings.num_threads_per_udp = 1;
    }
    else
    {
        settings.num_threads_per_udp = settings.num_threads;
    }

    if (settings.auth_file)
    {
        if (!protocol_specified)
        {
            settings.binding_protocol = ascii_prot;
        }
        else
        {
            if (settings.binding_protocol != ascii_prot)
            {
                fprintf(stderr, "ERROR: You cannot allow the BINARY protocol while using ascii authentication tokens.\n");
                exit(EX_USAGE);
            }
        }
    }

    if (udp_specified && settings.udpport != 0 && !tcp_specified)
    {
        settings.port = settings.udpport;
    }

    if (maxcore != 0)
    {
        struct rlimit rlim_new;
        /*
         * First try raising to infinity; if that fails, try bringing
         * the soft limit to the hard.
         */
        if (getrlimit(RLIMIT_CORE, &rlim) == 0)
        {
            rlim_new.rlim_cur = rlim_new.rlim_max = RLIM_INFINITY;
            if (setrlimit(RLIMIT_CORE, &rlim_new) != 0)
            {
                /* failed. try raising just to the old max */
                rlim_new.rlim_cur = rlim_new.rlim_max = rlim.rlim_max;
                (void)setrlimit(RLIMIT_CORE, &rlim_new);
            }
        }
        /*
         * getrlimit again to see what we ended up with. Only fail if
         * the soft limit ends up 0, because then no core files will be
         * created at all.
         */

        if ((getrlimit(RLIMIT_CORE, &rlim) != 0) || rlim.rlim_cur == 0)
        {
            fprintf(stderr, "failed to ensure corefile creation\n");
            exit(EX_OSERR);
        }
    }

    /*
     * If needed, increase rlimits to allow as many connections
     * as needed.
     */

    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0)
    {
        fprintf(stderr, "failed to getrlimit number of files\n");
        exit(EX_OSERR);
    }
    else
    {
#ifdef MEMCACHED_DEBUG
        if (rlim.rlim_cur < settings.maxconns || rlim.rlim_max < settings.maxconns)
        {
#endif
            rlim.rlim_cur = settings.maxconns;
            rlim.rlim_max = settings.maxconns;
            if (setrlimit(RLIMIT_NOFILE, &rlim) != 0)
            {
                fprintf(stderr, "failed to set rlimit for open files. Try starting as root or requesting smaller maxconns value.\n");
                exit(EX_OSERR);
            }
#ifdef MEMCACHED_DEBUG
        }
#endif
    }

    /* lose root privileges if we have them */
    if (getuid() == 0 || geteuid() == 0)
    {
        if (username == 0 || *username == '\0')
        {
            fprintf(stderr, "can't run as root without the -u switch\n");
            exit(EX_USAGE);
        }
        if ((pw = getpwnam(username)) == 0)
        {
            fprintf(stderr, "can't find the user %s to switch to\n", username);
            exit(EX_NOUSER);
        }
        if (setgroups(0, NULL) < 0)
        {
            /* setgroups may fail with EPERM, indicating we are already in a
             * minimally-privileged state. In that case we continue. For all
             * other failure codes we exit.
             *
             * Note that errno is stored here because fprintf may change it.
             */
            bool should_exit = errno != EPERM;
            fprintf(stderr, "failed to drop supplementary groups: %s\n",
                    strerror(errno));
            if (should_exit)
            {
                exit(EX_OSERR);
            }
        }
        if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0)
        {
            fprintf(stderr, "failed to assume identity of user %s\n", username);
            exit(EX_OSERR);
        }
    }

    /* initialize main thread libevent instance */
#if defined(LIBEVENT_VERSION_NUMBER) && LIBEVENT_VERSION_NUMBER >= 0x02000101
    /* If libevent version is larger/equal to 2.0.2-alpha, use newer version */
    struct event_config *ev_config;
    ev_config = event_config_new();
    event_config_set_flag(ev_config, EVENT_BASE_FLAG_NOLOCK);
    main_base = event_base_new_with_config(ev_config);
    event_config_free(ev_config);
#else
    /* Otherwise, use older API */
    main_base = event_init();
#endif

    /* Load initial auth file if required */
    if (settings.auth_file)
    {
        if (settings.udpport)
        {
            fprintf(stderr, "Cannot use UDP with ascii authentication enabled (-U 0 to disable)\n");
            exit(EX_USAGE);
        }

        switch (authfile_load(settings.auth_file))
        {
        case AUTHFILE_STATFAIL:
            vperror("Could not stat authfile [%s], error %s", settings.auth_file, strerror(errno));
            exit(EXIT_FAILURE);
            break;
        case AUTHFILE_OPENFAIL:
            vperror("Could not open authfile [%s] for reading, error %s", settings.auth_file, strerror(errno));
            exit(EXIT_FAILURE);
            break;
        case AUTHFILE_OOM:
            fprintf(stderr, "Out of memory reading password file: %s", settings.auth_file);
            exit(EXIT_FAILURE);
            break;
        case AUTHFILE_MALFORMED:
            fprintf(stderr, "Authfile [%s] has a malformed entry. Should be 'user:password'", settings.auth_file);
            exit(EXIT_FAILURE);
            break;
        case AUTHFILE_OK:
            break;
        }
    }

    //TODO: group these into 1 ecall

    //init enclave main_base event handle
    ecall_init_mainbase(global_eid, (void *)main_base);

    //init stats
    ecall_stats_init(global_eid);

    //init connections variables in & out
    ecall_conn_init(global_eid);
    conn_init();

    //init hash table
    ecall_init_hashtable(global_eid);

    //pyuhala: extstore disabled
    memcached_thread_init(settings.num_threads, NULL);
    init_lru_crawler(NULL);

    if (start_assoc_maint && sgx_start_assoc_maintenance_thread() == -1)
    {
        exit(EXIT_FAILURE);
    }
    if (start_lru_crawler && sgx_start_item_crawler_thread() != 0)
    {
        fprintf(stderr, "Failed to enable LRU crawler thread\n");
        exit(EXIT_FAILURE);
    }

    if (settings.slab_reassign &&
        sgx_start_slab_maintenance_thread() == -1)
    {
        exit(EXIT_FAILURE);
    }
    /**
     * pyuhala: 
     * lru crawler disabled. Not required for normal usage
     * conn timeout thread disabled
     */

    /* initialise clock event */
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
    {
        struct timespec ts;
        //pyuhala: disabled reuse_mem
        bool reuse_mem = false;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        {
            monotonic = true;
            monotonic_start = ts.tv_sec;
            // Monotonic clock needs special handling for restarts.
            // We get a start time at an arbitrary place, so we need to
            // restore the original time delta, which is always "now" - _start
            if (reuse_mem)
            {
                // the running timespan at stop time + the time we think we
                // were stopped.
                monotonic_start -= meta->current_time + meta->time_delta;
            }
            else
            {
                monotonic_start -= ITEM_UPDATE_INTERVAL + 2;
            }
        }
    }
#endif
    clock_handler(0, 0, 0);

    //>>>>>>> init server sockets >>>>>>
    /* create unix mode sockets after dropping privileges */
    if (settings.socketpath != NULL)
    {
        errno = 0;
        if (server_socket_unix(settings.socketpath, settings.access))
        {
            vperror("failed to listen on UNIX socket: %s", settings.socketpath);
            exit(EX_OSERR);
        }
    }

    /* create the listening socket, bind it, and init */
    if (settings.socketpath == NULL)
    {
        const char *portnumber_filename = getenv("MEMCACHED_PORT_FILENAME");
        printf("Portnumber file: %c\n", portnumber_filename);
        char *temp_portnumber_filename = NULL;
        size_t len;
        FILE *portnumber_file = NULL;

        if (portnumber_filename != NULL)
        {

            len = strlen(portnumber_filename) + 4 + 1;
            temp_portnumber_filename = malloc(len);
            snprintf(temp_portnumber_filename,
                     len,
                     "%s.lck", portnumber_filename);

            portnumber_file = fopen(temp_portnumber_filename, "a");
            if (portnumber_file == NULL)
            {
                fprintf(stderr, "Failed to open \"%s\": %s\n",
                        temp_portnumber_filename, strerror(errno));
            }
        }

        if (portnumber_file == NULL)
        {
            printf("Portnumber file is NULL\n");
        }
        errno = 0;
        if (settings.port && server_sockets(settings.port, tcp_transport,
                                            portnumber_file))
        {
            vperror("failed to listen on TCP port %d", settings.port);
            exit(EX_OSERR);
        }

        /*
         * initialization order: first create the listening sockets
         * (may need root on low ports), then drop root if needed,
         * then daemonize if needed, then init libevent (in some cases
         * descriptors created by libevent wouldn't survive forking).
         */

        /* create the UDP listening socket and bind it */
        errno = 0;
        if (settings.udpport && server_sockets(settings.udpport, udp_transport,
                                               portnumber_file))
        {
            vperror("failed to listen on UDP port %d", settings.udpport);
            exit(EX_OSERR);
        }

        if (portnumber_file)
        {
            fclose(portnumber_file);
            rename(temp_portnumber_filename, portnumber_filename);
        }
        if (temp_portnumber_filename)
            free(temp_portnumber_filename);
    }

    /* Give the sockets a moment to open. I know this is dumb, but the error
     * is only an advisory.
     */
    usleep(1000);
    if (stats_state.curr_conns + stats_state.reserved_fds >= settings.maxconns - 1)
    {
        fprintf(stderr, "Maxconns setting is too low, use -c to increase.\n");
        exit(EXIT_FAILURE);
    }

    if (pid_file != NULL)
    {
        save_pid(pid_file);
    }

    //>>>>>> end >>>>>>>>>>>>>

    //ecall_init_server_sockets(global_eid);

    /* Drop privileges no longer needed */
    if (settings.drop_privileges)
    {
        drop_privileges();
    }

    /* Initialize the uriencode lookup table. */
    //seems useful in and out of the enclave.
    uriencode_init();
    ecall_uriencode_init(global_eid);

    /* enter the event loop */
    while (!stop_main_loop)
    {
        if (event_base_loop(main_base, EVLOOP_ONCE) != 0)
        {
            retval = EXIT_FAILURE;
            break;
        }
    }

    switch (stop_main_loop)
    {
    case GRACE_STOP:
        fprintf(stderr, "Gracefully stopping\n");
        break;
    case EXIT_NORMALLY:
        // Don't need to print anything to STDERR for a normal shutdown.
        break;
    default:
        fprintf(stderr, "Exiting on error\n");
        break;
    }

    stop_threads();
    if (settings.memory_file != NULL && stop_main_loop == GRACE_STOP)
    {
        //restart_mmap_close();
    }

    free(meta);

    /* Clean up strdup() call for bind() address */
    if (settings.inter)
        free(settings.inter);

    /* cleanup base */
    event_base_free(main_base);

    return retval;
}
