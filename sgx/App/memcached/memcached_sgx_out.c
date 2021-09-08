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


/**
 * Some useful routines
 */

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
 * Initializes secure memcached: partitioned version of the memcached main routine
 * In-enclave: settings init, binary/ASCII handling, slab/cache management, hash fxns
 * Outside: thread init, libevent, signal handlers, socket init
 */

void init_memcached()
{
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
  
    if (!sanitycheck())
    {
        //free(meta);
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
    //ecall_init_settings(global_eid);

    /* set stderr non-buffering (for running under, say, daemontools) */
    setbuf(stderr, NULL);

    //ecall_init_hash(global_eid);

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

    //init stats
    ecall_stats_init(global_eid);
    
    //init connections array
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

}