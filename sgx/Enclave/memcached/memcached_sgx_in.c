/*
 * Created on Mon Sep 06 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 * This file contains routines which interface with routines outside to correctly
 * run memcached inside the enclave.
 */

#include "memcached_sgx_in.h"
#include "Enclave.h"

//app headers
#include "memcached.h"

#include "storage.h"
#include "proto_text.h"
#include "proto_bin.h"

//std headers
#include <unistd.h>

//sgx headers
#include <sgx/sys/un.h>
#include <sgx/netinet/tcp.h>
#include <sgx/sysexits.h>

/**
 * some prototypes
 */
void sgx_thread_libevent_process(evutil_socket_t fd, short which, void *arg);

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
 * External global variables
 */
extern sgx_thread_mutex_t conn_lock;

/**
 * Other globals
 */
static int conn_count = 0;
const uint64_t redzone = 0xdeadbeefcafebabe;

//pyuhala: int is not the real type of errno. Done this way for porting reasons and simplicy
int errno;

/*
 * forward declarations
 */
static void drive_machine(conn *c);
static int new_socket(struct addrinfo *ai);
static ssize_t tcp_read(conn *arg, void *buf, size_t count);
static ssize_t tcp_sendmsg(conn *arg, struct msghdr *msg, int flags);
static ssize_t tcp_write(conn *arg, void *buf, size_t count);

static void resp_free(conn *c, mc_resp *resp);

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

/* event handling, network IO */
static void event_handler(const evutil_socket_t fd, const short which, void *arg);
static void conn_close(conn *c);
static void conn_init(void);
static bool update_event(conn *c, const int new_flags);
static void complete_nread(conn *c);
static void conn_free(conn *c);

/* stats */
static void stats_init(void);
static void conn_to_str(const conn *c, char *addr, char *svr_addr);
static const char *state_text(enum conn_states state);

/* defaults */
static void settings_init(void);

static int read_into_chunked_item(conn *c);

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

//add new static routines here; if possible add prototypes above

/**
 * pyuhala:allocate a LIBEVENT_THREAD variable which will provide read buffers for this connection
 * inside the enclave.
 */
static void alloc_lthread_inside(conn *c)
{
    LIBEVENT_THREAD *myLthread = calloc(1, sizeof(LIBEVENT_THREAD));

    myLthread->rbuf_cache = cache_create("rbuf", READ_BUFFER_SIZE, sizeof(char *), NULL, NULL);
    if (myLthread->rbuf_cache == NULL)
    {
        //printf("Failed to alloc rbuf_cache inside >>>>>>>>>>>>>>>>>>\n");
        fprintf(stderr, "Failed to create read buffer cache\n");
        exit(EXIT_FAILURE);
    }
    // Note: we were cleanly passing in num_threads before, but this now
    // relies on settings globals too much.
    if (settings.read_buf_mem_limit)
    {
        int limit = settings.read_buf_mem_limit / settings.num_threads;
        if (limit < READ_BUFFER_SIZE)
        {
            limit = 1;
        }
        else
        {
            limit = limit / READ_BUFFER_SIZE;
        }
        cache_set_limit(myLthread->rbuf_cache, limit);
    }

    myLthread->io_cache = cache_create("io", sizeof(io_pending_t), sizeof(char *), NULL, NULL);
    if (myLthread->io_cache == NULL)
    {
        //printf("Failed to alloc io_cache inside >>>>>>>>>>>>>>>>>>\n");
        fprintf(stderr, "Failed to create IO object cache\n");
        exit(EXIT_FAILURE);
    }

    c->thread_in = myLthread;
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

static int nz_strcmp(int nzlength, const char *nz, const char *z)
{
    log_routine(__func__);
    int zlength = strlen(z);
    return (zlength == nzlength) && (strncmp(nz, z, zlength) == 0) ? 0 : -1;
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

   /*  mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
    if (incr)
    {
        c->thread->stats.slab_stats[ITEM_clsid(it)].incr_hits++;
    }
    else
    {
        c->thread->stats.slab_stats[ITEM_clsid(it)].decr_hits++;
    }
    mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */

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

void process_stat_settings(ADD_STAT add_stats, void *c)
{
    log_routine(__func__);
    printf("TODO: %s\n", __func__);
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

void server_stats(ADD_STAT add_stats, conn *c)
{
    log_routine(__func__);
    printf("TODO: %s\n", __func__);
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
        do_cache_free(c->thread_in->io_cache, resp->io_pending);
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
    /* THR_STATS_LOCK(c);
    c->thread->stats.response_obj_count--;
    THR_STATS_UNLOCK(c); */
    return next;
}

// tells if connection has a depth of response objects to process.
bool resp_has_stack(conn *c)
{
    log_routine(__func__);
    return c->resp_head->next != NULL ? true : false;
}

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

        //ocall
        event_base_set(main_base, &maxconnsevent);
        evtimer_add(&maxconnsevent, &t);
    }
    else
    {
        evtimer_del(&maxconnsevent);
        accept_new_conns(true);
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
               /*  mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
                c->thread->stats.bytes_read += res;
                mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */
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
        //printf("sanity check failed fd != c->sfd >>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
        if (settings.verbose > 0)
            fprintf(stderr, "Catastrophic: event fd doesn't match conn fd!\n");
        conn_close(c);
        return;
    }

    drive_machine(c);

    /* wait for next event */
    return;
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
       /*  mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
        c->thread->stats.bytes_read += res;
        mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */

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
        printf("rcurr != rbuf >>>>>>>>>>>>\n");
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
                //printf("NOT new rbuf >>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
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

        //printf("try_read_network:: c->rbytes = %d avail = %d >>>>>>>>>>>>>>\n", c->rbytes, avail);
        res = c->read(c, c->rbuf + c->rbytes, avail);
        //printf("try_read_network fd: %d avail: %d RES: \"%s\" size: %d >>>>>>>>>>>>>>>>\n", c->sfd, avail, (char *)c->rbuf, res);

        if (res > 0)
        {
            //pyuhala:
/* 
            mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
            c->thread->stats.bytes_read += res;
            mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */

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

static bool update_event(conn *c, const int new_flags)
{
    //pyuhala: modified to do event handling outside
    log_routine(__func__);
    assert(c != NULL);

    struct event_base *base = c->event.ev_base;
    if (c->ev_flags == new_flags)
        return true;

    int ret_del;
    mcd_ocall_event_del(&ret_del, c->conn_id);
    if (ret_del == -1)
        return false;

    int fd = c->sfd;
    int flags = new_flags;

    mcd_ocall_update_conn_event(fd, flags, base, (void *)c, c->conn_id);

    //event_set(&c->event, c->sfd, new_flags, event_handler, (void *)c);
    //event_base_set(base, &c->event);

    c->ev_flags = new_flags;

    int ret_add;
    mcd_ocall_event_add(&ret_add, c->conn_id);
    if (ret_add == -1)
        return false;
    return true;
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
            do_cache_free(c->thread_in->rbuf_cache, c->rbuf);
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
        /*c->rbuf = do_cache_alloc(c->thread_in->rbuf_cache);
        if (!c->rbuf)
        {
            THR_STATS_LOCK(c);
            c->thread->stats.read_buf_oom++;
            THR_STATS_UNLOCK(c);
            return false;
        }
        c->rsize = READ_BUFFER_SIZE;
        c->rcurr = c->rbuf;*/
        c->rbuf = malloc(READ_BUFFER_SIZE);
        c->rsize = READ_BUFFER_SIZE;
        c->rcurr = c->rbuf;
        c->rbuf_malloced = true;
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

    do_cache_free(c->thread_in->rbuf_cache, c->rbuf);
    memcpy(tmp, c->rcurr, c->rbytes);

    c->rcurr = c->rbuf = tmp;
    c->rsize = size;
    c->rbuf_malloced = true;
    return true;
}

static enum transmit_result transmit(conn *c);

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

/**
 * pyuhala: performs deep copy of in-enclave msghdr structure into one outside
 * TODO: move to shim library; very important routine for network related stuff
 */
static msg_deep_cpy(struct msghdr *msg_out, struct msghdr *msg_in)
{

    log_routine(__func__);
    

    //pyuhala: deep copy message name
    memcpy(msg_out->msg_name, msg_in->msg_name, msg_in->msg_namelen);
    //pyuhala: deep copy message control
    memcpy(msg_out->msg_control, msg_in->msg_control, msg_in->msg_controllen);
    //pyuhala: deep copy msg_iov; tricky: copy each struct in the iovec array

    for (int i = 0; i < msg_in->msg_iovlen; i++)
    {

        memcpy(msg_out->msg_iov[i].iov_base, msg_in->msg_iov[i].iov_base, msg_in->msg_iov[i].iov_len);
        msg_out->msg_iov[i].iov_len = msg_in->msg_iov[i].iov_len;
    }
    //copy lengths and flags
    msg_out->msg_namelen = msg_in->msg_namelen;
    msg_out->msg_iovlen = msg_in->msg_iovlen;
    msg_out->msg_flags = msg_in->msg_flags;
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

    int iovused = 0;

    // init the msg inside
    //pyuhala: modified abit but the same thing/better than previous
    struct msghdr *msg_in = malloc(sizeof(struct msghdr));

    memset(msg_in, 0, sizeof(struct msghdr));
    msg_in->msg_iov = iovs;

    //init msg outside
    void *ptr;
    ocall_transmit_prepare(&ptr);
    struct msghdr *msg_out = (struct msghdr *)ptr;

    iovused = _transmit_pre(c, iovs, iovused, TRANSMIT_ALL_RESP);
    ocall_getErrno(&errno);

    if (iovused == 0)
    {
        // Avoid the syscall if we're only handling a noreply.
        // Return the response object.
        _transmit_post(c, 0);
        //printf("after _transmit_post: TRANSMIT COMPLETE >>>>>>>>>>>>>>>>>>>>>>\n");
        return TRANSMIT_COMPLETE;
    }

    // Alright, send.
    ssize_t res;
    msg_in->msg_iovlen = iovused;

    //deep copy msg in to that out and send that out
    msg_deep_cpy(msg_out, msg_in);

    res = c->sendmsg(c, msg_out, 0);

    //printf("ERRNO before call: %d >>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n", errno);
    ocall_getErrno(&errno);

    //printf("Transmit sendmsg: res is: %d iovused: %d ERRNO: %d >>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n", res, iovused, errno);
    if (res >= 0)
    {
       /*  mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
        c->thread->stats.bytes_written += res;
        mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */

        // Decrement any partial IOV's and complete any finished resp's.
        _transmit_post(c, res);

        if (c->resp_head)
        {
            return TRANSMIT_INCOMPLETE;
        }
        else
        {
            //printf("TRANSMIT COMPLETE >>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
            return TRANSMIT_COMPLETE;
        }
    }
    ocall_getErrno(&errno);

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
    ocall_getErrno(&errno);
    if (res >= 0)
    {
        /* mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
        c->thread->stats.bytes_written += res;
        mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */

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

void ecall_init_settings(int numWorkers)
{
    log_routine(__func__);
    /* init settings */
    settings_init();
    settings.num_threads = numWorkers;
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
                         SGX_FILE portnumber_file, bool ssl_enabled)
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
            //printf("FAILED to create new socket >>>>>>>>>>\n");

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
    printf("SUCCESS in connection creation >>>>>>>>>>>>> \n");
    return success == 0;
}

static int server_sockets(int port, enum network_transport transport,
                          SGX_FILE portnumber_file)
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

        /* mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
        c->thread->stats.idle_kicks++;
        mcd_ocall_mutex_unlock_lthread_stats(c->conn_id);
 */
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

    //>>>>>>>>>>>>>>>>>> ocall
    event_set(&c->event, c->sfd, c->ev_flags, event_handler, (void *)c);
    event_base_set(c->thread->base, &c->event);

    // TODO: call conn_cleanup/fail/etc
    if (event_add(&c->event, 0) == -1)
    {
        perror("event_add");
    }
    //>>>>>>>>>>>>>>>

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

conn *conn_new(const int sfd, enum conn_states init_state,
               const int event_flags,
               const int read_buffer_size, enum network_transport transport,
               struct event_base *base, void *ssl)
{

    log_routine(__func__);
    conn *c;
    //printf("conn_new with sfd: %d >>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n",sfd);
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

        //pyuhala
        c->conn_id = sfd;

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
        //SSL_set_info_callback(c->ssl, ssl_callback);
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

    /**
     * pyuhala: we do all these gymnastics to correctly set up the event structure for this connection outside
     */
    int ret = -1;

    mcd_ocall_setup_conn_event(&ret, sfd, event_flags, base, (void *)c, c->conn_id);
    if (ret == -1)
    {
        //pyuhala:this happens if event_add fails
        return NULL;
    }
    //c->event = *(struct event *)ev_ptr;

    c->ev_flags = event_flags;

    STATS_LOCK();
    stats_state.curr_conns++;
    stats.total_conns++;
    STATS_UNLOCK();

    MEMCACHED_CONN_ALLOCATE(c->sfd);

    //pyuhala: create libevent thread struct inside to provide read buffers
    alloc_lthread_inside(c);

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
    //event_del(&c->event);
    int ret_del;
    mcd_ocall_event_del(&ret_del, c->conn_id);

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
    sgx_thread_mutex_lock(&conn_lock);
    allow_new_conns = true;
    sgx_thread_mutex_unlock(&conn_lock);

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
    //printf("conn_set_state: %s\n", state_text(state));

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
            ocall_getErrno(&errno);
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
    LIBEVENT_THREAD *th = c->thread_in;
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
        //void *ret;
        //mcd_ocall_do_cache_alloc(&ret, c->conn_id, th->libevent_tid);
        //b = ret;

        if (b)
        {
           /*  THR_STATS_LOCK(c);
            c->thread->stats.response_obj_bytes += READ_BUFFER_SIZE;
            THR_STATS_UNLOCK(c); */
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
    LIBEVENT_THREAD *th = c->thread_in;
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
            //mcd_ocall_do_cache_free(c->conn_id, th->libevent_tid, (void *)b);

           /*  THR_STATS_LOCK(c);
            c->thread->stats.response_obj_bytes -= READ_BUFFER_SIZE;
            THR_STATS_UNLOCK(c); */
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
       /*  THR_STATS_LOCK(c);
        c->thread->stats.response_obj_oom++;
        THR_STATS_UNLOCK(c); */
        return false;
    }
    // handling the stats counters here to simplify testing
   /*  THR_STATS_LOCK(c);
    c->thread->stats.response_obj_count++;
    THR_STATS_UNLOCK(c); */
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
               /*  mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
                c->thread->stats.slab_stats[ITEM_clsid(old_it)].cas_hits++;
                mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */
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

                /* mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
                c->thread->stats.slab_stats[ITEM_clsid(old_it)].cas_hits++;
                mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */
                do_store = true;
            }
            else
            {
                // NONE or BADVAL are the same for CAS cmd
               /*  mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
                c->thread->stats.slab_stats[ITEM_clsid(old_it)].cas_badval++;
                mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */

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
           /*  mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
            c->thread->stats.cas_misses++;
            mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */
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
            ocall_getErrno(&errno);
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
            ocall_getErrno(&errno);

            if (!update_event(c, EV_READ | EV_PERSIST))
            {
                printf("Failed to update event at conn_waiting >>>>>>>>>>>>>>>>>>>>\n");
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
            ocall_getErrno(&errno);
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
               /*  mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
                c->thread->stats.conn_yields++;
                mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */
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
                        ocall_getErrno(&errno);

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
                ocall_getErrno(&errno);
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

                ocall_getErrno(&errno);

                //printf("allocing item: tcp read rlbytes: %d read fd: %d res: %d ERRNO: %d >>>>>>>>>>>>>>>>>>>>>>>\n", c->rlbytes, c->sfd, res, errno);
                if (res > 0)
                {
                    /* mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
                    c->thread->stats.bytes_read += res;
                    mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */
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
            if (settings.verbose > 0 || true)
            {
                /*printf("Failed to read, and not due to blocking:\n"
                       "errno: %d %s \n"
                       "rcurr=%p ritem=%p rbuf=%p rlbytes=%d rsize=%d\n",
                       errno, strerror(errno),
                       (void *)c->rcurr, (void *)c->ritem, (void *)c->rbuf,
                       (int)c->rlbytes, (int)c->rsize);*/

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
            ocall_getErrno(&errno);

            if (res > 0)
            {
               /*  mcd_ocall_mutex_lock_lthread_stats(c->conn_id);
                c->thread->stats.bytes_read += res;
                mcd_ocall_mutex_unlock_lthread_stats(c->conn_id); */
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
            //abort();
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

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ECALL DEFINITIONS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

void ecall_init_hash()
{
    log_routine(__func__);
    enum hashfunc_type hash_type = MURMUR3_HASH;
    if (hash_init(hash_type) != 0)
    {
        fprintf(stderr, "Failed to initialize hash_algorithm!\n");
        exit(EX_USAGE);
    }
}

void ecall_stats_init()
{
    log_routine(__func__);
    stats_init();
}

void ecall_init_mainbase(void *mb)
{
    log_routine(__func__);
    main_base = (struct event_base *)mb;
}

void ecall_init_hashtable()
{
    log_routine(__func__);
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
    log_routine(__func__);
    assoc_maintenance_thread(NULL);
}

void ecall_start_item_crawler()
{
    log_routine(__func__);
    item_crawler_thread(NULL);
}

void ecall_start_slab_rebalance()
{
    log_routine(__func__);
    slab_rebalance_thread(NULL);
}

void ecall_assoc_start_expand()
{
    //log_routine(__func__);
    assoc_start_expand(stats_state.curr_items);
}

void ecall_init_server_sockets()
{
    log_routine(__func__);
    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>init server sockets>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

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
        SGX_FILE portnumber_file = -1;

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

        printf("portnumber SGX_FILE fd: %d >>>>>>>\n");
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

        if (portnumber_file != -1)
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
    //usleep(1000);
    if (stats_state.curr_conns + stats_state.reserved_fds >= settings.maxconns - 1)
    {
        fprintf(stderr, "Maxconns setting is too low, use -c to increase.\n");
        exit(EXIT_FAILURE);
    }

    if (pid_file != NULL)
    {
        save_pid(pid_file);
    }

    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>> stop server init >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
}

void ecall_init_globals(void *mb)
{
    log_routine(__func__);
    main_base = (struct event_base *)mb;
}

void ecall_drive_machine(void *ptr)
{
    log_routine(__func__);
    conn *c = (conn *)ptr;
    drive_machine(c);
}

void ecall_uriencode_init()
{
    log_routine(__func__);
    uriencode_init();
}

void ecall_conn_init()
{
    log_routine(__func__);
    conn_init();
}

void ecall_item_lru_bump_buf_create()
{
    log_routine(__func__);
    item_lru_bump_buf_create();
}

void ecall_thread_libevent_process(evutil_socket_t fd, short which, void *arg)
{
    log_routine(__func__);
    sgx_thread_libevent_process(fd, which, arg);
}

void *ecall_conn_new(int sfd, enum conn_states init_state,
                     int event_flags,
                     int read_buffer_size, enum network_transport transport,
                     struct event_base *base, void *ssl)
{
    log_routine(__func__);
    //pyuhala: not sure if this is very useful ?
    const int fd = sfd;
    const int flags = event_flags;
    const int bufsz = read_buffer_size;
    return (void *)conn_new(fd, init_state, flags, bufsz, transport, base, ssl);
}

void ecall_event_handler(const evutil_socket_t fd, const short which, void *arg)
{
    log_routine(__func__);
    const evutil_socket_t sfd = fd;
    const short wch = which;
    event_handler(sfd, wch, arg);
}

void ecall_conn_io_queue_add(void *conn_ptr, int type)
{
    log_routine(__func__);
    conn *c = (conn *)conn_ptr;
    //pyuhala: extstore disabled so all the rest will always be NULL
    conn_io_queue_add(c, type, NULL, NULL, NULL, NULL);
}

void ecall_set_conn_thread(void *conn_ptr, void *libevent_th)
{
    log_routine(__func__);
    conn *c = (conn *)conn_ptr;
    LIBEVENT_THREAD *lthread = (LIBEVENT_THREAD *)libevent_th;
    c->thread = lthread;
}