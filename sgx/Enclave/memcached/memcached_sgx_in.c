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