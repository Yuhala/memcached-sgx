/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Hash table
 *
 * The hash function used here is by Bob Jenkins, 1996:
 *    <http://burtleburtle.net/bob/hash/doobs.html>
 *       "By Bob Jenkins, 1996.  bob_jenkins@burtleburtle.net.
 *       You may use this code any way you wish, private, educational,
 *       or commercial.  It's free."
 *
 * The rest of the file is licensed under the BSD license.  See LICENSE.
 * PYuhala: the real hashtable is inside the enclave
 */

#include "memcached.h"
#include "memcached_sgx_out.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <signal.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "my_logger.h"

static pthread_cond_t maintenance_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t maintenance_lock = PTHREAD_MUTEX_INITIALIZER;

typedef uint32_t ub4;      /* unsigned 4-byte quantities */
typedef unsigned char ub1; /* unsigned 1-byte quantities */

/* how many powers of 2's worth of buckets we use */
unsigned int hashpower = HASHPOWER_DEFAULT;

#define hashsize(n) ((ub4)1 << (n))
#define hashmask(n) (hashsize(n) - 1)

/* Main hash table. This is where we look except during expansion. */
static item **primary_hashtable = 0;

/*
 * Previous hash table. During expansion, we look here for keys that haven't
 * been moved over to the primary yet.
 */
static item **old_hashtable = 0;

/* Flag: Are we in the middle of expanding now? */
static bool expanding = false;

static volatile int do_run_maintenance_thread = 1;

#define DEFAULT_HASH_BULK_MOVE 1
int hash_bulk_move = DEFAULT_HASH_BULK_MOVE;

static pthread_t maintenance_tid;

/**
 * pyuhala:
 * Start assoc maintenance thread. Since this thread operates on the memcached hashtable, 
 * we need it to perform an ecall into the enclave. 
 */

int sgx_start_assoc_maintenance_thread()
{
    log_routine(__func__);
    int ret;
    char *env = getenv("MEMCACHED_HASH_BULK_MOVE");
    if (env != NULL)
    {
        hash_bulk_move = atoi(env);
        if (hash_bulk_move == 0)
        {
            hash_bulk_move = DEFAULT_HASH_BULK_MOVE;
        }
    }

    if ((ret = pthread_create(&maintenance_tid, NULL,
                              e_assoc_maintenance_thread, NULL)) != 0)
    {
        fprintf(stderr, "Can't create thread: %s\n", strerror(ret));
        return -1;
    }
    return 0;
}

/**
 * Transition into the enclave for assoc maintenance.
 */
void *e_assoc_maintenance_thread(void *input){

    ecall_start_assoc_maintenance(global_eid);
}



void stop_assoc_maintenance_thread()
{
    log_routine(__func__);
    mutex_lock(&maintenance_lock);
    do_run_maintenance_thread = 0;
    pthread_cond_signal(&maintenance_cond);
    mutex_unlock(&maintenance_lock);

    /* Wait for the maintenance thread to stop */
    pthread_join(maintenance_tid, NULL);
}


