/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef CACHE_H
#define CACHE_H
#include <sgx_thread.h>

#ifndef NDEBUG
/* may be used for debug purposes */
extern int cache_error;
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

/**
 * Constructor used to initialize allocated objects
 *
 * @param obj pointer to the object to initialized.
 * @param notused1 This parameter is currently not used.
 * @param notused2 This parameter is currently not used.
 * @return you should return 0, but currently this is not checked
 */
typedef int cache_constructor_t(void* obj, void* notused1, int notused2);
/**
 * Destructor used to clean up allocated objects before they are
 * returned to the operating system.
 *
 * @param obj pointer to the object to clean up.
 * @param notused This parameter is currently not used.
 * @return you should return 0, but currently this is not checked
 */
typedef void cache_destructor_t(void* obj, void* notused);

/**
 * Definition of the structure to keep track of the internal details of
 * the cache allocator. Touching any of these variables results in
 * undefined behavior.
 */
typedef struct {
    /** Mutex to protect access to the structure */
    sgx_thread_mutex_t mutex;
    /** Name of the cache objects in this cache (provided by the caller) */
    char *name;
    /** List of pointers to available buffers in this cache */
    void **ptr;
    /** The size of each element in this cache */
    size_t bufsize;
    /** The capacity of the list of elements */
    int freetotal;
    /** Total malloc'ed objects */
    int total;
    /** The current number of free elements */
    int freecurr;
    /** A limit on the total number of elements */
    int limit;
    /** The constructor to be called each time we allocate more memory */
    cache_constructor_t* constructor;
    /** The destructor to be called each time before we release memory */
    cache_destructor_t* destructor;
} cache_t;

/**
 * Create an object cache.
 *
 * The object cache will let you allocate objects of the same size. It is fully
 * MT safe, so you may allocate objects from multiple threads without having to
 * do any synchronization in the application code.
 *
 * @param name the name of the object cache. This name may be used for debug purposes
 *             and may help you track down what kind of object you have problems with
 *             (buffer overruns, leakage etc)
 * @param bufsize the size of each object in the cache
 * @param align the alignment requirements of the objects in the cache.
 * @param constructor the function to be called to initialize memory when we need
 *                    to allocate more memory from the os.
 * @param destructor the function to be called before we release the memory back
 *                   to the os.
 * @return a handle to an object cache if successful, NULL otherwise.
 */
cache_t* cache_create(const char* name, size_t bufsize, size_t align,
                      cache_constructor_t* constructor,
                      cache_destructor_t* destructor);
/**
 * Destroy an object cache.
 *
 * Destroy and invalidate an object cache. You should return all buffers allocated
 * with cache_alloc by using cache_free before calling this function. Not doing
 * so results in undefined behavior (the buffers may or may not be invalidated)
 *
 * @param handle the handle to the object cache to destroy.
 */
void cache_destroy(cache_t* handle);
/**
 * Allocate an object from the cache.
 *
 * @param handle the handle to the object cache to allocate from
 * @return a pointer to an initialized object from the cache, or NULL if
 *         the allocation cannot be satisfied.
 */
void* cache_alloc(cache_t* handle);
void* do_cache_alloc(cache_t* handle);
/**
 * Return an object back to the cache.
 *
 * The caller should return the object in an initialized state so that
 * the object may be returned in an expected state from cache_alloc.
 *
 * @param handle handle to the object cache to return the object to
 * @param ptr pointer to the object to return.
 */
void cache_free(cache_t* handle, void* ptr);
void do_cache_free(cache_t* handle, void* ptr);
/**
 * Set or adjust a limit for the number of objects to malloc
 *
 * @param handle handle to the object cache to adjust
 * @param limit the number of objects to cache before returning NULL
 */
void cache_set_limit(cache_t* handle, int limit);


#if defined(__cplusplus)
}
#endif


#endif
