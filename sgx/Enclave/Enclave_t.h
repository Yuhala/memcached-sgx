#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"
#include "sgx_spinlock.h"
#include "sgx/sys/types.h"
#include "struct/sgx_stdio_struct.h"
#include "sgx/sys/types.h"
#include "struct/sgx_syssocket_struct.h"
#include "struct/sgx_arpainet_struct.h"
#include "sgx/sys/epoll.h"
#include "sgx/sys/poll.h"
#include "user_types.h"
#include "unistd.h"
#include "struct/sgx_pthread_struct.h"
#include "sgx/event.h"
#include "sgx/sys/types.h"
#include "mcd_types.h"
#include "sgx/sys/types.h"
#include "sgx/sys/stat.h"
#include "sgx/dirent.h"
#include "struct/sgx_time_struct.h"
#include "struct/sgx_pwd_struct.h"
#include "struct/sgx_sysresource_struct.h"
#include "struct/sgx_utsname_struct.h"
#include "sgx/netdb.h"
#include "sgx/sys/types.h"
#include "sgx/sys/stat.h"
#include "struct/sgx_sysstat_struct.h"
#include "struct/sgx_time_struct.h"
#include "struct/sgx_pwd_struct.h"
#include "struct/sgx_sysresource_struct.h"
#include "struct/sgx_utsname_struct.h"
#include "sgx/event2/util.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

typedef enum buffer_status {
	BUFFER_UNUSED,
	BUFFER_RESERVED,
	BUFFER_WAITING,
	BUFFER_PROCESSED,
	BUFFER_PAUSED,
	BUFFER_EXIT,
} buffer_status;

#ifndef _buffer
#define _buffer
typedef struct buffer {
	void* ocall_handler_switchless;
	void* ocall_handler;
	sgx_spinlock_t spinlock;
	int status;
	pid_t caller_tid;
	size_t args_size;
	void* args;
	size_t ret_size;
	void* ret;
} buffer;
#endif

typedef enum fn_token {
	FN_TOKEN_EMPTY,
	FN_TOKEN_SLEEP,
	FN_TOKEN_FSYNC,
	FN_TOKEN_DUP2,
	FN_TOKEN_CLOSE,
	FN_TOKEN_FWRITE,
	FN_TOKEN_PUTS,
	FN_TOKEN_UNLINK,
	FN_TOKEN_RMDIR,
	FN_TOKEN_REMOVE,
	FN_TOKEN_READ,
	FN_TOKEN_WRITE,
	FN_TOKEN_LSEEK64,
	FN_TOKEN_TOTAL_SIZE,
} fn_token;

void ecall_graal_main_args(int id, int arg1, struct buffer* switchless_buffers, struct buffer* switchless_buffer, void** sl_fn, void** fn, int* sl_count, int* f_count, int* number_of_workers);
void ecall_graal_main(int id, struct buffer* switchless_buffers, struct buffer* switchless_buffer, void** sl_fn, void** fn, int* sl_count, int* f_count, int* number_of_workers);
void ecall_run_main(int id);
void ecall_reader(int n, int id, struct buffer* switchless_buffers, struct buffer* switchless_buffer, void** sl_fn, void** fn, int* sl_count, int* f_count, int* number_of_workers);
void ecall_writer(int n, int id, struct buffer* switchless_buffers, struct buffer* switchless_buffer, void** sl_fn, void** fn, int* sl_count, int* f_count, int* number_of_workers);
void ecall_bench_thread(struct buffer* bs, struct buffer* b, void** sl_fn, void** fn, int* sl_count, int* f_count, int* number_of_workers);
void ecall_readN(int n);
void ecall_writeN(int n);
void ecall_kissdb_test(void);
void ecall_readKissdb(int n, int storeId);
void ecall_writeKissdb(int n, int storeId);
void ecall_test(void);
void ecall_execute_job(pthread_t pthread_self_id, unsigned long int job_id);
void ecall_init_settings(void);
void ecall_init_hash(void);
void ecall_stats_init(void);
void ecall_init_hashtable(void);
void ecall_start_assoc_maintenance(void);
void ecall_start_item_crawler(void);
void ecall_start_slab_rebalance(void);
void ecall_assoc_start_expand(void);
void ecall_init_server_sockets(void);
void ecall_init_mainbase(void* mb);
void ecall_drive_machine(void* conn);
void ecall_uriencode_init(void);
void ecall_conn_init(void);
void ecall_item_lru_bump_buf_create(void);
void ecall_thread_libevent_process(evutil_socket_t fd, short int which, void* arg);
void ecall_event_handler(evutil_socket_t fd, short int which, void* arg);
void* ecall_conn_new(int sfd, enum conn_states init_state, int flags, int rd_buff_sz, enum network_transport tport, struct event_base* base, void* ssl);
void ecall_conn_io_queue_add(void* c, int type);
void ecall_set_conn_thread(void* c, void* libevent_thread);

sgx_status_t SGX_CDECL ocall_malloc(void** retval, size_t size);
sgx_status_t SGX_CDECL ocall_realloc(void** retval, void* ptr, size_t size);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_gettid(long int* retval);
sgx_status_t SGX_CDECL ocall_bench(void);
sgx_status_t SGX_CDECL ocall_empty(int repeats);
sgx_status_t SGX_CDECL ocall_fsync(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_dup2(int* retval, int oldfd, int newfd);
sgx_status_t SGX_CDECL ocall_open(int* retval, const char* path, int oflag, int arg);
sgx_status_t SGX_CDECL ocall_open64(int* retval, const char* path, int oflag, int arg);
sgx_status_t SGX_CDECL ocall_xclose(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_lseek(off_t* retval, int fd, off_t offset, int whence);
sgx_status_t SGX_CDECL ocall_lseek64(off64_t* retval, int fd, off64_t offset, int whence);
sgx_status_t SGX_CDECL ocall_fflush(int* retval, SGX_FILE* stream);
sgx_status_t SGX_CDECL ocall_pread(ssize_t* retval, int fd, void* buf, size_t count, off_t offset);
sgx_status_t SGX_CDECL ocall_pread64(ssize_t* retval, int fd, void* buf, size_t count, off64_t offset);
sgx_status_t SGX_CDECL ocall_pwrite(ssize_t* retval, int fd, const void* buf, size_t count, off_t offset);
sgx_status_t SGX_CDECL ocall_fopen(SGX_FILE* retval, const char* filename, const char* mode);
sgx_status_t SGX_CDECL ocall_fdopen(SGX_FILE* retval, int fd, const char* mode);
sgx_status_t SGX_CDECL ocall_fclose(int* retval, SGX_FILE stream);
sgx_status_t SGX_CDECL ocall_fwrite(size_t* retval, const void* ptr, size_t size, size_t nmemb, SGX_FILE stream);
sgx_status_t SGX_CDECL ocall_fread(size_t* retval, void* ptr, size_t size, size_t nmemb, SGX_FILE stream);
sgx_status_t SGX_CDECL ocall_fseeko(int* retval, SGX_FILE file, off_t offset, int whence);
sgx_status_t SGX_CDECL ocall_ftello(off_t* retval, SGX_FILE file);
sgx_status_t SGX_CDECL ocall_read(ssize_t* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_write(ssize_t* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_fscanf(int* retval, SGX_FILE stream, const char* format);
sgx_status_t SGX_CDECL ocall_fprintf(int* retval, SGX_FILE stream, const char* str);
sgx_status_t SGX_CDECL ocall_fgets(char* str, int n, SGX_FILE stream);
sgx_status_t SGX_CDECL ocall_stderr(SGX_FILE* retval);
sgx_status_t SGX_CDECL ocall_puts(int* retval, const char* str);
sgx_status_t SGX_CDECL ocall_getchar(int* retval);
sgx_status_t SGX_CDECL ocall_mkdir(int* retval, const char* pathname, mode_t mode);
sgx_status_t SGX_CDECL ocall_truncate(int* retval, const char* path, off_t length);
sgx_status_t SGX_CDECL ocall_ftruncate64(int* retval, int fd, off_t length);
sgx_status_t SGX_CDECL ocall_mmap64(void** retval, void* addr, size_t len, int prot, int flags, int fildes, off_t off);
sgx_status_t SGX_CDECL ocall_pwrite64(ssize_t* retval, int fd, const void* buf, size_t nbyte, off_t offset);
sgx_status_t SGX_CDECL ocall_fdatasync(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_rename(int* retval, const char* oldpath, const char* newpath);
sgx_status_t SGX_CDECL ocall_unlink(int* retval, const char* pathname);
sgx_status_t SGX_CDECL ocall_rmdir(int* retval, const char* pathname);
sgx_status_t SGX_CDECL ocall_times(clock_t* retval);
sgx_status_t SGX_CDECL ocall_chown(int* retval, const char* pathname, uid_t owner, gid_t group);
sgx_status_t SGX_CDECL ocall_fchown(int* retval, int fd, uid_t owner, gid_t group);
sgx_status_t SGX_CDECL ocall_lchown(int* retval, const char* pathname, uid_t owner, gid_t group);
sgx_status_t SGX_CDECL ocall_chmod(int* retval, const char* pathname, mode_t mode);
sgx_status_t SGX_CDECL ocall_fchmod(int* retval, int fd, mode_t mode);
sgx_status_t SGX_CDECL ocall_lxstat64(int* retval, int ver, const char* path, struct stat* stat_buf);
sgx_status_t SGX_CDECL ocall_fcntl(int* retval, int fildes, int cmd, int arg);
sgx_status_t SGX_CDECL ocall_ioctl(int* retval, int fd, unsigned long int request, int arg);
sgx_status_t SGX_CDECL ocall_xstat64(int* retval, int ver, const char* path, struct stat* stat_buf);
sgx_status_t SGX_CDECL ocall_stat(int* retval, const char* path, struct stat* buf);
sgx_status_t SGX_CDECL ocall_fstat(int* retval, int fd, struct stat* buf);
sgx_status_t SGX_CDECL ocall_lstat(int* retval, const char* path, struct stat* buf);
sgx_status_t SGX_CDECL ocall_fstat64(int* retval, int fd, struct stat* buf);
sgx_status_t SGX_CDECL ocall_fxstat64(int* retval, int ver, int fildes, struct stat* stat_buf);
sgx_status_t SGX_CDECL ocall_fxstat(int* retval, int ver, int fd, struct stat* stat_buf);
sgx_status_t SGX_CDECL ocall_lxstat(int* retval, int ver, const char* path, struct stat* stat_buf);
sgx_status_t SGX_CDECL ocall_xstat(int* retval, int ver, const char* path, struct stat* stat_buf);
sgx_status_t SGX_CDECL ocall_pathconf(long int* retval, const char* path, int name);
sgx_status_t SGX_CDECL ocall_readlink(ssize_t* retval, const char* pathname, char* buf, size_t bufsiz);
sgx_status_t SGX_CDECL ocall_readdir64_r(int* retval, void* dirp, void* entry, struct dirent** result);
sgx_status_t SGX_CDECL ocall_opendir(void** retval, const char* name);
sgx_status_t SGX_CDECL ocall_chdir(int* retval, const char* path);
sgx_status_t SGX_CDECL ocall_closedir(int* retval, void* dirp);
sgx_status_t SGX_CDECL ocall_xmknod(int* retval, int vers, const char* path, mode_t mode, dev_t* dev);
sgx_status_t SGX_CDECL ocall_symlink(int* retval, const char* target, const char* linkpath);
sgx_status_t SGX_CDECL ocall_deflateEnd(int* retval, z_streamp stream);
sgx_status_t SGX_CDECL ocall_deflateParams(int* retval, z_streamp stream, int level, int strategy);
sgx_status_t SGX_CDECL ocall_deflate(int* retval, z_streamp stream, int flush);
sgx_status_t SGX_CDECL ocall_deflateInit2(int* retval, z_streamp stream, int level, int method, int windowBits, int memLevel, int strategy);
sgx_status_t SGX_CDECL ocall_inflateReset(int* retval, z_streamp stream);
sgx_status_t SGX_CDECL ocall_sendfile64(ssize_t* retval, int out_fd, int in_fd, off_t* offset, size_t count);
sgx_status_t SGX_CDECL ocall_adler32(ulong* retval, ulong adler, const Bytef* buf, size_t len);
sgx_status_t SGX_CDECL ocall_getenv(char** retval, const char* name);
sgx_status_t SGX_CDECL ocall_fileno(int* retval, SGX_FILE* stream);
sgx_status_t SGX_CDECL ocall_isatty(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_umask(mode_t* retval, mode_t mask);
sgx_status_t SGX_CDECL ocall_fputc(int* retval, int c, SGX_FILE stream);
sgx_status_t SGX_CDECL ocall_putc(int* retval, int c, SGX_FILE stream);
sgx_status_t SGX_CDECL ocall_socket(int* retval, int domain, int type, int protocol);
sgx_status_t SGX_CDECL ocall_getsockname(int* retval, int sockfd, struct sockaddr* addr, socklen_t* addrlen);
sgx_status_t SGX_CDECL ocall_getaddrinfo(int* retval, const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res);
sgx_status_t SGX_CDECL ocall_getnameinfo(int* retval, const struct sockaddr* addr, socklen_t addrlen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags);
sgx_status_t SGX_CDECL ocall_freeaddrinfo(struct addrinfo* res);
sgx_status_t SGX_CDECL ocall_gethostname(int* retval, char* name, size_t namelen);
sgx_status_t SGX_CDECL ocall_sethostname(int* retval, const char* name, size_t len);
sgx_status_t SGX_CDECL ocall_gettimeofday(int* retval, void* tv, int tv_size);
sgx_status_t SGX_CDECL ocall_clock_gettime(int* retval, clockid_t clk_id, void* tp, int ts_size);
sgx_status_t SGX_CDECL ocall_inet_pton(int* retval, int af, const char* src, void* dst);
sgx_status_t SGX_CDECL ocall_getpid(pid_t* retval);
sgx_status_t SGX_CDECL ocall_remove(int* retval, const char* pathname);
sgx_status_t SGX_CDECL ocall_shutdown(int* retval, int sockfd, int how);
sgx_status_t SGX_CDECL ocall_getsockopt(int* retval, int socket, int level, int option_name, void* option_value, socklen_t* option_len);
sgx_status_t SGX_CDECL ocall_setsockopt(int* retval, int socket, int level, int option_name, const void* option_value, socklen_t option_len);
sgx_status_t SGX_CDECL ocall_socketpair(int* retval, int domain, int type, int protocol, int* sv);
sgx_status_t SGX_CDECL ocall_bind(int* retval, int socket, const void* address, socklen_t address_len);
sgx_status_t SGX_CDECL ocall_epoll_wait(int* retval, int epfd, struct epoll_event* events, int maxevents, int timeout);
sgx_status_t SGX_CDECL ocall_epoll_ctl(int* retval, int epfd, int op, int fd, struct epoll_event* event);
sgx_status_t SGX_CDECL ocall_readv(ssize_t* retval, int fd, const struct iovec* iov, int iovcnt);
sgx_status_t SGX_CDECL ocall_writev(ssize_t* retval, int fd, const struct iovec* iov, int iovcnt);
sgx_status_t SGX_CDECL ocall_pipe(int* retval, int* pipefd);
sgx_status_t SGX_CDECL ocall_connect(int* retval, int sockfd, const void* addr, socklen_t addrlen);
sgx_status_t SGX_CDECL ocall_listen(int* retval, int socket, int backlog);
sgx_status_t SGX_CDECL ocall_accept(int* retval, int socket, struct sockaddr* address, socklen_t* address_len);
sgx_status_t SGX_CDECL ocall_accept4(int* retval, int socket, struct sockaddr* address, socklen_t* address_len, int flags);
sgx_status_t SGX_CDECL ocall_poll(int* retval, struct pollfd* fds, nfds_t nfds, int timeout);
sgx_status_t SGX_CDECL ocall_epoll_create(int* retval, int size);
sgx_status_t SGX_CDECL ocall_getpeername(int* retval, int sockfd, struct sockaddr* addr, socklen_t* addrlen);
sgx_status_t SGX_CDECL ocall_recv(ssize_t* retval, int sockfd, void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_send(ssize_t* retval, int sockfd, const void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_sendto(ssize_t* retval, int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);
sgx_status_t SGX_CDECL ocall_sendmsg(ssize_t* retval, int sockfd, struct msghdr* msg, int flags);
sgx_status_t SGX_CDECL ocall_recvfrom(ssize_t* retval, int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
sgx_status_t SGX_CDECL ocall_recvmsg(ssize_t* retval, int sockfd, struct msghdr* msg, int flags);
sgx_status_t SGX_CDECL ocall_htonl(uint32_t* retval, uint32_t hostlong);
sgx_status_t SGX_CDECL ocall_htons(uint16_t* retval, uint16_t hostshort);
sgx_status_t SGX_CDECL ocall_ntohl(uint32_t* retval, uint32_t netlong);
sgx_status_t SGX_CDECL ocall_ntohs(uint16_t* retval, uint16_t netshort);
sgx_status_t SGX_CDECL ocall_time(time_t* retval, time_t* t);
sgx_status_t SGX_CDECL ocall_inet_ntop(char** retval, int af, const void* src, char* dst, socklen_t len);
sgx_status_t SGX_CDECL ocall_dlsym(void* handle, const char* symbol, void* res);
sgx_status_t SGX_CDECL ocall_dlopen(void** retval, const char* symbol, int flag);
sgx_status_t SGX_CDECL ocall_sysconf(long int* retval, int name);
sgx_status_t SGX_CDECL ocall_getuid(int* retval);
sgx_status_t SGX_CDECL ocall_geteuid(int* retval);
sgx_status_t SGX_CDECL ocall_getcwd(char* buf, size_t len);
sgx_status_t SGX_CDECL ocall_getpwuid(uid_t uid, struct passwd* ret);
sgx_status_t SGX_CDECL ocall_exit(int stat);
sgx_status_t SGX_CDECL ocall_getrlimit(int* retval, int res, struct rlimit* rlim);
sgx_status_t SGX_CDECL ocall_setrlimit(int* retval, int resource, struct rlimit* rlim);
sgx_status_t SGX_CDECL ocall_uname(int* retval, struct utsname* buf);
sgx_status_t SGX_CDECL ocall_sleep(unsigned int* retval, unsigned int secs);
sgx_status_t SGX_CDECL ocall_usleep(int* retval, useconds_t usec);
sgx_status_t SGX_CDECL ocall_realpath(const char* path, char* res_path);
sgx_status_t SGX_CDECL ocall_xpg_strerror_r(int errnum, char* buf, size_t buflen);
sgx_status_t SGX_CDECL ocall_signal(__sighandler_t* retval, int signum, __sighandler_t handler);
sgx_status_t SGX_CDECL ocall_kill(int* retval, pid_t pid, int sig);
sgx_status_t SGX_CDECL ocall_get_cpuid_max(unsigned int* retval, unsigned int ext, unsigned int* sig);
sgx_status_t SGX_CDECL ocall_get_cpuid_count(int* retval, unsigned int leaf, unsigned int subleaf, unsigned int* eax, unsigned int* ebx, unsigned int* ecx, unsigned int* edx);
sgx_status_t SGX_CDECL ocall_pthread_attr_init(int* retval);
sgx_status_t SGX_CDECL ocall_pthread_create(int* retval, pthread_t* new_thread, unsigned long int job_id, sgx_enclave_id_t eid);
sgx_status_t SGX_CDECL ocall_pthread_self(pthread_t* retval);
sgx_status_t SGX_CDECL ocall_pthread_join(int* retval, pthread_t pt, void** res);
sgx_status_t SGX_CDECL ocall_pthread_attr_getguardsize(int* retval, size_t* guardsize);
sgx_status_t SGX_CDECL ocall_pthread_attr_getguardsize__bypass(int* retval, void* attr, size_t attr_len, size_t* guardsize);
sgx_status_t SGX_CDECL ocall_pthread_attr_destroy(int* retval);
sgx_status_t SGX_CDECL ocall_pthread_condattr_setclock(int* retval, void* attr, clockid_t clock_id, size_t attr_len);
sgx_status_t SGX_CDECL ocall_pthread_attr_destroy__bypass(int* retval, void* attr, size_t attr_len);
sgx_status_t SGX_CDECL ocall_pthread_attr_getstack(int* retval, void** stk_addr, size_t* stack_size);
sgx_status_t SGX_CDECL ocall_pthread_attr_getstack__bypass(int* retval, void* attr, size_t attr_len, void** stk_addr, size_t len, size_t* stack_size);
sgx_status_t SGX_CDECL ocall_pthread_getattr_np(int* retval, pthread_t tid);
sgx_status_t SGX_CDECL ocall_pthread_getattr_np__bypass(int* retval, pthread_t tid, void* attr, size_t len);
sgx_status_t SGX_CDECL ocall_event_del(int* retval, struct event* ev);
sgx_status_t SGX_CDECL ocall_event_base_set(int* retval, struct event_base* evb, struct event* ev);
sgx_status_t SGX_CDECL ocall_event_add(int* retval, struct event* ev, const struct timeval* timeout);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);
sgx_status_t SGX_CDECL mcd_ocall_setup_conn_event(int* retval, int fd, int event_flags, struct event_base* base, void* c, int conn_id);
sgx_status_t SGX_CDECL mcd_ocall_update_conn_event(int fd, int event_flags, struct event_base* base, void* c, int conn_id);
sgx_status_t SGX_CDECL mcd_ocall_event_base_loopexit(void);
sgx_status_t SGX_CDECL mcd_ocall_event_del(int* retval, int conn_id);
sgx_status_t SGX_CDECL mcd_ocall_event_add(int* retval, int conn_id);
sgx_status_t SGX_CDECL mcd_ocall_dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags, int read_buffer_size, enum network_transport transport, void* ssl);
sgx_status_t SGX_CDECL mcd_ocall_do_cache_alloc(void** retval, int conn_id, int lvt_thread_id);
sgx_status_t SGX_CDECL mcd_ocall_do_cache_free(int conn_id, int lvt_thread_id, void* bundle);
sgx_status_t SGX_CDECL mcd_ocall_mutex_lock_lthread_stats(int conn_id);
sgx_status_t SGX_CDECL mcd_ocall_mutex_unlock_lthread_stats(int conn_id);
sgx_status_t SGX_CDECL ocall_transmit_prepare(void** retval);
sgx_status_t SGX_CDECL ocall_getErrno(int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
