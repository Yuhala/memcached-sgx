#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

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
#include "sgx/sys/stat.h"
#include "struct/sgx_sysstat_struct.h"

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
	FN_TOKEN_SENDMSG,
	FN_TOKEN_TRANSMIT_PREPARE,
	FN_TOKEN_TOTAL_SIZE,
} fn_token;

#ifndef OCALL_FREE_REALLOCATE_POOL_DEFINED__
#define OCALL_FREE_REALLOCATE_POOL_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_free_reallocate_pool, (unsigned int pool_id));
#endif
#ifndef OCALL_MALLOC_DEFINED__
#define OCALL_MALLOC_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_malloc, (size_t size));
#endif
#ifndef OCALL_REALLOC_DEFINED__
#define OCALL_REALLOC_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_realloc, (void* ptr, size_t size));
#endif
#ifndef OCALL_MEMSYS5_REALLOC_DEFINED__
#define OCALL_MEMSYS5_REALLOC_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_memsys5_realloc, (void* old_pool, int pool_id));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_GETTID_DEFINED__
#define OCALL_GETTID_DEFINED__
long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gettid, (void));
#endif
#ifndef OCALL_BENCH_DEFINED__
#define OCALL_BENCH_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_bench, (void));
#endif
#ifndef U_SGXSSL_FTIME_DEFINED__
#define U_SGXSSL_FTIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
#define PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wait_timeout_ocall, (unsigned long long waiter, unsigned long long timeout));
#endif
#ifndef PTHREAD_CREATE_OCALL_DEFINED__
#define PTHREAD_CREATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_create_ocall, (unsigned long long self));
#endif
#ifndef PTHREAD_WAKEUP_OCALL_DEFINED__
#define PTHREAD_WAKEUP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wakeup_ocall, (unsigned long long waiter));
#endif
#ifndef OCALL_EMPTY_DEFINED__
#define OCALL_EMPTY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_empty, (int repeats));
#endif
#ifndef OCALL_FSYNC_DEFINED__
#define OCALL_FSYNC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fsync, (int fd));
#endif
#ifndef OCALL_MSYNC_DEFINED__
#define OCALL_MSYNC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_msync, (void* addr, size_t length, int flags));
#endif
#ifndef OCALL_SYNC_DEFINED__
#define OCALL_SYNC_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sync, (void));
#endif
#ifndef OCALL_SYNCFS_DEFINED__
#define OCALL_SYNCFS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_syncfs, (int fd));
#endif
#ifndef OCALL_DUP2_DEFINED__
#define OCALL_DUP2_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_dup2, (int oldfd, int newfd));
#endif
#ifndef OCALL_OPEN_DEFINED__
#define OCALL_OPEN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open, (const char* path, int oflag, int arg));
#endif
#ifndef OCALL_OPEN64_DEFINED__
#define OCALL_OPEN64_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open64, (const char* path, int oflag, int arg));
#endif
#ifndef OCALL_XCLOSE_DEFINED__
#define OCALL_XCLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_xclose, (int fd));
#endif
#ifndef OCALL_LSEEK_DEFINED__
#define OCALL_LSEEK_DEFINED__
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lseek, (int fd, off_t offset, int whence));
#endif
#ifndef OCALL_LSEEK64_DEFINED__
#define OCALL_LSEEK64_DEFINED__
off64_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lseek64, (int fd, off64_t offset, int whence));
#endif
#ifndef OCALL_FFLUSH_DEFINED__
#define OCALL_FFLUSH_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fflush, (SGX_FILE* stream));
#endif
#ifndef OCALL_PREAD_DEFINED__
#define OCALL_PREAD_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pread, (int fd, void* buf, size_t count, off_t offset));
#endif
#ifndef OCALL_PREAD64_DEFINED__
#define OCALL_PREAD64_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pread64, (int fd, void* buf, size_t count, off64_t offset));
#endif
#ifndef OCALL_PWRITE_DEFINED__
#define OCALL_PWRITE_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pwrite, (int fd, const void* buf, size_t count, off_t offset));
#endif
#ifndef OCALL_FOPEN_DEFINED__
#define OCALL_FOPEN_DEFINED__
SGX_FILE SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fopen, (const char* filename, const char* mode));
#endif
#ifndef OCALL_FDOPEN_DEFINED__
#define OCALL_FDOPEN_DEFINED__
SGX_FILE SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fdopen, (int fd, const char* mode));
#endif
#ifndef OCALL_FCLOSE_DEFINED__
#define OCALL_FCLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fclose, (SGX_FILE stream));
#endif
#ifndef OCALL_FWRITE_DEFINED__
#define OCALL_FWRITE_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fwrite, (const void* ptr, size_t size, size_t nmemb, SGX_FILE stream));
#endif
#ifndef OCALL_FREAD_DEFINED__
#define OCALL_FREAD_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fread, (void* ptr, size_t size, size_t nmemb, SGX_FILE stream));
#endif
#ifndef OCALL_FSEEKO_DEFINED__
#define OCALL_FSEEKO_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fseeko, (SGX_FILE file, off_t offset, int whence));
#endif
#ifndef OCALL_FTELLO_DEFINED__
#define OCALL_FTELLO_DEFINED__
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftello, (SGX_FILE file));
#endif
#ifndef OCALL_READ_DEFINED__
#define OCALL_READ_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read, (int fd, void* buf, size_t count));
#endif
#ifndef OCALL_WRITE_DEFINED__
#define OCALL_WRITE_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write, (int fd, const void* buf, size_t count));
#endif
#ifndef OCALL_FSCANF_DEFINED__
#define OCALL_FSCANF_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fscanf, (SGX_FILE stream, const char* format));
#endif
#ifndef OCALL_FPRINTF_DEFINED__
#define OCALL_FPRINTF_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fprintf, (SGX_FILE stream, const char* str));
#endif
#ifndef OCALL_FGETS_DEFINED__
#define OCALL_FGETS_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fgets, (char* str, int n, SGX_FILE stream));
#endif
#ifndef OCALL_STDERR_DEFINED__
#define OCALL_STDERR_DEFINED__
SGX_FILE SGX_UBRIDGE(SGX_NOCONVENTION, ocall_stderr, (void));
#endif
#ifndef OCALL_PUTS_DEFINED__
#define OCALL_PUTS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_puts, (const char* str));
#endif
#ifndef OCALL_GETCHAR_DEFINED__
#define OCALL_GETCHAR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getchar, (void));
#endif
#ifndef OCALL_MKDIR_DEFINED__
#define OCALL_MKDIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mkdir, (const char* pathname, mode_t mode));
#endif
#ifndef OCALL_TRUNCATE_DEFINED__
#define OCALL_TRUNCATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_truncate, (const char* path, off_t length));
#endif
#ifndef OCALL_FTRUNCATE64_DEFINED__
#define OCALL_FTRUNCATE64_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftruncate64, (int fd, off_t length));
#endif
#ifndef OCALL_MMAP64_DEFINED__
#define OCALL_MMAP64_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mmap64, (void* addr, size_t len, int prot, int flags, int fildes, off_t off));
#endif
#ifndef OCALL_PWRITE64_DEFINED__
#define OCALL_PWRITE64_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pwrite64, (int fd, const void* buf, size_t nbyte, off_t offset));
#endif
#ifndef OCALL_FDATASYNC_DEFINED__
#define OCALL_FDATASYNC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fdatasync, (int fd));
#endif
#ifndef OCALL_RENAME_DEFINED__
#define OCALL_RENAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_rename, (const char* oldpath, const char* newpath));
#endif
#ifndef OCALL_UNLINK_DEFINED__
#define OCALL_UNLINK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_unlink, (const char* pathname));
#endif
#ifndef OCALL_RMDIR_DEFINED__
#define OCALL_RMDIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_rmdir, (const char* pathname));
#endif
#ifndef OCALL_TIMES_DEFINED__
#define OCALL_TIMES_DEFINED__
clock_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_times, (void));
#endif
#ifndef OCALL_CHOWN_DEFINED__
#define OCALL_CHOWN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_chown, (const char* pathname, uid_t owner, gid_t group));
#endif
#ifndef OCALL_FCHOWN_DEFINED__
#define OCALL_FCHOWN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fchown, (int fd, uid_t owner, gid_t group));
#endif
#ifndef OCALL_LCHOWN_DEFINED__
#define OCALL_LCHOWN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lchown, (const char* pathname, uid_t owner, gid_t group));
#endif
#ifndef OCALL_CHMOD_DEFINED__
#define OCALL_CHMOD_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_chmod, (const char* pathname, mode_t mode));
#endif
#ifndef OCALL_FCHMOD_DEFINED__
#define OCALL_FCHMOD_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fchmod, (int fd, mode_t mode));
#endif
#ifndef OCALL_LXSTAT64_DEFINED__
#define OCALL_LXSTAT64_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lxstat64, (int ver, const char* path, struct stat* stat_buf));
#endif
#ifndef OCALL_FCNTL_DEFINED__
#define OCALL_FCNTL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl, (int fildes, int cmd, int arg));
#endif
#ifndef OCALL_FCNTL1_DEFINED__
#define OCALL_FCNTL1_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl1, (int fd, int cmd));
#endif
#ifndef OCALL_FCNTL2_DEFINED__
#define OCALL_FCNTL2_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl2, (int fd, int cmd, long int arg));
#endif
#ifndef OCALL_FCNTL3_DEFINED__
#define OCALL_FCNTL3_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl3, (int fd, int cmd, void* arg, int flock_size));
#endif
#ifndef OCALL_IOCTL_DEFINED__
#define OCALL_IOCTL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ioctl, (int fd, unsigned long int request, int arg));
#endif
#ifndef OCALL_XSTAT64_DEFINED__
#define OCALL_XSTAT64_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_xstat64, (int ver, const char* path, struct stat* stat_buf));
#endif
#ifndef OCALL_STAT_DEFINED__
#define OCALL_STAT_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_stat, (const char* path, int* stat_ret));
#endif
#ifndef OCALL_FSTAT_DEFINED__
#define OCALL_FSTAT_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fstat, (int fd, int* fstat_ret));
#endif
#ifndef OCALL_LSTAT_DEFINED__
#define OCALL_LSTAT_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lstat, (const char* path, int* lstat_ret));
#endif
#ifndef OCALL_FSTAT64_DEFINED__
#define OCALL_FSTAT64_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fstat64, (int fd, int* fstat_ret));
#endif
#ifndef OCALL_FXSTAT64_DEFINED__
#define OCALL_FXSTAT64_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fxstat64, (int ver, int fildes, struct stat* stat_buf));
#endif
#ifndef OCALL_FXSTAT_DEFINED__
#define OCALL_FXSTAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fxstat, (int ver, int fd, struct stat* stat_buf));
#endif
#ifndef OCALL_LXSTAT_DEFINED__
#define OCALL_LXSTAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lxstat, (int ver, const char* path, struct stat* stat_buf));
#endif
#ifndef OCALL_XSTAT_DEFINED__
#define OCALL_XSTAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_xstat, (int ver, const char* path, struct stat* stat_buf));
#endif
#ifndef OCALL_PATHCONF_DEFINED__
#define OCALL_PATHCONF_DEFINED__
long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pathconf, (const char* path, int name));
#endif
#ifndef OCALL_READLINK_DEFINED__
#define OCALL_READLINK_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readlink, (const char* pathname, char* buf, size_t bufsiz));
#endif
#ifndef OCALL_READDIR64_R_DEFINED__
#define OCALL_READDIR64_R_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readdir64_r, (void* dirp, void* entry, struct dirent** result));
#endif
#ifndef OCALL_OPENDIR_DEFINED__
#define OCALL_OPENDIR_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_opendir, (const char* name));
#endif
#ifndef OCALL_CHDIR_DEFINED__
#define OCALL_CHDIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_chdir, (const char* path));
#endif
#ifndef OCALL_CLOSEDIR_DEFINED__
#define OCALL_CLOSEDIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closedir, (void* dirp));
#endif
#ifndef OCALL_XMKNOD_DEFINED__
#define OCALL_XMKNOD_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_xmknod, (int vers, const char* path, mode_t mode, dev_t* dev));
#endif
#ifndef OCALL_SYMLINK_DEFINED__
#define OCALL_SYMLINK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_symlink, (const char* target, const char* linkpath));
#endif
#ifndef OCALL_DEFLATEEND_DEFINED__
#define OCALL_DEFLATEEND_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_deflateEnd, (z_streamp stream));
#endif
#ifndef OCALL_DEFLATEPARAMS_DEFINED__
#define OCALL_DEFLATEPARAMS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_deflateParams, (z_streamp stream, int level, int strategy));
#endif
#ifndef OCALL_DEFLATE_DEFINED__
#define OCALL_DEFLATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_deflate, (z_streamp stream, int flush));
#endif
#ifndef OCALL_DEFLATEINIT2_DEFINED__
#define OCALL_DEFLATEINIT2_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_deflateInit2, (z_streamp stream, int level, int method, int windowBits, int memLevel, int strategy));
#endif
#ifndef OCALL_INFLATERESET_DEFINED__
#define OCALL_INFLATERESET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_inflateReset, (z_streamp stream));
#endif
#ifndef OCALL_SENDFILE64_DEFINED__
#define OCALL_SENDFILE64_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sendfile64, (int out_fd, int in_fd, off_t* offset, size_t count));
#endif
#ifndef OCALL_ADLER32_DEFINED__
#define OCALL_ADLER32_DEFINED__
ulong SGX_UBRIDGE(SGX_NOCONVENTION, ocall_adler32, (ulong adler, const Bytef* buf, size_t len));
#endif
#ifndef OCALL_GETENV_DEFINED__
#define OCALL_GETENV_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getenv, (const char* name));
#endif
#ifndef OCALL_FILENO_DEFINED__
#define OCALL_FILENO_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fileno, (SGX_FILE* stream));
#endif
#ifndef OCALL_ISATTY_DEFINED__
#define OCALL_ISATTY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_isatty, (int fd));
#endif
#ifndef OCALL_UMASK_DEFINED__
#define OCALL_UMASK_DEFINED__
mode_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_umask, (mode_t mask));
#endif
#ifndef OCALL_FPUTC_DEFINED__
#define OCALL_FPUTC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fputc, (int c, SGX_FILE stream));
#endif
#ifndef OCALL_PUTC_DEFINED__
#define OCALL_PUTC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_putc, (int c, SGX_FILE stream));
#endif
#ifndef OCALL_TEST_DEFINED__
#define OCALL_TEST_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_test, (int a, int b));
#endif
#ifndef OCALL_F_DEFINED__
#define OCALL_F_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_f, (void));
#endif
#ifndef OCALL_G_DEFINED__
#define OCALL_G_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_g, (void));
#endif
#ifndef OCALL_SOCKET_DEFINED__
#define OCALL_SOCKET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_socket, (int domain, int type, int protocol));
#endif
#ifndef OCALL_GETSOCKNAME_DEFINED__
#define OCALL_GETSOCKNAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getsockname, (int sockfd, struct sockaddr* addr, socklen_t* addrlen));
#endif
#ifndef OCALL_GETADDRINFO_DEFINED__
#define OCALL_GETADDRINFO_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getaddrinfo, (const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res));
#endif
#ifndef OCALL_GETNAMEINFO_DEFINED__
#define OCALL_GETNAMEINFO_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getnameinfo, (const struct sockaddr* addr, socklen_t addrlen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags));
#endif
#ifndef OCALL_FREEADDRINFO_DEFINED__
#define OCALL_FREEADDRINFO_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_freeaddrinfo, (struct addrinfo* res));
#endif
#ifndef OCALL_GETHOSTNAME_DEFINED__
#define OCALL_GETHOSTNAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gethostname, (char* name, size_t namelen));
#endif
#ifndef OCALL_SETHOSTNAME_DEFINED__
#define OCALL_SETHOSTNAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sethostname, (const char* name, size_t len));
#endif
#ifndef OCALL_GETTIMEOFDAY_DEFINED__
#define OCALL_GETTIMEOFDAY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gettimeofday, (void* tv, int tv_size));
#endif
#ifndef OCALL_CLOCK_GETTIME_DEFINED__
#define OCALL_CLOCK_GETTIME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_clock_gettime, (clockid_t clk_id, void* tp, int ts_size));
#endif
#ifndef OCALL_INET_PTON_DEFINED__
#define OCALL_INET_PTON_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_inet_pton, (int af, const char* src, void* dst));
#endif
#ifndef OCALL_GETPID_DEFINED__
#define OCALL_GETPID_DEFINED__
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpid, (void));
#endif
#ifndef OCALL_REMOVE_DEFINED__
#define OCALL_REMOVE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_remove, (const char* pathname));
#endif
#ifndef OCALL_SHUTDOWN_DEFINED__
#define OCALL_SHUTDOWN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_shutdown, (int sockfd, int how));
#endif
#ifndef OCALL_GETSOCKOPT_DEFINED__
#define OCALL_GETSOCKOPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getsockopt, (int socket, int level, int option_name, void* option_value, socklen_t* option_len));
#endif
#ifndef OCALL_SETSOCKOPT_DEFINED__
#define OCALL_SETSOCKOPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_setsockopt, (int socket, int level, int option_name, const void* option_value, socklen_t option_len));
#endif
#ifndef OCALL_SOCKETPAIR_DEFINED__
#define OCALL_SOCKETPAIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_socketpair, (int domain, int type, int protocol, int* sv));
#endif
#ifndef OCALL_BIND_DEFINED__
#define OCALL_BIND_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_bind, (int socket, const void* address, socklen_t address_len));
#endif
#ifndef OCALL_EPOLL_WAIT_DEFINED__
#define OCALL_EPOLL_WAIT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_wait, (int epfd, struct epoll_event* events, int maxevents, int timeout));
#endif
#ifndef OCALL_EPOLL_CTL_DEFINED__
#define OCALL_EPOLL_CTL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_ctl, (int epfd, int op, int fd, struct epoll_event* event));
#endif
#ifndef OCALL_READV_DEFINED__
#define OCALL_READV_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readv, (int fd, const struct iovec* iov, int iovcnt));
#endif
#ifndef OCALL_WRITEV_DEFINED__
#define OCALL_WRITEV_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writev, (int fd, const struct iovec* iov, int iovcnt));
#endif
#ifndef OCALL_PIPE_DEFINED__
#define OCALL_PIPE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pipe, (int* pipefd));
#endif
#ifndef OCALL_CONNECT_DEFINED__
#define OCALL_CONNECT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_connect, (int sockfd, const void* addr, socklen_t addrlen));
#endif
#ifndef OCALL_LISTEN_DEFINED__
#define OCALL_LISTEN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_listen, (int socket, int backlog));
#endif
#ifndef OCALL_ACCEPT_DEFINED__
#define OCALL_ACCEPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_accept, (int socket, struct sockaddr* address, socklen_t* address_len));
#endif
#ifndef OCALL_ACCEPT4_DEFINED__
#define OCALL_ACCEPT4_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_accept4, (int socket, struct sockaddr* address, socklen_t* address_len, int flags));
#endif
#ifndef OCALL_POLL_DEFINED__
#define OCALL_POLL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_poll, (struct pollfd* fds, nfds_t nfds, int timeout));
#endif
#ifndef OCALL_EPOLL_CREATE_DEFINED__
#define OCALL_EPOLL_CREATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_create, (int size));
#endif
#ifndef OCALL_GETPEERNAME_DEFINED__
#define OCALL_GETPEERNAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpeername, (int sockfd, struct sockaddr* addr, socklen_t* addrlen));
#endif
#ifndef OCALL_RECV_DEFINED__
#define OCALL_RECV_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recv, (int sockfd, void* buf, size_t len, int flags));
#endif
#ifndef OCALL_SEND_DEFINED__
#define OCALL_SEND_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send, (int sockfd, const void* buf, size_t len, int flags));
#endif
#ifndef OCALL_SENDTO_DEFINED__
#define OCALL_SENDTO_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sendto, (int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen));
#endif
#ifndef OCALL_SENDMSG_DEFINED__
#define OCALL_SENDMSG_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sendmsg, (int sockfd, struct msghdr* msg, int flags));
#endif
#ifndef OCALL_RECVFROM_DEFINED__
#define OCALL_RECVFROM_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recvfrom, (int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen));
#endif
#ifndef OCALL_RECVMSG_DEFINED__
#define OCALL_RECVMSG_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recvmsg, (int sockfd, struct msghdr* msg, int flags));
#endif
#ifndef OCALL_HTONL_DEFINED__
#define OCALL_HTONL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_htonl, (uint32_t hostlong));
#endif
#ifndef OCALL_HTONS_DEFINED__
#define OCALL_HTONS_DEFINED__
uint16_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_htons, (uint16_t hostshort));
#endif
#ifndef OCALL_NTOHL_DEFINED__
#define OCALL_NTOHL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ntohl, (uint32_t netlong));
#endif
#ifndef OCALL_NTOHS_DEFINED__
#define OCALL_NTOHS_DEFINED__
uint16_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ntohs, (uint16_t netshort));
#endif
#ifndef OCALL_TIME_DEFINED__
#define OCALL_TIME_DEFINED__
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_time, (time_t* t));
#endif
#ifndef OCALL_INET_NTOP_DEFINED__
#define OCALL_INET_NTOP_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_inet_ntop, (int af, const void* src, char* dst, socklen_t len));
#endif
#ifndef OCALL_DLSYM_DEFINED__
#define OCALL_DLSYM_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_dlsym, (void* handle, const char* symbol, void* res));
#endif
#ifndef OCALL_DLOPEN_DEFINED__
#define OCALL_DLOPEN_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_dlopen, (const char* symbol, int flag));
#endif
#ifndef OCALL_MMAP_FILE_DEFINED__
#define OCALL_MMAP_FILE_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mmap_file, (int hint, size_t length, int prot, int flags, int fd, off_t offset));
#endif
#ifndef OCALL_SYSCONF_DEFINED__
#define OCALL_SYSCONF_DEFINED__
long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sysconf, (int name));
#endif
#ifndef OCALL_GETUID_DEFINED__
#define OCALL_GETUID_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getuid, (void));
#endif
#ifndef OCALL_GETEUID_DEFINED__
#define OCALL_GETEUID_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_geteuid, (void));
#endif
#ifndef OCALL_GETCWD_DEFINED__
#define OCALL_GETCWD_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getcwd, (char* buf, size_t len));
#endif
#ifndef OCALL_GETPWUID_DEFINED__
#define OCALL_GETPWUID_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpwuid, (uid_t uid, struct passwd* ret));
#endif
#ifndef OCALL_EXIT_DEFINED__
#define OCALL_EXIT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_exit, (int stat));
#endif
#ifndef OCALL_GETRLIMIT_DEFINED__
#define OCALL_GETRLIMIT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getrlimit, (int res, struct rlimit* rlim));
#endif
#ifndef OCALL_SETRLIMIT_DEFINED__
#define OCALL_SETRLIMIT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_setrlimit, (int resource, struct rlimit* rlim));
#endif
#ifndef OCALL_UNAME_DEFINED__
#define OCALL_UNAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_uname, (struct utsname* buf));
#endif
#ifndef OCALL_SLEEP_DEFINED__
#define OCALL_SLEEP_DEFINED__
unsigned int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sleep, (unsigned int secs));
#endif
#ifndef OCALL_USLEEP_DEFINED__
#define OCALL_USLEEP_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_usleep, (useconds_t usec));
#endif
#ifndef OCALL_REALPATH_DEFINED__
#define OCALL_REALPATH_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_realpath, (const char* path, char* res_path));
#endif
#ifndef OCALL_XPG_STRERROR_R_DEFINED__
#define OCALL_XPG_STRERROR_R_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_xpg_strerror_r, (int errnum, char* buf, size_t buflen));
#endif
#ifndef OCALL_SIGNAL_DEFINED__
#define OCALL_SIGNAL_DEFINED__
__sighandler_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_signal, (int signum, __sighandler_t handler));
#endif
#ifndef OCALL_KILL_DEFINED__
#define OCALL_KILL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_kill, (pid_t pid, int sig));
#endif
#ifndef OCALL_GET_CPUID_MAX_DEFINED__
#define OCALL_GET_CPUID_MAX_DEFINED__
unsigned int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_cpuid_max, (unsigned int ext, unsigned int* sig));
#endif
#ifndef OCALL_GET_CPUID_COUNT_DEFINED__
#define OCALL_GET_CPUID_COUNT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_cpuid_count, (unsigned int leaf, unsigned int subleaf, unsigned int* eax, unsigned int* ebx, unsigned int* ecx, unsigned int* edx));
#endif

sgx_status_t ecall_run_main(sgx_enclave_id_t eid, int id);
sgx_status_t ecall_read_kyoto(sgx_enclave_id_t eid, int n, int storeId);
sgx_status_t ecall_write_kyotodb(sgx_enclave_id_t eid, int n, int storeId);
sgx_status_t ecall_kissdb_test(sgx_enclave_id_t eid);
sgx_status_t ecall_read_kissdb(sgx_enclave_id_t eid, int n, int storeId);
sgx_status_t ecall_write_kissdb(sgx_enclave_id_t eid, int n, int storeId);
sgx_status_t ecall_do_lmbench_op(sgx_enclave_id_t eid, int num_ops, int thread_id, int op, void* cookie);
sgx_status_t ecall_do_openssl_op(sgx_enclave_id_t eid, int max_bytes, int thread_id, int op);
sgx_status_t ecall_test(sgx_enclave_id_t eid);
sgx_status_t ecall_undef_stack_protector(sgx_enclave_id_t eid);
sgx_status_t ecall_run_fg(sgx_enclave_id_t eid, int total, int tid);
sgx_status_t sl_init_switchless(sgx_enclave_id_t eid, sgx_status_t* retval, void* sl_data);
sgx_status_t sl_run_switchless_tworker(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t ecall_init_mpmc_queues_inside(sgx_enclave_id_t eid, void* req_q, void* resp_q);
sgx_status_t ecall_init_mem_pools(sgx_enclave_id_t eid, void* pools, void* zc_statistics);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
