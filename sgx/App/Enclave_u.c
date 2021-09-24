#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_graal_main_args_t {
	int ms_id;
	int ms_arg1;
	struct buffer* ms_switchless_buffers;
	struct buffer* ms_switchless_buffer;
	void** ms_sl_fn;
	void** ms_fn;
	int* ms_sl_count;
	int* ms_f_count;
	int* ms_number_of_workers;
} ms_ecall_graal_main_args_t;

typedef struct ms_ecall_graal_main_t {
	int ms_id;
	struct buffer* ms_switchless_buffers;
	struct buffer* ms_switchless_buffer;
	void** ms_sl_fn;
	void** ms_fn;
	int* ms_sl_count;
	int* ms_f_count;
	int* ms_number_of_workers;
} ms_ecall_graal_main_t;

typedef struct ms_ecall_run_main_t {
	int ms_id;
} ms_ecall_run_main_t;

typedef struct ms_ecall_reader_t {
	int ms_n;
	int ms_id;
	struct buffer* ms_switchless_buffers;
	struct buffer* ms_switchless_buffer;
	void** ms_sl_fn;
	void** ms_fn;
	int* ms_sl_count;
	int* ms_f_count;
	int* ms_number_of_workers;
} ms_ecall_reader_t;

typedef struct ms_ecall_writer_t {
	int ms_n;
	int ms_id;
	struct buffer* ms_switchless_buffers;
	struct buffer* ms_switchless_buffer;
	void** ms_sl_fn;
	void** ms_fn;
	int* ms_sl_count;
	int* ms_f_count;
	int* ms_number_of_workers;
} ms_ecall_writer_t;

typedef struct ms_ecall_bench_thread_t {
	struct buffer* ms_bs;
	struct buffer* ms_b;
	void** ms_sl_fn;
	void** ms_fn;
	int* ms_sl_count;
	int* ms_f_count;
	int* ms_number_of_workers;
} ms_ecall_bench_thread_t;

typedef struct ms_ecall_readN_t {
	int ms_n;
} ms_ecall_readN_t;

typedef struct ms_ecall_writeN_t {
	int ms_n;
} ms_ecall_writeN_t;

typedef struct ms_ecall_readKissdb_t {
	int ms_n;
	int ms_storeId;
} ms_ecall_readKissdb_t;

typedef struct ms_ecall_writeKissdb_t {
	int ms_n;
	int ms_storeId;
} ms_ecall_writeKissdb_t;

typedef struct ms_ecall_execute_job_t {
	pthread_t ms_pthread_self_id;
	unsigned long int ms_job_id;
} ms_ecall_execute_job_t;

typedef struct ms_ecall_init_settings_t {
	int ms_numWorkers;
} ms_ecall_init_settings_t;

typedef struct ms_ecall_init_mainbase_t {
	void* ms_mb;
} ms_ecall_init_mainbase_t;

typedef struct ms_ecall_drive_machine_t {
	void* ms_conn;
} ms_ecall_drive_machine_t;

typedef struct ms_ecall_thread_libevent_process_t {
	evutil_socket_t ms_fd;
	short int ms_which;
	void* ms_arg;
} ms_ecall_thread_libevent_process_t;

typedef struct ms_ecall_event_handler_t {
	evutil_socket_t ms_fd;
	short int ms_which;
	void* ms_arg;
} ms_ecall_event_handler_t;

typedef struct ms_ecall_conn_new_t {
	void* ms_retval;
	int ms_sfd;
	enum conn_states ms_init_state;
	int ms_flags;
	int ms_rd_buff_sz;
	enum network_transport ms_tport;
	struct event_base* ms_base;
	void* ms_ssl;
} ms_ecall_conn_new_t;

typedef struct ms_ecall_conn_io_queue_add_t {
	void* ms_c;
	int ms_type;
} ms_ecall_conn_io_queue_add_t;

typedef struct ms_ecall_set_conn_thread_t {
	void* ms_c;
	void* ms_libevent_thread;
} ms_ecall_set_conn_thread_t;

typedef struct ms_sl_init_switchless_t {
	sgx_status_t ms_retval;
	void* ms_sl_data;
} ms_sl_init_switchless_t;

typedef struct ms_sl_run_switchless_tworker_t {
	sgx_status_t ms_retval;
} ms_sl_run_switchless_tworker_t;

typedef struct ms_ocall_malloc_t {
	void* ms_retval;
	size_t ms_size;
} ms_ocall_malloc_t;

typedef struct ms_ocall_realloc_t {
	void* ms_retval;
	void* ms_ptr;
	size_t ms_size;
} ms_ocall_realloc_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_gettid_t {
	long int ms_retval;
} ms_ocall_gettid_t;

typedef struct ms_ocall_empty_t {
	int ms_repeats;
} ms_ocall_empty_t;

typedef struct ms_ocall_fsync_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_fsync_t;

typedef struct ms_ocall_dup2_t {
	int ms_retval;
	int ms_oldfd;
	int ms_newfd;
} ms_ocall_dup2_t;

typedef struct ms_ocall_open_t {
	int ms_retval;
	const char* ms_path;
	int ms_oflag;
	int ms_arg;
} ms_ocall_open_t;

typedef struct ms_ocall_open64_t {
	int ms_retval;
	const char* ms_path;
	int ms_oflag;
	int ms_arg;
} ms_ocall_open64_t;

typedef struct ms_ocall_xclose_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_xclose_t;

typedef struct ms_ocall_lseek_t {
	off_t ms_retval;
	int ms_fd;
	off_t ms_offset;
	int ms_whence;
} ms_ocall_lseek_t;

typedef struct ms_ocall_lseek64_t {
	off64_t ms_retval;
	int ms_fd;
	off64_t ms_offset;
	int ms_whence;
} ms_ocall_lseek64_t;

typedef struct ms_ocall_fflush_t {
	int ms_retval;
	SGX_FILE* ms_stream;
} ms_ocall_fflush_t;

typedef struct ms_ocall_pread_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
	off_t ms_offset;
} ms_ocall_pread_t;

typedef struct ms_ocall_pread64_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
	off64_t ms_offset;
} ms_ocall_pread64_t;

typedef struct ms_ocall_pwrite_t {
	ssize_t ms_retval;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
	off_t ms_offset;
} ms_ocall_pwrite_t;

typedef struct ms_ocall_fopen_t {
	SGX_FILE ms_retval;
	const char* ms_filename;
	const char* ms_mode;
} ms_ocall_fopen_t;

typedef struct ms_ocall_fdopen_t {
	SGX_FILE ms_retval;
	int ms_fd;
	const char* ms_mode;
} ms_ocall_fdopen_t;

typedef struct ms_ocall_fclose_t {
	int ms_retval;
	SGX_FILE ms_stream;
} ms_ocall_fclose_t;

typedef struct ms_ocall_fwrite_t {
	size_t ms_retval;
	const void* ms_ptr;
	size_t ms_size;
	size_t ms_nmemb;
	SGX_FILE ms_stream;
} ms_ocall_fwrite_t;

typedef struct ms_ocall_fread_t {
	size_t ms_retval;
	void* ms_ptr;
	size_t ms_size;
	size_t ms_nmemb;
	SGX_FILE ms_stream;
} ms_ocall_fread_t;

typedef struct ms_ocall_fseeko_t {
	int ms_retval;
	SGX_FILE ms_file;
	off_t ms_offset;
	int ms_whence;
} ms_ocall_fseeko_t;

typedef struct ms_ocall_ftello_t {
	off_t ms_retval;
	SGX_FILE ms_file;
} ms_ocall_ftello_t;

typedef struct ms_ocall_read_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_read_t;

typedef struct ms_ocall_write_t {
	ssize_t ms_retval;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
} ms_ocall_write_t;

typedef struct ms_ocall_fscanf_t {
	int ms_retval;
	SGX_FILE ms_stream;
	const char* ms_format;
} ms_ocall_fscanf_t;

typedef struct ms_ocall_fprintf_t {
	int ms_retval;
	SGX_FILE ms_stream;
	const char* ms_str;
} ms_ocall_fprintf_t;

typedef struct ms_ocall_fgets_t {
	char* ms_str;
	int ms_n;
	SGX_FILE ms_stream;
} ms_ocall_fgets_t;

typedef struct ms_ocall_stderr_t {
	SGX_FILE ms_retval;
} ms_ocall_stderr_t;

typedef struct ms_ocall_puts_t {
	int ms_retval;
	const char* ms_str;
} ms_ocall_puts_t;

typedef struct ms_ocall_getchar_t {
	int ms_retval;
} ms_ocall_getchar_t;

typedef struct ms_ocall_mkdir_t {
	int ms_retval;
	const char* ms_pathname;
	mode_t ms_mode;
} ms_ocall_mkdir_t;

typedef struct ms_ocall_truncate_t {
	int ms_retval;
	const char* ms_path;
	off_t ms_length;
} ms_ocall_truncate_t;

typedef struct ms_ocall_ftruncate64_t {
	int ms_retval;
	int ms_fd;
	off_t ms_length;
} ms_ocall_ftruncate64_t;

typedef struct ms_ocall_mmap64_t {
	void* ms_retval;
	void* ms_addr;
	size_t ms_len;
	int ms_prot;
	int ms_flags;
	int ms_fildes;
	off_t ms_off;
} ms_ocall_mmap64_t;

typedef struct ms_ocall_pwrite64_t {
	ssize_t ms_retval;
	int ms_fd;
	const void* ms_buf;
	size_t ms_nbyte;
	off_t ms_offset;
} ms_ocall_pwrite64_t;

typedef struct ms_ocall_fdatasync_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_fdatasync_t;

typedef struct ms_ocall_rename_t {
	int ms_retval;
	const char* ms_oldpath;
	const char* ms_newpath;
} ms_ocall_rename_t;

typedef struct ms_ocall_unlink_t {
	int ms_retval;
	const char* ms_pathname;
} ms_ocall_unlink_t;

typedef struct ms_ocall_rmdir_t {
	int ms_retval;
	const char* ms_pathname;
} ms_ocall_rmdir_t;

typedef struct ms_ocall_times_t {
	clock_t ms_retval;
} ms_ocall_times_t;

typedef struct ms_ocall_chown_t {
	int ms_retval;
	const char* ms_pathname;
	uid_t ms_owner;
	gid_t ms_group;
} ms_ocall_chown_t;

typedef struct ms_ocall_fchown_t {
	int ms_retval;
	int ms_fd;
	uid_t ms_owner;
	gid_t ms_group;
} ms_ocall_fchown_t;

typedef struct ms_ocall_lchown_t {
	int ms_retval;
	const char* ms_pathname;
	uid_t ms_owner;
	gid_t ms_group;
} ms_ocall_lchown_t;

typedef struct ms_ocall_chmod_t {
	int ms_retval;
	const char* ms_pathname;
	mode_t ms_mode;
} ms_ocall_chmod_t;

typedef struct ms_ocall_fchmod_t {
	int ms_retval;
	int ms_fd;
	mode_t ms_mode;
} ms_ocall_fchmod_t;

typedef struct ms_ocall_lxstat64_t {
	int ms_retval;
	int ms_ver;
	const char* ms_path;
	struct stat* ms_stat_buf;
} ms_ocall_lxstat64_t;

typedef struct ms_ocall_fcntl_t {
	int ms_retval;
	int ocall_errno;
	int ms_fildes;
	int ms_cmd;
	int ms_arg;
} ms_ocall_fcntl_t;

typedef struct ms_ocall_ioctl_t {
	int ms_retval;
	int ms_fd;
	unsigned long int ms_request;
	int ms_arg;
} ms_ocall_ioctl_t;

typedef struct ms_ocall_xstat64_t {
	int ms_retval;
	int ms_ver;
	const char* ms_path;
	struct stat* ms_stat_buf;
} ms_ocall_xstat64_t;

typedef struct ms_ocall_stat_t {
	int ms_retval;
	const char* ms_path;
	struct stat* ms_buf;
} ms_ocall_stat_t;

typedef struct ms_ocall_fstat_t {
	int ms_retval;
	int ms_fd;
	struct stat* ms_buf;
} ms_ocall_fstat_t;

typedef struct ms_ocall_lstat_t {
	int ms_retval;
	const char* ms_path;
	struct stat* ms_buf;
} ms_ocall_lstat_t;

typedef struct ms_ocall_fstat64_t {
	int ms_retval;
	int ms_fd;
	struct stat* ms_buf;
} ms_ocall_fstat64_t;

typedef struct ms_ocall_fxstat64_t {
	int ms_retval;
	int ms_ver;
	int ms_fildes;
	struct stat* ms_stat_buf;
} ms_ocall_fxstat64_t;

typedef struct ms_ocall_fxstat_t {
	int ms_retval;
	int ms_ver;
	int ms_fd;
	struct stat* ms_stat_buf;
} ms_ocall_fxstat_t;

typedef struct ms_ocall_lxstat_t {
	int ms_retval;
	int ms_ver;
	const char* ms_path;
	struct stat* ms_stat_buf;
} ms_ocall_lxstat_t;

typedef struct ms_ocall_xstat_t {
	int ms_retval;
	int ms_ver;
	const char* ms_path;
	struct stat* ms_stat_buf;
} ms_ocall_xstat_t;

typedef struct ms_ocall_pathconf_t {
	long int ms_retval;
	const char* ms_path;
	int ms_name;
} ms_ocall_pathconf_t;

typedef struct ms_ocall_readlink_t {
	ssize_t ms_retval;
	const char* ms_pathname;
	char* ms_buf;
	size_t ms_bufsiz;
} ms_ocall_readlink_t;

typedef struct ms_ocall_readdir64_r_t {
	int ms_retval;
	void* ms_dirp;
	void* ms_entry;
	struct dirent** ms_result;
} ms_ocall_readdir64_r_t;

typedef struct ms_ocall_opendir_t {
	void* ms_retval;
	const char* ms_name;
} ms_ocall_opendir_t;

typedef struct ms_ocall_chdir_t {
	int ms_retval;
	const char* ms_path;
} ms_ocall_chdir_t;

typedef struct ms_ocall_closedir_t {
	int ms_retval;
	void* ms_dirp;
} ms_ocall_closedir_t;

typedef struct ms_ocall_xmknod_t {
	int ms_retval;
	int ms_vers;
	const char* ms_path;
	mode_t ms_mode;
	dev_t* ms_dev;
} ms_ocall_xmknod_t;

typedef struct ms_ocall_symlink_t {
	int ms_retval;
	const char* ms_target;
	const char* ms_linkpath;
} ms_ocall_symlink_t;

typedef struct ms_ocall_deflateEnd_t {
	int ms_retval;
	z_streamp ms_stream;
} ms_ocall_deflateEnd_t;

typedef struct ms_ocall_deflateParams_t {
	int ms_retval;
	z_streamp ms_stream;
	int ms_level;
	int ms_strategy;
} ms_ocall_deflateParams_t;

typedef struct ms_ocall_deflate_t {
	int ms_retval;
	z_streamp ms_stream;
	int ms_flush;
} ms_ocall_deflate_t;

typedef struct ms_ocall_deflateInit2_t {
	int ms_retval;
	z_streamp ms_stream;
	int ms_level;
	int ms_method;
	int ms_windowBits;
	int ms_memLevel;
	int ms_strategy;
} ms_ocall_deflateInit2_t;

typedef struct ms_ocall_inflateReset_t {
	int ms_retval;
	z_streamp ms_stream;
} ms_ocall_inflateReset_t;

typedef struct ms_ocall_sendfile64_t {
	ssize_t ms_retval;
	int ms_out_fd;
	int ms_in_fd;
	off_t* ms_offset;
	size_t ms_count;
} ms_ocall_sendfile64_t;

typedef struct ms_ocall_adler32_t {
	ulong ms_retval;
	ulong ms_adler;
	const Bytef* ms_buf;
	size_t ms_len;
} ms_ocall_adler32_t;

typedef struct ms_ocall_getenv_t {
	char* ms_retval;
	const char* ms_name;
} ms_ocall_getenv_t;

typedef struct ms_ocall_fileno_t {
	int ms_retval;
	SGX_FILE* ms_stream;
} ms_ocall_fileno_t;

typedef struct ms_ocall_isatty_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_isatty_t;

typedef struct ms_ocall_umask_t {
	mode_t ms_retval;
	mode_t ms_mask;
} ms_ocall_umask_t;

typedef struct ms_ocall_fputc_t {
	int ms_retval;
	int ms_c;
	SGX_FILE ms_stream;
} ms_ocall_fputc_t;

typedef struct ms_ocall_putc_t {
	int ms_retval;
	int ms_c;
	SGX_FILE ms_stream;
} ms_ocall_putc_t;

typedef struct ms_ocall_socket_t {
	int ms_retval;
	int ms_domain;
	int ms_type;
	int ms_protocol;
} ms_ocall_socket_t;

typedef struct ms_ocall_getsockname_t {
	int ms_retval;
	int ms_sockfd;
	struct sockaddr* ms_addr;
	socklen_t* ms_addrlen;
} ms_ocall_getsockname_t;

typedef struct ms_ocall_getaddrinfo_t {
	int ms_retval;
	const char* ms_node;
	const char* ms_service;
	const struct addrinfo* ms_hints;
	struct addrinfo** ms_res;
} ms_ocall_getaddrinfo_t;

typedef struct ms_ocall_getnameinfo_t {
	int ms_retval;
	const struct sockaddr* ms_addr;
	socklen_t ms_addrlen;
	char* ms_host;
	socklen_t ms_hostlen;
	char* ms_serv;
	socklen_t ms_servlen;
	int ms_flags;
} ms_ocall_getnameinfo_t;

typedef struct ms_ocall_freeaddrinfo_t {
	struct addrinfo* ms_res;
} ms_ocall_freeaddrinfo_t;

typedef struct ms_ocall_gethostname_t {
	int ms_retval;
	char* ms_name;
	size_t ms_namelen;
} ms_ocall_gethostname_t;

typedef struct ms_ocall_sethostname_t {
	int ms_retval;
	const char* ms_name;
	size_t ms_len;
} ms_ocall_sethostname_t;

typedef struct ms_ocall_gettimeofday_t {
	int ms_retval;
	void* ms_tv;
	int ms_tv_size;
} ms_ocall_gettimeofday_t;

typedef struct ms_ocall_clock_gettime_t {
	int ms_retval;
	clockid_t ms_clk_id;
	void* ms_tp;
	int ms_ts_size;
} ms_ocall_clock_gettime_t;

typedef struct ms_ocall_inet_pton_t {
	int ms_retval;
	int ms_af;
	const char* ms_src;
	void* ms_dst;
} ms_ocall_inet_pton_t;

typedef struct ms_ocall_getpid_t {
	pid_t ms_retval;
} ms_ocall_getpid_t;

typedef struct ms_ocall_remove_t {
	int ms_retval;
	const char* ms_pathname;
} ms_ocall_remove_t;

typedef struct ms_ocall_shutdown_t {
	int ms_retval;
	int ms_sockfd;
	int ms_how;
} ms_ocall_shutdown_t;

typedef struct ms_ocall_getsockopt_t {
	int ms_retval;
	int ocall_errno;
	int ms_socket;
	int ms_level;
	int ms_option_name;
	void* ms_option_value;
	socklen_t* ms_option_len;
} ms_ocall_getsockopt_t;

typedef struct ms_ocall_setsockopt_t {
	int ms_retval;
	int ocall_errno;
	int ms_socket;
	int ms_level;
	int ms_option_name;
	const void* ms_option_value;
	socklen_t ms_option_len;
} ms_ocall_setsockopt_t;

typedef struct ms_ocall_socketpair_t {
	int ms_retval;
	int ms_domain;
	int ms_type;
	int ms_protocol;
	int* ms_sv;
} ms_ocall_socketpair_t;

typedef struct ms_ocall_bind_t {
	int ms_retval;
	int ocall_errno;
	int ms_socket;
	const void* ms_address;
	socklen_t ms_address_len;
} ms_ocall_bind_t;

typedef struct ms_ocall_epoll_wait_t {
	int ms_retval;
	int ms_epfd;
	struct epoll_event* ms_events;
	int ms_maxevents;
	int ms_timeout;
} ms_ocall_epoll_wait_t;

typedef struct ms_ocall_epoll_ctl_t {
	int ms_retval;
	int ms_epfd;
	int ms_op;
	int ms_fd;
	struct epoll_event* ms_event;
} ms_ocall_epoll_ctl_t;

typedef struct ms_ocall_readv_t {
	ssize_t ms_retval;
	int ms_fd;
	const struct iovec* ms_iov;
	int ms_iovcnt;
} ms_ocall_readv_t;

typedef struct ms_ocall_writev_t {
	ssize_t ms_retval;
	int ms_fd;
	const struct iovec* ms_iov;
	int ms_iovcnt;
} ms_ocall_writev_t;

typedef struct ms_ocall_pipe_t {
	int ms_retval;
	int* ms_pipefd;
} ms_ocall_pipe_t;

typedef struct ms_ocall_connect_t {
	int ms_retval;
	int ms_sockfd;
	const void* ms_addr;
	socklen_t ms_addrlen;
} ms_ocall_connect_t;

typedef struct ms_ocall_listen_t {
	int ms_retval;
	int ocall_errno;
	int ms_socket;
	int ms_backlog;
} ms_ocall_listen_t;

typedef struct ms_ocall_accept_t {
	int ms_retval;
	int ocall_errno;
	int ms_socket;
	struct sockaddr* ms_address;
	socklen_t* ms_address_len;
} ms_ocall_accept_t;

typedef struct ms_ocall_accept4_t {
	int ms_retval;
	int ocall_errno;
	int ms_socket;
	struct sockaddr* ms_address;
	socklen_t* ms_address_len;
	int ms_flags;
} ms_ocall_accept4_t;

typedef struct ms_ocall_poll_t {
	int ms_retval;
	int ocall_errno;
	struct pollfd* ms_fds;
	nfds_t ms_nfds;
	int ms_timeout;
} ms_ocall_poll_t;

typedef struct ms_ocall_epoll_create_t {
	int ms_retval;
	int ms_size;
} ms_ocall_epoll_create_t;

typedef struct ms_ocall_getpeername_t {
	int ms_retval;
	int ms_sockfd;
	struct sockaddr* ms_addr;
	socklen_t* ms_addrlen;
} ms_ocall_getpeername_t;

typedef struct ms_ocall_recv_t {
	ssize_t ms_retval;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_recv_t;

typedef struct ms_ocall_send_t {
	ssize_t ms_retval;
	int ms_sockfd;
	const void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_send_t;

typedef struct ms_ocall_sendto_t {
	ssize_t ms_retval;
	int ms_sockfd;
	const void* ms_buf;
	size_t ms_len;
	int ms_flags;
	const struct sockaddr* ms_dest_addr;
	socklen_t ms_addrlen;
} ms_ocall_sendto_t;

typedef struct ms_ocall_sendmsg_t {
	ssize_t ms_retval;
	int ms_sockfd;
	struct msghdr* ms_msg;
	int ms_flags;
} ms_ocall_sendmsg_t;

typedef struct ms_ocall_recvfrom_t {
	ssize_t ms_retval;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
	struct sockaddr* ms_src_addr;
	socklen_t* ms_addrlen;
} ms_ocall_recvfrom_t;

typedef struct ms_ocall_recvmsg_t {
	ssize_t ms_retval;
	int ms_sockfd;
	struct msghdr* ms_msg;
	int ms_flags;
} ms_ocall_recvmsg_t;

typedef struct ms_ocall_htonl_t {
	uint32_t ms_retval;
	uint32_t ms_hostlong;
} ms_ocall_htonl_t;

typedef struct ms_ocall_htons_t {
	uint16_t ms_retval;
	uint16_t ms_hostshort;
} ms_ocall_htons_t;

typedef struct ms_ocall_ntohl_t {
	uint32_t ms_retval;
	uint32_t ms_netlong;
} ms_ocall_ntohl_t;

typedef struct ms_ocall_ntohs_t {
	uint16_t ms_retval;
	uint16_t ms_netshort;
} ms_ocall_ntohs_t;

typedef struct ms_ocall_time_t {
	time_t ms_retval;
	time_t* ms_t;
} ms_ocall_time_t;

typedef struct ms_ocall_inet_ntop_t {
	char* ms_retval;
	int ms_af;
	const void* ms_src;
	char* ms_dst;
	socklen_t ms_len;
} ms_ocall_inet_ntop_t;

typedef struct ms_ocall_dlsym_t {
	void* ms_handle;
	const char* ms_symbol;
	void* ms_res;
} ms_ocall_dlsym_t;

typedef struct ms_ocall_dlopen_t {
	void* ms_retval;
	const char* ms_symbol;
	int ms_flag;
} ms_ocall_dlopen_t;

typedef struct ms_ocall_sysconf_t {
	long int ms_retval;
	int ms_name;
} ms_ocall_sysconf_t;

typedef struct ms_ocall_getuid_t {
	int ms_retval;
} ms_ocall_getuid_t;

typedef struct ms_ocall_geteuid_t {
	int ms_retval;
} ms_ocall_geteuid_t;

typedef struct ms_ocall_getcwd_t {
	char* ms_buf;
	size_t ms_len;
} ms_ocall_getcwd_t;

typedef struct ms_ocall_getpwuid_t {
	uid_t ms_uid;
	struct passwd* ms_ret;
} ms_ocall_getpwuid_t;

typedef struct ms_ocall_exit_t {
	int ms_stat;
} ms_ocall_exit_t;

typedef struct ms_ocall_getrlimit_t {
	int ms_retval;
	int ms_res;
	struct rlimit* ms_rlim;
} ms_ocall_getrlimit_t;

typedef struct ms_ocall_setrlimit_t {
	int ms_retval;
	int ms_resource;
	struct rlimit* ms_rlim;
} ms_ocall_setrlimit_t;

typedef struct ms_ocall_uname_t {
	int ms_retval;
	struct utsname* ms_buf;
} ms_ocall_uname_t;

typedef struct ms_ocall_sleep_t {
	unsigned int ms_retval;
	unsigned int ms_secs;
} ms_ocall_sleep_t;

typedef struct ms_ocall_usleep_t {
	int ms_retval;
	useconds_t ms_usec;
} ms_ocall_usleep_t;

typedef struct ms_ocall_realpath_t {
	const char* ms_path;
	char* ms_res_path;
} ms_ocall_realpath_t;

typedef struct ms_ocall_xpg_strerror_r_t {
	int ms_errnum;
	char* ms_buf;
	size_t ms_buflen;
} ms_ocall_xpg_strerror_r_t;

typedef struct ms_ocall_signal_t {
	__sighandler_t ms_retval;
	int ms_signum;
	__sighandler_t ms_handler;
} ms_ocall_signal_t;

typedef struct ms_ocall_kill_t {
	int ms_retval;
	pid_t ms_pid;
	int ms_sig;
} ms_ocall_kill_t;

typedef struct ms_ocall_get_cpuid_max_t {
	unsigned int ms_retval;
	unsigned int ms_ext;
	unsigned int* ms_sig;
} ms_ocall_get_cpuid_max_t;

typedef struct ms_ocall_get_cpuid_count_t {
	int ms_retval;
	unsigned int ms_leaf;
	unsigned int ms_subleaf;
	unsigned int* ms_eax;
	unsigned int* ms_ebx;
	unsigned int* ms_ecx;
	unsigned int* ms_edx;
} ms_ocall_get_cpuid_count_t;

typedef struct ms_ocall_pthread_attr_init_t {
	int ms_retval;
} ms_ocall_pthread_attr_init_t;

typedef struct ms_ocall_pthread_create_t {
	int ms_retval;
	pthread_t* ms_new_thread;
	unsigned long int ms_job_id;
	sgx_enclave_id_t ms_eid;
} ms_ocall_pthread_create_t;

typedef struct ms_ocall_pthread_self_t {
	pthread_t ms_retval;
} ms_ocall_pthread_self_t;

typedef struct ms_ocall_pthread_join_t {
	int ms_retval;
	pthread_t ms_pt;
	void** ms_res;
} ms_ocall_pthread_join_t;

typedef struct ms_ocall_pthread_attr_getguardsize_t {
	int ms_retval;
	size_t* ms_guardsize;
} ms_ocall_pthread_attr_getguardsize_t;

typedef struct ms_ocall_pthread_attr_getguardsize__bypass_t {
	int ms_retval;
	void* ms_attr;
	size_t ms_attr_len;
	size_t* ms_guardsize;
} ms_ocall_pthread_attr_getguardsize__bypass_t;

typedef struct ms_ocall_pthread_attr_destroy_t {
	int ms_retval;
} ms_ocall_pthread_attr_destroy_t;

typedef struct ms_ocall_pthread_condattr_setclock_t {
	int ms_retval;
	void* ms_attr;
	clockid_t ms_clock_id;
	size_t ms_attr_len;
} ms_ocall_pthread_condattr_setclock_t;

typedef struct ms_ocall_pthread_attr_destroy__bypass_t {
	int ms_retval;
	void* ms_attr;
	size_t ms_attr_len;
} ms_ocall_pthread_attr_destroy__bypass_t;

typedef struct ms_ocall_pthread_attr_getstack_t {
	int ms_retval;
	void** ms_stk_addr;
	size_t* ms_stack_size;
} ms_ocall_pthread_attr_getstack_t;

typedef struct ms_ocall_pthread_attr_getstack__bypass_t {
	int ms_retval;
	void* ms_attr;
	size_t ms_attr_len;
	void** ms_stk_addr;
	size_t ms_len;
	size_t* ms_stack_size;
} ms_ocall_pthread_attr_getstack__bypass_t;

typedef struct ms_ocall_pthread_getattr_np_t {
	int ms_retval;
	pthread_t ms_tid;
} ms_ocall_pthread_getattr_np_t;

typedef struct ms_ocall_pthread_getattr_np__bypass_t {
	int ms_retval;
	pthread_t ms_tid;
	void* ms_attr;
	size_t ms_len;
} ms_ocall_pthread_getattr_np__bypass_t;

typedef struct ms_ocall_event_del_t {
	int ms_retval;
	struct event* ms_ev;
} ms_ocall_event_del_t;

typedef struct ms_ocall_event_base_set_t {
	int ms_retval;
	struct event_base* ms_evb;
	struct event* ms_ev;
} ms_ocall_event_base_set_t;

typedef struct ms_ocall_event_add_t {
	int ms_retval;
	struct event* ms_ev;
	const struct timeval* ms_timeout;
} ms_ocall_event_add_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

typedef struct ms_mcd_ocall_setup_conn_event_t {
	int ms_retval;
	int ms_fd;
	int ms_event_flags;
	struct event_base* ms_base;
	void* ms_c;
	int ms_conn_id;
} ms_mcd_ocall_setup_conn_event_t;

typedef struct ms_mcd_ocall_update_conn_event_t {
	int ms_fd;
	int ms_event_flags;
	struct event_base* ms_base;
	void* ms_c;
	int ms_conn_id;
} ms_mcd_ocall_update_conn_event_t;

typedef struct ms_mcd_ocall_event_del_t {
	int ms_retval;
	int ms_conn_id;
} ms_mcd_ocall_event_del_t;

typedef struct ms_mcd_ocall_event_add_t {
	int ms_retval;
	int ms_conn_id;
} ms_mcd_ocall_event_add_t;

typedef struct ms_mcd_ocall_dispatch_conn_new_t {
	int ms_sfd;
	enum conn_states ms_init_state;
	int ms_event_flags;
	int ms_read_buffer_size;
	enum network_transport ms_transport;
	void* ms_ssl;
} ms_mcd_ocall_dispatch_conn_new_t;

typedef struct ms_mcd_ocall_do_cache_alloc_t {
	void* ms_retval;
	int ms_conn_id;
	int ms_lvt_thread_id;
} ms_mcd_ocall_do_cache_alloc_t;

typedef struct ms_mcd_ocall_do_cache_free_t {
	int ms_conn_id;
	int ms_lvt_thread_id;
	void* ms_bundle;
} ms_mcd_ocall_do_cache_free_t;

typedef struct ms_mcd_ocall_mutex_lock_lthread_stats_t {
	int ms_conn_id;
} ms_mcd_ocall_mutex_lock_lthread_stats_t;

typedef struct ms_mcd_ocall_mutex_unlock_lthread_stats_t {
	int ms_conn_id;
} ms_mcd_ocall_mutex_unlock_lthread_stats_t;

typedef struct ms_ocall_transmit_prepare_t {
	void* ms_retval;
} ms_ocall_transmit_prepare_t;

typedef struct ms_ocall_getErrno_t {
	int ms_retval;
} ms_ocall_getErrno_t;

static sgx_status_t SGX_CDECL Enclave_ocall_malloc(void* pms)
{
	ms_ocall_malloc_t* ms = SGX_CAST(ms_ocall_malloc_t*, pms);
	ms->ms_retval = ocall_malloc(ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_realloc(void* pms)
{
	ms_ocall_realloc_t* ms = SGX_CAST(ms_ocall_realloc_t*, pms);
	ms->ms_retval = ocall_realloc(ms->ms_ptr, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_gettid(void* pms)
{
	ms_ocall_gettid_t* ms = SGX_CAST(ms_ocall_gettid_t*, pms);
	ms->ms_retval = ocall_gettid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_bench(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_bench();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_empty(void* pms)
{
	ms_ocall_empty_t* ms = SGX_CAST(ms_ocall_empty_t*, pms);
	ocall_empty(ms->ms_repeats);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fsync(void* pms)
{
	ms_ocall_fsync_t* ms = SGX_CAST(ms_ocall_fsync_t*, pms);
	ms->ms_retval = ocall_fsync(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_dup2(void* pms)
{
	ms_ocall_dup2_t* ms = SGX_CAST(ms_ocall_dup2_t*, pms);
	ms->ms_retval = ocall_dup2(ms->ms_oldfd, ms->ms_newfd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_open(void* pms)
{
	ms_ocall_open_t* ms = SGX_CAST(ms_ocall_open_t*, pms);
	ms->ms_retval = ocall_open(ms->ms_path, ms->ms_oflag, ms->ms_arg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_open64(void* pms)
{
	ms_ocall_open64_t* ms = SGX_CAST(ms_ocall_open64_t*, pms);
	ms->ms_retval = ocall_open64(ms->ms_path, ms->ms_oflag, ms->ms_arg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_xclose(void* pms)
{
	ms_ocall_xclose_t* ms = SGX_CAST(ms_ocall_xclose_t*, pms);
	ms->ms_retval = ocall_xclose(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lseek(void* pms)
{
	ms_ocall_lseek_t* ms = SGX_CAST(ms_ocall_lseek_t*, pms);
	ms->ms_retval = ocall_lseek(ms->ms_fd, ms->ms_offset, ms->ms_whence);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lseek64(void* pms)
{
	ms_ocall_lseek64_t* ms = SGX_CAST(ms_ocall_lseek64_t*, pms);
	ms->ms_retval = ocall_lseek64(ms->ms_fd, ms->ms_offset, ms->ms_whence);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fflush(void* pms)
{
	ms_ocall_fflush_t* ms = SGX_CAST(ms_ocall_fflush_t*, pms);
	ms->ms_retval = ocall_fflush(ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pread(void* pms)
{
	ms_ocall_pread_t* ms = SGX_CAST(ms_ocall_pread_t*, pms);
	ms->ms_retval = ocall_pread(ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pread64(void* pms)
{
	ms_ocall_pread64_t* ms = SGX_CAST(ms_ocall_pread64_t*, pms);
	ms->ms_retval = ocall_pread64(ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pwrite(void* pms)
{
	ms_ocall_pwrite_t* ms = SGX_CAST(ms_ocall_pwrite_t*, pms);
	ms->ms_retval = ocall_pwrite(ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fopen(void* pms)
{
	ms_ocall_fopen_t* ms = SGX_CAST(ms_ocall_fopen_t*, pms);
	ms->ms_retval = ocall_fopen(ms->ms_filename, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fdopen(void* pms)
{
	ms_ocall_fdopen_t* ms = SGX_CAST(ms_ocall_fdopen_t*, pms);
	ms->ms_retval = ocall_fdopen(ms->ms_fd, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fclose(void* pms)
{
	ms_ocall_fclose_t* ms = SGX_CAST(ms_ocall_fclose_t*, pms);
	ms->ms_retval = ocall_fclose(ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fwrite(void* pms)
{
	ms_ocall_fwrite_t* ms = SGX_CAST(ms_ocall_fwrite_t*, pms);
	ms->ms_retval = ocall_fwrite(ms->ms_ptr, ms->ms_size, ms->ms_nmemb, ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fread(void* pms)
{
	ms_ocall_fread_t* ms = SGX_CAST(ms_ocall_fread_t*, pms);
	ms->ms_retval = ocall_fread(ms->ms_ptr, ms->ms_size, ms->ms_nmemb, ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fseeko(void* pms)
{
	ms_ocall_fseeko_t* ms = SGX_CAST(ms_ocall_fseeko_t*, pms);
	ms->ms_retval = ocall_fseeko(ms->ms_file, ms->ms_offset, ms->ms_whence);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_ftello(void* pms)
{
	ms_ocall_ftello_t* ms = SGX_CAST(ms_ocall_ftello_t*, pms);
	ms->ms_retval = ocall_ftello(ms->ms_file);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read(void* pms)
{
	ms_ocall_read_t* ms = SGX_CAST(ms_ocall_read_t*, pms);
	ms->ms_retval = ocall_read(ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write(void* pms)
{
	ms_ocall_write_t* ms = SGX_CAST(ms_ocall_write_t*, pms);
	ms->ms_retval = ocall_write(ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fscanf(void* pms)
{
	ms_ocall_fscanf_t* ms = SGX_CAST(ms_ocall_fscanf_t*, pms);
	ms->ms_retval = ocall_fscanf(ms->ms_stream, ms->ms_format);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fprintf(void* pms)
{
	ms_ocall_fprintf_t* ms = SGX_CAST(ms_ocall_fprintf_t*, pms);
	ms->ms_retval = ocall_fprintf(ms->ms_stream, ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fgets(void* pms)
{
	ms_ocall_fgets_t* ms = SGX_CAST(ms_ocall_fgets_t*, pms);
	ocall_fgets(ms->ms_str, ms->ms_n, ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_stderr(void* pms)
{
	ms_ocall_stderr_t* ms = SGX_CAST(ms_ocall_stderr_t*, pms);
	ms->ms_retval = ocall_stderr();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_puts(void* pms)
{
	ms_ocall_puts_t* ms = SGX_CAST(ms_ocall_puts_t*, pms);
	ms->ms_retval = ocall_puts(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getchar(void* pms)
{
	ms_ocall_getchar_t* ms = SGX_CAST(ms_ocall_getchar_t*, pms);
	ms->ms_retval = ocall_getchar();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mkdir(void* pms)
{
	ms_ocall_mkdir_t* ms = SGX_CAST(ms_ocall_mkdir_t*, pms);
	ms->ms_retval = ocall_mkdir(ms->ms_pathname, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_truncate(void* pms)
{
	ms_ocall_truncate_t* ms = SGX_CAST(ms_ocall_truncate_t*, pms);
	ms->ms_retval = ocall_truncate(ms->ms_path, ms->ms_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_ftruncate64(void* pms)
{
	ms_ocall_ftruncate64_t* ms = SGX_CAST(ms_ocall_ftruncate64_t*, pms);
	ms->ms_retval = ocall_ftruncate64(ms->ms_fd, ms->ms_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mmap64(void* pms)
{
	ms_ocall_mmap64_t* ms = SGX_CAST(ms_ocall_mmap64_t*, pms);
	ms->ms_retval = ocall_mmap64(ms->ms_addr, ms->ms_len, ms->ms_prot, ms->ms_flags, ms->ms_fildes, ms->ms_off);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pwrite64(void* pms)
{
	ms_ocall_pwrite64_t* ms = SGX_CAST(ms_ocall_pwrite64_t*, pms);
	ms->ms_retval = ocall_pwrite64(ms->ms_fd, ms->ms_buf, ms->ms_nbyte, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fdatasync(void* pms)
{
	ms_ocall_fdatasync_t* ms = SGX_CAST(ms_ocall_fdatasync_t*, pms);
	ms->ms_retval = ocall_fdatasync(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_rename(void* pms)
{
	ms_ocall_rename_t* ms = SGX_CAST(ms_ocall_rename_t*, pms);
	ms->ms_retval = ocall_rename(ms->ms_oldpath, ms->ms_newpath);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_unlink(void* pms)
{
	ms_ocall_unlink_t* ms = SGX_CAST(ms_ocall_unlink_t*, pms);
	ms->ms_retval = ocall_unlink(ms->ms_pathname);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_rmdir(void* pms)
{
	ms_ocall_rmdir_t* ms = SGX_CAST(ms_ocall_rmdir_t*, pms);
	ms->ms_retval = ocall_rmdir(ms->ms_pathname);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_times(void* pms)
{
	ms_ocall_times_t* ms = SGX_CAST(ms_ocall_times_t*, pms);
	ms->ms_retval = ocall_times();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_chown(void* pms)
{
	ms_ocall_chown_t* ms = SGX_CAST(ms_ocall_chown_t*, pms);
	ms->ms_retval = ocall_chown(ms->ms_pathname, ms->ms_owner, ms->ms_group);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fchown(void* pms)
{
	ms_ocall_fchown_t* ms = SGX_CAST(ms_ocall_fchown_t*, pms);
	ms->ms_retval = ocall_fchown(ms->ms_fd, ms->ms_owner, ms->ms_group);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lchown(void* pms)
{
	ms_ocall_lchown_t* ms = SGX_CAST(ms_ocall_lchown_t*, pms);
	ms->ms_retval = ocall_lchown(ms->ms_pathname, ms->ms_owner, ms->ms_group);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_chmod(void* pms)
{
	ms_ocall_chmod_t* ms = SGX_CAST(ms_ocall_chmod_t*, pms);
	ms->ms_retval = ocall_chmod(ms->ms_pathname, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fchmod(void* pms)
{
	ms_ocall_fchmod_t* ms = SGX_CAST(ms_ocall_fchmod_t*, pms);
	ms->ms_retval = ocall_fchmod(ms->ms_fd, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lxstat64(void* pms)
{
	ms_ocall_lxstat64_t* ms = SGX_CAST(ms_ocall_lxstat64_t*, pms);
	ms->ms_retval = ocall_lxstat64(ms->ms_ver, ms->ms_path, ms->ms_stat_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fcntl(void* pms)
{
	ms_ocall_fcntl_t* ms = SGX_CAST(ms_ocall_fcntl_t*, pms);
	ms->ms_retval = ocall_fcntl(ms->ms_fildes, ms->ms_cmd, ms->ms_arg);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_ioctl(void* pms)
{
	ms_ocall_ioctl_t* ms = SGX_CAST(ms_ocall_ioctl_t*, pms);
	ms->ms_retval = ocall_ioctl(ms->ms_fd, ms->ms_request, ms->ms_arg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_xstat64(void* pms)
{
	ms_ocall_xstat64_t* ms = SGX_CAST(ms_ocall_xstat64_t*, pms);
	ms->ms_retval = ocall_xstat64(ms->ms_ver, ms->ms_path, ms->ms_stat_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_stat(void* pms)
{
	ms_ocall_stat_t* ms = SGX_CAST(ms_ocall_stat_t*, pms);
	ms->ms_retval = ocall_stat(ms->ms_path, ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fstat(void* pms)
{
	ms_ocall_fstat_t* ms = SGX_CAST(ms_ocall_fstat_t*, pms);
	ms->ms_retval = ocall_fstat(ms->ms_fd, ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lstat(void* pms)
{
	ms_ocall_lstat_t* ms = SGX_CAST(ms_ocall_lstat_t*, pms);
	ms->ms_retval = ocall_lstat(ms->ms_path, ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fstat64(void* pms)
{
	ms_ocall_fstat64_t* ms = SGX_CAST(ms_ocall_fstat64_t*, pms);
	ms->ms_retval = ocall_fstat64(ms->ms_fd, ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fxstat64(void* pms)
{
	ms_ocall_fxstat64_t* ms = SGX_CAST(ms_ocall_fxstat64_t*, pms);
	ms->ms_retval = ocall_fxstat64(ms->ms_ver, ms->ms_fildes, ms->ms_stat_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fxstat(void* pms)
{
	ms_ocall_fxstat_t* ms = SGX_CAST(ms_ocall_fxstat_t*, pms);
	ms->ms_retval = ocall_fxstat(ms->ms_ver, ms->ms_fd, ms->ms_stat_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lxstat(void* pms)
{
	ms_ocall_lxstat_t* ms = SGX_CAST(ms_ocall_lxstat_t*, pms);
	ms->ms_retval = ocall_lxstat(ms->ms_ver, ms->ms_path, ms->ms_stat_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_xstat(void* pms)
{
	ms_ocall_xstat_t* ms = SGX_CAST(ms_ocall_xstat_t*, pms);
	ms->ms_retval = ocall_xstat(ms->ms_ver, ms->ms_path, ms->ms_stat_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pathconf(void* pms)
{
	ms_ocall_pathconf_t* ms = SGX_CAST(ms_ocall_pathconf_t*, pms);
	ms->ms_retval = ocall_pathconf(ms->ms_path, ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readlink(void* pms)
{
	ms_ocall_readlink_t* ms = SGX_CAST(ms_ocall_readlink_t*, pms);
	ms->ms_retval = ocall_readlink(ms->ms_pathname, ms->ms_buf, ms->ms_bufsiz);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readdir64_r(void* pms)
{
	ms_ocall_readdir64_r_t* ms = SGX_CAST(ms_ocall_readdir64_r_t*, pms);
	ms->ms_retval = ocall_readdir64_r(ms->ms_dirp, ms->ms_entry, ms->ms_result);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_opendir(void* pms)
{
	ms_ocall_opendir_t* ms = SGX_CAST(ms_ocall_opendir_t*, pms);
	ms->ms_retval = ocall_opendir(ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_chdir(void* pms)
{
	ms_ocall_chdir_t* ms = SGX_CAST(ms_ocall_chdir_t*, pms);
	ms->ms_retval = ocall_chdir(ms->ms_path);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closedir(void* pms)
{
	ms_ocall_closedir_t* ms = SGX_CAST(ms_ocall_closedir_t*, pms);
	ms->ms_retval = ocall_closedir(ms->ms_dirp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_xmknod(void* pms)
{
	ms_ocall_xmknod_t* ms = SGX_CAST(ms_ocall_xmknod_t*, pms);
	ms->ms_retval = ocall_xmknod(ms->ms_vers, ms->ms_path, ms->ms_mode, ms->ms_dev);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_symlink(void* pms)
{
	ms_ocall_symlink_t* ms = SGX_CAST(ms_ocall_symlink_t*, pms);
	ms->ms_retval = ocall_symlink(ms->ms_target, ms->ms_linkpath);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_deflateEnd(void* pms)
{
	ms_ocall_deflateEnd_t* ms = SGX_CAST(ms_ocall_deflateEnd_t*, pms);
	ms->ms_retval = ocall_deflateEnd(ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_deflateParams(void* pms)
{
	ms_ocall_deflateParams_t* ms = SGX_CAST(ms_ocall_deflateParams_t*, pms);
	ms->ms_retval = ocall_deflateParams(ms->ms_stream, ms->ms_level, ms->ms_strategy);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_deflate(void* pms)
{
	ms_ocall_deflate_t* ms = SGX_CAST(ms_ocall_deflate_t*, pms);
	ms->ms_retval = ocall_deflate(ms->ms_stream, ms->ms_flush);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_deflateInit2(void* pms)
{
	ms_ocall_deflateInit2_t* ms = SGX_CAST(ms_ocall_deflateInit2_t*, pms);
	ms->ms_retval = ocall_deflateInit2(ms->ms_stream, ms->ms_level, ms->ms_method, ms->ms_windowBits, ms->ms_memLevel, ms->ms_strategy);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_inflateReset(void* pms)
{
	ms_ocall_inflateReset_t* ms = SGX_CAST(ms_ocall_inflateReset_t*, pms);
	ms->ms_retval = ocall_inflateReset(ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sendfile64(void* pms)
{
	ms_ocall_sendfile64_t* ms = SGX_CAST(ms_ocall_sendfile64_t*, pms);
	ms->ms_retval = ocall_sendfile64(ms->ms_out_fd, ms->ms_in_fd, ms->ms_offset, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_adler32(void* pms)
{
	ms_ocall_adler32_t* ms = SGX_CAST(ms_ocall_adler32_t*, pms);
	ms->ms_retval = ocall_adler32(ms->ms_adler, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getenv(void* pms)
{
	ms_ocall_getenv_t* ms = SGX_CAST(ms_ocall_getenv_t*, pms);
	ms->ms_retval = ocall_getenv(ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fileno(void* pms)
{
	ms_ocall_fileno_t* ms = SGX_CAST(ms_ocall_fileno_t*, pms);
	ms->ms_retval = ocall_fileno(ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_isatty(void* pms)
{
	ms_ocall_isatty_t* ms = SGX_CAST(ms_ocall_isatty_t*, pms);
	ms->ms_retval = ocall_isatty(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_umask(void* pms)
{
	ms_ocall_umask_t* ms = SGX_CAST(ms_ocall_umask_t*, pms);
	ms->ms_retval = ocall_umask(ms->ms_mask);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fputc(void* pms)
{
	ms_ocall_fputc_t* ms = SGX_CAST(ms_ocall_fputc_t*, pms);
	ms->ms_retval = ocall_fputc(ms->ms_c, ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_putc(void* pms)
{
	ms_ocall_putc_t* ms = SGX_CAST(ms_ocall_putc_t*, pms);
	ms->ms_retval = ocall_putc(ms->ms_c, ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_socket(void* pms)
{
	ms_ocall_socket_t* ms = SGX_CAST(ms_ocall_socket_t*, pms);
	ms->ms_retval = ocall_socket(ms->ms_domain, ms->ms_type, ms->ms_protocol);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getsockname(void* pms)
{
	ms_ocall_getsockname_t* ms = SGX_CAST(ms_ocall_getsockname_t*, pms);
	ms->ms_retval = ocall_getsockname(ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getaddrinfo(void* pms)
{
	ms_ocall_getaddrinfo_t* ms = SGX_CAST(ms_ocall_getaddrinfo_t*, pms);
	ms->ms_retval = ocall_getaddrinfo(ms->ms_node, ms->ms_service, ms->ms_hints, ms->ms_res);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getnameinfo(void* pms)
{
	ms_ocall_getnameinfo_t* ms = SGX_CAST(ms_ocall_getnameinfo_t*, pms);
	ms->ms_retval = ocall_getnameinfo(ms->ms_addr, ms->ms_addrlen, ms->ms_host, ms->ms_hostlen, ms->ms_serv, ms->ms_servlen, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_freeaddrinfo(void* pms)
{
	ms_ocall_freeaddrinfo_t* ms = SGX_CAST(ms_ocall_freeaddrinfo_t*, pms);
	ocall_freeaddrinfo(ms->ms_res);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_gethostname(void* pms)
{
	ms_ocall_gethostname_t* ms = SGX_CAST(ms_ocall_gethostname_t*, pms);
	ms->ms_retval = ocall_gethostname(ms->ms_name, ms->ms_namelen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sethostname(void* pms)
{
	ms_ocall_sethostname_t* ms = SGX_CAST(ms_ocall_sethostname_t*, pms);
	ms->ms_retval = ocall_sethostname(ms->ms_name, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_gettimeofday(void* pms)
{
	ms_ocall_gettimeofday_t* ms = SGX_CAST(ms_ocall_gettimeofday_t*, pms);
	ms->ms_retval = ocall_gettimeofday(ms->ms_tv, ms->ms_tv_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_clock_gettime(void* pms)
{
	ms_ocall_clock_gettime_t* ms = SGX_CAST(ms_ocall_clock_gettime_t*, pms);
	ms->ms_retval = ocall_clock_gettime(ms->ms_clk_id, ms->ms_tp, ms->ms_ts_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_inet_pton(void* pms)
{
	ms_ocall_inet_pton_t* ms = SGX_CAST(ms_ocall_inet_pton_t*, pms);
	ms->ms_retval = ocall_inet_pton(ms->ms_af, ms->ms_src, ms->ms_dst);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getpid(void* pms)
{
	ms_ocall_getpid_t* ms = SGX_CAST(ms_ocall_getpid_t*, pms);
	ms->ms_retval = ocall_getpid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_remove(void* pms)
{
	ms_ocall_remove_t* ms = SGX_CAST(ms_ocall_remove_t*, pms);
	ms->ms_retval = ocall_remove(ms->ms_pathname);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_shutdown(void* pms)
{
	ms_ocall_shutdown_t* ms = SGX_CAST(ms_ocall_shutdown_t*, pms);
	ms->ms_retval = ocall_shutdown(ms->ms_sockfd, ms->ms_how);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getsockopt(void* pms)
{
	ms_ocall_getsockopt_t* ms = SGX_CAST(ms_ocall_getsockopt_t*, pms);
	ms->ms_retval = ocall_getsockopt(ms->ms_socket, ms->ms_level, ms->ms_option_name, ms->ms_option_value, ms->ms_option_len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_setsockopt(void* pms)
{
	ms_ocall_setsockopt_t* ms = SGX_CAST(ms_ocall_setsockopt_t*, pms);
	ms->ms_retval = ocall_setsockopt(ms->ms_socket, ms->ms_level, ms->ms_option_name, ms->ms_option_value, ms->ms_option_len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_socketpair(void* pms)
{
	ms_ocall_socketpair_t* ms = SGX_CAST(ms_ocall_socketpair_t*, pms);
	ms->ms_retval = ocall_socketpair(ms->ms_domain, ms->ms_type, ms->ms_protocol, ms->ms_sv);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_bind(void* pms)
{
	ms_ocall_bind_t* ms = SGX_CAST(ms_ocall_bind_t*, pms);
	ms->ms_retval = ocall_bind(ms->ms_socket, ms->ms_address, ms->ms_address_len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_epoll_wait(void* pms)
{
	ms_ocall_epoll_wait_t* ms = SGX_CAST(ms_ocall_epoll_wait_t*, pms);
	ms->ms_retval = ocall_epoll_wait(ms->ms_epfd, ms->ms_events, ms->ms_maxevents, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_epoll_ctl(void* pms)
{
	ms_ocall_epoll_ctl_t* ms = SGX_CAST(ms_ocall_epoll_ctl_t*, pms);
	ms->ms_retval = ocall_epoll_ctl(ms->ms_epfd, ms->ms_op, ms->ms_fd, ms->ms_event);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readv(void* pms)
{
	ms_ocall_readv_t* ms = SGX_CAST(ms_ocall_readv_t*, pms);
	ms->ms_retval = ocall_readv(ms->ms_fd, ms->ms_iov, ms->ms_iovcnt);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_writev(void* pms)
{
	ms_ocall_writev_t* ms = SGX_CAST(ms_ocall_writev_t*, pms);
	ms->ms_retval = ocall_writev(ms->ms_fd, ms->ms_iov, ms->ms_iovcnt);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pipe(void* pms)
{
	ms_ocall_pipe_t* ms = SGX_CAST(ms_ocall_pipe_t*, pms);
	ms->ms_retval = ocall_pipe(ms->ms_pipefd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_connect(void* pms)
{
	ms_ocall_connect_t* ms = SGX_CAST(ms_ocall_connect_t*, pms);
	ms->ms_retval = ocall_connect(ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_listen(void* pms)
{
	ms_ocall_listen_t* ms = SGX_CAST(ms_ocall_listen_t*, pms);
	ms->ms_retval = ocall_listen(ms->ms_socket, ms->ms_backlog);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_accept(void* pms)
{
	ms_ocall_accept_t* ms = SGX_CAST(ms_ocall_accept_t*, pms);
	ms->ms_retval = ocall_accept(ms->ms_socket, ms->ms_address, ms->ms_address_len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_accept4(void* pms)
{
	ms_ocall_accept4_t* ms = SGX_CAST(ms_ocall_accept4_t*, pms);
	ms->ms_retval = ocall_accept4(ms->ms_socket, ms->ms_address, ms->ms_address_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_poll(void* pms)
{
	ms_ocall_poll_t* ms = SGX_CAST(ms_ocall_poll_t*, pms);
	ms->ms_retval = ocall_poll(ms->ms_fds, ms->ms_nfds, ms->ms_timeout);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_epoll_create(void* pms)
{
	ms_ocall_epoll_create_t* ms = SGX_CAST(ms_ocall_epoll_create_t*, pms);
	ms->ms_retval = ocall_epoll_create(ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getpeername(void* pms)
{
	ms_ocall_getpeername_t* ms = SGX_CAST(ms_ocall_getpeername_t*, pms);
	ms->ms_retval = ocall_getpeername(ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_recv(void* pms)
{
	ms_ocall_recv_t* ms = SGX_CAST(ms_ocall_recv_t*, pms);
	ms->ms_retval = ocall_recv(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_send(void* pms)
{
	ms_ocall_send_t* ms = SGX_CAST(ms_ocall_send_t*, pms);
	ms->ms_retval = ocall_send(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sendto(void* pms)
{
	ms_ocall_sendto_t* ms = SGX_CAST(ms_ocall_sendto_t*, pms);
	ms->ms_retval = ocall_sendto(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags, ms->ms_dest_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sendmsg(void* pms)
{
	ms_ocall_sendmsg_t* ms = SGX_CAST(ms_ocall_sendmsg_t*, pms);
	ms->ms_retval = ocall_sendmsg(ms->ms_sockfd, ms->ms_msg, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_recvfrom(void* pms)
{
	ms_ocall_recvfrom_t* ms = SGX_CAST(ms_ocall_recvfrom_t*, pms);
	ms->ms_retval = ocall_recvfrom(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags, ms->ms_src_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_recvmsg(void* pms)
{
	ms_ocall_recvmsg_t* ms = SGX_CAST(ms_ocall_recvmsg_t*, pms);
	ms->ms_retval = ocall_recvmsg(ms->ms_sockfd, ms->ms_msg, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_htonl(void* pms)
{
	ms_ocall_htonl_t* ms = SGX_CAST(ms_ocall_htonl_t*, pms);
	ms->ms_retval = ocall_htonl(ms->ms_hostlong);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_htons(void* pms)
{
	ms_ocall_htons_t* ms = SGX_CAST(ms_ocall_htons_t*, pms);
	ms->ms_retval = ocall_htons(ms->ms_hostshort);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_ntohl(void* pms)
{
	ms_ocall_ntohl_t* ms = SGX_CAST(ms_ocall_ntohl_t*, pms);
	ms->ms_retval = ocall_ntohl(ms->ms_netlong);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_ntohs(void* pms)
{
	ms_ocall_ntohs_t* ms = SGX_CAST(ms_ocall_ntohs_t*, pms);
	ms->ms_retval = ocall_ntohs(ms->ms_netshort);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_time(void* pms)
{
	ms_ocall_time_t* ms = SGX_CAST(ms_ocall_time_t*, pms);
	ms->ms_retval = ocall_time(ms->ms_t);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_inet_ntop(void* pms)
{
	ms_ocall_inet_ntop_t* ms = SGX_CAST(ms_ocall_inet_ntop_t*, pms);
	ms->ms_retval = ocall_inet_ntop(ms->ms_af, ms->ms_src, ms->ms_dst, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_dlsym(void* pms)
{
	ms_ocall_dlsym_t* ms = SGX_CAST(ms_ocall_dlsym_t*, pms);
	ocall_dlsym(ms->ms_handle, ms->ms_symbol, ms->ms_res);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_dlopen(void* pms)
{
	ms_ocall_dlopen_t* ms = SGX_CAST(ms_ocall_dlopen_t*, pms);
	ms->ms_retval = ocall_dlopen(ms->ms_symbol, ms->ms_flag);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sysconf(void* pms)
{
	ms_ocall_sysconf_t* ms = SGX_CAST(ms_ocall_sysconf_t*, pms);
	ms->ms_retval = ocall_sysconf(ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getuid(void* pms)
{
	ms_ocall_getuid_t* ms = SGX_CAST(ms_ocall_getuid_t*, pms);
	ms->ms_retval = ocall_getuid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_geteuid(void* pms)
{
	ms_ocall_geteuid_t* ms = SGX_CAST(ms_ocall_geteuid_t*, pms);
	ms->ms_retval = ocall_geteuid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getcwd(void* pms)
{
	ms_ocall_getcwd_t* ms = SGX_CAST(ms_ocall_getcwd_t*, pms);
	ocall_getcwd(ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getpwuid(void* pms)
{
	ms_ocall_getpwuid_t* ms = SGX_CAST(ms_ocall_getpwuid_t*, pms);
	ocall_getpwuid(ms->ms_uid, ms->ms_ret);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_exit(void* pms)
{
	ms_ocall_exit_t* ms = SGX_CAST(ms_ocall_exit_t*, pms);
	ocall_exit(ms->ms_stat);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getrlimit(void* pms)
{
	ms_ocall_getrlimit_t* ms = SGX_CAST(ms_ocall_getrlimit_t*, pms);
	ms->ms_retval = ocall_getrlimit(ms->ms_res, ms->ms_rlim);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_setrlimit(void* pms)
{
	ms_ocall_setrlimit_t* ms = SGX_CAST(ms_ocall_setrlimit_t*, pms);
	ms->ms_retval = ocall_setrlimit(ms->ms_resource, ms->ms_rlim);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_uname(void* pms)
{
	ms_ocall_uname_t* ms = SGX_CAST(ms_ocall_uname_t*, pms);
	ms->ms_retval = ocall_uname(ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sleep(void* pms)
{
	ms_ocall_sleep_t* ms = SGX_CAST(ms_ocall_sleep_t*, pms);
	ms->ms_retval = ocall_sleep(ms->ms_secs);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_usleep(void* pms)
{
	ms_ocall_usleep_t* ms = SGX_CAST(ms_ocall_usleep_t*, pms);
	ms->ms_retval = ocall_usleep(ms->ms_usec);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_realpath(void* pms)
{
	ms_ocall_realpath_t* ms = SGX_CAST(ms_ocall_realpath_t*, pms);
	ocall_realpath(ms->ms_path, ms->ms_res_path);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_xpg_strerror_r(void* pms)
{
	ms_ocall_xpg_strerror_r_t* ms = SGX_CAST(ms_ocall_xpg_strerror_r_t*, pms);
	ocall_xpg_strerror_r(ms->ms_errnum, ms->ms_buf, ms->ms_buflen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_signal(void* pms)
{
	ms_ocall_signal_t* ms = SGX_CAST(ms_ocall_signal_t*, pms);
	ms->ms_retval = ocall_signal(ms->ms_signum, ms->ms_handler);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_kill(void* pms)
{
	ms_ocall_kill_t* ms = SGX_CAST(ms_ocall_kill_t*, pms);
	ms->ms_retval = ocall_kill(ms->ms_pid, ms->ms_sig);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_cpuid_max(void* pms)
{
	ms_ocall_get_cpuid_max_t* ms = SGX_CAST(ms_ocall_get_cpuid_max_t*, pms);
	ms->ms_retval = ocall_get_cpuid_max(ms->ms_ext, ms->ms_sig);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_cpuid_count(void* pms)
{
	ms_ocall_get_cpuid_count_t* ms = SGX_CAST(ms_ocall_get_cpuid_count_t*, pms);
	ms->ms_retval = ocall_get_cpuid_count(ms->ms_leaf, ms->ms_subleaf, ms->ms_eax, ms->ms_ebx, ms->ms_ecx, ms->ms_edx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_attr_init(void* pms)
{
	ms_ocall_pthread_attr_init_t* ms = SGX_CAST(ms_ocall_pthread_attr_init_t*, pms);
	ms->ms_retval = ocall_pthread_attr_init();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_create(void* pms)
{
	ms_ocall_pthread_create_t* ms = SGX_CAST(ms_ocall_pthread_create_t*, pms);
	ms->ms_retval = ocall_pthread_create(ms->ms_new_thread, ms->ms_job_id, ms->ms_eid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_self(void* pms)
{
	ms_ocall_pthread_self_t* ms = SGX_CAST(ms_ocall_pthread_self_t*, pms);
	ms->ms_retval = ocall_pthread_self();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_join(void* pms)
{
	ms_ocall_pthread_join_t* ms = SGX_CAST(ms_ocall_pthread_join_t*, pms);
	ms->ms_retval = ocall_pthread_join(ms->ms_pt, ms->ms_res);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_attr_getguardsize(void* pms)
{
	ms_ocall_pthread_attr_getguardsize_t* ms = SGX_CAST(ms_ocall_pthread_attr_getguardsize_t*, pms);
	ms->ms_retval = ocall_pthread_attr_getguardsize(ms->ms_guardsize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_attr_getguardsize__bypass(void* pms)
{
	ms_ocall_pthread_attr_getguardsize__bypass_t* ms = SGX_CAST(ms_ocall_pthread_attr_getguardsize__bypass_t*, pms);
	ms->ms_retval = ocall_pthread_attr_getguardsize__bypass(ms->ms_attr, ms->ms_attr_len, ms->ms_guardsize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_attr_destroy(void* pms)
{
	ms_ocall_pthread_attr_destroy_t* ms = SGX_CAST(ms_ocall_pthread_attr_destroy_t*, pms);
	ms->ms_retval = ocall_pthread_attr_destroy();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_condattr_setclock(void* pms)
{
	ms_ocall_pthread_condattr_setclock_t* ms = SGX_CAST(ms_ocall_pthread_condattr_setclock_t*, pms);
	ms->ms_retval = ocall_pthread_condattr_setclock(ms->ms_attr, ms->ms_clock_id, ms->ms_attr_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_attr_destroy__bypass(void* pms)
{
	ms_ocall_pthread_attr_destroy__bypass_t* ms = SGX_CAST(ms_ocall_pthread_attr_destroy__bypass_t*, pms);
	ms->ms_retval = ocall_pthread_attr_destroy__bypass(ms->ms_attr, ms->ms_attr_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_attr_getstack(void* pms)
{
	ms_ocall_pthread_attr_getstack_t* ms = SGX_CAST(ms_ocall_pthread_attr_getstack_t*, pms);
	ms->ms_retval = ocall_pthread_attr_getstack(ms->ms_stk_addr, ms->ms_stack_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_attr_getstack__bypass(void* pms)
{
	ms_ocall_pthread_attr_getstack__bypass_t* ms = SGX_CAST(ms_ocall_pthread_attr_getstack__bypass_t*, pms);
	ms->ms_retval = ocall_pthread_attr_getstack__bypass(ms->ms_attr, ms->ms_attr_len, ms->ms_stk_addr, ms->ms_len, ms->ms_stack_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_getattr_np(void* pms)
{
	ms_ocall_pthread_getattr_np_t* ms = SGX_CAST(ms_ocall_pthread_getattr_np_t*, pms);
	ms->ms_retval = ocall_pthread_getattr_np(ms->ms_tid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_getattr_np__bypass(void* pms)
{
	ms_ocall_pthread_getattr_np__bypass_t* ms = SGX_CAST(ms_ocall_pthread_getattr_np__bypass_t*, pms);
	ms->ms_retval = ocall_pthread_getattr_np__bypass(ms->ms_tid, ms->ms_attr, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_event_del(void* pms)
{
	ms_ocall_event_del_t* ms = SGX_CAST(ms_ocall_event_del_t*, pms);
	ms->ms_retval = ocall_event_del(ms->ms_ev);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_event_base_set(void* pms)
{
	ms_ocall_event_base_set_t* ms = SGX_CAST(ms_ocall_event_base_set_t*, pms);
	ms->ms_retval = ocall_event_base_set(ms->ms_evb, ms->ms_ev);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_event_add(void* pms)
{
	ms_ocall_event_add_t* ms = SGX_CAST(ms_ocall_event_add_t*, pms);
	ms->ms_retval = ocall_event_add(ms->ms_ev, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_mcd_ocall_setup_conn_event(void* pms)
{
	ms_mcd_ocall_setup_conn_event_t* ms = SGX_CAST(ms_mcd_ocall_setup_conn_event_t*, pms);
	ms->ms_retval = mcd_ocall_setup_conn_event(ms->ms_fd, ms->ms_event_flags, ms->ms_base, ms->ms_c, ms->ms_conn_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_mcd_ocall_update_conn_event(void* pms)
{
	ms_mcd_ocall_update_conn_event_t* ms = SGX_CAST(ms_mcd_ocall_update_conn_event_t*, pms);
	mcd_ocall_update_conn_event(ms->ms_fd, ms->ms_event_flags, ms->ms_base, ms->ms_c, ms->ms_conn_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_mcd_ocall_event_base_loopexit(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	mcd_ocall_event_base_loopexit();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_mcd_ocall_event_del(void* pms)
{
	ms_mcd_ocall_event_del_t* ms = SGX_CAST(ms_mcd_ocall_event_del_t*, pms);
	ms->ms_retval = mcd_ocall_event_del(ms->ms_conn_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_mcd_ocall_event_add(void* pms)
{
	ms_mcd_ocall_event_add_t* ms = SGX_CAST(ms_mcd_ocall_event_add_t*, pms);
	ms->ms_retval = mcd_ocall_event_add(ms->ms_conn_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_mcd_ocall_dispatch_conn_new(void* pms)
{
	ms_mcd_ocall_dispatch_conn_new_t* ms = SGX_CAST(ms_mcd_ocall_dispatch_conn_new_t*, pms);
	mcd_ocall_dispatch_conn_new(ms->ms_sfd, ms->ms_init_state, ms->ms_event_flags, ms->ms_read_buffer_size, ms->ms_transport, ms->ms_ssl);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_mcd_ocall_do_cache_alloc(void* pms)
{
	ms_mcd_ocall_do_cache_alloc_t* ms = SGX_CAST(ms_mcd_ocall_do_cache_alloc_t*, pms);
	ms->ms_retval = mcd_ocall_do_cache_alloc(ms->ms_conn_id, ms->ms_lvt_thread_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_mcd_ocall_do_cache_free(void* pms)
{
	ms_mcd_ocall_do_cache_free_t* ms = SGX_CAST(ms_mcd_ocall_do_cache_free_t*, pms);
	mcd_ocall_do_cache_free(ms->ms_conn_id, ms->ms_lvt_thread_id, ms->ms_bundle);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_mcd_ocall_mutex_lock_lthread_stats(void* pms)
{
	ms_mcd_ocall_mutex_lock_lthread_stats_t* ms = SGX_CAST(ms_mcd_ocall_mutex_lock_lthread_stats_t*, pms);
	mcd_ocall_mutex_lock_lthread_stats(ms->ms_conn_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_mcd_ocall_mutex_unlock_lthread_stats(void* pms)
{
	ms_mcd_ocall_mutex_unlock_lthread_stats_t* ms = SGX_CAST(ms_mcd_ocall_mutex_unlock_lthread_stats_t*, pms);
	mcd_ocall_mutex_unlock_lthread_stats(ms->ms_conn_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_transmit_prepare(void* pms)
{
	ms_ocall_transmit_prepare_t* ms = SGX_CAST(ms_ocall_transmit_prepare_t*, pms);
	ms->ms_retval = ocall_transmit_prepare();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getErrno(void* pms)
{
	ms_ocall_getErrno_t* ms = SGX_CAST(ms_ocall_getErrno_t*, pms);
	ms->ms_retval = ocall_getErrno();

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[176];
} ocall_table_Enclave = {
	176,
	{
		(void*)Enclave_ocall_malloc,
		(void*)Enclave_ocall_realloc,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_gettid,
		(void*)Enclave_ocall_bench,
		(void*)Enclave_ocall_empty,
		(void*)Enclave_ocall_fsync,
		(void*)Enclave_ocall_dup2,
		(void*)Enclave_ocall_open,
		(void*)Enclave_ocall_open64,
		(void*)Enclave_ocall_xclose,
		(void*)Enclave_ocall_lseek,
		(void*)Enclave_ocall_lseek64,
		(void*)Enclave_ocall_fflush,
		(void*)Enclave_ocall_pread,
		(void*)Enclave_ocall_pread64,
		(void*)Enclave_ocall_pwrite,
		(void*)Enclave_ocall_fopen,
		(void*)Enclave_ocall_fdopen,
		(void*)Enclave_ocall_fclose,
		(void*)Enclave_ocall_fwrite,
		(void*)Enclave_ocall_fread,
		(void*)Enclave_ocall_fseeko,
		(void*)Enclave_ocall_ftello,
		(void*)Enclave_ocall_read,
		(void*)Enclave_ocall_write,
		(void*)Enclave_ocall_fscanf,
		(void*)Enclave_ocall_fprintf,
		(void*)Enclave_ocall_fgets,
		(void*)Enclave_ocall_stderr,
		(void*)Enclave_ocall_puts,
		(void*)Enclave_ocall_getchar,
		(void*)Enclave_ocall_mkdir,
		(void*)Enclave_ocall_truncate,
		(void*)Enclave_ocall_ftruncate64,
		(void*)Enclave_ocall_mmap64,
		(void*)Enclave_ocall_pwrite64,
		(void*)Enclave_ocall_fdatasync,
		(void*)Enclave_ocall_rename,
		(void*)Enclave_ocall_unlink,
		(void*)Enclave_ocall_rmdir,
		(void*)Enclave_ocall_times,
		(void*)Enclave_ocall_chown,
		(void*)Enclave_ocall_fchown,
		(void*)Enclave_ocall_lchown,
		(void*)Enclave_ocall_chmod,
		(void*)Enclave_ocall_fchmod,
		(void*)Enclave_ocall_lxstat64,
		(void*)Enclave_ocall_fcntl,
		(void*)Enclave_ocall_ioctl,
		(void*)Enclave_ocall_xstat64,
		(void*)Enclave_ocall_stat,
		(void*)Enclave_ocall_fstat,
		(void*)Enclave_ocall_lstat,
		(void*)Enclave_ocall_fstat64,
		(void*)Enclave_ocall_fxstat64,
		(void*)Enclave_ocall_fxstat,
		(void*)Enclave_ocall_lxstat,
		(void*)Enclave_ocall_xstat,
		(void*)Enclave_ocall_pathconf,
		(void*)Enclave_ocall_readlink,
		(void*)Enclave_ocall_readdir64_r,
		(void*)Enclave_ocall_opendir,
		(void*)Enclave_ocall_chdir,
		(void*)Enclave_ocall_closedir,
		(void*)Enclave_ocall_xmknod,
		(void*)Enclave_ocall_symlink,
		(void*)Enclave_ocall_deflateEnd,
		(void*)Enclave_ocall_deflateParams,
		(void*)Enclave_ocall_deflate,
		(void*)Enclave_ocall_deflateInit2,
		(void*)Enclave_ocall_inflateReset,
		(void*)Enclave_ocall_sendfile64,
		(void*)Enclave_ocall_adler32,
		(void*)Enclave_ocall_getenv,
		(void*)Enclave_ocall_fileno,
		(void*)Enclave_ocall_isatty,
		(void*)Enclave_ocall_umask,
		(void*)Enclave_ocall_fputc,
		(void*)Enclave_ocall_putc,
		(void*)Enclave_ocall_socket,
		(void*)Enclave_ocall_getsockname,
		(void*)Enclave_ocall_getaddrinfo,
		(void*)Enclave_ocall_getnameinfo,
		(void*)Enclave_ocall_freeaddrinfo,
		(void*)Enclave_ocall_gethostname,
		(void*)Enclave_ocall_sethostname,
		(void*)Enclave_ocall_gettimeofday,
		(void*)Enclave_ocall_clock_gettime,
		(void*)Enclave_ocall_inet_pton,
		(void*)Enclave_ocall_getpid,
		(void*)Enclave_ocall_remove,
		(void*)Enclave_ocall_shutdown,
		(void*)Enclave_ocall_getsockopt,
		(void*)Enclave_ocall_setsockopt,
		(void*)Enclave_ocall_socketpair,
		(void*)Enclave_ocall_bind,
		(void*)Enclave_ocall_epoll_wait,
		(void*)Enclave_ocall_epoll_ctl,
		(void*)Enclave_ocall_readv,
		(void*)Enclave_ocall_writev,
		(void*)Enclave_ocall_pipe,
		(void*)Enclave_ocall_connect,
		(void*)Enclave_ocall_listen,
		(void*)Enclave_ocall_accept,
		(void*)Enclave_ocall_accept4,
		(void*)Enclave_ocall_poll,
		(void*)Enclave_ocall_epoll_create,
		(void*)Enclave_ocall_getpeername,
		(void*)Enclave_ocall_recv,
		(void*)Enclave_ocall_send,
		(void*)Enclave_ocall_sendto,
		(void*)Enclave_ocall_sendmsg,
		(void*)Enclave_ocall_recvfrom,
		(void*)Enclave_ocall_recvmsg,
		(void*)Enclave_ocall_htonl,
		(void*)Enclave_ocall_htons,
		(void*)Enclave_ocall_ntohl,
		(void*)Enclave_ocall_ntohs,
		(void*)Enclave_ocall_time,
		(void*)Enclave_ocall_inet_ntop,
		(void*)Enclave_ocall_dlsym,
		(void*)Enclave_ocall_dlopen,
		(void*)Enclave_ocall_sysconf,
		(void*)Enclave_ocall_getuid,
		(void*)Enclave_ocall_geteuid,
		(void*)Enclave_ocall_getcwd,
		(void*)Enclave_ocall_getpwuid,
		(void*)Enclave_ocall_exit,
		(void*)Enclave_ocall_getrlimit,
		(void*)Enclave_ocall_setrlimit,
		(void*)Enclave_ocall_uname,
		(void*)Enclave_ocall_sleep,
		(void*)Enclave_ocall_usleep,
		(void*)Enclave_ocall_realpath,
		(void*)Enclave_ocall_xpg_strerror_r,
		(void*)Enclave_ocall_signal,
		(void*)Enclave_ocall_kill,
		(void*)Enclave_ocall_get_cpuid_max,
		(void*)Enclave_ocall_get_cpuid_count,
		(void*)Enclave_ocall_pthread_attr_init,
		(void*)Enclave_ocall_pthread_create,
		(void*)Enclave_ocall_pthread_self,
		(void*)Enclave_ocall_pthread_join,
		(void*)Enclave_ocall_pthread_attr_getguardsize,
		(void*)Enclave_ocall_pthread_attr_getguardsize__bypass,
		(void*)Enclave_ocall_pthread_attr_destroy,
		(void*)Enclave_ocall_pthread_condattr_setclock,
		(void*)Enclave_ocall_pthread_attr_destroy__bypass,
		(void*)Enclave_ocall_pthread_attr_getstack,
		(void*)Enclave_ocall_pthread_attr_getstack__bypass,
		(void*)Enclave_ocall_pthread_getattr_np,
		(void*)Enclave_ocall_pthread_getattr_np__bypass,
		(void*)Enclave_ocall_event_del,
		(void*)Enclave_ocall_event_base_set,
		(void*)Enclave_ocall_event_add,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_pthread_wait_timeout_ocall,
		(void*)Enclave_pthread_create_ocall,
		(void*)Enclave_pthread_wakeup_ocall,
		(void*)Enclave_mcd_ocall_setup_conn_event,
		(void*)Enclave_mcd_ocall_update_conn_event,
		(void*)Enclave_mcd_ocall_event_base_loopexit,
		(void*)Enclave_mcd_ocall_event_del,
		(void*)Enclave_mcd_ocall_event_add,
		(void*)Enclave_mcd_ocall_dispatch_conn_new,
		(void*)Enclave_mcd_ocall_do_cache_alloc,
		(void*)Enclave_mcd_ocall_do_cache_free,
		(void*)Enclave_mcd_ocall_mutex_lock_lthread_stats,
		(void*)Enclave_mcd_ocall_mutex_unlock_lthread_stats,
		(void*)Enclave_ocall_transmit_prepare,
		(void*)Enclave_ocall_getErrno,
	}
};
sgx_status_t ecall_graal_main_args(sgx_enclave_id_t eid, int id, int arg1, struct buffer* switchless_buffers, struct buffer* switchless_buffer, void** sl_fn, void** fn, int* sl_count, int* f_count, int* number_of_workers)
{
	sgx_status_t status;
	ms_ecall_graal_main_args_t ms;
	ms.ms_id = id;
	ms.ms_arg1 = arg1;
	ms.ms_switchless_buffers = switchless_buffers;
	ms.ms_switchless_buffer = switchless_buffer;
	ms.ms_sl_fn = sl_fn;
	ms.ms_fn = fn;
	ms.ms_sl_count = sl_count;
	ms.ms_f_count = f_count;
	ms.ms_number_of_workers = number_of_workers;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_graal_main(sgx_enclave_id_t eid, int id, struct buffer* switchless_buffers, struct buffer* switchless_buffer, void** sl_fn, void** fn, int* sl_count, int* f_count, int* number_of_workers)
{
	sgx_status_t status;
	ms_ecall_graal_main_t ms;
	ms.ms_id = id;
	ms.ms_switchless_buffers = switchless_buffers;
	ms.ms_switchless_buffer = switchless_buffer;
	ms.ms_sl_fn = sl_fn;
	ms.ms_fn = fn;
	ms.ms_sl_count = sl_count;
	ms.ms_f_count = f_count;
	ms.ms_number_of_workers = number_of_workers;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_run_main(sgx_enclave_id_t eid, int id)
{
	sgx_status_t status;
	ms_ecall_run_main_t ms;
	ms.ms_id = id;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_reader(sgx_enclave_id_t eid, int n, int id, struct buffer* switchless_buffers, struct buffer* switchless_buffer, void** sl_fn, void** fn, int* sl_count, int* f_count, int* number_of_workers)
{
	sgx_status_t status;
	ms_ecall_reader_t ms;
	ms.ms_n = n;
	ms.ms_id = id;
	ms.ms_switchless_buffers = switchless_buffers;
	ms.ms_switchless_buffer = switchless_buffer;
	ms.ms_sl_fn = sl_fn;
	ms.ms_fn = fn;
	ms.ms_sl_count = sl_count;
	ms.ms_f_count = f_count;
	ms.ms_number_of_workers = number_of_workers;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_writer(sgx_enclave_id_t eid, int n, int id, struct buffer* switchless_buffers, struct buffer* switchless_buffer, void** sl_fn, void** fn, int* sl_count, int* f_count, int* number_of_workers)
{
	sgx_status_t status;
	ms_ecall_writer_t ms;
	ms.ms_n = n;
	ms.ms_id = id;
	ms.ms_switchless_buffers = switchless_buffers;
	ms.ms_switchless_buffer = switchless_buffer;
	ms.ms_sl_fn = sl_fn;
	ms.ms_fn = fn;
	ms.ms_sl_count = sl_count;
	ms.ms_f_count = f_count;
	ms.ms_number_of_workers = number_of_workers;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_bench_thread(sgx_enclave_id_t eid, struct buffer* bs, struct buffer* b, void** sl_fn, void** fn, int* sl_count, int* f_count, int* number_of_workers)
{
	sgx_status_t status;
	ms_ecall_bench_thread_t ms;
	ms.ms_bs = bs;
	ms.ms_b = b;
	ms.ms_sl_fn = sl_fn;
	ms.ms_fn = fn;
	ms.ms_sl_count = sl_count;
	ms.ms_f_count = f_count;
	ms.ms_number_of_workers = number_of_workers;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_readN(sgx_enclave_id_t eid, int n)
{
	sgx_status_t status;
	ms_ecall_readN_t ms;
	ms.ms_n = n;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_writeN(sgx_enclave_id_t eid, int n)
{
	sgx_status_t status;
	ms_ecall_writeN_t ms;
	ms.ms_n = n;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_kissdb_test(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_readKissdb(sgx_enclave_id_t eid, int n, int storeId)
{
	sgx_status_t status;
	ms_ecall_readKissdb_t ms;
	ms.ms_n = n;
	ms.ms_storeId = storeId;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_writeKissdb(sgx_enclave_id_t eid, int n, int storeId)
{
	sgx_status_t status;
	ms_ecall_writeKissdb_t ms;
	ms.ms_n = n;
	ms.ms_storeId = storeId;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_test(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_execute_job(sgx_enclave_id_t eid, pthread_t pthread_self_id, unsigned long int job_id)
{
	sgx_status_t status;
	ms_ecall_execute_job_t ms;
	ms.ms_pthread_self_id = pthread_self_id;
	ms.ms_job_id = job_id;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_init_settings(sgx_enclave_id_t eid, int numWorkers)
{
	sgx_status_t status;
	ms_ecall_init_settings_t ms;
	ms.ms_numWorkers = numWorkers;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_init_hash(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_stats_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_init_hashtable(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 16, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_start_assoc_maintenance(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 17, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_start_item_crawler(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 18, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_start_slab_rebalance(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 19, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_assoc_start_expand(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 20, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_init_server_sockets(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 21, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_init_mainbase(sgx_enclave_id_t eid, void* mb)
{
	sgx_status_t status;
	ms_ecall_init_mainbase_t ms;
	ms.ms_mb = mb;
	status = sgx_ecall(eid, 22, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_drive_machine(sgx_enclave_id_t eid, void* conn)
{
	sgx_status_t status;
	ms_ecall_drive_machine_t ms;
	ms.ms_conn = conn;
	status = sgx_ecall(eid, 23, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_uriencode_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 24, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_conn_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 25, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_item_lru_bump_buf_create(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 26, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_thread_libevent_process(sgx_enclave_id_t eid, evutil_socket_t fd, short int which, void* arg)
{
	sgx_status_t status;
	ms_ecall_thread_libevent_process_t ms;
	ms.ms_fd = fd;
	ms.ms_which = which;
	ms.ms_arg = arg;
	status = sgx_ecall(eid, 27, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_event_handler(sgx_enclave_id_t eid, evutil_socket_t fd, short int which, void* arg)
{
	sgx_status_t status;
	ms_ecall_event_handler_t ms;
	ms.ms_fd = fd;
	ms.ms_which = which;
	ms.ms_arg = arg;
	status = sgx_ecall(eid, 28, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_conn_new(sgx_enclave_id_t eid, void** retval, int sfd, enum conn_states init_state, int flags, int rd_buff_sz, enum network_transport tport, struct event_base* base, void* ssl)
{
	sgx_status_t status;
	ms_ecall_conn_new_t ms;
	ms.ms_sfd = sfd;
	ms.ms_init_state = init_state;
	ms.ms_flags = flags;
	ms.ms_rd_buff_sz = rd_buff_sz;
	ms.ms_tport = tport;
	ms.ms_base = base;
	ms.ms_ssl = ssl;
	status = sgx_ecall(eid, 29, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_conn_io_queue_add(sgx_enclave_id_t eid, void* c, int type)
{
	sgx_status_t status;
	ms_ecall_conn_io_queue_add_t ms;
	ms.ms_c = c;
	ms.ms_type = type;
	status = sgx_ecall(eid, 30, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_set_conn_thread(sgx_enclave_id_t eid, void* c, void* libevent_thread)
{
	sgx_status_t status;
	ms_ecall_set_conn_thread_t ms;
	ms.ms_c = c;
	ms.ms_libevent_thread = libevent_thread;
	status = sgx_ecall(eid, 31, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t sl_init_switchless(sgx_enclave_id_t eid, sgx_status_t* retval, void* sl_data)
{
	sgx_status_t status;
	ms_sl_init_switchless_t ms;
	ms.ms_sl_data = sl_data;
	status = sgx_ecall(eid, 32, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sl_run_switchless_tworker(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_sl_run_switchless_tworker_t ms;
	status = sgx_ecall(eid, 33, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

