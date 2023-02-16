
/*
 * Created on Tue Jul 21 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

/**
 * Quick note on TODOs: most of the routines should be simple to reimplement with ocalls.
 * A few may require special attention. For example routines with struct or other complex
 * types as return or param types.
 */

#include "checks.h"  //for pointer checks
#include "Enclave.h" //for printf
#include "graal_sgx_shim_switchless.h"
#include "ocall_manager.h"
#include "zcTrusted/zc_in.h"

// forward declarations
void copy_stats(struct stat *dest, struct stat *src);

void empty(int repeats)
{
    // log_ocall(FN_TOKEN_EMPTY);
    if (should_be_switchless(FN_TOKEN_EMPTY))
        empty_switchless(repeats);
    else
        ocall_empty(repeats);
}

void copy_stats(struct stat *dest, struct stat *src)
{
    dest->st_dev = src->st_dev;
    dest->st_ino = src->st_ino;
    dest->st_mode = src->st_mode;
    dest->st_nlink = src->st_nlink;
    dest->st_uid = src->st_uid;
    dest->st_gid = src->st_gid;
    dest->st_rdev = src->st_rdev;
    dest->st_size = src->st_size;
    dest->st_blksize = src->st_blksize;
    dest->st_blocks = src->st_blocks;
    dest->st_atim = src->st_atim;
    dest->st_mtim = src->st_mtim;
    dest->st_ctim = src->st_ctim;
}

void sgx_exit()
{
    GRAAL_SGX_INFO();
    exit(1);
}

void sync(void)
{
    GRAAL_SGX_INFO();

    int index = reserve_worker();

    if (index != ZC_NO_FREE_POOL)
    {

        zc_sync(index);
    }
    else
    {
        ocall_sync();
    }
}

int syncfs(int fd)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_syncfs(&ret, fd);
    return ret;
}

int fsync(int fd)
{
    GRAAL_SGX_INFO();
    int ret = 0;

    int index = reserve_worker();

    if (index != ZC_NO_FREE_POOL)
    {

        ret = zc_fsync(fd, index);
    }
    else
    {
        ocall_fsync(&ret, fd);
    }
    return ret;
}

/* int msync(void *addr, size_t length, int flags)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_msync(&ret, addr, length, flags);
    return ret;
} */

int dup2(int oldfd, int newfd)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_dup2(&ret, oldfd, newfd);
    /* log_ocall(FN_TOKEN_FSYNC);
    if (should_be_switchless(FN_TOKEN_FSYNC))
        ret = dup2_switchless(oldfd, newfd);
    else
        ocall_dup2(&ret, oldfd, newfd); */
    return ret;
}

int open(const char *path, int oflag, ...)
{
    GRAAL_SGX_INFO();
    va_list ap;
    va_start(ap, oflag);
    int arg = va_arg(ap, int);
    va_end(ap);

    int ret;
    int sgx_ret = ocall_open(&ret, path, oflag, arg);

    if (sgx_ret != SGX_SUCCESS)
    {
        printf("Error in open OCALL\n");
        sgx_exit();
    }

    return ret;
}

int open64(const char *path, int oflag, ...)
{
    GRAAL_SGX_INFO();
    va_list ap;
    va_start(ap, oflag);
    int arg = va_arg(ap, int);
    va_end(ap);

    int ret;
    int sgx_ret = ocall_open64(&ret, path, oflag, arg);

    if (sgx_ret != SGX_SUCCESS)
    {
        printf("Error in open64 OCALL\n");
        sgx_exit();
    }

    return ret;
}

int close(int fd)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_xclose(&ret, fd);
    /* log_ocall(FN_TOKEN_CLOSE);
    if (should_be_switchless(FN_TOKEN_CLOSE))
        ret = close_switchless(fd);
    else
        ocall_xclose(&ret, fd); */
    return ret;
}

SGX_FILE fopen(const char *pathname, const char *mode)
{
    GRAAL_SGX_INFO();
    SGX_FILE f = 0;
    ocall_fopen(&f, pathname, mode);
    return f;
}

SGX_FILE fdopen(int fd, const char *mode)
{
    GRAAL_SGX_INFO();
    SGX_FILE f = 0;
    ocall_fdopen(&f, fd, mode);
    return f;
}
/* SGX_FILE stderr()
{
    GRAAL_SGX_INFO();
    SGX_FILE f = 0;
    ocall_stderr(&f);
    return f;
} */

int fclose(SGX_FILE stream)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_fclose(&ret, stream);
    return ret;
}
size_t fwrite(const void *ptr, size_t size, size_t nmemb, SGX_FILE f)
{
    GRAAL_SGX_INFO();
    size_t ret = 0;
    /* if (should_be_switchless(FN_TOKEN_FWRITE))
        ret = fwrite_switchless(ptr, size, nmemb, f);
    else
        ocall_fwrite(&ret, ptr, size, nmemb, f);
    return ret; */

    int index = reserve_worker();

    if (index != ZC_NO_FREE_POOL)
    {

        ret = zc_fwrite(ptr, size, nmemb, f, index);
    }
    else
    {
        ocall_fwrite(&ret, ptr, size, nmemb, f);
    }
    return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, SGX_FILE f)
{
    GRAAL_SGX_INFO();
    size_t ret = 0;
    int index = reserve_worker();
    index = ZC_NO_FREE_POOL;

    if (index != ZC_NO_FREE_POOL)
    {

        ret = zc_fread(ptr, size, nmemb, f, index);
    }
    else
    {
        ocall_fread(&ret, ptr, size, nmemb, f);
    }

    return ret;
}

int fseeko(SGX_FILE file, off_t offset, int whence)
{
    GRAAL_SGX_INFO();
    int ret = 0;

    int index = reserve_worker();

    if (index != ZC_NO_FREE_POOL)
    {

        ret = zc_fseeko(file, offset, whence, index);
    }
    else
    {
        ocall_fseeko(&ret, file, offset, whence);
    }
    return ret;
}

off_t ftello(SGX_FILE file)
{
    GRAAL_SGX_INFO();
    off_t ret = 0;
    ocall_ftello(&ret, file);
    return ret;
}
int puts(const char *str)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    // log_ocall(FN_TOKEN_CLOSE);
    // if (should_be_switchless(FN_TOKEN_CLOSE))
    //    ret = puts_switchless(str);
    // else
    //     ocall_puts(&ret, str);
    ocall_puts(&ret, str);
    return ret;
}
int fscanf(SGX_FILE stream, const char *fmt, ...)
{ // undefined behaviour at runtime
    GRAAL_SGX_INFO();
    int ret = 0;
    // obtain additional arguments
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_fscanf(&ret, stream, buf);
    return ret;
}
int fprintf(SGX_FILE stream, const char *fmt, ...)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    // obtain additional arguments
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    // int len = (int)strnlen(buf, BUFSIZ - 1) + 1;
    ocall_fprintf(&ret, stream, buf);
    return ret;
}
char *fgets(char *str, int n, SGX_FILE stream)
{
    GRAAL_SGX_INFO();
    // printf("Fget str: %s\n", str);
    ocall_fgets(str, n, stream);
    return str;
}

ssize_t read(int fd, void *buf, size_t count)
{
    GRAAL_SGX_INFO();
    ssize_t ret = 0;

    int index = reserve_worker();

    if (index != ZC_NO_FREE_POOL)
    {

        ret = zc_read(fd, buf, count, index);
    }
    else
    {
        ocall_read(&ret, fd, buf, count);
    }
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    GRAAL_SGX_INFO();
    ssize_t ret = 0;

    int index = reserve_worker();

    if (index != ZC_NO_FREE_POOL)
    {

        ret = zc_write(fd, buf, count, index);
    }
    else
    {
        ocall_write(&ret, fd, buf, count);
    }
    return ret;
}
int sprintf(char *str, const char *fmt, ...)
{
    // GRAAL_SGX_INFO();
    // this should work but may need revision
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    int size = (int)strnlen(buf, BUFSIZ - 1) + 1 + BUFSIZ;
    return snprintf(str, size_t(size), fmt);
}
int vfprintf(SGX_FILE *stream, const char *format, va_list ap)
{
    GRAAL_SGX_INFO();
    // TODO
    return 0;
}

char *strcpy(char *dest, const char *src)
{
    GRAAL_SGX_INFO();
    return strncpy(dest, src, strnlen(src, BUFSIZ - 1) + 1);
}

char *strcat(char *dest, const char *src)
{
    GRAAL_SGX_INFO();
    return strncat(dest, src, strnlen(src, BUFSIZ - 1) + 1);
}

void *opendir(const char *name)
{
    printf("Opendir name: %s\n", name);
    GRAAL_SGX_INFO();
    void *ret;
    ocall_opendir(&ret, name);
    return ret;
}

// void *fdopendir(int fd);
int closedir(void *dirp)
{
    GRAAL_SGX_INFO();
    int ret;
    ocall_closedir(&ret, dirp);
    return ret;
}
// struct dirent *readdir(void *dirp);
int readdir64_r(void *dirp, struct dirent *entry, struct dirent **result)
{
    GRAAL_SGX_INFO();
    int ret;
    ocall_readdir64_r(&ret, dirp, entry, result);
    return ret;
}
// int remove(const char *pathname);
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
    GRAAL_SGX_INFO();
    ssize_t ret;
    ocall_readlink(&ret, pathname, buf, bufsiz);
    return ret;
}
long pathconf(const char *path, int name)
{
    GRAAL_SGX_INFO();
    long ret;
    ocall_pathconf(&ret, path, name);
    return ret;
}
int __xstat(int ver, const char *path, struct stat *stat_buf)
{
    GRAAL_SGX_INFO();
    int ret;
    ocall_xstat(&ret, ver, path, stat_buf);
    return ret;
}
int __lxstat(int ver, const char *path, struct stat *stat_buf)
{
    GRAAL_SGX_INFO();
    int ret;
    ocall_lxstat(&ret, ver, path, stat_buf);
    return ret;
}
int __fxstat(int ver, int fd, struct stat *stat_buf)
{
    GRAAL_SGX_INFO();
    int ret;
    ocall_fxstat(&ret, ver, fd, stat_buf);
    return ret;
}

int fstat64(int fd, struct stat *buf)
{
    GRAAL_SGX_INFO();
    int fstat_ret;
    void *ret;
    ocall_fstat64(&ret, fd, &fstat_ret);
    struct stat *ret_buf = (struct stat *)ret;
    copy_stats(buf, ret_buf);
    return fstat_ret;
}
int __fxstat64(int ver, int fd, struct stat *stat_buf)
{
    GRAAL_SGX_INFO();
    int ret;
    ocall_fxstat64(&ret, ver, fd, stat_buf);
    return ret;
}

int stat(const char *path, struct stat *buf)
{
    GRAAL_SGX_INFO();
    void *ret;
    int stat_ret;
    ocall_stat(&ret, path, &stat_ret);
    struct stat *ret_buf = (struct stat *)ret;
    copy_stats(buf, ret_buf);
    return stat_ret;
}
int fstat(int fd, struct stat *buf)
{
    GRAAL_SGX_INFO();
    int fstat_ret;
    void *ret;
    ocall_fstat(&ret, fd, &fstat_ret);
    struct stat *ret_buf = (struct stat *)ret;
    copy_stats(buf, ret_buf);
    return fstat_ret;
}
int lstat(const char *path, struct stat *buf)
{
    GRAAL_SGX_INFO();
    void *ret;
    int lstat_ret;
    ocall_lstat(&ret, path, &lstat_ret);
    struct stat *ret_buf = (struct stat *)ret;
    copy_stats(buf, ret_buf);
    return lstat_ret;
}

char *getenv(const char *name)
{
    char *retval;
    sgx_status_t status = ocall_getenv(&retval, name);
    // CHECK_STATUS(status);
    return retval;
}

ulong crc32(ulong crc, const Byte *buf, uint len)
{
    GRAAL_SGX_INFO();
    // TODO
}

int mkdir(const char *pathname, mode_t mode)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_mkdir(&ret, pathname, mode);
    return ret;
}
int truncate(const char *path, off_t length)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_truncate(&ret, path, length);
    return ret;
}
int ftruncate64(int fd, off_t length)
{
    GRAAL_SGX_INFO();
    int ret = 0;

    int index = reserve_worker();

    if (index != ZC_NO_FREE_POOL)
    {

        ret = zc_ftruncate64(fd, length, index);
    }
    else
    {
        ocall_ftruncate64(&ret, fd, length);
    }
    return ret;
}

int ftruncate(int fd, off_t length)
{
    GRAAL_SGX_INFO();
    // TODO: is calling ftruncate64 correct ?
    return ftruncate64(fd, length);
}
void *mmap64(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
    /**
     * mmap64 is mostly used to map [large]files in the application VAS.
     * To our knowledge so far, graal uses mmap to allocate heap memory for apps; we allocate that
     * in sgx reserved memory. mmap64 does not use sgx reserve memory for now. fd != -1 here.
     */

    GRAAL_SGX_INFO();
    // printf("In mmap 64: fd = %d\n", fd);
    // return mmap(addr, len, prot, flags, fd, off);
    void *ret = nullptr;
    ocall_mmap64(&ret, addr, len, prot, flags, fd, off);
    return ret;
}
ssize_t pwrite64(int fd, const void *buf, size_t nbyte, off_t offset)
{
    GRAAL_SGX_INFO();
    ssize_t ret = 0;
    ocall_pwrite64(&ret, fd, buf, nbyte, offset);
    return ret;
}
int fdatasync(int fd)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_fdatasync(&ret, fd);
    return ret;
}
int rename(const char *oldpath, const char *newpath)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_rename(&ret, oldpath, newpath);
    return ret;
}
int unlink(const char *pathname)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    /* log_ocall(FN_TOKEN_UNLINK);
    if (should_be_switchless(FN_TOKEN_UNLINK))
        ret = unlink_switchless(pathname);
    else */

    ocall_unlink(&ret, pathname);
    return ret;
}
int rmdir(const char *pathname)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    /* log_ocall(FN_TOKEN_RMDIR);
    if (should_be_switchless(FN_TOKEN_RMDIR))
        rmdir_switchless(pathname);
    else */
    ocall_rmdir(&ret, pathname);
    return ret;
}
clock_t times(struct tms *buf)
{
    GRAAL_SGX_INFO();
    clock_t ret = 0;
    ocall_times(&ret);
    return ret;
}
int utimes(const char *filename, const struct timeval times[2])
{
    GRAAL_SGX_INFO();
    int ret = 0;
    // TODO
    return ret;
}
int chown(const char *pathname, uid_t owner, gid_t group)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_chown(&ret, pathname, owner, group);
    return ret;
}
int fchown(int fd, uid_t owner, gid_t group)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_fchown(&ret, fd, owner, group);
    return ret;
}
int lchown(const char *pathname, uid_t owner, gid_t group)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_lchown(&ret, pathname, owner, group);
    return ret;
}
int chmod(const char *pathname, mode_t mode)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_chmod(&ret, pathname, mode);
    return ret;
}
int fchmod(int fd, mode_t mode)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_fchmod(&ret, fd, mode);
    return ret;
}
int __lxstat64(int ver, const char *path, struct stat *stat_buf)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_lxstat64(&ret, ver, path, stat_buf);
    return ret;
}
int __xmknod(int vers, const char *path, mode_t mode, dev_t *dev)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_xmknod(&ret, vers, path, mode, dev);
    return ret;
}
int symlink(const char *target, const char *linkpath)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_symlink(&ret, target, linkpath);
    return ret;
}
int deflateEnd(z_streamp stream)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_deflateEnd(&ret, stream);
    return ret;
}
int deflateParams(z_streamp stream, int level, int strategy)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_deflateParams(&ret, stream, level, strategy);
    return ret;
}
int deflate(z_streamp stream, int flush)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_deflate(&ret, stream, flush);
    return ret;
}
int deflateInit2_(z_streamp stream, int level, int method, int windowBits, int memLevel, int strategy)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_deflateInit2(&ret, stream, level, method, windowBits, memLevel, strategy);
    return ret;
}
int inflateReset(z_streamp stream)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_inflateReset(&ret, stream);
    return ret;
}
ssize_t sendfile64(int out_fd, int in_fd, off_t *offset, size_t count)
{
    GRAAL_SGX_INFO();
    ssize_t ret = 0;
    ocall_sendfile64(&ret, out_fd, in_fd, offset, count);
    return ret;
}
ulong adler32(ulong adler, const Bytef *buf, size_t len)
{
    GRAAL_SGX_INFO();
    ulong ret = 0;
    ocall_adler32(&ret, adler, buf, len);
    return ret;
}
// correct: extern **char environ
int environ(void)
{
    GRAAL_SGX_INFO();
    return 0;
}

// Added for graal 21.0
int __libc_current_sigrtmax(void)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    // TODO
    return ret;
}
off_t lseek(int fd, off_t offset, int whence)
{
    GRAAL_SGX_INFO();
    off_t ret = 0;
    ocall_lseek(&ret, fd, offset, whence);
    return ret;
}
struct dirent *readdir(DIR *dirp)
{
    GRAAL_SGX_INFO();
    // TODO
    return nullptr;
}
struct dirent *readdir64(DIR *dirp)
{
    GRAAL_SGX_INFO();

    // TODO
    return nullptr;
}
int ioctl(int fd, unsigned long request, ...)
{
    GRAAL_SGX_INFO();
    va_list ap;
    va_start(ap, request);
    int arg = va_arg(ap, int);
    va_end(ap);

    int ret;
    int sgx_ret = ocall_ioctl(&ret, fd, request, arg);

    if (sgx_ret != SGX_SUCCESS)
    {
        printf("Error in fcntl OCALL\n");
        sgx_exit();
    }

    return ret;
}
off64_t lseek64(int fd, off64_t offset, int whence)
{
    GRAAL_SGX_INFO();
    off64_t ret = 0;
    /*  log_ocall(FN_TOKEN_LSEEK64);
    if (should_be_switchless(FN_TOKEN_LSEEK64))
        ret = lseek64_switchless(fd, offset, whence);
    else */
    ocall_lseek64(&ret, fd, offset, whence);
    return ret;
}
int fflush(SGX_FILE *stream)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_fflush(&ret, stream);
    return ret;
}

const char *gai_strerror(int ecode)
{
    GRAAL_SGX_INFO();
    const char *ret = "gai_strerror";
    // TODO
    return ret;
}
ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    GRAAL_SGX_INFO();
    ssize_t ret = 0;
    ocall_pread(&ret, fd, buf, count, offset);
    return ret;
}
ssize_t pread64(int fd, void *buf, size_t count, off64_t offset)
{
    GRAAL_SGX_INFO();
    ssize_t ret = 0;
    ocall_pread64(&ret, fd, buf, count, offset);
    return 0;
}
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    GRAAL_SGX_INFO();
    ssize_t ret = 0;
    ocall_pwrite(&ret, fd, buf, count, offset);
    return 0;
}

/**
 * Definition of fcntl: copyright Panoply
 */
int fcntl(int fd, int cmd, ... /* arg */)
{
    GRAAL_SGX_INFO();
    /* va_list ap;
    va_start(ap, cmd);
    int arg = va_arg(ap, int);
    va_end(ap);

    int ret;
    int sgx_ret = ocall_fcntl(&ret, fd, cmd, arg);

    if (sgx_ret != SGX_SUCCESS)
    {
        printf("Error in fcntl OCALL\n");
        sgx_exit();
    }
    return ret; */

    sgx_status_t status;
    va_list ap;
    int retval;
    va_start(ap, cmd);
    long larg = -1;
    struct flock *flarg = NULL;
    // Fix me: Should refer to the linux kernel in order to do it in the right way
    switch (cmd)
    {
    case F_GETFD:
    case F_GETFL:
    case F_GETOWN:
        va_end(ap);
        status = ocall_fcntl1(&retval, fd, cmd);
        CHECK_STATUS(status);
        return retval;
    case F_DUPFD:
    case F_DUPFD_CLOEXEC:
    case F_SETFD:
    case F_SETFL:
    case F_SETOWN:
        larg = va_arg(ap, long);
        // fprintf(stderr, "fcntl setfd or setfl with flag: %d \n", larg);
        status = ocall_fcntl2(&retval, fd, cmd, larg);
        CHECK_STATUS(status);
        return retval;
    case F_SETLK:
    case F_GETLK:
    case F_SETLKW:
        flarg = va_arg(ap, struct flock *);

        status = ocall_fcntl3(&retval, fd, cmd, flarg, sizeof(struct flock));
        CHECK_STATUS(status);
        return retval;
    default:
        va_end(ap);
        return -1;
    };

    return -1;
}

int fstatvfs64(int fd, struct statvfs *buf)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    // TODO
    return ret;
}

int __xstat64(int ver, const char *path, struct stat *stat_buf)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_xstat64(&ret, ver, path, stat_buf);
    return ret;
}

// int pthread_kill(pthread_t thread, int sig)
// {
//     GRAAL_SGX_INFO();
//     int ret = 0;
//     // TODO
//     return ret;
// }
int inflateInit2_(z_streamp strm, int windowBits, char *version, int stream_size)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    // TODO
    return ret;
}
int inflate(z_streamp stream, int flush)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    // TODO
    return ret;
}
int inflateEnd(z_streamp stream)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    // TODO
    return ret;
}

int dup(int oldfd)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    // TODO
    return ret;
}

int access(const char *pathname, int mode)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    // TODO
    return ret;
}
int chdir(const char *path)
{
    GRAAL_SGX_INFO();
    int ret;
    ocall_chdir(&ret, path);
    return ret;
}
int fileno(SGX_FILE *stream)
{
    GRAAL_SGX_INFO();
    if (stream == nullptr)
    {
        printf("fileno stream is null\n");
        return -1;
    }
    int ret;
    ocall_fileno(&ret, stream);
    return ret;
}
int isatty(int fd)
{
    GRAAL_SGX_INFO();
    int ret;
    ocall_isatty(&ret, fd);
    return ret;
}
mode_t umask(mode_t mask)
{
    GRAAL_SGX_INFO();
    mode_t ret;
    ocall_umask(&ret, mask);
    return ret;
}
int getchar()
{
    GRAAL_SGX_INFO();
    int ret;
    ocall_getchar(&ret);
    return ret;
}

int sscanf(const char *str, const char *format, ...)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    // TODO
    return ret;
}

int fputc(int c, SGX_FILE stream)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_fputc(&ret, c, stream);
    return ret;
}
int putc(int c, SGX_FILE stream)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_putc(&ret, c, stream);
    return ret;
}
void perror(const char *m)
{
    PERROR("ERROR");
}

int test_multi(int a, int b)
{
    int soln = a * b;
    int ret = 0;

    int index = reserve_worker();

    if (index != ZC_NO_FREE_POOL)
    {

        ret = zc_test(a, b, index);
        ZC_ASSERT(ret == soln);
    }
    else
    {
        ocall_test(&ret, a, b);
        ZC_ASSERT(ret == soln);
    }
    return ret;
}

void *untrusted_malloc(ssize_t siz)
{

    void *ret;
    ocall_malloc(&ret, siz);
    return ret;
}

ssize_t getline(char **lineptr, size_t *n,
                SGX_FILE *stream)
{
    ssize_t ret = 0;
    // ocall_getline(&ret, lineptr, n, stream);
    return ret;
}

void micro_f()
{
    int index = reserve_worker();

    if (index != ZC_NO_FREE_POOL)
    {

        zc_micro_f(index);
    }
    else
    {
        ocall_f();
    }
}
void micro_g()
{
    int index = reserve_worker();

    if (index != ZC_NO_FREE_POOL)
    {

        zc_micro_g(index);
    }
    else
    {
        ocall_g();
    }
}