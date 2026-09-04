#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/elf.h>

#ifndef NT_FPREGSET
#define NT_FPREGSET 2
#endif
#ifndef NT_X86_XSTATE
#define NT_X86_XSTATE 0x202
#endif

static pid_t last_event_child;
static int child_detached_with_kill;
static int saw_interrupt;
static DIR *injected_task_dir;
static int injected_task_seen;

time_t time(time_t *result)
{
    static time_t (*real_time)(time_t *);
    if (!real_time) {
        real_time = (time_t (*)(time_t *))dlsym(RTLD_NEXT, "time");
    }
    const char *fake = getenv("ARTHUR_FAKE_TIME");
    time_t value = fake ? (time_t)strtoll(fake, NULL, 10) : real_time(NULL);
    if (result) {
        *result = value;
    }
    return value;
}

int lstat(const char *pathname, struct stat *statbuf)
{
    static int (*real_lstat)(const char *, struct stat *);
    static unsigned matching_calls;
    static int swapped;
    if (!real_lstat) {
        real_lstat = (int (*)(const char *, struct stat *))dlsym(RTLD_NEXT, "lstat");
    }
    int rc = real_lstat(pathname, statbuf);
    const char *target = getenv("ARTHUR_SWAP_OUTPUT_AFTER_LSTAT");
    if (rc == 0 && target && strcmp(pathname, target) == 0) {
        matching_calls++;
        if (!swapped && matching_calls == 2) {
            char replacement[4096];
            int n = snprintf(replacement, sizeof(replacement), "%s.competitor", target);
            if (n > 0 && (size_t)n < sizeof(replacement)) {
                int fd = open(replacement, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                static const char content[] = "last-window-writer-output\n";
                if (fd >= 0 && write(fd, content, sizeof(content) - 1) ==
                               (ssize_t)(sizeof(content) - 1) &&
                    close(fd) == 0 && rename(replacement, target) == 0) {
                    swapped = 1;
                } else if (fd >= 0) {
                    close(fd);
                }
            }
        }
    }
    return rc;
}

static pid_t fault_target_pid(void)
{
    const char *text = getenv("ARTHUR_TARGET_PID");
    return text ? (pid_t)strtol(text, NULL, 10) : 0;
}

long ptrace(enum __ptrace_request request, ...)
{
    static long (*real_ptrace)(enum __ptrace_request, ...);
    static int failed_getregs;
    static int failed_fpregs;
    static int failed_siginfo;
    static int failed_detach;
    static int injected_attach_delivery;
    static unsigned setregs_calls;
    static int failed_setoptions;
    static int failed_cont;
    static int failed_geteventmsg;
    static int failed_listen;
    static int failed_child_poke;
    static int failed_setxstate;
    static unsigned cont_calls;
    static int cleared_tracefork;
    if (!real_ptrace) {
        real_ptrace = (long (*)(enum __ptrace_request, ...))
            dlsym(RTLD_NEXT, "ptrace");
    }

    va_list ap;
    va_start(ap, request);
    pid_t pid = va_arg(ap, pid_t);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);

    int getregs = request == PTRACE_GETREGS ||
        (request == PTRACE_GETREGSET && (uintptr_t)addr == NT_PRSTATUS);
    int setregs = request == PTRACE_SETREGS ||
        (request == PTRACE_SETREGSET && (uintptr_t)addr == NT_PRSTATUS);
    int getfpregs = request == PTRACE_GETFPREGS ||
        (request == PTRACE_GETREGSET && (uintptr_t)addr == NT_FPREGSET);
    const char *detach_failure = getenv("ARTHUR_FAIL_DETACH");
    if (request == PTRACE_DETACH && pid == last_event_child &&
        getenv("ARTHUR_FAIL_CHILD_DETACH_ESRCH")) {
        errno = ESRCH;
        return -1;
    }
    if (request == PTRACE_DETACH && detach_failure &&
        (!failed_detach || strstr(detach_failure, "always") != NULL)) {
        failed_detach = 1;
        errno = strstr(detach_failure, "esrch") != NULL ? ESRCH : EIO;
        return -1;
    }
    if (!failed_getregs && getregs && getenv("ARTHUR_FAIL_GETREGS")) {
        failed_getregs = 1;
        errno = EIO;
        return -1;
    }
    if (!failed_getregs && getregs && child_detached_with_kill &&
        getenv("ARTHUR_FAIL_GETREGS_AFTER_CHILD_KILL")) {
        failed_getregs = 1;
        errno = EIO;
        return -1;
    }
    if (setregs) {
#if defined(__x86_64__)
        if (getenv("ARTHUR_REQUIRE_CALL_STACK_ALIGNMENT")) {
            const struct user_regs_struct *regs =
                (const struct user_regs_struct *)data;
            if ((regs->rsp & 0xf) != 8) {
                fprintf(stderr, "injected call stack is misaligned: rsp=%#llx\n",
                        (unsigned long long)regs->rsp);
                errno = EINVAL;
                return -1;
            }
        }
#endif
        setregs_calls++;
        const char *from_text = getenv("ARTHUR_FAIL_SETREGS_FROM");
        if (from_text && setregs_calls >= strtoul(from_text, NULL, 10)) {
            errno = EIO;
            return -1;
        }
    }
    if (!failed_cont && request == PTRACE_CONT) {
        const char *after_text = getenv("ARTHUR_FAIL_CONT_AFTER_SETREGS");
        if (after_text && setregs_calls >= strtoul(after_text, NULL, 10)) {
            failed_cont = 1;
            errno = EIO;
            return -1;
        }
        if (cleared_tracefork && getenv("ARTHUR_FAIL_CONT_AFTER_CLEAR")) {
            failed_cont = 1;
            errno = EIO;
            return -1;
        }
    }
    if (!failed_setoptions && request == PTRACE_SETOPTIONS &&
        getenv("ARTHUR_FAIL_CLEAR_TRACEFORK") &&
        (((uintptr_t)data & PTRACE_O_TRACEFORK) == 0)) {
        failed_setoptions = 1;
        errno = EIO;
        return -1;
    }
    if (request == PTRACE_SETOPTIONS &&
        (((uintptr_t)data & PTRACE_O_TRACEFORK) == 0)) {
        cleared_tracefork = 1;
    }
    if (!failed_fpregs && getfpregs && getenv("ARTHUR_FAIL_GETFPREGS")) {
        failed_fpregs = 1;
        errno = EIO;
        return -1;
    }
    if (!failed_setxstate && request == PTRACE_SETREGSET &&
        (uintptr_t)addr == NT_X86_XSTATE && getenv("ARTHUR_FAIL_SETXSTATE")) {
        failed_setxstate = 1;
        errno = EIO;
        return -1;
    }
    if (!failed_siginfo && request == PTRACE_GETSIGINFO &&
        getenv("ARTHUR_FAIL_GETSIGINFO")) {
        failed_siginfo = 1;
        errno = EIO;
        return -1;
    }
    if (!failed_geteventmsg && request == PTRACE_GETEVENTMSG &&
        child_detached_with_kill &&
        getenv("ARTHUR_FAIL_GETEVENTMSG_AFTER_CHILD_KILL")) {
        failed_geteventmsg = 1;
        errno = EIO;
        return -1;
    }
    if (!failed_geteventmsg && request == PTRACE_GETEVENTMSG && saw_interrupt &&
        getenv("ARTHUR_FAIL_GETEVENTMSG_AFTER_INTERRUPT")) {
        failed_geteventmsg = 1;
        errno = EIO;
        return -1;
    }
    if (!failed_listen && request == PTRACE_LISTEN &&
        getenv("ARTHUR_FAIL_LISTEN")) {
        failed_listen = 1;
        errno = EIO;
        return -1;
    }
    if (request == PTRACE_INTERRUPT && child_detached_with_kill &&
        getenv("ARTHUR_FAIL_INTERRUPT_AFTER_CHILD_KILL")) {
        errno = EIO;
        return -1;
    }
    if (request == PTRACE_INTERRUPT) {
        saw_interrupt = 1;
    }
    if (!failed_child_poke && request == PTRACE_POKEDATA &&
        pid == last_event_child && getenv("ARTHUR_FAIL_CHILD_POKEDATA")) {
        failed_child_poke = 1;
        errno = EIO;
        return -1;
    }
    if (request == PTRACE_DETACH && (uintptr_t)data == SIGKILL &&
        getenv("ARTHUR_FAIL_CHILD_DETACH")) {
        errno = EIO;
        return -1;
    }
    if (request == PTRACE_DETACH && pid == last_event_child &&
        getenv("ARTHUR_FAIL_CLONE_CHILD_WAIT")) {
        fprintf(stderr, "detaching tracked clone child %d\n", (int)pid);
    }
    const char *delivery_text = getenv("ARTHUR_ATTACH_DELIVERY_SIGNAL");
    if (!injected_attach_delivery && request == PTRACE_ATTACH && delivery_text) {
        char *end = NULL;
        long sig = strtol(delivery_text, &end, 10);
        if (end != delivery_text && *end == '\0' && sig > 0 && sig < NSIG) {
            // Deterministically model the race permitted by ptrace(2), where
            // an ordinary delivery-stop wins over PTRACE_ATTACH's own SIGSTOP.
            long rc = real_ptrace(PTRACE_SEIZE, pid, NULL, NULL);
            if (rc == 0) {
                injected_attach_delivery = 1;
                kill(pid, (int)sig);
            }
            return rc;
        }
    }
    if (request == PTRACE_CONT && pid == fault_target_pid()) {
        cont_calls++;
        const char *crash_at = getenv("ARTHUR_CRASH_ON_CONT");
        if (crash_at && cont_calls == strtoul(crash_at, NULL, 10)) {
            kill(pid, SIGSEGV);
        }
    }
    long rc = real_ptrace(request, pid, addr, data);
    if (rc == 0 && request == PTRACE_GETEVENTMSG && data != NULL) {
        last_event_child = (pid_t)*(unsigned long *)data;
    }
    if (rc == 0 && request == PTRACE_DETACH && (uintptr_t)data == SIGKILL) {
        child_detached_with_kill = 1;
    }
    return rc;
}

DIR *opendir(const char *name)
{
    static DIR *(*real_opendir)(const char *);
    if (!real_opendir) {
        real_opendir = (DIR *(*)(const char *))dlsym(RTLD_NEXT, "opendir");
    }
    DIR *dir = real_opendir(name);
    pid_t target = fault_target_pid();
    char expected[64];
    snprintf(expected, sizeof(expected), "/proc/%d/task/", (int)target);
    if (dir && target > 0 && getenv("ARTHUR_FAIL_TASK_READDIR") &&
        strcmp(name, expected) == 0) {
        injected_task_dir = dir;
        injected_task_seen = 0;
    }
    return dir;
}

struct dirent *readdir(DIR *dirp)
{
    static struct dirent *(*real_readdir)(DIR *);
    if (!real_readdir) {
        real_readdir = (struct dirent *(*)(DIR *))dlsym(RTLD_NEXT, "readdir");
    }
    if (dirp == injected_task_dir && injected_task_seen) {
        errno = EIO;
        return NULL;
    }
    struct dirent *entry = real_readdir(dirp);
    if (dirp == injected_task_dir && entry && entry->d_name[0] != '.') {
        injected_task_seen = 1;
    }
    return entry;
}

int access(const char *pathname, int mode)
{
    static int (*real_access)(const char *, int);
    static int injected;
    if (!real_access) {
        real_access = (int (*)(const char *, int))dlsym(RTLD_NEXT, "access");
    }
    pid_t target = fault_target_pid();
    int leader = 0;
    int tid = 0;
    char tail = '\0';
    if (!injected && target > 0 && getenv("ARTHUR_FAIL_THREAD_ACCESS") &&
        sscanf(pathname, "/proc/%d/task/%d%c", &leader, &tid, &tail) == 2 &&
        leader == target && tid != leader) {
        injected = 1;
        errno = EIO;
        return -1;
    }
    return real_access(pathname, mode);
}

ssize_t read(int fd, void *buf, size_t count)
{
    static ssize_t (*real_read)(int, void *, size_t);
    static int injected;
    if (!real_read) {
        real_read = (ssize_t (*)(int, void *, size_t))dlsym(RTLD_NEXT, "read");
    }
    if (!injected && getenv("ARTHUR_FAIL_STATUS_READ")) {
        char fd_path[64];
        char target_path[256] = {0};
        char expected[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(fd_path, target_path, sizeof(target_path) - 1);
        snprintf(expected, sizeof(expected), "/proc/%d/status",
                 (int)fault_target_pid());
        if (n > 0) {
            target_path[n] = '\0';
        }
        if (strcmp(target_path, expected) == 0) {
            injected = 1;
            errno = EIO;
            return -1;
        }
    }
    return real_read(fd, buf, count);
}

pid_t waitpid(pid_t pid, int *status, int options)
{
    static pid_t (*real_waitpid)(pid_t, int *, int);
    static int injected;
    if (!real_waitpid) {
        real_waitpid = (pid_t (*)(pid_t, int *, int))dlsym(RTLD_NEXT, "waitpid");
    }
    if (!injected && getenv("ARTHUR_FAIL_WAITPID")) {
        injected = 1;
        errno = EIO;
        return -1;
    }
    if (!injected && child_detached_with_kill &&
        getenv("ARTHUR_FAIL_WAITPID_AFTER_CHILD_KILL")) {
        injected = 1;
        errno = EIO;
        return -1;
    }
    if (last_event_child > 0 && pid == last_event_child &&
        getenv("ARTHUR_FAIL_CLONE_CHILD_WAIT")) {
        fprintf(stderr, "injected clone-child wait failure for %d\n", (int)pid);
        errno = EIO;
        return -1;
    }
    return real_waitpid(pid, status, options);
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    static ssize_t (*real_pread)(int, void *, size_t, off_t);
    static int injected;
    if (!real_pread) {
        real_pread = (ssize_t (*)(int, void *, size_t, off_t))
            dlsym(RTLD_NEXT, "pread");
    }

    if (!injected && getenv("ARTHUR_FAIL_PROC_MEM_EOF")) {
        char link_path[64];
        char target[256] = {0};
        snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(link_path, target, sizeof(target) - 1);
        if (n > 0) {
            target[n] = '\0';
            int mem_pid = 0;
            char tail = '\0';
            if (sscanf(target, "/proc/%d/mem%c", &mem_pid, &tail) == 1 &&
                mem_pid == (int)last_event_child) {
                injected = 1;
                return 0;
            }
        }
    }
    return real_pread(fd, buf, count, offset);
}

int sigwaitinfo(const sigset_t *set, siginfo_t *info)
{
    static int (*real_sigwaitinfo)(const sigset_t *, siginfo_t *);
    static int injected;
    if (!real_sigwaitinfo) {
        real_sigwaitinfo = (int (*)(const sigset_t *, siginfo_t *))
            dlsym(RTLD_NEXT, "sigwaitinfo");
    }
    if (!injected && getenv("ARTHUR_FAIL_SIGWAITINFO")) {
        injected = 1;
        errno = EIO;
        return -1;
    }
    return real_sigwaitinfo(set, info);
}

int fsync(int fd)
{
    static int (*real_fsync)(int);
    static int injected;
    if (!real_fsync) {
        real_fsync = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
    }

    struct stat st;
    const char *fail_directory = getenv("ARTHUR_FAIL_DIR_FSYNC");
    if (!injected && fail_directory && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
        injected = 1;
        errno = EIO;
        return -1;
    }
    return real_fsync(fd);
}

int fclose(FILE *stream)
{
    static int (*real_fclose)(FILE *);
    static int injected;
    if (!real_fclose) {
        real_fclose = (int (*)(FILE *))dlsym(RTLD_NEXT, "fclose");
    }

    char link_path[64];
    char target[4096] = {0};
    int fd = fileno(stream);
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link_path, target, sizeof(target) - 1);
    if (n > 0) {
        target[n] = '\0';
    }

    int rc = real_fclose(stream);
    const char *needle = getenv("ARTHUR_FAIL_FCLOSE");
    if (!injected && needle && strstr(target, needle)) {
        injected = 1;
        errno = ENOSPC;
        return EOF;
    }
    return rc;
}

int fseeko(FILE *stream, off_t offset, int whence)
{
    static int (*real_fseeko)(FILE *, off_t, int);
    static int injected;
    if (!real_fseeko) {
        real_fseeko = (int (*)(FILE *, off_t, int))dlsym(RTLD_NEXT, "fseeko");
    }

    char link_path[64];
    char target[4096] = {0};
    int fd = fileno(stream);
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link_path, target, sizeof(target) - 1);
    if (n > 0) {
        target[n] = '\0';
    }

    const char *needle = getenv("ARTHUR_FAIL_FSEEKO");
    if (!injected && needle && strstr(target, needle)) {
        injected = 1;
        errno = EIO;
        return -1;
    }
    return real_fseeko(stream, offset, whence);
}
