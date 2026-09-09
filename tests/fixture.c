#define _GNU_SOURCE

#include <pthread.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t trigger;
static volatile sig_atomic_t exec_after_exit;
static volatile pid_t first_decoy_tid;
static volatile pid_t late_tid;
static volatile pid_t spawned_tid;
static volatile sig_atomic_t child_notice;

static void on_child_exit(int sig, siginfo_t *info, void *context)
{
    (void)sig;
    (void)context;
    int saved_errno = errno;
    child_notice = info->si_pid;
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
    errno = saved_errno;
}

#if defined(__x86_64__)
__attribute__((naked, noinline, noreturn)) static void leaf_stack_spin(void)
{
    __asm__ __volatile__(
        "1:\n"
        "pause\n"
        "jmp 1b\n");
}
#endif

static void on_signal(int sig)
{
    (void)sig;
    trigger = 1;
}

static void on_exec_after_exit(int sig)
{
    (void)sig;
    exec_after_exit = 1;
}

static void *crash_worker(void *unused)
{
    (void)unused;
    printf("worker-tid=%ld\n", syscall(SYS_gettid));
    fflush(stdout);
    *(volatile int *)0 = 1;
    return NULL;
}

static void *exec_worker(void *unused)
{
    (void)unused;
    printf("exec-worker-tid=%ld\n", syscall(SYS_gettid));
    fflush(stdout);
    execl("/bin/sleep", "sleep", "30", (char *)NULL);
    _exit(5);
}

static void *spin_worker(void *unused)
{
    volatile pid_t *published_tid = (volatile pid_t *)unused;
    if (published_tid != NULL) {
        *published_tid = (pid_t)syscall(SYS_gettid);
        if (published_tid == &late_tid) {
            printf("late-tid=%d\n", (int)*published_tid);
            fflush(stdout);
        }
    }
    for (;;) {
        __asm__ __volatile__("" ::: "memory");
    }
    return NULL;
}

static void *leader_exit_worker(void *unused)
{
    int allow_exec = unused != NULL;
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &blocked, NULL);
    if (allow_exec) {
        signal(SIGUSR1, on_exec_after_exit);
    }
    printf("leader-worker-tid=%ld\n", syscall(SYS_gettid));
    fflush(stdout);
    for (;;) {
        if (allow_exec) {
            if (exec_after_exit) {
                execl("/bin/sleep", "sleep", "30", (char *)NULL);
                _exit(5);
            }
            usleep(1000);
        } else {
            pause();
        }
    }
    return NULL;
}

static char task_state(pid_t tid)
{
    char path[128];
    char line[1024];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/stat", getpid(), tid);
    FILE *file = fopen(path, "r");
    if (file == NULL || fgets(line, sizeof(line), file) == NULL) {
        if (file != NULL) {
            fclose(file);
        }
        return 0;
    }
    fclose(file);
    char *close = strrchr(line, ')');
    return close != NULL && close[1] == ' ' ? close[2] : 0;
}

static void *late_spawner(void *unused)
{
    (void)unused;
    while (first_decoy_tid == 0 || task_state(first_decoy_tid) != 't') {
        sched_yield();
    }
    pthread_attr_t attr;
    pthread_t worker;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 64 * 1024);
    if (pthread_create(&worker, &attr, spin_worker, (void *)&late_tid) != 0) {
        _exit(6);
    }
    pthread_attr_destroy(&attr);
    for (;;) {
        __asm__ __volatile__("" ::: "memory");
    }
    return NULL;
}

static int clone_process_crash(void *unused)
{
    (void)unused;
    *(volatile int *)0 = 1;
    return 0;
}

static void ready(void)
{
    puts("ready");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    struct rlimit no_core = {0, 0};
    setrlimit(RLIMIT_CORE, &no_core);
    if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) != 0 || argc < 2) {
        return 2;
    }

    if (strcmp(argv[1], "metadata") == 0) {
        if (argc != 6 || prctl(PR_SET_NAME, argv[2], 0, 0, 0) != 0) {
            return 2;
        }
        ready();
        for (;;) {
            __asm__ __volatile__("" ::: "memory");
        }
    }

    if (strcmp(argv[1], "reap-spin") == 0) {
        if (argc != 3) {
            return 2;
        }
        if (strcmp(argv[2], "blocked") == 0) {
            sigset_t mask;
            sigemptyset(&mask);
            sigaddset(&mask, SIGCHLD);
            if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0) {
                return 2;
            }
        } else if (strcmp(argv[2], "handler") == 0) {
            struct sigaction action = {0};
            action.sa_sigaction = on_child_exit;
            action.sa_flags = SA_SIGINFO;
            sigemptyset(&action.sa_mask);
            if (sigaction(SIGCHLD, &action, NULL) != 0) {
                return 2;
            }
        } else if (strcmp(argv[2], "default") != 0) {
            return 2;
        }
        ready();
        sig_atomic_t reported = 0;
        for (;;) {
            if (reported != child_notice) {
                reported = child_notice;
                printf("child-notice=%d\n", (int)reported);
                fflush(stdout);
            }
        }
    }

    if (strcmp(argv[1], "worker-crash") == 0) {
        signal(SIGUSR2, on_signal);
        ready();
        while (!trigger) {
            pause();
        }
        pthread_t worker;
        if (pthread_create(&worker, NULL, crash_worker, NULL) != 0) {
            return 3;
        }
        for (;;) {
            pause();
        }
    }

    if (strcmp(argv[1], "leader-exit") == 0 || strcmp(argv[1], "leader-exit-exec") == 0 ||
        strcmp(argv[1], "leader-exit-multi") == 0) {
        signal(SIGUSR2, on_signal);
        pthread_t worker;
        void *allow_exec = strcmp(argv[1], "leader-exit-exec") == 0 ? argv[1] : NULL;
        int count = strcmp(argv[1], "leader-exit-multi") == 0 ? 3 : 1;
        for (int i = 0; i < count; i++) {
            if (pthread_create(&worker, NULL, leader_exit_worker, allow_exec) != 0) {
                return 3;
            }
        }
        ready();
        while (!trigger) {
            pause();
        }
        pthread_exit(NULL);
    }

    if (strcmp(argv[1], "relay-term") == 0 || strcmp(argv[1], "relay-term-spin") == 0 ||
        strcmp(argv[1], "relay-quit-spin") == 0) {
        signal(strcmp(argv[1], "relay-quit-spin") == 0 ? SIGQUIT : SIGTERM, on_signal);
        ready();
        while (!trigger) {
            if (strcmp(argv[1], "relay-term") != 0) {
                __asm__ __volatile__("" ::: "memory");
            } else {
                pause();
            }
        }
        return 42;
    }

    if (strcmp(argv[1], "syscall-read") == 0) {
        int pipe_fds[2];
        char byte;
        if (pipe(pipe_fds) != 0) {
            return 4;
        }
        ready();
        for (;;) {
            (void)read(pipe_fds[0], &byte, 1);
        }
    }
    if (strcmp(argv[1], "syscall-sleep") == 0) {
        ready();
        for (;;) {
            struct timespec duration = {60, 0};
            nanosleep(&duration, NULL);
        }
    }

    if (strcmp(argv[1], "relay-cont") == 0) {
        signal(SIGCONT, on_signal);
        ready();
        while (!trigger) {
            pause();
        }
        return 42;
    }

    if (strcmp(argv[1], "blocked-cont") == 0 ||
        strcmp(argv[1], "ignored-cont") == 0) {
        if (strcmp(argv[1], "blocked-cont") == 0) {
            sigset_t mask;
            sigemptyset(&mask);
            sigaddset(&mask, SIGCONT);
            if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0) {
                return 3;
            }
        } else {
            signal(SIGCONT, SIG_IGN);
        }
        ready();
        for (;;) {
            pause();
        }
    }

    if (strcmp(argv[1], "exec") == 0) {
        signal(SIGUSR2, on_signal);
        ready();
        while (!trigger) {
            pause();
        }
        pthread_t worker;
        if (pthread_create(&worker, NULL, exec_worker, NULL) != 0) {
            return 3;
        }
        for (;;) {
            pause();
        }
    }

    if (strcmp(argv[1], "spawn-worker") == 0) {
        signal(SIGUSR2, on_signal);
        ready();
        while (!trigger) {
            pause();
        }
        pthread_t worker;
        if (pthread_create(&worker, NULL, spin_worker, (void *)&spawned_tid) != 0) {
            return 3;
        }
        while (spawned_tid == 0) {
            sched_yield();
        }
        printf("spawn-worker-tid=%d\n", (int)spawned_tid);
        fflush(stdout);
        for (;;) {
            pause();
        }
    }

    if (strcmp(argv[1], "ignore-quit") == 0) {
        signal(SIGQUIT, SIG_IGN);
        ready();
        for (;;) {
            pause();
        }
    }

    if (strcmp(argv[1], "ignore-segv-sync") == 0) {
        signal(SIGUSR2, on_signal);
        signal(SIGSEGV, SIG_IGN);
        ready();
        while (!trigger) {
            pause();
        }
        *(volatile int *)0 = 1;
        return 0;
    }

    if (strcmp(argv[1], "memory") == 0 || strcmp(argv[1], "memory-spin") == 0) {
        int spin = strcmp(argv[1], "memory-spin") == 0;
        size_t mib = argc > 2 ? strtoul(argv[2], NULL, 10) : 8;
        size_t size = mib * 1024 * 1024;
        unsigned char *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            return 4;
        }
        for (size_t off = 0; off < size; off += 4096) {
            p[off] = (unsigned char)(off / 4096);
        }
        ready();
        if (spin) {
            for (;;) {
                __asm__ __volatile__("" ::: "memory");
            }
        }
        for (;;) {
            pause();
        }
    }

#if defined(__x86_64__)
    if (strcmp(argv[1], "leaf-stack-spin") == 0) {
        ready();
        leaf_stack_spin();
    }
#endif

    if (strcmp(argv[1], "fork-cont") == 0) {
        signal(SIGCONT, on_signal);
        signal(SIGCHLD, SIG_IGN);
        size_t size = 64 * 1024 * 1024;
        unsigned char *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            return 4;
        }
        for (size_t off = 0; off < size; off += 4096) {
            p[off] = (unsigned char)(off / 4096);
        }
        ready();
        for (;;) {
            trigger = 0;
            for (volatile unsigned spin = 0; spin < 5000000; spin++) {
                __asm__ __volatile__("" ::: "memory");
            }
            pid_t child = fork();
            if (child < 0) {
                continue;
            }
            if (child == 0) {
                usleep(10000);
                if (trigger) {
                    puts("child-sigcont");
                    fflush(stdout);
                }
                _exit(trigger ? 42 : 0);
            }
        }
    }

    if (strcmp(argv[1], "dontfork-spin") == 0) {
        uint64_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED || madvise(p, 4096, MADV_DONTFORK) != 0) {
            return 4;
        }
        *p = UINT64_C(0x1122334455667788);
        printf("dontfork-address=%p\n", (void *)p);
        ready();
        for (;;) {
            __asm__ __volatile__("" ::: "memory");
        }
    }

    if (strcmp(argv[1], "shared-spin") == 0) {
        volatile uint64_t *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        volatile uint64_t *local = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (shared == MAP_FAILED || local == MAP_FAILED) {
            return 4;
        }
        printf("shared-address=%p\n", (const void *)shared);
        printf("local-address=%p\n", (const void *)local);
        ready();
        uint64_t value = 0;
        for (;;) {
            local[0] = value * 2 + 1;
            shared[0] = ++value;
            local[1] = value;
            local[0] = value * 2;
            for (volatile int i = 0; i < 10000; i++) {
            }
        }
    }

    if (strcmp(argv[1], "late-thread") == 0) {
        pthread_attr_t attr;
        pthread_t decoys[16];
        pthread_t spawner;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, 64 * 1024);
        if (pthread_create(&decoys[0], &attr, spin_worker,
                           (void *)&first_decoy_tid) != 0) {
            return 3;
        }
        while (first_decoy_tid == 0) {
            sched_yield();
        }
        for (size_t i = 1; i < sizeof(decoys) / sizeof(decoys[0]); i++) {
            if (pthread_create(&decoys[i], &attr, spin_worker, NULL) != 0) {
                return 3;
            }
        }
        if (pthread_create(&spawner, &attr, late_spawner, NULL) != 0) {
            return 3;
        }
        pthread_attr_destroy(&attr);
        ready();
        for (;;) {
            pause();
        }
    }

    if (strcmp(argv[1], "prot-none") == 0) {
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED || mprotect(p, 4096, PROT_NONE) != 0) {
            return 4;
        }
        printf("prot-none-address=%p\n", p);
        ready();
        for (;;) {
            pause();
        }
    }

    if (strcmp(argv[1], "write-only") == 0) {
        uint64_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            return 4;
        }
        *p = UINT64_C(0x8877665544332211);
        if (mprotect(p, 4096, PROT_WRITE) != 0) {
            return 4;
        }
        printf("write-only-address=%p\n", (void *)p);
        ready();
        for (;;) {
            pause();
        }
    }

    if (strcmp(argv[1], "write-only-dontfork-spin") == 0) {
        uint64_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            return 4;
        }
        *p = UINT64_C(0x1029384756abcdef);
        if (madvise(p, 4096, MADV_DONTFORK) != 0 ||
            mprotect(p, 4096, PROT_WRITE) != 0) {
            return 4;
        }
        printf("write-only-dontfork-address=%p\n", (void *)p);
        ready();
        for (;;) {
            __asm__ __volatile__("" ::: "memory");
        }
    }

    if (strcmp(argv[1], "rwx-file") == 0) {
        if (argc < 3) {
            return 2;
        }
        long page_size = sysconf(_SC_PAGESIZE);
        int fd = open(argv[2], O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (page_size <= 0 || fd < 0 || ftruncate(fd, page_size * 2) != 0) {
            return 4;
        }
        unsigned char *p = mmap(NULL, page_size * 2,
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE, fd, 0);
        if (p == MAP_FAILED) {
            return 4;
        }
        uint64_t *marker = (uint64_t *)(p + page_size);
        *marker = UINT64_C(0xa1b2c3d4e5f60718);
        printf("rwx-file-address=%p\n", (void *)marker);
        ready();
        for (;;) {
            pause();
        }
    }

    if (strcmp(argv[1], "clone-process-crash") == 0) {
        signal(SIGUSR1, SIG_IGN);
        signal(SIGUSR2, on_signal);
        ready();
        while (!trigger) {
            pause();
        }
        char *stack = malloc(64 * 1024);
        if (stack == NULL) {
            return 4;
        }
        pid_t child = clone(clone_process_crash, stack + 64 * 1024,
                            SIGUSR1, NULL);
        if (child < 0) {
            return 5;
        }
        printf("clone-process-pid=%d\n", child);
        fflush(stdout);
        for (;;) {
            pause();
        }
    }

    return 2;
}
