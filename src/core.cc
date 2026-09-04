/* Arthur coredump implementation.
 */

#include <sys/ptrace.h> // PTRACE_XXX
#include <sys/signal.h> // siginfo_t
#include <sys/types.h>  // size_t, second_t ...
#include <sys/wait.h>   // waitpid
#include <sys/mman.h>   // mmap
#include <sys/stat.h>   // fstat
#include <sys/utsname.h>// uname
#include <sys/uio.h>    // pread/pwrite
#include <sys/syscall.h>// renameat2
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <assert.h>
#include <fcntl.h>      // open
#include <errno.h>      // errno (PEEKDATA 判读)
#include <climits>      // INT_MAX (b141: strtol pid_t 上界)
#include <dlfcn.h>      // dlsym
#include <dirent.h>     // readdir

#include <algorithm>
#include <sstream>
#include <iterator>
#include <limits>

#include "core.h"
#include "proc.h"

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

// General-purpose capture buffer size. Large instances use heap storage.
#define BUFFER_SIZE 1L*1024*1024         // general buffer size to store data
static_assert(BUFFER_SIZE >= 1*1024*1024, "buffer size should more than 1MB.");

#define roundup(x,n) (((x)+((n)-1))&(~((n)-1)))

// R50-40: mmap 注入结果的用户态地址上限。B16 缓释只拒"明显垃圾"（0/未对齐/过低），
// 上限按用户空间 TASK_SIZE 取。原编译架构常量在 aarch64（48 位 VA，top-down mmap
// 返回 ~0x0000FFFF_xxxx_xxxx > 2^47）误拒所有合法结果。
// R50-50: 固定常量仍不够——x86-64 LA57（5 级页表）用户空间 56 位，合法 mmap 结果
// 高于 2^47，47 位常量全误拒、forkcore/forkcore_m 在 LA57 内核上不可用；aarch64
// LVA（52 位 VA）同理。top-down mmap 返回地址必低于进程现有最高映射（栈顶/
// mmap_base），故以 /proc/self/maps 的最高 end 为合法结果上界（采集侧与目标同内核
// 同架构，即目标 TASK_SIZE），编译架构常量兜底解析失败/低 VA 配置。
static uint64_t arthur_max_user_va()
{
    static uint64_t bound = 0;
    if (bound != 0) {
        return bound;
    }
    uint64_t hi = 0;
    FILE *f = fopen("/proc/self/maps", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            uint64_t a = 0, b = 0;
            if (sscanf(line, "%lx-%lx", &a, &b) == 2 && b > hi) {
                hi = b;
            }
        }
        fclose(f);
    }
    // 编译架构常量兜底（47 位 x86-64 / 48 位 aarch64）
    uint64_t arch_lo = 0x00007FFFFFFFFFFFUL;
#ifdef __aarch64__
    arch_lo = 0x0000FFFFFFFFFFFFUL;
#endif
    bound = (hi > arch_lo) ? hi : arch_lo;
    return bound;
}

// R50-20 (#2): 输入输出同路径时 fopen("wb") 先截断输入 → 静默数据丢失。
// strcmp 覆盖同字符串；stat 比较覆盖 "./x" vs "x"、符号链接等殊途同归。
static bool same_file(const char* a, const char* b)
{
    if (!a || !b) {
        return false;
    }
    if (strcmp(a, b) == 0) {
        return true;
    }
    struct stat sa, sb;
    if (stat(a, &sa) == 0 && stat(b, &sb) == 0) {
        return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
    }
    return false;
}

// R50-21: 单调钟毫秒——超时截止必须用 CLOCK_MONOTONIC。原 gettimeofday 是墙钟：
// NTP 回拨时 tv_sec 差值变负 → 截止永不触发（R50-1 的 hang 收敛失效、无限挂起）；
// 前跳则误超时。
static long long monotonic_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Linux default actions that produce a core image (signal(7)). Keep monitor,
// injection recovery and exit-state classification on one shared definition.
static bool is_core_dump_signal(int sig)
{
    switch (sig) {
        case SIGABRT:
        case SIGBUS:
        case SIGFPE:
        case SIGILL:
        case SIGQUIT:
        case SIGSEGV:
        case SIGSYS:
        case SIGTRAP:
        case SIGXCPU:
        case SIGXFSZ:
            return true;
        default:
            return false;
    }
}

extern "C" {

// the function is only for compile asm code.
#define __used__ __attribute__((used))

#ifdef __aarch64__
static __used__ void inject_fork(void)
{
    // aarch64 没有 SYS_fork，用 SYS_clone 等价 fork。
    // x0 = flags = SIGCHLD(17)：与 x86 SYS_fork 语义一致（纯 fork）。
    // 原实现 `movk x0, #120, lsl #16` 把 bits 19-22（CLONE_SETTLS/PARENT_SETTID/
    // CLEARTID/DETACHED）置位，与注释"CLONE_CHILD_SETTID|CLEARTID"(bit24/21) 不符；
    // 对快照功能虽无害，但非干净 fork。改为仅 SIGCHLD。
    asm(
    "inject_begin: \n"
        "mov x0, #17 \n"        // SIGCHLD（fork 语义）
        "mov x1, #0 \n"
        "mov x2, #0 \n"
        "mov x3, #0 \n"
        "mov x4, #0 \n"
        "mov x8, #220 \n"       // SYS_clone
        "svc #0 \n"
        "cmp x0, #0 \n"
        "beq inject_child \n"
        "ret \n"
    "inject_child: \n"
        "brk #0 \n"             // generate a core by SIGTRACE
    "inject_exit: \n"
        "mov x8, #93 \n"        // exit(0)
        "mov x0, #0 \n"
        "svc #0 \n"
    "inject_end: \n"
    );
}

#else
static __used__ void inject_fork(void) 
{
    /* asm code for fork injection.
     */
    asm(
    "inject_begin: \n"
        "mov $57, %rax \n"  // SYS_fork
        "syscall \n"
        "cmpl $0, %eax \n"
        "je inject_child \n"
        "ret \n"
    "inject_child: \n"
        "int $3 \n"         // generate a core by SIGTRACE
    "inject_exit: \n"
        "mov $60, %rax \n"  // exit(0)
        "mov $0, %rdi \n"
        "syscall \n"
    "inject_end: \n"
   );
}
#endif
}; // extern 'C'

namespace arthur {

static const char TEST_STREAM_MAGIC[] = {'A', 'R', 'T', 'H', 'Z', '4', '\0', '\4'};

struct AtomicOutputState {
    bool replace_existing;
    dev_t initial_device;
    ino_t initial_inode;

    AtomicOutputState() : replace_existing(false), initial_device(0), initial_inode(0) {}
};

class ScopedSignalMask {
public:
    ScopedSignalMask() : _active(false) {}

    int Block(const sigset_t& mask) {
        if (sigprocmask(SIG_BLOCK, &mask, &_old_mask) != 0) {
            return -1;
        }
        _active = true;
        return 0;
    }

    ~ScopedSignalMask() {
        if (_active && sigprocmask(SIG_SETMASK, &_old_mask, NULL) != 0) {
            warn("cannot restore monitor signal mask (%s)", strerror(errno));
        }
    }

private:
    bool _active;
    sigset_t _old_mask;
};

static int create_atomic_output(const char *final_path, std::string& temp_path,
                                AtomicOutputState& state)
{
    struct stat st;
    // Atomic rename replaces a symlink itself rather than its referent. Reject
    // every existing non-regular path so /dev/stdout and similar destinations
    // cannot be accidentally replaced.
    if (lstat(final_path, &st) == 0) {
        if (!S_ISREG(st.st_mode)) {
            error("refusing non-regular output path %s", final_path);
            errno = EINVAL;
            return -1;
        }
        state.replace_existing = true;
        state.initial_device = st.st_dev;
        state.initial_inode = st.st_ino;
    } else {
        if (errno != ENOENT) {
            error("cannot inspect output path %s (%s)", final_path, strerror(errno));
            return -1;
        }
        state.replace_existing = false;
    }

    temp_path.assign(final_path);
    temp_path.append(".tmp.XXXXXX");
    std::vector<char> name(temp_path.begin(), temp_path.end());
    name.push_back('\0');
    int fd = mkstemp(name.data());
    if (fd < 0 && errno == ENAMETOOLONG) {
        const char *slash = strrchr(final_path, '/');
        if (slash) {
            temp_path.assign(final_path, (size_t)(slash - final_path + 1));
        } else {
            temp_path.clear();
        }
        temp_path.append(".arthur.tmp.XXXXXX");
        name.assign(temp_path.begin(), temp_path.end());
        name.push_back('\0');
        fd = mkstemp(name.data());
    }
    if (fd < 0) {
        error("cannot create temporary output beside %s (%s)", final_path, strerror(errno));
        return -1;
    }
    temp_path.assign(name.data());
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        int saved_errno = errno;
        close(fd);
        unlink(temp_path.c_str());
        errno = saved_errno;
        error("cannot secure temporary output %s (%s)", temp_path.c_str(), strerror(errno));
        return -1;
    }
    return fd;
}

static int sync_output_directory(const char *path)
{
    std::string directory(".");
    const char *slash = strrchr(path, '/');
    if (slash) {
        directory.assign(path, slash == path ? 1 : (size_t)(slash - path));
    }
    int fd = open(directory.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        error("open output directory %s for sync failed (%s)",
              directory.c_str(), strerror(errno));
        return -1;
    }
    if (fsync(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        error("sync output directory %s failed (%s)", directory.c_str(), strerror(errno));
        return -1;
    }
    close(fd);
    return 0;
}

static int commit_atomic_path(const std::string& temp_path, const std::string& final_path,
                              const AtomicOutputState& state)
{
    int rename_rc = -1;
    int cleanup_rc = 0;
    if (state.replace_existing) {
        struct stat st;
        if (lstat(final_path.c_str(), &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_dev != state.initial_device || st.st_ino != state.initial_inode) {
            error("output path %s changed identity or type before commit",
                  final_path.c_str());
            unlink(temp_path.c_str());
            errno = EBUSY;
            return -1;
        }
#ifdef SYS_renameat2
        // A check followed by rename is not an atomic conditional replace: a
        // producer can install another file after lstat and have it silently
        // overwritten. Exchange the names first, then validate the displaced
        // inode. A mismatch is exchanged back before this transaction fails.
        rename_rc = syscall(SYS_renameat2, AT_FDCWD, temp_path.c_str(),
                            AT_FDCWD, final_path.c_str(), RENAME_EXCHANGE);
        if (rename_rc == 0) {
            struct stat displaced;
            int inspect_rc = lstat(temp_path.c_str(), &displaced);
            if (inspect_rc != 0 ||
                !S_ISREG(displaced.st_mode) ||
                displaced.st_dev != state.initial_device ||
                displaced.st_ino != state.initial_inode) {
                int inspect_errno = inspect_rc != 0 ? errno : EBUSY;
                if (syscall(SYS_renameat2, AT_FDCWD, temp_path.c_str(),
                            AT_FDCWD, final_path.c_str(), RENAME_EXCHANGE) != 0) {
                    error("output path %s changed during commit and rollback failed (%s)",
                          final_path.c_str(), strerror(errno));
                    return -1;
                }
                unlink(temp_path.c_str());
                error("output path %s changed identity or type during commit",
                      final_path.c_str());
                errno = inspect_errno;
                return -1;
            }
            if (unlink(temp_path.c_str()) != 0) {
                error("committed output but failed to remove replaced file %s (%s)",
                      temp_path.c_str(), strerror(errno));
                cleanup_rc = -1;
            }
        }
#else
        errno = ENOTSUP;
        error("atomic replacement of existing output %s is not supported",
              final_path.c_str());
#endif
    } else {
        // Do not overwrite a file another producer created while this dump was
        // in progress. renameat2 gives an atomic no-replace commit; hard-linking
        // is a same-directory fallback for older kernels.
#ifdef SYS_renameat2
        rename_rc = syscall(SYS_renameat2, AT_FDCWD, temp_path.c_str(),
                            AT_FDCWD, final_path.c_str(), 1 /* RENAME_NOREPLACE */);
        if (rename_rc != 0 &&
            (errno == ENOSYS || errno == EINVAL || errno == EOPNOTSUPP)) {
#endif
            rename_rc = link(temp_path.c_str(), final_path.c_str());
            if (rename_rc == 0 && unlink(temp_path.c_str()) != 0) {
                error("committed output but failed to remove temporary link %s (%s)",
                      temp_path.c_str(), strerror(errno));
                cleanup_rc = -1;
            }
#ifdef SYS_renameat2
        }
#endif
    }
    if (rename_rc != 0) {
        error("commit output %s failed (%s)", final_path.c_str(), strerror(errno));
        unlink(temp_path.c_str());
        return -1;
    }
    // The rename has already committed the output and cannot be rolled back.
    // Still report a directory-sync failure: the name is not durable across a
    // crash until this succeeds.
    int sync_rc = sync_output_directory(final_path.c_str());
    return (cleanup_rc == 0 && sync_rc == 0) ? 0 : -1;
}

static int open_atomic_lz4(Lz4Stream& out, const char *final_path,
                           std::string& temp_path, AtomicOutputState& state)
{
    int fd = create_atomic_output(final_path, temp_path, state);
    if (fd < 0) {
        return -1;
    }
    if (out.OpenFd(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        unlink(temp_path.c_str());
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int commit_atomic_lz4(Lz4Stream& out, const std::string& temp_path,
                             const std::string& final_path,
                             const AtomicOutputState& state)
{
    int sync_rc = out.Sync();
    int close_rc = out.Close();
    if (sync_rc != 0 || close_rc != 0) {
        unlink(temp_path.c_str());
        return -1;
    }
    return commit_atomic_path(temp_path, final_path, state);
}

static FILE *open_atomic_file(const char *final_path, std::string& temp_path,
                              AtomicOutputState& state)
{
    int fd = create_atomic_output(final_path, temp_path, state);
    if (fd < 0) {
        return NULL;
    }
    FILE *file = fdopen(fd, "wb");
    if (!file) {
        int saved_errno = errno;
        close(fd);
        unlink(temp_path.c_str());
        errno = saved_errno;
        return NULL;
    }
    return file;
}

static int commit_atomic_file(FILE *&file, const std::string& temp_path,
                              const std::string& final_path,
                              const AtomicOutputState& state)
{
    int rc = 0;
    if (fflush(file) != 0 || fsync(fileno(file)) != 0) {
        error("sync output %s failed (%s)", final_path.c_str(), strerror(errno));
        rc = -1;
    }
    if (fclose(file) != 0) {
        error("close output core failed for %s (%s)", final_path.c_str(), strerror(errno));
        rc = -1;
    }
    file = NULL;
    if (rc != 0) {
        unlink(temp_path.c_str());
        return -1;
    }
    return commit_atomic_path(temp_path, final_path, state);
}

void debugstr(std::string a)
{
        //std::string a = note.str();
        //unsigned char *ptr2 = (unsigned char*)&nh;
        unsigned char *ptr = (unsigned char*)a.c_str();
        for (size_t i=0; i<a.size()+1; i++) {
            printf(" %02x", ptr[i]);
            if ((i+1) % 16 == 0) printf("\n");
        }
        printf("\n");
}

// function for get module base address
uint64_t get_module_address(pid_t pid, const char* so_path)
{
    uint64_t r_addr = 0;

    // this proc
    if (pid == -1) {
        pid = getpid();
    }

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        return 0;
    }
    char *line = NULL;
    size_t line_cap = 0;
    while (getline(&line, &line_cap, f) >= 0) {
        char *path = strchr(line, '/');
        if (!path) {
            continue;
        }

        // find (R50-9: 只匹配路径 basename 开头——原 strstr 在父目录含
        // "libc-"/"libc." 前缀时误中，把该目录下文件基址当 libc 返回；
        // 反之父目录 "libc6" 等会整行误负。要求 so_path 即 basename 开头）
        int find_len = strlen(so_path);
        char *slash = strrchr(path, '/');
        char *bname = slash ? slash + 1 : path;
        char *find = (strncmp(bname, so_path, find_len) == 0) ? bname : NULL;
        if (!find || (find[find_len]!='-' && find[find_len]!='.' )) {
            continue;
        }

        char *end = NULL;
        errno = 0;
        unsigned long long base = strtoull(line, &end, 16);
        if (end == line || *end != '-' || errno == ERANGE) {
            continue;
        }
        r_addr = (uint64_t)base;

        break;
    }
    free(line);
    fclose(f);

    return r_addr;
}

// 从目标进程自身 libc ELF 的 .dynsym 解析符号地址（B11 修复）。
//
// 原实现 get_remote_func_address 用本机 dlsym 偏移 + 目标 libc 基址，
// 隐含假设 arthur 与目标进程的 libc 版本/符号布局完全一致。目标运行在
// 不同发行版/容器/chroot，或 arthur 所在机器 glibc 升级后，偏移即错——
// pt_call 会让目标从错误地址取指令执行（垃圾代码）→ SIGSEGV 被当作正常
// 完成，写坏 acore、破坏目标内存。
//
// 这里直接从目标 libc ELF 的 PT_DYNAMIC → DT_SYMTAB/DT_STRTAB 解析符号的
// st_value（相对偏移），与宿主 libc 无关。符号个数经 SysV hash（nchain）
// 或 GNU hash（链尾哨兵）确定。
//
// 不能用节表：libc 的节表（e_shoff 处）不在任何 PT_LOAD 的 p_filesz 内，
// 运行期内存中该区域是 BSS 零填充，读出来全是 0。
static uint64_t get_remote_sym_address(pid_t pid, uint64_t base, const char *func_name)
{
#define ARTHUR_STT_NOTYPE   0
#define ARTHUR_STT_FUNC     2
#define ARTHUR_PT_DYNAMIC   2
#define ARTHUR_DT_NULL      0
#define ARTHUR_DT_HASH      4
#define ARTHUR_DT_STRTAB    5
#define ARTHUR_DT_SYMTAB    6
#define ARTHUR_DT_STRSZ     10
#define ARTHUR_DT_SYMENT    11
#define ARTHUR_DT_GNU_HASH  0x6ffffef5
    // R50-9: 从目标读出的符号计数/哈希表尺寸全部设硬上限——损坏/恶意目标可把
    // nchain/nbuckets/bloom_size 设成巨大值并让映射可读，arthur 在符号解析里
    // 无超时逐条 pread 空转（真实 libc 符号 ~5k、bucket ~4k、bloom ~数百，
    // 1M 上限已远高于任何合法 ELF，同时把攻击从分钟级收敛到亚秒级）。
#define ARTHUR_MAX_SYM      (1<<20)   // 最大符号数
#define ARTHUR_MAX_NBUCKETS (1<<20)   // 最大 GNU hash bucket 数
#define ARTHUR_MAX_BLOOM    (1<<20)   // 最大 bloom 字数（8MB）
#define ARTHUR_MAX_CHAIN    (1<<20)   // 单链最大步数
#define ARTHUR_MAX_DYN      4096      // 最大动态表项数
#define ARTHUR_MAX_STRTAB   (64U<<20) // 动态字符串表上限
    if (base == 0 || func_name == NULL) {
        return 0;
    }

    char mempath[64];
    snprintf(mempath, sizeof(mempath), "/proc/%u/mem", pid);
    int fd = open(mempath, O_RDONLY);
    if (fd < 0) {
        return 0;
    }

    // read ELF header at the load base
    Elf64_Ehdr ehdr;
    if (pread(fd, &ehdr, sizeof(ehdr), base) != (ssize_t)sizeof(ehdr) ||
        ehdr.e_ident[0] != ELFMAG0 || ehdr.e_ident[1] != 'E' ||
        ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F' ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
        base > UINT64_MAX - ehdr.e_phoff) {
        close(fd);
        return 0;
    }

    // read program headers, find PT_DYNAMIC
    std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum);
    ssize_t ph_bytes = (ssize_t)(ehdr.e_phnum * ehdr.e_phentsize);
    if (ph_bytes != (ssize_t)(phdrs.size() * sizeof(Elf64_Phdr)) ||
        pread(fd, phdrs.data(), ph_bytes, base + ehdr.e_phoff) != ph_bytes) {
        close(fd);
        return 0;
    }
    uint64_t dyn_vaddr = 0;
    uint64_t dyn_size = 0;
    // B188: 符号地址 = 加载基址 + st_value，加载基址 = 映射起始 - 首 PT_LOAD 的
    // p_vaddr。glibc/musl 首 PT_LOAD 恒 p_vaddr=0（base 即加载基址），原实现
    // base + st_value 正确；但非零首段 vaddr 的异构 libc（容器替换/非 glibc）会
    // 让符号地址偏移 p_vaddr、注入跑垃圾代码。记下首 PT_LOAD p_vaddr 修正。
    // 注意：① 用 found 标志替代 `first_load_vaddr == 0` 哨兵——首 PT_LOAD 的
    // p_vaddr 合法值为 0，哨兵条件恒真、会在第二个 PT_LOAD（如 0x26000）处覆盖
    // 捕获（实证：glibc 首 LOAD vaddr=0 被误捕成 0x26000，符号地址偏移 → 注入
    // 跑垃圾）。② dyn_vaddr 循环必须保留 break（取第一个 PT_DYNAMIC）。
    uint64_t first_load_vaddr = 0;
    bool found_first_load = false;
    for (size_t i = 0; i < phdrs.size(); i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            first_load_vaddr = phdrs[i].p_vaddr;
            found_first_load = true;
            break;
        }
    }
    if (!found_first_load || base < first_load_vaddr) {
        close(fd);
        return 0;
    }
    uint64_t load_bias = base - first_load_vaddr;
    for (size_t i = 0; i < phdrs.size(); i++) {
        if (phdrs[i].p_type == ARTHUR_PT_DYNAMIC) {
            // C130: 与下方符号公式同源——PT_DYNAMIC 的运行时地址 = 加载基址 +
            // p_vaddr，加载基址 = base - 首 PT_LOAD p_vaddr。ET_DYN（首段 vaddr=0）
            // 下等价原 base + p_vaddr；ET_EXEC（非 PIE，p_vaddr 是绝对地址）下
            // base + p_vaddr 会双倍偏移、读错 .dynamic → 符号解析失败（C130 原
            // 评估的 fail-closed）。统一修正公式（首 PT_LOAD 未捕获时维持原行为）。
            if (load_bias > UINT64_MAX - phdrs[i].p_vaddr) {
                close(fd);
                return 0;
            }
            dyn_vaddr = load_bias + phdrs[i].p_vaddr;
            dyn_size = phdrs[i].p_memsz;
            break;
        }
    }
    if (dyn_vaddr == 0 || dyn_size < sizeof(Elf64_Dyn)) {
        close(fd);
        return 0;
    }

    // read dynamic entries until DT_NULL
    //
    // 注意：这里读的是运行期已 RELOCATE 过的 .dynamic（目标进程内存）——
    // 动态链接器把 DT_SYMTAB/DT_STRTAB/DT_HASH/DT_GNU_HASH 的 d_ptr
    // 重定位成了进程内绝对地址，不能再加 base。用 d_ptr < base 兜底：
    // 若拿到的是文件内相对 vaddr（未重定位场景），补 base。
    uint64_t symtab = 0, strtab = 0, strsz = 0;
    uint64_t syment = 24, hash = 0, gnu_hash = 0;
    bool dynamic_terminated = false;
    size_t dyn_entries = (size_t)MIN(dyn_size / sizeof(Elf64_Dyn),
                                     (uint64_t)ARTHUR_MAX_DYN);
    for (size_t i = 0; i < dyn_entries; i++) {
        Elf64_Dyn dyn;
        if (i > (UINT64_MAX - dyn_vaddr) / sizeof(dyn) ||
            pread(fd, &dyn, sizeof(dyn), dyn_vaddr + i * sizeof(dyn)) !=
                (ssize_t)sizeof(dyn)) {
            close(fd);
            return 0;
        }
        if (dyn.d_tag == ARTHUR_DT_NULL) {
            dynamic_terminated = true;
            break;
        }
        uint64_t ptr = dyn.d_un.d_ptr;
        if (ptr != 0 && ptr < base) {
            if (load_bias > UINT64_MAX - ptr) {
                close(fd);
                return 0;
            }
            ptr += load_bias;    // 未重定位的相对 vaddr
        }
        switch (dyn.d_tag) {
            case ARTHUR_DT_SYMTAB: symtab = ptr; break;
            case ARTHUR_DT_STRTAB: strtab = ptr; break;
            case ARTHUR_DT_STRSZ:  strsz = dyn.d_un.d_val; break;
            case ARTHUR_DT_SYMENT: syment = dyn.d_un.d_val; break;
            case ARTHUR_DT_HASH:   hash = ptr; break;
            case ARTHUR_DT_GNU_HASH: gnu_hash = ptr; break;
        }
    }
    if (!dynamic_terminated || symtab == 0 || strtab == 0 || strsz == 0 ||
        strsz > ARTHUR_MAX_STRTAB ||
        syment != sizeof(Elf64_Sym)) {
        close(fd);
        return 0;
    }

    // symbol count: SysV hash nchain, or GNU hash chain walk
    uint64_t sym_count = 0;
    if (hash != 0) {
        uint32_t nbucket, nchain;
        if (hash > UINT64_MAX - 4 ||
            pread(fd, &nbucket, 4, hash) != 4 ||
            pread(fd, &nchain, 4, hash + 4) != 4) {
            close(fd);
            return 0;
        }
        // Declared hash geometry is part of the symbol-table boundary. Do not
        // truncate a corrupt table and then resolve names from its prefix.
        if (nbucket == 0 || nbucket > ARTHUR_MAX_NBUCKETS ||
            nchain == 0 || nchain > ARTHUR_MAX_SYM) {
            close(fd);
            return 0;
        }
        sym_count = nchain;
    } else if (gnu_hash != 0) {
        uint32_t hdr[4];
        if (pread(fd, hdr, sizeof(hdr), gnu_hash) != (ssize_t)sizeof(hdr)) {
            close(fd);
            return 0;
        }
        uint32_t nbuckets = hdr[0], symoffset = hdr[1], bloom_size = hdr[2];
        // R50-9: nbuckets/bloom_size 目标可控——过大时 buckets/chains 偏移会
        // 指向任意可读映射，遍历空转。设上限后直接失败。
        if (nbuckets == 0 || nbuckets > ARTHUR_MAX_NBUCKETS ||
            bloom_size == 0 || bloom_size > ARTHUR_MAX_BLOOM ||
            symoffset == 0 || symoffset > ARTHUR_MAX_SYM ||
            gnu_hash > UINT64_MAX - 16 ||
            (uint64_t)bloom_size * 8 > UINT64_MAX - (gnu_hash + 16)) {
            close(fd);
            return 0;
        }
        uint64_t buckets = gnu_hash + 16 + (uint64_t)bloom_size * 8;
        if ((uint64_t)nbuckets * 4 > UINT64_MAX - buckets) {
            close(fd);
            return 0;
        }
        uint64_t chains = buckets + (uint64_t)nbuckets * 4;
        uint32_t max_chain = 0;
        bool saw_bucket = false;
        // B186: nbuckets(≤1M) × 每链步数(≤1M) 的**乘积**可达 10^12——构造的 libc
        // 让每个 bucket 都指向同一长链（全 0 无终止位）时，内外层循环跑满 10^12 次
        // pread（每次走 /proc/pid/mem 的 VMA 查找），arthur 挂起数天（对 crash-dump/
        // monitor 工具的反取证 DoS）。R50-9 的单维度上限未覆盖乘积放大。加跨 bucket
        // 全局步数上限，把总工作量收敛到亚秒级（合法 libc nbuckets~4k、链 1-2 项，
        // 实际 ~9k 步，远低于上限）。
        uint64_t total_steps = 0;
        for (uint32_t b = 0; b < nbuckets; b++) {
            uint32_t idx;
            uint64_t bucket_addr = buckets + (uint64_t)b * 4;
            if (bucket_addr < buckets ||
                pread(fd, &idx, 4, bucket_addr) != 4) {
                close(fd);
                return 0;
            }
            if (idx == 0) {
                continue;
            }
            if (idx < symoffset) {
                close(fd);
                return 0;
            }
            saw_bucket = true;
            uint32_t steps = 0;
            bool chain_terminated = false;
            while (idx >= symoffset && steps < ARTHUR_MAX_CHAIN) {
                uint32_t c = idx - symoffset;
                if (c > max_chain) max_chain = c;
                uint32_t chain;
                uint64_t chain_addr = chains + (uint64_t)c * 4;
                if (chain_addr < chains ||
                    pread(fd, &chain, 4, chain_addr) != 4) {
                    close(fd);
                    return 0;
                }
                total_steps++;
                if (total_steps > ARTHUR_MAX_SYM) {
                    close(fd);
                    return 0;
                }
                if (chain & 1) {
                    chain_terminated = true;
                    break;
                }
                idx++;
                steps++;
            }
            if (!chain_terminated) {
                close(fd);
                return 0;
            }
        }
        if (saw_bucket &&
            (uint64_t)symoffset + max_chain + 1 > ARTHUR_MAX_SYM) {
            close(fd);
            return 0;
        }
        sym_count = saw_bucket ? (uint64_t)symoffset + max_chain + 1 : symoffset;
    }
    if (sym_count == 0) {
        close(fd);
        return 0;
    }

    // Validate the complete table boundaries before accepting a matching
    // prefix. Otherwise a truncated or forged table can resolve one early
    // symbol and hide the fact that its declared tail is unreadable.
    unsigned char boundary;
    if (sym_count - 1 > (UINT64_MAX - symtab) / syment ||
        symtab + (sym_count - 1) * syment > UINT64_MAX - (sizeof(Elf64_Sym) - 1) ||
        pread(fd, &boundary, 1,
              symtab + (sym_count - 1) * syment + sizeof(Elf64_Sym) - 1) != 1 ||
        strtab > UINT64_MAX - (strsz - 1) ||
        pread(fd, &boundary, 1, strtab + strsz - 1) != 1) {
        close(fd);
        return 0;
    }

    for (uint64_t i = 0; i < sym_count; i++) {
        Elf64_Sym sym;
        if (i > (UINT64_MAX - symtab) / syment ||
            pread(fd, &sym, sizeof(sym), symtab + i * syment) !=
                (ssize_t)sizeof(sym)) {
            break;
        }
        int type = sym.st_info & 0xf;   // ELF64_ST_TYPE
        if (type != ARTHUR_STT_FUNC && type != ARTHUR_STT_NOTYPE) {
            continue;
        }
        // B79 (Codex B11 review): 未定义符号（st_shndx==SHN_UNDEF，st_value 常为 0）
        // 若只匹配名字会返回 base+0（非零 libc 基址），绕过调用方 `== 0` 检查，
        // 把 ELF 头当代码执行。拒绝未定义/零值符号。
        if (sym.st_shndx == 0 || sym.st_value == 0) {
            continue;
        }
        if (sym.st_name == 0 || sym.st_name >= strsz ||
            strtab > UINT64_MAX - sym.st_name) {
            continue;
        }
        char name[256];
        size_t available = (size_t)MIN(strsz - sym.st_name,
                                      (uint64_t)(sizeof(name) - 1));
        ssize_t r = pread(fd, name, available, strtab + sym.st_name);
        if (r <= 0) {
            continue;
        }
        char *terminator = (char *)memchr(name, '\0', (size_t)r);
        if (!terminator) {
            continue;
        }
        *terminator = '\0';
        if (strcmp(name, func_name) == 0) {
            close(fd);
            // B188: 加载基址修正（见 first_load_vaddr 捕获处）。合法 libc
            // first_load_vaddr==0 时等价于原 base + st_value。
            if (load_bias > UINT64_MAX - sym.st_value) {
                return 0;
            }
            return load_bias + sym.st_value;
        }
    }
    close(fd);
    return 0;
#undef ARTHUR_STT_NOTYPE
#undef ARTHUR_STT_FUNC
#undef ARTHUR_PT_DYNAMIC
#undef ARTHUR_DT_NULL
#undef ARTHUR_DT_HASH
#undef ARTHUR_DT_STRTAB
#undef ARTHUR_DT_SYMTAB
#undef ARTHUR_DT_STRSZ
#undef ARTHUR_DT_SYMENT
#undef ARTHUR_DT_GNU_HASH
#undef ARTHUR_MAX_SYM
#undef ARTHUR_MAX_NBUCKETS
#undef ARTHUR_MAX_BLOOM
#undef ARTHUR_MAX_CHAIN
#undef ARTHUR_MAX_DYN
#undef ARTHUR_MAX_STRTAB
}

/* pt_ functions, for ptrace_ calls.
 */
static inline int pt_wait(pid_t pid, int *terminal_status = NULL)
{
    int status = 0;
    if (terminal_status) {
        *terminal_status = -1;
    }
    // 原实现忽略 waitpid 返回值：失败（EINTR 被信号打断 / ECHILD 目标已被 reap）时
    // status 未初始化就被返回，pt_call 循环对垃圾值做 WIFSTOPPED/WSTOPSIG。
    // R50-1: 阻塞 waitpid 会无限挂起——多线程目标 fork 注入实测：auto-attach 的
    // child 停住未回收，leader 在 EVENT_FORK 后不再停靠，waitpid 永不返回。改用
    // WNOHANG 轮询 + 截止时间，卡死时返回 -1（调用方 fail-closed）。
    // R50-21: 截止用单调钟——墙钟 NTP 回拨会使超时永不触发，hang 收敛失效。
    long long t0 = monotonic_ms();
    const long WAIT_TIMEOUT_MS = 10000;
    for (;;) {
        if (monotonic_ms() - t0 > WAIT_TIMEOUT_MS) {
            error("pt_wait: %d did not stop within %ld ms (target stuck?)", pid, WAIT_TIMEOUT_MS);
            errno = ETIMEDOUT;
            return -1;
        }
        pid_t rc = waitpid(pid, &status, WUNTRACED | WNOHANG);
        if (rc == pid) {
            // B187: tracee 可能在 attach/interrupt 与 waitpid 之间退出——waitpid
            // 返回 WIFEXITED/WIFSIGNALED 状态（正数），原实现当"成功停靠"返回，
            // pt_attach/pt_int 只查 <0 误报成功 → 死线程被当停靠（collect_threads
            // 写零化块、末尾 pt_detach 伪 ESRCH 错误、ECHILD 误标 EAGAIN/D 态）。
            // 只有真正的 stop（signal-delivery/group/event stop）才算停靠成功。
            if (!WIFSTOPPED(status)) {
                if (terminal_status) {
                    *terminal_status = status;
                }
                errno = ESRCH;
                return -1;
            }
            break;
        }
        if (rc < 0 && errno == EINTR) {
            continue;   // 被信号打断，重试
        }
        if (rc == 0) {
            usleep(1000);   // 无状态变化，稍等再查
            continue;
        }
        return -1;      // ECHILD 等：调用方按"非停止/失败"处理
    }
    dprint("status = %x (%d, %d)", status, WIFSTOPPED(status), WSTOPSIG(status));
    return status;
}

// 1: still traced by this Arthur, 0: disappeared or no longer ours,
// -1: ownership could not be determined.
static int trace_ownership(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/status", pid);
    FILE *status = fopen(path, "r");
    if (!status) {
        return (errno == ENOENT || errno == ESRCH) ? 0 : -1;
    }

    char line[256];
    pid_t tracer = 0;
    bool saw_tracer = false;
    while (fgets(line, sizeof(line), status)) {
        if (sscanf(line, "TracerPid:\t%d", &tracer) == 1) {
            saw_tracer = true;
            break;
        }
    }
    bool read_failed = ferror(status) != 0;
    int close_rc = fclose(status);
    if (!saw_tracer || read_failed || close_rc != 0) {
        return -1;
    }
    return tracer == getpid() ? 1 : 0;
}

static inline int pt_detach(pid_t pid, int signal = 0)
{
    // PTRACE_DETACH already resumes an attach-stopped tracee. Injecting
    // SIGCONT here changes application-visible signal state and can resume a
    // pre-existing job-control stop.
    for (int attempt = 0; attempt < 2; attempt++) {
        int rc = ptrace(PTRACE_DETACH, pid, NULL, (uintptr_t)signal);
        if (rc == 0) {
            return 0;
        }
        int saved_errno = errno;
        if (attempt == 0 && (saved_errno == EINTR || saved_errno == EIO)) {
            continue;
        }
        errno = saved_errno;
        if (saved_errno == ESRCH) {
            int ownership = trace_ownership(pid);
            if (ownership == 0) {
                return -1;
            }
            if (ownership > 0) {
                errno = EBUSY;
                error("detach %d returned ESRCH but tracee is still owned", pid);
            } else {
                errno = EIO;
                error("detach %d returned ESRCH and ownership is unknown", pid);
            }
        } else {
            error("detach %d failed (%s)", pid, strerror(saved_errno));
        }
        return -1;
    }
    errno = EIO;
    return -1;
}

/* B152: 注入超时时 tracee 仍在运行（pt_wait WNOHANG 轮询 10s 无停靠）——
 * fail() 的 POKEDATA/SETREGSET 与调用方 pt_setregs/restore_target_after_fail
 * 的 SETOPTIONS/CONT 对运行中 tracee 全 ESRCH（实证），恢复全失效，目标会继续
 * 执行注入代码 → ret-to-0 假 SIGSEGV 崩溃。先停住它再让恢复路径生效。
 * SEIZE-attach（forkcore_m）用 PTRACE_INTERRUPT；ATTACH-attach（forkcore，
 * INTERRUPT 返回 EIO）回退 kill(SIGSTOP)。D 态 tracee 两种都停不住（SIGSTOP
 * 挂起到唤醒），此时注入代码未执行、恢复无意义，返回 -1 维持原状。
 */
static inline int pt_stop_if_running(pid_t pid)
{
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) != 0) {
        if (kill(pid, SIGSTOP) != 0) {
            return -1;
        }
    }
    return pt_wait(pid);
}

// read all general purpose registers
static inline int pt_getregs(pid_t pid, user_regs64_struct *pregs)
{
    int rc;

#ifdef __aarch64__
    struct iovec iov;
    iov.iov_base = pregs;
    iov.iov_len = sizeof(user_regs64_struct);
    rc = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
#else
    rc = ptrace(PTRACE_GETREGS, pid, NULL, pregs);
#endif

    // B30: 不 assert，失败由调用方（WriteThreadMeta）处理，避免线程退出时 abort
    return rc;
}

// read all fp registers
static inline int pt_getfpregs(pid_t pid, user_fpregs64_struct *pregs)
{
    int rc;

#ifdef __aarch64__
    struct iovec iov;
    iov.iov_base = pregs;
    iov.iov_len = sizeof(user_fpregs64_struct);
    rc = ptrace(PTRACE_GETREGSET, pid, NT_FPREGSET, &iov);
#else
    rc = ptrace(PTRACE_GETFPREGS, pid, NULL, pregs);
#endif

    // B30: 不 assert，失败由调用方处理
    return rc;
}

// write all fp registers (B3：注入后恢复被被调函数践踏的 FP/SIMD)
static inline int pt_setfpregs(pid_t pid, user_fpregs64_struct *pregs)
{
    int rc;

#ifdef __aarch64__
    struct iovec iov;
    iov.iov_base = pregs;
    iov.iov_len = sizeof(user_fpregs64_struct);
    rc = ptrace(PTRACE_SETREGSET, pid, NT_FPREGSET, &iov);
#else
    rc = ptrace(PTRACE_SETFPREGS, pid, NULL, pregs);
#endif

    return rc;
}

// R50-10 (aarch64): 注入恢复若用 NT_FPREGSET 会把 TIF_SVE 任务的 SVE 状态清空
//（内核 fpsimd_set 对 TIF_SVE 任务 test_and_clear TIF_SVE + sve_free，z/p/FFR
// 全部丢失）——本机 x86 无法实测，按内核 arch/arm64/kernel/ptrace.c sve_get/
// sve_set 语义实现。优先用 NT_ARM_SVE 保存/恢复（SVE 使能内核上可用，含 FPSIMD
// 视图），内核无 SVE 时回退 NT_FPREGSET（此时无 SVE 状态可丢，FPSIMD 完整）。
// 返回 0 表示 SVE 已保存（*out_buf malloc，调用方 free）；-1 表示需回退 FPSIMD。
#ifdef __aarch64__
#define ARTHUR_NT_ARM_SVE 0x405
static inline int pt_save_sve(pid_t pid, char **out_buf, size_t *out_len)
{
    // struct user_sve_header（arm64 uapi <asm/ptrace.h>）：16 字节定长
    struct {
        uint32_t size;
        uint32_t max_size;
        uint16_t vl;
        uint16_t max_vl;
        uint16_t flags;
        uint16_t reserved;
    } hdr;
    struct iovec iov;
    iov.iov_base = &hdr;
    iov.iov_len = sizeof(hdr);
    if (ptrace(PTRACE_GETREGSET, pid, ARTHUR_NT_ARM_SVE, &iov) != 0) {
        return -1;   // 内核无 SVE（EINVAL）→ 回退 FPSIMD
    }
    // 防御：size 是内核算出的总 dump 大小（FPSIMD 视图 ~272B / SVE 随 VL 到几 KB），
    // 异常大说明目标/内核异常，拒用。
    if (hdr.size < sizeof(hdr) || hdr.size > 64*1024) {
        return -1;
    }
    char *buf = (char*)malloc(hdr.size);
    if (!buf) {
        return -1;
    }
    iov.iov_base = buf;
    iov.iov_len = hdr.size;
    if (ptrace(PTRACE_GETREGSET, pid, ARTHUR_NT_ARM_SVE, &iov) != 0) {
        free(buf);
        return -1;
    }
    *out_buf = buf;
    *out_len = hdr.size;
    return 0;
}

static inline int pt_restore_sve(pid_t pid, const char *buf, size_t len)
{
    struct iovec iov;
    iov.iov_base = (void*)buf;
    iov.iov_len = len;
    return ptrace(PTRACE_SETREGSET, pid, ARTHUR_NT_ARM_SVE, &iov);
}
#undef ARTHUR_NT_ARM_SVE
#endif

// read all xstate registers (x64)
static inline int pt_getxstateregs(pid_t pid, x64_xstatereg *pregs, size_t *out_len = NULL)
{
    int rc;

    struct iovec iov;
    iov.iov_base = pregs;
    iov.iov_len = sizeof(x64_xstatereg);
    rc = ptrace(PTRACE_GETREGSET, pid, NT_X86_XSTATE, &iov);

    // B30: 不 assert，失败由调用方处理
    if (out_len) {
        // 内核回写 iov_len 为实际 XSTATE 大小（取决于 XCR0）
        *out_len = (rc == 0) ? iov.iov_len : 0;
    }
    return rc;
}

// b3: 恢复完整 XSTATE。len 用保存时的实际长度——SETREGSET 对大于 CPU 支持
// 的缓冲（iov_len 超 XCR0 覆盖区）会失败。
static inline int pt_setxstateregs(pid_t pid, x64_xstatereg *pregs, size_t len)
{
    struct iovec iov;
    iov.iov_base = pregs;
    iov.iov_len = len;
    return ptrace(PTRACE_SETREGSET, pid, NT_X86_XSTATE, &iov);
}

// write all general purpose registers
static inline int pt_setregs(pid_t pid, user_regs64_struct *pregs)
{
    int rc = -1;
    int saved_errno = 0;
    for (int attempt = 0; attempt < 2; attempt++) {
#ifdef __aarch64__
        struct iovec iov;
        iov.iov_base = pregs;
        iov.iov_len = sizeof(user_regs64_struct);
        rc = ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
#else
        rc = ptrace(PTRACE_SETREGS, pid, NULL, pregs);
#endif
        if (rc == 0) {
            return 0;
        }
        saved_errno = errno;
        if (attempt == 0 && (saved_errno == EINTR || saved_errno == EIO)) {
            continue;
        }
        break;
    }

    // B57: 目标可能已退出；返回错误码让调用方 fail-closed，不再 assert。
    errno = saved_errno;
    return rc;
}

/* the pt_call put a call frame with return address of ZERO on top of the current thread,
 * and wait the SIGSEGV ocur.
 */
// R50-50: 捕获的寄存器 rax 若是 syscall-restart 返回值（-ERESTARTSYS=-512、
// -ERESTARTNOINTR=-513、-ERESTARTNOHAND=-514、-ERESTART_RESTARTBLOCK=-516，
// 内核 exit_to_user_mode_loop 检测 -512..-516），CONT(0) 会让内核做 regs->ip -= 2
// 重启——注入的 waitpid 不执行，目标从 waitpid-2 跑垃圾代码（B16 的 mmap 路径靠
// 返回值 fail-closed，waitpid 收尾注入只有 B73 告警，且垃圾执行本身有栈践踏风险）。
// 此时跳过 best-effort 注入（fork 子进程可能残留 zombie，如实告警）。范围保守含
// -515（非真实 errno，跳过无害）。
static inline bool regs_has_restart_return(user_regs64_struct &regs)
{
    long long rax = (long long)regs.get_rc();
    return rax <= -512 && rax >= -516;
}

// R50-51: forkcore_m 返回给 monitor 的组停靠哨兵（现有 -1=failed / -2=exited）。
// 组停靠 leader 时 forkcore_m 直接返回它让 monitor 置 leader_in_group_stop；
// monitor 仍以 waitpid 状态而不是可能合并的 SIGCHLD siginfo 作为事件事实。
static const int GROUP_STOP_SENTINEL = -3;
// pt_call normally returns -1 when the injected operation fails. This distinct
// value means Arthur also failed to restore state it had already modified, so
// a persistent monitor must not continue tracing the target as if it were sound.
static const int PT_CALL_RECOVERY_FAILED = -4;

// R50-51: 基于 wait 状态的 leader 崩溃/死亡确定性检出（C134）。崩溃 SIGCHLD 会被
// coalescing（first-wins）合并进 INTERRUPT 噪音，纯 siginfo 分类无法检出（且注入完成
// 的 ret-to-0 SIGSEGV 也是 CLD_TRAPPED/SIGSEGV，会误报），必须看实际停靠状态。
// 返回 >0 崩溃信号；-2 正常退出；0 运行中/无崩溃/非崩溃停靠。WNOWAIT 保留状态，
// 调用方的探测不会消费普通 signal-delivery stop 或退出事件。
static int detect_leader_death(pid_t pid)
{
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    if (waitid(P_PID, pid, &si, WEXITED | WSTOPPED | WNOHANG | WNOWAIT) != 0 ||
        si.si_pid == 0) {
        return 0;
    }
    if (si.si_code == CLD_KILLED || si.si_code == CLD_DUMPED) {
        return si.si_status;
    }
    if (si.si_code == CLD_EXITED) {
        return -2;
    }
    if (si.si_code == CLD_STOPPED || si.si_code == CLD_TRAPPED) {
        if (is_core_dump_signal(si.si_status)) {
            return si.si_status;
        }
    }
    return 0;
}

// B197: 注入失败时探测 leader 是否停在真实崩溃 delivery-stop（B158 已检出
// "crash during injection"、GETSIGINFO 可见 si_code==SI_USER/SI_TKILL）。restore
// 的 CONT(0) 会抑制该崩溃信号 → 目标"复活"、崩溃丢失（实证：失败 dump 窗口
// kill-SEGV 后目标存活、无采集）。调用方据此返回崩溃信号让 monitor 采集。
static int probe_crash_stop(pid_t pid)
{
    siginfo_t pending;
    memset(&pending, 0, sizeof(pending));
    if (waitid(P_PID, pid, &pending, WSTOPPED | WNOHANG | WNOWAIT) == 0 &&
        pending.si_pid != 0 &&
        (pending.si_code == CLD_STOPPED || pending.si_code == CLD_TRAPPED)) {
        if (is_core_dump_signal(pending.si_status)) {
            return pending.si_status;
        }
    }
    siginfo_t si;
    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0 &&
        is_core_dump_signal(si.si_signo) &&
        (si.si_code == SI_USER || si.si_code == SI_TKILL)) {
        return si.si_signo;
    }
    return 0;
}

// B72: out_inject_rsp/out_orig_word 输出注入时写 0 的 [rsp-8] 槽位与原字——
// fork 注入后子进程（COW 快照）保留注入的 0，父进程恢复了但 dump 读的子进程没有，
// 调用方可用这两个值把原字写回子进程，消除快照污染。
// R50-50: out_fork_child 输出 TRACEFORK auto-attach 的 fork 子进程 pid——fork 注入
// 中 fork 已成功（子进程冻结在 EVENT_FORK stop）但 pt_call 之后失败时，调用方据此
// SIGKILL 回收，否则子进程残留为 arthur 的 tracee（arthur 退出才释放并执行注入
// 壳代码尾部，int $3 崩溃/exit）。
// B195: DETACH(SIGKILL) 的 SIGKILL 与子进程壳代码 int $3 的竞态——SIGKILL 落地前
// 子进程已执行 int $3，SIGTRAP 默认动作转储内核 core（monitor 每次 SIGUSR1 dump
// 在目标 cwd 留 core.<comm>.<host>.<pid>；forkcore 因 leader 保持停止、SIGKILL
// 恰好先落地而不留）。把子进程 rip 指到 exit(0) 序列（跳过 int $3）：SIGKILL 先到
// 则 SIGKILL 杀、子进程先跑则干净 exit(0)，两条路都不转储 core。mode-2（sys_core）
// 子进程非 tracee（GETREGS 失败直接返回），int $3 内核 core 正是 merge 所需，不受
// 影响。调用方在 SIGKILL detach 前调用。
static inline void pt_child_skip_int3(pid_t child, uint64_t inject_page,
                                      long inject_exit_off)
{
    if (child <= 0 || inject_page == 0 || inject_exit_off <= 0) {
        return;
    }
    user_regs64_struct cregs;
    if (pt_getregs(child, &cregs) != 0) {
        // 子进程不可用（非 tracee / 已消失）——维持原 SIGKILL detach 行为。
        return;
    }
#ifdef __aarch64__
    cregs.pc = inject_page + (uint64_t)inject_exit_off;
#else
    cregs.rip = inject_page + (uint64_t)inject_exit_off;
#endif
    if (pt_setregs(child, &cregs) != 0) {
        // 设置失败维持原状，不掩盖错误。
    }
}

// Snapshot children are tracees but not children of Arthur. DETACH(SIGKILL) is
// the normal release path. If DETACH itself fails, explicitly queue SIGKILL,
// drive any ptrace exit stop, and consume the tracer-side terminal status so a
// long-lived monitor cannot retain a frozen snapshot process indefinitely.
static inline int pt_terminate_tracee(pid_t pid)
{
    if (pid <= 0) {
        return 0;
    }
    if (pt_detach(pid, SIGKILL) == 0) {
        return 0;
    }

    // ESRCH from PTRACE_DETACH does not prove that the tracee disappeared; it
    // is also returned when the task is not in a detachable ptrace stop. If it
    // is still owned by this tracer, drive the normal kill/wait fallback.
    if (errno == ESRCH) {
        char path[64];
        char line[256];
        snprintf(path, sizeof(path), "/proc/%u/status", pid);
        FILE *status = fopen(path, "r");
        if (!status) {
            if (errno == ENOENT || errno == ESRCH) {
                return 0;
            }
        } else {
            pid_t tracer = 0;
            bool saw_tracer = false;
            while (fgets(line, sizeof(line), status)) {
                if (sscanf(line, "TracerPid:\t%d", &tracer) == 1) {
                    saw_tracer = true;
                    break;
                }
            }
            bool read_failed = ferror(status) != 0;
            fclose(status);
            if (saw_tracer && !read_failed && tracer != getpid()) {
                return 0;
            }
        }
    }

    int detach_errno = errno;
    error("detach snapshot child %d with SIGKILL failed (%s); using kill fallback",
          pid, strerror(detach_errno));
    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
        error("kill snapshot child %d failed (%s)", pid, strerror(errno));
        return -1;
    }

    for (int attempt = 0; attempt < 1000; attempt++) {
        int status = 0;
        pid_t wr = waitpid(pid, &status, __WALL | WUNTRACED | WNOHANG);
        if (wr == pid) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                return 0;
            }
            if (WIFSTOPPED(status) &&
                ptrace(PTRACE_CONT, pid, 0, (uintptr_t)SIGKILL) != 0 &&
                errno != ESRCH) {
                error("continue snapshot child %d toward SIGKILL failed (%s)",
                      pid, strerror(errno));
                return -1;
            }
            continue;
        }
        if (wr < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ECHILD || errno == ESRCH) {
                return 0;
            }
            error("wait for killed snapshot child %d failed (%s)",
                  pid, strerror(errno));
            return -1;
        }
        usleep(1000);
    }
    errno = ETIMEDOUT;
    error("snapshot child %d did not terminate after SIGKILL", pid);
    return -1;
}
static inline int pt_call(pid_t pid, user_regs64_struct *oregs, uint64_t func, int argc,
                          uint64_t argv[], uint64_t *out_inject_rsp = NULL,
                          uint64_t *out_orig_word = NULL,
                          uint64_t *out_fork_child = NULL,
                          int *out_death = NULL,
                          int *out_stop_signal = NULL)
{
    int rc, status = 0;
    user_regs64_struct regs;
    assert(argc <= 6);
    if (out_stop_signal) {
        *out_stop_signal = 0;
    }

    // B71: 中途失败也要恢复被注入践踏的状态（[rsp-8] 内存字 + FP/SIMD），
    // 否则 fail-closed 后目标带着注入的 0 / 垃圾 xmm 继续运行。
#ifdef __aarch64__
    user_fpregs64_struct fpregs;
    int fp_saved = 0;
    // R50-10: NT_FPREGSET 恢复会清空 TIF_SVE 任务的 SVE 状态；有 SVE 时改用
    // NT_ARM_SVE 保存/恢复（pt_save_sve 成功则 sve_saved=1，buf 需 free）。
    char *sve_buf = NULL;
    size_t sve_len = 0;
    int sve_saved = 0;
#endif
#ifndef __aarch64__
    // b3 (Codex review): 注入真实 libc 函数按 SysV ABI 践踏 caller-saved 扩展
    // 状态——FXSAVE 512B 只覆盖 x87/xmm 低 128 位，AVX/AVX-512 的 ymm/zmm
    // 高半部与 opmask 在 XSTATE 里。GETREGSET(NT_X86_XSTATE) 全量保存，
    // SETREGSET 同实际长度写回（XCR0 决定大小）。
    x64_xstatereg xstate;
    size_t xstate_len = 0;
    int xstate_saved = 0;
#endif
    int stack_saved = 0;
    uint64_t orig_stack_word = 0;
    uint64_t inject_rsp = 0;
    // R50-17: waitpid 注入多线程目标走 glibc wait4 慢路径（__libc_single_threaded==0），
    // 在目标原红区 [R-0x48, R-8) 分配 0x28 栈帧并存参——pt_call 原只保存 [rsp-8] 一个
    // 字，注入后目标红区其余 40~56 字节保留 wait4 垃圾，叶函数红区局部变量被破坏。
    // 保存/恢复整个 128 字节红区 [R-128, R)。
    uint64_t red_base = 0;
    uint64_t red_zone[16];
    int red_saved = 0;

    auto fail = [&](const char* msg) -> int {
        bool recovery_failed = false;
        error("pt_call: %s %d failed (%s)", msg, pid, strerror(errno));
        // 恢复注入期间被修改的目标状态
#ifndef __aarch64__
        if (stack_saved) {
            errno = 0;
            if (ptrace(PTRACE_POKEDATA, pid, inject_rsp,
                       (void*)orig_stack_word) != 0) {
                error("pt_call: restore stack word %d failed (%s)",
                      pid, strerror(errno));
                recovery_failed = true;
            }
        }
        // R50-17: wait4 慢路径践踏目标红区（见 save 处注释）——恢复整个 128 字节红区。
        if (red_saved) {
            for (int i = 0; i < 16; i++) {
                errno = 0;
                if (ptrace(PTRACE_POKEDATA, pid, red_base + i * 8,
                           (void*)red_zone[i]) != 0) {
                    error("pt_call: restore red zone word %d/%d failed (%s)",
                          i, pid, strerror(errno));
                    recovery_failed = true;
                }
            }
        }
        if (xstate_saved && pt_setxstateregs(pid, &xstate, xstate_len) != 0) {
            error("pt_call: restore xstate %d failed (%s)", pid, strerror(errno));
            recovery_failed = true;
        }
#else
        if (sve_saved) {
            // R50-10: 恢复 SVE（不清 TIF_SVE）；失败告警
            if (pt_restore_sve(pid, sve_buf, sve_len) != 0) {
                error("pt_call: restore SVE %d failed (%s)", pid, strerror(errno));
                recovery_failed = true;
            }
            free(sve_buf);
            sve_buf = NULL;
        } else if (fp_saved) {
            if (pt_setfpregs(pid, &fpregs) != 0) {
                error("pt_call: restore FPSIMD %d failed (%s)", pid, strerror(errno));
                recovery_failed = true;
            }
        }
#endif
        return recovery_failed ? PT_CALL_RECOVERY_FAILED : -1;
    };

    // get origin regs
    // B57: 目标可能在注入中途死亡（兄弟线程 SIGKILL / 自身崩溃），各 ptrace
    // 调用返回 -ESRCH。全部改为干净返回错误，不再 assert abort。
    rc = pt_getregs(pid, &regs);
    if (rc != 0) { return fail("getregs"); }

    // B3: 保存 FP/SIMD（x86-64 用 XSTATE 全量含 AVX-512，aarch64 用 FPSIMD）
#ifndef __aarch64__
    rc = pt_getxstateregs(pid, &xstate, &xstate_len);
    if (rc != 0) { return fail("getxstateregs"); }
    xstate_saved = 1;
#else
    // R50-10: 优先 NT_ARM_SVE 保存（含 SVE 时不清状态）；无 SVE 回退 FPSIMD。
    if (pt_save_sve(pid, &sve_buf, &sve_len) == 0) {
        sve_saved = 1;
    } else {
        rc = pt_getfpregs(pid, &fpregs);
        if (rc != 0) { return fail("getfpregs"); }
        fp_saved = 1;
    }
#endif

    // simulate call instruction
#ifdef __aarch64__
    regs.regs[30] = 0;
#else
    // A real SysV call enters its callee with rsp == 8 (mod 16). A tracee can
    // be interrupted in a leaf frame with its original rsp already == 8;
    // blindly subtracting 8 would then enter libc misaligned. Reserve the
    // return slot plus the original low alignment bits so every injected
    // callee sees the required stack alignment.
    inject_rsp = regs.rsp - 8 - (regs.rsp & 0xf);
    errno = 0;
    long peeked = ptrace(PTRACE_PEEKDATA, pid, inject_rsp, NULL);
    if (errno != 0) {
        // R50-1: PEEKDATA 失败（栈槽不可读）却继续 POKE 0，恢复时因 stack_saved=0
        // 漏写回，目标 [rsp-8] 永久残留 0 → 后续 ret 到 0 崩。栈槽不可读是异常
        // 状态，fail-closed 返回（fail() 会恢复 xstate/fp）。
        return fail("peek [rsp-8]");
    }
    stack_saved = 1;
    orig_stack_word = (uint64_t)peeked;
    // R50-17: 保存整个 128 字节红区 [rsp-128, rsp)——wait4 多线程慢路径会写
    // [R-0x48, R-8)，单字保存覆盖不到。PEEKDATA 失败（栈槽不可读）时 fail-closed。
    red_base = regs.rsp - 128;
    for (int i = 0; i < 16; i++) {
        errno = 0;
        long w = ptrace(PTRACE_PEEKDATA, pid, red_base + i * 8, NULL);
        if (errno != 0) {
            return fail("peek red zone");
        }
        red_zone[i] = (uint64_t)w;
    }
    red_saved = 1;
    regs.rsp = inject_rsp;
    rc = ptrace(PTRACE_POKEDATA, pid, regs.rsp, 0);
    if (rc != 0) { return fail("poke injected return slot"); }
    // B72: 暴露恢复数据给调用方（fork 后写回子进程快照）
    if (out_inject_rsp) { *out_inject_rsp = inject_rsp; }
    if (out_orig_word) { *out_orig_word = orig_stack_word; }
#endif

    // makeup function call and arguments
    regs.set_pc(func);
    for (int i=0; i<argc; i++) {
        switch (i) {
            case 0:
                regs.set_arg0(argv[0]);
                break;
            case 1:
                regs.set_arg1(argv[1]);
                break;
            case 2:
                regs.set_arg2(argv[2]);
                break;
            case 3:
                regs.set_arg3(argv[3]);
                break;
            case 4:
                regs.set_arg4(argv[4]);
                break;
            case 5:
                regs.set_arg5(argv[5]);
                break;
            default:
               assert(0);
        }
    }

    rc = pt_setregs(pid, &regs);
    if (rc != 0) { return fail("setregs"); }

    // wait for a SIGSEGV
    // R50-1: 注入可能卡死——多线程目标的 fork 注入实测：EVENT_FORK 后 leader 不再
    // 停靠（auto-attach 的 child 停住未回收，leader 在注入页运行却不 fault），pt_wait
    // 无限阻塞，arthur 永久挂起。加超时，卡死时 fail-closed（fail() 恢复 xstate/
    // [rsp-8]），调用方还原目标。
    // R50-21: 截止用单调钟（墙钟 NTP 回拨会永不触发）。
    long long t0 = monotonic_ms();
    const long INJECT_TIMEOUT_MS = 10000;
    for (;;) {
        if (monotonic_ms() - t0 > INJECT_TIMEOUT_MS) {
            // B152: 超时时 tracee 仍在运行，fail() 与调用方的 POKEDATA/SETREGSET/
            // setregs 恢复全 ESRCH 失效（R50-1/R50-21 的注释假设 tracee 已停）。
            // 先停住它，恢复才生效；D 态停不住则维持原状（注入代码未执行）。
            pt_stop_if_running(pid);
            return fail("inject timeout");
        }
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == SIGSEGV) {
                // B158: 区分注入完成的 SIGSEGV 与注入期间目标的真实崩溃。完成是
                // 注入函数/壳代码 ret 到模拟返回地址 0 产生的**页面 fault**（fetch
                // 0 或执行 NX 栈页——实测 fork 壳代码的完成 fault si_addr 是栈地址、
                // si_code=SEGV_ACCERR，因此 si_addr 不可靠）。kill 投递的 SIGSEGV
                // 无 fault，si_code=SI_USER(0) 或 SI_TKILL（tgkill）。注入函数是 syscall
                // 包装不内部 fault，故注入期间唯一非 fault 的 SIGSEGV 就是 kill 投递的
                // 真实崩溃——用 si_code==SI_USER/SI_TKILL 判定（实证：mmap 注入期间
                // kill -SEGV → 原实现把崩溃当完成、mmap 返回 0x1、目标"复活"崩溃漏抓；
                // B196: 漏 SI_TKILL 会漏掉兄弟线程 tgkill 的崩溃）。
                siginfo_t si = {};
                int siginfo_rc = ptrace(PTRACE_GETSIGINFO, pid, 0, &si);
                if (siginfo_rc != 0 || si.si_code == SI_USER || si.si_code == SI_TKILL) {
                    if (siginfo_rc != 0) {
                        error("cannot inspect SIGSEGV during injection (%s)", strerror(errno));
                    } else {
                        error("SIGSEGV si_code=%d during injection (real crash, not completion)",
                              si.si_code);
                    }
                    return fail("crash during injection");
                }
                break;
            }
            int stop_event = (status >> 16) & 0xffff;
            if (stop_event == 0 && is_core_dump_signal(WSTOPSIG(status))) {
                // Any other core-dumping delivery-stop is an application
                // crash, not part of the injected syscall completion protocol.
                error("%s during injection (real crash, not completion)",
                      strsignal(WSTOPSIG(status)));
                return fail("crash during injection");
            }
            if (stop_event == 0) {
                // A real delivery-stop unrelated to the injected call must not
                // be resumed with signal 0. Report it to the owner, which will
                // restore GPRs and relay the signal to the original TID.
                if (out_stop_signal) {
                    *out_stop_signal = WSTOPSIG(status);
                }
                errno = EINTR;
                return fail("signal during injection");
            }
            if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
                unsigned long msg;
                rc = ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg);
                if (rc != 0) { return fail("geteventmsg"); }
                dprint("child pid = %lu", msg);
                // R50-50: 记录 auto-attach 的 fork 子进程——pt_call 后续若失败
                //（目标中途死亡/超时/崩溃），调用方据此 SIGKILL 回收冻结子进程。
                if (out_fork_child) { *out_fork_child = (uint64_t)msg; }
            }
        }
        rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
        if (rc < 0) {
            // 目标在注入过程中死亡（兄弟线程 SIGKILL 等）
            // B198: CONT 失败（ESRCH）说明目标已死——死亡状态未被下方 pt_wait
            // 返回（在本次 stop 与 CONT 之间死亡），记录供调用方返回 -2 清理退出
            //（否则 monitor 继续监控死进程挂起）。
            if (out_death) {
                *out_death = -2;
            }
            return fail("cont");
        }

        int terminal_status = -1;
        status = pt_wait(pid, &terminal_status);
        if (status < 0) {
            int wait_errno = errno;
            if (terminal_status >= 0 && out_death) {
                *out_death = WIFSIGNALED(terminal_status) ?
                    WTERMSIG(terminal_status) : -2;
            }
            if (wait_errno == ETIMEDOUT) {
                // pt_wait timed out while the tracee was still running. State
                // restoration below requires a ptrace stop.
                if (pt_stop_if_running(pid) < 0) {
                    error("pt_call: cannot stop %d after wait timeout (%s)",
                          pid, strerror(errno));
                }
            }
            errno = wait_errno;
            return fail("wait for injected call");
        }
        // B198: 捕获注入期间目标的死亡/退出——waitpid 状态被本函数消费后调用方
        //（detect_leader_death）拿不到，死亡 SIGCHLD 又被 dump 噪音 first-wins 合并
        // 吞掉，monitor 会继续监控死进程（挂起）。记录供调用方返回 -2 清理退出。
        if (out_death && (WIFSIGNALED(status) || WIFEXITED(status))) {
            *out_death = WIFSIGNALED(status) ? WTERMSIG(status) : -2;
        }
    }
    
    if (oregs) {
        // b30 (Codex review): 末尾 getregs 返回被忽略——注入结束后目标若已退出
        // （兄弟线程 SIGKILL/自身崩溃），oregs 是未初始化垃圾，调用方按它继续
        // （waitpid 结果/恢复寄存器）会出错。检查返回并 fail-closed。
        if (pt_getregs(pid, oregs) != 0) {
            return fail("getregs after call");
        }
    }

    // B3: 恢复被注入践踏的状态。ret 已把 rsp 还原，[inject_rsp] 仍存 0；
    // 写回原返回地址字，并恢复 FP/SIMD（x86-64 用 XSTATE 全量含 AVX-512）。
#ifdef __aarch64__
    // 无 [rsp-8] 模拟；仅恢复 FP。R50-10: 有 SVE 时用 NT_ARM_SVE 恢复（不清 TIF_SVE）。
    bool restore_ok = true;
    if (sve_saved) {
        if (pt_restore_sve(pid, sve_buf, sve_len) != 0) {
            error("pt_call: restore SVE %d failed (%s)", pid, strerror(errno));
            restore_ok = false;
        }
        free(sve_buf);
        sve_buf = NULL;
    } else if (fp_saved) {
        if (pt_setfpregs(pid, &fpregs) != 0) {
            error("pt_call: restore FPSIMD %d failed (%s)", pid, strerror(errno));
            restore_ok = false;
        }
    }
#else
    bool restore_ok = true;
    if (stack_saved) {
        errno = 0;
        if (ptrace(PTRACE_POKEDATA, pid, inject_rsp,
                   (void*)orig_stack_word) != 0) {
            error("pt_call: restore stack word %d failed (%s)", pid, strerror(errno));
            restore_ok = false;
        }
    }
    // R50-17: 恢复整个 128 字节红区（wait4 慢路径践踏的部分）
    if (red_saved) {
        for (int i = 0; i < 16; i++) {
            errno = 0;
            if (ptrace(PTRACE_POKEDATA, pid, red_base + i * 8,
                       (void*)red_zone[i]) != 0) {
                error("pt_call: restore red zone word %d/%d failed (%s)",
                      i, pid, strerror(errno));
                restore_ok = false;
            }
        }
    }
    if (xstate_saved && pt_setxstateregs(pid, &xstate, xstate_len) != 0) {
        error("pt_call: restore xstate %d failed (%s)", pid, strerror(errno));
        restore_ok = false;
    }
#endif

    if (!restore_ok) {
        errno = EIO;
        return PT_CALL_RECOVERY_FAILED;
    }

    return rc;
}

static inline int pt_write(pid_t pid, uint64_t dest, void *src, size_t len)
{
    // B31: 原实现写硬编码 inject_fork 而非参数 src——当前调用者恰好都传
    // inject_fork 才没暴露。改用 pwrite（避免 lseek+write 的偏移竞态）并
    // 检查写全。
    char pbuf[128];
    snprintf(pbuf, sizeof(pbuf), "/proc/%u/mem", pid);
    int fd = open(pbuf, O_RDWR);
    if (fd < 0) {
        error("open %s failed", pbuf);
        return -1;
    }
    ssize_t rc = pwrite(fd, src, len, dest);
    if (rc != (ssize_t)len) {
        // R50-1: 短写（0<=rc<len）时 POSIX 不保证设置 errno，打印陈旧 errno 误导
        // 排障。仅 rc<0 才解释 errno；短写打印实际字节数。
        if (rc < 0) {
            error("write mem(%lx) of %d failed (%s)", dest, pid, strerror(errno));
        } else {
            error("write mem(%lx) of %d short write: %zd of %zu bytes", dest, pid, rc, len);
        }
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static inline int pt_attach(pid_t pid, int *relay_signal = NULL)
{
    int rc;

    if (relay_signal) {
        *relay_signal = 0;
    }

    rc = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (rc != 0) {
        // 线程可能已退出（ESRCH）：返回错误让调用方容错，而非 abort
        return rc;
    }
    // R50-22: pt_wait 超时（线程 D 态不可停，SIGSTOP 无法交付）时 attach 虽成功但
    // tracee 未停靠——若当成功，WriteThreadMeta 写零化块、结尾 DETACH 失败残留
    // PT_PTRACED+SIGSTOP，D 态解除后线程永久冻结。传播失败让调用方 fail-closed。
    // B179/C131: 仅传播失败仍把 tracee 留在 PT_PTRACED+SIGSTOP——arthur 退出后内核
    // 自动 detach 不恢复 TASK_STOPPED，D 态线程解除后 SIGSTOP 交付、永久冻结。
    // 注意：PTRACE_DETACH 对运行中/D 态（未停靠）tracee 返回 -ESRCH（实证），无法
    // 撤销 attach；有效手段是 kill(SIGCONT) 直接投递 SIGCONT 取消 pending SIGSTOP
    //（SIGCONT 是续跑信号，不产生 ptrace delivery-stop，tracer 无需处理；D 态解除
    // 后 SIGCONT 先于 SIGSTOP 处理并取消它，线程继续运行，不再冻结）。best-effort：
    // 正常路径（tracee 及时停靠）不触发，无副作用。
    int status = pt_wait(pid);
    if (status < 0) {
        if (kill(pid, SIGCONT) != 0) {
            warn("pt_attach: SIGCONT %d after timeout failed (%s)", pid, strerror(errno));
        }
        // 顺带 best-effort DETACH（tracee 若碰巧已停靠则清 PT_PTRACED；运行中/D 态
        // 返回 ESRCH，无副作用）。
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        // B185: 超时（D 态不可停）显式置 EAGAIN——调用方（collect_threads）据此与
        // ESRCH 同待遇跳过该线程而非 abort（崩溃采集/正常 dump 都不该为一个不可停
        // 的线程丢整个现场）。原实现靠 DETACH 失败残留的 ESRCH errno 碰巧跳过，
        // 脆弱（DETACH 碰巧成功则 errno=0 → 误 abort）。
        errno = EAGAIN;
        return -1;
    }

    // PTRACE_ATTACH's SIGSTOP races with ordinary signal delivery. waitpid is
    // allowed to report that real delivery-stop first; detaching with signal 0
    // would then suppress an application-visible signal. Ptrace events and the
    // kernel-generated attach SIGSTOP are Arthur's own control stops. A real
    // SIGSTOP has non-kernel siginfo and must be re-injected on detach.
    int event = (status >> 16) & 0xffff;
    int stop_signal = WSTOPSIG(status);
    if (relay_signal && event == 0) {
        if (stop_signal != SIGSTOP) {
            *relay_signal = stop_signal;
        } else {
            siginfo_t stop_info = {};
            if (ptrace(PTRACE_GETSIGINFO, pid, 0, &stop_info) == 0) {
                if (stop_info.si_code != SI_KERNEL) {
                    *relay_signal = SIGSTOP;
                }
            } else if (errno != EINVAL) {
                int saved_errno = errno;
                pt_detach(pid);
                errno = saved_errno;
                return -1;
            }
        }
    }

    return rc;
}

static inline int pt_int(pid_t pid)
{
    int rc;
    rc = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
    // B57: 目标可能已退出，INTERRUPT 返回 -ESRCH；assert 会让 monitor abort。
    if (rc != 0) {
        return rc;
    }
    // R50-22: 同 pt_attach——INTERRUPT 后未停靠（D 态）时传播超时失败。
    if (pt_wait(pid) < 0) {
        return -1;
    }

    return rc;
}

static inline int pt_cont(pid_t pid) {
    int rc;
    rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
    // B57: 目标可能在 attach 后退出，CONT 返回 -ESRCH；assert 会让 monitor
    // 对瞬时退出目标 abort。调用方检查 rc 或忽略（monitor 场景目标已死，无害）。
    return rc;
}

int makeroom(FILE* fout, size_t n)
{
    char zero[PAGE_SIZE] = {0};

    size_t m = 0;
    while (m < n) {
        size_t len = MIN(PAGE_SIZE, n-m);
        ssize_t rc = fwrite(zero, 1, len, fout);
        if (rc <= 0) {
            // B68: 磁盘满时 fwrite 短写/失败；原实现 break 后仍返回 0，
            // decompress 的 `rc<0` 检查是死代码，部分预留被静默接受。
            error("makeroom: disk full, reserved %lu of %lu bytes", m, n);
            return -1;
        }
        m += rc;
    }

    return 0;
}

int ProcessData::ParseAll()
{
    _d_maps = new ProcMaps(_maps);
    assert(_d_maps);
    // B163: maps Parse 超 region 上限（构造 acore）时返回 -1——fail-closed 传播，
    // 不让海量 region 放大内存/hdr_size 后继续。
    if (_d_maps->Parse() <= 0) {
        error("maps contains no valid regions, acore corrupt");
        return -1;
    }

    _d_cmdline = new ProcCmdline(_cmdline);
    assert(_d_cmdline);
    if (_d_cmdline->Parse() < 0) {
        return -1;
    }

#if 0
    _d_stat = new ProcStat(_stat);
    assert(_d_stat);
    _d_stat->Parse();
    printf("pid = %d\n", _d_stat->pid);
    printf("ppid = %d\n", _d_stat->ppid);
    printf("pgid = %d\n", _d_stat->pgid);
    printf("sid = %d\n", _d_stat->sid);
#endif

    _d_auxv = new ProcAuxv(_auxv);
    assert(_d_auxv);
    if (_d_auxv->Parse() != 0) {
        return -1;
    }

    if (_stat) {
        _d_stat = new ProcStat(_stat);
        assert(_d_stat);
        if (_d_stat->Parse() != 0 || _d_stat->pid != (pid_t)_stat->f_pid) {
            error("process stat identity mismatch (parsed pid %d)", _d_stat->pid);
            return -1;
        }
    }
    if (!_credentials_valid) {
        // v1-v4 did not carry live credentials. Preserve their historical
        // behavior by using exec-time auxv IDs when reading old archives.
        _uid = _d_auxv->uid;
        _gid = _d_auxv->gid;
        _credentials_valid = true;
    }
    dprint("uid(%d), euid(%d), gid(%d), egid(%d)", 
            _d_auxv->uid, _d_auxv->euid, _d_auxv->gid, _d_auxv->egid);
    
    for (auto& t: _threads) {
        t._d_stat = new ProcStat(t._stat);
        assert(t._d_stat);
        if (t._d_stat->Parse() != 0 || t._d_stat->pid != (pid_t)t._pid) {
            error("thread %u stat identity mismatch (parsed pid %d), acore corrupt",
                  t._pid, t._d_stat->pid);
            return -1;
        }
    }

    return 0;
}

/* allocate a piece of NOTE memory, return the start of payload.
 */
char* Note::allocate(size_t payload_size)
{
    const char *name = "CORE";
    int name_size = 5;
    if (_type == NT_X86_XSTATE) {
        name = "LINUX"; 
        name_size = 6;
    }
 
    const size_t prefix_size = sizeof(Elf64_Nhdr) + 8;
    if (payload_size > UINT32_MAX || payload_size > SIZE_MAX - prefix_size) {
        errno = EOVERFLOW;
        error("note payload is too large (%zu bytes)", payload_size);
        return NULL;
    }
    size_t raw_size = prefix_size + payload_size;
    if (raw_size > SIZE_MAX - 3) {
        errno = EOVERFLOW;
        error("note allocation size overflows");
        return NULL;
    }
    size_t size = (raw_size + 3) & ~(size_t)3;
    char *note = (char*)malloc(size);
    if (!note) {
        error("allocate %zu-byte note failed", size);
        return NULL;
    }
    memset(note, 0, size);

    Elf64_Nhdr *nhdr = (Elf64_Nhdr*)note;
    nhdr->n_namesz = name_size;
    nhdr->n_descsz = (uint32_t)payload_size;
    nhdr->n_type = _type;

    strncpy(note+sizeof(Elf64_Nhdr), name, 8);

    _data = note;
    _size = size;

    return note + sizeof(Elf64_Nhdr) + 8; 
}

template <class T>
T* Note::allocate()
{
    return (T*)allocate(sizeof(T));
}

// NT_PRPSINFO
int Note::fill_prpsinfo(const ProcessData& proc, pid_t leader_pid, bool crashed)
{
    const ProcStat *process_stat = proc._d_stat;
    if (!process_stat) {
        for (const ThreadData& thread : proc._threads) {
            if ((pid_t)thread._pid == leader_pid) {
                process_stat = thread._d_stat;
                break;
            }
        }
    }
    if (!process_stat || !proc._credentials_valid) {
        error("prpsinfo: missing process/credential metadata");
        return -1;
    }
    // B36: note desc 落在 note+20（4 对齐非 8 对齐），直接 p->field 解引用是
    // 未对齐 UB（UBSan 报错，aarch64 有风险）。在对齐局部结构里填好再 memcpy。
    elf_prpsinfo64 info = {};
    info.pr_state = process_stat->state;
    info.pr_sname = process_stat->sname;
    info.pr_uid = proc._uid;
    info.pr_gid = proc._gid;
    info.pr_pid = process_stat->pid;
    info.pr_ppid = process_stat->ppid;
    info.pr_pgrp = process_stat->pgid;
    info.pr_sid = process_stat->sid;

    // B25: 填充 pr_flag/pr_zomb/pr_nice（内核原生 core 会填这些）
    info.pr_flag = process_stat->flags;
    if (crashed) {
        // Linux fs/binfmt_elf.c exposes PF_DUMPCORE|PF_SIGNALED in crash
        // PRPSINFO, while a debugger snapshot retains the live task flags.
        info.pr_flag |= 0x00000200UL | 0x00000400UL;
    }
    // b25 (Codex review): 内核 fill_psinfo 用 `pr_zomb = exit_state==EXIT_ZOMBIE`。
    // 恒 0 是错的——僵尸进程应置 1。/proc 的 sname=='Z' 即 EXIT_ZOMBIE。
    info.pr_zomb = (process_stat->sname == 'Z') ? 1 : 0;
    info.pr_nice = process_stat->nice;

    // B63: pr_fname 用 task->comm（stat 括号内文本，可执行名），与内核原生 core
    // 一致。原实现用 argv[0] 全路径，gdb/ps 显示截断的路径而非进程名。
    // b63 (Codex B63 review): 合法空 comm（PR_SET_NAME("")）与 stat 缺失/畸形都
    // 表现为 comm[0]=='\0'，原实现一律回退 argv[0] 与内核不一致。已解析的 stat
    // 必有 pid>0——仅 pid==0（stat 未解析）才回退 argv[0]；合法空 comm 保持空。
    std::string fname;
    if (process_stat->comm[0] != '\0') {
        fname = process_stat->comm;
    } else if (process_stat->pid <= 0 &&
               proc._d_cmdline && proc._d_cmdline->argv.size() > 0) {
        // B26: cmdline 为空时 argv[0] 越界。取 argv[0] 或空串。
        fname = proc._d_cmdline->argv[0];
    }
    strncpy(info.pr_fname, fname.c_str(), sizeof(info.pr_fname));
    info.pr_fname[sizeof(info.pr_fname) - 1] = '\0';

    const char* delim = " ";
    std::ostringstream args;
    if (proc._d_cmdline) {
        std::copy(proc._d_cmdline->argv.begin(), proc._d_cmdline->argv.end(),
               std::ostream_iterator<std::string>(args, delim));
    }
    strncpy(info.pr_psargs, args.str().c_str(), sizeof(info.pr_psargs));
    info.pr_psargs[sizeof(info.pr_psargs) - 1] = '\0';

    char *p = allocate(sizeof(info));
    if (!p) {
        return -1;
    }
    memcpy(p, &info, sizeof(info));

    return 0;
}

// NT_AUXV
int Note::fill_auxv(const ProcessData& proc)
{
    // B56: 损坏 acore 使 GetFile 返回 NULL（size 前缀截断 / size>64MB 上限）时
    // _auxv 为 NULL，直接 ->f_size 解引用崩溃。
    if (!proc._auxv || proc._auxv->f_size == 0) {
        error("auxv missing (corrupt acore)");
        return -1;
    }
    char *info = allocate(proc._auxv->f_size);
    if (!info) {
        return -1;
    }
    memcpy(info, proc._auxv->f_data, proc._auxv->f_size);
    return 0;
}

// NT_FILE
int Note::fill_file(const ProcessData& proc)
{
    // R50-1: 原用固定 64KB 的局部 Block 拼 NT_FILE，block.Write 的 -ENOSPC 返回
    // 全被忽略——进程文件型映射足够多（约 >2000 个）时内容超 64KB，多余 entry/
    // 文件名静默丢弃，但第 8 字节的 count 仍是完整数 → gdb 报 malformed note。
    // 改为可增长 std::string，不再有容量上限。
    struct file_entry {
        uint64_t start_addr;
        uint64_t end_addr;
        uint64_t offset;
        std::string filename;
    };
    std::vector<file_entry> entries;

    for (auto &r : *proc._d_maps) {
        if (r.name.size() > 0 && r.inode > 0) {
            file_entry n;
            n.start_addr = r.start_addr;
            n.end_addr = r.end_addr;
            n.offset = r.offset;
            n.filename = r.name;
            entries.push_back(n);
        }
    }

    std::string payload;
    uint64_t v = entries.size();
    payload.append((const char*)&v, 8);

    // R50-6: NT_FILE 的 page_size 字段是 file_ofs 的单位，file_ofs 必须写
    // **页偏移**（内核 fill_files_note 写 vma->vm_pgoff），不是 /proc/maps
    // 的字节偏移。gdb linux-tdep 读 file_ofs 后乘 page_size；旧实现写字节
    // 偏移导致 gdb info proc mappings 的文件偏移放大 4096 倍（已实证）。
    // acore 可以在不同页大小的同架构主机上转换，必须使用采集目标 auxv 中的
    // AT_PAGESZ，不能使用转换机的 sysconf(_SC_PAGESIZE)。
    uint64_t page_size = proc._d_auxv ? proc._d_auxv->page_size : 0;
    if (page_size == 0 || (page_size & (page_size - 1)) != 0) {
        error("target AT_PAGESZ missing or invalid (%lu)", (unsigned long)page_size);
        return -1;
    }
    v = page_size;
    payload.append((const char*)&v, 8);

    // address
    for (auto& n : entries) {
        if (n.offset % page_size != 0) {
            error("mapped file offset %lu is not aligned to target page size %lu",
                  (unsigned long)n.offset, (unsigned long)page_size);
            return -1;
        }
        payload.append((const char*)&n.start_addr, 8);
        payload.append((const char*)&n.end_addr, 8);
        // file_ofs = 字节偏移 / page_size（页对齐，整除无舍入）
        uint64_t file_ofs = n.offset / page_size;
        payload.append((const char*)&file_ofs, 8);
    }

    // file names
    for (auto& n : entries) {
        payload.append(n.filename.c_str(), n.filename.size() + 1);
    }

    // 文件名区精确长度作 descsz，不要在内部补零。
    // B15: 原实现 roundup(block.Size(),4) 会在文件名末尾补 0，gdb 把它解析成
    // 一个多余的空文件名 → names 区比 count 个文件实际占用大 → gdb 报
    // "malformed note - filename area is too big"。native core 的 NT_FILE
    // descsz = 16 + count*24 + 精确文件名长度，末尾补齐由 note 对齐处理。
    char *p = allocate(payload.size());
    if (!p) {
        return -1;
    }
    memcpy(p, payload.data(), payload.size());

    return 0;
}

// B62: /proc/<pid>/stat 的 utime/stime 是 jiffies（CLK_TCK/秒，通常 100），
// 内核原生 core 的 pr_utime 是 timeval（秒+微秒）。原实现把 jiffies 直接当
// tv_sec——CPU 时间显示放大 ~100 倍（0.8s 写成 80s）。转成秒+微秒。
static void jiffies_to_timeval(unsigned long jiffies, uint64_t& tv_sec, uint64_t& tv_usec)
{
    static long clk_tck = sysconf(_SC_CLK_TCK);
    if (clk_tck <= 0) {
        clk_tck = 100;
    }
    tv_sec = jiffies / (unsigned long)clk_tck;
    tv_usec = (jiffies % (unsigned long)clk_tck) * (1000000UL / (unsigned long)clk_tck);
}

// NT_PRSTATUS
int Note::fill_prstatus(const ThreadData& thr)
{
    // B36: note desc 非 8 对齐，在对齐局部结构里填好再 memcpy。同时防护 _d_stat 为空。
    if (!thr._d_stat) {
        error("prstatus: thread %u missing stat metadata", thr._pid);
        return -1;
    }
    if (thr._arch == ARCH_X64) {
        x64_elf_prstatus info = {};
        info.pr_info.si_signo = thr._prstatus_signal;
        info.pr_cursig = thr._prstatus_signal;
        if (thr._prstatus_signal != 0 &&
            thr._siginfo.si_signo == thr._prstatus_signal) {
            info.pr_info.si_code = thr._siginfo.si_code;
            info.pr_info.si_errno = thr._siginfo.si_errno;
        }
        memcpy(&info.pr_reg, &thr._regs.x64, sizeof(thr._regs.x64));
        info.pr_pid = thr._d_stat->pid;
        info.pr_ppid = thr._d_stat->ppid;
        info.pr_pgrp = thr._d_stat->pgid;
        info.pr_sid = thr._d_stat->sid;
        // B62: jiffies → 秒+微秒（内核原生 core 的 pr_utime 是 timeval）
        jiffies_to_timeval(thr._d_stat->utime, info.pr_utime.tv_sec, info.pr_utime.tv_usec);
        jiffies_to_timeval(thr._d_stat->stime, info.pr_stime.tv_sec, info.pr_stime.tv_usec);
        jiffies_to_timeval(thr._d_stat->cutime, info.pr_cutime.tv_sec, info.pr_cutime.tv_usec);
        jiffies_to_timeval(thr._d_stat->cstime, info.pr_cstime.tv_sec, info.pr_cstime.tv_usec);
        // B25: 填充 pr_sigpend/pr_sighold/pr_fpvalid（内核原生 core 会填）
        // b25: v3 用 status 源的全 64 位 SigPnd/SigBlk（stat 字段 31/32 被内核
        // & 0x7fffffff 掩掉 RT 信号）；v2 无则回退 stat 字段（低 31 位，旧行为）。
        info.pr_sigpend = thr._signal_masks_valid ? thr._sigpend : thr._d_stat->pending;
        info.pr_sighold = thr._signal_masks_valid ? thr._sighold : thr._d_stat->blocked;
        info.pr_fpvalid = thr._fp_valid ? 1 : 0;
        char *p = allocate(sizeof(info));
        if (!p) {
            return -1;
        }
        memcpy(p, &info, sizeof(info));
    }
    else if (thr._arch == ARCH_AARCH64) {
        arm64_elf_prstatus info = {};
        info.pr_info.si_signo = thr._prstatus_signal;
        info.pr_cursig = thr._prstatus_signal;
        if (thr._prstatus_signal != 0 &&
            thr._siginfo.si_signo == thr._prstatus_signal) {
            info.pr_info.si_code = thr._siginfo.si_code;
            info.pr_info.si_errno = thr._siginfo.si_errno;
        }
        memcpy(&info.pr_reg, &thr._regs.arm64, sizeof(thr._regs.arm64));
        info.pr_pid = thr._d_stat->pid;
        info.pr_ppid = thr._d_stat->ppid;
        info.pr_pgrp = thr._d_stat->pgid;
        info.pr_sid = thr._d_stat->sid;
        // B62: jiffies → 秒+微秒（内核原生 core 的 pr_utime 是 timeval）
        jiffies_to_timeval(thr._d_stat->utime, info.pr_utime.tv_sec, info.pr_utime.tv_usec);
        jiffies_to_timeval(thr._d_stat->stime, info.pr_stime.tv_sec, info.pr_stime.tv_usec);
        jiffies_to_timeval(thr._d_stat->cutime, info.pr_cutime.tv_sec, info.pr_cutime.tv_usec);
        jiffies_to_timeval(thr._d_stat->cstime, info.pr_cstime.tv_sec, info.pr_cstime.tv_usec);
        // B25: 填充 pr_sigpend/pr_sighold/pr_fpvalid（内核原生 core 会填）
        // b25: v3 用 status 源的全 64 位 SigPnd/SigBlk（stat 字段 31/32 被内核
        // & 0x7fffffff 掩掉 RT 信号）；v2 无则回退 stat 字段（低 31 位，旧行为）。
        info.pr_sigpend = thr._signal_masks_valid ? thr._sigpend : thr._d_stat->pending;
        info.pr_sighold = thr._signal_masks_valid ? thr._sighold : thr._d_stat->blocked;
        info.pr_fpvalid = thr._fp_valid ? 1 : 0;
        char *p = allocate(sizeof(info));
        if (!p) {
            return -1;
        }
        memcpy(p, &info, sizeof(info));
    }
    else {
        // b23 (Codex review): 未知 arch 时若静默返回 0，note 带 NULL 数据/未初始化
        // 长度被 GenerateNotes 接受。fail-closed：拒绝生成该 note。
        error("prstatus: unsupported arch %d", thr._arch);
        return -1;
    }
    return 0;
}

// NT_FPREGSET
int Note::fill_fpregset(const ThreadData& thr)
{
    if (thr._arch == ARCH_X64) {
        x64_elf_fpregset *p = allocate<x64_elf_fpregset>();
        if (!p) {
            return -1;
        }
        memcpy(p, &thr._fpregs.x64, sizeof(thr._fpregs.x64));
    }
    else if (thr._arch == ARCH_AARCH64) {
        arm64_elf_fpregset *p = allocate<arm64_elf_fpregset>();
        if (!p) {
            return -1;
        }
        memcpy(p, &thr._fpregs.arm64, sizeof(thr._fpregs.arm64));
    }
    else {
        // b23 (Codex review): 同 fill_prstatus，未知 arch fail-closed。
        error("fpregset: unsupported arch %d", thr._arch);
        return -1;
    }
    return 0;
}

// NT_SIGINFO
int Note::fill_siginfo(const ThreadData& thr)
{
    siginfo_t *p = allocate<siginfo_t>();
    if (!p) {
        return -1;
    }
    memcpy(p, &thr._siginfo, sizeof(*p));
    return 0;
}

// NT_X86_XSTATE
int Note::fill_x86_xstate(const ThreadData& thr)
{
    // 用 sizeof 而非硬编码 2688：x64_xstatereg = X86_XSTATE_MAX_SIZE = 2696。
    // 原硬编码 2688 让 note 少 8 字节，gdb 报 "Unexpected size of section
    // .reg-xstate"，且与 WriteThreadMeta 写入/ReadMeta 读回的 2696 不一致。
    char *p = allocate(sizeof(thr._xstate.x64));
    if (!p) {
        return -1;
    }
    memcpy(p, &thr._xstate.x64, sizeof(thr._xstate.x64));
    return 0;
}

// NT_ARM_SVE
int Note::fill_arm_sve(const ThreadData& thr)
{
    // TBD: support arm sve registsers
    return -1; 
}

Coredump::Coredump(pid_t pid)
    : _pid(pid),
      _core_pid(0),
      // B34: _arch 之前未初始化。WriteThreadMeta 用 `_arch == ARCH_X64` 决定
      // 是否写 xstate——未初始化时若非 0 会跳过 xstate，而 ReadMeta 按 acore
      // 头 arch 仍读 xstate → 块错位。采集侧统一按编译平台设置。
#ifdef __aarch64__
      _arch(ARCH_AARCH64),
#else
      _arch(ARCH_X64),
#endif
      _acore_version(ACORE_VERSION),
      _crash_sig(0),   // 非 0 时驱动 v5 PROCESS crash signal 和解码后的 PRSTATUS
      // 按 core.h 成员声明顺序（_ptrace_options 在 _ehdr/_note_phdr 之前）
      _ptrace_options(0),
      _monitor_crash_tid(0),
      _monitor_recovery_failed(false),
      _monitor_leader_exited(false),
      _ehdr(),
      _note_phdr(),
      _offset_load(0)
{
}

int Coredump::WriteFileHeader(Lz4Stream& out)
{
    AcoreHeader hdr;

    // B70: 磁盘满时头写失败 → acore 不可用，报错。
    if (out.WriteRaw((const char*)&hdr, sizeof(hdr)) != (int)sizeof(hdr)) {
        error("write acore header failed (disk full?)");
        return -1;
    }
    if (out.EnableBlockChecksums() != 0) {
        error("enable acore block checksums failed");
        return -1;
    }

    return 0;
}

int Coredump::WriteProcessMeta(Lz4Stream& out, ProcMaps& maps, pid_t source_pid)
{ 
    if (source_pid == 0) {
        source_pid = _pid;
    }
    if (_process._thrd_pid.empty() ||
        _process._thrd_pid.size() > std::numeric_limits<uint32_t>::max()) {
        error("invalid capture thread count %zu", _process._thrd_pid.size());
        return -1;
    }
    std::set<pid_t> capture_tids;
    for (pid_t tid : _process._thrd_pid) {
        if (tid <= 0 || !capture_tids.insert(tid).second) {
            error("invalid or duplicate capture thread id %d", tid);
            return -1;
        }
    }
    std::vector<char> buf(BUFFER_SIZE);
    {
        bool status_truncated = false;
        ProcFile *status_file = ProcFile::ReadPid(
            buf.data(), buf.size(), source_pid, PROC_TYPE_STATUS,
            &status_truncated);
        ProcStatus status(status_file);
        if (!status_file || status_truncated || status.Parse() != 0) {
            error("runtime credentials of %d failed structural validation", _pid);
            return -1;
        }
        _process._uid = status.uid;
        _process._gid = status.gid;
        _process._credentials_valid = true;
    }

    // put ProcessData
    {
        uint32_t u32;
        if (out.SetBlock(BLOCK_TYPE_PROCESS) != 0) {
            error("set PROCESS block type failed");
            return -1;
        }
        // R50-1: 各 out.Write/Flush 返回原未检查——磁盘满时 PROCESS 块缺失仍继续。
        auto wr = [&](const void* p, size_t n) -> bool {
            return out.Write((const char*)p, n) >= 0;
        };

        // this pid
        u32 = _pid;
        bool ok = wr(&u32, sizeof(u32));

        // forked pid if has
        u32 = _core_pid;
        ok = ok && wr(&u32, sizeof(u32));

        // thread number
        u32 = _process._thrd_pid.size();
        ok = ok && wr(&u32, sizeof(u32));

        // time
        struct timeval tv = {};
        struct timezone tz = {0};   // gettimeofday 不填 tz，避免把未初始化栈写进 acore
        if (gettimeofday(&tv, &tz) != 0) {
            error("gettimeofday failed while writing PROCESS metadata (%s)", strerror(errno));
            return -1;
        }
        ok = ok && wr(&tv, sizeof(tv));
        ok = ok && wr(&tz, sizeof(tz));

        // uname（sizeof 512 只写入 ~390 字节，其余置零）
        char ubuf[512] = {0};
        if (uname((utsname*)ubuf) != 0) {
            error("uname failed while writing PROCESS metadata (%s)", strerror(errno));
            return -1;
        }
        ok = ok && wr(ubuf, sizeof(ubuf));

        // v5 records the live real credentials. Auxv AT_UID/AT_GID are a
        // snapshot from exec and do not track later setuid/setgid calls.
        ok = ok && wr(&_process._uid, sizeof(_process._uid));
        ok = ok && wr(&_process._gid, sizeof(_process._gid));
        uint32_t crash_sig = (uint32_t)_crash_sig;
        ok = ok && wr(&crash_sig, sizeof(crash_sig));

        if (!ok || out.Flush() < 0) {
            error("write PROCESS block failed (disk full?)");
            return -1;
        }
    }

    // put raw files
    // B29: 原实现忽略 ReadPid 返回值——读失败时 NULL 传入 PutFile（NULL 解引用
    // 崩溃）或未初始化 buf 被当 ProcFile 写出垃圾。这里逐项检查，失败即返回 -1。
    // B180: 与 maps 的 R50-31 对齐——cmdline/auxv/environ/io/limits 超 1MB 缓冲
    // 截断时也 fail-closed（原实现静默把截断数据当完整写入 acore，解压端 64MB
    // 上限不会兜底，截断透传到生成的 core）。真实进程这些文件极少超 1MB
    //（environ 在巨型环境变量场景可达）。
    auto read_pid_checked = [&](ProcType t, const char* what) -> int {
        bool truncated = false;
        pid_t read_pid = t == PROC_TYPE_STAT ? _pid : source_pid;
        ProcFile* pf = ProcFile::ReadPid(buf.data(), buf.size(), read_pid, t,
                                         &truncated);
        if (!pf) {
            error("read %s of %d failed", what, _pid);
            return -1;
        }
        if (truncated) {
            error("%s of %d exceeds buffer (%ld bytes), refusing incomplete dump",
                  what, _pid, (long)BUFFER_SIZE);
            return -1;
        }
        if (t == PROC_TYPE_CMDLINE) {
            ProcCmdline decoded(pf);
            if (decoded.Parse() < 0) {
                error("live cmdline of %d failed structural validation", _pid);
                return -1;
            }
        } else if (t == PROC_TYPE_AUXV) {
            ProcAuxv decoded(pf);
            if (decoded.Parse() != 0 || decoded.page_size == 0 ||
                (decoded.page_size & (decoded.page_size - 1)) != 0) {
                error("live auxv of %d failed structural validation", _pid);
                return -1;
            }
        } else if (t == PROC_TYPE_STAT) {
            ProcStat decoded(pf);
            if (decoded.Parse() != 0 || decoded.pid != _pid) {
                error("live process stat of %d failed structural validation", _pid);
                return -1;
            }
        }
        // v6 PROCESS files describe the TGID even when a live worker supplied
        // shared proc data after the original leader called pthread_exit.
        pf->f_pid = (uint32_t)_pid;
        if (out.PutFile(pf) < 0) {
            error("write %s failed (disk full?)", what);
            return -1;
        }
        return 0;
    };
    if (read_pid_checked(PROC_TYPE_CMDLINE, "cmdline") != 0) {
        return -1;
    }
    if (read_pid_checked(PROC_TYPE_AUXV, "auxv") != 0) {
        return -1;
    }

    bool maps_truncated = false;
    ProcFile* _maps = ProcFile::ReadPid(buf.data(), buf.size(), source_pid,
                                        PROC_TYPE_MAPS, &maps_truncated);
    if (!_maps) {
        error("read maps of %d failed", _pid);
        return -1;
    }
    // R50-31: maps 超 1MB 缓冲截断时，WriteLoads/NT_FILE 只覆盖截断前的映射——
    // dump 自洽但尾部映射静默缺失（数据丢失）。fail-closed 而非产出不完整 core。
    if (maps_truncated) {
        error("maps of %d exceeds buffer (%ld bytes), refusing incomplete dump", _pid, (long)BUFFER_SIZE);
        return -1;
    }
    maps.setpf(_maps);
    int maps_rc = maps.Parse();
    // R50-27: _maps 指向本函数栈上 buf，函数返回即失效。Parse 已把数据深拷贝进
    // ProcMaps 的 std::vector（std::string name 自包含），WriteLoads 只迭代向量、
    // 不再解引用 _pf。置 NULL 防未来任何在返回后调用 Parse/readline 的路径读到
    // 悬垂指针（_pf==NULL 时 readline/Parse 安全返回 0）。
    maps.setpf(NULL);
    if (maps_rc <= 0) {
        error("live maps of %d failed structural validation", _pid);
        return -1;
    }
    _maps->f_pid = (uint32_t)_pid;
    if (out.PutFile(_maps) < 0) {
        error("write maps failed (disk full?)");
        return -1;
    }

    if (read_pid_checked(PROC_TYPE_ENVIRON, "environ") != 0) {
        return -1;
    }
    if (read_pid_checked(PROC_TYPE_IO, "io") != 0) {
        return -1;
    }
    if (read_pid_checked(PROC_TYPE_LIMITS, "limits") != 0) {
        return -1;
    }
    if (read_pid_checked(PROC_TYPE_STAT, "stat") != 0) {
        return -1;
    }

    return 0;
}

// Parse one hexadecimal signal mask from /proc/<tid>/status. A zero mask is a
// valid result, so success is reported separately from the value.
static bool parse_status_mask(const char *data, const char *key, uint64_t *out)
{
    if (!data || !key || !out) {
        return false;
    }

    const size_t key_len = strlen(key);
    const char *line = data;
    while (*line && strncmp(line, key, key_len) != 0) {
        const char *next = strchr(line, '\n');
        if (!next) {
            return false;
        }
        line = next + 1;
    }
    if (!*line) {
        return false;
    }

    const char *p = line + key_len;
    while (*p == '\t' || *p == ' ') {
        p++;
    }
    if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
          (*p >= 'A' && *p <= 'F'))) {
        return false;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(p, &end, 16);
    if (end == p || errno == ERANGE) {
        return false;
    }
    while (*end == ' ' || *end == '\t' || *end == '\r') {
        end++;
    }
    if (*end != '\0' && *end != '\n') {
        return false;
    }
    *out = (uint64_t)value;
    return true;
}

// A core-dumping signal is fatal only with its default disposition. Return 1
// for caught/ignored, 0 for default, and -1 when /proc cannot establish the
// answer. Unknown must never be converted into a false fatal crash.
static int signal_has_nondefault_disposition(pid_t pid, int sig)
{
    if (sig < 1 || sig > 64) {
        errno = EINVAL;
        return -1;
    }
    std::vector<char> buf(BUFFER_SIZE);
    bool truncated = false;
    ProcFile *spf = ProcFile::ReadPid(buf.data(), buf.size(), pid,
                                      PROC_TYPE_STATUS, &truncated);
    if (!spf || truncated) {
        return -1;
    }
    uint64_t caught = 0;
    uint64_t ignored = 0;
    if (!parse_status_mask(spf->f_data, "SigCgt:", &caught) ||
        !parse_status_mask(spf->f_data, "SigIgn:", &ignored)) {
        errno = EPROTO;
        return -1;
    }
    uint64_t bit = 1ULL << (sig - 1);
    return ((caught | ignored) & bit) != 0;
}

int Coredump::WriteThreadMeta(Lz4Stream& out, pid_t pid, bool is_main) {
    info("thread: %d", pid); // thread info
    int rc;

    // 线程由调用方预先 attach（collect_threads）；此处只读寄存器。
    // A thread listed in PROCESS metadata must have a usable register image.
    // Publishing an all-zero PRSTATUS makes a structurally valid acore that
    // debuggers cannot use and hides the capture failure from automation.
    ThreadData i;   // 构造器 memset 为零
    int fp_ok = 1;
    rc = pt_getregs(pid, (user_regs64_struct*)&i._regs);
    if (rc != 0) {
        error("getregs thread %d failed; refusing unusable thread metadata", pid);
        return -1;
    }
    rc = pt_getfpregs(pid, (user_fpregs64_struct*)&i._fpregs);
    if (rc != 0) { warn("getfpregs thread %d failed, zeroed block", pid); fp_ok = 0; }
    rc = ptrace(PTRACE_GETSIGINFO, pid, 0, &i._siginfo);
    if (rc != 0) {
        if (_crash_sig != 0 && pid == _monitor_crash_tid) {
            error("getsiginfo for crashing thread %d failed", pid);
            return -1;
        }
        warn("getsiginfo thread %d failed, zeroed signal metadata", pid);
    }
    // The raw ptrace siginfo is serialized for NT_SIGINFO. PRSTATUS is derived
    // separately while decoding: normal snapshots report no terminating
    // signal, while crash archives report the process crash signal on every
    // thread, matching Linux core semantics.
    i._prstatus_signal = _crash_sig;
    if (_arch == ARCH_X64) {
        rc = pt_getxstateregs(pid, (x64_xstatereg*)&i._xstate);
        if (rc != 0) { warn("getxstateregs thread %d failed, zeroed block", pid); fp_ok = 0; }
    }
    // v3: FP/扩展状态读取成功才有 pr_fpvalid=1；失败（线程退出）时写 0。
    i._fp_valid = (fp_ok != 0);

    // b25: /proc/<tid>/status 的 SigPnd/SigBlk 是全 64 位掩码。stat 字段 31/32
    // 被内核 `& 0x7fffffff` 掩成 31 位，丢 RT 信号（32-64）——pr_sigpend/pr_sighold
    // 会缺失。解析后随 THREAD 块写入，解压端填 pr_sigpend。
    std::vector<char> buf(BUFFER_SIZE);
    bool status_truncated = false;
    ProcFile *spf = ProcFile::ReadPid(buf.data(), buf.size(), pid, PROC_TYPE_STATUS,
                                      &status_truncated);
    if (!spf || status_truncated ||
        !parse_status_mask(spf->f_data, "SigPnd:", &i._sigpend) ||
        !parse_status_mask(spf->f_data, "SigBlk:", &i._sighold)) {
        error("read complete signal masks for thread %d failed", pid);
        return -1;
    }

    // write thread meta
    // R50-1: 各 out.Write/Flush/PutFile 返回原未检查——磁盘满时静默产出缺线程块的
    // 坏 acore（与 B64-B70 同 class，WriteThreadMeta 漏了）。检查并 fail-closed。
    if (out.SetBlock(BLOCK_TYPE_THREAD) != 0) {
        error("set THREAD block type failed");
        return -1;
    }
    auto wr = [&](const void* p, size_t n) -> bool {
        return out.Write((const char*)p, n) >= 0;
    };
    bool ok = wr(&pid, sizeof(i._pid));
    // B14: 写成员实际大小，不能用 sizeof(i._regs)（union = max(x64, arm64) 成员）。
    // x64 下 union regs=272/fpregs=528，但 ReadMeta 读 sizeof(x64 成员)=216/512，
    // 多写的 56+16=72 字节让 fpregs/siginfo/xstate 在解压时整体偏移 72 →
    // xstate 头 xfeatures 读到错位数据变 0，gdb 报 .reg-xstate 尺寸不符。
#ifdef __aarch64__
    ok = ok && wr(&i._regs, sizeof(i._regs.arm64));
    ok = ok && wr(&i._fpregs, sizeof(i._fpregs.arm64));
#else
    ok = ok && wr(&i._regs, sizeof(i._regs.x64));
    ok = ok && wr(&i._fpregs, sizeof(i._fpregs.x64));
#endif
    ok = ok && wr(&i._siginfo, sizeof(i._siginfo));
    if (_arch == ARCH_X64) {
        ok = ok && wr(&i._xstate.x64, sizeof(i._xstate.x64));
    }
    ok = ok && wr(&i._fp_valid, sizeof(i._fp_valid));
    ok = ok && wr(&i._sigpend, sizeof(i._sigpend));
    ok = ok && wr(&i._sighold, sizeof(i._sighold));
    if (!ok || out.Flush() < 0) {
        error("write thread meta failed (disk full?)");
        return -1;
    }
    // A missing or malformed live stat can never be converted later: ReadMeta
    // and ParseAll require a real stat record with the same TID. Fail during
    // capture instead of publishing an acore that is guaranteed to be rejected.
    bool stat_truncated = false;
    ProcFile *pf = ProcFile::ReadPid(buf.data(), buf.size(), pid, PROC_TYPE_STAT,
                                     &stat_truncated);
    if (!pf || stat_truncated) {
        error("read complete /proc/%d/stat failed", pid);
        return -1;
    }
    ProcStat decoded_stat(pf);
    if (decoded_stat.Parse() != 0 || decoded_stat.pid != pid) {
        error("live stat identity mismatch for thread %d (parsed %d)",
              pid, decoded_stat.pid);
        return -1;
    }
    if (out.PutFile(pf) < 0) {
        error("write thread stat failed (disk full?)");
        return -1;
    }

    return 0;
}

static int list_task_tids(pid_t leader, std::set<pid_t>& tids)
{
    char pbuf[64];
    snprintf(pbuf, sizeof(pbuf), "/proc/%u/task/", leader);
    DIR *dirp = opendir(pbuf);
    if (!dirp) {
        return -1;
    }
    int readdir_errno = 0;
    for (;;) {
        errno = 0;
        struct dirent *dp = readdir(dirp);
        if (!dp) {
            readdir_errno = errno;
            break;
        }
        if (dp->d_name[0] == '.') continue;
        // R50-22: atoi 对超长数字串溢出是 UB（真实 /proc/task 由内核生成不可触发，
        // 防伪造/损坏 /proc）。strtol + 全串校验。
        // b141 (Codex B141 review): 还须拒绝 ERANGE 与超出 pid_t 正范围的值——
        // 否则超长数字串缩窄成 32 位 pid_t 时是实现定义截断（可指向无关进程）。
        char *end = NULL;
        errno = 0;
        long tid = strtol(dp->d_name, &end, 10);
        if (end == dp->d_name || *end != '\0' || tid <= 0 ||
            errno == ERANGE || tid > (long)INT_MAX) continue;
        tids.insert((pid_t)tid);
    }
    int close_rc = closedir(dirp);
    if (readdir_errno != 0) {
        errno = readdir_errno;
        return -1;
    }
    if (close_rc != 0) {
        return -1;
    }
    return 0;
}

static bool traced_by_self(pid_t tid)
{
    return trace_ownership(tid) > 0;
}

// 1: member, 0: task disappeared or is not a member, -1: identity unknown.
static int belongs_to_thread_group(pid_t leader, pid_t tid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/task/%u", leader, tid);
    if (access(path, F_OK) == 0) {
        return 1;
    }
    return (errno == ENOENT || errno == ESRCH) ? 0 : -1;
}

int Coredump::monitor_threads(pid_t leader)
{
    _monitor_tids.clear();
    _ptrace_options = PTRACE_O_TRACEEXIT | PTRACE_O_TRACECLONE;

    for (int round = 0; round < 64; round++) {
        std::set<pid_t> observed;
        if (list_task_tids(leader, observed) != 0) {
            error("cannot enumerate threads of %d", leader);
            break;
        }

        size_t before = _monitor_tids.size();
        for (pid_t tid : observed) {
            if (_monitor_tids.count(tid)) {
                continue;
            }
            if (ptrace(PTRACE_SEIZE, tid, NULL, _ptrace_options) != 0) {
                if (errno == ESRCH) {
                    continue;
                }
                // TRACECLONE may have attached a just-created thread before its
                // parent event is drained. In that case SEIZE reports EPERM, but
                // the thread already belongs to this tracer.
                if (errno == EPERM && traced_by_self(tid)) {
                    _monitor_tids.insert(tid);
                    continue;
                }
                error("cannot seize thread %d of process %d (%s)",
                      tid, leader, strerror(errno));
                goto fail;
            }
            _monitor_tids.insert(tid);
        }

        if (!_monitor_tids.count(leader)) {
            error("leader %d vanished while attaching monitor", leader);
            break;
        }
        if (_monitor_tids.size() == before) {
            return 0;
        }
    }

fail:
    // PTRACE_DETACH requires a ptrace-stop. Restore every thread seized before
    // the failure so a partial monitor attach cannot leave the target traced.
    for (pid_t tid : _monitor_tids) {
        if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) == 0) {
            pt_wait(tid);
        }
        if (pt_detach(tid) != 0 && errno != ESRCH) {
            error("cannot detach partially monitored thread %d (%s)",
                  tid, strerror(errno));
        }
    }
    _monitor_tids.clear();
    return -1;
}

int Coredump::collect_threads(pid_t leader)
{
    _process._thrd_pid.clear();

    if (!_monitor_tids.empty()) {
        std::set<pid_t> stopped;
        int fatal_sig = 0;
        bool stop_error = false;
        _monitor_relay_signals.clear();

        auto record_stop = [&](pid_t tid, int status) -> void {
            if (!WIFSTOPPED(status)) {
                return;
            }
            int event = (status >> 16) & 0xffff;
            int sig = WSTOPSIG(status);
            if (event == PTRACE_EVENT_CLONE) {
                unsigned long child = 0;
                if (ptrace(PTRACE_GETEVENTMSG, tid, 0, &child) != 0 || child == 0) {
                    int event_errno = errno;
                    error("cannot read clone event while stopping thread %d (%s)",
                          tid, child == 0 ? "invalid child pid" : strerror(event_errno));
                    // The kernel may already have auto-attached an unknown child.
                    // A persistent monitor cannot safely continue because that
                    // child would remain outside every later resume/detach set.
                    stop_error = true;
                    _monitor_recovery_failed = true;
                } else {
                    pid_t child_tid = (pid_t)child;
                    // Register ownership before any wait/group check can fail so
                    // monitor cleanup always sees the auto-attached child.
                    _monitor_tids.insert(child_tid);
                    int membership = belongs_to_thread_group(leader, child_tid);
                    if (membership < 0) {
                        error("cannot determine thread-group identity of clone %d (%s)",
                              child_tid, strerror(errno));
                        stop_error = true;
                        _monitor_recovery_failed = true;
                    } else if (membership == 0) {
                        // TRACECLONE also reports clone-created processes whose
                        // exit signal is not SIGCHLD. They are not target
                        // threads and must not contribute crashes or notes.
                        if (pt_wait(child_tid) < 0 || pt_detach(child_tid) != 0) {
                            error("cannot release non-thread clone %d (%s)",
                                  child_tid, strerror(errno));
                            stop_error = true;
                            _monitor_recovery_failed = true;
                        } else {
                            _monitor_tids.erase(child_tid);
                        }
                    }
                }
            } else if (event == 0 && tid != _monitor_crash_tid) {
                if (is_core_dump_signal(sig)) {
                    int disposition = signal_has_nondefault_disposition(leader, sig);
                    if (disposition < 0) {
                        error("cannot determine disposition of %s for process %d",
                              strsignal(sig), leader);
                        _monitor_relay_signals[tid] = sig;
                        stop_error = true;
                        _monitor_recovery_failed = true;
                    } else if (disposition == 0) {
                        if (fatal_sig == 0) {
                            fatal_sig = sig;
                            _monitor_crash_tid = tid;
                        }
                    } else {
                        _monitor_relay_signals[tid] = sig;
                    }
                } else {
                    _monitor_relay_signals[tid] = sig;
                }
            }
            stopped.insert(tid);
        };

        for (int round = 0; round < 64; round++) {
            std::set<pid_t> observed;
            if (list_task_tids(leader, observed) != 0) {
                return -1;
            }
            if (_monitor_leader_exited) {
                observed.erase(leader);
            }
            for (pid_t tid : observed) {
                if (_monitor_tids.count(tid)) {
                    continue;
                }
                if (ptrace(PTRACE_SEIZE, tid, NULL, _ptrace_options) == 0 ||
                    (errno == EPERM && traced_by_self(tid))) {
                    _monitor_tids.insert(tid);
                } else if (errno != ESRCH) {
                    error("cannot seize newly discovered thread %d (%s)",
                          tid, strerror(errno));
                    return -1;
                }
            }

            std::vector<pid_t> snapshot(_monitor_tids.begin(), _monitor_tids.end());
            for (pid_t tid : snapshot) {
                if (stopped.count(tid)) {
                    continue;
                }
                if (_monitor_leader_exited && tid == leader) {
                    continue;
                }
                if (tid == _monitor_crash_tid) {
                    stopped.insert(tid);
                    continue;
                }

                int status = 0;
                pid_t wr = waitpid(tid, &status, __WALL | WUNTRACED | WNOHANG);
                if (wr == tid) {
                    if (WIFEXITED(status) || WIFSIGNALED(status)) {
                        _monitor_tids.erase(tid);
                        if (tid == leader) {
                            return -1;
                        }
                        continue;
                    }
                    record_stop(tid, status);
                    if (stop_error) {
                        return -1;
                    }
                    continue;
                }

                user_regs64_struct regs;
                if (pt_getregs(tid, &regs) == 0) {
                    stopped.insert(tid);
                    continue;
                }
                if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0) {
                    if (errno == ESRCH && kill(tid, 0) != 0 && errno == ESRCH) {
                        _monitor_tids.erase(tid);
                        continue;
                    }
                    error("cannot interrupt monitored thread %d (%s)", tid, strerror(errno));
                    return -1;
                }
                status = pt_wait(tid);
                if (status < 0) {
                    if (kill(tid, 0) != 0 && errno == ESRCH) {
                        _monitor_tids.erase(tid);
                        continue;
                    }
                    return -1;
                }
                record_stop(tid, status);
                if (stop_error) {
                    return -1;
                }
            }

            std::set<pid_t> confirm;
            if (list_task_tids(leader, confirm) != 0) {
                return -1;
            }
            if (_monitor_leader_exited) {
                confirm.erase(leader);
            }
            bool all_stopped = true;
            for (pid_t tid : confirm) {
                if (!_monitor_tids.count(tid) || !stopped.count(tid)) {
                    all_stopped = false;
                    break;
                }
            }
            if (!all_stopped) {
                continue;
            }

            std::vector<pid_t> known(_monitor_tids.begin(), _monitor_tids.end());
            for (pid_t tid : known) {
                if (!confirm.count(tid) &&
                    !(_monitor_leader_exited && tid == leader)) {
                    _monitor_tids.erase(tid);
                }
            }
            _process._thrd_pid.assign(confirm.begin(), confirm.end());
            if (fatal_sig != 0) {
                return fatal_sig;
            }
            if (!_monitor_relay_signals.empty()) {
                return -1;
            }
            return 0;
        }
        error("thread set of %d did not converge while stopping", leader);
        return -1;
    }

    _process._thrd_pid.push_back(leader);   // leader is already attached by caller
    std::set<pid_t> stopped;
    std::set<pid_t> unavailable;
    stopped.insert(leader);

    // A single readdir pass is not a thread-group snapshot: an untraced
    // sibling can clone after its directory entry was visited. Attach every
    // newly observed TID, then enumerate again. Once every current creator is
    // stopped, the set cannot grow and the fixed point is stable.
    for (int round = 0; round < 64; round++) {
        std::set<pid_t> observed;
        if (list_task_tids(leader, observed) != 0 || !observed.count(leader)) {
            error("cannot enumerate complete thread set of %d", leader);
            return -1;
        }

        for (pid_t tid : observed) {
            if (stopped.count(tid) || unavailable.count(tid)) {
                continue;
            }
            errno = 0;
            int relay_signal = 0;
            if (pt_attach(tid, &relay_signal) != 0) {
                // A disappearing TID is retried only if it is still present in
                // the confirmation pass. An uninterruptible thread remains an
                // explicit best-effort omission, matching the crash path's
                // established B185 behavior.
                if (errno == ESRCH) {
                    error("attach thread %d failed (exited), skipped", tid);
                    continue;
                }
                if (errno == EAGAIN) {
                    error("attach thread %d in D-state (uninterruptible), skipped", tid);
                    unavailable.insert(tid);
                    continue;
                }
                error("attach thread %d failed (%s), aborting collection",
                      tid, strerror(errno));
                return -1;
            }
            stopped.insert(tid);
            _process._thrd_pid.push_back(tid);
            if (relay_signal != 0) {
                _monitor_relay_signals[tid] = relay_signal;
            }
        }

        std::set<pid_t> confirm;
        if (list_task_tids(leader, confirm) != 0 || !confirm.count(leader)) {
            error("cannot confirm thread set of %d", leader);
            return -1;
        }
        bool complete = true;
        for (pid_t tid : confirm) {
            if (!stopped.count(tid) && !unavailable.count(tid)) {
                complete = false;
                break;
            }
        }
        if (complete) {
            return 0;
        }
    }

    error("thread set of %d did not converge while attaching", leader);
    return -1;
}

// B35(问题1): 采集失败后还原目标。兄弟线程用 PTRACE_DETACH(NULL) 恢复
// （无 SIGCONT，与 forkcore_m 末尾一致）；leader 用 CONT 恢复。monitor 场景
// 下若不做这个还原，兄弟线程会永久停在 attach-stop，目标进程死锁。
void Coredump::restore_target_after_fail()
{
    bool monitor_attached = !_monitor_tids.empty();
    std::vector<pid_t> tids;
    if (monitor_attached) {
        tids.assign(_monitor_tids.begin(), _monitor_tids.end());
    } else {
        tids = _process._thrd_pid;
    }

    if (!monitor_attached) {
        for (pid_t tid : tids) {
            std::map<pid_t, int>::const_iterator pending =
                _monitor_relay_signals.find(tid);
            int relay = pending == _monitor_relay_signals.end() ? 0 : pending->second;
            if (pt_detach(tid, relay) != 0 && errno != ESRCH) {
                error("restore: detach thread %d failed (%s)", tid, strerror(errno));
            }
        }
        _process._thrd_pid.clear();
        _monitor_relay_signals.clear();
        return;
    }

    for (pid_t tid : tids) {
        if (tid == _pid) {
            continue;
        }
        std::map<pid_t, int>::const_iterator pending = _monitor_relay_signals.find(tid);
        int relay = pending == _monitor_relay_signals.end() ? 0 : pending->second;
        if (ptrace(PTRACE_CONT, tid, NULL, (uintptr_t)relay) != 0 &&
            errno != ESRCH) {
            error("restore: cont thread %d failed (%s)", tid, strerror(errno));
            _monitor_recovery_failed = true;
        }
    }
    _process._thrd_pid.clear();

    // N2: forkcore/forkcore_m 开头设过 PTRACE_O_TRACEFORK。fail 路径若只 CONT
    // 不清理，monitor 继续运行时目标后续每个 fork 都被自动 attach+SIGSTOP 冻结
    // （实证：fail-closed 后所有新 fork 子进程 TracerPid=arthur）。此刻 leader
    // 处于 stop（所有调用方都在 pt_call/attach 后调用），SETOPTIONS 生效，先清
    // TRACEFORK（恢复 _ptrace_options，monitor 下即 TRACEEXIT）再 CONT。
    // b39 (Codex review): SETOPTIONS/CONT 返回值要检查——恢复失败时目标仍残留
    // TRACEFORK/停靠，monitor 继续运行会把之后每个 fork 冻结；如实告警。
    if (ptrace(PTRACE_SETOPTIONS, _pid, 0, _ptrace_options) != 0) {
        error("restore: set options on %d failed (%s)", _pid, strerror(errno));
        if (monitor_attached && errno != ESRCH) {
            _monitor_recovery_failed = true;
        }
    }
    std::map<pid_t, int>::const_iterator leader_pending =
        _monitor_relay_signals.find(_pid);
    int leader_relay = leader_pending == _monitor_relay_signals.end()
        ? 0 : leader_pending->second;
    if (ptrace(PTRACE_CONT, _pid, NULL, (uintptr_t)leader_relay) != 0) {
        error("restore: cont %d failed (%s)", _pid, strerror(errno));
        if (monitor_attached && errno != ESRCH) {
            _monitor_recovery_failed = true;
        }
    }
    _monitor_relay_signals.clear();
}

int Coredump::VerifyFileHeader(Lz4Stream& in)
{
    int rc;
    AcoreHeader hdr, good;
    rc = in.ReadRaw(hdr.magic, sizeof(hdr.magic));
    if (rc != sizeof(hdr.magic) || memcmp(hdr.magic, good.magic, sizeof(hdr.magic))) {
        error("magic failed.");
        return -1;
    }

    rc = in.ReadRaw((char*)&hdr.m, sizeof(hdr.m));
    if (rc != sizeof(hdr.m) || hdr.m.version < ACORE_MIN_VERSION ||
        hdr.m.version > ACORE_VERSION) {
        error("unsupported acore version %d (supported %d..%d)",
              hdr.m.version, ACORE_MIN_VERSION, ACORE_VERSION);
        return -1;
    }

    // b23 (Codex review): arch 来自 acore 头，损坏 acore 可构造为任意值。未知
    // arch 会让 fill_prstatus/fill_fpregset 不进入任何分支却返回 0，add_note
    // 于是接受 _data==NULL、_size 未初始化的 note，fwrite 崩溃或写出超大写。
    // 在入口拒绝未知 arch（fail-closed）。
    if (hdr.m.arch >= ARCH_MAX) {
        error("unsupported arch %d, acore corrupt", hdr.m.arch);
        return -1;
    }

    // for version 1, the arch is always x64.
    _arch = hdr.m.arch;
    // v3: THREAD 块尾部有 FP 有效位；读侧按版本决定是否消费
    _acore_version = hdr.m.version;
    if (_acore_version >= 4) {
        if (in.EnableBlockChecksums() != 0) {
            error("enable acore block checksums failed");
            return -1;
        }
    }

    return 0;
}

int Coredump::ReadMeta(Lz4Stream& in)
{
    Block *buf;
    BlockHeader hdr;

    buf = in.ReadBlock(hdr);
    if (!buf) {
        return -1;
    }
    // R50-12: 与 GetFile/ReadLoads/ReadElfHeader 对齐——PROCESS 块类型校验，
    // 损坏 acore 把块类型写错时 fail-closed 而非按定长硬读。
    if (hdr.block_type != BLOCK_TYPE_PROCESS) {
        error("expected PROCESS block, got type %u (acore corrupt)", hdr.block_type);
        return -1;
    }
    if (hdr.prev_cont != 0) {
        error("PROCESS metadata starts with a continuation block (acore corrupt)");
        return -1;
    }

    // process data
    int u = 0;
    int thread_num = 0;
    {
        // R50-1: PROCESS 块读返回未检查——块解压不足 12 字节时 u 保留陈旧值，
        // _pid/_core_pid/thread_num 全错，decompress 带错误计数继续。fail-closed。
        if (buf->Read((char*)&u, sizeof(u)) != (int)sizeof(u)) {
            error("PROCESS block too short (acore corrupt)");
            return -1;
        }
        _pid = u;
        if (buf->Read((char*)&u, sizeof(u)) != (int)sizeof(u)) {
            error("PROCESS block too short (acore corrupt)");
            return -1;
        }
        _core_pid = u;
        if (buf->Read((char*)&u, sizeof(u)) != (int)sizeof(u)) {
            error("PROCESS block too short (acore corrupt)");
            return -1;
        }
        thread_num = u;

        // The writer has always appended these legacy informational fields to
        // the PROCESS block. They are not used when rebuilding the ELF core,
        // but consuming their exact layout prevents a corrupt block from
        // smuggling unversioned metadata into an otherwise accepted acore.
        struct timeval tv;
        struct timezone tz;
        char uname_buf[512];
        if (buf->Read((char*)&tv, sizeof(tv)) != (int)sizeof(tv) ||
            buf->Read((char*)&tz, sizeof(tz)) != (int)sizeof(tz) ||
            buf->Read(uname_buf, sizeof(uname_buf)) != (int)sizeof(uname_buf)) {
            error("PROCESS block has an unexpected payload length (acore corrupt)");
            return -1;
        }
        if (_acore_version >= 5) {
            uint32_t crash_sig = 0;
            if (buf->Read((char*)&_process._uid, sizeof(_process._uid)) !=
                    (int)sizeof(_process._uid) ||
                buf->Read((char*)&_process._gid, sizeof(_process._gid)) !=
                    (int)sizeof(_process._gid) ||
                buf->Read((char*)&crash_sig, sizeof(crash_sig)) !=
                    (int)sizeof(crash_sig)) {
                error("PROCESS block lacks v5 credentials (acore corrupt)");
                return -1;
            }
            if (crash_sig != 0 && !is_core_dump_signal((int)crash_sig)) {
                error("PROCESS block has invalid crash signal %u", crash_sig);
                return -1;
            }
            _crash_sig = (int)crash_sig;
            _process._credentials_valid = true;
        } else {
            _crash_sig = 0;
            _process._credentials_valid = false;
        }
        if (buf->Size() != 0) {
            error("PROCESS block has an unexpected payload length (acore corrupt)");
            return -1;
        }
    }
    if (_pid <= 0) {
        error("invalid process pid %d in acore", _pid);
        return -1;
    }
    info("pid = %d", _pid);
    info("thread_num = %d", thread_num);

    _process._cmdline = in.GetFile();
    _process._auxv = in.GetFile();
    _process._maps = in.GetFile();
    _process._environ = in.GetFile();
    _process._io = in.GetFile();
    _process._limits = in.GetFile();
    _process._stat = _acore_version >= 6 ? in.GetFile() : NULL;

    // b23/b43 (Codex review): 任一必需 proc 文件读失败（截断 size 前缀、超 64MB
    // 上限、小 size、块类型不符）都是损坏 acore——fail-closed，而非带 NULL/部分
    // 数据继续解析，让后续 ParseAll/fill_* 消费堆垃圾。
    if (!_process._cmdline || !_process._auxv || !_process._maps ||
        !_process._environ || !_process._io || !_process._limits ||
        (_acore_version >= 6 && !_process._stat)) {
        error("a required proc file failed to load, acore corrupt");
        return -1;
    }
    const struct {
        ProcFile *file;
        ProcType type;
        const char *name;
    } process_files[] = {
        { _process._cmdline, PROC_TYPE_CMDLINE, "cmdline" },
        { _process._auxv, PROC_TYPE_AUXV, "auxv" },
        { _process._maps, PROC_TYPE_MAPS, "maps" },
        { _process._environ, PROC_TYPE_ENVIRON, "environ" },
        { _process._io, PROC_TYPE_IO, "io" },
        { _process._limits, PROC_TYPE_LIMITS, "limits" },
        { _process._stat, PROC_TYPE_STAT, "stat" },
    };
    for (const auto& entry : process_files) {
        if (!entry.file && _acore_version < 6 && entry.type == PROC_TYPE_STAT) {
            continue;
        }
        if (entry.file->f_type != entry.type ||
            entry.file->f_pid != (uint32_t)_pid) {
            error("proc file %s identity mismatch (type %u, pid %u), acore corrupt",
                  entry.name, entry.file->f_type, entry.file->f_pid);
            return -1;
        }
    }

    // B23: thread_num 来自损坏 acore 可为任意值；限定上限避免无限/超长循环。
    // b23/b43 (Codex review): 100 万线程上限仍允许数 GiB 分配（每 ThreadData
    // 约 3KB 寄存器 + stat，可压缩到极小）。降到 2^17，并加线程块累计未压缩
    // 字节预算兜底——构造的线程块无法无限放大内存。
    if (thread_num <= 0 || thread_num > 131072) {
        error("implausible thread_num %d, acore corrupt", thread_num);
        return -1;
    }
    // 线程元数据累计未压缩字节上限（x64 每线程 ~3.5KB，131072 线程 ≈ 460MB）
    const size_t THREAD_META_MAX = 512*1024*1024;
    size_t meta_bytes = 0;
    std::set<uint32_t> thread_ids;

    for (int i=0; i<thread_num; i++) {
        ThreadData td;
        td._arch = _arch;

        buf = in.ReadBlock(hdr);
        if (!buf) {
            // 损坏 acore 提前结束。b43 (Codex review): 线程块缺失是截断，不能
            // break 后带不完整线程集当成功返回——fail-closed 返回 -1，让
            // decompress 统一清理并报错。
            error("thread block %d missing (truncated acore)", i);
            return -1;
        }
        // R50-12: 与 GetFile 对齐——THREAD 块类型校验，损坏 acore 把块类型
        // 写错时 fail-closed 而非按定长硬读。
        if (hdr.block_type != BLOCK_TYPE_THREAD) {
            error("expected THREAD block %d, got type %u (acore corrupt)", i, hdr.block_type);
            return -1;
        }
        if (hdr.prev_cont != 0) {
            error("THREAD block %d starts with a continuation flag (acore corrupt)", i);
            return -1;
        }

        meta_bytes += buf->Length();
        if (meta_bytes > THREAD_META_MAX) {
            error("thread metadata %zu exceeds budget, acore corrupt", meta_bytes);
            return -1;
        }

        // R50-1: 线程块字段读返回未检查——块解压不足时 td 靠 memset 全零仍被
        // push，产出全零寄存器/pid 的线程。fail-closed。
        bool tb_ok = (buf->Read((char*)&td._pid, sizeof(td._pid)) == (int)sizeof(td._pid));

        if (_arch == ARCH_X64) {
            tb_ok = tb_ok &&
                buf->Read((char*)&td._regs, sizeof(td._regs.x64)) == (int)sizeof(td._regs.x64) &&
                buf->Read((char*)&td._fpregs, sizeof(td._fpregs.x64)) == (int)sizeof(td._fpregs.x64) &&
                buf->Read((char*)&td._siginfo, sizeof(td._siginfo)) == (int)sizeof(td._siginfo) &&
                buf->Read((char*)&td._xstate, sizeof(td._xstate.x64)) == (int)sizeof(td._xstate.x64);
        } else if (_arch == ARCH_AARCH64) {
            tb_ok = tb_ok &&
                buf->Read((char*)&td._regs, sizeof(td._regs.arm64)) == (int)sizeof(td._regs.arm64) &&
                buf->Read((char*)&td._fpregs, sizeof(td._fpregs.arm64)) == (int)sizeof(td._fpregs.arm64) &&
                buf->Read((char*)&td._siginfo, sizeof(td._siginfo)) == (int)sizeof(td._siginfo);
        }

        // v3: THREAD 块尾部——FP 有效位(1) + SigPnd/SigBlk(8+8)；v2 及更早无
        // （默认 fp 有效，掩码由 fill_prstatus 回退 stat 字段）。
        if (_acore_version >= 3) {
            char fv = 0;
            tb_ok = tb_ok &&
                buf->Read((char*)&fv, 1) == 1 &&
                buf->Read((char*)&td._sigpend, sizeof(td._sigpend)) == (int)sizeof(td._sigpend) &&
                buf->Read((char*)&td._sighold, sizeof(td._sighold)) == (int)sizeof(td._sighold);
            if (tb_ok && fv != 0 && fv != 1) {
                error("thread block %d has invalid FP-valid value %d (acore corrupt)",
                      i, (int)(unsigned char)fv);
                return -1;
            }
            td._fp_valid = (fv != 0);
            td._signal_masks_valid = 1;
        } else {
            td._fp_valid = 1;
            td._signal_masks_valid = 0;
        }

        if (!tb_ok) {
            error("thread block %d too short (acore corrupt)", i);
            return -1;
        }
        if (buf->Size() != 0) {
            error("thread block %d has %zu trailing bytes (acore corrupt)",
                  i, buf->Size());
            return -1;
        }
        if (td._siginfo.si_signo < 0 || td._siginfo.si_signo >= NSIG) {
            error("thread block %d has invalid signal %d (acore corrupt)",
                  i, td._siginfo.si_signo);
            return -1;
        }
        if (_acore_version >= 5) {
            // v5 PROCESS metadata is authoritative for PRSTATUS. Only the first
            // thread (the serialized crash TID) must carry matching raw siginfo;
            // the remaining threads normally retain their ptrace stop siginfo.
            if (_crash_sig != 0 && i == 0 &&
                td._siginfo.si_signo != _crash_sig) {
                error("crashing thread signal %d disagrees with crash signal %d",
                      td._siginfo.si_signo, _crash_sig);
                return -1;
            }
            td._prstatus_signal = _crash_sig;
        } else {
            // Legacy archives have no process-level crash field. Preserve crash
            // cores written by older Arthur versions without treating their
            // attach-generated SIGSTOP as a process termination.
            td._prstatus_signal = is_core_dump_signal(td._siginfo.si_signo)
                ? td._siginfo.si_signo : 0;
        }
        if (td._pid == 0 || !thread_ids.insert(td._pid).second) {
            error("invalid or duplicate thread id %u in acore", td._pid);
            return -1;
        }

        td._stat = in.GetFile();
        // R50-1: 线程 stat 的 GetFile 失败（NULL）未检查——后续 ProcStat(NULL)/
        // fill_prstatus 全零。fail-closed。
        if (!td._stat) {
            error("thread %d stat missing (acore corrupt)", td._pid);
            return -1;
        }
        if (td._pid == 0 || td._stat->f_type != PROC_TYPE_STAT ||
            td._stat->f_pid != td._pid) {
            error("thread %u stat metadata identity mismatch (type %u, pid %u), acore corrupt",
                  td._pid, td._stat->f_type, td._stat->f_pid);
            free(td._stat);
            return -1;
        }
        // R50-7: 线程 stat 的 GetFile 上限 64MB，且不计入上方 THREAD_META_MAX 预算
        //（只累加 THREAD 块长度）——构造 acore 可让每线程 stat 都接近 64MB，
        // 131072 线程 ≈ 8TB 堆分配（LZ4 高压缩比重复数据使文件本身很小）。
        // 把 stat 序列化大小也计入预算，超限即拒。
        meta_bytes += td._stat->Size();
        if (meta_bytes > THREAD_META_MAX) {
            // b116 (Codex B116 review): 超预算时 td 尚未 push_back 进 _threads，
            // cleanup_decompress 只释放已登记线程的 stat——当前 _stat 需显式释放，
            // 否则每次失败泄漏 ≤64MB（同进程重复 decompress 会累积）。
            error("thread metadata %zu exceeds budget (with stat), acore corrupt", meta_bytes);
            free(td._stat);
            return -1;
        }
        _process._threads.push_back(td);
        info("thread: %d", td._pid);
    }

    if (_acore_version < 6 && !thread_ids.count((uint32_t)_pid)) {
        error("thread metadata does not contain process leader %d", _pid);
        return -1;
    }

    return 0;
}

static int expected_load_phdrs(ProcMaps& maps, std::vector<Elf64_Phdr>& phdrs,
                               size_t& total_bytes)
{
    phdrs.clear();
    total_bytes = 0;
    for (const MemRegion& region : maps) {
        Elf64_Phdr ph = {};
        ph.p_type = PT_LOAD;
        ph.p_align = 1;
        ph.p_flags = region.perms;
        ph.p_vaddr = region.start_addr;
        ph.p_memsz = region.end_addr - region.start_addr;
        // Preserve every VMA in the offline address-space layout. Linux core
        // files represent unreadable/filtered mappings with p_filesz=0 rather
        // than omitting the PT_LOAD entirely.
        // Only a true PROT_NONE VMA has no captured bytes. Linux permits
        // write-only mappings, and executable file mappings can contain
        // runtime-private modifications beyond their first page.
        ph.p_filesz = region.perms != 0 ? ph.p_memsz : 0;
        ph.p_offset = total_bytes;
        if (ph.p_filesz > (uint64_t)SSIZE_MAX - total_bytes) {
            error("maps-derived LOAD data exceeds supported size");
            return -1;
        }
        total_bytes += (size_t)ph.p_filesz;
        phdrs.push_back(ph);
    }
    return 0;
}

int Coredump::WriteLoads(Lz4Stream& out, pid_t pid, ProcMaps& maps)
{
    std::vector<Elf64_Phdr> expected_phdrs;
    size_t expected_bytes = 0;
    if (expected_load_phdrs(maps, expected_phdrs, expected_bytes) != 0 ||
        expected_phdrs.empty()) {
        error("maps contains no representable readable LOAD segments");
        return -1;
    }

    int fd;
    {
        char fmem[128];
        snprintf(fmem, 128, "/proc/%u/mem", pid);
        fd = open(fmem, O_RDONLY);
        if (fd < 0) {
            return -1;
        }
    }

    if (out.SetBlock(BLOCK_TYPE_LOADS) != 0) {
        error("set LOADS block type failed");
        close(fd);
        return -1;
    }

    // slot for loads size
    size_t file_size = 0, mem_size = 0;
    bool saw_eof = false;

#if 0
    long loads_slot = out.Tell();
    out.WriteRaw((const char *)&file_size, sizeof(file_size));
#endif

    // mem regions 
    std::vector<char> buf(BUFFER_SIZE);
    size_t load_index = 0;
    for (auto &r : maps) {
        if (load_index >= expected_phdrs.size()) {
            error("internal LOAD derivation mismatch");
            close(fd);
            return -1;
        }
        Elf64_Phdr ph = expected_phdrs[load_index++];
        uint64_t end_addr = r.start_addr + ph.p_filesz;
    
        // write memory dump
        size_t size = 0;
        for (uint64_t addr = r.start_addr; addr < end_addr; addr += buf.size()) {
            int req = MIN((end_addr - addr), buf.size());
            // b93 (Codex B93 review): 短读（0<len<req）时按整缓冲推进会把
            // [addr+len, addr+req) 静默跳过，后续读到的数据在 core 中映射到更低的
            // 虚拟地址（数据错位 + 洞）。改为循环读满 req（处理 EINTR）；读不动
            // （EOF/硬错误，如 R50-1 观测的栈页 pread EIO）时零填充剩余字节保持
            // PT_LOAD 布局连续，不静默错位。目标已停靠时短读少见，零填充比整个
            // dump fail-closed 更不破坏真实采集。
            ssize_t got = 0;
            while (got < req) {
                ssize_t len = pread(fd, buf.data() + got, req - got, addr + got);
                if (len < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    warn("pread mem(%lx) failed(%d); zero-filling %zd bytes",
                         addr + got, errno, req - got);
                    memset(buf.data() + got, 0, req - got);
                    break;
                }
                if (len == 0) {
                    warn("pread mem(%lx) EOF after %zd of %d bytes; zero-filling",
                         addr, got, req);
                    memset(buf.data() + got, 0, req - got);
                    saw_eof = true;
                    break;
                }
                got += len;
            }
            mem_size += got;
            if (saw_eof) {
                error("memory source for %d reached EOF during dump; refusing partial core", pid);
                close(fd);
                return -1;
            }
            if (got < req) {
                got = req;   // 零填充已补满，写循环按整块输出保持布局连续
            }

            for (ssize_t i=0; i<got; i+= BLOCK_SIZE) {
                size_t j = MIN(got - i, BLOCK_SIZE);
                // B68: WriteBlock 失败（压缩错误）返回 -1；直接 `size += rc` 会让
                // size_t 下溢成巨大值，ph.p_filesz 声明巨额 → 解压被一致性检查拒。
                int wrc = out.WriteBlock(buf.data() + i, j, BLOCK_TYPE_LOADS);
                if (wrc < 0) {
                    error("write loads block failed (%d)", wrc);
                    close(fd);
                    return -1;
                }
                size += wrc;
            }

            // update file size
            dprint("read %lu bytes", got);

        } // for addr 
 
        if (size != ph.p_filesz) {
            error("captured LOAD size %zu differs from maps-derived size %lu",
                  size, (unsigned long)ph.p_filesz);
            close(fd);
            return -1;
        }
        //printf("%lx : %ld %ld\n", ph.p_vaddr, ph.p_memsz, ph.p_filesz);
        _phdrs.emplace_back(ph);

        // update memory size
        file_size += size;

    } // for maps

    if (load_index != expected_phdrs.size() || file_size != expected_bytes) {
        error("captured LOAD layout differs from maps-derived layout");
        close(fd);
        return -1;
    }

#if 0
    pos_t saved_tail = out.tellp();
    out.seekp(loads_slot);
    out.write_raw((const char*)&file_size, sizeof(file_size));
    out.seekp(saved_tail);
    printf("compressed %lu into %lu Bytes, ratio %0.2f%\n", mem_size, file_size, ((double)file_size / mem_size * 100));
#endif

    // B169: pread 全部失败（进程在 dump 窗口被外部 SIGKILL/看门狗杀掉、mm 已拆除）
    // 时 mem_size==0——原实现无条件 return 0，产出"寄存器抓到、内存全缺"的假成功
    // core（gdb 能加载但 Cannot access memory）。单 region 的 EIO（栈 guard 页）仍
    // 只告警成洞（合法快照常见），只有整块内存都没读到才 fail-closed。真实进程恒有
    // 可读映射（栈/堆），mem_size==0 只来自进程消失。
    if (saw_eof || mem_size == 0) {
        error("no memory readable for %d (process vanished during dump?)", pid);
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

/* write elf header to stream
 */
int Coredump::WriteElfHeader(Lz4Stream& out)
{
    // R50-13: e_phnum 是 uint16_t，>0xFFFF 个 phdr 时静默截断（对 65536 取模），
    // gdb 读到的段数错误、大部分 LOAD 段丢失，core 静默损坏无报错。高 vm.max_map_count
    // 生产环境（≥1M）可读 VMA 数可超 65535。未实现 PN_XNUM 扩展编号，fail-closed。
    // b128 (Codex B128 review): 0xFFFF 是 ELF PN_XNUM 保留哨兵，真实数量必须写进
    // section 0 的 sh_info（Arthur 无该 section），恰 65535 个也须拒绝——用 >= 。
    if (_phdrs.size() >= 0xFFFF) {
        error("phdr count %zu exceeds uint16 e_phnum limit (acore too fragmented)",
              _phdrs.size());
        return -1;
    }
    Elf64_Ehdr ehdr;
    ehdr.e_phnum = _phdrs.size();

    // hard coded the 'machine' by platform
#ifdef __aarch64__
    ehdr.e_machine = EM_AARCH64;
#else
    ehdr.e_machine = EM_X86_64;
#endif

    if (out.SetBlock(BLOCK_TYPE_ELF) != 0) {
        error("set ELF block type failed");
        return -1;
    }
    // R50-1: ehdr/phdr 的 Write 返回原未检查——块满时隐式 Flush 失败（磁盘满）会
    // 丢该段数据，最终 Flush 若恢复成功则返回 0，但 ELF 块 phdr 有空洞。
    if (out.Write((const char*)&ehdr, sizeof(ehdr)) < 0) {
        error("write elf ehdr failed (disk full?)");
        return -1;
    }

    for (auto& phdr : _phdrs) {
        if (out.Write((const char*)&phdr, sizeof(phdr)) < 0) {
            error("write elf phdr failed (disk full?)");
            return -1;
        }
    }

    // B69: 磁盘满时 Flush 的 Compress 失败返回 -1；原实现忽略 → ELF 块缺失的
    // acore 静默产出，解压报 "elf block missing"。传播错误。
    if (out.Flush() < 0) {
        error("write elf block failed (disk full?)");
        return -1;
    }
    return 0;
}

int Coredump::WriteElfHeader(FILE* fout)
{
    int rc = 0;
    ssize_t len;
    // R50-13: 同压缩侧——>0xFFFF 个 phdr 时 e_phnum 静默截断，gdb 读段数错误。
    // b128: PN_XNUM 保留值，>= 0xFFFF 即拒（同压缩侧）。
    if (_phdrs.size() >= 0xFFFF) {
        error("phdr count %zu exceeds uint16 e_phnum limit (core too fragmented)",
              _phdrs.size());
        return -1;
    }
    Elf64_Ehdr ehdr;

    ehdr.e_machine = _ehdr.e_machine;
    ehdr.e_phnum = _phdrs.size();

    len = fwrite(&ehdr, 1, sizeof(ehdr), fout);
    // B54: 输出磁盘满时 fwrite 短写，原 assert 直接 abort。
    if (len != (ssize_t)sizeof(ehdr)) {
        error("write elf header failed (%ld != %zu), disk full?", len, sizeof(ehdr));
        return -1;
    }
    rc += len;

    for (auto& _phdr : _phdrs) {
        Elf64_Phdr phdr = _phdr;
        if (phdr.p_type == PT_LOAD) {
            uint64_t adjusted_offset = 0;
            if (_offset_load < 0 ||
                __builtin_add_overflow(phdr.p_offset, (uint64_t)_offset_load,
                                       &adjusted_offset)) {
                error("LOAD file offset overflows ELF64 range");
                return -1;
            }
            phdr.p_offset = adjusted_offset;
        }
        len = fwrite(&phdr, 1, sizeof(phdr), fout);
        if (len != (ssize_t)sizeof(phdr)) {
            error("write phdr failed (%ld != %zu), disk full?", len, sizeof(phdr));
            return -1;
        }
        rc += len;
    }

    return rc; 
}

int Coredump::WriteTailMark(Lz4Stream& out)
{
    BlockHeader mark = BlockHeader::TailMark();
    // B70: 磁盘满时尾标写失败 → acore 无结束标记，解压读 EOF 报截断。
    if (out.WriteRaw((const char*)&mark, sizeof(mark)) != (int)sizeof(mark)) {
        error("write tail mark failed (disk full?)");
        return -1;
    }
    return 0;
}

int Coredump::ReadElfHeader(Lz4Stream& in, size_t max_phdrs)
{
    int rc;
    BlockHeader hdr;
    Block* block = in.ReadBlock(hdr);
    if (!block) {
        // 损坏 acore：ELF 块缺失
        error("elf block missing (truncated acore)");
        return -1;
    }
    // B160: 首个 ELF 块的 block_type 必须校验（续块已校验，B127 的"ReadElfHeader
    // 都校验块类型"对首块不成立）——构造 acore 把 LOADS 后的块类型写成 THREAD 等
    // 非 ELF，解压字节仍可凑成合法 Elf64_Ehdr+PT_LOAD 过 e_machine/PT_LOAD/p_offset
    // 校验，decompress 产出攻击者控制的 ELF 元数据 core 且返回 0（实证）。fail-closed。
    if (hdr.block_type != BLOCK_TYPE_ELF) {
        error("first ELF block type %u (not ELF), acore corrupt", hdr.block_type);
        return -1;
    }
    if (hdr.prev_cont != 0) {
        error("first ELF block is marked as a continuation (acore corrupt)");
        return -1;
    }

    rc = block->Read((char*)&_ehdr, sizeof(_ehdr));
    if (rc != sizeof(_ehdr)) {
        error("decode ehdr failed.");
        return -1;
    }
    // R50-23 (defect 3): acore 头 arch 与 ELF 块 e_machine 一致性校验——合法 acore
    // 两者恒一致（写侧均由编译平台决定）；损坏/恶意 acore 可构造为 arch=AARCH64 但
    // e_machine=EM_X86_64，ReadMeta 按 arm64 读、输出 core 却标 x86 → gdb 按 x86 解析
    // 0x188 prstatus 全错。fail-closed。
    if ((_arch == ARCH_X64 && _ehdr.e_machine != EM_X86_64) ||
        (_arch == ARCH_AARCH64 && _ehdr.e_machine != EM_AARCH64)) {
        error("acore arch %d mismatches ELF machine %u (acore corrupt)",
              _arch, _ehdr.e_machine);
        return -1;
    }
    if (_ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        _ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        _ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        _ehdr.e_ident[EI_MAG3] != ELFMAG3 ||
        _ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        _ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
        _ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
        _ehdr.e_type != ET_CORE || _ehdr.e_version != EV_CURRENT ||
        _ehdr.e_phoff != sizeof(Elf64_Ehdr) ||
        _ehdr.e_ehsize != sizeof(Elf64_Ehdr) ||
        _ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
        _ehdr.e_shoff != 0 || _ehdr.e_shnum != 0) {
        error("invalid embedded ELF header layout (acore corrupt)");
        return -1;
    }

    while (block) {

        while (block->Size() > 0) {
            // R50-7: 构造 acore 可用高压缩比的重复 phdr 数据在拒绝前撑爆 _phdrs
            //（每 ELF 块 64KB/56B ≈ 1170 个 phdr；LZ4 重复块在文件里可极小）。
            // 预算上限（maps 条目 + 1 note）在读入时强制执行，不做事后检查。
            if (_phdrs.size() >= max_phdrs) {
                error("elf phdr count %zu exceeds budget %zu (acore corrupt)",
                      _phdrs.size() + 1, max_phdrs);
                return -1;
            }
            Elf64_Phdr phdr;
            rc = block->Read((char*)&phdr, sizeof(phdr));
            if (rc != sizeof(phdr)) {
                error("decode phdr failed.");
                return -1;
            }
            // B154: 写侧 WriteLoads 只产出 PT_LOAD phdr——非 PT_LOAD 必是损坏/
            // 恶意 acore。不拒绝时 decompress 把其 p_offset（不加 _offset_load）
            // 当绝对偏移写进输出 core，gdb 解析垃圾段拒绝整个 core（实证
            // "not a core dump"）。fail-closed。
            if (phdr.p_type != PT_LOAD) {
                error("elf phdr type %u (not PT_LOAD), acore corrupt", phdr.p_type);
                return -1;
            }
            _phdrs.push_back(phdr);
        }

        rc = in.Peek((char*)&hdr, sizeof(hdr));
        if (rc < 0) {
            error("failed to inspect ELF continuation block");
            return -1;
        }
        if (rc != sizeof(hdr)) {
            break;
        }
        if (hdr.block_type != BLOCK_TYPE_ELF) {
            break;
        }
        block = in.ReadBlock(hdr);
        if (!block) {
            // b46 (Codex review): Peek 已看到后续 ELF 块，但 ReadBlock 因截断/
            // 解压失败返回 NULL——结束循环当成功会产出残缺 core。fail-closed。
            error("elf continuation block truncated (acore corrupt)");
            return -1;
        }
    }

    dprint("phdr : %d, %d", _ehdr.e_phnum, _phdrs.size());
    return 0;
}

ssize_t Coredump::ReadLoads(Lz4Stream& in, FILE* fout, size_t expected_bytes)
{
    int rc;
    //size_t file_size = 0;
    size_t loads_size = 0;

#if 0
    Block buf;
    char *pbuf = (char *)buf.rdbuf();
    in.ReadRaw((char *)&loads_size, sizeof(loads_size));
    printf("loads size %lu\n", loads_size);
#endif

    BlockHeader hdr;
    for (;;) {
        // R50-15 (T2): 块头在 1~2 字节处截断时 Peek 返回正数短读（rc>0），
        // 旧 `rc <= 0` 不 break，读垃圾 block_type——若垃圾恰为 LOADS 会报错，
        // 否则静默当 LOADS 段结束（截断被下游捕获）。统一严格 == sizeof。
        rc = in.Peek((char*)&hdr, sizeof(hdr));
        if (rc < 0) {
            error("failed to inspect LOADS continuation block");
            return -1;
        }
        if (rc != (int)sizeof(hdr)) {
            break;
        }

        if (hdr.block_type != BLOCK_TYPE_LOADS) {
            break;
        }

        Block *block = in.ReadBlock(hdr);
        if (!block) {
            // 截断在 LOADS 块数据中间：Peek 读到头、ReadBlock 读数据失败。
            // B54: 原 assert(block) 使损坏 acore 直接 abort（NDEBUG 下 NULL 解引用）。
            error("loads block read failed (acore truncated)");
            return -1;
        }

        if (loads_size > expected_bytes ||
            block->Size() > expected_bytes - loads_size) {
            error("LOADS stream exceeds maps-derived budget %zu (acore corrupt)",
                  expected_bytes);
            return -1;
        }

        size_t len = fwrite(block->rBuf(), 1, block->Size(), fout);
        if (len != block->Size()) {
            error("write loads block failed (%lu != %lu)", len, block->Size());
            return -1;
        }

        //file_size += hdr.size;
        if (block->Size() > (size_t)SSIZE_MAX - loads_size) {
            error("LOADS stream exceeds ssize_t accounting range");
            return -1;
        }
        loads_size += block->Size();
    }

    //dprint("Readloads: file(%lu), data(%lu)", file_size, loads_size);
    return loads_size;
}

int Coredump::GenerateNotes()
{
    int rc = 0;

    // B37: fill_* 失败（损坏 acore 缺元数据）时 note 的 _data 为 NULL，
    // 直接 push 会让 fwrite(NULL) 崩溃。只在成功时加入。
    // b47 (Codex review): "返回 0" 不等价于 "payload 已初始化"——纵深防护，
    // 只接受 fill 成功且 _data 非空（Note::_size 已由构造器初始化为 0）。
    auto add_note = [&](Note* nt, int fill_rc, bool required) -> bool {
        if (fill_rc != 0 || nt->_data == NULL) {
            error("%s note fill failed", required ? "required" : "optional");
            delete nt;
            return !required;
        }
        _notes.push_back(nt);
        return true;
    };

    // NT_PRPSINFO (prpsinfo structure)
    Note *nt = new Note(NT_PRPSINFO);
    if (!add_note(nt, nt->fill_prpsinfo(_process, _pid, _crash_sig != 0), true)) {
        return -1;
    }

    // NT_AUXV (auxiliary vector)
    nt = new Note(NT_AUXV);
    if (!add_note(nt, nt->fill_auxv(_process), true)) {
        return -1;
    }

    // NT_FILE (mapped files)
    nt = new Note(NT_FILE);
    if (!add_note(nt, nt->fill_file(_process), true)) {
        return -1;
    }

    bool siginfo_added = false;
    for (auto& i : _process._threads) {
        // NT_PRSTATUS (prstatus structure)
        nt = new Note(NT_PRSTATUS);
        if (!add_note(nt, nt->fill_prstatus(i), true)) {
            return -1;
        }

        // Do not publish zero-filled optional register notes after ptrace
        // explicitly reported that the FP/extended state was unavailable.
        if (i._fp_valid) {
            nt = new Note(NT_FPREGSET);
            add_note(nt, nt->fill_fpregset(i), false);

            if (_arch == ARCH_X64) {
                nt = new Note(NT_X86_XSTATE);
                add_note(nt, nt->fill_x86_xstate(i), false);
            }
        }

        // NT_SIGINFO is a process-level core note. The crash thread is first
        // in monitor archives, so one note also preserves the relevant siginfo.
        if (!siginfo_added) {
            nt = new Note(NT_SIGINFO);
            if (!add_note(nt, nt->fill_siginfo(i), true)) {
                return -1;
            }
            siginfo_added = true;
        }
    }

    for (Note *nt : _notes) {
        // b133 (Codex B133 review): Note::_size 已是 size_t，%d/%x 与实参类型不匹配
        // （-DDEBUG 时变参 UB）。改 %zu/%zx。
        dprint(" [%x] %zu 0x%zx", nt->_type, nt->_size, nt->_size);
        if (nt->_size > (size_t)(INT_MAX - rc)) {
            error("combined ELF notes exceed supported size");
            return -1;
        }
        rc += (int)nt->_size;
    }

    return rc;
}

int Coredump::takememspace()
{
    // Historical code prefaulted 2 MiB on the caller's stack. It did not
    // reserve memory for later operations and crashed valid low-stack targets
    // before capture began. Large I/O buffers now have explicit heap storage.
    return 0;
}

/* generate() is similar to gcore does.
 * 1) stop all threads.
 * 2) generate corefile.
 */
int Coredump::generate(const char *corefile)
{
    // 每次采集前清空跨调用累积的 _phdrs（SIGUSR1 forkcore_m 后再崩溃会写陈旧 phdr）
    _phdrs.clear();
    _core_pid = 0;
    _crash_sig = 0;
    _monitor_relay_signals.clear();
    int rc = 0;
    const std::string final_corefile(corefile);
    std::string temp_corefile;
    AtomicOutputState output_state;
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = open_atomic_lz4(out, final_corefile.c_str(), temp_corefile,
                         output_state);
    if (rc < 0) {
        return -1;
    }
    corefile = temp_corefile.c_str();

    // write acore
    // R50-1: WriteFileHeader 返回未检查——磁盘满时缺 8 字节头的 acore 静默产出，
    // 解压报 "magic failed"。
    if (WriteFileHeader(out) != 0) {
        error("write acore header failed");
        out.Close();
        unlink(corefile);
        return -1;
    }

    // attach main thread
    int leader_relay_signal = 0;
    if (pt_attach(_pid, &leader_relay_signal) != 0) {
        // 目标不存在/无权限：干净报错而非深层 assert 崩溃
        // b41 (Codex review): 只依赖析构关文件会留下 8 字节空 acore；显式清理，
        // 避免无效/无权限 pid 产出误导性文件。
        error("cannot attach to process %d", _pid);
        out.Close();
        unlink(corefile);
        return -1;
    }
    if (leader_relay_signal != 0) {
        _monitor_relay_signals[_pid] = leader_relay_signal;
    }

    auto detach_collected_threads = [&]() -> int {
        int detach_rc = 0;
        for (pid_t tid : _process._thrd_pid) {
            std::map<pid_t, int>::const_iterator pending =
                _monitor_relay_signals.find(tid);
            int relay = pending == _monitor_relay_signals.end() ? 0 : pending->second;
            if (pt_detach(tid, relay) != 0 && errno != ESRCH) {
                detach_rc = -1;
            }
        }
        _process._thrd_pid.clear();
        _monitor_relay_signals.clear();
        return detach_rc;
    };
    // get all threads pid（attach 全部非主线程，剔除已退出的）
    // B77: collect_threads 失败（opendir / 非 ESRCH attach 错误）时 fail-closed。
    // R50-6: leader 已 attach（SIGSTOP）；失败须 detach 已 attach 线程，
    // 否则目标冻结（内核自动 detach 不恢复 TASK_STOPPED）。
    if (collect_threads(_pid) != 0) {
        error("failed to collect threads of %d", _pid);
        detach_collected_threads();
        out.Close();
        unlink(corefile);
        return -1;
    }

    ProcMaps maps;
    // N4: WriteProcessMeta 失败（/proc 读失败）时继续写会让 acore 缺进程元数据，
    // 解压错位；直接失败。
    if (WriteProcessMeta(out, maps) != 0) {
        error("write process meta failed");
        // R50-1: 失败路径残留部分 acore + 已 attach 线程未 detach。清理并还原。
        detach_collected_threads();
        out.Close();
        unlink(corefile);
        return -1;
    }
    // handle  leader first and then rest
    // R50-1: WriteThreadMeta 现在会因写失败返回 -1；忽略则线程块缺失仍继续
    // LOADS/ELF → 坏 acore。检查并清理部分产物。
    if (WriteThreadMeta(out, _pid, true) != 0) {
        error("write leader thread meta failed");
        // B178: 同函数其余失败路径全部 detach——缺 detach 时已 attach 线程（含 leader）
        // 残留 PT_PTRACED+SIGSTOP，arthur 退出后内核自动 detach 不恢复 TASK_STOPPED，
        // 目标永久冻结（磁盘满等 WriteThreadMeta 失败是 B64-B70 同触发类）。
        detach_collected_threads();
        out.Close();
        unlink(corefile);
        return -1;
    }
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == _pid)
            continue;

        if (WriteThreadMeta(out, tid) != 0) {
            error("write thread meta of %d failed", tid);
            // B178: 兄弟线程 WriteThreadMeta 失败同 leader——必须 detach 已 attach
            // 的兄弟，否则目标冻结（对称遗漏，forkcore 已用 restore 修复）。
            detach_collected_threads();
            out.Close();
            unlink(corefile);
            return -1;
        }
    }
    // write acore
    {
        // B65: WriteLoads 失败（/proc/pid/mem 打不开，dumpable=0/进程消失）时
        // 静默产出无内存的空 core；显式失败。
        if (WriteLoads(out, _pid, maps) != 0) {
            error("failed to dump memory of %d", _pid);
            // R50-1: 清理部分 acore + detach 已 attach 线程。
            detach_collected_threads();
            out.Close();
            unlink(corefile);
            return -1;
        }
        // B69: ELF 块写入失败（磁盘满）时显式失败。
        if (WriteElfHeader(out) != 0) {
            error("failed to write elf header for %d", _pid);
            detach_collected_threads();
            out.Close();
            unlink(corefile);
            return -1;
        }
        // R50-6: 尾标 3 字节短写（磁盘满）时 acore 缺结束标记，解压报 truncated；
        // 与 B68/B69/B70 同类，检查并 fail-closed。
        if (WriteTailMark(out) != 0) {
            error("failed to write tail mark for %d (disk full?)", _pid);
            detach_collected_threads();
            out.Close();
            unlink(corefile);
            return -1;
        }
    }
    // detach all threads
    if (detach_collected_threads() != 0) {
        error("generate: failed to restore every captured thread");
        out.Close();
        unlink(corefile);
        return -1;
    }

    out.PrintStat();
    // b167/b191: Close 返回关闭期错误（ENOSPC），不再静默返回 0
    if (commit_atomic_lz4(out, temp_corefile, final_corefile,
                          output_state) != 0) {
        error("generate: final close failed, core removed");
        unlink(corefile);
        return -1;
    }
    return 0;
}

// A fork child does not preserve captured mappings marked MADV_DONTFORK and
// zeroes mappings marked MADV_WIPEONFORK. Capturing the child's memory while
// retaining the parent's maps would therefore publish a structurally valid
// core with false zero bytes. Inspect smaps while every target thread is
// stopped; if fork cannot preserve all non-PROT_NONE mappings (or smaps cannot be
// verified completely), the caller falls back to a direct parent snapshot.
static bool fork_snapshot_requires_direct_capture(pid_t pid, ProcMaps& maps)
{
    for (const MemRegion& region : maps) {
        if (region.perms != 0 && region.is_shared) {
            info("captured MAP_SHARED mapping found; using direct snapshot");
            return true;
        }
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/smaps", pid);
    FILE *file = fopen(path, "r");
    if (!file) {
        warn("cannot inspect %s; using direct snapshot", path);
        return true;
    }

    char *line = NULL;
    size_t line_cap = 0;
    size_t captured_mappings = 0;
    size_t captured_vmflags = 0;
    bool current_captured = false;
    bool special = false;
    while (getline(&line, &line_cap, file) >= 0) {
        unsigned long long start = 0, end = 0;
        char perms[5] = {0};
        if (sscanf(line, "%llx-%llx %4s", &start, &end, perms) == 3 &&
            start < end && strlen(perms) == 4) {
            current_captured =
                (perms[0] == 'r' || perms[1] == 'w' || perms[2] == 'x');
            if (current_captured) {
                captured_mappings++;
            }
            continue;
        }
        if (!current_captured || strncmp(line, "VmFlags:", 8) != 0) {
            continue;
        }

        captured_vmflags++;
        std::istringstream flags(line + 8);
        std::string flag;
        while (flags >> flag) {
            if (flag == "dc" || flag == "wf") {
                special = true;
                break;
            }
        }
        if (special) {
            break;
        }
    }
    free(line);
    int read_error = ferror(file);
    fclose(file);

    if (special) {
        info("captured MADV_DONTFORK/MADV_WIPEONFORK mapping found; "
             "using direct snapshot");
        return true;
    }
    if (read_error || captured_mappings == 0 ||
        captured_vmflags != captured_mappings) {
        warn("could not verify fork behavior for every captured mapping; "
             "using direct snapshot");
        return true;
    }
    return false;
}

int Coredump::forkcore(const char *corefile, bool sys_core)
{
    // 每次采集前清空跨调用累积的 _phdrs
    _phdrs.clear();
    _core_pid = 0;
    _crash_sig = 0;
    _monitor_relay_signals.clear();

    // B74 (Codex B1 review): mode 2 依赖子进程 `int $3` 触发内核 core dump。
    // RLIMIT_CORE=0（文件型 pattern）或管道型 core_pattern 时不会有可合并的
    // core 文件，arthur 却静默报成功。预检并明确警告。
    if (sys_core) {
        char limpath[64];
        snprintf(limpath, sizeof(limpath), "/proc/%u/limits", _pid);
        FILE* lf = fopen(limpath, "r");
        if (lf) {
            char line[256];
            while (fgets(line, sizeof(line), lf)) {
                if (strncmp(line, "Max core file size", 18) == 0) {
                    unsigned long soft = 0;
                    // 格式: "Max core file size <soft> <hard> <unit>"，数值在第 5 个词
                    if (sscanf(line, "%*s %*s %*s %*s %lu", &soft) == 1 && soft == 0) {
                        warn("mode 2: target RLIMIT_CORE=0, kernel core dump disabled");
                    }
                    break;
                }
            }
            fclose(lf);
        }
        FILE* pf = fopen("/proc/sys/kernel/core_pattern", "r");
        if (pf) {
            char pat[128] = {0};
            if (fgets(pat, sizeof(pat), pf) && pat[0] == '|') {
                warn("mode 2: core_pattern is a pipe (%s), core goes to a helper "
                     "not a regular file", pat);
            }
            fclose(pf);
        }
        // R50-8: `int $3` 触发内核 core 依赖 SIGTRAP 的默认处置。目标若安装了
        // SIGTRAP handler（SigCgt 位 4 置位），fork 子进程继承该 handler，int $3
        // 改走 handler（实证：写 "TRAP!" 后继续执行 diverge 到零填充页 SIGSEGV），
        // 产出垃圾信号/错误的 core 而非目标快照，且 arthur 无法察觉（注入的
        // waitpid 用 NULL status）。B74 同类预检：明确警告。
        {
            char statpath[64];
            snprintf(statpath, sizeof(statpath), "/proc/%u/status", _pid);
            FILE* sf = fopen(statpath, "r");
            if (sf) {
                char line[256];
                while (fgets(line, sizeof(line), sf)) {
                    if (strncmp(line, "SigCgt:", 7) == 0) {
                        unsigned long long sigcgt = 0;
                        if (sscanf(line + 7, "%llx", &sigcgt) == 1 &&
                            (sigcgt & (1ULL << (SIGTRAP - 1)))) {
                            warn("mode 2: target catches SIGTRAP; the forked core "
                                 "child will run its handler instead of dumping a "
                                 "clean snapshot");
                        }
                    } else if (strncmp(line, "SigBlk:", 7) == 0) {
                        // b148 (Codex B148 review): 原 R50-30 (D4) 假定阻塞 SIGTRAP 时
                        // int $3 的 SIGTRAP 挂起、子进程继续到 exit(0) 无 core——但
                        // x86-64/aarch64 的 int $3 是同步硬件异常、强制投递、不受
                        // sigmask 影响（实测阻塞 SIGTRAP 后 int3 仍以 SIGTRAP 终止）。
                        // SigBlk 告警是确定性误报，删除。真正的 core 产出应以子进程
                        // wait status / 实际产物判定。
                        (void)0;
                    }
                }
                fclose(sf);
            }
        }
    }

    /* forkcore using a forked process for large memory dump,
     * and all thread Registers Set is collected by this function.
     * 
     * after the function, there two parts of whole corefile.
     * 1) a corefile.<pid> from forked process, this has the contents of all COW memory files.
     * 2) a metadata.<pid> for orignal process info includes all Registers for all threads.
     *
     * the two parts should be merged by arthur merge command to generate the final corefile.
     */

    int rc;
    const std::string final_corefile(corefile);
    std::string temp_corefile;
    AtomicOutputState output_state;
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = open_atomic_lz4(out, final_corefile.c_str(), temp_corefile,
                         output_state);
    if (rc < 0) {
        return -1;
    }
    corefile = temp_corefile.c_str();

    if (!sys_core) {
        // R50-1: WriteFileHeader 返回未检查——缺头 acore 静默产出。检查并清理。
        if (WriteFileHeader(out) != 0) {
            error("write acore header failed");
            out.Close();
            unlink(corefile);
            return -1;
        }
    }

    TS ts_pause;
    ts_pause.begin();

    // attach main thread
    int leader_relay_signal = 0;
    if (pt_attach(_pid, &leader_relay_signal) != 0) {
        // 目标不存在/无权限：干净报错而非深层 assert 崩溃
        // b41 (Codex review): 失败路径要清理已打开的空 acore（8 字节 header）。
        error("cannot attach to process %d", _pid);
        out.Close();
        unlink(corefile);
        return -1;
    }
    if (leader_relay_signal != 0) {
        _monitor_relay_signals[_pid] = leader_relay_signal;
    }

    // get all threads pid（attach 全部非主线程，剔除已退出的）
    // B77: collect_threads 失败（opendir / 非 ESRCH attach 错误）时 fail-closed。
    // R50-6: leader 已 attach（SIGSTOP）；须还原（detach 兄弟 + 清 TRACEFORK +
    // CONT leader），否则目标冻结。
    if (collect_threads(_pid) != 0) {
        error("failed to collect threads of %d", _pid);
        restore_target_after_fail();
        out.Close();
        unlink(corefile);
        return -1;
    }
    if (_monitor_relay_signals.count(_pid)) {
        error("initial attach of %d intercepted %s; aborting injection and relaying it",
              _pid, strsignal(_monitor_relay_signals[_pid]));
        restore_target_after_fail();
        out.Close();
        unlink(corefile);
        return -1;
    }

    ProcMaps maps;
    // N4: WriteProcessMeta 失败（/proc 读失败）时若继续写，acore 缺进程元数据，
    // 解压端 ReadMeta 的 GetFile 序列错位。fail-closed 还原目标。
    if (WriteProcessMeta(out, maps) != 0) {
        error("write process meta failed");
        restore_target_after_fail();
        out.Close();
        unlink(corefile);
        return -1;
    }
    // handle  leader first and then rest
    // R50-1: WriteThreadMeta 现在会因写失败返回 -1；忽略则线程块缺失仍继续
    // LOADS/ELF → 坏 acore。检查并清理部分产物、还原目标。
    if (WriteThreadMeta(out, _pid, true) != 0) {
        error("write leader thread meta failed");
        restore_target_after_fail();
        out.Close();
        unlink(corefile);
        return -1;
    }
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == _pid) {
            continue;
        }
        if (WriteThreadMeta(out, tid) != 0) {
            error("write thread meta of %d failed", tid);
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
    }

    bool direct_snapshot =
        !sys_core && fork_snapshot_requires_direct_capture(_pid, maps);

    // Fork injection needs these dynamic libc entry points. Static programs and
    // runtimes without usable dynamic symbols are still valid mode-0 targets:
    // every thread is already stopped, so capture the parent directly instead.
    uint64_t r_libc = 0;
    uint64_t r_mmap = 0;
    uint64_t r_munmap = 0;
    uint64_t r_waitpid = 0;
    if (!direct_snapshot) {
        r_libc = get_module_address(_pid, "libc");
        r_mmap = get_remote_sym_address(_pid, r_libc, "mmap");
        r_munmap = get_remote_sym_address(_pid, r_libc, "munmap");
        r_waitpid = get_remote_sym_address(_pid, r_libc, "waitpid");
        if (r_mmap == 0 || r_munmap == 0 || r_waitpid == 0) {
            if (!sys_core) {
                info("target has no usable libc injection symbols; "
                     "using direct snapshot");
                direct_snapshot = true;
            } else {
                error("failed to resolve libc symbols in target (libc base %lx)",
                      r_libc);
                restore_target_after_fail();
                out.Close();
                unlink(corefile);
                return -1;
            }
        }
    }

    if (direct_snapshot) {
        int write_rc = WriteLoads(out, _pid, maps);
        if (write_rc == 0) {
            write_rc = WriteElfHeader(out);
        }
        if (write_rc == 0) {
            write_rc = WriteTailMark(out);
        }
        for (pid_t tid : _process._thrd_pid) {
            std::map<pid_t, int>::const_iterator pending =
                _monitor_relay_signals.find(tid);
            int relay = pending == _monitor_relay_signals.end() ? 0 : pending->second;
            if (pt_detach(tid, relay) != 0 && errno != ESRCH) {
                error("detach direct-snapshot thread %d failed (%s)",
                      tid, strerror(errno));
                write_rc = -1;
            }
        }
        _process._thrd_pid.clear();
        _monitor_relay_signals.clear();
        ts_pause.end();
        if (write_rc != 0) {
            error("direct mode-0 snapshot failed");
            out.Close();
            unlink(corefile);
            return -1;
        }
        info("Process %u paused %0.3f ms (direct fallback).",
             _pid, ts_pause.timediff()*1000);
        out.PrintStat();
        if (commit_atomic_lz4(out, temp_corefile, final_corefile,
                              output_state) != 0) {
            error("forkcore direct fallback: final close failed, core removed");
            unlink(corefile);
            return -1;
        }
        return 0;
    }
 
    // we've injected an 'int 3' in child process, that generates a corefile by kernel.
    // B39: SETOPTIONS 是整体替换——直接设 TRACEFORK 会清掉 monitor_threads
    // 设定的 TRACEEXIT/TRACECLONE，monitor 的退出与新线程跟踪会降级。
    if (!sys_core) {
        // 在持久 _ptrace_options 上叠加 TRACEFORK，避免整体替换清掉
        // TRACEEXIT/TRACECLONE（B39）。
        rc = ptrace(PTRACE_SETOPTIONS, _pid, 0,
                    _ptrace_options | (long)PTRACE_O_TRACEFORK);
        if (rc != 0) {
            // B57: 目标可能在 attach/stop 后退出；fail-closed 还原，不 assert。
            error("set TRACEFORK on %d failed (%s)", _pid, strerror(errno));
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
    }

    info("remote mmap at %lx", r_mmap);
    //info("remote fork at %p", r_fork);
    info("remote waitpid at %lx", r_waitpid);

    // save the program regs
    user_regs64_struct saved_regs;
    // R50-1: getregs 返回未检查——失败时 saved_regs 未初始化，后面 pt_setregs
    // 会把垃圾寄存器写回目标。目标处于 stop 正常不会失败，仍检查以 fail-closed。
    if (pt_getregs(_pid, &saved_regs) != 0) {
        error("save regs of %d failed (%s)", _pid, strerror(errno));
        restore_target_after_fail();
        out.Close();
        unlink(corefile);
        return -1;
    }

    int detach_signal = 0;

    // get a page for shellcode
    user_regs64_struct regs;

    uint64_t inject_page = 0;
    long inject_exit_off = 0;   // B195: 子进程 exit(0) 序列相对 inject_begin 偏移
    {
        //uint64_t gv[6] = {0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0};
        uint64_t gv[6] = {0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0};
        // B57: pt_call 失败（目标中途死亡）时不填充 regs；不检查会在下面读未初始化的
        // inject_page 当垃圾地址继续注入。
        // R50-21 (D1): 与 forkcore_m 同路径对齐——pt_call 失败时 fail() 只恢复
        // xstate/[rsp-8]/红区不恢复 GPR；若目标是注入超时而非死亡（存活），
        // 直接 restore_target_after_fail 的 CONT 会让目标从被注入的 rip/rsp 继续
        // 执行 → 乱跑/崩溃。先恢复注入前完整寄存器。
        int mmap_signal = 0;
        if (pt_call(_pid, &regs, r_mmap, 6, gv, NULL, NULL, NULL,
                    NULL, &mmap_signal) != 0) {
            error("mmap injection failed (target died?)");
            pt_setregs(_pid, &saved_regs);
            if (mmap_signal == 0) {
                mmap_signal = probe_crash_stop(_pid);
            }
            if (mmap_signal != 0) {
                _monitor_relay_signals[_pid] = mmap_signal;
            }
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
        info("mmap = %lx", regs.get_rc());
        inject_page = regs.get_rc();
        // B16 缓解：目标阻塞在可重启 syscall 时，syscall-restart 会覆盖注入，
        // mmap 结果变垃圾（如 rax=0xdb）。合法结果必是页对齐、非零、用户态地址。
        // 否则 fail-closed 还原目标，避免用垃圾 inject_page 继续注入。
        if (inject_page == 0 || (inject_page & 0xfff) != 0 || inject_page < 0x10000 ||
            inject_page > arthur_max_user_va()) {
            error("remote mmap returned implausible %#lx "
                  "(target likely in a restartable syscall); aborting", inject_page);
            // B16 续: 注入失败时 pt_call 已在目标栈 [rsp-8] 写 0、把 rip 推向
            // 0（syscall-restart 覆盖注入后 ret 到 0 fault）。fail-closed 前
            // 恢复注入前的完整寄存器（含 rip/rsp/syscall 参数），CONT(0) 抑制
            // 该 SIGSEGV 后目标从原 syscall 指令继续，不再崩溃。仅靠
            // restore_target_after_fail 的 CONT(0) 会让 rip=0 立即重新 fault。
            pt_setregs(_pid, &saved_regs);
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
    }
    pt_getregs(_pid, &regs);

    // inject fork
    {
        char *inject_begin=0, *inject_end=0, *inject_exit=0;
#ifdef __aarch64__
        asm ("adr %0, inject_begin\n" : "=r" (inject_begin));
        asm ("adr %0, inject_end\n" : "=r" (inject_end));
        asm ("adr %0, inject_exit\n" : "=r" (inject_exit));
#else
        asm ("mov $inject_begin, %0 \n" : "=r" (inject_begin));
        asm ("mov $inject_end, %0 \n" : "=r" (inject_end));
        asm ("mov $inject_exit, %0 \n" : "=r" (inject_exit));
#endif
        int inject_size = (inject_end - inject_begin);
        inject_exit_off = (long)(inject_exit - inject_begin);
        dprint("inject_range(%p - %p), size(%d)", inject_begin, inject_end, inject_size);
        // B159: 必须从 inject_begin 拷贝，不能从 inject_fork（函数首）——inject_size
        // 只量 asm 块（inject_end - inject_begin），而函数首在 -O0 下多 4 字节前导
        //（x86: push rbp; mov rsp,rbp；aarch64 同理）。原实现拷贝错位：前 4 字节
        // 前导注入 + 末尾 4 字节截断。后果（实证）：
        //   ① 前导 push rbp 把目标 rbp 写进 [rsp-16]，B72 只恢复 [rsp-8]——每次
        //      mode-0/2 dump 的栈都残留一个错字；
        //   ② 父进程 ret 弹的是 push 的 rbp（栈地址）而非注入的 0，完成 fault 落在
        //      rbp（B158 观察到的"si_addr 是栈地址"实为此根因）——execstack 目标会
        //      执行栈字节（代码执行危害）；
        //   ③ 子进程 exit 路径的末尾 syscall 被截断，SIGTRAP 被捕获/阻塞时子进程
        //      SIGSEGV 而非干净 exit(0)（mode 2 边角）。
        // B80: pt_write 失败（注入页不可写/短写）时继续注入会执行垃圾代码；fail-closed。
        if (pt_write(_pid, inject_page, (void *)inject_begin, inject_size) != 0) {
            error("write inject shellcode to %lx failed", (unsigned long)inject_page);
            pt_setregs(_pid, &saved_regs);
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
        // B57: 注入 fork 失败（目标中途死亡）时 regs 未填充，_core_pid 会读垃圾。
        // B72: 记录注入写 0 的 [rsp-8] 槽位与原字，fork 后写回子进程快照。
        uint64_t inj_rsp = 0, inj_word = 0;
        uint64_t fork_child = 0;
        int fork_signal = 0;
        if (pt_call(_pid, &regs, inject_page, 0, NULL, &inj_rsp, &inj_word,
                    &fork_child, NULL, &fork_signal) != 0) {
            error("fork injection failed (target died?)");
            // R50-50: fork 已成功（TRACEFORK auto-attach 子进程冻结在 EVENT_FORK
            // stop）但 pt_call 后续失败（目标中途死亡/超时）——子进程残留为 arthur
            // 的 tracee（TracerPid=arthur, state=t），arthur 退出时释放并继续执行
            // 注入壳代码尾部（int $3 → SIGTRAP 崩溃 / exit(0)）。明确 SIGKILL 回收。
            if (fork_child > 0) {
                if (!sys_core) {
                    pt_terminate_tracee((pid_t)fork_child);
                }
                info("killed auto-attached fork child %lu from failed injection", fork_child);
            }
            pt_setregs(_pid, &saved_regs);
            if (fork_signal == 0) {
                fork_signal = probe_crash_stop(_pid);
            }
            if (fork_signal != 0) {
                _monitor_relay_signals[_pid] = fork_signal;
            }
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
        info("child_pid = %d", (int)regs.get_rc());
        _core_pid = regs.get_rc();
        if (_core_pid <= 0) {
            error("fork returned implausible child %d", (int)_core_pid);
            pt_setregs(_pid, &saved_regs);
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
        // B72: 子进程（COW 快照）保留注入的 0；写回原字消除快照污染。
        // R50-30: mode 0（TRACEFORK auto-attach）下子进程是 tracee，POKE 生效；
        // mode 2（sys_core）不设 TRACEFORK，子进程非 tracee，POKE 必 ESRCH 失败
        //（内核 core 的 [rsp-8] 残留 0）——检查返回并如实告警。
        if (inj_rsp) {
            if (ptrace(PTRACE_POKEDATA, _core_pid, inj_rsp, (void*)inj_word) != 0) {
                if (!sys_core) {
                    error("restore [rsp-8] in fork child %d failed (%s); "
                          "discarding polluted snapshot", _core_pid, strerror(errno));
                    pt_child_skip_int3(_core_pid, inject_page, inject_exit_off);
                    pt_terminate_tracee(_core_pid);
                    pt_setregs(_pid, &saved_regs);
                    restore_target_after_fail();
                    out.Close();
                    unlink(corefile);
                    return -1;
                }
                warn("restore [rsp-8] in untraced mode-2 child %d failed (%s); "
                     "kernel snapshot keeps injected 0", _core_pid, strerror(errno));
            }
        }
    }

    // munmap injected page.
    {
        uint64_t gv[2] = {inject_page, 0x1000};
        // R50-1: 返回未检查——目标中途死亡时 regs 未初始化，下面 get_rc() 读垃圾
        // 进日志；注入页泄漏。检查并告警（acore 已有效，仅 best-effort 清理）。
        // b98 (Codex B98 review): munmap 失败时 regs 保留上次调用的陈旧返回值，
        // info 无条件打印会把 child pid 误报成 munmap 结果——移入成功分支。
        int munmap_signal = 0;
        if (pt_call(_pid, &regs, r_munmap, 2, gv, NULL, NULL, NULL,
                    NULL, &munmap_signal) != 0) {
            warn("munmap injection failed (target died?)");
            if (munmap_signal == 0) {
                munmap_signal = probe_crash_stop(_pid);
            }
            detach_signal = munmap_signal;
        } else {
            info("munmap = %d", (int)regs.get_rc());
        }
    }

    // Restore the application GPR image before any thread is released. A core
    // is not a successful snapshot if Arthur cannot undo its injected call.
    if (pt_setregs(_pid, &saved_regs) != 0) {
        error("restore registers of %d after fork injection failed (%s)",
              _pid, strerror(errno));
        if (!sys_core) {
            pt_terminate_tracee(_core_pid);
        }
        restore_target_after_fail();
        out.Close();
        unlink(corefile);
        return -1;
    }

    // detach all threads
    int detach_threads_rc = 0;
    for (pid_t tid : _process._thrd_pid) {
        std::map<pid_t, int>::const_iterator pending =
            _monitor_relay_signals.find(tid);
        int relay = pending == _monitor_relay_signals.end() ? 0 : pending->second;
        if (tid == _pid && detach_signal != 0) {
            relay = detach_signal;
        }
        if (pt_detach(tid, relay) != 0 && errno != ESRCH) {
            detach_threads_rc = -1;
        }
    }
    _process._thrd_pid.clear();
    _monitor_relay_signals.clear();
    // Any signal observed during munmap was delivered by the detach above. The
    // later waitpid cleanup re-attaches the leader and must not deliver it twice.
    detach_signal = 0;
    ts_pause.end();
    if (detach_threads_rc != 0) {
        error("forkcore: failed to restore every captured thread");
        if (!sys_core) {
            pt_terminate_tracee(_core_pid);
        }
        out.Close();
        unlink(corefile);
        return -1;
    }

    bool child_cleanup_failed = false;
    if (!sys_core) {
        // R50-6: 失败路径在末尾杀 fork 子进程之前提前 return，子进程会作为
        // TRACEFORK 停止态 tracee 泄漏（若目标有 SIGTRAP handler，detach 后
        // 重投的 SIGTRAP 被处理，子进程作为目标副本继续存活）。统一先杀。
        auto kill_fork_child = [&]() -> void {
            pt_child_skip_int3(_core_pid, inject_page, inject_exit_off);   // B195
            if (pt_terminate_tracee(_core_pid) != 0) {
                child_cleanup_failed = true;
            }
        };
        // write acore
        // B65: 读子进程内存失败（child 消失/dumpable=0）时 fail-closed，还原目标。
        if (WriteLoads(out, _core_pid, maps) != 0) {
            error("failed to dump memory of child %d", (int)_core_pid);
            kill_fork_child();
            // 目标已在上方 detach（2704），TRACEFORK 随 DETACH 清除；
            // restore_target_after_fail 会对未跟踪 leader 报 ESRCH 误导，跳过。
            out.Close();
            unlink(corefile);
            return -1;
        }
        // B69: ELF 块写入失败（磁盘满）时 fail-closed。
        if (WriteElfHeader(out) != 0) {
            error("failed to write elf header");
            kill_fork_child();
            // 目标已在上方 detach（2704），TRACEFORK 随 DETACH 清除；
            // restore_target_after_fail 会对未跟踪 leader 报 ESRCH 误导，跳过。
            out.Close();
            unlink(corefile);
            return -1;
        }
        // R50-6: 尾标写失败同 B69/B70——缺结束标记的解压必拒，显式失败。
        if (WriteTailMark(out) != 0) {
            error("failed to write tail mark (disk full?)");
            kill_fork_child();
            // 目标已在上方 detach（2704），TRACEFORK 随 DETACH 清除；
            // restore_target_after_fail 会对未跟踪 leader 报 ESRCH 误导，跳过。
            out.Close();
            unlink(corefile);
            return -1;
        }
    }

    // kill the forked process
    // B195: SIGKILL 前把子进程 rip 指到 exit(0)（跳过 int $3），避免 SIGKILL 竞态
    // 下 int $3 先执行、SIGTRAP 默认转储内核 core（monitor 每次 SIGUSR1 dump 在
    // 目标 cwd 留 core.* 文件）。
    pt_child_skip_int3(_core_pid, inject_page, inject_exit_off);
    if (!sys_core && pt_terminate_tracee(_core_pid) != 0) {
        child_cleanup_failed = true;
    }
    //assert(rc == 0);

    // now the process becomes zombie,
    // we have to waitpid the forked pid.
    // B76 (Codex B6 review): 末尾 re-attach 的 pt_attach/pt_getregs/pt_setregs/
    // pt_detach 返回全被忽略——目标若在自由运行窗口退出/被另一 tracer 占用，
    // attach 失败后继续注入会读到垃圾。acore 已写（有效），此处告警而非静默成功。
    // b6 (Codex review): attach 失败后仍无条件 getregs/waitpid/setregs/detach，
    // 在未 attached/已死亡目标上执行并消费垃圾寄存器——跳过收尾注入，dump 仍有效。
    bool final_restore_failed = child_cleanup_failed;
    int reattach_relay_signal = 0;
    if (pt_attach(_pid, &reattach_relay_signal) != 0) {
        warn("re-attach of %d failed; injected waitpid may not have reaped the "
             "fork child", _pid);
    } else if (reattach_relay_signal != 0) {
        warn("re-attach of %d intercepted %s; skipping waitpid injection and relaying it",
             _pid, strsignal(reattach_relay_signal));
        if (pt_detach(_pid, reattach_relay_signal) != 0 && errno != ESRCH) {
            final_restore_failed = true;
        }
    } else if (pt_getregs(_pid, &saved_regs) != 0) {
        warn("cannot save registers for waitpid cleanup of %d; skipping injection", _pid);
        if (pt_detach(_pid) != 0 && errno != ESRCH) {
            final_restore_failed = true;
        }
    } else {
        // R50-50: leader 停靠时若处于可重启 syscall 的 -ERESTART* 返回点，CONT(0)
        // 会触发 syscall-restart（内核 ip-=2），注入的 waitpid 不执行、目标从
        // waitpid-2 跑垃圾代码（与 B16 的 mmap 注入同机制，但 waitpid 收尾路径
        // 只有 B73 的返回值告警、无 fail-closed）。跳过注入，fork 子进程可能
        // 残留 zombie（目标自身 waitpid 或退出时回收）。
        if (regs_has_restart_return(saved_regs)) {
            warn("leader %d captured in restartable syscall (rax=%lld); skipping "
                 "waitpid injection (fork child may linger as a zombie)",
                 _pid, (long long)saved_regs.get_rc());
        } else {
            uint64_t gv[3] = { (uint64_t)_core_pid, (uint64_t)NULL, 0 };
            // R50-1: pt_call 返回未检查——目标中途死亡时 regs 未初始化，get_rc()
            // 读垃圾进日志/告警。检查并告警（acore 已有效，best-effort 收尸）。
            int wait_signal = 0;
            if (pt_call(_pid, &regs, r_waitpid, 3, gv, NULL, NULL, NULL,
                        NULL, &wait_signal) != 0) {
                // R50-38: 注入 waitpid 失败不必然是"target died"——mode 2 下
                // fork 子进程非 tracee，DETACH+SIGKILL 无效，子进程靠 int $3 内核
                // core 后自行死亡；大目标内核 core dump 可 >10s，pt_call 超时
                // 触发同一失败路径。两种情况都会让子进程 zombie 残留（目标退出或
                // 自行 waitpid 才回收）。如实区分告警，不再误导为"target died"。
                // b165 (Codex B165 review): mode 0 不会出现"mode-2 kernel core dump
                // 超时"这一原因——按 sys_core 分流，避免误导诊断。
                if (sys_core) {
                    warn("waitpid injection failed (target died, or mode-2 kernel "
                         "core dump exceeded 10s); fork child %d may linger as a "
                         "zombie until the target exits", (int)_core_pid);
                } else {
                    warn("waitpid injection failed (target died?); fork child %d "
                         "may linger as a zombie until the target exits",
                         (int)_core_pid);
                }
                if (wait_signal == 0) {
                    wait_signal = probe_crash_stop(_pid);
                }
                detach_signal = wait_signal;
            } else {
                info("waitpid = %d", (int)regs.get_rc());
                // B73 (Codex B2 review): 目标阻塞在可重启 syscall 时，B16 的 syscall-restart
                // 会让注入的 waitpid 不执行，返回垃圾/ECHILD → 子进程作为目标 zombie 残留，
                // 重复采集累积。检查返回值并如实报告。
                if (regs.get_rc() != (uint64_t)_core_pid) {
                    warn("injected waitpid returned %d (expected %d); child may linger "
                         "as a zombie (target likely in a restartable syscall)",
                         (int)regs.get_rc(), (int)_core_pid);
                }
            }
        }
        if (pt_setregs(_pid, &saved_regs) != 0) {
            error("restore registers after waitpid cleanup of %d failed (%s)",
                  _pid, strerror(errno));
            final_restore_failed = true;
        }
        if (pt_detach(_pid, detach_signal) != 0 && errno != ESRCH) {
            final_restore_failed = true;
        }
    }
    if (final_restore_failed) {
        error("forkcore: final target restoration failed");
        out.Close();
        unlink(corefile);
        return -1;
    }

    info("Process %u paused %0.3f ms.", _pid, ts_pause.timediff()*1000);
    out.PrintStat();
    // b167/b191: Close 返回关闭期错误（ENOSPC），不再静默返回 0
    if (commit_atomic_lz4(out, temp_corefile, final_corefile,
                          output_state) != 0) {
        error("forkcore: final close failed, core removed");
        unlink(corefile);
        return -1;
    }
    // R50-38: mode 2（sys_core）的元数据 acore 无 magic/LOADS/ELF/尾标
    //（WriteFileHeader/WriteLoads/WriteElfHeader/WriteTailMark 被跳过），且
    // merge(-m) 未实现——产出物（元数据 + 内核 core）无法合并成可用 core，
    // 内核 core 还是注入子进程的单线程快照（寄存器是注入态）。exit 0 会误导
    // 自动化判成功；如实告警。
    if (sys_core) {
        warn("mode 2: metadata acore '%s' cannot be merged into a usable core "
             "(merge -m not implemented); kernel core is a single-threaded "
             "snapshot of the injected child with injection-state registers",
             final_corefile.c_str());
    }
    return 0;
}

/* forkcore_m() generate corefile in the same way as forkcore()
 * except: 
 *    1. using PTRACE_INTERRUPT to stop tracee
 *    2. resume tracee instead of detach from tracee
 */ 
int Coredump::forkcore_m(const char *corefile, bool sys_core)
{
    // 每次采集前清空跨调用累积的 _phdrs
    _phdrs.clear();
    _core_pid = 0;
    _crash_sig = 0;
    _monitor_recovery_failed = false;
    /* forkcore using a forked process for large memory dump, 
     * and all thread Registers Set is collected by this function.
     * 
     * after the function, there two parts of whole corefile.
     * 1) a corefile.<pid> from forked process, this has the contents of all COW memory files.
     * 2) a metadata.<pid> for orignal process info includes all Registers for all threads.
     *
     * the two parts should be merged by arthur merge command to generate the final corefile.
     */

    int rc;
    const std::string final_corefile(corefile);
    std::string temp_corefile;
    AtomicOutputState output_state;
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = open_atomic_lz4(out, final_corefile.c_str(), temp_corefile,
                         output_state);
    if (rc < 0) {
        return -1;
    }
    corefile = temp_corefile.c_str();

    if (!sys_core) {
        // R50-1: WriteFileHeader 返回未检查——缺头 acore 静默产出。检查并清理。
        if (WriteFileHeader(out) != 0) {
            error("write acore header failed");
            out.Close();
            unlink(corefile);
            return -1;
        }
    }

    TS ts_pause;
    ts_pause.begin();

    pid_t snapshot_tid = _pid;
    if (_monitor_leader_exited) {
        snapshot_tid = 0;
        for (pid_t tid : _monitor_tids) {
            if (tid != _pid) {
                snapshot_tid = tid;
                break;
            }
        }
        if (snapshot_tid == 0) {
            error("cannot snapshot process %d after leader exit: no live worker", _pid);
            out.Close();
            unlink(corefile);
            return -1;
        }
    }

    // stop tracee
    // R50-1: pt_int 返回未检查——INTERRUPT 失败（目标已退出 ESRCH / 非 seize 态
    // EIO）时静默继续，后续在未停住的目标上注入/采集。fail-closed。
    if (pt_int(snapshot_tid) != 0) {
        error("cannot interrupt snapshot thread %d (%s)", snapshot_tid,
              strerror(errno));
        out.Close();
        unlink(corefile);
        return -1;
    }

    // get all threads pid（attach 全部非主线程，剔除已退出的）
    // B77: collect_threads 失败（opendir / 非 ESRCH attach 错误）时 fail-closed。
    // R50-6: leader 已被 INTERRUPT 停住；失败须还原（detach 兄弟 + 清 TRACEFORK +
    // CONT leader），否则目标冻结、monitor 误以为仍在监控。
    int collect_rc = collect_threads(_pid);
    if (collect_rc != 0) {
        error("failed to collect threads of %d", _pid);
        if (collect_rc > 0 && !_monitor_tids.empty()) {
            // A monitored worker entered an unhandled fatal delivery-stop while
            // SIGUSR1 collection was freezing the thread group. Keep every
            // tracee stopped and hand the real signal to monitor crash capture.
            out.Close();
            unlink(corefile);
            return collect_rc;
        }
        restore_target_after_fail();
        // b41 (Codex review): 清理已打开的空 acore（8 字节 header），不残留假文件。
        out.Close();
        unlink(corefile);
        return -1;
    }

    ProcMaps maps;
    // N4: WriteProcessMeta 失败（/proc 读失败）时若继续写，acore 缺进程元数据，
    // 解压端 ReadMeta 的 GetFile 序列错位。fail-closed 还原目标。
    if (WriteProcessMeta(out, maps, snapshot_tid) != 0) {
        error("write process meta failed");
        restore_target_after_fail();
        out.Close();
        unlink(corefile);
        return -1;
    }
    // Serialize a live control thread first. Normally this is the process
    // leader; after pthread_exit it is a worker and v6 PROCESS stat carries
    // the independent process identity needed by NT_PRPSINFO.
    // R50-1: WriteThreadMeta 现在会因写失败返回 -1；忽略则线程块缺失仍继续
    // LOADS/ELF → 坏 acore。检查并清理部分产物、还原目标。
    if (std::find(_process._thrd_pid.begin(), _process._thrd_pid.end(),
                  snapshot_tid) == _process._thrd_pid.end()) {
        snapshot_tid = _process._thrd_pid.front();
    }
    if (WriteThreadMeta(out, snapshot_tid, snapshot_tid == _pid) != 0) {
        error("write snapshot control thread meta failed");
        restore_target_after_fail();
        out.Close();
        unlink(corefile);
        return -1;
    }
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == snapshot_tid) {
            continue;
        }
        if (WriteThreadMeta(out, tid) != 0) {
            error("write thread meta of %d failed", tid);
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
    }

    bool direct_snapshot = !sys_core &&
        (_monitor_leader_exited ||
         fork_snapshot_requires_direct_capture(_pid, maps));

    uint64_t r_libc = 0;
    uint64_t r_mmap = 0;
    uint64_t r_munmap = 0;
    uint64_t r_waitpid = 0;
    if (!direct_snapshot) {
        r_libc = get_module_address(_pid, "libc");
        r_mmap = get_remote_sym_address(_pid, r_libc, "mmap");
        r_munmap = get_remote_sym_address(_pid, r_libc, "munmap");
        r_waitpid = get_remote_sym_address(_pid, r_libc, "waitpid");
        if (r_mmap == 0 || r_munmap == 0 || r_waitpid == 0) {
            if (!sys_core) {
                info("target has no usable libc injection symbols; "
                     "using direct snapshot");
                direct_snapshot = true;
            } else {
                error("failed to resolve libc symbols in target (libc base %lx)",
                      r_libc);
                restore_target_after_fail();
                out.Close();
                unlink(corefile);
                return -1;
            }
        }
    }

    if (direct_snapshot) {
        int write_rc = WriteLoads(out, snapshot_tid, maps);
        if (write_rc == 0) {
            write_rc = WriteElfHeader(out);
        }
        if (write_rc == 0) {
            write_rc = WriteTailMark(out);
        }
        if (write_rc != 0) {
            error("direct monitor snapshot failed");
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }

        for (pid_t tid : _process._thrd_pid) {
            std::map<pid_t, int>::const_iterator pending =
                _monitor_relay_signals.find(tid);
            int relay = pending == _monitor_relay_signals.end() ? 0 : pending->second;
            if (ptrace(PTRACE_CONT, tid, NULL, (uintptr_t)relay) != 0 &&
                errno != ESRCH) {
                error("resume direct-snapshot thread %d failed (%s)",
                      tid, strerror(errno));
                _monitor_recovery_failed = true;
            }
        }
        _monitor_relay_signals.clear();
        _process._thrd_pid.clear();
        ts_pause.end();
        if (_monitor_recovery_failed) {
            out.Close();
            unlink(corefile);
            return -1;
        }
        info("Process %u paused %0.3f ms (direct fallback).",
             _pid, ts_pause.timediff()*1000);
        out.PrintStat();
        if (commit_atomic_lz4(out, temp_corefile, final_corefile,
                              output_state) != 0) {
            error("forkcore_m direct fallback: final close failed, core removed");
            unlink(corefile);
            return -1;
        }
        return 0;
    }
 
    // we've injected an 'int 3' in child process, that generates a corefile by kernel.
    // B39: SETOPTIONS 是整体替换——直接设 TRACEFORK 会清掉 monitor_threads
    // 设定的 TRACEEXIT/TRACECLONE，monitor 的退出与新线程跟踪会降级。
    if (!sys_core) {
        // 在持久 _ptrace_options 上叠加 TRACEFORK，避免整体替换清掉
        // TRACEEXIT/TRACECLONE（B39）。
        rc = ptrace(PTRACE_SETOPTIONS, _pid, 0,
                    _ptrace_options | (long)PTRACE_O_TRACEFORK);
        if (rc != 0) {
            // B57: 目标可能在 attach/stop 后退出；fail-closed 还原，不 assert。
            error("set TRACEFORK on %d failed (%s)", _pid, strerror(errno));
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
    }

    info("remote mmap at %lx", r_mmap);
    info("remote waitpid at %lx", r_waitpid);

    // save the program regs
    user_regs64_struct saved_regs;
    // R50-1: getregs 返回未检查——失败时 saved_regs 未初始化，后面 pt_setregs
    // 会把垃圾寄存器写回目标。目标处于 stop 正常不会失败，仍检查以 fail-closed。
    if (pt_getregs(_pid, &saved_regs) != 0) {
        error("save regs of %d failed (%s)", _pid, strerror(errno));
        restore_target_after_fail();
        out.Close();
        unlink(corefile);
        return -1;
    }

    auto restore_saved_gprs = [&]() -> bool {
        if (pt_setregs(_pid, &saved_regs) == 0) {
            return true;
        }
        error("restore registers of %d after failed monitored injection failed (%s)",
              _pid, strerror(errno));
        _monitor_recovery_failed = true;
        return false;
    };

    // get a page for shellcode
    user_regs64_struct regs;
    uint64_t inject_page = 0;
    long inject_exit_off = 0;   // B195: 子进程 exit(0) 序列相对 inject_begin 偏移
    {
        uint64_t gv[6] = {0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0};
        // B57: pt_call 失败（目标中途死亡）时不填充 regs。forkcore 同位置有检查，
        // 此处漏掉（R50-1）——未检查会在下面把未初始化的 get_rc() 当 inject_page
        // 继续注入。fail-closed 还原目标。
        int mmap_death = 0;
        int mmap_signal = 0;
        int mmap_call = pt_call(_pid, &regs, r_mmap, 6, gv, NULL, NULL, NULL,
                                &mmap_death, &mmap_signal);
        if (mmap_call != 0) {
            if (mmap_call == PT_CALL_RECOVERY_FAILED) {
                _monitor_recovery_failed = true;
            }
            if (mmap_signal != 0) {
                info("leader stopped at %s during mmap injection; restoring and relaying",
                     strsignal(mmap_signal));
                restore_saved_gprs();
                _monitor_relay_signals[_pid] = mmap_signal;
                restore_target_after_fail();
                out.Close();
                unlink(corefile);
                return -1;
            }
            // B197: 并发崩溃（B158 "crash during injection"）时 leader 停在崩溃
            // delivery-stop——restore_target_after_fail 的 CONT(0) 会抑制崩溃信号、
            // 目标"复活"崩溃丢失（实证：失败 dump 窗口 kill-SEGV 后目标存活、无
            // 采集）。先探测崩溃并返回给 monitor 采集（保留停靠不 CONT；被捕获则
            // CONT(sig) 中继走 handler，与 B184 对齐）。
            int crash = probe_crash_stop(_pid);
            if (crash != 0) {
                int disposition = signal_has_nondefault_disposition(_pid, crash);
                if (disposition < 0) {
                    error("cannot determine disposition of %s after failed injection; "
                          "relaying and stopping monitor", strsignal(crash));
                    restore_saved_gprs();
                    _monitor_relay_signals[_pid] = crash;
                    _monitor_recovery_failed = true;
                    restore_target_after_fail();
                } else if (disposition > 0) {
                    info("leader stopped at non-default %s after failed injection; relaying",
                         strsignal(crash));
                    restore_saved_gprs();
                    _monitor_relay_signals[_pid] = crash;
                    restore_target_after_fail();
                } else {
                    info("leader stopped at %s after failed injection; returning to collect",
                         strsignal(crash));
                    _monitor_crash_tid = _pid;
                    ptrace(PTRACE_SETOPTIONS, _pid, 0, _ptrace_options);   // 清 TRACEFORK，不 CONT
                }
                out.Close();
                unlink(corefile);
                return disposition == 0 ? crash : -1;
            }
            // B198: 目标在注入期间被杀（SIGKILL/OOM/看门狗）——死亡 SIGCHLD 被
            // dump 噪音 first-wins 合并吞掉（实证：monitor 继续监控死进程、8s 不
            // 退出、额外 SIGUSR1 无效）。pt_call 内 waitpid 已消费死亡状态（本函数
            // detect_leader_death 拿不到），用 out_death 捕获；返回 -2 让 monitor
            // 清理 -o 并退出。
            int death = mmap_death ? mmap_death : detect_leader_death(_pid);
            if (death != 0) {
                if (is_core_dump_signal(death)) {
                    // 崩溃 stop（probe_crash_stop 之后新到）——按崩溃返回，monitor 采集。
                    _monitor_crash_tid = _pid;
                    out.Close();
                    unlink(corefile);
                    return death;
                }
                // WIFSIGNALED（如 SIGKILL=9）或 WIFEXITED(-2)——目标已死。
                info("leader %d died during failed injection (death=%d); exiting monitor",
                     _pid, death);
                out.Close();
                unlink(corefile);
                return -2;
            }
            error("mmap injection failed (target died?)");
            restore_saved_gprs();
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
        info("mmap = %lx", regs.get_rc());
        inject_page = regs.get_rc();
        // B16 缓解：目标阻塞在可重启 syscall 时，syscall-restart 会覆盖注入，
        // mmap 结果变垃圾（如 rax=0xdb）。合法结果必是页对齐、非零、用户态地址。
        // 否则 fail-closed 还原目标，避免用垃圾 inject_page 继续注入。
        if (inject_page == 0 || (inject_page & 0xfff) != 0 || inject_page < 0x10000 ||
            inject_page > arthur_max_user_va()) {
            error("remote mmap returned implausible %#lx "
                  "(target likely in a restartable syscall); aborting", inject_page);
            // B16 续: 注入失败时 pt_call 已在目标栈 [rsp-8] 写 0、把 rip 推向
            // 0（syscall-restart 覆盖注入后 ret 到 0 fault）。fail-closed 前
            // 恢复注入前的完整寄存器（含 rip/rsp/syscall 参数），CONT(0) 抑制
            // 该 SIGSEGV 后目标从原 syscall 指令继续，不再崩溃。仅靠
            // restore_target_after_fail 的 CONT(0) 会让 rip=0 立即重新 fault。
            restore_saved_gprs();
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
    }
    pt_getregs(_pid, &regs);

    // inject fork
    {
        char *inject_begin=0, *inject_end=0, *inject_exit=0;
#ifdef __aarch64__
        asm ("adr %0, inject_begin\n" : "=r" (inject_begin));
        asm ("adr %0, inject_end\n" : "=r" (inject_end));
        asm ("adr %0, inject_exit\n" : "=r" (inject_exit));
#else
        asm ("mov $inject_begin, %0 \n" : "=r" (inject_begin));
        asm ("mov $inject_end, %0 \n" : "=r" (inject_end));
        asm ("mov $inject_exit, %0 \n" : "=r" (inject_exit));
#endif
        int inject_size = (inject_end - inject_begin);
        inject_exit_off = (long)(inject_exit - inject_begin);
        dprint("inject_range(%p - %p), size(%d)", inject_begin, inject_end, inject_size);
        // B159: 必须从 inject_begin 拷贝，不能从 inject_fork（函数首）——inject_size
        // 只量 asm 块（inject_end - inject_begin），而函数首在 -O0 下多 4 字节前导
        //（x86: push rbp; mov rsp,rbp；aarch64 同理）。原实现拷贝错位：前 4 字节
        // 前导注入 + 末尾 4 字节截断。后果（实证）：
        //   ① 前导 push rbp 把目标 rbp 写进 [rsp-16]，B72 只恢复 [rsp-8]——每次
        //      mode-0/2 dump 的栈都残留一个错字；
        //   ② 父进程 ret 弹的是 push 的 rbp（栈地址）而非注入的 0，完成 fault 落在
        //      rbp（B158 观察到的"si_addr 是栈地址"实为此根因）——execstack 目标会
        //      执行栈字节（代码执行危害）；
        //   ③ 子进程 exit 路径的末尾 syscall 被截断，SIGTRAP 被捕获/阻塞时子进程
        //      SIGSEGV 而非干净 exit(0)（mode 2 边角）。
        // B80: pt_write 失败（注入页不可写/短写）时继续注入会执行垃圾代码；fail-closed。
        if (pt_write(_pid, inject_page, (void *)inject_begin, inject_size) != 0) {
            error("write inject shellcode to %lx failed", (unsigned long)inject_page);
            restore_saved_gprs();
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
        // B57: 注入 fork 失败（目标中途死亡）时 regs 未填充，_core_pid 会读垃圾。
        // B72: 记录注入写 0 的 [rsp-8] 槽位与原字，fork 后写回子进程快照。
        uint64_t inj_rsp = 0, inj_word = 0;
        uint64_t fork_child = 0;
        int fork_signal = 0;
        int fork_call = pt_call(_pid, &regs, inject_page, 0, NULL,
                                &inj_rsp, &inj_word, &fork_child, NULL,
                                &fork_signal);
        if (fork_call != 0) {
            if (fork_call == PT_CALL_RECOVERY_FAILED) {
                _monitor_recovery_failed = true;
            }
            error("fork injection failed (target died?)");
            // R50-50: fork 已成功（TRACEFORK auto-attach 子进程冻结在 EVENT_FORK
            // stop）但 pt_call 后续失败（目标中途死亡/超时）——子进程残留为 arthur
            // 的 tracee（TracerPid=arthur, state=t），arthur 退出时释放并继续执行
            // 注入壳代码尾部（int $3 → SIGTRAP 崩溃 / exit(0)）。明确 SIGKILL 回收。
            if (fork_child > 0) {
                if (!sys_core && pt_terminate_tracee((pid_t)fork_child) != 0) {
                    _monitor_recovery_failed = true;
                }
                info("killed auto-attached fork child %lu from failed injection", fork_child);
            }
            restore_saved_gprs();
            if (fork_signal == 0) {
                fork_signal = probe_crash_stop(_pid);
            }
            if (fork_signal != 0) {
                int disposition = is_core_dump_signal(fork_signal)
                    ? signal_has_nondefault_disposition(_pid, fork_signal) : 1;
                if (disposition == 0) {
                    info("leader stopped at %s during fork injection; returning to collect",
                         strsignal(fork_signal));
                    _monitor_crash_tid = _pid;
                    if (ptrace(PTRACE_SETOPTIONS, _pid, 0, _ptrace_options) != 0 &&
                        errno != ESRCH) {
                        _monitor_recovery_failed = true;
                    }
                    out.Close();
                    unlink(corefile);
                    return fork_signal;
                }
                if (disposition < 0) {
                    error("cannot determine disposition of %s during fork injection; "
                          "relaying and stopping monitor", strsignal(fork_signal));
                    _monitor_recovery_failed = true;
                }
                _monitor_relay_signals[_pid] = fork_signal;
            }
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
        info("child_pid = %d", (int)regs.get_rc());
        _core_pid = regs.get_rc();
        if (_core_pid <= 0) {
            error("fork returned implausible child %d", (int)_core_pid);
            restore_saved_gprs();
            restore_target_after_fail();
            out.Close();
            unlink(corefile);
            return -1;
        }
        // B72: 子进程（COW 快照）保留注入的 0；写回原字消除快照污染。
        // R50-30: mode 0（TRACEFORK auto-attach）下子进程是 tracee，POKE 生效；
        // mode 2（sys_core）不设 TRACEFORK，子进程非 tracee，POKE 必 ESRCH 失败
        //（内核 core 的 [rsp-8] 残留 0）——检查返回并如实告警。
        if (inj_rsp) {
            if (ptrace(PTRACE_POKEDATA, _core_pid, inj_rsp, (void*)inj_word) != 0) {
                if (!sys_core) {
                    error("restore [rsp-8] in fork child %d failed (%s); "
                          "discarding polluted snapshot", _core_pid, strerror(errno));
                    pt_child_skip_int3(_core_pid, inject_page, inject_exit_off);
                    if (pt_terminate_tracee(_core_pid) != 0) {
                        _monitor_recovery_failed = true;
                    }
                    restore_saved_gprs();
                    restore_target_after_fail();
                    out.Close();
                    unlink(corefile);
                    return -1;
                }
                warn("restore [rsp-8] in untraced mode-2 child %d failed (%s); "
                     "kernel snapshot keeps injected 0", _core_pid, strerror(errno));
            }
        }
    }

    // munmap injected page.
    {
        uint64_t gv[2] = {inject_page, 0x1000};
        // R50-1: 返回未检查——目标中途死亡时 regs 未初始化，下面 get_rc() 读垃圾
        // 进日志；注入页泄漏。检查并告警（acore 已有效，仅 best-effort 清理）。
        // b98 (Codex B98 review): munmap 失败时 regs 保留上次调用的陈旧返回值，
        // info 无条件打印会把 child pid 误报成 munmap 结果——移入成功分支。
        int munmap_signal = 0;
        int munmap_call = pt_call(_pid, &regs, r_munmap, 2, gv, NULL,
                                  NULL, NULL, NULL, &munmap_signal);
        if (munmap_call != 0) {
            if (munmap_call == PT_CALL_RECOVERY_FAILED) {
                _monitor_recovery_failed = true;
            }
            warn("munmap injection failed (target died?)");
            if (munmap_signal == 0) {
                munmap_signal = probe_crash_stop(_pid);
            }
            if (munmap_signal != 0) {
                pt_child_skip_int3(_core_pid, inject_page, inject_exit_off);
                if (!sys_core && pt_terminate_tracee(_core_pid) != 0) {
                    _monitor_recovery_failed = true;
                }
                restore_saved_gprs();
                int disposition = is_core_dump_signal(munmap_signal)
                    ? signal_has_nondefault_disposition(_pid, munmap_signal) : 1;
                if (disposition == 0) {
                    info("leader stopped at %s during munmap injection; returning to collect",
                         strsignal(munmap_signal));
                    _monitor_crash_tid = _pid;
                    if (ptrace(PTRACE_SETOPTIONS, _pid, 0, _ptrace_options) != 0 &&
                        errno != ESRCH) {
                        _monitor_recovery_failed = true;
                    }
                    out.Close();
                    unlink(corefile);
                    return munmap_signal;
                }
                if (disposition < 0) {
                    error("cannot determine disposition of %s during munmap injection; "
                          "relaying and stopping monitor", strsignal(munmap_signal));
                    _monitor_recovery_failed = true;
                }
                _monitor_relay_signals[_pid] = munmap_signal;
                restore_target_after_fail();
                out.Close();
                unlink(corefile);
                return -1;
            }
        } else {
            info("munmap = %d", (int)regs.get_rc());
        }
    }

    // Restore the application GPR image before resuming any monitored thread.
    if (pt_setregs(_pid, &saved_regs) != 0) {
        error("restore registers of %d after monitored fork injection failed (%s)",
              _pid, strerror(errno));
        _monitor_recovery_failed = true;
        if (!sys_core) {
            pt_terminate_tracee(_core_pid);
        }
        out.Close();
        unlink(corefile);
        return -1;
    }

    // Resume persistently monitored workers; standalone forkcore attaches are
    // one-shot and must still detach.
    for(pid_t& tid : _process._thrd_pid) {
        if(tid == _pid)
            continue;
        if (_monitor_tids.empty()) {
            std::map<pid_t, int>::const_iterator pending =
                _monitor_relay_signals.find(tid);
            int relay = pending == _monitor_relay_signals.end() ? 0 : pending->second;
            if (pt_detach(tid, relay) != 0 && errno != ESRCH) {
                error("detach snapshot thread %d failed (%s)", tid, strerror(errno));
                _monitor_recovery_failed = true;
            }
        } else {
            std::map<pid_t, int>::const_iterator pending =
                _monitor_relay_signals.find(tid);
            int relay = pending == _monitor_relay_signals.end() ? 0 : pending->second;
            if (ptrace(PTRACE_CONT, tid, NULL, (uintptr_t)relay) != 0 &&
                errno != ESRCH) {
                error("resume snapshot thread %d failed (%s)", tid, strerror(errno));
                _monitor_recovery_failed = true;
            }
        }
    }
    ts_pause.end();

    /**
     * Tracee will resume executing while writing out corefile with data from forked process;
     * if any exception happens in between this section, tracee will be stopped; 
     * the signal is supposed to be pending before finishing writing corefile
     */
    if (pt_cont(_pid) != 0 && errno != ESRCH && !_monitor_tids.empty()) {
        _monitor_recovery_failed = true;
    }
    _process._thrd_pid.clear(); // clear all thread id in array
    _monitor_relay_signals.clear();
    if (_monitor_recovery_failed) {
        error("forkcore_m: failed to resume every monitored thread");
        if (!sys_core) {
            pt_terminate_tracee(_core_pid);
        }
        out.Close();
        unlink(corefile);
        return -1;
    }

    // R50-1: leader 已被 pt_cont 放行（运行中带 TRACEFORK）。此处失败若只调
    // restore_target_after_fail，对运行中 tracee 的 SETOPTIONS/CONT 都会失败（ESRCH，
    // agent 实测），TRACEFORK 残留 → 目标下次 fork 被冻结/SIGTRAP 误杀；且 _core_pid
    // 子进程（auto-attach 冻结）未被回收。先杀子进程、再 INTERRUPT 停住 leader 清
    // TRACEFORK（保留 TRACEEXIT）再 CONT。
    auto recover_after_resume = [&]() -> void {
        pt_child_skip_int3(_core_pid, inject_page, inject_exit_off);   // B195
        if (pt_terminate_tracee(_core_pid) != 0) {
            _monitor_recovery_failed = true;
        }
        if (pt_int(_pid) != 0) {                            // 停住 leader 才能 SETOPTIONS
            error("late recovery: interrupt leader %d failed (%s)",
                  _pid, strerror(errno));
            _monitor_recovery_failed = true;
            return;
        }
        if (ptrace(PTRACE_SETOPTIONS, _pid, 0, _ptrace_options) != 0) {
            error("late recovery: clear TRACEFORK on %d failed (%s)",
                  _pid, strerror(errno));
            _monitor_recovery_failed = true;
        }
        if (ptrace(PTRACE_CONT, _pid, NULL, NULL) != 0) {
            error("late recovery: continue leader %d failed (%s)",
                  _pid, strerror(errno));
            _monitor_recovery_failed = true;
        }
    };

    // TBD: dump memory regions
    if (!sys_core) {
        // write acore
        {
            // B65: 读子进程内存失败（child 消失/dumpable=0）时 fail-closed，还原目标。
            // R50-6: 放行后失败同样要清理部分 acore（此前只 recover，残留残缺文件）。
        if (WriteLoads(out, _core_pid, maps) != 0) {
            error("failed to dump memory of child %d", (int)_core_pid);
            recover_after_resume();
            out.Close();
            unlink(corefile);
            return -1;
        }
            // B69: ELF 块写入失败（磁盘满）时 fail-closed。
            if (WriteElfHeader(out) != 0) {
                error("failed to write elf header");
                recover_after_resume();
                out.Close();
                unlink(corefile);
                return -1;
            }
            // R50-6: 尾标写失败同 B69——缺结束标记的解压必拒，显式失败并清理。
            if (WriteTailMark(out) != 0) {
                error("failed to write tail mark (disk full?)");
                recover_after_resume();
                out.Close();
                unlink(corefile);
                return -1;
            }
        }
    }

    // kill the forked process
    // B195: SIGKILL 前把子进程 rip 指到 exit(0)（跳过 int $3），避免 SIGKILL 竞态
    // 下 int $3 先执行、SIGTRAP 默认转储内核 core（monitor 每次 SIGUSR1 dump 在
    // 目标 cwd 留 core.* 文件）。
    pt_child_skip_int3(_core_pid, inject_page, inject_exit_off);
    if (pt_terminate_tracee(_core_pid) != 0) {
        _monitor_recovery_failed = true;
    }
    // assert(rc == 0);

    // in case any signal generated above
    // 目标可能仍被 SIGUSR1 的 forkcore_m 停住；s 未初始化会被 WIFSIGNALED/WIFSTOPPED 误读
    int s = 0, sig = 0;
    // B153: 必须带 WUNTRACED——不加时 waitpid 不报告组停靠（SIGSTOP/SIGTSTP/
    // SIGTTIN/SIGTTOU，实证），leader 在 dump 窗口内被作业控制停止会走 else
    // 分支对已停 tracee 做 pt_int：INTERRUPT 不产生新停靠 → pt_wait 卡 10s
    // 超时 → 注入把组停靠的 leader 恢复运行（本应保持停靠）。加 WUNTRACED 让
    // 组停靠进 WIFSTOPPED 分支，sig=SIGSTOP 由 monitor 的 LISTEN/CONT 中继恢复。
    // R50-11: 目标在 dump 窗口内死于信号（崩溃/被 kill）。原 `exit(0)` 三错：
    // ① 目标崩溃却以 0（成功）退出，绕过 B38 的"崩溃无 core→非零"语义；
    // ② exit() 不跑栈对象析构，monitor 的 -o 空 acore（只写了 8 字节头）永不
    //    Close/unlink，残留解压必拒的假文件（B38/B111 专门清理被绕过）；
    // ③ 崩溃漏抓，调用方从退出码无从得知。
    // 改为：清理本次 SIGUSR1 dump 的部分 acore + 返回该信号。崩溃信号会让
    // monitor break 进崩溃采集（目标已死 → collect_threads 失败 → kill_crashed
    // 清理 -o 空 acore 并返回 -1，正确 fail-closed）。
    // B156: waitpid 可能返回 0（leader 仍在运行、无 pending 状态）——此时 s 保持
    // 初始 0，WIFEXITED(0) 恒真（(0&0x7f)==0）会误报"退出"（实证：组停靠/运行中
    // leader 的 SIGUSR1 dump 被误判为 exit(0)、monitor 错误退出）。必须用 waitpid
    // 返回值 >0 判断确有状态。WIFSIGNALED(0) 不误报（(0&0x7f)!=0x7f 恒假），
    // 但统一加 `wr > 0` 更严谨。
    pid_t wr;
    do {
        wr = waitpid(_pid, &s, WUNTRACED | WNOHANG);
    } while (wr < 0 && errno == EINTR);
    bool wait_status_failed = false;
    if (wr < 0) {
        error("wait for leader %d after snapshot failed (%s)",
              _pid, strerror(errno));
        wait_status_failed = true;
        _monitor_recovery_failed = true;
    }
    if (wr > 0 && WIFSIGNALED(s)) {
        error("%s: process %d died during dump (no core written)",
              strsignal(WTERMSIG(s)), _pid);
        out.Close();
        if (unlink(corefile) != 0) {
            error("failed to remove partial acore %s (%s)", corefile, strerror(errno));
        }
        return WTERMSIG(s);
    }
    // B156: 目标在 dump 期间正常退出（exit()/main 返回，非信号）。原实现只查
    // WIFSIGNALED，WIFEXITED 落入下方 else 对已死 pid 做 pt_int/注入全失败、
    // return sig=0；末尾 drain 把已 pending 的目标退出 SIGCHLD 消费掉，monitor
    // 的 sigwaitinfo 永远等不到目标状态 → 永久挂起（实证 wchan=do_sigtimedwait）。
    // 显式清理部分 acore + 返回哨兵 -2，让 monitor 走清理退出路径。
    if (wr > 0 && WIFEXITED(s)) {
        error("process %d exited (code %d) during dump", _pid, WEXITSTATUS(s));
        out.Close();
        if (unlink(corefile) != 0) {
            error("failed to remove partial acore %s (%s)", corefile, strerror(errno));
        }
        return -2;
    }
    // tracee will stop if signaled on exit
    bool stopped_at_ptrace_event = false;
    // R50-50: SEIZE 下组停靠（SIGSTOP/TSTP/TTIN/TTOU）报为 PTRACE_EVENT_STOP（事件
    // 128），WSTOPSIG=SIGTRAP——与 FORK/CLONE 同属 ptrace 事件。B66 把"所有事件→
    // CONT 清除"泛化，对组停靠错误：CONT 会静默解除作业控制停靠（Ctrl+Z 后目标
    // 继续跑），且 monitor 的 leader_in_group_stop 不会置位。组停靠须 PTRACE_LISTEN
    // 保持停靠，等目标自身的 SIGCONT 恢复。
    bool group_stop_event = false;
    // B189: 注入期间 leader 崩溃（B158 fail-closed 检测到）后保留 delivery-stop——
    // 置位后下方 pt_cont 跳过（CONT(0) 会抑制崩溃信号、目标复活、崩溃丢失）。
    // relay_sig：被捕获崩溃的中继信号——延迟到 SETOPTIONS（清 TRACEFORK，需 leader
    // 停止）之后、pt_cont 段用 CONT(sig) 交付（立即 CONT 会让 SETOPTIONS 对运行中
    // leader 失败、TRACEFORK 残留 → 后续 fork 子进程被冻结）。
    bool crash_preserved = false;
    int relay_sig = 0;
    if(WIFSTOPPED(s)) {
        sig = WSTOPSIG(s);
        // B66: dump 窗口（pt_cont 后 TRACEFORK 仍设）内 leader 自己 fork 会触发
        // PTRACE_EVENT_FORK 停靠，WSTOPSIG 返回 SIGTRAP(5)——但这是 ptrace 事件
        // 停靠，不是真实信号。返回给 monitor 会被当中继信号投递 → 目标被 SIGTRAP
        // 杀死（实测 forker 目标 SIGUSR1 后死于 "Trace/breakpoint trap"）。
        // 泛化到所有 ptrace event（FORK/CLONE/EXEC/VFORK/EXIT）：wait status 的
        // 高字节含事件码即为事件停靠。事件停靠不算信号：清零，且结尾必须 CONT
        // 清除该事件停靠（否则 leader 冻结）。
        stopped_at_ptrace_event =
            (WIFSTOPPED(s) &&
             ((s >> 8) & 0xff) == SIGTRAP &&
             ((s >> 16) & 0xff) != 0);
        if (stopped_at_ptrace_event) {
            sig = 0;
            // R50-50: 识别 PTRACE_EVENT_STOP（组停靠）——见 stopped_at_ptrace_event
            // 声明处注释，与 FORK/CLONE 的事件处理分开。
            int ev = (int)((s >> 16) & 0xff);
            group_stop_event = (ev == PTRACE_EVENT_STOP);
            // B67: TRACEFORK auto-attach 的 fork 子进程残留在 arthur 上（TracerPid=arthur、
            // state=t），monitor 继续运行时不 CONT 它 → 永久冻结。GETEVENTMSG 拿子进程
            // pid 并 DETACH(0) 解冻，让它正常继续运行而不合成 SIGCONT。
            // R50-1: 只有 FORK/CLONE/VFORK（事件 1/2/3）才有 auto-attach 的子进程要
            // detach。EVENT_EXIT 的 GETEVENTMSG 是退出码（实测 exit(42)→0x2a00），
            // 把它当 pid 去 DETACH 会对无关进程发伪 ptrace 调用。
            if (ev == PTRACE_EVENT_FORK || ev == PTRACE_EVENT_VFORK || ev == PTRACE_EVENT_CLONE) {
                unsigned long child_pid = 0;
                if (ptrace(PTRACE_GETEVENTMSG, _pid, 0, &child_pid) != 0 ||
                    child_pid == 0) {
                    int event_errno = errno;
                    error("read auto-attached child from event %d on %d failed (%s)",
                          ev, _pid,
                          child_pid == 0 ? "invalid child pid" : strerror(event_errno));
                    // The child PID is the only handle needed to release the
                    // kernel's auto-attach stop. Do not publish or keep serving
                    // after losing that identity.
                    _monitor_recovery_failed = true;
                } else {
                    if (pt_detach((pid_t)child_pid) != 0 && errno != ESRCH) {
                        error("detach auto-attached fork child %lu failed (%s)",
                              child_pid, strerror(errno));
                        _monitor_recovery_failed = true;
                    } else {
                        info("detached auto-attached fork child %lu", child_pid);
                    }
                }
            }
        }
    } else {
        // now the process becomes zombie,
        // we have to waitpid the forked pid.
        // R50-1: pt_int 返回未检查——失败时 leader 未停住，注入 waitpid 跑在运行中
        // 目标上。acore 已有效，告警（child 可能残留 zombie）。
        if (pt_int(_pid) != 0) {
            error("re-interrupt of %d after snapshot failed (%s)",
                  _pid, strerror(errno));
            _monitor_recovery_failed = true;
        }
    }
    // B151: 目标在 dump 窗口内崩溃（真实信号 delivery-stop，非 ptrace 事件）。
    // 若仍做 waitpid 注入，pt_call 的 CONT(0) 会把 pending 的崩溃信号抑制掉
    // （与 H2 入口同机制），随后崩溃采集的 NT_SIGINFO 变成注入完成的假 SIGSEGV
    // ——实测 0xdeadbeef 崩溃 → core 报 si_addr=0、si_code 变注入值。崩溃停靠时
    // 跳过注入，保留真实崩溃现场（寄存器 + si_addr/si_code）供崩溃采集读取。
    // fork 子进程已在上方 SIGKILL，leader 崩溃后由其 reaper（init）收尸，无需注入。
    bool crashed_in_window =
        WIFSTOPPED(s) && !stopped_at_ptrace_event && is_core_dump_signal(sig);
    if (wait_status_failed) {
        // The status identity is unknown, so an injected libc call could
        // suppress a delivery stop or run from a ptrace event. The else branch
        // above has interrupted a running leader; only restore ptrace options
        // and resume it below, then fail the publication transaction.
        info("leader %d wait status unavailable; skipping waitpid injection", _pid);
    } else if (group_stop_event) {
        // R50-50: 组停靠 leader——waitpid 注入的 pt_call CONT(0) 会解除作业控制
        // 停靠。跳过注入，末尾用 LISTEN 保持停靠；fork 子进程已 SIGKILL（可能
        // 残留 zombie，等目标 SIGCONT 后自身 waitpid 回收，同 B73 告警情形）。
        info("leader %d in job-control group-stop during dump; skipping waitpid "
             "injection to preserve the stop", _pid);
    } else if (stopped_at_ptrace_event) {
        // The target's own fork/clone/exec/exit event is not a safe context for
        // an unrelated remote waitpid call. The snapshot child has already been
        // killed; resume this event after clearing TRACEFORK below.
        info("leader %d stopped at ptrace event during dump; skipping waitpid injection",
             _pid);
    } else if (crashed_in_window) {
        // B184: crashed_in_window 缺非默认信号处置检查（B168 对称遗漏）——dump 窗口内
        // leader 停在被捕获或忽略的 crash-class delivery-stop（handler 目标做 safepoint/
        // 崩溃上报）时，原实现跳过注入 + 返回崩溃信号 → 假崩溃采集 + kill_crashed
        // 重投后进程不死 + 静默放弃监控。非默认处置则中继，dump 正常完成返回 0；
        // 只有默认处置才是真崩溃，保留现场供崩溃采集。
        int disposition = signal_has_nondefault_disposition(_pid, sig);
        if (disposition != 0) {
            if (disposition < 0) {
                error("cannot determine disposition of %s during dump; "
                      "relaying and stopping monitor", strsignal(sig));
                _monitor_recovery_failed = true;
            }
            info("leader %d stopped at non-default %s during dump; relaying "
                 "(not crash collection)", _pid, strsignal(sig));
            if (ptrace(PTRACE_CONT, _pid, NULL, (uintptr_t)sig) != 0 &&
                errno != ESRCH) {
                error("relay %s to leader %d failed (%s)",
                      strsignal(sig), _pid, strerror(errno));
                _monitor_recovery_failed = true;
            }
            sig = 0;
        } else {
            info("leader %d crashed in %s delivery-stop during dump; "
                 "skipping waitpid injection to preserve crash stop",
                 _pid, strsignal(sig));
        }
    } else if (pt_getregs(_pid, &saved_regs) != 0) {
        error("save registers of %d for waitpid cleanup failed (%s)",
              _pid, strerror(errno));
        _monitor_recovery_failed = true;
    } else {
        // R50-50: leader 停靠时若处于可重启 syscall 的 -ERESTART* 返回点，CONT(0)
        // 会触发 syscall-restart（内核 ip-=2），注入的 waitpid 不执行、目标从
        // waitpid-2 跑垃圾代码（与 B16 的 mmap 注入同机制，但 waitpid 收尾路径
        // 只有 B73 的返回值告警、无 fail-closed）。跳过注入，fork 子进程可能
        // 残留 zombie（目标自身 waitpid 或退出时回收）。
        if (regs_has_restart_return(saved_regs)) {
            warn("leader %d captured in restartable syscall (rax=%lld); skipping "
                 "waitpid injection (fork child may linger as a zombie)",
                 _pid, (long long)saved_regs.get_rc());
        } else {
            uint64_t gv[3] = {(uint64_t)_core_pid, (uint64_t)NULL, 0};
            // R50-1: pt_call 返回未检查——目标中途死亡时 regs 未初始化，get_rc() 读垃圾。
            int wait_signal = 0;
            int wait_call = pt_call(_pid, &regs, r_waitpid, 3, gv, NULL,
                                    NULL, NULL, NULL, &wait_signal);
            if (wait_call != 0) {
                if (wait_call == PT_CALL_RECOVERY_FAILED) {
                    _monitor_recovery_failed = true;
                }
                warn("waitpid injection failed (target died?)");
                if (wait_signal != 0) {
                    relay_sig = wait_signal;
                    crash_preserved = true;
                }
            } else {
                info("waitpid = %d", (int)regs.get_rc());
                // B73 (Codex B2 review): 注入 waitpid 失败（B16 syscall-restart）时
                // 子进程作为目标 zombie 残留；如实报告。
                if (regs.get_rc() != (uint64_t)_core_pid) {
                    warn("injected waitpid returned %d (expected %d); child may linger "
                         "as a zombie (target likely in a restartable syscall)",
                         (int)regs.get_rc(), (int)_core_pid);
                }
            }
        }
        if (pt_setregs(_pid, &saved_regs) != 0) {
            error("restore registers of %d after waitpid cleanup failed (%s)",
                  _pid, strerror(errno));
            _monitor_recovery_failed = true;
        }
        // B189: 注入期间 leader 崩溃——B158 fail-closed 检测到 kill-SIGSEGV/ABRT/ILL
        //（si_code==SI_USER）后 leader 停在真实 delivery-stop，但原实现下方 pt_cont(0)
        // 把崩溃信号以 0 抑制 → 目标"复活"、崩溃 SIGCHLD 被收尾 drain 吞掉 → monitor
        // 挂起 + 崩溃丢失（实证：dump 窗口 kill -SEGV 落在 waitpid 注入 → "crash during
        // injection" 后 monitor 永久挂起）。用 GETSIGINFO 检测（崩溃 wait status 已被
        // pt_call 内部 pt_wait 消费，waitpid/detect_leader_death 拿不到）：leader 停在
        // crash-class delivery-stop → 保留停靠、返回信号走崩溃采集（与 crashed_in_window
        // 对齐）；被捕获则中继（B184）。
        siginfo_t inj_si;
        // B190: B189 的 GETSIGINFO 检查缺 si_code 区分——注入**完成**的 SIGSEGV 是
        // ret-to-0 页面 fault（si_code=SEGV_MAPERR/ACCERR），若目标无 SIGSEGV handler，
        // B189 把它误判为崩溃 → 假崩溃采集 + kill_crashed 杀掉健康目标（实证：正常
        // SIGUSR1 dump 触发假采集、目标死亡）。只有 kill/tkill 投递的崩溃
        //（si_code==SI_USER/SI_TKILL）才是真崩溃；同步 fault 在注入上下文=完成。
        if (ptrace(PTRACE_GETSIGINFO, _pid, 0, &inj_si) == 0 &&
            is_core_dump_signal(inj_si.si_signo) &&
            (inj_si.si_code == SI_USER || inj_si.si_code == SI_TKILL)) {
            int ic = inj_si.si_signo;
            int disposition = signal_has_nondefault_disposition(_pid, ic);
            if (disposition != 0) {
                if (disposition < 0) {
                    error("cannot determine disposition of %s after injection; "
                          "relaying and stopping monitor", strsignal(ic));
                    _monitor_recovery_failed = true;
                }
                info("leader %d stopped at non-default %s after injection; relaying "
                     "(not crash collection)", _pid, strsignal(ic));
                relay_sig = ic;   // 延迟到 SETOPTIONS 之后用 CONT(sig) 中继
                crash_preserved = true;
            } else {
                info("leader %d crashed in %s after injection; preserving crash stop "
                     "for crash collection", _pid, strsignal(ic));
                sig = ic;
                crash_preserved = true;
            }
        }
    }
    // B39: 本函数开头设了 PTRACE_O_TRACEFORK，若不清除则 monitor 继续运行时目标
    // 后续每个 fork 的子进程都被自动 attach+SIGSTOP 冻结（实证：state=t、
    // TracerPid=arthur）。SETOPTIONS 需 tracee 停止——此刻 leader 刚被 pt_attach
    // 停住，是清除的正确时机（放在 pt_cont 之前）。只清 TRACEFORK，保留
    // 恢复 monitor_threads 的 TRACEEXIT/TRACECLONE（去掉 TRACEFORK），
    // 避免 SETOPTIONS(0) 全清（B39）。
    rc = ptrace(PTRACE_SETOPTIONS, _pid, 0, _ptrace_options);
    if (rc != 0) {
        error("clear TRACEFORK on %d failed (%s)", _pid, strerror(errno));
        if (errno != ESRCH) {
            _monitor_recovery_failed = true;
        }
    }
    // B66: 事件停靠（PTRACE_EVENT_FORK）也必须 CONT 清除，否则 leader 冻结。
    // 普通 signal-delivery stop 由 monitor 的 signal_forkcore 中继恢复。
    if (group_stop_event) {
        // R50-50: 组停靠用 PTRACE_LISTEN 消费事件停靠并保持停靠（等目标自身的
        // SIGCONT 恢复），不是 CONT（CONT 会解除作业控制停靠、目标继续跑）。
        // 组停靠的 SIGCHLD 仍在队列，monitor 主循环会经 LISTEN 中继并置
        // leader_in_group_stop，后续 SIGUSR1 dump 被 H2 预检跳过。
        if (ptrace(PTRACE_LISTEN, _pid, NULL, NULL) != 0) {
            error("group-stop leader %d: PTRACE_LISTEN failed (%s)", _pid, strerror(errno));
            if (errno != ESRCH) {
                _monitor_recovery_failed = true;
            }
        }
    } else if (crash_preserved) {
        // B189: 注入后崩溃——保留 delivery-stop 供崩溃采集（不 CONT，避免 CONT(0)
        // 抑制崩溃信号）；被捕获则 CONT(sig) 中继走 handler（SETOPTIONS 已在 leader
        // 停止时清 TRACEFORK）。
        if (relay_sig) {
            if (ptrace(PTRACE_CONT, _pid, NULL, (uintptr_t)relay_sig) != 0 &&
                errno != ESRCH) {
                error("relay %s after injection to leader %d failed (%s)",
                      strsignal(relay_sig), _pid, strerror(errno));
                _monitor_recovery_failed = true;
            }
        }
    } else if(!WIFSTOPPED(s) || stopped_at_ptrace_event) {
        if (pt_cont(_pid) != 0 && errno != ESRCH) {
            error("resume leader %d after snapshot cleanup failed (%s)",
                  _pid, strerror(errno));
            _monitor_recovery_failed = true;
        }
    }

    info("Process %u paused %0.3f ms.", _pid, ts_pause.timediff()*1000);
    out.PrintStat();
    if (_monitor_recovery_failed) {
        error("forkcore_m: final monitor restoration failed; snapshot not published");
        out.Close();
        unlink(corefile);
        return -1;
    }
    // b167/b191: Close 返回关闭期错误（ENOSPC）；失败删除部分 acore，返回 -1
    // 让 monitor 走 "forkcore failed" 继续监控（目标已恢复运行）。
    if (commit_atomic_lz4(out, temp_corefile, final_corefile,
                          output_state) != 0) {
        error("forkcore_m: final close failed, partial acore removed");
        unlink(corefile);
        return -1;
    }

    // 不在这里消费 SIGCHLD 或 wait status。SIGCHLD 可以合并，但每个 ptrace stop
    // 都仍可由 monitor 的 waitpid 状态机读取；主循环会在下一次 dump 或阻塞等待前
    // 排空这些状态，因此收尾窗口事件不会丢失。组停靠则用专用哨兵直接同步状态。
    if (group_stop_event) {
        return GROUP_STOP_SENTINEL;
    }

    return sig;
}

/* monitor() will attach the target process
 * write out corefile on target exit on signal
 * SIGSEGV, SIGABRT, SIGILL; able to produce corefile
 * on SIGUSR1
 */
int Coredump::monitor(const char* corefile)
{
    int rc;
    // B201: 提前声明——attach 窗口崩溃检测可能 goto crash_collect，跨越这些变量
    // 的初始化（C++ goto 规则）。
    int exit_sig = 0;
    int signal_forkcore = 0;    // signal generated due to free section in forkcore
    unsigned dump_seq = 0;      // B58: SIGUSR1 dump 单调序号，避免同秒文件名覆盖
    bool dump_requested = false;
    // Job-control stop is a thread-group state. After the original leader has
    // called pthread_exit(), only a worker can report the ptrace stop/resume
    // notifications, so keying this state to tid == _pid loses the stop and a
    // SIGUSR1 snapshot can hang or resume the stopped process.
    bool process_in_group_stop = false;
    sigset_t mask;
    ScopedSignalMask signal_mask_guard;
    const std::string final_corefile(corefile);
    std::string temp_corefile;
    AtomicOutputState output_state;
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    _monitor_leader_exited = false;

    // Own termination signals synchronously before creating the temporary
    // output or seizing any tracee. The default SIGTERM/SIGINT action would
    // otherwise bypass both unlink and explicit ptrace detach.
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (signal_mask_guard.Block(mask) != 0) {
        error("cannot block monitor signals (%s)", strerror(errno));
        return -1;
    }

    rc = open_atomic_lz4(out, final_corefile.c_str(), temp_corefile,
                         output_state);
    if (rc < 0) {
        return -1;
    }
    corefile = temp_corefile.c_str();

    // write acore
    // R50-1: WriteFileHeader 返回未检查——缺头 acore 静默产出。
    if (WriteFileHeader(out) != 0) {
        error("write acore header failed");
        out.Close();
        unlink(corefile);
        return -1;
    }

    // Seize every current TID and enable TRACECLONE before any thread is
    // allowed to escape the monitored set. PTRACE_SEIZE is non-stopping, so
    // startup itself does not create an attach/CONT crash window.
    rc = monitor_threads(_pid);
    if (rc != 0) {
        error("monitor attach failed; process %d not traced", _pid);
        out.Close();
        unlink(corefile);
        return -1;
    }
    info("Launched in monitor mode");

    auto detach_monitored_threads = [&]() -> int {
        int detach_rc = 0;
        std::set<pid_t> pending = _monitor_tids;
        while (!pending.empty()) {
            pid_t tid = *pending.begin();
            pending.erase(pending.begin());

            int status = 0;
            bool synthetic_status = false;
            pid_t wr = waitpid(tid, &status, __WALL | WUNTRACED | WNOHANG);
            if (wr == 0) {
                user_regs64_struct stopped_regs;
                if (pt_getregs(tid, &stopped_regs) == 0) {
                    // The stop status was consumed by the failing operation;
                    // GETREGSET proves the tracee is still detach-ready.
                    status = (SIGSTOP << 8) | 0x7f;
                    synthetic_status = true;
                } else if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0) {
                    if (errno != ESRCH) {
                        warn("cannot interrupt monitored thread %d for detach (%s)",
                             tid, strerror(errno));
                        detach_rc = -1;
                    }
                    continue;
                } else {
                    status = pt_wait(tid);
                    if (status < 0) {
                        warn("monitored thread %d did not stop for detach", tid);
                        detach_rc = -1;
                        continue;
                    }
                }
            } else if (wr < 0) {
                if (errno != ECHILD && errno != ESRCH) {
                    warn("wait for monitored thread %d during detach failed (%s)",
                         tid, strerror(errno));
                    detach_rc = -1;
                }
                // A wait error does not prove the tracee is gone. Try the same
                // stopped/interrupt path used for an empty poll so cleanup does
                // not silently skip a still-owned TID.
                user_regs64_struct stopped_regs;
                if (pt_getregs(tid, &stopped_regs) != 0) {
                    if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0) {
                        if (errno != ESRCH) {
                            warn("cannot interrupt monitored thread %d after wait error (%s)",
                                 tid, strerror(errno));
                            detach_rc = -1;
                        }
                        continue;
                    }
                    status = pt_wait(tid);
                    if (status < 0) {
                        warn("monitored thread %d did not stop after wait error", tid);
                        detach_rc = -1;
                        continue;
                    }
                } else {
                    status = (SIGSTOP << 8) | 0x7f;
                    synthetic_status = true;
                }
            }

            int event = (status >> 16) & 0xffff;
            if (event == PTRACE_EVENT_CLONE) {
                unsigned long child = 0;
                if (ptrace(PTRACE_GETEVENTMSG, tid, 0, &child) == 0 && child != 0) {
                    pending.insert((pid_t)child);
                    _monitor_tids.insert((pid_t)child);
                } else {
                    int event_errno = errno;
                    warn("cannot read clone child from thread %d during detach (%s)",
                         tid, child == 0 ? "invalid child pid" : strerror(event_errno));
                    detach_rc = -1;
                }
            }

            int relay = 0;
            if (WIFSTOPPED(status) && event == 0 && !synthetic_status) {
                // Persistent monitoring uses PTRACE_SEIZE: Arthur's interrupt
                // and job-control stops carry PTRACE_EVENT_STOP. An event-zero
                // status is therefore a real delivery stop and its signal must
                // be relayed even when GETSIGINFO is unavailable during cleanup.
                relay = WSTOPSIG(status);
            }
            if (pt_detach(tid, relay) != 0 &&
                errno != ESRCH) {
                warn("detach monitored thread %d failed (%s)", tid, strerror(errno));
                detach_rc = -1;
            }
        }
        _monitor_tids.clear();
        return detach_rc;
    };

    // SIGCHLD is only a wakeup. ptrace event identity and ordering come from
    // waitpid statuses, which survive signal coalescing and retain event codes.
    auto drain_monitor_events = [&]() -> int {
        bool crash_found = (exit_sig != 0);
        auto resume = [&](pid_t tid, int sig) -> bool {
            if (ptrace(PTRACE_CONT, tid, 0, (uintptr_t)sig) == 0) {
                return true;
            }
            error("monitor: continue thread %d with signal %d failed (%s)",
                  tid, sig, strerror(errno));
            return false;
        };
        bool progress;
        do {
            progress = false;
            std::vector<pid_t> tids(_monitor_tids.begin(), _monitor_tids.end());
            for (pid_t tid : tids) {
                int status = 0;
                pid_t wr = waitpid(tid, &status, __WALL | WUNTRACED | WNOHANG);
                if (wr == 0 || (wr < 0 && errno == EINTR)) {
                    continue;
                }
                if (wr < 0) {
                    int wait_errno = errno;
                    if ((wait_errno == ECHILD || wait_errno == ESRCH) &&
                        kill(tid, 0) != 0 && errno == ESRCH) {
                        _monitor_tids.erase(tid);
                        if (tid == _pid) {
                            info("process %d disappeared without a waitable status", _pid);
                            return 2;
                        }
                        progress = true;
                        continue;
                    }
                    error("monitor: wait for thread %d failed (%s)",
                          tid, strerror(wait_errno));
                    return -1;
                }
                progress = true;

                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    int term_sig = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
                    _monitor_tids.erase(tid);
                    if (is_core_dump_signal(term_sig)) {
                        error("%s: thread %d exited before its fatal ptrace stop was collected",
                              strsignal(term_sig), tid);
                        return -1;
                    }
                    if (tid == _pid) {
                        if (term_sig) {
                            info("process %d terminated by %s", _pid, strsignal(term_sig));
                        } else {
                            info("process %d exited (code %d)", _pid, WEXITSTATUS(status));
                        }
                        return 2;
                    }
                    continue;
                }
                if (!WIFSTOPPED(status)) {
                    continue;
                }

                int sig = WSTOPSIG(status);
                int event = (status >> 16) & 0xffff;
                if (event == PTRACE_EVENT_CLONE) {
                    unsigned long child = 0;
                    if (ptrace(PTRACE_GETEVENTMSG, tid, 0, &child) != 0 || child == 0) {
                        error("cannot read clone event from thread %d (%s)",
                              tid, strerror(errno));
                        return -1;
                    }
                    pid_t child_tid = (pid_t)child;
                    // GETEVENTMSG establishes ptrace ownership. Record it before
                    // waiting so every error path can still detach the child.
                    _monitor_tids.insert(child_tid);
                    int child_status = pt_wait(child_tid);
                    if (child_status < 0) {
                        error("new thread %lu did not enter ptrace stop", child);
                        return -1;
                    }
                    int membership = belongs_to_thread_group(_pid, child_tid);
                    if (membership < 0) {
                        error("cannot determine thread-group identity of clone %d (%s)",
                              child_tid, strerror(errno));
                        return -1;
                    }
                    if (membership == 0) {
                        if (pt_detach(child_tid) != 0 &&
                            errno != ESRCH) {
                            error("cannot detach non-thread clone %d (%s)",
                                  child_tid, strerror(errno));
                            return -1;
                        }
                        _monitor_tids.erase(child_tid);
                        if (!crash_found && !resume(tid, 0)) {
                            return -1;
                        }
                        continue;
                    }
                    _monitor_tids.insert(child_tid);
                    if (!crash_found) {
                        if (!resume(tid, 0) || !resume(child_tid, 0)) {
                            return -1;
                        }
                    }
                    continue;
                }
                if (event == PTRACE_EVENT_EXIT) {
                    if (tid == _pid) {
                        // A thread-group leader may call pthread_exit while
                        // workers keep the process alive. It can no longer
                        // provide registers, but /proc/<tgid> remains the
                        // process identity until the final worker exits.
                        _monitor_leader_exited = true;
                    }
                    if (!crash_found && !resume(tid, 0)) {
                        return -1;
                    }
                    continue;
                }
                if (event != 0) {
                    if (event == PTRACE_EVENT_STOP &&
                        (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU)) {
                        if (ptrace(PTRACE_LISTEN, tid, 0, 0) != 0) {
                            error("monitor: listen on group-stopped thread %d failed (%s)",
                                  tid, strerror(errno));
                            return -1;
                        }
                        process_in_group_stop = true;
                    } else if (!crash_found) {
                        if (!resume(tid, 0)) {
                            return -1;
                        }
                    }
                    continue;
                }

                if (is_core_dump_signal(sig)) {
                    int disposition = signal_has_nondefault_disposition(_pid, sig);
                    if (disposition < 0) {
                        error("cannot determine disposition of %s for process %d; "
                              "relaying and stopping monitor", strsignal(sig), _pid);
                        resume(tid, sig);
                        return -1;
                    }
                    if (disposition > 0) {
                        info("thread %d signal %s has non-default disposition; relaying",
                             tid, strsignal(sig));
                        if (!resume(tid, sig)) {
                            return -1;
                        }
                    } else if (!crash_found) {
                        exit_sig = sig;
                        _monitor_crash_tid = tid;
                        crash_found = true;
                        info("thread %d stopped at fatal %s; freezing process",
                             tid, strsignal(sig));
                    }
                    continue;
                }

                if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
                    // With PTRACE_SEIZE, event==0 is the signal-delivery stop
                    // that initiates job control, not the completed group-stop.
                    // PTRACE_LISTEN is only valid after the later
                    // PTRACE_EVENT_STOP notification; using it here returns
                    // EIO and makes monitor abandon an otherwise healthy
                    // target. Relay the stop signal first and let the event
                    // branch above put every stopped thread into LISTEN.
                    if (!crash_found && !resume(tid, sig)) {
                        return -1;
                    }
                } else if (!crash_found) {
                    if (sig == SIGCONT) {
                        process_in_group_stop = false;
                    }
                    if (!resume(tid, sig)) {
                        return -1;
                    }
                }
            }
        } while (progress);
        return crash_found ? 1 : 0;
    };

    while (1) {
        int event_state = drain_monitor_events();
        if (event_state < 0) {
            if (detach_monitored_threads() != 0) {
                error("monitor event failure cleanup could not detach every thread");
            }
            out.Close();
            unlink(corefile);
            return -1;
        }
        if (event_state == 2) {
            out.Close();
            int unlink_rc = unlink(corefile);
            if (unlink_rc != 0 && errno != ENOENT) {
                error("failed to remove empty acore %s (%s)", corefile, strerror(errno));
                unlink_rc = -1;
            } else {
                unlink_rc = 0;
            }
            return unlink_rc == 0 ? 0 : -1;
        }
        if (event_state == 1) {
            break;
        }

        if (signal_forkcore != 0) {
            if (signal_forkcore == -2) {
                info("process %d exited during SIGUSR1 dump", _pid);
                int detach_rc = detach_monitored_threads();
                out.Close();
                int unlink_rc = unlink(corefile);
                if (unlink_rc != 0 && errno != ENOENT) {
                    error("failed to remove monitor temporary output %s (%s)",
                          corefile, strerror(errno));
                    unlink_rc = -1;
                } else {
                    unlink_rc = 0;
                }
                return (detach_rc == 0 && unlink_rc == 0) ? 0 : -1;
            }
            if (signal_forkcore == GROUP_STOP_SENTINEL) {
                process_in_group_stop = true;
                signal_forkcore = 0;
                continue;
            }
            if (signal_forkcore < 0) {
                info("forkcore failed (%d), continue monitoring", signal_forkcore);
                signal_forkcore = 0;
                continue;
            }
            if (is_core_dump_signal(signal_forkcore)) {
                exit_sig = signal_forkcore;
                if (_monitor_crash_tid == 0) {
                    _monitor_crash_tid = _pid;
                }
                break;
            }
            if (ptrace(PTRACE_CONT, _pid, 0,
                       (uintptr_t)signal_forkcore) != 0 && errno != ESRCH) {
                error("monitor: continue leader %d after SIGUSR1 dump failed (%s)",
                      _pid, strerror(errno));
                detach_monitored_threads();
                out.Close();
                unlink(corefile);
                return -1;
            }
            signal_forkcore = 0;
            continue;
        }

        if (dump_requested) {
            dump_requested = false;
            if (process_in_group_stop) {
                info("process in group-stop; skipping SIGUSR1 dump "
                     "(resume with SIGCONT and retry)");
                continue;
            }
            char dump_name[64];
            std::string dump_directory;
            const char *slash = strrchr(corefile, '/');
            if (slash) {
                dump_directory.assign(corefile, slash == corefile ? 1 :
                                      (size_t)(slash - corefile));
                if (dump_directory[dump_directory.size() - 1] != '/') {
                    dump_directory.push_back('/');
                }
            }
            std::string dump_path;
            const unsigned dump_time = (unsigned)time(NULL);
            for (int attempt = 0; attempt < 10000; attempt++) {
                snprintf(dump_name, sizeof(dump_name), "acore.%u.%u.%u",
                         (unsigned)_pid, dump_time, dump_seq++);
                dump_path = dump_directory;
                dump_path.append(dump_name);
                struct stat existing;
                if (lstat(dump_path.c_str(), &existing) != 0) {
                    if (errno == ENOENT) {
                        break;
                    }
                    error("cannot inspect SIGUSR1 snapshot path %s (%s)",
                          dump_path.c_str(), strerror(errno));
                    dump_path.clear();
                    break;
                }
                dump_path.clear();
            }
            if (dump_path.empty()) {
                error("cannot allocate a unique SIGUSR1 snapshot name");
                continue;
            }
            info("writing out %s...", dump_path.c_str());
            signal_forkcore = forkcore_m(dump_path.c_str(), false);
            info("writing out acore finished, resume monitoring");
            if (_monitor_recovery_failed) {
                error("SIGUSR1 snapshot could not restore every monitored thread");
                detach_monitored_threads();
                out.Close();
                unlink(corefile);
                return -1;
            }
            continue;
        }

        siginfo_t wake;
        int signo;
        do {
            signo = sigwaitinfo(&mask, &wake);
        } while (signo < 0 && errno == EINTR);
        if (signo < 0) {
            error("monitor sigwaitinfo failed (%s)", strerror(errno));
            detach_monitored_threads();
            out.Close();
            unlink(corefile);
            return -1;
        }
        if (signo == SIGUSR1) {
            dump_requested = true;
        } else if (signo == SIGTERM || signo == SIGINT) {
            info("monitor received %s; detaching from process %d",
                 strsignal(signo), _pid);
            int detach_rc = detach_monitored_threads();
            int close_rc = out.Close();
            if (unlink(corefile) != 0 && errno != ENOENT) {
                error("failed to remove monitor temporary output %s (%s)",
                      corefile, strerror(errno));
                close_rc = -1;
            }
            return (detach_rc == 0 && close_rc == 0) ? 0 : -1;
        }
    }

    info("%s: process %d exit", strsignal(exit_sig), _pid);
    info("Writing out corefile...");

    // N1: 崩溃采集路径必须清空跨调用累积的 _phdrs——SIGUSR1 dump（forkcore_m）
    // 之后 _phdrs 已有该次 dump 的 LOAD 段；若不清空，本次崩溃 WriteLoads 再
    // push 一组，ELF 块出现 2× 幻影 phdr，解压时 loads 字节数与 phdr 声明和
    // 不符直接拒绝（实证：wrote 17739776 / phdrs 35479552）。与 B35 在
    // generate/forkcore/forkcore_m 入口的清理保持一致。
    _phdrs.clear();
    _core_pid = 0;
    // 崩溃采集时所有线程的 PRSTATUS 使用进程崩溃信号；THREAD 中原始 siginfo
    // 保持不变，因此 worker 的 attach SIGSTOP 不会污染进程级崩溃语义。
    _crash_sig = exit_sig;

    // R50-6: 崩溃采集的失败路径同样要让崩溃进程死亡——成功路径末尾对每个线程
    // PTRACE_DETACH(exit_sig) 重投崩溃信号；失败路径若只 detach(NULL) 或直接
    // return，leader 停在崩溃信号 delivery-stop，内核自动 detach 不重投信号，
    // 进程既不运行也不死亡，滞留冻结。统一走这个 kill_crashed。
    auto kill_crashed = [&]() -> int {
        std::vector<pid_t> tids;
        if (!_monitor_tids.empty()) {
            tids.assign(_monitor_tids.begin(), _monitor_tids.end());
        } else {
            tids = _process._thrd_pid;
        }
        bool detach_failed = false;
        for (pid_t tid : tids) {
            if (_monitor_leader_exited && tid == _pid) {
                continue;
            }
            if (pt_detach(tid, exit_sig) != 0 &&
                errno != ESRCH) {
                error("detach crashed thread %d with %s failed (%s)",
                      tid, strsignal(exit_sig), strerror(errno));
                detach_failed = true;
            }
        }
        if (detach_failed && kill(_pid, exit_sig) != 0 && errno != ESRCH) {
            error("fallback delivery of %s to crashed process %d failed (%s)",
                  strsignal(exit_sig), _pid, strerror(errno));
            _monitor_tids.clear();
            return -1;
        }
        _monitor_tids.clear();
        return detach_failed ? -1 : 0;
    };

    // get all threads pid（attach 全部非主线程，剔除已退出的）
    // B77: collect_threads 失败（opendir / 非 ESRCH attach 错误）时 fail-closed。
    if (collect_threads(_pid) != 0) {
        error("failed to collect threads of %d", _pid);
        kill_crashed();
        out.Close();
        unlink(corefile);
        return -1;
    }

    ProcMaps maps;
    // N4: 崩溃路径 /proc 读失败时目标已死，无法重试；报错并清理空 acore。
    pid_t process_source = _monitor_leader_exited ? _monitor_crash_tid : _pid;
    if (WriteProcessMeta(out, maps, process_source) != 0) {
        error("write process meta failed for crashed process");
        kill_crashed();
        out.Close();
        unlink(corefile);
        return -1;
    }

    // GDB selects the first NT_PRSTATUS as the current thread. Serialize the
    // actual crashing TID first, while fill_prpsinfo independently uses the
    // leader metadata for process identity.
    bool crash_tid_present = false;
    for (pid_t tid : _process._thrd_pid) {
        if (tid == _monitor_crash_tid) {
            crash_tid_present = true;
            break;
        }
    }
    if (!crash_tid_present ||
        WriteThreadMeta(out, _monitor_crash_tid, _monitor_crash_tid == _pid) != 0) {
        error("write crashing thread meta failed (tid=%d)", _monitor_crash_tid);
        kill_crashed();
        out.Close();
        unlink(corefile);
        return -1;
    }
    if (!_monitor_leader_exited && _monitor_crash_tid != _pid &&
        WriteThreadMeta(out, _pid, true) != 0) {
        error("write leader thread meta failed");
        kill_crashed();
        out.Close();
        unlink(corefile);
        return -1;
    }
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == _pid || tid == _monitor_crash_tid)
            continue;

        if (WriteThreadMeta(out, tid) != 0) {
            error("write thread meta of %d failed", tid);
            kill_crashed();
            out.Close();
            unlink(corefile);
            return -1;
        }
    }
    // write acore
    {
        // B65: 崩溃路径 /proc/pid/mem 读不到时报错并清理，不产出空 core。
        if (WriteLoads(out, process_source, maps) != 0) {
            error("failed to dump memory of crashed process %d", _pid);
            kill_crashed();
            out.Close();
            unlink(corefile);
            return -1;
        }
        // B69: ELF 块写入失败时清理。
        if (WriteElfHeader(out) != 0) {
            error("failed to write elf header for crashed process");
            kill_crashed();
            out.Close();
            unlink(corefile);
            return -1;
        }
        // R50-6: 尾标写失败同 B69——缺结束标记的解压必拒，清理残缺 acore。
        if (WriteTailMark(out) != 0) {
            error("failed to write tail mark (disk full?)");
            kill_crashed();
            out.Close();
            unlink(corefile);
            return -1;
        }
    }

    if (kill_crashed() != 0) {
        error("monitor crash dump: could not release every crashed tracee; "
              "snapshot not published");
        out.Close();
        unlink(corefile);
        return -1;
    }
    out.PrintStat();
    // b167/b191: Close 返回关闭期错误（ENOSPC）；失败删除部分 core
    if (commit_atomic_lz4(out, temp_corefile, final_corefile,
                          output_state) != 0) {
        error("monitor crash dump: final close failed, core removed");
        unlink(corefile);
        return -1;
    }
    return 0;
}

int Coredump::decompress(const char* in_file, const char* out_core)
{
    int rc = 0;
    // R50-18: 与采集函数入口风格一致——同一 Coredump 先 generate() 再 decompress()
    // 时 _phdrs 残留陈旧 LOAD 段（cleanup_decompress 只在末尾清）。预算校验能兜底，
    // 但入口清空避免幻影 phdr 混入。
    _phdrs.clear();
    Lz4Stream in(Lz4Stream::LZ4_Decompress);
    rc = in.Open(in_file);
    if (rc < 0) {
        return -1;
    }
    rc = VerifyFileHeader(in);
    if (rc != 0) {
        return rc;
    }

    // load meta
    rc = ReadMeta(in);
    if (rc != 0) {
        // ReadMeta 可能已分配部分 ProcFiles（cmdline/auxv/maps），
        // 提前返回前要清理，否则损坏输入路径泄漏。
        cleanup_decompress();
        return rc;
    }
    
    char fpath[PATH_MAX];
    if (!out_core) {
        snprintf(fpath, sizeof(fpath), "core.%u", _pid);
        out_core = fpath;
    }
    // R50-20 (#2): input and output aliases are never a valid conversion.
    if (same_file(in_file, out_core)) {
        error("decompress: input and output are the same file (%s)", in_file);
        cleanup_decompress();
        return -1;
    }
    const std::string final_out_core(out_core);
    std::string temp_out_core;
    AtomicOutputState output_state;
    FILE *fout = open_atomic_file(final_out_core.c_str(), temp_out_core,
                                  output_state);
    if (!fout) {
        error("Fail to open file %s", final_out_core.c_str());
        // B50 残留: ReadMeta 已分配 ProcFiles/decoders/线程 _d_stat，
        // fopen 失败提前返回时未清理 → LeakSanitizer 报 8999 字节泄漏。
        cleanup_decompress();
        return -1;
    }
    off_t p_elf = ftello(fout);

    // Write beside the requested path and rename only after every validation,
    // flush, fsync and close succeeds. A failed conversion therefore cannot
    // destroy a previously valid output.
    auto fail_core = [&]() -> int {
        in.Close();
        if (fout) {
            fclose(fout);
            fout = NULL;
        }
        unlink(temp_out_core.c_str());
        cleanup_decompress();
        return -1;
    };

    if (p_elf < 0) {
        error("cannot determine output core position (%s)", strerror(errno));
        return fail_core();
    }

    // parse
    // B163: ParseAll 失败（maps 超 region 上限等损坏 acore）时 fail-closed。
    if (_process.ParseAll() != 0) {
        error("parse /proc data failed (acore corrupt), core removed");
        return fail_core();
    }

    std::vector<Elf64_Phdr> expected_loads;
    size_t expected_load_bytes = 0;
    if (expected_load_phdrs(*_process._d_maps, expected_loads,
                            expected_load_bytes) != 0 || expected_loads.empty()) {
        error("cannot derive LOAD layout from maps (acore corrupt)");
        return fail_core();
    }

    // make room for elf headers
    size_t phnum = expected_loads.size() + 1;
    // Arthur does not emit PN_XNUM, so a valid input can never require the
    // reserved 0xffff e_phnum value. Reject it before allocating notes or
    // reserving tens of megabytes for a core that cannot be represented.
    if (phnum >= 0xFFFF) {
        error("maps count %zu exceeds ELF program-header limit", phnum - 1);
        return fail_core();
    }
    size_t phdr_bytes = 0;
    size_t hdr_size = 0;
    size_t with_slack = 0;
    if (__builtin_mul_overflow(phnum, sizeof(Elf64_Phdr), &phdr_bytes) ||
        __builtin_add_overflow(sizeof(Elf64_Ehdr), phdr_bytes, &hdr_size) ||
        __builtin_add_overflow(hdr_size, (size_t)4096, &with_slack) ||
        __builtin_add_overflow(with_slack, (size_t)4095, &hdr_size)) {
        error("ELF header reservation size overflows size_t");
        return fail_core();
    }
    hdr_size &= ~(size_t)4095;
    dprint("room = %zu", hdr_size);
    rc = makeroom(fout, hdr_size);
    if (rc < 0) {
        error("make room for elf headers failed, core removed");
        return fail_core();
    }
    off_t p_note = ftello(fout);
    if (p_note < 0) {
        error("cannot determine note offset (%s)", strerror(errno));
        return fail_core();
    }

    // makeup notes
    int notes_size = GenerateNotes();
    if (notes_size < 0) {
        error("generate required ELF notes failed, core removed");
        return fail_core();
    }
    Elf64_Phdr note_phdr = {0};
    note_phdr.p_type = PT_NOTE;
    note_phdr.p_offset = (uint64_t)p_note;
    note_phdr.p_filesz = notes_size;
    _phdrs.push_back(note_phdr);

    for (Note* nt : _notes) {
        ssize_t len;
        len = fwrite(nt->_data, 1, nt->_size, fout);
        // B54: 输出磁盘满时 fwrite 可能短写，原 assert 直接 abort。
        if (len != (ssize_t)nt->_size) {
            error("write note failed (%ld != %zu), disk full? core removed", len, nt->_size);
            return fail_core();
        }
    }
    _offset_load = ftello(fout);
    if (_offset_load < 0) {
        error("cannot determine LOAD offset (%s)", strerror(errno));
        return fail_core();
    }

    // write loads
    // B54: 截断 acore 使 ReadLoads 失败时不再 assert abort，干净报错。
    // B60: ReadLoads 返回 ssize_t（实际写出的未压缩字节数）——>2GB 的合法
    // dump 若用 int 返回会被截断成负数误判为失败（实证：3.2GB dump 被拒）。
    ssize_t loads_rc = ReadLoads(in, fout, expected_load_bytes);
    if (loads_rc < 0) {
        error("read loads failed, core incomplete (removed)");
        return fail_core();
    }
    size_t loads_written = (size_t)loads_rc;

    // write elf header
    // ReadElfHeader 失败（损坏 acore 缺 ELF 块）时 _phdrs 为空，写出的 core 无
    // LOAD 段；检查返回值，报错而非产出残缺 core。
    // R50-7: 预算上限（maps 条目 + 1 note）传入读循环，构造 acore 在分配
    // 海量 phdr 前即被拒（原实现读完后才检查）。
    rc = ReadElfHeader(in, expected_loads.size() + 1);
    if (rc != 0) {
        error("read elf header failed, core incomplete (removed)");
        return fail_core();
    }
    // R50-1: ELF 块 phdr 数超过 maps 预算时，WriteElfHeader 会写穿 makeroom 预留的
    // hdr_size 覆盖 note 数据。构造 acore 可携带任意多 phdr（p_filesz=0 绕过下面
    // 的 loads/expected 校验）；校验总 phdr 数 <= maps 条目 + 1（note）。
    if (_phdrs.size() != expected_loads.size() + 1 ||
        _ehdr.e_phnum != expected_loads.size()) {
        error("ELF LOAD count %zu/header %u differs from maps-derived count %zu",
              _phdrs.size() - 1, _ehdr.e_phnum, expected_loads.size());
        return fail_core();
    }
    for (size_t i = 0; i < expected_loads.size(); i++) {
        const Elf64_Phdr& actual = _phdrs[i + 1];
        const Elf64_Phdr& expected_ph = expected_loads[i];
        if (actual.p_type != expected_ph.p_type ||
            actual.p_flags != expected_ph.p_flags ||
            actual.p_offset != expected_ph.p_offset ||
            actual.p_vaddr != expected_ph.p_vaddr ||
            actual.p_paddr != expected_ph.p_paddr ||
            actual.p_filesz != expected_ph.p_filesz ||
            actual.p_memsz != expected_ph.p_memsz ||
            actual.p_align != expected_ph.p_align) {
            error("ELF LOAD %zu differs from maps-derived layout (acore corrupt)", i);
            return fail_core();
        }
    }

    // 校验：读侧实际写出的 LOAD 字节数 == acore ELF 块 phdr 声明的 p_filesz 之和。
    // 写侧 p_filesz 是每个 region 实际写入的未压缩字节数（含 pread 失败时的部分），
    // 二者应严格相等；不一致说明 LOADS 块被 bit-flip 成了合法但不同长度的 LZ4 流，
    // 静默写错 core 比报错更危险。
    // R50-7: 构造 phdr 可声明 p_filesz=2^64-1，多个求和回绕后撞上真实 loads_written
    // 绕过校验——用溢出检测代替裸累加（真实 dump 的字节和远小于 2^64）。
    size_t expected = 0;
    // B155: 连续 LOAD 的 p_offset 必须与前一个的 p_offset+p_filesz 相接（首个为 0）。
    // 写侧 p_offset 是累计未压缩字节恒连续；构造 acore 可误报各 region 的 p_filesz
    // 使总和仍等于 loads_written（过 B117/上面的和校验），但 gdb 无报错加载时区域
    // 内容错位/成洞（实证：region 尾部填下个 region 字节）。fail-closed。
    uint64_t prev_load_end = 0;
    for (const auto& phdr : _phdrs) {
        if (phdr.p_type == PT_LOAD) {
            size_t next;
            if (__builtin_add_overflow(expected, phdr.p_filesz, &next)) {
                error("phdr p_filesz sum overflows size_t (acore corrupt, core removed)");
                return fail_core();
            }
            expected = next;
            // R50-13: 校验单个 LOAD 的 p_offset 边界——构造 acore 可把 p_offset
            // 设成接近 2^64 的值，`p_offset += _offset_load` 回绕后指向输出 core 的
            // ehdr/note 区（gdb 把 note 当内存读）。真实写侧 p_offset 恒 < loads 流长。
            // 用 uint64 溢出检测：p_offset 是 uint64，_offset_load 是 long（恒 ≥0）。
            if (phdr.p_offset > loads_written ||
                phdr.p_filesz > loads_written - (size_t)phdr.p_offset) {
                error("phdr p_offset %lu + filesz %lu exceeds loads %lu (acore corrupt, core removed)",
                      (unsigned long)phdr.p_offset, (unsigned long)phdr.p_filesz,
                      (unsigned long)loads_written);
                return fail_core();
            }
            if (phdr.p_offset != prev_load_end ||
                phdr.p_offset + phdr.p_filesz < phdr.p_offset) {
                error("phdr p_offset %lu not contiguous after prev end %lu (acore corrupt, core removed)",
                      (unsigned long)phdr.p_offset, (unsigned long)prev_load_end);
                return fail_core();
            }
            if ((uint64_t)_offset_load >
                std::numeric_limits<uint64_t>::max() - phdr.p_offset) {
                error("phdr output offset overflows ELF64 range (acore corrupt, core removed)");
                return fail_core();
            }
            prev_load_end = phdr.p_offset + phdr.p_filesz;
        }
    }
    if (loads_written != expected) {
        error("loads size mismatch: wrote %lu bytes, phdrs declare %lu (acore corrupt, core removed)",
              loads_written, expected);
        return fail_core();
    }
    if (fseeko(fout, p_elf, SEEK_SET) != 0) {
        error("seek to ELF header failed (%s), core removed", strerror(errno));
        return fail_core();
    }
    rc = WriteElfHeader(fout);
    if (rc < 0) {
        error("write elf header to core failed, core removed");
        return fail_core();
    }

    // B161: decompress 校验尾标——ReadElfHeader 在 ELF 块后 break 未消费尾标，
    // 生产路径从不验证 acore 以 TailMark 收尾（test_decompress 已要求 TailSeen，
    // B135）。缺尾标（截断在尾标边界/损坏）的 acore 被静默当完整接受（实证：去掉
    // 末尾 3 字节仍返回 0）。此处显式读尾标，缺失/类型错即 fail-closed。
    {
        BlockHeader tail_hdr;
        Block* tail_block = in.ReadBlock(tail_hdr);
        if (tail_block != NULL || !in.TailSeen()) {
            error("acore missing tail mark (truncated), core removed");
            return fail_core();
        }
        if (in.VerifyPhysicalEof() != 0) {
            error("acore has trailing data after tail mark, core removed");
            return fail_core();
        }
    }

    in.Close();
    // Closing can surface delayed ENOSPC. Commit only after the temporary core
    // is durable; commit_atomic_file leaves an existing destination untouched
    // on every pre-rename failure.
    if (commit_atomic_file(fout, temp_out_core, final_out_core,
                           output_state) != 0) {
        return fail_core();
    }
    cleanup_decompress();
    info("saved corefile '%s'.", final_out_core.c_str());
    return 0;
}

// B50: decompress 一次性泄漏——GetFile 的 ProcFiles、ParseAll 的 decoders、
// 线程 _d_stat、GenerateNotes 的 Note 对象均未释放。按依赖顺序清理。
void Coredump::cleanup_decompress()
{
    for (Note* nt : _notes) {
        delete nt;      // ~Note 释放 _data
    }
    _notes.clear();

    if (_process._d_maps) { delete _process._d_maps; _process._d_maps = NULL; }
    if (_process._d_cmdline) { delete _process._d_cmdline; _process._d_cmdline = NULL; }
    if (_process._d_auxv) { delete _process._d_auxv; _process._d_auxv = NULL; }
    if (_process._d_stat) { delete _process._d_stat; _process._d_stat = NULL; }
    for (auto& t : _process._threads) {
        if (t._d_stat) { delete t._d_stat; t._d_stat = NULL; }
        if (t._stat) { free(t._stat); t._stat = NULL; }   // GetFile malloc'd
    }

    ProcFile* pfs[] = { _process._cmdline, _process._auxv, _process._maps,
                        _process._environ, _process._io, _process._limits,
                        _process._stat };
    for (ProcFile* pf : pfs) {
        if (pf) {
            free(pf);
        }
    }
    _process._cmdline = _process._auxv = _process._maps = NULL;
    _process._environ = _process._io = _process._limits = NULL;
    _process._stat = NULL;
    _process._uid = 0;
    _process._gid = 0;
    _process._credentials_valid = false;
    _crash_sig = 0;

    // b50 (Codex review): 未清空 _threads/_phdrs——同一 Coredump 重复 decompress()
    // 会保留上一次的线程向量与段头，第二次采集叠加出幻影 phdr/线程。清空以便复用。
    _process._threads.clear();
    _phdrs.clear();
}

int Coredump::test_compress(const char* in_file, const char* out_file)
{
    int rc = 0;
    // R50-20 (#2): input and output aliases are never a valid conversion.
    if (same_file(in_file, out_file)) {
        error("test_compress: input and output are the same file (%s)", in_file);
        return -1;
    }
    FILE *fin = fopen(in_file, "rb");
    if (!fin) {
        error("Fail to open file %s", in_file);
        return -1;
    }

    const std::string final_out_file(out_file);
    std::string temp_out_file;
    AtomicOutputState output_state;
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = open_atomic_lz4(out, final_out_file.c_str(), temp_out_file,
                         output_state);
    if (rc < 0) {
        // R50-6: out 打开失败时 fin 已 fopen，泄漏输入 fd。
        fclose(fin);
        return -1;
    }
    if (out.WriteRaw(TEST_STREAM_MAGIC, sizeof(TEST_STREAM_MAGIC)) !=
        (int)sizeof(TEST_STREAM_MAGIC)) {
        error("write compressed stream header failed");
        rc = -1;
    }
    if (out.EnableBlockChecksums() != 0 ||
        out.SetBlock(BLOCK_TYPE_STREAM) != 0) {
        error("initialize compressed test stream failed");
        rc = -1;
    }

    char buf[4*1024];
    while (rc == 0) {
        size_t len = fread(buf, 1, sizeof(buf), fin);
        if (len == 0) {
            // B22: fread==0 不只有 EOF——真实 I/O 错误（ferror）也返回 0。
            // b22 (Codex review): 只有 feof 才是正常结束；ferror 时须报错并返回
            // 非零，否则调用者会把空/截断输出当成成功的压缩结果。
            if (ferror(fin)) {
                error("read failed (%s)", strerror(errno));
                rc = -1;
            }
            break;
        }
        for (size_t i=0; i<len; i+= BLOCK_SIZE) {
            size_t j = MIN(len - i, BLOCK_SIZE);
            // B78/B70: Write 可因磁盘满返回 -1；用显式检查代替 assert（NDEBUG
            // 下 assert 消失，失败会静默丢数据）。原 data_size += len 误放内层
            // 循环，多块读时把同一段字节重复计数（只影响日志，一并修正）。
            int wrc = out.Write((const char*)(buf+i), j);
            if (wrc <= 0) {
                error("compress write failed (%d)", wrc);
                rc = -1;
                goto flush_and_close;
            }
        }

        if (len < sizeof(buf)) {
            // 短读可能伴随 I/O 错误；ferror 时不能当正常结束。
            if (ferror(fin)) {
                error("read failed (%s)", strerror(errno));
                rc = -1;
            }
            break;
        }
    }

flush_and_close:
    if (rc == 0 && out.Flush() < 0) {
        error("compress flush failed");
        rc = -1;
    }
    // R50-6: 尾标写失败（磁盘满）时输出缺结束标记，解压必拒；与 rc 一并传播。
    if (rc == 0 && WriteTailMark(out) != 0) {
        rc = -1;
    }
    fclose(fin);

    if (rc == 0) {
        if (commit_atomic_lz4(out, temp_out_file, final_out_file,
                              output_state) != 0) {
            rc = -1;
        }
    } else {
        out.Close();
        unlink(temp_out_file.c_str());
    }

    if (rc == 0) {
        out.PrintStat();
    }

    return rc;
}

int Coredump::test_decompress(const char* in_file, const char* out_file)
{
    int rc = 0;
    // R50-20 (#2): input and output aliases are never a valid conversion.
    if (same_file(in_file, out_file)) {
        error("test_decompress: input and output are the same file (%s)", in_file);
        return -1;
    }
    Lz4Stream in(Lz4Stream::LZ4_Decompress);
    rc = in.Open(in_file);
    if (rc < 0) {
        return -1;
    }

    char stream_magic[sizeof(TEST_STREAM_MAGIC)];
    int peek_rc = in.Peek(stream_magic, sizeof(stream_magic));
    if (peek_rc < 0) {
        error("test_decompress requires a seekable input file");
        in.Close();
        return -1;
    }
    bool typed_stream = false;
    if (peek_rc == (int)sizeof(stream_magic) &&
        memcmp(stream_magic, TEST_STREAM_MAGIC, sizeof(stream_magic)) == 0) {
        if (in.ReadRaw(stream_magic, sizeof(stream_magic)) != (int)sizeof(stream_magic)) {
            error("read compressed stream header failed");
            in.Close();
            return -1;
        }
        if (in.EnableBlockChecksums() != 0) {
            error("initialize checksummed input stream failed");
            in.Close();
            return -1;
        }
        typed_stream = true;
    }

    const std::string final_out_file(out_file);
    std::string temp_out_file;
    AtomicOutputState output_state;
    FILE *fout = open_atomic_file(final_out_file.c_str(), temp_out_file,
                                  output_state);
    if (!fout) {
        error("Fail to open file %s", final_out_file.c_str());
        in.Close();
        return -1;
    }
   
    size_t file_size = 0;
    BlockHeader hdr;
    for (;;) {
        Block* block = in.ReadBlock(hdr);
        if (!block) {
            // R50-1: ReadBlock NULL 不只是干净 EOF——块头短读/数据截断/size 超限/
            // 解压失败/真实 I/O 错误都返回 NULL。只有块边界 EOF/尾标（LastReadClean）
            // 才是正常结束；否则是损坏/截断流，报错返回非零。
            // R50-20: LastReadClean 还不够——块边界 EOF（尾标缺失 / 0 字节文件）也
            // 置 clean。合法 test_compress 输出恒以尾标收尾；块边界 EOF 只来自整块
            // 截断。要求确实读到尾标才算成功（空输入往返也满足：空压缩产物有尾标）。
            if (!in.LastReadClean() || !in.TailSeen()) {
                error("decompress stream corrupt or truncated%s",
                      in.LastReadClean() ? " (tail mark missing)" : "");
                rc = -1;
            } else if (in.VerifyPhysicalEof() != 0) {
                rc = -1;
            }
            break;
        }
        if (typed_stream && hdr.block_type != BLOCK_TYPE_STREAM) {
            error("expected STREAM block, got type %u (compressed stream corrupt)",
                  hdr.block_type);
            rc = -1;
            break;
        }

        ssize_t len = fwrite(block->rBuf(), 1, block->Size(), fout);
        if (len != (ssize_t)block->Size()) {
            error("write failed (disk full?)");
            rc = -1;
            break;
        }
        file_size += len;
    }
    in.Close();

    if (rc == 0) {
        if (commit_atomic_file(fout, temp_out_file, final_out_file,
                               output_state) != 0) {
            rc = -1;
        }
    } else {
        fclose(fout);
        fout = NULL;
        unlink(temp_out_file.c_str());
    }

    if (rc == 0) {
        info("write %lu bytes.", file_size);
    }
    return rc;
}

}; // arthur
