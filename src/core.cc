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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <assert.h>
#include <fcntl.h>      // open
#include <errno.h>      // errno (PEEKDATA 判读)
#include <dlfcn.h>      // dlsym
#include <dirent.h>     // readdir

#include <sstream>
#include <iterator>

#include "core.h"
#include "proc.h"

// arthur only use a memory of BUFFER_SIZE on main stack.
#define BUFFER_SIZE 1L*1024*1024         // general buffer size to store data
#define ARTHUR_BUFFER_SIZE 2L*1024*1024  // take up 2M physical memory on stack

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
    // B53: PATH_MAX 在 inc.h 被压到 128，深容器/长路径的 maps 行会被 fgets 截断，
    // "libc" 出现在截断点之后 → 找不到 → B11 符号解析失败。缓冲提到 4096。
    const int MAPS_BUF = 4096;
    char line[MAPS_BUF];
    char base[MAPS_BUF];
    char name[MAPS_BUF];
    uint64_t r_addr = 0;
    size_t cur, start;

    // this proc
    if (pid == -1) {
        pid = getpid();
    }

    snprintf(name, sizeof(name), "/proc/%u/maps", pid);
    FILE *f = fopen(name, "r");
    if (!f) {
        return 0;
    }
    while (!feof(f)) {
        // read line
        fgets(line, sizeof(line), f);

        // find path
        cur = 0;
        while (line[cur] && line[cur]!='/') {
            cur++;
        }

        // not found
        if (line[cur] != '/') {
            continue;
        }

        // read file name
        start = cur;
        while (line[cur] && (cur - start) < (sizeof(name) - 1)) {
            name[cur-start] = line[cur];
            cur++;
        }
        name[cur-start] = 0;
        //printf("%s\n", name);

        // find (R50-9: 只匹配路径 basename 开头——原 strstr 在父目录含
        // "libc-"/"libc." 前缀时误中，把该目录下文件基址当 libc 返回；
        // 反之父目录 "libc6" 等会整行误负。要求 so_path 即 basename 开头）
        int find_len = strlen(so_path);
        char *slash = strrchr(name, '/');
        char *bname = slash ? slash + 1 : name;
        char *find = (strncmp(bname, so_path, find_len) == 0) ? bname : NULL;
        if (!find || (find[find_len]!='-' && find[find_len]!='.' )) {
            continue;
        }

        // read base address
        cur = 0;
        while (line[cur] && line[cur] != '-') {
            base[cur] = line[cur];
            cur++;
        }
        base[cur] = 0;
        sscanf(base, "%lx", (long*)(&r_addr));

        break;
    }
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
        ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F') {
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
        if (phdrs[i].p_type == PT_LOAD && !found_first_load) {
            first_load_vaddr = phdrs[i].p_vaddr;
            found_first_load = true;
        }
        if (phdrs[i].p_type == ARTHUR_PT_DYNAMIC) {
            // C130: 与下方符号公式同源——PT_DYNAMIC 的运行时地址 = 加载基址 +
            // p_vaddr，加载基址 = base - 首 PT_LOAD p_vaddr。ET_DYN（首段 vaddr=0）
            // 下等价原 base + p_vaddr；ET_EXEC（非 PIE，p_vaddr 是绝对地址）下
            // base + p_vaddr 会双倍偏移、读错 .dynamic → 符号解析失败（C130 原
            // 评估的 fail-closed）。统一修正公式（首 PT_LOAD 未捕获时维持原行为）。
            dyn_vaddr = base - first_load_vaddr + phdrs[i].p_vaddr;
            break;
        }
    }
    if (dyn_vaddr == 0) {
        close(fd);
        return 0;
    }

    // read dynamic entries until DT_NULL
    //
    // 注意：这里读的是运行期已 RELOCATE 过的 .dynamic（目标进程内存）——
    // 动态链接器把 DT_SYMTAB/DT_STRTAB/DT_HASH/DT_GNU_HASH 的 d_ptr
    // 重定位成了进程内绝对地址，不能再加 base。用 d_ptr < base 兜底：
    // 若拿到的是文件内相对 vaddr（未重定位场景），补 base。
    uint64_t symtab = 0, strtab = 0;
    uint64_t syment = 24, hash = 0, gnu_hash = 0;
    for (size_t i = 0; ; i++) {
        Elf64_Dyn dyn;
        if (pread(fd, &dyn, sizeof(dyn), dyn_vaddr + i * sizeof(dyn)) != (ssize_t)sizeof(dyn)) {
            close(fd);
            return 0;
        }
        if (dyn.d_tag == ARTHUR_DT_NULL) {
            break;
        }
        uint64_t ptr = dyn.d_un.d_ptr;
        if (ptr != 0 && ptr < base) {
            ptr += base;    // 未重定位的相对 vaddr
        }
        switch (dyn.d_tag) {
            case ARTHUR_DT_SYMTAB: symtab = ptr; break;
            case ARTHUR_DT_STRTAB: strtab = ptr; break;
            case ARTHUR_DT_SYMENT: syment = dyn.d_un.d_val; break;
            case ARTHUR_DT_HASH:   hash = ptr; break;
            case ARTHUR_DT_GNU_HASH: gnu_hash = ptr; break;
        }
    }
    if (symtab == 0 || strtab == 0 || syment == 0) {
        close(fd);
        return 0;
    }

    // symbol count: SysV hash nchain, or GNU hash chain walk
    uint64_t sym_count = 0;
    if (hash != 0) {
        uint32_t nbucket, nchain;
        if (pread(fd, &nbucket, 4, hash) != 4 ||
            pread(fd, &nchain, 4, hash + 4) != 4) {
            close(fd);
            return 0;
        }
        // R50-9: nchain 目标可控（最大 0xFFFFFFFF）——设上限，防逐条 pread 空转。
        sym_count = (nchain <= ARTHUR_MAX_SYM) ? nchain : ARTHUR_MAX_SYM;
    } else if (gnu_hash != 0) {
        uint32_t hdr[4];
        if (pread(fd, hdr, sizeof(hdr), gnu_hash) != (ssize_t)sizeof(hdr)) {
            close(fd);
            return 0;
        }
        uint32_t nbuckets = hdr[0], symoffset = hdr[1], bloom_size = hdr[2];
        // R50-9: nbuckets/bloom_size 目标可控——过大时 buckets/chains 偏移会
        // 指向任意可读映射，遍历空转。设上限后直接失败。
        if (nbuckets > ARTHUR_MAX_NBUCKETS || bloom_size > ARTHUR_MAX_BLOOM ||
            symoffset > ARTHUR_MAX_SYM) {
            close(fd);
            return 0;
        }
        uint64_t buckets = gnu_hash + 16 + (uint64_t)bloom_size * 8;
        uint64_t chains = buckets + (uint64_t)nbuckets * 4;
        uint32_t max_chain = 0;
        // B186: nbuckets(≤1M) × 每链步数(≤1M) 的**乘积**可达 10^12——构造的 libc
        // 让每个 bucket 都指向同一长链（全 0 无终止位）时，内外层循环跑满 10^12 次
        // pread（每次走 /proc/pid/mem 的 VMA 查找），arthur 挂起数天（对 crash-dump/
        // monitor 工具的反取证 DoS）。R50-9 的单维度上限未覆盖乘积放大。加跨 bucket
        // 全局步数上限，把总工作量收敛到亚秒级（合法 libc nbuckets~4k、链 1-2 项，
        // 实际 ~9k 步，远低于上限）。
        uint64_t total_steps = 0;
        for (uint32_t b = 0; b < nbuckets; b++) {
            uint32_t idx;
            if (pread(fd, &idx, 4, buckets + b * 4) != 4) {
                close(fd);
                return 0;
            }
            uint32_t steps = 0;
            while (idx >= symoffset && steps < ARTHUR_MAX_CHAIN) {
                uint32_t c = idx - symoffset;
                if (c > max_chain) max_chain = c;
                uint32_t chain;
                if (pread(fd, &chain, 4, chains + c * 4) != 4) {
                    close(fd);
                    return 0;
                }
                if (chain & 1) break;
                idx++;
                steps++;
                // B186: 全局步数上限（跨 bucket），防乘积放大 DoS
                if (++total_steps > ARTHUR_MAX_SYM) {
                    close(fd);
                    return 0;
                }
            }
        }
        sym_count = symoffset + max_chain + 1;
        if (sym_count > ARTHUR_MAX_SYM) {
            sym_count = ARTHUR_MAX_SYM;
        }
    }
    if (sym_count == 0) {
        close(fd);
        return 0;
    }

    for (uint64_t i = 0; i < sym_count; i++) {
        Elf64_Sym sym;
        if (pread(fd, &sym, sizeof(sym), symtab + i * syment) != (ssize_t)sizeof(sym)) {
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
        if (sym.st_name == 0) {
            continue;
        }
        char name[256];
        ssize_t r = pread(fd, name, sizeof(name) - 1, strtab + sym.st_name);
        if (r <= 0) {
            continue;
        }
        name[r] = '\0';
        if (strcmp(name, func_name) == 0) {
            close(fd);
            // B188: 加载基址修正（见 first_load_vaddr 捕获处）。合法 libc
            // first_load_vaddr==0 时等价于原 base + st_value。
            return base - first_load_vaddr + sym.st_value;
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
#undef ARTHUR_DT_SYMENT
#undef ARTHUR_DT_GNU_HASH
#undef ARTHUR_MAX_SYM
#undef ARTHUR_MAX_NBUCKETS
#undef ARTHUR_MAX_BLOOM
#undef ARTHUR_MAX_CHAIN
}

/* pt_ functions, for ptrace_ calls.
 */
static inline int pt_wait(pid_t pid)
{
    int status = 0;
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

static inline int pt_detach(pid_t pid)
{
    int rc;

    rc = ptrace(PTRACE_DETACH, pid, NULL, (void *)SIGCONT);
    if (rc) {
        error("detach %d failed", pid);
    }
    return rc;
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
    int rc;

#ifdef __aarch64__
    struct iovec iov;
    iov.iov_base = pregs;
    iov.iov_len = sizeof(user_regs64_struct);
    rc = ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
#else
    rc = ptrace(PTRACE_SETREGS, pid, NULL, pregs);
#endif

    // B57: 目标可能已退出；返回错误码让调用方 fail-closed，不再 assert。
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
// 组停靠 leader 时 forkcore_m 直接返回它让 monitor 置 leader_in_group_stop——不依赖
// SIGCHLD siginfo 中继（first-wins 会被 INTERRUPT 噪音污染，见 drain_noise 注释）。
static const int GROUP_STOP_SENTINEL = -3;

// R50-51: 基于 wait 状态的 leader 崩溃/死亡确定性检出（C134）。崩溃 SIGCHLD 会被
// coalescing（first-wins）合并进 INTERRUPT 噪音，纯 siginfo 分类无法检出（且注入完成
// 的 ret-to-0 SIGSEGV 也是 CLD_TRAPPED/SIGSEGV，会误报），必须看实际停靠状态。
// 返回 >0 崩溃信号；-2 正常退出；0 运行中/无崩溃/非崩溃停靠（非崩溃停靠的 status
// 已被 waitpid 消费，SIGCHLD 仍在队列留给 monitor 中继）。
static int detect_leader_death(pid_t pid)
{
    int ws = 0;
    pid_t r = waitpid(pid, &ws, WUNTRACED | WNOHANG);
    if (r <= 0) {
        return 0;
    }
    if (WIFSIGNALED(ws)) {
        return WTERMSIG(ws);
    }
    if (WIFEXITED(ws)) {
        return -2;
    }
    if (WIFSTOPPED(ws)) {
        int st = WSTOPSIG(ws);
        if (st == SIGILL || st == SIGABRT || st == SIGSEGV) {
            return st;
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
    int ws = 0;
    pid_t r = waitpid(pid, &ws, WUNTRACED | WNOHANG);
    if (r > 0 && WIFSTOPPED(ws)) {
        int st = WSTOPSIG(ws);
        if (st == SIGILL || st == SIGABRT || st == SIGSEGV) {
            return st;
        }
    }
    siginfo_t si;
    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0 &&
        (si.si_signo == SIGILL || si.si_signo == SIGABRT || si.si_signo == SIGSEGV) &&
        (si.si_code == SI_USER || si.si_code == SI_TKILL)) {
        return si.si_signo;
    }
    return 0;
}

// R50-51: drain 遗留的 INTERRUPT/ptrace-stop 噪音 SIGCHLD（CLD_STOPPED 且
// si_status==0）。stale 噪音会留在 pending 队列里，与后续真实信号 coalescing
// first-wins 遮蔽（C133）——forkcore_m 失败路径（restore CONT leader 后）与收尾
// 窗口都需要清掉，否则 monitor 出队 status=0 会 CONT(0) 中继，甚至解除组停靠
//（B172 的"SIGCHLD 中继置位"机制被此破坏，R50-51 改为哨兵直传）。
// 只吞 CLD_STOPPED/0；遇到非噪音（真实停靠/退出）即停止——调用方必须先调
// detect_leader_death 兜底崩溃/退出（本函数不判崩溃），顺序保证不吞真实信号。
static void drain_noise_sigchld(void)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    struct timespec zero_ts = {0, 0};
    for (;;) {
        siginfo_t si;
        errno = 0;
        if (sigtimedwait(&mask, &si, &zero_ts) < 0) {
            break;   // EAGAIN：无 pending
        }
        if (si.si_code == CLD_STOPPED && si.si_status == 0) {
            continue;   // INTERRUPT/ptrace-stop 噪音，吞掉
        }
        break;   // 非噪音：已出队消费；崩溃/退出由调用方 detect 兜底，不再多吞
    }
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
    if (ptrace(PTRACE_GETREGS, child, 0, &cregs) != 0) {
        // 子进程不可用（非 tracee / 已消失）——维持原 SIGKILL detach 行为。
        return;
    }
#ifdef __aarch64__
    cregs.pc = inject_page + (uint64_t)inject_exit_off;
#else
    cregs.rip = inject_page + (uint64_t)inject_exit_off;
#endif
    if (ptrace(PTRACE_SETREGS, child, 0, &cregs) != 0) {
        // 设置失败维持原状，不掩盖错误。
    }
}
static inline int pt_call(pid_t pid, user_regs64_struct *oregs, uint64_t func, int argc,
                          uint64_t argv[], uint64_t *out_inject_rsp = NULL,
                          uint64_t *out_orig_word = NULL,
                          uint64_t *out_fork_child = NULL,
                          int *out_death = NULL)
{
    int rc, status = 0;
    user_regs64_struct regs;
    assert(argc <= 6);

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
        error("pt_call: %s %d failed (%s)", msg, pid, strerror(errno));
        // 恢复注入期间被修改的目标状态
#ifndef __aarch64__
        if (stack_saved) {
            errno = 0;
            ptrace(PTRACE_POKEDATA, pid, inject_rsp, (void*)orig_stack_word);
        }
        // R50-17: wait4 慢路径践踏目标红区（见 save 处注释）——恢复整个 128 字节红区。
        if (red_saved) {
            for (int i = 0; i < 16; i++) {
                errno = 0;
                ptrace(PTRACE_POKEDATA, pid, red_base + i * 8, (void*)red_zone[i]);
            }
        }
        if (xstate_saved && pt_setxstateregs(pid, &xstate, xstate_len) != 0) {
            error("pt_call: restore xstate %d failed (%s)", pid, strerror(errno));
        }
#else
        if (sve_saved) {
            // R50-10: 恢复 SVE（不清 TIF_SVE）；失败告警
            if (pt_restore_sve(pid, sve_buf, sve_len) != 0) {
                error("pt_call: restore SVE %d failed (%s)", pid, strerror(errno));
            }
            free(sve_buf);
            sve_buf = NULL;
        } else if (fp_saved) {
            pt_setfpregs(pid, &fpregs);
        }
#endif
        return -1;
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
    // B3: [rsp-8] 是模拟 call 压入的返回地址槽位（red zone 下方）。原实现写 0
    // 后永不恢复，目标帧返回时 rip=0 → 崩。先 PEEKDATA 保存原字，注入结束后写回。
    inject_rsp = regs.rsp - 8;
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
    regs.rsp -= 8;
    rc = ptrace(PTRACE_POKEDATA, pid, regs.rsp, 0);
    if (rc != 0) { return fail("poke [rsp-8]"); }
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
                siginfo_t si;
                if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) != 0 ||
                    si.si_code == SI_USER || si.si_code == SI_TKILL) {
                    error("SIGSEGV si_code=%d during injection (real crash, not completion)",
                          si.si_code);
                    return fail("crash during injection");
                }
                break;
            }
            if (WSTOPSIG(status) == SIGABRT || WSTOPSIG(status) == SIGILL) {
                // B171: 注入期间目标 abort/illegal（SIGABRT/SIGILL delivery-stop）。
                // 注入的 syscall 包装函数（mmap/fork/waitpid）不 abort/不执行非法指令，
                // 这两个信号只来自目标自身的真实崩溃（异步 kill -ABRT/-ILL 或内部
                // assert）。原实现对这些信号只 CONT(0) 抑制——崩溃被静默吞掉、目标
                // 继续运行（与 B158 的 kill-SEGV 同类未覆盖）。fail-closed。
                error("%s during injection (real crash, not completion)",
                      strsignal(WSTOPSIG(status)));
                return fail("crash during injection");
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

        status = pt_wait(pid);
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
    if (sve_saved) {
        if (pt_restore_sve(pid, sve_buf, sve_len) != 0) {
            error("pt_call: restore SVE %d failed (%s)", pid, strerror(errno));
        }
        free(sve_buf);
        sve_buf = NULL;
    } else if (fp_saved) {
        pt_setfpregs(pid, &fpregs);
    }
#else
    if (stack_saved) {
        errno = 0;
        ptrace(PTRACE_POKEDATA, pid, inject_rsp, (void*)orig_stack_word);
    }
    // R50-17: 恢复整个 128 字节红区（wait4 慢路径践踏的部分）
    if (red_saved) {
        for (int i = 0; i < 16; i++) {
            errno = 0;
            ptrace(PTRACE_POKEDATA, pid, red_base + i * 8, (void*)red_zone[i]);
        }
    }
    if (xstate_saved && pt_setxstateregs(pid, &xstate, xstate_len) != 0) {
        error("pt_call: restore xstate %d failed (%s)", pid, strerror(errno));
    }
#endif

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

static inline int pt_attach(pid_t pid)
{
    int rc;

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
    if (pt_wait(pid) < 0) {
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

static inline int pt_monitor(pid_t pid) {
    int rc;
    // B57: 目标可能刚好退出（瞬时进程 / 已僵尸）。SEIZE/INTERRUPT/SETOPTIONS
    // 任一步返回 -ESRCH 都干净报错返回，不再 assert abort。
    rc = ptrace(PTRACE_SEIZE, pid, NULL, NULL);
    if (rc != 0) {
        error("cannot seize process %d (%s)", pid, strerror(errno));
        return -1;
    }
    rc = pt_int(pid);
    if (rc != 0) {
        error("cannot interrupt process %d (%s)", pid, strerror(errno));
        return -1;
    }
    rc = ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXIT);
    if (rc != 0) {
        error("cannot set options on process %d (%s)", pid, strerror(errno));
        return -1;
    }
    // restart main thread
    rc = pt_cont(pid);
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
    if (_d_maps->Parse() < 0) {
        return -1;
    }

    _d_cmdline = new ProcCmdline(_cmdline);
    assert(_d_cmdline);
    _d_cmdline->Parse();

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
    _d_auxv->Parse();
    dprint("uid(%d), euid(%d), gid(%d), egid(%d)", 
            _d_auxv->uid, _d_auxv->euid, _d_auxv->gid, _d_auxv->egid);
    
    for (auto& t: _threads) {
        t._d_stat = new ProcStat(t._stat);
        assert(t._d_stat);
        t._d_stat->Parse();
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
 
    size_t size = roundup((sizeof(Elf64_Nhdr) + 8 + payload_size), 4);
    // assert 在此构建（-O0 -g 无 NDEBUG）下 OOM 即 abort——fail-closed；改 NULL 返回
    // 需同步护住 6 处 memcpy 调用点，收益低。保持 assert。
    char *note = (char*)malloc(size);
    assert(note);
    memset(note, 0, size);

    Elf64_Nhdr *nhdr = (Elf64_Nhdr*)note;
    nhdr->n_namesz = name_size;
    nhdr->n_descsz = payload_size;
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
int Note::fill_prpsinfo(const ProcessData& proc)
{
    // 损坏 acore 可能让 thread_num=0 或 _d_stat 为空；_threads[0] 越界/空指针解引用
    if (proc._threads.size() == 0 || !proc._threads[0]._d_stat || !proc._d_auxv) {
        error("prpsinfo: missing thread/auxv metadata");
        return -1;
    }
    // B36: note desc 落在 note+20（4 对齐非 8 对齐），直接 p->field 解引用是
    // 未对齐 UB（UBSan 报错，aarch64 有风险）。在对齐局部结构里填好再 memcpy。
    elf_prpsinfo64 info = {};
    info.pr_state = proc._threads[0]._d_stat->state;
    info.pr_sname = proc._threads[0]._d_stat->sname;
    info.pr_uid = proc._d_auxv->uid;
    info.pr_gid = proc._d_auxv->gid;
    info.pr_pid = proc._threads[0]._d_stat->pid;
    info.pr_ppid = proc._threads[0]._d_stat->ppid;
    info.pr_pgrp = proc._threads[0]._d_stat->pgid;
    info.pr_sid = proc._threads[0]._d_stat->sid;

    // B25: 填充 pr_flag/pr_zomb/pr_nice（内核原生 core 会填这些）
    info.pr_flag = proc._threads[0]._d_stat->flags;
    // b25 (Codex review): 内核 fill_psinfo 用 `pr_zomb = exit_state==EXIT_ZOMBIE`。
    // 恒 0 是错的——僵尸进程应置 1。/proc 的 sname=='Z' 即 EXIT_ZOMBIE。
    info.pr_zomb = (proc._threads[0]._d_stat->sname == 'Z') ? 1 : 0;
    info.pr_nice = proc._threads[0]._d_stat->nice;

    // B63: pr_fname 用 task->comm（stat 括号内文本，可执行名），与内核原生 core
    // 一致。原实现用 argv[0] 全路径，gdb/ps 显示截断的路径而非进程名。
    // comm 缺失（损坏 acore）时退回 argv[0]。
    std::string fname;
    if (proc._threads[0]._d_stat->comm[0] != '\0') {
        fname = proc._threads[0]._d_stat->comm;
    } else if (proc._d_cmdline && proc._d_cmdline->argv.size() > 0) {
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
    // page_size 用真实页大小（ptrace 同架构宿主==目标），不硬编码 0x1000，
    // aarch64 64K 页系统同样正确。
    long page_size = sysconf(_SC_PAGESIZE);
    v = (uint64_t)page_size;
    payload.append((const char*)&v, 8);

    // address
    for (auto& n : entries) {
        payload.append((const char*)&n.start_addr, 8);
        payload.append((const char*)&n.end_addr, 8);
        // file_ofs = 字节偏移 / page_size（页对齐，整除无舍入）
        uint64_t file_ofs = n.offset / (uint64_t)page_size;
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
        info.pr_info.si_code = thr._siginfo.si_code;
        info.pr_info.si_errno = thr._siginfo.si_errno;
        info.pr_info.si_signo = thr._siginfo.si_signo;
        info.pr_cursig = thr._siginfo.si_signo;
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
        info.pr_sigpend = thr._sigpend ? thr._sigpend : thr._d_stat->pending;
        info.pr_sighold = thr._sighold ? thr._sighold : thr._d_stat->blocked;
        info.pr_fpvalid = thr._fp_valid ? 1 : 0;
        char *p = allocate(sizeof(info));
        memcpy(p, &info, sizeof(info));
    }
    else if (thr._arch == ARCH_AARCH64) {
        arm64_elf_prstatus info = {};
        info.pr_info.si_code = thr._siginfo.si_code;
        info.pr_info.si_errno = thr._siginfo.si_errno;
        info.pr_info.si_signo = thr._siginfo.si_signo;
        info.pr_cursig = thr._siginfo.si_signo;
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
        info.pr_sigpend = thr._sigpend ? thr._sigpend : thr._d_stat->pending;
        info.pr_sighold = thr._sighold ? thr._sighold : thr._d_stat->blocked;
        info.pr_fpvalid = thr._fp_valid ? 1 : 0;
        char *p = allocate(sizeof(info));
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
        memcpy(p, &thr._fpregs.x64, sizeof(thr._fpregs.x64));
    }
    else if (thr._arch == ARCH_AARCH64) {
        arm64_elf_fpregset *p = allocate<arm64_elf_fpregset>();
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
      _crash_sig(0),   // B199: 非 0 时 WriteThreadMeta 覆盖所有线程 si_signo
      // 按 core.h 成员声明顺序（_ptrace_options 在 _ehdr/_note_phdr 之前）
      _ptrace_options(0),
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

    return 0;
}

int Coredump::WriteProcessMeta(Lz4Stream& out, ProcMaps& maps)
{ 
    // put ProcessData
    {
        uint32_t u32;
        out.SetBlock(BLOCK_TYPE_PROCESS);
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
        struct timeval tv;
        struct timezone tz = {0};   // gettimeofday 不填 tz，避免把未初始化栈写进 acore
        gettimeofday (&tv, &tz);
        ok = ok && wr(&tv, sizeof(tv));
        ok = ok && wr(&tz, sizeof(tz));

        // uname（sizeof 512 只写入 ~390 字节，其余置零）
        char ubuf[512] = {0};
        uname((utsname*)ubuf);
        ok = ok && wr(ubuf, sizeof(ubuf));

        if (!ok || out.Flush() < 0) {
            error("write PROCESS block failed (disk full?)");
            return -1;
        }
    }

    // put raw files
    char buf[BUFFER_SIZE];
    // B29: 原实现忽略 ReadPid 返回值——读失败时 NULL 传入 PutFile（NULL 解引用
    // 崩溃）或未初始化 buf 被当 ProcFile 写出垃圾。这里逐项检查，失败即返回 -1。
    // B180: 与 maps 的 R50-31 对齐——cmdline/auxv/environ/io/limits 超 1MB 缓冲
    // 截断时也 fail-closed（原实现静默把截断数据当完整写入 acore，解压端 64MB
    // 上限不会兜底，截断透传到生成的 core）。真实进程这些文件极少超 1MB
    //（environ 在巨型环境变量场景可达）。
    auto read_pid_checked = [&](ProcType t, const char* what) -> int {
        bool truncated = false;
        ProcFile* pf = ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, t, &truncated);
        if (!pf) {
            error("read %s of %d failed", what, _pid);
            return -1;
        }
        if (truncated) {
            error("%s of %d exceeds buffer (%ld bytes), refusing incomplete dump",
                  what, _pid, (long)BUFFER_SIZE);
            return -1;
        }
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
    ProcFile* _maps = ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_MAPS, &maps_truncated);
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
    if (out.PutFile(_maps) < 0) {
        error("write maps failed (disk full?)");
        return -1;
    }
    maps.setpf(_maps);
    maps.Parse();
    // R50-27: _maps 指向本函数栈上 buf，函数返回即失效。Parse 已把数据深拷贝进
    // ProcMaps 的 std::vector（std::string name 自包含），WriteLoads 只迭代向量、
    // 不再解引用 _pf。置 NULL 防未来任何在返回后调用 Parse/readline 的路径读到
    // 悬垂指针（_pf==NULL 时 readline/Parse 安全返回 0）。
    maps.setpf(NULL);

    if (read_pid_checked(PROC_TYPE_ENVIRON, "environ") != 0) {
        return -1;
    }
    if (read_pid_checked(PROC_TYPE_IO, "io") != 0) {
        return -1;
    }
    if (read_pid_checked(PROC_TYPE_LIMITS, "limits") != 0) {
        return -1;
    }

    return 0;
}

// b25: 从 /proc/<tid>/status 文本解析 SigPnd:/SigBlk: 的 64 位十六进制掩码。
// f_data 已 NUL 结尾（B17），strstr/strtoull 有界。未找到返回 0。
static uint64_t parse_status_mask(const char *data, const char *key)
{
    if (!data) {
        return 0;
    }
    const char *p = strstr(data, key);
    if (!p) {
        return 0;
    }
    p += strlen(key);
    while (*p == ':' || *p == '\t' || *p == ' ') {
        p++;
    }
    return strtoull(p, NULL, 16);
}

// B168: 目标是否捕获了 sig（/proc/<pid>/status 的 SigCgt 掩码，位 sig-1）。
// monitor 崩溃判定用：捕获的 SIGSEGV/SIGILL/SIGABRT 应中继（CONT 让 handler 跑）
// 而非当致命崩溃采集——否则写出假 core、kill_crashed 重投走 handler 进程不死，
// monitor 还静默放弃监控。/proc 读失败时保守按未捕获（致命）处理。
static bool signal_is_caught(pid_t pid, int sig)
{
    if (sig < 1 || sig > 64) {
        return false;
    }
    char buf[BUFFER_SIZE];
    ProcFile *spf = ProcFile::ReadPid(buf, BUFFER_SIZE, pid, PROC_TYPE_STATUS);
    if (!spf) {
        return false;
    }
    uint64_t mask = parse_status_mask(spf->f_data, "SigCgt:");
    return (mask & (1ULL << (sig - 1))) != 0;
}

int Coredump::WriteThreadMeta(Lz4Stream& out, pid_t pid, bool is_main) {
    info("thread: %d", pid); // thread info
    int rc;

    // 线程由调用方预先 attach（collect_threads）；此处只读寄存器。
    // 读失败（线程可能在 attach 与 SIGSTOP 生效间退出）时不能跳过——meta 的
    // thread_num 已按 _thrd_pid.size() 写入，缺块会让解压端按 thread_num 读到
    // 下一个 LOADS/ELF 块当 THREAD 块，整体错位。改为写零化块保持计数一致
    // （该线程现场确已消失，零寄存器是诚实近似）。
    ThreadData i;   // 构造器 memset 为零
    int fp_ok = 1;
    rc = pt_getregs(pid, (user_regs64_struct*)&i._regs);
    if (rc != 0) {
        warn("getregs thread %d failed, zeroed block", pid);
        // R50-6: 通用寄存器读失败同样说明该线程现场不可信，pr_fpvalid 应整体
        // 置 0——否则写出"GP 全零、pr_fpvalid=1"的自相矛盾 THREAD 块。
        fp_ok = 0;
    }
    rc = pt_getfpregs(pid, (user_fpregs64_struct*)&i._fpregs);
    if (rc != 0) { warn("getfpregs thread %d failed, zeroed block", pid); fp_ok = 0; }
    rc = ptrace(PTRACE_GETSIGINFO, pid, 0, &i._siginfo);
    if (rc != 0) { warn("getsiginfo thread %d failed, zeroed block", pid); }
    // B199: monitor 崩溃采集时所有线程 pr_cursig 应为进程崩溃信号（内核原生 core
    // 如此，gdb 按线程信号显示"Program terminated"）——worker 线程停在 attach 的
    // SIGSTOP，不覆盖则 gdb 报 "SIGSTOP" 误导（实证：改 pr_cursig 后 gdb 正确显示
    // SIGSEGV）。generate/forkcore（非崩溃）_crash_sig==0，保持各自 stop 信号。
    if (_crash_sig != 0) {
        i._siginfo.si_signo = _crash_sig;
    }
    if (_arch == ARCH_X64) {
        rc = pt_getxstateregs(pid, (x64_xstatereg*)&i._xstate);
        if (rc != 0) { warn("getxstateregs thread %d failed, zeroed block", pid); fp_ok = 0; }
    }
    // v3: FP/扩展状态读取成功才有 pr_fpvalid=1；失败（线程退出）时写 0。
    i._fp_valid = (fp_ok != 0);

    // b25: /proc/<tid>/status 的 SigPnd/SigBlk 是全 64 位掩码。stat 字段 31/32
    // 被内核 `& 0x7fffffff` 掩成 31 位，丢 RT 信号（32-64）——pr_sigpend/pr_sighold
    // 会缺失。解析后随 THREAD 块写入，解压端填 pr_sigpend。
    char buf[BUFFER_SIZE];
    ProcFile *spf = ProcFile::ReadPid(buf, BUFFER_SIZE, pid, PROC_TYPE_STATUS);
    if (spf) {
        i._sigpend = parse_status_mask(spf->f_data, "SigPnd:");
        i._sighold = parse_status_mask(spf->f_data, "SigBlk:");
    }

    // write thread meta
    // R50-1: 各 out.Write/Flush/PutFile 返回原未检查——磁盘满时静默产出缺线程块的
    // 坏 acore（与 B64-B70 同 class，WriteThreadMeta 漏了）。检查并 fail-closed。
    out.SetBlock(BLOCK_TYPE_THREAD);
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
    // read /proc/<pid>/stat；读失败时写最小合法 ProcFile（f_size=0），
    // 避免把未初始化 buf 当 ProcFile 写出（解压端 GetFile 读垃圾 size）。
    // （buf 复用：上方 status 已解析完，这里覆盖。）
    ProcFile *pf = ProcFile::ReadPid(buf, BUFFER_SIZE, pid, PROC_TYPE_STAT);
    if (!pf) {
        warn("read /proc/%d/stat failed, empty stat", pid);
        memset(buf, 0, sizeof(ProcFile));
        pf = (ProcFile*)buf;
        pf->f_pid = pid;
        pf->f_type = PROC_TYPE_STAT;
    }
    if (out.PutFile(pf) < 0) {
        error("write thread stat failed (disk full?)");
        return -1;
    }

    return 0;
}

int Coredump::collect_threads(pid_t leader)
{
    _process._thrd_pid.clear();
    _process._thrd_pid.push_back(leader);   // leader 计入计数，但由调用方单独 attach

    char pbuf[64];
    snprintf(pbuf, sizeof(pbuf), "/proc/%u/task/", leader);
    DIR *dirp = opendir(pbuf);
    if (!dirp) {
        return -1;
    }
    struct dirent *dp = NULL;
    while ((dp = readdir(dirp)) != NULL) {
        if (dp->d_name[0] == '.') continue;
        // R50-22: atoi 对超长数字串溢出是 UB（真实 /proc/task 由内核生成不可触发，
        // 防伪造/损坏 /proc）。strtol + 全串校验。
        char *end = NULL;
        errno = 0;
        long tid = strtol(dp->d_name, &end, 10);
        if (end == dp->d_name || *end != '\0' || tid <= 0 || tid == leader) continue;
        errno = 0;
        if (pt_attach((pid_t)tid) != 0) {
            // B77 (Codex B7 review): 线程可能在枚举与 attach 间退出（ESRCH，跳过）；
            // 但 EPERM/tracer 冲突等非 ESRCH 错误是真实故障，跳过会静默产出不完整
            // dump。fail-closed。
            // B185: EAGAIN（pt_attach pt_wait 超时 = 线程 D 态不可停，B179/B185）与
            // ESRCH 同等待遇——跳过而非 abort，避免崩溃采集/正常 dump 为单个不可停
            // 线程丢掉整个现场（D 态兄弟在崩溃瞬间是现实场景，磁盘/NFS 阻塞）。
            if (errno == ESRCH || errno == EAGAIN) {
                if (errno == ESRCH) {
                    error("attach thread %ld failed (exited), skipped", tid);
                } else {
                    error("attach thread %ld in D-state (uninterruptible), skipped", tid);
                }
                continue;
            }
            error("attach thread %ld failed (%s), aborting collection", tid, strerror(errno));
            closedir(dirp);
            return -1;
        }
        _process._thrd_pid.push_back(tid);
    }
    closedir(dirp);
    return 0;
}

// B35(问题1): 采集失败后还原目标。兄弟线程用 PTRACE_DETACH(NULL) 恢复
// （无 SIGCONT，与 forkcore_m 末尾一致）；leader 用 CONT 恢复。monitor 场景
// 下若不做这个还原，兄弟线程会永久停在 attach-stop，目标进程死锁。
void Coredump::restore_target_after_fail()
{
    for (pid_t tid : _process._thrd_pid) {
        if (tid == _pid) {
            continue;
        }
        ptrace(PTRACE_DETACH, tid, NULL, NULL);
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
    }
    if (ptrace(PTRACE_CONT, _pid, NULL, NULL) != 0) {
        error("restore: cont %d failed (%s)", _pid, strerror(errno));
    }
    // R50-51: 失败路径收尾——drain pt_int/ptrace-stop 遗留的 INTERRUPT 噪音
    //（CLD_STOPPED/0）。stale 噪音留在 pending 队列会与后续真实崩溃信号 coalescing
    // first-wins 遮蔽（C133：monitor 出队 status=0 中继 CONT(0) 抑制崩溃）。monitor
    // 场景 SIGCHLD 被 block，噪音不会自动消失；standalone（SIGCHLD 未 block）下
    // sigtimedwait 返回 EINVAL、本函数是安全空操作。真实崩溃/退出由调用方（forkcore_m
    // 收尾 detect_leader_death）另行检出，本函数只清噪音。
    drain_noise_sigchld();
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
    if (rc != sizeof(hdr.m) || hdr.m.version > ACORE_VERSION) {
        error("acore version %d > %d.", hdr.m.version, ACORE_VERSION);
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
    }
    info("pid = %d", _pid);
    info("thread_num = %d", thread_num);

    _process._cmdline = in.GetFile();
    _process._auxv = in.GetFile();
    _process._maps = in.GetFile();
    _process._environ = in.GetFile();
    _process._io = in.GetFile();
    _process._limits = in.GetFile();

    // b23/b43 (Codex review): 任一必需 proc 文件读失败（截断 size 前缀、超 64MB
    // 上限、小 size、块类型不符）都是损坏 acore——fail-closed，而非带 NULL/部分
    // 数据继续解析，让后续 ParseAll/fill_* 消费堆垃圾。
    if (!_process._cmdline || !_process._auxv || !_process._maps ||
        !_process._environ || !_process._io || !_process._limits) {
        error("a required proc file failed to load, acore corrupt");
        return -1;
    }

    // B23: thread_num 来自损坏 acore 可为任意值；限定上限避免无限/超长循环。
    // b23/b43 (Codex review): 100 万线程上限仍允许数 GiB 分配（每 ThreadData
    // 约 3KB 寄存器 + stat，可压缩到极小）。降到 2^17，并加线程块累计未压缩
    // 字节预算兜底——构造的线程块无法无限放大内存。
    if (thread_num < 0 || thread_num > 131072) {
        error("implausible thread_num %d, acore corrupt", thread_num);
        return -1;
    }
    // 线程元数据累计未压缩字节上限（x64 每线程 ~3.5KB，131072 线程 ≈ 460MB）
    const size_t THREAD_META_MAX = 512*1024*1024;
    size_t meta_bytes = 0;

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
            td._fp_valid = (fv != 0);
        } else {
            td._fp_valid = 1;
        }

        if (!tb_ok) {
            error("thread block %d too short (acore corrupt)", i);
            return -1;
        }

        td._stat = in.GetFile();
        // R50-1: 线程 stat 的 GetFile 失败（NULL）未检查——后续 ProcStat(NULL)/
        // fill_prstatus 全零。fail-closed。
        if (!td._stat) {
            error("thread %d stat missing (acore corrupt)", td._pid);
            return -1;
        }
        // R50-7: 线程 stat 的 GetFile 上限 64MB，且不计入上方 THREAD_META_MAX 预算
        //（只累加 THREAD 块长度）——构造 acore 可让每线程 stat 都接近 64MB，
        // 131072 线程 ≈ 8TB 堆分配（LZ4 高压缩比重复数据使文件本身很小）。
        // 把 stat 序列化大小也计入预算，超限即拒。
        meta_bytes += td._stat->Size();
        if (meta_bytes > THREAD_META_MAX) {
            error("thread metadata %zu exceeds budget (with stat), acore corrupt", meta_bytes);
            return -1;
        }
        _process._threads.push_back(td);
        info("thread: %d", td._pid);
    }

    return 0;
}

int Coredump::WriteLoads(Lz4Stream& out, pid_t pid, ProcMaps& maps)
{
    int fd;
    {
        char fmem[128];
        snprintf(fmem, 128, "/proc/%u/mem", pid);
        fd = open(fmem, O_RDONLY);
        if (fd < 0) {
            return -1;
        }
    }

    out.SetBlock(BLOCK_TYPE_LOADS);

    // slot for loads size
    size_t file_size = 0, mem_size = 0;

#if 0
    long loads_slot = out.Tell();
    out.WriteRaw((const char *)&file_size, sizeof(file_size));
#endif

    // mem regions 
    char buf[BUFFER_SIZE];
    for (auto &r : maps) {

        // program header entry
        Elf64_Phdr ph = {};
        ph.p_type = PT_LOAD;
        ph.p_align = 1;
        ph.p_flags = r.perms; 
        ph.p_vaddr = r.start_addr;
        ph.p_memsz = (r.end_addr - r.start_addr);
        ph.p_filesz = 0;    // update after pread
        ph.p_offset = file_size;

        // TBD: if user request all memory.
        uint64_t end_addr = r.end_addr;
        // 只 dump 可执行文件映射的首页以省体积，但仅当磁盘 ELF 可恢复时安全。
        // memfd(/memfd:) 与已删除((deleted)) 映射没有磁盘文件，inode>0 不可信，
        // 必须全量 dump，否则代码段永久缺失且 GDB 无法恢复。
        // B75 (Codex B4 review): 只匹配精确的 " (deleted)" 后缀——原 rfind 任意
        // 位置匹配，`/opt/(deleted)/lib.so` 这类正常路径会被误判为已删除并放大 acore。
        bool file_recoverable =
            !(r.name.size() >= 10 &&
              r.name.compare(r.name.size() - 10, 10, " (deleted)") == 0) &&
            !(r.name.compare(0, 7, "/memfd:") == 0);
        if (!(r.perms & PF_R)) { // not readable
            // do nothing
            continue;
        } else if (r.inode > 0 && file_recoverable && (r.perms & PF_X) && (ph.p_memsz > 0x1000)) {
            // dump only the first page.
            end_addr = r.start_addr + 0x1000;
        }
    
        // write memory dump
        size_t size = 0;
        for (uint64_t addr = r.start_addr; addr < end_addr; addr += sizeof(buf)) {
            int req = MIN((end_addr - addr), sizeof(buf));
            ssize_t len = pread(fd, buf, req, addr);
            if (len < 0) {
                warn("pread mem(%lx) failed(%d).", addr, errno);
                break;
            }
            if (len < req) {
                // R50-1: 短读（0<=len<req）时本循环按整缓冲推进，未读部分被静默跳过
                // → 该区域 core 数据有洞（gdb 零填充）。目标已停止时少见，但不应无声。
                warn("pread mem(%lx) short read %zd of %d bytes; region data hole",
                     addr, len, req);
            }
            mem_size += len;

            for (ssize_t i=0; i<len; i+= BLOCK_SIZE) {
                size_t j = MIN(len - i, BLOCK_SIZE);
                // B68: WriteBlock 失败（压缩错误）返回 -1；直接 `size += rc` 会让
                // size_t 下溢成巨大值，ph.p_filesz 声明巨额 → 解压被一致性检查拒。
                int wrc = out.WriteBlock((const char*)(buf+i), j, BLOCK_TYPE_LOADS);
                if (wrc < 0) {
                    error("write loads block failed (%d)", wrc);
                    close(fd);
                    return -1;
                }
                size += wrc;
            }

            // update file size
            dprint("read %lu bytes", len);

        } // for addr 
 
        // update file size in phdr
        ph.p_filesz = size;
        //printf("%lx : %ld %ld\n", ph.p_vaddr, ph.p_memsz, ph.p_filesz);
        _phdrs.emplace_back(ph);

        // update memory size
        file_size += size;

    } // for maps

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
    if (mem_size == 0) {
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
    if (_phdrs.size() > 0xFFFF) {
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

    out.SetBlock(BLOCK_TYPE_ELF);
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
    if (_phdrs.size() > 0xFFFF) {
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
            phdr.p_offset += _offset_load;
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

ssize_t Coredump::ReadLoads(Lz4Stream& in, FILE* fout)
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

        size_t len = fwrite(block->rBuf(), 1, block->Size(), fout);
        if (len != block->Size()) {
            error("write loads block failed (%lu != %lu)", len, block->Size());
            return -1;
        }

        //file_size += hdr.size;
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
    auto add_note = [&](Note* nt, int fill_rc) -> void {
        if (fill_rc != 0 || nt->_data == NULL) {
            error("note fill failed, skipping");
            delete nt;
            return;
        }
        _notes.push_back(nt);
    };

    // NT_PRPSINFO (prpsinfo structure)
    Note *nt = new Note(NT_PRPSINFO);
    add_note(nt, nt->fill_prpsinfo(_process));

    // NT_AUXV (auxiliary vector)
    nt = new Note(NT_AUXV);
    add_note(nt, nt->fill_auxv(_process));

    // NT_FILE (mapped files)
    nt = new Note(NT_FILE);
    add_note(nt, nt->fill_file(_process));

    for (auto& i : _process._threads) {
        // NT_PRSTATUS (prstatus structure)
        nt = new Note(NT_PRSTATUS);
        add_note(nt, nt->fill_prstatus(i));

        // NT_FPREGSET (floating point registers)
        nt = new Note(NT_FPREGSET);
        add_note(nt, nt->fill_fpregset(i));

        if (_arch == ARCH_X64) {
            // NT_X86_XSTATE (x86 XSAVE extended state)
            nt = new Note(NT_X86_XSTATE);
            add_note(nt, nt->fill_x86_xstate(i));
        }

        // NT_SIGINFO (siginfo_t data)
        nt = new Note(NT_SIGINFO);
        add_note(nt, nt->fill_siginfo(i));
    }

    for (Note *nt : _notes) {
        dprint(" [%x] %d 0x%x", nt->_type, nt->_size, nt->_size);
        rc += nt->_size;
    }

    return rc;
}

int Coredump::takememspace()
{   
    char buf[ARTHUR_BUFFER_SIZE];
    int pg_size = getpagesize();
    int off = 0;
    while (off < ARTHUR_BUFFER_SIZE) {
        buf[off] = 0;
        off += pg_size;
    }
    assert(buf[0] == 0);
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
    int rc = 0;
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = out.Open(corefile);
    if (rc < 0) {
        return -1;
    }

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
    if (pt_attach(_pid) != 0) {
        // 目标不存在/无权限：干净报错而非深层 assert 崩溃
        // b41 (Codex review): 只依赖析构关文件会留下 8 字节空 acore；显式清理，
        // 避免无效/无权限 pid 产出误导性文件。
        error("cannot attach to process %d", _pid);
        out.Close();
        unlink(corefile);
        return -1;
    }
    // get all threads pid（attach 全部非主线程，剔除已退出的）
    // B77: collect_threads 失败（opendir / 非 ESRCH attach 错误）时 fail-closed。
    // R50-6: leader 已 attach（SIGSTOP）；失败须 detach 已 attach 线程，
    // 否则目标冻结（内核自动 detach 不恢复 TASK_STOPPED）。
    if (collect_threads(_pid) != 0) {
        error("failed to collect threads of %d", _pid);
        for (pid_t& tid : _process._thrd_pid) {
            pt_detach(tid);
        }
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
        for (pid_t& tid : _process._thrd_pid) {
            pt_detach(tid);
        }
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
        for (pid_t& tid : _process._thrd_pid) {
            pt_detach(tid);
        }
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
            for (pid_t& t : _process._thrd_pid) {
                pt_detach(t);
            }
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
            for (pid_t& tid : _process._thrd_pid) {
                pt_detach(tid);
            }
            out.Close();
            unlink(corefile);
            return -1;
        }
        // B69: ELF 块写入失败（磁盘满）时显式失败。
        if (WriteElfHeader(out) != 0) {
            error("failed to write elf header for %d", _pid);
            for (pid_t& tid : _process._thrd_pid) {
                pt_detach(tid);
            }
            out.Close();
            unlink(corefile);
            return -1;
        }
        // R50-6: 尾标 3 字节短写（磁盘满）时 acore 缺结束标记，解压报 truncated；
        // 与 B68/B69/B70 同类，检查并 fail-closed。
        if (WriteTailMark(out) != 0) {
            error("failed to write tail mark for %d (disk full?)", _pid);
            for (pid_t& tid : _process._thrd_pid) {
                pt_detach(tid);
            }
            out.Close();
            unlink(corefile);
            return -1;
        }
    }
    // detach all threads
    for (pid_t& tid : _process._thrd_pid) {
        pt_detach(tid);
    }
    
    out.PrintStat();
    out.Close();
    return 0;
}

int Coredump::forkcore(const char *corefile, bool sys_core)
{
    // 每次采集前清空跨调用累积的 _phdrs
    _phdrs.clear();
    _core_pid = 0;

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
                        // R50-30 (D4): 目标阻塞 SIGTRAP 时，子进程 `int $3` 的 SIGTRAP
                        // 挂起不投递，子进程继续执行到 exit(0) 干净退出——不触发内核
                        // core，mode 2 静默产出无用的 meta 文件。与 SigCgt 同风格告警。
                        unsigned long long sigblk = 0;
                        if (sscanf(line + 7, "%llx", &sigblk) == 1 &&
                            (sigblk & (1ULL << (SIGTRAP - 1)))) {
                            warn("mode 2: target blocks SIGTRAP; the forked child's "
                                 "int $3 will be held pending and no kernel core will "
                                 "be generated");
                        }
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
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = out.Open(corefile);
    if (rc < 0) {
        return -1;
    }

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
    if (pt_attach(_pid) != 0) {
        // 目标不存在/无权限：干净报错而非深层 assert 崩溃
        // b41 (Codex review): 失败路径要清理已打开的空 acore（8 字节 header）。
        error("cannot attach to process %d", _pid);
        out.Close();
        unlink(corefile);
        return -1;
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
 
    // we've injected an 'int 3' in child process, that generates a corefile by kernel.
    // B39: SETOPTIONS 是整体替换——直接设 TRACEFORK 会清掉 pt_monitor 设的
    // TRACEEXIT，monitor 的退出检测降级。GET 现有选项后 OR 上 TRACEFORK。
    if (!sys_core) {
        // 用跟踪的 _ptrace_options（pt_monitor 设的 TRACEEXIT）叠加 TRACEFORK，
        // 避免整体替换清掉 TRACEEXIT（B39）。
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

    // 从目标进程自身 libc 的 .dynsym 解析符号地址（B11），
    // 不再假设宿主 libc 与目标 libc 同构。
    uint64_t r_libc = get_module_address(_pid, "libc");
    uint64_t r_mmap = get_remote_sym_address(_pid, r_libc, "mmap");
    uint64_t r_munmap = get_remote_sym_address(_pid, r_libc, "munmap");
    //uint64_t r_fork = get_remote_sym_address(_pid, r_libc, "fork");
    uint64_t r_waitpid = get_remote_sym_address(_pid, r_libc, "waitpid");
    if (r_mmap == 0 || r_munmap == 0 || r_waitpid == 0) {
        // 目标 libc 无法解析（无节表/符号缺失）：fail-closed，
        // 避免用垃圾地址远程执行破坏目标内存。
        error("failed to resolve libc symbols in target (libc base %lx)", r_libc);
        // 目标已被 pt_attach/pt_int + collect_threads 停住/attach：先还原再失败，
        // 否则 monitor 场景下兄弟线程永久冻结、leader 无法恢复。
        restore_target_after_fail();
        out.Close();
        unlink(corefile);
        return -1;
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
        if (pt_call(_pid, &regs, r_mmap, 6, gv) != 0) {
            error("mmap injection failed (target died?)");
            pt_setregs(_pid, &saved_regs);
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
        if (pt_call(_pid, &regs, inject_page, 0, NULL, &inj_rsp, &inj_word, &fork_child) != 0) {
            error("fork injection failed (target died?)");
            // R50-50: fork 已成功（TRACEFORK auto-attach 子进程冻结在 EVENT_FORK
            // stop）但 pt_call 后续失败（目标中途死亡/超时）——子进程残留为 arthur
            // 的 tracee（TracerPid=arthur, state=t），arthur 退出时释放并继续执行
            // 注入壳代码尾部（int $3 → SIGTRAP 崩溃 / exit(0)）。明确 SIGKILL 回收。
            if (fork_child > 0) {
                ptrace(PTRACE_DETACH, (pid_t)fork_child, NULL, SIGKILL);
                info("killed auto-attached fork child %lu from failed injection", fork_child);
            }
            pt_setregs(_pid, &saved_regs);
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
                warn("restore [rsp-8] in fork child %d failed (%s) - child not traced "
                     "(mode 2?), snapshot keeps injected 0", _core_pid, strerror(errno));
            }
        }
    }

    // munmap injected page.
    {
        uint64_t gv[2] = {inject_page, 0x1000};
        // R50-1: 返回未检查——目标中途死亡时 regs 未初始化，下面 get_rc() 读垃圾
        // 进日志；注入页泄漏。检查并告警（acore 已有效，仅 best-effort 清理）。
        if (pt_call(_pid, &regs, r_munmap, 2, gv) != 0) {
            warn("munmap injection failed (target died?)");
        }
        info("munmap = %d", (int)regs.get_rc());
    }

    // restore program 
    pt_setregs(_pid, &saved_regs);

    // detach all threads
    for(pid_t& tid : _process._thrd_pid) {
        pt_detach(tid);
    }
    ts_pause.end();

    if (!sys_core) {
        // R50-6: 失败路径在末尾杀 fork 子进程之前提前 return，子进程会作为
        // TRACEFORK 停止态 tracee 泄漏（若目标有 SIGTRAP handler，detach 后
        // 重投的 SIGTRAP 被处理，子进程作为目标副本继续存活）。统一先杀。
        auto kill_fork_child = [&]() -> void {
            pt_child_skip_int3(_core_pid, inject_page, inject_exit_off);   // B195
            ptrace(PTRACE_DETACH, _core_pid, NULL, SIGKILL);
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
    ptrace(PTRACE_DETACH, _core_pid, NULL, SIGKILL);
    //assert(rc == 0);

    // now the process becomes zombie,
    // we have to waitpid the forked pid.
    // B76 (Codex B6 review): 末尾 re-attach 的 pt_attach/pt_getregs/pt_setregs/
    // pt_detach 返回全被忽略——目标若在自由运行窗口退出/被另一 tracer 占用，
    // attach 失败后继续注入会读到垃圾。acore 已写（有效），此处告警而非静默成功。
    // b6 (Codex review): attach 失败后仍无条件 getregs/waitpid/setregs/detach，
    // 在未 attached/已死亡目标上执行并消费垃圾寄存器——跳过收尾注入，dump 仍有效。
    if (pt_attach(_pid) != 0) {
        warn("re-attach of %d failed; injected waitpid may not have reaped the "
             "fork child", _pid);
    } else {
        pt_getregs(_pid, &saved_regs);
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
            if (pt_call(_pid, &regs, r_waitpid, 3, gv) != 0) {
                // R50-38: 注入 waitpid 失败不必然是"target died"——mode 2 下
                // fork 子进程非 tracee，DETACH+SIGKILL 无效，子进程靠 int $3 内核
                // core 后自行死亡；大目标内核 core dump 可 >10s，pt_call 超时
                // 触发同一失败路径。两种情况都会让子进程 zombie 残留（目标退出或
                // 自行 waitpid 才回收）。如实区分告警，不再误导为"target died"。
                warn("waitpid injection failed (target died, or mode-2 kernel "
                     "core dump exceeded 10s); fork child %d may linger as a "
                     "zombie until the target exits", (int)_core_pid);
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
        pt_setregs(_pid, &saved_regs);
        pt_detach(_pid);
    }

    info("Process %u paused %0.3f ms.", _pid, ts_pause.timediff()*1000);
    out.PrintStat();
    out.Close();
    // R50-38: mode 2（sys_core）的元数据 acore 无 magic/LOADS/ELF/尾标
    //（WriteFileHeader/WriteLoads/WriteElfHeader/WriteTailMark 被跳过），且
    // merge(-m) 未实现——产出物（元数据 + 内核 core）无法合并成可用 core，
    // 内核 core 还是注入子进程的单线程快照（寄存器是注入态）。exit 0 会误导
    // 自动化判成功；如实告警。
    if (sys_core) {
        warn("mode 2: metadata acore '%s' cannot be merged into a usable core "
             "(merge -m not implemented); kernel core is a single-threaded "
             "snapshot of the injected child with injection-state registers",
             corefile);
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
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = out.Open(corefile);
    if (rc < 0) {
        return -1;
    }

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

    // stop tracee
    // R50-1: pt_int 返回未检查——INTERRUPT 失败（目标已退出 ESRCH / 非 seize 态
    // EIO）时静默继续，后续在未停住的目标上注入/采集。fail-closed。
    if (pt_int(_pid) != 0) {
        error("cannot interrupt %d (%s)", _pid, strerror(errno));
        out.Close();
        unlink(corefile);
        return -1;
    }

    // get all threads pid（attach 全部非主线程，剔除已退出的）
    // B77: collect_threads 失败（opendir / 非 ESRCH attach 错误）时 fail-closed。
    // R50-6: leader 已被 INTERRUPT 停住；失败须还原（detach 兄弟 + 清 TRACEFORK +
    // CONT leader），否则目标冻结、monitor 误以为仍在监控。
    if (collect_threads(_pid) != 0) {
        error("failed to collect threads of %d", _pid);
        restore_target_after_fail();
        // b41 (Codex review): 清理已打开的空 acore（8 字节 header），不残留假文件。
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
 
    // we've injected an 'int 3' in child process, that generates a corefile by kernel.
    // B39: SETOPTIONS 是整体替换——直接设 TRACEFORK 会清掉 pt_monitor 设的
    // TRACEEXIT，monitor 的退出检测降级。GET 现有选项后 OR 上 TRACEFORK。
    if (!sys_core) {
        // 用跟踪的 _ptrace_options（pt_monitor 设的 TRACEEXIT）叠加 TRACEFORK，
        // 避免整体替换清掉 TRACEEXIT（B39）。
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

    // 从目标进程自身 libc 的 .dynsym 解析符号地址（B11），
    // 不再假设宿主 libc 与目标 libc 同构。
    uint64_t r_libc = get_module_address(_pid, "libc");
    uint64_t r_mmap = get_remote_sym_address(_pid, r_libc, "mmap");
    uint64_t r_munmap = get_remote_sym_address(_pid, r_libc, "munmap");
    //uint64_t r_fork = get_remote_sym_address(_pid, r_libc, "fork");
    uint64_t r_waitpid = get_remote_sym_address(_pid, r_libc, "waitpid");
    if (r_mmap == 0 || r_munmap == 0 || r_waitpid == 0) {
        // 目标 libc 无法解析（无节表/符号缺失）：fail-closed，
        // 避免用垃圾地址远程执行破坏目标内存。
        error("failed to resolve libc symbols in target (libc base %lx)", r_libc);
        // 目标已被 pt_attach/pt_int + collect_threads 停住/attach：先还原再失败，
        // 否则 monitor 场景下兄弟线程永久冻结、leader 无法恢复。
        restore_target_after_fail();
        out.Close();
        unlink(corefile);
        return -1;
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
        if (pt_call(_pid, &regs, r_mmap, 6, gv, NULL, NULL, NULL, &mmap_death) != 0) {
            // B197: 并发崩溃（B158 "crash during injection"）时 leader 停在崩溃
            // delivery-stop——restore_target_after_fail 的 CONT(0) 会抑制崩溃信号、
            // 目标"复活"崩溃丢失（实证：失败 dump 窗口 kill-SEGV 后目标存活、无
            // 采集）。先探测崩溃并返回给 monitor 采集（保留停靠不 CONT；被捕获则
            // CONT(sig) 中继走 handler，与 B184 对齐）。
            int crash = probe_crash_stop(_pid);
            if (crash != 0) {
                if (signal_is_caught(_pid, crash)) {
                    info("leader stopped at caught %s after failed injection; relaying to handler",
                         strsignal(crash));
                    ptrace(PTRACE_SETOPTIONS, _pid, 0, _ptrace_options);
                    ptrace(PTRACE_CONT, _pid, NULL, (uintptr_t) crash);
                } else {
                    info("leader stopped at %s after failed injection; returning to collect",
                         strsignal(crash));
                    for (pid_t& tid : _process._thrd_pid) {
                        if (tid != _pid) {
                            ptrace(PTRACE_DETACH, tid, NULL, NULL);
                        }
                    }
                    _process._thrd_pid.clear();
                    ptrace(PTRACE_SETOPTIONS, _pid, 0, _ptrace_options);   // 清 TRACEFORK，不 CONT
                }
                out.Close();
                unlink(corefile);
                return crash;
            }
            // B198: 目标在注入期间被杀（SIGKILL/OOM/看门狗）——死亡 SIGCHLD 被
            // dump 噪音 first-wins 合并吞掉（实证：monitor 继续监控死进程、8s 不
            // 退出、额外 SIGUSR1 无效）。pt_call 内 waitpid 已消费死亡状态（本函数
            // detect_leader_death 拿不到），用 out_death 捕获；返回 -2 让 monitor
            // 清理 -o 并退出。
            int death = mmap_death ? mmap_death : detect_leader_death(_pid);
            if (death != 0) {
                if (death == SIGILL || death == SIGABRT || death == SIGSEGV) {
                    // 崩溃 stop（probe_crash_stop 之后新到）——按崩溃返回，monitor 采集。
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
            pt_setregs(_pid, &saved_regs);
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
        if (pt_call(_pid, &regs, inject_page, 0, NULL, &inj_rsp, &inj_word, &fork_child) != 0) {
            error("fork injection failed (target died?)");
            // R50-50: fork 已成功（TRACEFORK auto-attach 子进程冻结在 EVENT_FORK
            // stop）但 pt_call 后续失败（目标中途死亡/超时）——子进程残留为 arthur
            // 的 tracee（TracerPid=arthur, state=t），arthur 退出时释放并继续执行
            // 注入壳代码尾部（int $3 → SIGTRAP 崩溃 / exit(0)）。明确 SIGKILL 回收。
            if (fork_child > 0) {
                ptrace(PTRACE_DETACH, (pid_t)fork_child, NULL, SIGKILL);
                info("killed auto-attached fork child %lu from failed injection", fork_child);
            }
            pt_setregs(_pid, &saved_regs);
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
                warn("restore [rsp-8] in fork child %d failed (%s) - child not traced "
                     "(mode 2?), snapshot keeps injected 0", _core_pid, strerror(errno));
            }
        }
    }

    // munmap injected page.
    {
        uint64_t gv[2] = {inject_page, 0x1000};
        // R50-1: 返回未检查——目标中途死亡时 regs 未初始化，下面 get_rc() 读垃圾
        // 进日志；注入页泄漏。检查并告警（acore 已有效，仅 best-effort 清理）。
        if (pt_call(_pid, &regs, r_munmap, 2, gv) != 0) {
            warn("munmap injection failed (target died?)");
        }
        info("munmap = %d", (int)regs.get_rc());
    }

    // restore program regs
    pt_setregs(_pid, &saved_regs);

    // detach all threads
    for(pid_t& tid : _process._thrd_pid) {
        if(tid == _pid)
            continue;
        
        // in pt_detach use SIGCONT, wont work here which will have tracee not resumed
        // send NULL signal instead
        ptrace(PTRACE_DETACH, tid, NULL, NULL); 
    }
    ts_pause.end();

    /**
     * Tracee will resume executing while writing out corefile with data from forked process;
     * if any exception happens in between this section, tracee will be stopped; 
     * the signal is supposed to be pending before finishing writing corefile
     */
    pt_cont(_pid);
    _process._thrd_pid.clear(); // clear all thread id in array

    // R50-1: leader 已被 pt_cont 放行（运行中带 TRACEFORK）。此处失败若只调
    // restore_target_after_fail，对运行中 tracee 的 SETOPTIONS/CONT 都会失败（ESRCH，
    // agent 实测），TRACEFORK 残留 → 目标下次 fork 被冻结/SIGTRAP 误杀；且 _core_pid
    // 子进程（auto-attach 冻结）未被回收。先杀子进程、再 INTERRUPT 停住 leader 清
    // TRACEFORK（保留 TRACEEXIT）再 CONT。
    auto recover_after_resume = [&]() -> void {
        pt_child_skip_int3(_core_pid, inject_page, inject_exit_off);   // B195
        ptrace(PTRACE_DETACH, _core_pid, NULL, SIGKILL);   // 回收冻结的 fork 子进程
        if (pt_int(_pid) == 0) {                            // 停住 leader 才能 SETOPTIONS
            ptrace(PTRACE_SETOPTIONS, _pid, 0, _ptrace_options);
            ptrace(PTRACE_CONT, _pid, NULL, NULL);
        }
        // R50-51: 收尾 drain 本 lambda 的 pt_int INTERRUPT 噪音（同 restore 加固，
        // C133——stale CLD_STOPPED/0 会遮蔽后续真实崩溃信号的 SIGCHLD）。
        drain_noise_sigchld();
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
    ptrace(PTRACE_DETACH, _core_pid, NULL, SIGKILL);
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
    pid_t wr = waitpid(_pid, &s, WUNTRACED | WNOHANG);
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
            // pid 并 DETACH(SIGCONT) 解冻，让它正常继续运行。
            // R50-1: 只有 FORK/CLONE/VFORK（事件 1/2/3）才有 auto-attach 的子进程要
            // detach。EVENT_EXIT 的 GETEVENTMSG 是退出码（实测 exit(42)→0x2a00），
            // 把它当 pid 去 DETACH 会对无关进程发伪 ptrace 调用。
            if (ev == PTRACE_EVENT_FORK || ev == PTRACE_EVENT_VFORK || ev == PTRACE_EVENT_CLONE) {
                unsigned long child_pid = 0;
                if (ptrace(PTRACE_GETEVENTMSG, _pid, 0, &child_pid) == 0 && child_pid > 0) {
                    ptrace(PTRACE_DETACH, (pid_t)child_pid, NULL, (void*)SIGCONT);
                    info("detached auto-attached fork child %lu", child_pid);
                }
            }
        }
    } else {
        // now the process becomes zombie,
        // we have to waitpid the forked pid.
        // R50-1: pt_int 返回未检查——失败时 leader 未停住，注入 waitpid 跑在运行中
        // 目标上。acore 已有效，告警（child 可能残留 zombie）。
        if (pt_int(_pid) != 0) {
            warn("re-interrupt of %d failed (%s); fork child may linger as zombie",
                 _pid, strerror(errno));
        }
    }
    // B151: 目标在 dump 窗口内崩溃（真实信号 delivery-stop，非 ptrace 事件）。
    // 若仍做 waitpid 注入，pt_call 的 CONT(0) 会把 pending 的崩溃信号抑制掉
    // （与 H2 入口同机制），随后崩溃采集的 NT_SIGINFO 变成注入完成的假 SIGSEGV
    // ——实测 0xdeadbeef 崩溃 → core 报 si_addr=0、si_code 变注入值。崩溃停靠时
    // 跳过注入，保留真实崩溃现场（寄存器 + si_addr/si_code）供崩溃采集读取。
    // fork 子进程已在上方 SIGKILL，leader 崩溃后由其 reaper（init）收尸，无需注入。
    bool crashed_in_window =
        WIFSTOPPED(s) && !stopped_at_ptrace_event &&
        (sig == SIGILL || sig == SIGABRT || sig == SIGSEGV);
    if (group_stop_event) {
        // R50-50: 组停靠 leader——waitpid 注入的 pt_call CONT(0) 会解除作业控制
        // 停靠。跳过注入，末尾用 LISTEN 保持停靠；fork 子进程已 SIGKILL（可能
        // 残留 zombie，等目标 SIGCONT 后自身 waitpid 回收，同 B73 告警情形）。
        info("leader %d in job-control group-stop during dump; skipping waitpid "
             "injection to preserve the stop", _pid);
    } else if (crashed_in_window) {
        // B184: crashed_in_window 缺 signal_is_caught（B168 对称遗漏）——dump 窗口内
        // leader 停在**被捕获**的 crash-class delivery-stop（handler 目标做 safepoint/
        // 崩溃上报）时，原实现跳过注入 + 返回崩溃信号 → 假崩溃采集 + kill_crashed
        // 重投走 handler 进程不死 + 静默放弃监控。被捕获则中继（CONT(sig) 让 handler
        // 跑），dump 正常完成返回 0；未捕获才是真崩溃，保留现场供崩溃采集。
        if (signal_is_caught(_pid, sig)) {
            info("leader %d stopped at caught %s during dump; relaying to handler "
                 "(not crash collection)", _pid, strsignal(sig));
            ptrace(PTRACE_CONT, _pid, NULL, (uintptr_t) sig);
            sig = 0;
        } else {
            info("leader %d crashed in %s delivery-stop during dump; "
                 "skipping waitpid injection to preserve crash stop",
                 _pid, strsignal(sig));
        }
    } else {
        pt_getregs(_pid, &saved_regs);
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
            if (pt_call(_pid, &regs, r_waitpid, 3, gv) != 0) {
                warn("waitpid injection failed (target died?)");
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
        pt_setregs(_pid, &saved_regs);
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
            (inj_si.si_signo == SIGILL || inj_si.si_signo == SIGABRT || inj_si.si_signo == SIGSEGV) &&
            (inj_si.si_code == SI_USER || inj_si.si_code == SI_TKILL)) {
            int ic = inj_si.si_signo;
            if (signal_is_caught(_pid, ic)) {
                info("leader %d stopped at caught %s after injection; relaying to "
                     "handler (not crash collection)", _pid, strsignal(ic));
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
    // 恢复 pt_monitor 设的 TRACEEXIT（去掉 TRACEFORK）——用跟踪的 _ptrace_options，
    // 避免 SETOPTIONS(0) 全清（B39）。
    rc = ptrace(PTRACE_SETOPTIONS, _pid, 0, _ptrace_options);
    if (rc != 0) {
        error("clear TRACEFORK on %d failed", _pid);
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
        }
    } else if (crash_preserved) {
        // B189: 注入后崩溃——保留 delivery-stop 供崩溃采集（不 CONT，避免 CONT(0)
        // 抑制崩溃信号）；被捕获则 CONT(sig) 中继走 handler（SETOPTIONS 已在 leader
        // 停止时清 TRACEFORK）。
        if (relay_sig) {
            ptrace(PTRACE_CONT, _pid, NULL, (uintptr_t) relay_sig);
        }
    } else if(!WIFSTOPPED(s) || stopped_at_ptrace_event) {
        pt_cont(_pid);
    }

    info("Process %u paused %0.3f ms.", _pid, ts_pause.timediff()*1000);
    out.PrintStat();
    out.Close();

    // clean pending signal generated above by tracee
    // b38 (Codex review): sigset_t 未 sigemptyset 就在未初始化位图上 sigaddset 是
    // UB——除 SIGCHLD 外的垃圾位会进入 sigwaitinfo 集合，monitor 状态机可能等错信号。
    // R50-11 (M3): 原 sigwaitinfo 阻塞等待——forkcore_m 收尾窗口内若 leader 崩溃
    // 进入 SIGSEGV delivery-stop，其 SIGCHLD 会被这里消费掉（siginfo 丢弃），
    // monitor 主循环再也等不到该崩溃通知 → leader 冻结 + monitor 永久挂起。
    // 改 sigtimedwait 零超时：只 drain 已 pending 的噪音 SIGCHLD，不阻塞等待，
    // 之后的真实崩溃 SIGCHLD 留给主循环。
    // R50-51: 零超时 drain 仍会吞掉收尾窗口内已 pending 的崩溃 SIGCHLD（C134，
    // 崩溃 SIGCHLD 还会被 coalescing 合并进 INTERRUPT 噪音，siginfo 分类判不出）。
    // 改两步：先 detect_leader_death 按 wait 状态确定性检出收尾窗口内崩溃/退出并
    // 返回给 monitor；再 drain_noise_sigchld 只清 INTERRUPT 噪音（CLD_STOPPED/0）。
    // 组停靠场景由此返回 GROUP_STOP_SENTINEL 让 monitor 直接置位（不依赖被 first-wins
    // 污染的 SIGCHLD siginfo 中继——否则 monitor 出队 status=0 会 CONT(0) 解除组停靠）。
    int death = detect_leader_death(_pid);
    if (death != 0) {
        drain_noise_sigchld();
        if (death == -2) {
            return -2;
        }
        // B184: detect_leader_death 检出的崩溃信号若被捕获（handler），不是致命
        // 崩溃——与 B168 对齐中继（CONT(sig) 走 handler），不触发假崩溃采集。
        // WIFSIGNALED（真死亡）不在此列（进程已死，无 handler 可走）。
        if ((death == SIGILL || death == SIGABRT || death == SIGSEGV) &&
            signal_is_caught(_pid, death)) {
            info("leader %d stopped at caught %s in tail window; relaying to "
                 "handler (not crash collection)", _pid, strsignal(death));
            ptrace(PTRACE_CONT, _pid, NULL, (uintptr_t) death);
            return 0;
        }
        return death;
    }
    drain_noise_sigchld();
    if (group_stop_event) {
        return GROUP_STOP_SENTINEL;
    }

    return sig;
}

/* monitor() will attacg the target process
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
    siginfo_t sig_info;
    bool leader_in_group_stop = false;
    sigset_t mask;
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = out.Open(corefile);
    if (rc < 0) {
        return -1;
    }

    // write acore
    // R50-1: WriteFileHeader 返回未检查——缺头 acore 静默产出。
    if (WriteFileHeader(out) != 0) {
        error("write acore header failed");
        out.Close();
        unlink(corefile);
        return -1;
    }

    // B57: pt_monitor 失败（目标瞬时退出/无权限）时干净退出，不留空 acore。
    rc = pt_monitor(_pid);
    if (rc != 0) {
        error("monitor attach failed; process %d not traced", _pid);
        out.Close();
        unlink(corefile);
        return -1;
    }
    // B39: 内核无 GETOPTIONS，arthur 自己跟踪设过的 options
    _ptrace_options = PTRACE_O_TRACEEXIT;
    info("Launched in monitor mode");

    // B201: 目标在 pt_monitor 初始 attach 窗口崩溃（fault/kill 落在 SEIZE/pt_int
    // 期间）时，SIGSEGV delivery-stop 的 SIGCHLD 被 pt_int/pt_wait 消费/合并吞掉
    //（monitor SigPnd=0、wchan=do_sigtimedwait），目标停在 delivery-stop（state=t）、
    // monitor 阻塞 sigwaitinfo 永久挂起、崩溃既不采集也不杀目标（实证 3/3）。用
    // waitpid 状态（免疫 SIGCHLD 合并）检测 attach 窗口崩溃：无 handler → exit_sig
    // 走崩溃采集；有 handler → CONT(sig) 中继；已退出 → 清理返回。
    {
        int death = detect_leader_death(_pid);
        if (death != 0) {
            if (death == -2) {
                info("process %d exited during monitor attach", _pid);
                out.Close();
                unlink(corefile);
                return 0;
            }
            if ((death == SIGILL || death == SIGABRT || death == SIGSEGV) &&
                signal_is_caught(_pid, death)) {
                info("leader %d stopped at caught %s during attach; relaying to handler",
                     _pid, strsignal(death));
                ptrace(PTRACE_CONT, _pid, NULL, (uintptr_t) death);
            } else {
                info("leader %d crashed during attach (%s); collecting",
                     _pid, strsignal(death));
                exit_sig = death;
                goto crash_collect;
            }
        }
    }

    // block all signals
    // b38 (Codex review): 未 sigemptyset 的 sigset_t 直接 sigaddset 是 UB，
    // 垃圾位会被 SIG_BLOCK 阻塞任意信号并进入 sigwaitinfo 等待集合。
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD); // signal from tracee
    sigaddset(&mask, SIGUSR1); // signal for generating corefile while monitor
    sigprocmask(SIG_BLOCK, &mask, NULL);

    // B157: leader 是否处于组停靠（SIGSTOP/TSTP/TTIN/TTOU）。SIGCHLD handler 在
    // LISTEN 组停靠时置位、中继/恢复时清零；H2 预检据此跳过 SIGUSR1 dump（waitpid
    // 查不到：组停靠 wait status 已被 LISTEN 消费）。
    while(1) {
        if(signal_forkcore) {
            if (signal_forkcore < 0) {
                if (signal_forkcore == -2) {
                    // B156: 目标在 SIGUSR1 dump 期间正常退出（exit/main 返回）——
                    // 清理 -o 空 acore 并返回（与正常退出路径一致），不再挂起等待。
                    info("process %d exited during SIGUSR1 dump", _pid);
                    out.Close();
                    if (unlink(corefile) != 0) {
                        error("failed to remove empty acore %s (%s)", corefile, strerror(errno));
                    }
                    return 0;
                }
                if (signal_forkcore == GROUP_STOP_SENTINEL) {
                    // R50-51: forkcore_m 在 dump 窗口内检出 leader 组停靠并已 LISTEN
                    // 保持停靠（B172）。不依赖 SIGCHLD siginfo 中继（first-wins 会被
                    // INTERRUPT 噪音污染，出队 status=0 会走 CONT(0) 解除组停靠）。
                    // 直接置位标志，后续 SIGUSR1 dump 被 H2 预检跳过；SIGCONT 恢复时
                    // 下方中继路径清标志。
                    info("leader in group-stop during dump; skipping further dumps "
                         "until resumed (SIGCONT)");
                    leader_in_group_stop = true;
                    signal_forkcore = 0;
                    continue;
                }
                // forkcore_m 失败（fail-closed）：restore_target_after_fail 已 resume
                // leader，无需、也不应把 -1 当中继信号注入。跳过。
                info("forkcore failed (%d), continue monitoring", signal_forkcore);
                signal_forkcore = 0;
                continue;
            }
            info("signal forkcore %d", signal_forkcore);
            if (signal_forkcore == SIGILL || signal_forkcore == SIGABRT || signal_forkcore == SIGSEGV) {
                // write out corefile under SIGILL, SIGABRT, SIGSEGV
                exit_sig = signal_forkcore;
                break;
            } else { // relay signals to tracee
                ptrace(PTRACE_CONT, _pid, NULL, (uintptr_t) signal_forkcore);
                signal_forkcore = 0; // reset forkcore signal
                continue;
            }
        }

        // unblock all signals and wait atomically
        sigwaitinfo(&mask, &sig_info);
        int signo = sig_info.si_signo;
        if(signo == SIGCHLD) {
            // signal from tracee
            int status = sig_info.si_status; // status signal code
            int code = sig_info.si_code;  // tracee current state
            if (code == CLD_KILLED || code == CLD_DUMPED || code == CLD_EXITED){
                if (code == CLD_EXITED) {
                    // 正常退出，si_status 是退出码（不是信号号）
                    info("process %d exited (code %d)", _pid, status);
                } else if (status == SIGILL || status == SIGABRT || status == SIGSEGV) {
                    // B38: 进程死于致命信号但未产生 leader 的 signal-delivery-stop
                    // （通常是非 leader 线程崩溃，进程已死，内存/寄存器已消失，
                    // 无法采集现场）。如实报告并清掉开头写的空 acore。
                    // b38 (Codex review): 崩溃且无 core 是失败而非成功——返回非零，
                    // 避免自动化把"目标崩溃、没产出 core"判成成功；unlink 结果要检查。
                    error("%s: process %d crashed (likely a non-leader thread); "
                          "no core written", strsignal(status), _pid);
                    out.Close();
                    if (unlink(corefile) != 0) {
                        error("failed to remove empty acore %s (%s)", corefile, strerror(errno));
                    }
                    return -1;
                } else {
                    info("%s: process %d terminated by signal", strsignal(status), _pid);
                    ptrace(PTRACE_DETACH, _pid, NULL, (uintptr_t) status);
                }
                // b38 (Codex review): 正常退出/非捕获信号终止都没产出 core——
                // 统一清掉开头写的 8 字节空 acore，不残留误导性假文件。
                out.Close();
                if (unlink(corefile) != 0) {
                    error("failed to remove empty acore %s (%s)", corefile, strerror(errno));
                }
                return 0;
            } else if (status == SIGILL || status == SIGABRT || status == SIGSEGV) {
                // B168: 崩溃类信号的 delivery-stop 不必然是致命崩溃——目标可能装了
                // handler（Node.js/V8/JVM 装 SIGSEGV/SIGABRT handler 做 safepoint/
                // 崩溃上报）。原实现只看裸信号号就 break 进崩溃采集 + kill_crashed
                // 重投：handler 目标收到重投信号走 handler 不死，却写出假崩溃 core、
                // 返回 0、静默放弃监控（实证：core 显示致命 SIGSEGV 但进程活着继续跑）。
                // 查 SigCgt：捕获则中继（CONT 让 handler 跑）继续监控；未捕获才是
                // 致命崩溃。同步 fault 的 handler 若 return 会指令重放——那是目标
                // 自身行为，arthur 只正确中继。
                if (signal_is_caught(_pid, status)) {
                    info("signal %s caught by target handler; relaying (not crash collection)",
                         strsignal(status));
                    ptrace(PTRACE_CONT, _pid, NULL, (uintptr_t) status);
                    continue;
                }
                // write out corefile under SIGILL, SIGABRT, SIGSEGV
                exit_sig = status;
                break;
            } else { // relay signals to tracee
                // 中继目标用 sig_info.si_pid：TRACEFORK 自动 attach 的子进程
                // 或非 leader 线程的停靠，si_pid 才是正确的恢复目标；固定 _pid
                // 会恢复错误线程，让真正的停靠者永久冻结（问题2）。
                // b39 (Codex review): SIGCHLD.si_status 对所有 ptrace 停靠只是裸信号号
                // （事件号只在 waitpid 的 status 字高 16 位，sigwaitinfo 拿不到）。
                // 对停止类信号（SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU）先试 PTRACE_LISTEN——
                // 组停靠的正确恢复是保持停靠并停止上报，避免反复重投 SIGSTOP 的
                // stop-resume 空转；非组停靠（普通 signal-delivery stop）回退 CONT(sig)。
                int sig = status;
                if ((sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) &&
                    ptrace(PTRACE_LISTEN, sig_info.si_pid, NULL, NULL) == 0) {
                    // 组停靠：已 LISTEN，保持停靠等 SIGCONT。不重投信号。
                    // B157: 记录 leader 组停靠状态（H2 预检据此跳过 SIGUSR1 dump，
                    // 避免 forkcore_m 的 pt_int/注入把组停靠消费掉、leader 被恢复）。
                    if (sig_info.si_pid == _pid) {
                        leader_in_group_stop = true;
                    }
                } else {
                    // B157: 中继/恢复（CONT(sig)）——若 leader 被 SIGCONT 恢复，
                    // 清除组停靠标志。
                    if (sig_info.si_pid == _pid) {
                        leader_in_group_stop = false;
                    }
                    ptrace(PTRACE_CONT, sig_info.si_pid, NULL, (uintptr_t) status);
                }
            }
            signal_forkcore = 0; // reset signal 
        } else {
            // signal SIGUSR1 to arthur
            // R50-11 (H2): SIGUSR1 与崩溃同刻到达时出队顺序不定——若 leader 此刻
            // 已停在崩溃信号（SIGSEGV/SIGILL/SIGABRT）的 delivery-stop，forkcore_m
            // 的 pt_int 无法区分"干净停靠"与"崩溃停靠"，pt_call 的 CONT(0) 会把
            // pending 的崩溃信号以信号 0 抑制掉：同步 fault 重放 / 异步 kill 目标
            // "复活"，随后产出寄存器全零、内存竞态的垃圾 dump。先 WNOHANG 查 leader
            // 停靠原因，已是崩溃停靠则直接走崩溃采集（跳过注入）。
            {
                // B157: 组停靠检测靠 monitor 侧标志位 leader_in_group_stop（SIGCHLD
                // handler 在 LISTEN 时维护）——waitpid 查不到：组停靠的 wait status
                // 已被主循环的 LISTEN 消费（实证 h2 waitpid=0），且 SEIZE 下组停靠
                // 报为 PTRACE_EVENT_STOP。组停靠时跳过 dump，避免 forkcore_m 的
                // pt_int/注入把组停靠消费掉、leader 被静默恢复运行（实证 State t→R）。
                // SIGUSR1 被消费，用户 SIGCONT 后可重试。
                if (leader_in_group_stop) {
                    info("leader in group-stop; skipping SIGUSR1 dump "
                         "(resume with SIGCONT and retry)");
                    signal_forkcore = 0;
                    continue;
                }
                int ws = 0;
                if (waitpid(_pid, &ws, WUNTRACED | WNOHANG) > 0 && WIFSTOPPED(ws) &&
                    ((ws >> 16) & 0xff) == 0) {   // 非 ptrace event 停靠
                    int st = WSTOPSIG(ws);
                    if (st == SIGILL || st == SIGABRT || st == SIGSEGV) {
                        // B184: B168 的对称遗漏——此预检路径不查 signal_is_caught。
                        // leader 停在**被捕获**的 crash-class delivery-stop（V8/Node
                        // 装 crash handler 做 safepoint/崩溃上报）且 SIGUSR1 先出队时，
                        // 原实现把它当致命崩溃 break → 假崩溃 core + kill_crashed 重投
                        // 走 handler 进程不死 + 静默放弃监控（B168 只修了主循环 path B）。
                        // 与 path B 对齐：被捕获则跳过 dump、交给主循环中继（SIGCHLD
                        // 仍在队列，path B 会 CONT(sig) 让 handler 跑）。
                        if (signal_is_caught(_pid, st)) {
                            info("signal %s caught by target handler; relaying "
                                 "(not crash collection)", strsignal(st));
                            signal_forkcore = 0;
                            continue;
                        }
                        info("leader already in %s delivery-stop; skipping SIGUSR1 dump",
                             strsignal(st));
                        exit_sig = st;
                        break;   // 走崩溃采集路径
                    }
                    // B170: leader 停在**非崩溃**停靠（pending 的可中继信号、组停靠
                    // SIGCHLD 尚未被主循环处理等）——forkcore_m 的 pt_int 对已停
                    // tracee 的 INTERRUPT 不产生新停靠（实证），pt_wait 轮询 10s 超时、
                    // 失败路径还不 CONT → leader 冻结 + SIGUSR1 dump 静默跳过。
                    // 这里消费掉 wait status 后跳过 dump，让 pending 的 SIGCHLD 由
                    // 主循环中继（CONT(sig)/LISTEN），leader 保持正确状态。
                    info("leader stopped at %s; skipping SIGUSR1 dump "
                         "(relay via main loop)", strsignal(st));
                    signal_forkcore = 0;
                    continue;
                }
            }
            // B19: 原实现 `char out[17]; sprintf(out, "acore.%u\n", ...)`——
            // 10 位时间戳时写 18 字节（含 NUL）溢出 1 字节；格式串还带换行。
            // B58: 秒级 time(NULL) 做文件名，同一秒内多次 SIGUSR1 互相覆盖丢数据
            // （实证：3 次 dump 只留 2 个文件）。加单调序号保证唯一。
            // R50-11 (M4): 加目标 pid——两个 monitor 同 CWD 各收到 SIGUSR1 时
            // 各自 dump_seq 从 0 开始，同秒内都写 acore.<sec>.0 互相覆盖。
            char out[48];
            snprintf(out, sizeof(out), "acore.%u.%u.%u",
                     (unsigned)_pid, (unsigned)time(NULL), dump_seq++);
            info("writing out %s...", out);
            signal_forkcore = forkcore_m(out, false);
            info("writing out acore finished, resume monitoring");
        }
    }

crash_collect:
    info("%s: process %d exit", strsignal(exit_sig), _pid);
    info("Writing out corefile...");

    // N1: 崩溃采集路径必须清空跨调用累积的 _phdrs——SIGUSR1 dump（forkcore_m）
    // 之后 _phdrs 已有该次 dump 的 LOAD 段；若不清空，本次崩溃 WriteLoads 再
    // push 一组，ELF 块出现 2× 幻影 phdr，解压时 loads 字节数与 phdr 声明和
    // 不符直接拒绝（实证：wrote 17739776 / phdrs 35479552）。与 B35 在
    // generate/forkcore/forkcore_m 入口的清理保持一致。
    _phdrs.clear();
    _core_pid = 0;
    // B199: 崩溃采集时所有线程 pr_cursig 用进程崩溃信号（WriteThreadMeta 覆盖
    // si_signo）——worker 线程停在 attach SIGSTOP，不覆盖则 gdb 报 "SIGSTOP"。
    _crash_sig = exit_sig;

    // R50-6: 崩溃采集的失败路径同样要让崩溃进程死亡——成功路径末尾对每个线程
    // PTRACE_DETACH(exit_sig) 重投崩溃信号；失败路径若只 detach(NULL) 或直接
    // return，leader 停在崩溃信号 delivery-stop，内核自动 detach 不重投信号，
    // 进程既不运行也不死亡，滞留冻结。统一走这个 kill_crashed。
    auto kill_crashed = [&]() -> void {
        for (pid_t& tid : _process._thrd_pid) {
            ptrace(PTRACE_DETACH, tid, NULL, (uintptr_t) exit_sig);
        }
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
    if (WriteProcessMeta(out, maps) != 0) {
        error("write process meta failed for crashed process");
        kill_crashed();
        out.Close();
        unlink(corefile);
        return -1;
    }

    // handle  leader first and then rest
    // R50-1: WriteThreadMeta 现在会因写失败返回 -1；忽略则线程块缺失仍继续
    // LOADS/ELF → 坏 acore。检查并清理部分产物。
    if (WriteThreadMeta(out, _pid, true) != 0) {
        error("write leader thread meta failed");
        kill_crashed();
        out.Close();
        unlink(corefile);
        return -1;
    }
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == _pid)
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
        if (WriteLoads(out, _pid, maps) != 0) {
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

    for (pid_t& tid : _process._thrd_pid) {
        // cannot guarantee thread exit order, not to check ptrace rc
        ptrace(PTRACE_DETACH, tid, NULL, (uintptr_t) exit_sig);
    }
    out.PrintStat();
    out.Close();
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
    // R50-20 (#2): 同路径时 fopen(out,"wb") 截断输入 acore。
    if (same_file(in_file, out_core)) {
        error("decompress: input and output are the same file (%s)", in_file);
        cleanup_decompress();
        return -1;
    }
    FILE *fout = fopen(out_core, "wb");
    if (!fout) {
        error("Fail to open file %s", out_core);
        // B50 残留: ReadMeta 已分配 ProcFiles/decoders/线程 _d_stat，
        // fopen 失败提前返回时未清理 → LeakSanitizer 报 8999 字节泄漏。
        cleanup_decompress();
        return -1;
    }
    long p_elf = ftell(fout);

    // b23 (Codex review): 失败会遗留部分输出 core，误导调用方（看起来像有效结果）。
    // 各失败路径先打印各自的具体错误，再经 fail_core 关流、删除不完整产物并清理。
    // （完整方案：写同目录临时文件、验证/flush 成功后原子 rename，暂留。）
    auto fail_core = [&]() -> int {
        in.Close();
        fclose(fout);
        unlink(out_core);
        cleanup_decompress();
        return -1;
    };

    // parse
    // B163: ParseAll 失败（maps 超 region 上限等损坏 acore）时 fail-closed。
    if (_process.ParseAll() != 0) {
        error("parse /proc data failed (acore corrupt), core removed");
        return fail_core();
    }

    // make room for elf headers
    int phnum = _process._d_maps->size() + 1;
    size_t hdr_size = sizeof(Elf64_Ehdr) + (phnum * sizeof(Elf64_Phdr));
    hdr_size = roundup(hdr_size + 4096, 4096);
    dprint("room = %d", hdr_size);
    rc = makeroom(fout, hdr_size);
    if (rc < 0) {
        error("make room for elf headers failed, core removed");
        return fail_core();
    }
    long p_note = ftell(fout);

    // makeup notes
    int notes_size = GenerateNotes();
    Elf64_Phdr note_phdr = {0};
    note_phdr.p_type = PT_NOTE;
    note_phdr.p_offset = p_note;
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
    _offset_load = ftell(fout);

    // write loads
    // B54: 截断 acore 使 ReadLoads 失败时不再 assert abort，干净报错。
    // B60: ReadLoads 返回 ssize_t（实际写出的未压缩字节数）——>2GB 的合法
    // dump 若用 int 返回会被截断成负数误判为失败（实证：3.2GB dump 被拒）。
    ssize_t loads_rc = ReadLoads(in, fout);
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
    rc = ReadElfHeader(in, _process._d_maps->size() + 1);
    if (rc != 0) {
        error("read elf header failed, core incomplete (removed)");
        return fail_core();
    }
    // R50-1: ELF 块 phdr 数超过 maps 预算时，WriteElfHeader 会写穿 makeroom 预留的
    // hdr_size 覆盖 note 数据。构造 acore 可携带任意多 phdr（p_filesz=0 绕过下面
    // 的 loads/expected 校验）；校验总 phdr 数 <= maps 条目 + 1（note）。
    if (_phdrs.size() > _process._d_maps->size() + 1) {
        error("elf phdr count %zu exceeds maps budget %zu (acore corrupt)",
              _phdrs.size(), _process._d_maps->size() + 1);
        return fail_core();
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
            prev_load_end = phdr.p_offset + phdr.p_filesz;
        }
    }
    if (loads_written != expected) {
        error("loads size mismatch: wrote %lu bytes, phdrs declare %lu (acore corrupt, core removed)",
              loads_written, expected);
        return fail_core();
    }
    fseek(fout, p_elf, SEEK_SET);
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
    }

    in.Close();
    fclose(fout);
    cleanup_decompress();
    info("saved corefile '%s'.", out_core);
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
    for (auto& t : _process._threads) {
        if (t._d_stat) { delete t._d_stat; t._d_stat = NULL; }
        if (t._stat) { free(t._stat); t._stat = NULL; }   // GetFile malloc'd
    }

    ProcFile* pfs[] = { _process._cmdline, _process._auxv, _process._maps,
                        _process._environ, _process._io, _process._limits };
    for (ProcFile* pf : pfs) {
        if (pf) {
            free(pf);
        }
    }
    _process._cmdline = _process._auxv = _process._maps = NULL;
    _process._environ = _process._io = _process._limits = NULL;

    // b50 (Codex review): 未清空 _threads/_phdrs——同一 Coredump 重复 decompress()
    // 会保留上一次的线程向量与段头，第二次采集叠加出幻影 phdr/线程。清空以便复用。
    _process._threads.clear();
    _phdrs.clear();
}

int Coredump::test_compress(const char* in_file, const char* out_file)
{
    int rc = 0;
    // R50-20 (#2): 同路径时 out.Open("wb") 会把输入截成 0 字节。
    if (same_file(in_file, out_file)) {
        error("test_compress: input and output are the same file (%s)", in_file);
        return -1;
    }
    FILE *fin = fopen(in_file, "rb");
    if (!fin) {
        error("Fail to open file %s", in_file);
        return -1;
    }

    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = out.Open(out_file);
    if (rc < 0) {
        // R50-6: out 打开失败时 fin 已 fopen，泄漏输入 fd。
        fclose(fin);
        return -1;
    }

    size_t data_size = 0, file_size = 0;
    char buf[4*1024];
    for (;;) {
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
        data_size += len;

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
            file_size += wrc;
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
    if (out.Flush() < 0) {
        error("compress flush failed");
        rc = -1;
    }
    // R50-6: 尾标写失败（磁盘满）时输出缺结束标记，解压必拒；与 rc 一并传播。
    if (WriteTailMark(out) != 0) {
        rc = -1;
    }
    out.Close();
    fclose(fin);

    // R50-20 (#3): 失败时遗留带尾标的部分 .z4——脚本按"文件存在+size>0"误判为有效
    // 产物。与 decompress 的 fail_core 对齐，失败即删。
    if (rc != 0) {
        if (unlink(out_file) != 0) {
            error("failed to remove partial %s (%s)", out_file, strerror(errno));
        }
    }

    info(" %lu => %lu ", data_size, file_size);

    return rc;
}

int Coredump::test_decompress(const char* in_file, const char* out_file)
{
    int rc = 0;
    // R50-20 (#2): 同路径时 fopen(out,"wb") 截断输入 → 静默数据丢失。
    if (same_file(in_file, out_file)) {
        error("test_decompress: input and output are the same file (%s)", in_file);
        return -1;
    }
    Lz4Stream in(Lz4Stream::LZ4_Decompress);
    rc = in.Open(in_file);
    if (rc < 0) {
        return -1;
    }

    FILE *fout = fopen(out_file, "wb");
    if (!fout) {
        error("Fail to open file %s", out_file);
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
            }
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
    fclose(fout);
    in.Close();

    // B167: 失败时遗留部分输出（损坏输入/磁盘满短写）——脚本按"文件存在+size>0"
    // 误判为有效产物。test_compress 已在 R50-20 (#3) 对齐 fail_core 清理，这里
    // 是同一 class 的遗漏。失败即删（fopen(fout) 失败路径无文件，无需删）。
    if (rc != 0) {
        if (unlink(out_file) != 0) {
            error("failed to remove partial %s (%s)", out_file, strerror(errno));
        }
    }

    info("write %lu bytes.", file_size);
    return rc;
}

}; // arthur
