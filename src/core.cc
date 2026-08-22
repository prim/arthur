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

        // find
        int find_len = strlen(so_path);
        char *find = strstr(name, so_path);
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
    for (size_t i = 0; i < phdrs.size(); i++) {
        if (phdrs[i].p_type == ARTHUR_PT_DYNAMIC) {
            dyn_vaddr = base + phdrs[i].p_vaddr;
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
        sym_count = nchain;
    } else if (gnu_hash != 0) {
        uint32_t hdr[4];
        if (pread(fd, hdr, sizeof(hdr), gnu_hash) != (ssize_t)sizeof(hdr)) {
            close(fd);
            return 0;
        }
        uint32_t nbuckets = hdr[0], symoffset = hdr[1], bloom_size = hdr[2];
        uint64_t buckets = gnu_hash + 16 + (uint64_t)bloom_size * 8;
        uint64_t chains = buckets + (uint64_t)nbuckets * 4;
        uint32_t max_chain = 0;
        for (uint32_t b = 0; b < nbuckets; b++) {
            uint32_t idx;
            if (pread(fd, &idx, 4, buckets + b * 4) != 4) {
                close(fd);
                return 0;
            }
            while (idx >= symoffset) {
                uint32_t c = idx - symoffset;
                if (c > max_chain) max_chain = c;
                uint32_t chain;
                if (pread(fd, &chain, 4, chains + c * 4) != 4) {
                    close(fd);
                    return 0;
                }
                if (chain & 1) break;
                idx++;
            }
        }
        sym_count = symoffset + max_chain + 1;
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
            return base + sym.st_value;
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
}

/* pt_ functions, for ptrace_ calls.
 */
static inline int pt_wait(pid_t pid)
{
    int status;
    waitpid(pid, &status, WUNTRACED);
    //assert (rc == pid);
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

// read all xstate registers (x64)
static inline int pt_getxstateregs(pid_t pid, x64_xstatereg *pregs)
{
    int rc;

    struct iovec iov;
    iov.iov_base = pregs;
    iov.iov_len = sizeof(x64_xstatereg);
    rc = ptrace(PTRACE_GETREGSET, pid, NT_X86_XSTATE, &iov);

    // B30: 不 assert，失败由调用方处理
    return rc;
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
// B72: out_inject_rsp/out_orig_word 输出注入时写 0 的 [rsp-8] 槽位与原字——
// fork 注入后子进程（COW 快照）保留注入的 0，父进程恢复了但 dump 读的子进程没有，
// 调用方可用这两个值把原字写回子进程，消除快照污染。
static inline int pt_call(pid_t pid, user_regs64_struct *oregs, uint64_t func, int argc,
                          uint64_t argv[], uint64_t *out_inject_rsp = NULL,
                          uint64_t *out_orig_word = NULL)
{
    int rc, status = 0;
    user_regs64_struct regs;
    assert(argc <= 6);

    // B71: 中途失败也要恢复被注入践踏的状态（[rsp-8] 内存字 + FP/SIMD），
    // 否则 fail-closed 后目标带着注入的 0 / 垃圾 xmm 继续运行。
    user_fpregs64_struct fpregs;
    int fp_saved = 0;
    int stack_saved = 0;
    uint64_t orig_stack_word = 0;
    uint64_t inject_rsp = 0;

    auto fail = [&](const char* msg) -> int {
        error("pt_call: %s %d failed (%s)", msg, pid, strerror(errno));
        // 恢复注入期间被修改的目标状态
#ifndef __aarch64__
        if (stack_saved) {
            errno = 0;
            ptrace(PTRACE_POKEDATA, pid, inject_rsp, (void*)orig_stack_word);
        }
#endif
        if (fp_saved) {
            pt_setfpregs(pid, &fpregs);
        }
        return -1;
    };

    // get origin regs
    // B57: 目标可能在注入中途死亡（兄弟线程 SIGKILL / 自身崩溃），各 ptrace
    // 调用返回 -ESRCH。全部改为干净返回错误，不再 assert abort。
    rc = pt_getregs(pid, &regs);
    if (rc != 0) { return fail("getregs"); }

    // B3: 注入会跑真实 libc 函数，按 SysV ABI 践踏 caller-saved 的 FP/SIMD
    // 寄存器；监控型 dump 后目标继续运行会读到垃圾 xmm。先保存，结束恢复。
    rc = pt_getfpregs(pid, &fpregs);
    if (rc != 0) { return fail("getfpregs"); }
    fp_saved = 1;

    // simulate call instruction
#ifdef __aarch64__
    regs.regs[30] = 0;
#else
    // B3: [rsp-8] 是模拟 call 压入的返回地址槽位（red zone 下方）。原实现写 0
    // 后永不恢复，目标帧返回时 rip=0 → 崩。先 PEEKDATA 保存原字，注入结束后写回。
    inject_rsp = regs.rsp - 8;
    errno = 0;
    long peeked = ptrace(PTRACE_PEEKDATA, pid, inject_rsp, NULL);
    if (errno == 0) {
        stack_saved = 1;
        orig_stack_word = (uint64_t)peeked;
    }
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
    for (;;) {
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == SIGSEGV) {
                break;
            }
            if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
                unsigned long msg;
                rc = ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg);
                if (rc != 0) { return fail("geteventmsg"); }
                dprint("child pid = %lu", msg);
            }
            dprint("statux = %x", status);
        }
        rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
        if (rc < 0) {
            // 目标在注入过程中死亡（兄弟线程 SIGKILL 等）
            return fail("cont");
        }

        status = pt_wait(pid);
    }
    
    if (oregs) {
        pt_getregs(pid, oregs);
    }

    // B3: 恢复被注入践踏的状态。ret 已把 rsp 还原，[inject_rsp] 仍存 0；
    // 写回原返回地址字，并恢复 FP/SIMD。
#ifdef __aarch64__
    // 无 [rsp-8] 模拟；仅恢复 FP
    pt_setfpregs(pid, &fpregs);
#else
    if (stack_saved) {
        errno = 0;
        ptrace(PTRACE_POKEDATA, pid, inject_rsp, (void*)orig_stack_word);
    }
    pt_setfpregs(pid, &fpregs);
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
        error("write mem(%lx) of %d failed(%d).", dest, pid, errno);
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
    pt_wait(pid);

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
    pt_wait(pid);

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
    _d_maps->Parse();

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
    info.pr_zomb = 0;
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
    Block block;
    struct file_entry {
        uint64_t start_addr;
        uint64_t end_addr;
        uint64_t offset;
        std::string filename;
    };
    std::vector<file_entry> entries;

    uint64_t v;
    block.Clear();
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

    // number of entries
    v = entries.size();
    block.Write((const char*)&v, 8);
    
    // page size (4k)
    v = 0x1000;
    block.Write((const char*)&v, 8);

    // address 
    for (auto& n :entries) {
        block.Write((const char*)&n.start_addr, 8);
        block.Write((const char*)&n.end_addr, 8);
        block.Write((const char*)&n.offset, 8);
    }
   
    // file names
    for (auto& n :entries) {
        block.Write(n.filename.c_str(), n.filename.size() + 1);
    }
    
    // 文件名区精确长度作 descsz，不要在内部补零。
    // B15: 原实现 roundup(block.Size(),4) 会在文件名末尾补 0，gdb 把它解析成
    // 一个多余的空文件名 → names 区比 count 个文件实际占用大 → gdb 报
    // "malformed note - filename area is too big"。native core 的 NT_FILE
    // descsz = 16 + count*24 + 精确文件名长度，末尾补齐由 note 对齐处理。
    char *p = allocate(block.Size());
    memcpy(p, block.rBuf(), block.Size());

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
        info.pr_sigpend = thr._d_stat->pending;
        info.pr_sighold = thr._d_stat->blocked;
        info.pr_fpvalid = 1;
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
        info.pr_sigpend = thr._d_stat->pending;
        info.pr_sighold = thr._d_stat->blocked;
        info.pr_fpvalid = 1;
        char *p = allocate(sizeof(info));
        memcpy(p, &info, sizeof(info));
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

        // this pid 
        u32 = _pid; 
        out.Write((const char*)&u32, sizeof(u32));
        
        // forked pid if has
        u32 = _core_pid;
        out.Write((const char*)&u32, sizeof(u32));

        // thread number
        u32 = _process._thrd_pid.size();
        out.Write((const char*)&u32, sizeof(u32));

        // time
        struct timeval tv;
        struct timezone tz = {0};   // gettimeofday 不填 tz，避免把未初始化栈写进 acore
        gettimeofday (&tv, &tz);
        out.Write((const char*)&tv, sizeof(tv));
        out.Write((const char*)&tz, sizeof(tz));

        // uname（sizeof 512 只写入 ~390 字节，其余置零）
        char ubuf[512] = {0};
        uname((utsname*)ubuf);
        out.Write((const char*)ubuf, sizeof(ubuf));
        
        out.Flush();
    }

    // put raw files
    char buf[BUFFER_SIZE];
    // B29: 原实现忽略 ReadPid 返回值——读失败时 NULL 传入 PutFile（NULL 解引用
    // 崩溃）或未初始化 buf 被当 ProcFile 写出垃圾。这里逐项检查，失败即返回 -1。
    if (!ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_CMDLINE)) {
        error("read cmdline of %d failed", _pid); return -1;
    }
    out.PutFile((ProcFile*) buf);
    if (!ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_AUXV)) {
        error("read auxv of %d failed", _pid); return -1;
    }
    out.PutFile((ProcFile*) buf);

    ProcFile* _maps = ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_MAPS);
    if (!_maps) {
        error("read maps of %d failed", _pid);
        return -1;
    }
    out.PutFile(_maps);
    maps.setpf(_maps);
    maps.Parse();

    if (!ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_ENVIRON)) {
        error("read environ of %d failed", _pid); return -1;
    }
    out.PutFile((ProcFile*) buf);
    if (!ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_IO)) {
        error("read io of %d failed", _pid); return -1;
    }
    out.PutFile((ProcFile*) buf);
    if (!ProcFile::ReadPid(buf, BUFFER_SIZE, _pid, PROC_TYPE_LIMITS)) {
        error("read limits of %d failed", _pid); return -1;
    }
    out.PutFile((ProcFile*) buf);

    return 0;
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
    rc = pt_getregs(pid, (user_regs64_struct*)&i._regs);
    if (rc != 0) { warn("getregs thread %d failed, zeroed block", pid); }
    rc = pt_getfpregs(pid, (user_fpregs64_struct*)&i._fpregs);
    if (rc != 0) { warn("getfpregs thread %d failed, zeroed block", pid); }
    rc = ptrace(PTRACE_GETSIGINFO, pid, 0, &i._siginfo);
    if (rc != 0) { warn("getsiginfo thread %d failed, zeroed block", pid); }
    if (_arch == ARCH_X64) {
        rc = pt_getxstateregs(pid, (x64_xstatereg*)&i._xstate);
        if (rc != 0) { warn("getxstateregs thread %d failed, zeroed block", pid); }
    }

    // write thread meta
    out.SetBlock(BLOCK_TYPE_THREAD);
    out.Write((const char*)&pid, sizeof(i._pid));
    // B14: 写成员实际大小，不能用 sizeof(i._regs)（union = max(x64, arm64) 成员）。
    // x64 下 union regs=272/fpregs=528，但 ReadMeta 读 sizeof(x64 成员)=216/512，
    // 多写的 56+16=72 字节让 fpregs/siginfo/xstate 在解压时整体偏移 72 →
    // xstate 头 xfeatures 读到错位数据变 0，gdb 报 .reg-xstate 尺寸不符。
#ifdef __aarch64__
    out.Write((const char*)&i._regs, sizeof(i._regs.arm64));
    out.Write((const char*)&i._fpregs, sizeof(i._fpregs.arm64));
#else
    out.Write((const char*)&i._regs, sizeof(i._regs.x64));
    out.Write((const char*)&i._fpregs, sizeof(i._fpregs.x64));
#endif
    out.Write((const char*)&i._siginfo, sizeof(i._siginfo));
    if (_arch == ARCH_X64) {
        out.Write((const char*)&i._xstate.x64, sizeof(i._xstate.x64));
    }

    out.Flush();
    // read /proc/<pid>/stat；读失败时写最小合法 ProcFile（f_size=0），
    // 避免把未初始化 buf 当 ProcFile 写出（解压端 GetFile 读垃圾 size）。
    char buf[BUFFER_SIZE];
    ProcFile *pf = ProcFile::ReadPid(buf, BUFFER_SIZE, pid, PROC_TYPE_STAT);
    if (!pf) {
        warn("read /proc/%d/stat failed, empty stat", pid);
        memset(buf, 0, sizeof(ProcFile));
        pf = (ProcFile*)buf;
        pf->f_pid = pid;
        pf->f_type = PROC_TYPE_STAT;
    }
    out.PutFile(pf);

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
        int tid = atoi(dp->d_name);
        if (tid == 0 || tid == leader) continue;
        errno = 0;
        if (pt_attach(tid) != 0) {
            // B77 (Codex B7 review): 线程可能在枚举与 attach 间退出（ESRCH，跳过）；
            // 但 EPERM/tracer 冲突等非 ESRCH 错误是真实故障，跳过会静默产出不完整
            // dump。fail-closed。
            if (errno == ESRCH) {
                error("attach thread %d failed (exited), skipped", tid);
                continue;
            }
            error("attach thread %d failed (%s), aborting collection", tid, strerror(errno));
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
    ptrace(PTRACE_SETOPTIONS, _pid, 0, _ptrace_options);

    ptrace(PTRACE_CONT, _pid, NULL, NULL);
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

    // for version 1, the arch is always x64.
    _arch = hdr.m.arch;

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

    // process data
    int u = 0;
    int thread_num = 0;
    {
        buf->Read((char*)&u, sizeof(u));
        _pid = u;
        buf->Read((char*)&u, sizeof(u));
        _core_pid = u;
        buf->Read((char*)&u, sizeof(u));
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
   
    // B23: thread_num 来自损坏 acore 可为任意值；限定上限避免无限/超长循环
    if (thread_num < 0 || thread_num > 1000000) {
        error("implausible thread_num %d, acore corrupt", thread_num);
        return -1;
    }

    for (int i=0; i<thread_num; i++) {
        ThreadData td;
        td._arch = _arch;

        buf = in.ReadBlock(hdr);
        if (!buf) {
            // 损坏 acore 提前结束：跳过剩余线程（避免 NULL 解引用）
            error("thread block %d missing (truncated acore), stopping", i);
            break;
        }

        buf->Read((char*)&td._pid, sizeof(td._pid));

        if (_arch == ARCH_X64) {
            buf->Read((char*)&td._regs, sizeof(td._regs.x64));
            buf->Read((char*)&td._fpregs, sizeof(td._fpregs.x64));
            buf->Read((char*)&td._siginfo, sizeof(td._siginfo));
            buf->Read((char*)&td._xstate, sizeof(td._xstate.x64));
        } else if (_arch == ARCH_AARCH64) {
            buf->Read((char*)&td._regs, sizeof(td._regs.arm64));
            buf->Read((char*)&td._fpregs, sizeof(td._fpregs.arm64));
            buf->Read((char*)&td._siginfo, sizeof(td._siginfo));
        }

        td._stat = in.GetFile();
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

    close(fd);
    return 0; 
}

/* write elf header to stream
 */
int Coredump::WriteElfHeader(Lz4Stream& out)
{
    Elf64_Ehdr ehdr;
    ehdr.e_phnum = _phdrs.size();

    // hard coded the 'machine' by platform
#ifdef __aarch64__
    ehdr.e_machine = EM_AARCH64;
#else
    ehdr.e_machine = EM_X86_64;
#endif

    out.SetBlock(BLOCK_TYPE_ELF);
    out.Write((const char*)&ehdr, sizeof(ehdr));

    for (auto& phdr : _phdrs) {
        out.Write((const char*)&phdr, sizeof(phdr));
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

int Coredump::ReadElfHeader(Lz4Stream& in)
{
    int rc;
    BlockHeader hdr;
    Block* block = in.ReadBlock(hdr);
    if (!block) {
        // 损坏 acore：ELF 块缺失
        error("elf block missing (truncated acore)");
        return -1;
    }

    rc = block->Read((char*)&_ehdr, sizeof(_ehdr));
    if (rc != sizeof(_ehdr)) {
        error("decode ehdr failed.");
        return -1;
    }

    while (block) {

        while (block->Size() > 0) {
            Elf64_Phdr phdr;
            rc = block->Read((char*)&phdr, sizeof(phdr));
            if (rc != sizeof(phdr)) {
                error("decode phdr failed.");
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
        rc = in.Peek((char*)&hdr, sizeof(hdr));
        if (rc <= 0) {
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
    auto add_note = [&](Note* nt, int fill_rc) -> void {
        if (fill_rc != 0) {
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
    WriteFileHeader(out);

    // attach main thread
    if (pt_attach(_pid) != 0) {
        // 目标不存在/无权限：干净报错而非深层 assert 崩溃
        error("cannot attach to process %d", _pid);
        return -1;
    }
    // get all threads pid（attach 全部非主线程，剔除已退出的）
    // B77: collect_threads 失败（opendir / 非 ESRCH attach 错误）时 fail-closed。
    if (collect_threads(_pid) != 0) {
        error("failed to collect threads of %d", _pid);
        return -1;
    }

    ProcMaps maps;
    // N4: WriteProcessMeta 失败（/proc 读失败）时继续写会让 acore 缺进程元数据，
    // 解压错位；直接失败。
    if (WriteProcessMeta(out, maps) != 0) {
        error("write process meta failed");
        return -1;
    }
    // handle  leader first and then rest
    WriteThreadMeta(out, _pid, true);
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == _pid)
            continue;

        WriteThreadMeta(out, tid);
    }
    // write acore
    {
        // B65: WriteLoads 失败（/proc/pid/mem 打不开，dumpable=0/进程消失）时
        // 静默产出无内存的空 core；显式失败。
        if (WriteLoads(out, _pid, maps) != 0) {
            error("failed to dump memory of %d", _pid);
            return -1;
        }
        // B69: ELF 块写入失败（磁盘满）时显式失败。
        if (WriteElfHeader(out) != 0) {
            error("failed to write elf header for %d", _pid);
            return -1;
        }
        WriteTailMark(out);
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
        WriteFileHeader(out);
    }
    
    TS ts_pause;
    ts_pause.begin();

    // attach main thread
    if (pt_attach(_pid) != 0) {
        // 目标不存在/无权限：干净报错而非深层 assert 崩溃
        error("cannot attach to process %d", _pid);
        return -1;
    }

    // get all threads pid（attach 全部非主线程，剔除已退出的）
    // B77: collect_threads 失败（opendir / 非 ESRCH attach 错误）时 fail-closed。
    if (collect_threads(_pid) != 0) {
        error("failed to collect threads of %d", _pid);
        return -1;
    }

    ProcMaps maps;
    // N4: WriteProcessMeta 失败（/proc 读失败）时若继续写，acore 缺进程元数据，
    // 解压端 ReadMeta 的 GetFile 序列错位。fail-closed 还原目标。
    if (WriteProcessMeta(out, maps) != 0) {
        error("write process meta failed");
        restore_target_after_fail();
        return -1;
    }
    // handle  leader first and then rest
    WriteThreadMeta(out, _pid, true);
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == _pid) {
            continue;
        }
        WriteThreadMeta(out, tid);
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
        return -1;
    }
    info("remote mmap at %lx", r_mmap);
    //info("remote fork at %p", r_fork);
    info("remote waitpid at %lx", r_waitpid);

    // save the program regs
    user_regs64_struct saved_regs;
    pt_getregs(_pid, &saved_regs);

    // get a page for shellcode
    user_regs64_struct regs;

    uint64_t inject_page = 0;
    {
        //uint64_t gv[6] = {0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0};
        uint64_t gv[6] = {0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0};
        // B57: pt_call 失败（目标中途死亡）时不填充 regs；不检查会在下面读未初始化的
        // inject_page 当垃圾地址继续注入。
        if (pt_call(_pid, &regs, r_mmap, 6, gv) != 0) {
            error("mmap injection failed (target died?)");
            restore_target_after_fail();
            return -1;
        }
        info("mmap = %lx", regs.get_rc());
        inject_page = regs.get_rc();
        // B16 缓解：目标阻塞在可重启 syscall 时，syscall-restart 会覆盖注入，
        // mmap 结果变垃圾（如 rax=0xdb）。合法结果必是页对齐、非零、用户态地址。
        // 否则 fail-closed 还原目标，避免用垃圾 inject_page 继续注入。
        if (inject_page == 0 || (inject_page & 0xfff) != 0 || inject_page < 0x10000 ||
            inject_page > 0x0000800000000000UL) {
            error("remote mmap returned implausible %#lx "
                  "(target likely in a restartable syscall); aborting", inject_page);
            // B16 续: 注入失败时 pt_call 已在目标栈 [rsp-8] 写 0、把 rip 推向
            // 0（syscall-restart 覆盖注入后 ret 到 0 fault）。fail-closed 前
            // 恢复注入前的完整寄存器（含 rip/rsp/syscall 参数），CONT(0) 抑制
            // 该 SIGSEGV 后目标从原 syscall 指令继续，不再崩溃。仅靠
            // restore_target_after_fail 的 CONT(0) 会让 rip=0 立即重新 fault。
            pt_setregs(_pid, &saved_regs);
            restore_target_after_fail();
            return -1;
        }
    }
    pt_getregs(_pid, &regs);

    // inject fork
    {
        char *inject_begin=0, *inject_end=0; 
#ifdef __aarch64__
        asm ("adr %0, inject_begin\n" : "=r" (inject_begin));
        asm ("adr %0, inject_end\n" : "=r" (inject_end));
#else
        asm ("mov $inject_begin, %0 \n" : "=r" (inject_begin));
        asm ("mov $inject_end, %0 \n" : "=r" (inject_end));
#endif
        int inject_size = (inject_end - inject_begin);
        dprint("inject_range(%p - %p), size(%d)", inject_begin, inject_end, inject_size);
     
        // B80: pt_write 失败（注入页不可写/短写）时继续注入会执行垃圾代码；fail-closed。
        if (pt_write(_pid, inject_page, (void *)inject_fork, inject_size) != 0) {
            error("write inject shellcode to %lx failed", (unsigned long)inject_page);
            pt_setregs(_pid, &saved_regs);
            restore_target_after_fail();
            return -1;
        }
        // B57: 注入 fork 失败（目标中途死亡）时 regs 未填充，_core_pid 会读垃圾。
        // B72: 记录注入写 0 的 [rsp-8] 槽位与原字，fork 后写回子进程快照。
        uint64_t inj_rsp = 0, inj_word = 0;
        if (pt_call(_pid, &regs, inject_page, 0, NULL, &inj_rsp, &inj_word) != 0) {
            error("fork injection failed (target died?)");
            pt_setregs(_pid, &saved_regs);
            restore_target_after_fail();
            return -1;
        }
        info("child_pid = %d", (int)regs.get_rc());
        _core_pid = regs.get_rc();
        if (_core_pid <= 0) {
            error("fork returned implausible child %d", (int)_core_pid);
            pt_setregs(_pid, &saved_regs);
            restore_target_after_fail();
            return -1;
        }
        // B72: 子进程（COW 快照）保留注入的 0；写回原字消除快照污染。
        if (inj_rsp) {
            ptrace(PTRACE_POKEDATA, _core_pid, inj_rsp, (void*)inj_word);
        }
    }

    // munmap injected page.
    {
        uint64_t gv[2] = {inject_page, 0x1000};
        pt_call(_pid, &regs, r_munmap, 2, gv);
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
        // write acore
        // B65: 读子进程内存失败（child 消失/dumpable=0）时 fail-closed，还原目标。
        if (WriteLoads(out, _core_pid, maps) != 0) {
            error("failed to dump memory of child %d", (int)_core_pid);
            restore_target_after_fail();
            return -1;
        }
        // B69: ELF 块写入失败（磁盘满）时 fail-closed。
        if (WriteElfHeader(out) != 0) {
            error("failed to write elf header");
            restore_target_after_fail();
            return -1;
        }
        WriteTailMark(out);
    }

    // kill the forked process
    ptrace(PTRACE_DETACH, _core_pid, NULL, SIGKILL);
    //assert(rc == 0);

    // now the process becomes zombie,
    // we have to waitpid the forked pid.
    // B76 (Codex B6 review): 末尾 re-attach 的 pt_attach/pt_getregs/pt_setregs/
    // pt_detach 返回全被忽略——目标若在自由运行窗口退出/被另一 tracer 占用，
    // attach 失败后继续注入会读到垃圾。acore 已写（有效），此处告警而非静默成功。
    if (pt_attach(_pid) != 0) {
        warn("re-attach of %d failed; injected waitpid may not have reaped the "
             "fork child", _pid);
    }
    pt_getregs(_pid, &saved_regs);
    {
        uint64_t gv[3] = { (uint64_t)_core_pid, (uint64_t)NULL, 0 };
        pt_call(_pid, &regs, r_waitpid, 3, gv);
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
    pt_setregs(_pid, &saved_regs);
    pt_detach(_pid);

    info("Process %u paused %0.3f ms.", _pid, ts_pause.timediff()*1000);
    out.PrintStat();
    out.Close();
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
        WriteFileHeader(out);
    }
    
    TS ts_pause;
    ts_pause.begin();

    // stop tracee
    pt_int(_pid);

    // get all threads pid（attach 全部非主线程，剔除已退出的）
    // B77: collect_threads 失败（opendir / 非 ESRCH attach 错误）时 fail-closed。
    if (collect_threads(_pid) != 0) {
        error("failed to collect threads of %d", _pid);
        return -1;
    }

    ProcMaps maps;
    // N4: WriteProcessMeta 失败（/proc 读失败）时若继续写，acore 缺进程元数据，
    // 解压端 ReadMeta 的 GetFile 序列错位。fail-closed 还原目标。
    if (WriteProcessMeta(out, maps) != 0) {
        error("write process meta failed");
        restore_target_after_fail();
        return -1;
    }
    // handle  leader first and then rest
    WriteThreadMeta(out, _pid, true);
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == _pid) {
            continue;
        }
        WriteThreadMeta(out, tid);
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
        return -1;
    }
    info("remote mmap at %lx", r_mmap);
    info("remote waitpid at %lx", r_waitpid);

    // save the program regs
    user_regs64_struct saved_regs;
    pt_getregs(_pid, &saved_regs);

    // get a page for shellcode
    user_regs64_struct regs;
    uint64_t inject_page = 0;
    {
        uint64_t gv[6] = {0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0};
        pt_call(_pid, &regs, r_mmap, 6, gv);
        info("mmap = %lx", regs.get_rc());
        inject_page = regs.get_rc();
        // B16 缓解：目标阻塞在可重启 syscall 时，syscall-restart 会覆盖注入，
        // mmap 结果变垃圾（如 rax=0xdb）。合法结果必是页对齐、非零、用户态地址。
        // 否则 fail-closed 还原目标，避免用垃圾 inject_page 继续注入。
        if (inject_page == 0 || (inject_page & 0xfff) != 0 || inject_page < 0x10000 ||
            inject_page > 0x0000800000000000UL) {
            error("remote mmap returned implausible %#lx "
                  "(target likely in a restartable syscall); aborting", inject_page);
            // B16 续: 注入失败时 pt_call 已在目标栈 [rsp-8] 写 0、把 rip 推向
            // 0（syscall-restart 覆盖注入后 ret 到 0 fault）。fail-closed 前
            // 恢复注入前的完整寄存器（含 rip/rsp/syscall 参数），CONT(0) 抑制
            // 该 SIGSEGV 后目标从原 syscall 指令继续，不再崩溃。仅靠
            // restore_target_after_fail 的 CONT(0) 会让 rip=0 立即重新 fault。
            pt_setregs(_pid, &saved_regs);
            restore_target_after_fail();
            return -1;
        }
    }
    pt_getregs(_pid, &regs);

    // inject fork
    {
        char *inject_begin=0, *inject_end=0; 
#ifdef __aarch64__
        asm ("adr %0, inject_begin\n" : "=r" (inject_begin));
        asm ("adr %0, inject_end\n" : "=r" (inject_end));
#else
        asm ("mov $inject_begin, %0 \n" : "=r" (inject_begin));
        asm ("mov $inject_end, %0 \n" : "=r" (inject_end));
#endif        
        int inject_size = (inject_end - inject_begin);
        dprint("inject_range(%p - %p), size(%d)", inject_begin, inject_end, inject_size);
     
        // B80: pt_write 失败（注入页不可写/短写）时继续注入会执行垃圾代码；fail-closed。
        if (pt_write(_pid, inject_page, (void *)inject_fork, inject_size) != 0) {
            error("write inject shellcode to %lx failed", (unsigned long)inject_page);
            pt_setregs(_pid, &saved_regs);
            restore_target_after_fail();
            return -1;
        }
        // B57: 注入 fork 失败（目标中途死亡）时 regs 未填充，_core_pid 会读垃圾。
        // B72: 记录注入写 0 的 [rsp-8] 槽位与原字，fork 后写回子进程快照。
        uint64_t inj_rsp = 0, inj_word = 0;
        if (pt_call(_pid, &regs, inject_page, 0, NULL, &inj_rsp, &inj_word) != 0) {
            error("fork injection failed (target died?)");
            pt_setregs(_pid, &saved_regs);
            restore_target_after_fail();
            return -1;
        }
        info("child_pid = %d", (int)regs.get_rc());
        _core_pid = regs.get_rc();
        if (_core_pid <= 0) {
            error("fork returned implausible child %d", (int)_core_pid);
            pt_setregs(_pid, &saved_regs);
            restore_target_after_fail();
            return -1;
        }
        // B72: 子进程（COW 快照）保留注入的 0；写回原字消除快照污染。
        if (inj_rsp) {
            ptrace(PTRACE_POKEDATA, _core_pid, inj_rsp, (void*)inj_word);
        }
    }

    // munmap injected page.
    {
        uint64_t gv[2] = {inject_page, 0x1000};
        pt_call(_pid, &regs, r_munmap, 2, gv);
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

    // TBD: dump memory regions
    if (!sys_core) {
        // write acore
        {
            // B65: 读子进程内存失败（child 消失/dumpable=0）时 fail-closed，还原目标。
        if (WriteLoads(out, _core_pid, maps) != 0) {
            error("failed to dump memory of child %d", (int)_core_pid);
            restore_target_after_fail();
            return -1;
        }
            // B69: ELF 块写入失败（磁盘满）时 fail-closed。
            if (WriteElfHeader(out) != 0) {
                error("failed to write elf header");
                restore_target_after_fail();
                return -1;
            }
            WriteTailMark(out);
        }
    }

    // kill the forked process
    ptrace(PTRACE_DETACH, _core_pid, NULL, SIGKILL);
    // assert(rc == 0);

    // in case any signal generated above
    // 目标可能仍被 SIGUSR1 的 forkcore_m 停住；s 未初始化会被 WIFSIGNALED/WIFSTOPPED 误读
    int s = 0, sig = 0;
    waitpid(_pid, &s, WNOHANG);
    // tracee will be killed if signaled on termination (SIGKILL)
    // arthur will exit here
    if(WIFSIGNALED(s)) {
        info("%s: process %d terminated", strsignal(WTERMSIG(s)), _pid);
        exit(0);
    }
    // tracee will stop if signaled on exit
    bool stopped_at_ptrace_event = false;
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
            // B67: TRACEFORK auto-attach 的 fork 子进程残留在 arthur 上（TracerPid=arthur、
            // state=t），monitor 继续运行时不 CONT 它 → 永久冻结。GETEVENTMSG 拿子进程
            // pid 并 DETACH(SIGCONT) 解冻，让它正常继续运行。
            unsigned long child_pid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, _pid, 0, &child_pid) == 0 && child_pid > 0) {
                ptrace(PTRACE_DETACH, (pid_t)child_pid, NULL, (void*)SIGCONT);
                info("detached auto-attached fork child %lu", child_pid);
            }
        }
    } else {
        // now the process becomes zombie,
        // we have to waitpid the forked pid.
        pt_int(_pid);
    }
    pt_getregs(_pid, &saved_regs);
    {
        uint64_t gv[3] = {(uint64_t)_core_pid, (uint64_t)NULL, 0};
        pt_call(_pid, &regs, r_waitpid, 3, gv);
        info("waitpid = %d", (int)regs.get_rc());
        // B73 (Codex B2 review): 注入 waitpid 失败（B16 syscall-restart）时
        // 子进程作为目标 zombie 残留；如实报告。
        if (regs.get_rc() != (uint64_t)_core_pid) {
            warn("injected waitpid returned %d (expected %d); child may linger "
                 "as a zombie (target likely in a restartable syscall)",
                 (int)regs.get_rc(), (int)_core_pid);
        }
    }
    pt_setregs(_pid, &saved_regs);
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
    if(!WIFSTOPPED(s) || stopped_at_ptrace_event) {
        pt_cont(_pid);
    }

    info("Process %u paused %0.3f ms.", _pid, ts_pause.timediff()*1000);
    out.PrintStat();
    out.Close();

    // clean pending signal generated above by tracee
    sigset_t mask;
    //siginfo_t sig_info;
    sigaddset(&mask, SIGCHLD);
    sigwaitinfo(&mask, NULL);

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
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = out.Open(corefile);
    if (rc < 0) {
        return -1;
    }

    // write acore
    WriteFileHeader(out);

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

    // block all signals
    sigset_t mask;
    sigaddset(&mask, SIGCHLD); // signal from tracee
    sigaddset(&mask, SIGUSR1); // signal for generating corefile while monitor
    sigprocmask(SIG_BLOCK, &mask, NULL);

    int exit_sig = 0;
    int signal_forkcore = 0; // signal generated due to free section in forkcore
    unsigned dump_seq = 0;   // B58: SIGUSR1 dump 单调序号，避免同秒文件名覆盖
    siginfo_t sig_info;
    while(1) {
        if(signal_forkcore) {
            if (signal_forkcore < 0) {
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
                    error("%s: process %d crashed (likely a non-leader thread); "
                          "no core written", strsignal(status), _pid);
                    out.Close();
                    unlink(corefile);
                } else {
                    info("%s: process %d terminated by signal", strsignal(status), _pid);
                    ptrace(PTRACE_DETACH, _pid, NULL, (uintptr_t) status);
                }
                return 0;
            } else if (status == SIGILL || status == SIGABRT || status == SIGSEGV) {
                // write out corefile under SIGILL, SIGABRT, SIGSEGV
                exit_sig = status;
                break;
            } else { // relay signals to tracee
                // 中继目标用 sig_info.si_pid：TRACEFORK 自动 attach 的子进程
                // 或非 leader 线程的停靠，si_pid 才是正确的恢复目标；固定 _pid
                // 会恢复错误线程，让真正的停靠者永久冻结（问题2）。
                ptrace(PTRACE_CONT, sig_info.si_pid, NULL, (uintptr_t) status);
            }
            signal_forkcore = 0; // reset signal 
        } else {
            // signal SIGUSR1 to arthur
            // B19: 原实现 `char out[17]; sprintf(out, "acore.%u\n", ...)`——
            // 10 位时间戳时写 18 字节（含 NUL）溢出 1 字节；格式串还带换行。
            // B58: 秒级 time(NULL) 做文件名，同一秒内多次 SIGUSR1 互相覆盖丢数据
            // （实证：3 次 dump 只留 2 个文件）。加单调序号保证唯一。
            char out[40];
            snprintf(out, sizeof(out), "acore.%u.%u",
                     (unsigned)time(NULL), dump_seq++);
            info("writing out %s...", out);
            signal_forkcore = forkcore_m(out, false);
            info("writing out acore finished, resume monitoring");
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

    // get all threads pid（attach 全部非主线程，剔除已退出的）
    // B77: collect_threads 失败（opendir / 非 ESRCH attach 错误）时 fail-closed。
    if (collect_threads(_pid) != 0) {
        error("failed to collect threads of %d", _pid);
        return -1;
    }

    ProcMaps maps;
    // N4: 崩溃路径 /proc 读失败时目标已死，无法重试；报错并清理空 acore。
    if (WriteProcessMeta(out, maps) != 0) {
        error("write process meta failed for crashed process");
        out.Close();
        unlink(corefile);
        return -1;
    }

    // handle  leader first and then rest
    WriteThreadMeta(out, _pid, true);
    for(pid_t& tid : _process._thrd_pid) {
        if (tid == _pid)
            continue;

        WriteThreadMeta(out, tid);
    }
    // write acore
    {
        // B65: 崩溃路径 /proc/pid/mem 读不到时报错并清理，不产出空 core。
        if (WriteLoads(out, _pid, maps) != 0) {
            error("failed to dump memory of crashed process %d", _pid);
            out.Close();
            unlink(corefile);
            return -1;
        }
        // B69: ELF 块写入失败时清理。
        if (WriteElfHeader(out) != 0) {
            error("failed to write elf header for crashed process");
            out.Close();
            unlink(corefile);
            return -1;
        }
        WriteTailMark(out);
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
    FILE *fout = fopen(out_core, "wb");
    if (!fout) {
        error("Fail to open file %s", out_core);
        // B50 残留: ReadMeta 已分配 ProcFiles/decoders/线程 _d_stat，
        // fopen 失败提前返回时未清理 → LeakSanitizer 报 8999 字节泄漏。
        cleanup_decompress();
        return -1;
    }
    long p_elf = ftell(fout);

    // parse  
    _process.ParseAll();

    // make room for elf headers
    int phnum = _process._d_maps->size() + 1;
    size_t hdr_size = sizeof(Elf64_Ehdr) + (phnum * sizeof(Elf64_Phdr));
    hdr_size = roundup(hdr_size + 4096, 4096);
    dprint("room = %d", hdr_size);
    rc = makeroom(fout, hdr_size);
    if (rc < 0) {
        fclose(fout);
        cleanup_decompress();
        return -1;
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
        if (len != nt->_size) {
            error("write note failed (%ld != %d), disk full?", len, nt->_size);
            fclose(fout);
            in.Close();
            cleanup_decompress();
            return -1;
        }
    }
    _offset_load = ftell(fout);

    // write loads
    // B54: 截断 acore 使 ReadLoads 失败时不再 assert abort，干净报错。
    // B60: ReadLoads 返回 ssize_t（实际写出的未压缩字节数）——>2GB 的合法
    // dump 若用 int 返回会被截断成负数误判为失败（实证：3.2GB dump 被拒）。
    ssize_t loads_rc = ReadLoads(in, fout);
    if (loads_rc < 0) {
        error("read loads failed, core incomplete");
        fclose(fout);
        in.Close();
        cleanup_decompress();
        return -1;
    }
    size_t loads_written = (size_t)loads_rc;

    // write elf header
    // ReadElfHeader 失败（损坏 acore 缺 ELF 块）时 _phdrs 为空，写出的 core 无
    // LOAD 段；检查返回值，报错而非产出残缺 core。
    rc = ReadElfHeader(in);
    if (rc != 0) {
        error("read elf header failed, core incomplete");
        fclose(fout);
        in.Close();
        cleanup_decompress();
        return -1;
    }

    // 校验：读侧实际写出的 LOAD 字节数 == acore ELF 块 phdr 声明的 p_filesz 之和。
    // 写侧 p_filesz 是每个 region 实际写入的未压缩字节数（含 pread 失败时的部分），
    // 二者应严格相等；不一致说明 LOADS 块被 bit-flip 成了合法但不同长度的 LZ4 流，
    // 静默写错 core 比报错更危险。
    size_t expected = 0;
    for (const auto& phdr : _phdrs) {
        if (phdr.p_type == PT_LOAD) {
            expected += phdr.p_filesz;
        }
    }
    if (loads_written != expected) {
        error("loads size mismatch: wrote %lu bytes, phdrs declare %lu (acore corrupt)",
              loads_written, expected);
        fclose(fout);
        in.Close();
        cleanup_decompress();
        return -1;
    }
    fseek(fout, p_elf, SEEK_SET);
    rc = WriteElfHeader(fout);
    if (rc < 0) {
        error("write elf header to core failed");
        fclose(fout);
        in.Close();
        cleanup_decompress();
        return -1;
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
}

int Coredump::test_compress(const char* in_file, const char* out_file)
{
    int rc = 0;
    FILE *fin = fopen(in_file, "rb"); 
    if (!fin) {
        error("Fail to open file %s", in_file);
        return -1;
    }

    Lz4Stream out(Lz4Stream::LZ4_Compress);
    rc = out.Open(out_file);
    if (rc < 0) {
        return -1;
    }

    size_t data_size = 0, file_size = 0;
    char buf[4*1024];
    for (;;) {
        size_t len = fread(buf, 1, sizeof(buf), fin);
        if (len == 0) {
            // B22: EOF（fread 返回 0）是正常结束，不是错误
            break;
        }
        
        for (size_t i=0; i<len; i+= BLOCK_SIZE) {
            size_t j = MIN(len - i, BLOCK_SIZE);
            int rc = out.Write((const char*)(buf+i), j);
            assert(rc > 0);
            data_size += len;
            file_size += rc;
        }
             
        if (len < sizeof(buf)) {
            break;
        }
    }
    out.Flush();
    WriteTailMark(out);
    out.Close();
    fclose(fin); 

    info(" %lu => %lu ", data_size, file_size);

    return 0;
}

int Coredump::test_decompress(const char* in_file, const char* out_file)
{
    int rc = 0;
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
            break;
        }

        ssize_t len = fwrite(block->rBuf(), 1, block->Size(), fout);
        if (len != (int)block->Size()) {
            break;
        }
        file_size += len; 
    }
    fclose(fout);
    in.Close();

    info("write %lu bytes.", file_size);
    return 0;
}

}; // arthur
