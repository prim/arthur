/* Support '/proc/xxx' pseudo-filesystem.
 */

#include <string> 
#include <iostream> 
#include <sstream> 
#include <cstdarg>
#include <fcntl.h>

#include "inc.h"
#include "proc.h"
#include "elf.h"

namespace arthur {

const char* szProcType(ProcType type)
{
    switch (type) {
#define V(a, b) case a: return b;
        PROC_TYPE_LIST(V)
#undef V
        default: 
            break;
    }

    return NULL;
}

ProcFile* ProcFile::ReadPath(char* buf, int buf_len, const char *path, bool *out_truncated)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        error("open %s failed", path);
        return NULL;
    }

    ProcFile *pf = (ProcFile*)buf;
    int rc;
    // 预留 1 字节给末尾 NUL 终止符：f_data 最多放 buf_len - sizeof(ProcFile) - 1
    // 字节数据，否则 pf->f_data[len]='\0' 会越界写（B17 off-by-one）。
    int left = buf_len - sizeof(ProcFile) - 1;
    int len = 0;

    for (;;) {
        // 剩余空间不足时立即停止，避免越过 f_data 末尾写（B17）。
        // 原实现读满后仍继续写，left 变负仍 read，堆/栈缓冲区溢出。
        if (left <= 0) {
            warn("buffer too small for %s, truncating at %d bytes", path, len);
            if (out_truncated) { *out_truncated = true; }
            break;
        }

        rc = read(fd, pf->f_data+len, MIN(4096, left));
        if (rc <= 0) {
            break;
        }

        len += rc;
        left -= rc;
    }

    if (left == 0) {
        warn("buffer may be too small for %s", path);
        if (out_truncated) { *out_truncated = true; }
    }

    close(fd);

    pf->f_data[len] = '\0';
    pf->f_size = len;

    return pf;
}

ProcFile* ProcFile::Read(bool *out_truncated, char* buf, int buf_len, const char *fmt, ...)
{
    char path[PATH_MAX];

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(path, sizeof(path), fmt, ap);
    va_end(ap);

    return ReadPath(buf, buf_len, path, out_truncated);
}

int ProcDecoder::readline(int& cur, char *out, size_t n)
{
    // b27 (Codex review) 加固点: n==0 时下方 `(int)n-1` 得 -1，memcpy 变成巨大
    // size_t 越界；!out 同理。入口显式拒绝。
    if (!out || n == 0) {
        return 0;
    }
    if (!_pf || cur >= (int)_pf->f_size) {
        return 0;
    }

    const char* p = _pf->f_data + cur;
    // B36: 原实现 `end = p + f_size` 把结束指针放到 f_data+cur+f_size，
    // 扫描/拷贝越过缓冲 cur 字节（ASAN 模糊测试确认堆越界）。
    const char* end = _pf->f_data + _pf->f_size;
    const char* q = p;

    // find '\n'
    for (; q < end; q++) {
        if (*q == '\n') {
            break;
        }
    }
    
    int len = q - p;

    // B27: 原实现 `memcpy(out, p, len)` 不按 n 截断，maps 行长于调用方缓冲
    // （ProcMaps 用 PATH_MAX=128）即栈溢出。这里截断到 n-1 保留 NUL 位置。
    if (len >= (int)n) {
        len = (int)n - 1;
    }
    memcpy(out, p, len);
    out[len] = '\0';

    // skip '\n'
    for (; q < end; q++) {
        if (*q != '\n') {
            break;
        }
    }

    // update cur
    cur = q - _pf->f_data;

    return len;
}

int ProcMaps::Parse()
{
    // B27: PATH_MAX 在 inc.h 被压到 128，真实映射路径（深容器/长库名）会超，
    // 既有 readline 溢出风险又有路径截断。行缓冲与名字缓冲提到 4096。
    const int MAPS_BUF = 4096;
    char name[MAPS_BUF];
    char line[MAPS_BUF];

    int cur = 0;
    while (readline(cur, line, sizeof(line))) {
        //printf("%s\n", line);
        MemRegion r = {};
        // b103 (Codex B103 review): perm 声明在循环外只清零一次——合法行之后出现
        // 在 %4s 前解析失败的畸形行时，会继承上一行权限（陈旧 perms/私有标志）。
        // 逐行清零 + 严格校验 sscanf 7 个转换，畸形行整体跳过，不再入表。
        char perm[16] = {0};
        name[0] = 0;
        int consumed = 0;
        // R50-5: 偏移字段用 %8lx 会截断 ≥4GiB 的映射偏移（内核打印 %08llx 无上限）——
        // 9 位十六进制时 %8lx 读 8 位后空格不匹配，整行解析失败（offset/inode/name 全丢）。
        // 去掉宽度用 %lx 读全。格式不匹配时 perms 保持 0 而非垃圾。
        int nfields = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %n",
                &r.start_addr,
                &r.end_addr,
                perm,
                &r.offset,
                &r.dev_major,
                &r.dev_minor,
                &r.inode,
                &consumed);
        if (nfields != 7) {
            // 畸形/截断行：跳过，不产生继承陈旧权限或部分解析的 region
            continue;
        }
        // maps 第 6 列后的路径可能含空格或 (deleted) 后缀；%s 会截断，
        // 用 %n 定位 inode 字段结束位置，取剩余整行为映射名。
        if (consumed > 0 && consumed < (int)sizeof(line)) {
            const char *path = line + consumed;
            while (*path == ' ' || *path == '\t') {
                path++;
            }
            snprintf(name, sizeof(name), "%s", path);
        }

        // decode perm bits
        if (perm[0] == 'r') {
            r.perms |= PF_R;
        }
        if (perm[1] == 'w') {
            r.perms |= PF_W;
        }
        if (perm[2] == 'x') {
            r.perms |= PF_X;
        }
        if (perm[3] == 'p') {
            r.is_private = 1;
        } else if (perm[3] == 's') {
            r.is_shared = 1;
        }
        r.name = name;

        // B163: region 数无上限——构造 acore 的 maps 文件（GetFile 上限 64MB）可用
        // 2 字节短行（"x\n"）塞入海量 region，每 region 48 字节 + SSO string ≈ 42x
        // 内存放大（实测 2M 行 → 165MB），64MB 上限 → ~2.7GB → OOM abort；且
        // size() 同步放大 decompress 的 hdr_size/makeroom 磁盘写。与 argv MAX_ARGV
        // 线程数上限同 class，maps 此前无对应上限。2^20 远超任何真实进程（默认
        // max_map_count 65530、B128 已限 phdr ≤0xFFFF），超限 fail-closed。
        if (size() >= (1 << 20)) {
            error("maps regions exceed 2^20, acore corrupt");
            return -1;
        }
        emplace_back(r);
    }

    return size();
}

int ProcCmdline::Parse()
{
    // B37: 原实现 std::string(p) 依赖 strlen——损坏 acore 的 cmdline 数据无 NUL
    // 终止时越界读。改用显式长度构造，并限定扫描范围。
    if (!_pf) {
        return 0;
    }
    const char* end = _pf->f_data + _pf->f_size;
    const char* p = _pf->f_data;
    // R50-5: 无上限——构造的 NUL 密集 cmdline（GetFile 上限 64MB）可产生约 64M 个
    // 空 argv（数 GB 分配，OOM/DoS）。真实 cmdline 受 ARG_MAX(~2MB) 限制。加数量上限。
    const size_t MAX_ARGV = 16384;
    while (p < end && argv.size() < MAX_ARGV) {
        const char* q = p;
        while (q < end && *q) {
            q++;
        }
        argv.push_back(std::string(p, (size_t)(q - p)));
        if (q >= end) {
            break;   // 无 NUL 终止（损坏数据）：结束
        }
        p = q + 1;
    }

    return argv.size();
}

int ProcStat::Parse()
{
    // B18/B37: stat 解析要同时防"字段不足崩溃"与"comm 含空格字段错位"。
    // /proc/<pid>/stat 格式 `pid (comm) state ppid ...`——comm 可能含空格/括号，
    // strtok 按空格切分会把字段整体错位。正确做法：取第一个 '(' 与最后一个 ')'，
    // '(' 前是 pid，')' 后才是真正按空格切的字段。字段不足时用 fld() 兜底 "0"。
    if (!_pf) {
        return 0;
    }

    char buf[1024];
    size_t n = _pf->f_size;
    if (n >= sizeof(buf)) {
        n = sizeof(buf) - 1;   // 防越界，替代原 assert
    }
    memcpy(buf, _pf->f_data, n);
    buf[n] = '\0';

    char *array[64] = {0};
    int fields = 0;

    char *open = strchr(buf, '(');
    char *close = open ? strrchr(open, ')') : NULL;
    if (open && close) {
        // B63: comm = 括号内文本（内核 task->comm，可执行名）。可能含空格/括号，
        // 用长度拷贝（不能截到空格）。
        size_t clen = (size_t)(close - open - 1);
        if (clen >= sizeof(comm)) {
            clen = sizeof(comm) - 1;
        }
        memcpy(comm, open + 1, clen);
        comm[clen] = '\0';

        // pid 在 '(' 之前
        *open = '\0';
        char *tok = strtok(buf, " ");
        if (tok) {
            array[fields++] = tok;        // array[0] = pid
        }
        // array[1] 保留为 comm（不解析，保持索引与注释一致）
        // ')' 之后的字段：state ppid ...
        char *rest = close + 1;
        while (*rest == ' ') rest++;
        tok = strtok(rest, " ");
        int idx = 2;                      // array[2] = state, array[3] = ppid ...
        while (tok) {
            if (idx >= (int)ARRAYSIZE(array) - 1) {
                break;
            }
            array[idx++] = tok;
            tok = strtok(NULL, " ");
        }
        fields = idx;
    } else {
        // 无括号：退化为空格切分（字段可能错位，但保证不崩溃）
        char *tok = strtok(buf, " ");
        while (tok) {
            if (fields >= (int)ARRAYSIZE(array) - 1) {
                break;
            }
            array[fields++] = tok;
            tok = strtok(NULL, " ");
        }
    }

    // 字段缺失时返回 "0" 而非 NULL，避免 strtol/解引用崩溃
    auto fld = [&](int idx) -> const char* {
        return (idx >= 0 && idx < fields && array[idx]) ? array[idx] : "0";
    };

    sname = fld(2)[0];
    // b25 (Codex review): ELF prpsinfo 的 pr_state 由内核 fill_psinfo 填
    // task_state_index(p)，即 fs/proc/array.c task_state_array 的**序数**
    // （`return fls(state)`：find last set bit），不是 TASK_* 位值。
    // task_state_array = {R,S,D,T,t,X,Z,P,I}，序数为 R=0 S=1 D=2 T=3 t=4
    // X=5 Z=6 P=7 I=8。原实现写的是位值（T=4/t=8/X=16/Z=32/P=64/I=128），
    // 与内核 pr_state 不符，gdb info proc 显示错误的状态序号。
    switch (sname) {
        case 'R': state=0; break;
        case 'S': state=1; break;
        case 'D': state=2; break;
        case 'T': state=3; break;   // task_state_array index 3 (stopped)
        case 't': state=4; break;   // index 4 (tracing stop)
        case 'X': state=5; break;   // index 5 (dead)
        case 'Z': state=6; break;   // index 6 (zombie)
        case 'P': state=7; break;   // index 7 (parked)
        case 'I': state=8; break;   // index 8 (idle)
        default: state=0; break;
    }

    pid = strtol(fld(0), NULL, 10);
    ppid = strtol(fld(3), NULL, 10);
    pgid = strtol(fld(4), NULL, 10);
    sid = strtol(fld(5), NULL, 10);

    /* kernel uses jiffies, here changed to MS
     */
    utime = strtoul(fld(13), NULL, 10);
    stime = strtoul(fld(14), NULL, 10);
    cutime = strtoul(fld(15), NULL, 10);
    cstime = strtoul(fld(16), NULL, 10);

    /* kernel task_vsize, PAGESIZE * mm->total_vm
     */
    vsize = strtoul(fld(22), NULL, 10) / 1024;

    /* kernel mm_struct, rss is anon_rss + file_rss pages
     */
    // R50-25: rss 以内核 MMU 页计——PAGE_SIZE 宏硬编码 4096 在 64K 页 aarch64
    // 上偏小 16 倍。用真实页大小（采集侧==宿主，ptrace 同架构）。
    {
        static long page_size = sysconf(_SC_PAGESIZE);
        rss = strtoul(fld(23), NULL, 10) * (unsigned long)page_size / 1024;
    }

    // num_threads
    num_threads = strtoul(fld(19), NULL, 10);

    // B25: 补充 note 字段
    flags = strtoul(fld(8), NULL, 10);    // stat 字段 9
    nice = (int)strtol(fld(18), NULL, 10); // stat 字段 19
    pending = strtoul(fld(30), NULL, 10); // stat 字段 31
    blocked = strtoul(fld(31), NULL, 10); // stat 字段 32

    return 0;
}

int ProcAuxv::Parse()
{
    // B28: ProcFile 是 #pragma pack(1)，f_data 在偏移 9（未对齐）；直接
    // (uint64_t*) 解引用在 aarch64 上可能 fault。用 memcpy 逐对读。
    if (!_pf) {
        return 0;
    }
    const char* base = _pf->f_data;
    size_t count = _pf->f_size / 8;
    for (size_t i = 0; i + 1 < count; i += 2) {
        uint64_t type, val;
        memcpy(&type, base + i * 8, 8);
        memcpy(&val, base + (i + 1) * 8, 8);
        switch (type) {
            case AT_NULL:
                // end mark
                return 0;
                break;

            case AT_UID:
                uid = (uint32_t)val;
                break;

            case AT_GID:
                gid = (uint32_t)val;
                break;

            case AT_EUID:
                euid = (uint32_t)val;
                break;

            case AT_EGID:
                egid = (uint32_t)val;
                break;
        }
    }

    return 0;
}

}; // arthur

