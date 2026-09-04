/* Support '/proc/xxx' pseudo-filesystem.
 */

#include <string> 
#include <iostream> 
#include <sstream> 
#include <cstdarg>
#include <cerrno>
#include <climits>
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
    if (out_truncated) {
        *out_truncated = false;
    }
    if (!buf || buf_len < (int)sizeof(ProcFile) + 1 || !path) {
        errno = EINVAL;
        error("invalid buffer or path for proc file read");
        return NULL;
    }
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
        // 载荷区恰好读满时必须再探测 1 字节才能区分“完整读到 EOF”和
        // “确实还有数据”。探测字节不写入调用方缓冲区，保持 B17 的边界。
        if (left <= 0) {
            char extra;
            do {
                rc = read(fd, &extra, 1);
            } while (rc < 0 && errno == EINTR);
            if (rc < 0) {
                int saved_errno = errno;
                error("read %s failed (%s)", path, strerror(saved_errno));
                close(fd);
                errno = saved_errno;
                return NULL;
            }
            if (rc > 0) {
                warn("buffer too small for %s, truncating at %d bytes", path, len);
                if (out_truncated) { *out_truncated = true; }
            }
            break;
        }

        rc = read(fd, pf->f_data+len, MIN(4096, left));
        if (rc < 0 && errno == EINTR) {
            continue;
        }
        if (rc < 0) {
            int saved_errno = errno;
            error("read %s failed (%s)", path, strerror(saved_errno));
            close(fd);
            errno = saved_errno;
            return NULL;
        }
        if (rc == 0) {
            break;
        }

        len += rc;
        left -= rc;
    }

    close(fd);

    pf->f_data[len] = '\0';
    pf->f_size = len;

    return pf;
}

ProcFile* ProcFile::Read(bool *out_truncated, char* buf, int buf_len, const char *fmt, ...)
{
    char path[PATH_MAX];

    if (!fmt) {
        errno = EINVAL;
        return NULL;
    }

    va_list ap;
    va_start(ap, fmt);
    int path_len = vsnprintf(path, sizeof(path), fmt, ap);
    va_end(ap);
    if (path_len < 0 || path_len >= (int)sizeof(path)) {
        errno = ENAMETOOLONG;
        error("proc file path exceeds PATH_MAX");
        return NULL;
    }

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

int ProcDecoder::readline(int& cur, std::string& out)
{
    out.clear();
    if (!_pf || cur < 0 || cur >= (int)_pf->f_size) {
        return 0;
    }

    const char *begin = _pf->f_data + cur;
    const char *end = _pf->f_data + _pf->f_size;
    const char *line_end = begin;
    while (line_end < end && *line_end != '\n') {
        line_end++;
    }
    out.assign(begin, (size_t)(line_end - begin));
    while (line_end < end && *line_end == '\n') {
        line_end++;
    }
    cur = (int)(line_end - _pf->f_data);
    return (int)out.size();
}

int ProcMaps::Parse()
{
    clear();
    int cur = 0;
    std::string line;
    uint64_t previous_end = 0;
    while (readline(cur, line)) {
        // /proc/<pid>/maps is text. An embedded NUL makes sscanf stop at a
        // valid-looking prefix while the path extraction below keeps the
        // hidden suffix, producing a malformed NT_FILE note.
        if (line.find('\0') != std::string::npos) {
            error("maps line contains an embedded NUL, acore corrupt");
            return -1;
        }
        //printf("%s\n", line);
        MemRegion r = {};
        // b103 (Codex B103 review): perm 声明在循环外只清零一次——合法行之后出现
        // 在 %4s 前解析失败的畸形行时，会继承上一行权限（陈旧 perms/私有标志）。
        // 逐行清零 + 严格校验 sscanf 7 个转换，畸形行整体跳过，不再入表。
        char perm[16] = {0};
        int consumed = 0;
        // R50-5: 偏移字段用 %8lx 会截断 ≥4GiB 的映射偏移（内核打印 %08llx 无上限）——
        // 9 位十六进制时 %8lx 读 8 位后空格不匹配，整行解析失败（offset/inode/name 全丢）。
        // 去掉宽度用 %lx 读全。格式不匹配时 perms 保持 0 而非垃圾。
        int nfields = sscanf(line.c_str(), "%lx-%lx %4s %lx %x:%x %lu %n",
                &r.start_addr,
                &r.end_addr,
                perm,
                &r.offset,
                &r.dev_major,
                &r.dev_minor,
                &r.inode,
                &consumed);
        if (nfields != 7) {
            error("malformed maps line, acore corrupt");
            return -1;
        }
        if (strlen(perm) != 4 ||
            (perm[0] != 'r' && perm[0] != '-') ||
            (perm[1] != 'w' && perm[1] != '-') ||
            (perm[2] != 'x' && perm[2] != '-') ||
            (perm[3] != 'p' && perm[3] != 's') ||
            r.start_addr >= r.end_addr || r.start_addr < previous_end) {
            error("invalid or overlapping maps region %lx-%lx, acore corrupt",
                  (unsigned long)r.start_addr, (unsigned long)r.end_addr);
            return -1;
        }
        previous_end = r.end_addr;
        // maps 第 6 列后的路径可能含空格或 (deleted) 后缀；%s 会截断，
        // 用 %n 定位 inode 字段结束位置，取剩余整行为映射名。
        if (consumed > 0 && (size_t)consumed < line.size()) {
            size_t path = (size_t)consumed;
            while (path < line.size() && (line[path] == ' ' || line[path] == '\t')) {
                path++;
            }
            r.name.assign(line, path, std::string::npos);
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
    argv.clear();
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
            p = end;
            break;   // bounded final argument without NUL
        }
        p = q + 1;
    }

    if (p < end) {
        error("cmdline exceeds %lu arguments, acore corrupt",
              (unsigned long)MAX_ARGV);
        return -1;
    }

    return argv.size();
}

int ProcStat::Parse()
{
    // B18/B37: stat 解析要同时防"字段不足崩溃"与"comm 含空格字段错位"。
    // /proc/<pid>/stat 格式 `pid (comm) state ppid ...`——comm 可能含空格/括号，
    // strtok 按空格切分会把字段整体错位。正确做法：取第一个 '(' 与最后一个 ')'，
    // '(' 前是 pid，')' 后才是真正按空格切的字段。字段不足时用 fld() 兜底 "0"。
    if (!_pf || _pf->f_size == 0 || _pf->f_size >= 1024) {
        error("stat missing or exceeds parser boundary, acore corrupt");
        return -1;
    }
    if (memchr(_pf->f_data, '\0', _pf->f_size) != NULL) {
        error("stat contains an embedded NUL, acore corrupt");
        return -1;
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
        // task->comm may legally contain a newline. Only a newline after the
        // closing ')' terminates the stat record; treating the first newline
        // in the buffer as the terminator rejects a live, valid Linux task.
        char *newline = strchr(close + 1, '\n');
        if (newline && newline != buf + n - 1) {
            error("stat contains data after its first record, acore corrupt");
            return -1;
        }
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
        char *saveptr = NULL;
        char *tok = strtok_r(buf, " ", &saveptr);
        if (tok) {
            array[fields++] = tok;        // array[0] = pid
        }
        if (!tok || strtok_r(NULL, " ", &saveptr) != NULL) {
            error("stat contains extra data before comm, acore corrupt");
            return -1;
        }
        // array[1] 保留为 comm（不解析，保持索引与注释一致）
        // ')' 之后的字段：state ppid ...
        char *rest = close + 1;
        while (*rest == ' ') rest++;
        tok = strtok_r(rest, " ", &saveptr);
        int idx = 2;                      // array[2] = state, array[3] = ppid ...
        while (tok) {
            if (idx >= (int)ARRAYSIZE(array) - 1) {
                break;
            }
            array[idx++] = tok;
            tok = strtok_r(NULL, " ", &saveptr);
        }
        fields = idx;
    } else {
        error("stat lacks a complete comm field, acore corrupt");
        return -1;
    }

    // Every supported Linux /proc/<pid>/stat contains well beyond field 32;
    // Arthur consumes through SigBlk (field 32). Missing fields previously
    // became string "0" and yielded a plausible-looking but false PRSTATUS.
    if (fields <= 31) {
        error("stat has only %d fields, acore corrupt", fields);
        return -1;
    }

    // 字段缺失时返回 "0" 而非 NULL，避免 strtol/解引用崩溃
    auto fld = [&](int idx) -> const char* {
        return (idx >= 0 && idx < fields && array[idx]) ? array[idx] : "0";
    };

    if (fld(2)[0] == '\0' || fld(2)[1] != '\0') {
        error("stat task state is not exactly one character, acore corrupt");
        return -1;
    }
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
        // Linux 2.6.33-3.13 exposed these transient states. Arthur still
        // reads v1-v3 archives from that era; retain approximate modern
        // equivalents instead of rejecting an otherwise valid old stat.
        case 'x': state=5; break;   // dead
        case 'K': state=2; break;   // wakekill
        case 'W': state=0; break;   // waking (also pre-2.6 paging)
        default:
            error("stat has invalid task state '%c', acore corrupt", sname);
            return -1;
    }

    auto parse_signed = [&](int idx, long& out) -> bool {
        const char *text = fld(idx);
        char *end = NULL;
        errno = 0;
        long value = strtol(text, &end, 10);
        if (end == text || *end != '\0' || errno == ERANGE) {
            error("stat field %d is not a valid signed integer, acore corrupt", idx + 1);
            return false;
        }
        out = value;
        return true;
    };
    auto parse_unsigned = [&](int idx, unsigned long& out) -> bool {
        const char *text = fld(idx);
        if (*text == '-') {
            error("stat field %d is unexpectedly negative, acore corrupt", idx + 1);
            return false;
        }
        char *end = NULL;
        errno = 0;
        unsigned long value = strtoul(text, &end, 10);
        if (end == text || *end != '\0' || errno == ERANGE) {
            error("stat field %d is not a valid unsigned integer, acore corrupt", idx + 1);
            return false;
        }
        out = value;
        return true;
    };

    long parsed_pid, parsed_ppid, parsed_pgid, parsed_sid;
    long parsed_nice, parsed_num_threads, parsed_rss;
    unsigned long parsed_flags, parsed_utime, parsed_stime, parsed_cutime;
    unsigned long parsed_cstime, parsed_vsize, parsed_pending, parsed_blocked;
    if (!parse_signed(0, parsed_pid) || !parse_signed(3, parsed_ppid) ||
        !parse_signed(4, parsed_pgid) || !parse_signed(5, parsed_sid) ||
        !parse_unsigned(8, parsed_flags) || !parse_unsigned(13, parsed_utime) ||
        !parse_unsigned(14, parsed_stime) || !parse_unsigned(15, parsed_cutime) ||
        !parse_unsigned(16, parsed_cstime) || !parse_signed(18, parsed_nice) ||
        !parse_signed(19, parsed_num_threads) || !parse_unsigned(22, parsed_vsize) ||
        !parse_signed(23, parsed_rss) || !parse_unsigned(30, parsed_pending) ||
        !parse_unsigned(31, parsed_blocked)) {
        return -1;
    }
    if (parsed_pid <= 0 || parsed_pid > INT_MAX || parsed_ppid < 0 ||
        parsed_ppid > INT_MAX || parsed_pgid < 0 || parsed_pgid > INT_MAX ||
        parsed_sid < 0 || parsed_sid > INT_MAX || parsed_nice < -20 ||
        parsed_nice > 19 || parsed_num_threads <= 0 ||
        parsed_num_threads > INT_MAX || parsed_rss < 0) {
        error("stat numeric field outside supported range, acore corrupt");
        return -1;
    }

    pid = (pid_t)parsed_pid;
    ppid = (pid_t)parsed_ppid;
    pgid = (pid_t)parsed_pgid;
    sid = (pid_t)parsed_sid;

    /* kernel uses jiffies, here changed to MS
     */
    utime = parsed_utime;
    stime = parsed_stime;
    cutime = parsed_cutime;
    cstime = parsed_cstime;

    /* kernel task_vsize, PAGESIZE * mm->total_vm
     */
    vsize = parsed_vsize / 1024;

    /* kernel mm_struct, rss is anon_rss + file_rss pages
     */
    // R50-25: rss 以内核 MMU 页计——PAGE_SIZE 宏硬编码 4096 在 64K 页 aarch64
    // 上偏小 16 倍。用真实页大小（采集侧==宿主，ptrace 同架构）。
    {
        static long page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0 || (unsigned long)parsed_rss > ULONG_MAX / (unsigned long)page_size) {
            error("stat rss conversion overflows, acore corrupt");
            return -1;
        }
        rss = (unsigned long)parsed_rss * (unsigned long)page_size / 1024;
    }

    // num_threads
    num_threads = (int)parsed_num_threads;

    // B25: 补充 note 字段
    flags = parsed_flags;       // stat field 9
    nice = (int)parsed_nice;    // stat field 19
    pending = parsed_pending;   // stat field 31
    blocked = parsed_blocked;   // stat field 32

    return 0;
}

int ProcAuxv::Parse()
{
    // B28: ProcFile 是 #pragma pack(1)，f_data 在偏移 9（未对齐）；直接
    // (uint64_t*) 解引用在 aarch64 上可能 fault。用 memcpy 逐对读。
    if (!_pf || _pf->f_size < 2 * sizeof(uint64_t) ||
        (_pf->f_size % (2 * sizeof(uint64_t))) != 0) {
        error("auxv size %u is not a complete entry sequence, acore corrupt",
              _pf ? _pf->f_size : 0);
        return -1;
    }
    uid = gid = euid = egid = 0;
    page_size = 0;
    const char* base = _pf->f_data;
    size_t count = _pf->f_size / 8;
    for (size_t i = 0; i + 1 < count; i += 2) {
        uint64_t type, val;
        memcpy(&type, base + i * 8, 8);
        memcpy(&val, base + (i + 1) * 8, 8);
        switch (type) {
            case AT_NULL:
                if (i + 2 != count) {
                    error("auxv contains data after AT_NULL, acore corrupt");
                    return -1;
                }
                return 0;

            case AT_UID:
                if (val > UINT32_MAX) {
                    error("auxv AT_UID exceeds uid_t range, acore corrupt");
                    return -1;
                }
                uid = (uint32_t)val;
                break;

            case AT_GID:
                if (val > UINT32_MAX) {
                    error("auxv AT_GID exceeds gid_t range, acore corrupt");
                    return -1;
                }
                gid = (uint32_t)val;
                break;

            case AT_EUID:
                if (val > UINT32_MAX) {
                    error("auxv AT_EUID exceeds uid_t range, acore corrupt");
                    return -1;
                }
                euid = (uint32_t)val;
                break;

            case AT_EGID:
                if (val > UINT32_MAX) {
                    error("auxv AT_EGID exceeds gid_t range, acore corrupt");
                    return -1;
                }
                egid = (uint32_t)val;
                break;

            case AT_PAGESZ:
                if (val == 0 || val > UINT32_MAX || (val & (val - 1)) != 0) {
                    error("auxv AT_PAGESZ is invalid, acore corrupt");
                    return -1;
                }
                page_size = val;
                break;
        }
    }

    error("auxv missing AT_NULL terminator, acore corrupt");
    return -1;
}

int ProcStatus::Parse()
{
    if (!_pf || _pf->f_size == 0 ||
        memchr(_pf->f_data, '\0', _pf->f_size) != NULL) {
        error("status missing or contains an embedded NUL");
        return -1;
    }

    bool saw_uid = false;
    bool saw_gid = false;
    int cur = 0;
    std::string line;
    while (readline(cur, line)) {
        const char *field = NULL;
        uint32_t *real_id = NULL;
        bool *seen = NULL;
        if (line.compare(0, 4, "Uid:") == 0) {
            field = "Uid";
            real_id = &uid;
            seen = &saw_uid;
        } else if (line.compare(0, 4, "Gid:") == 0) {
            field = "Gid";
            real_id = &gid;
            seen = &saw_gid;
        } else {
            continue;
        }

        if (*seen) {
            error("status contains duplicate %s field", field);
            return -1;
        }
        *seen = true;

        const char *p = line.c_str() + 4;
        uint32_t values[4] = {};
        for (size_t i = 0; i < ARRAYSIZE(values); i++) {
            bool separated = false;
            while (*p == ' ' || *p == '\t') {
                separated = true;
                p++;
            }
            if (!separated || *p < '0' || *p > '9') {
                error("status %s field lacks four valid IDs", field);
                return -1;
            }
            char *end = NULL;
            errno = 0;
            unsigned long long value = strtoull(p, &end, 10);
            if (end == p || errno == ERANGE || value > UINT32_MAX) {
                error("status %s field contains an out-of-range ID", field);
                return -1;
            }
            values[i] = (uint32_t)value;
            p = end;
        }
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p != '\0') {
            error("status %s field contains trailing data", field);
            return -1;
        }
        *real_id = values[0];
    }

    if (!saw_uid || !saw_gid) {
        error("status is missing Uid or Gid credentials");
        return -1;
    }
    return 0;
}

}; // arthur
