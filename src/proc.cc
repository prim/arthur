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

ProcFile* ProcFile::ReadPath(char* buf, int buf_len, const char *path)
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
    }

    close(fd);

    pf->f_data[len] = '\0';
    pf->f_size = len;

    return pf;
}

ProcFile* ProcFile::Read(char* buf, int buf_len, const char *fmt, ...)
{
    char path[PATH_MAX];
   
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(path, sizeof(path), fmt, ap);
    va_end(ap);
   
    return ReadPath(buf, buf_len, path);
}

int ProcDecoder::readline(int& cur, char *out, size_t n)
{
    if (!_pf || cur >= (int)_pf->f_size) {
        return 0;
    }

    const char* p = _pf->f_data + cur;
    const char* end = p + _pf->f_size;
    const char* q = p;

    // find '\n'
    for (; q < end; q++) {
        if (*q == '\n') {
            break;
        }
    }
    
    int len = q - p;
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
    char perm[16];
    char name[PATH_MAX];
    char line[PATH_MAX];

    int cur = 0;
    while (readline(cur, line, sizeof(line))) {
        //printf("%s\n", line);
        MemRegion r = {};
        name[0] = 0;
        int consumed = 0;
        sscanf(line, "%lx-%lx %4s %8lx %x:%x %lu %n",
                &r.start_addr,
                &r.end_addr,
                perm,
                &r.offset,
                &r.dev_major,
                &r.dev_minor,
                &r.inode,
                &consumed);
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

        emplace_back(r);
    }

    return size();
}

int ProcCmdline::Parse()
{
    for (const char *p = _pf->f_data; p<(_pf->f_data + _pf->f_size);) {
        // printf("%s\n", p);
        argv.push_back(p);

        // next string
        while(*p++); 
    }
    
    return argv.size();
}

int ProcStat::Parse()
{
#define BUF_MAX (1024) 
    char buf[BUF_MAX];
    char *array[64] = {0};
    
    assert(_pf->f_size < BUF_MAX);

    memcpy(buf, _pf->f_data, _pf->f_size);
    buf[_pf->f_size] = '\0'; 

    int i = 0;
    char *p = strtok(buf, " ");
    while(p) {
        if (i > ((int)ARRAYSIZE(array) - 1)) {
            break;
        }
        array[i++] = p;
        p = strtok(NULL, " ");
    }

    sname = array[2][0]; 
    switch (sname) {
        case 'R': state=0; break;
        case 'S': state=1; break;
        case 'D': state=2; break;
        case 'T': state=3; break;
        case 'Z': state=4; break;
        case 'W': state=5; break;
    }

    pid = strtol(array[0], NULL, 10);
    ppid = strtol(array[3], NULL, 10);
    pgid = strtol(array[4], NULL, 10);
    sid = strtol(array[5], NULL, 10);

    /* kernel uses jiffies, here changed to MS
     */
    utime = strtoul(array[13], NULL, 10);
    stime = strtoul(array[14], NULL, 10);
    cutime = strtoul(array[15], NULL, 10);
    cstime = strtoul(array[16], NULL, 10);

    /* kernel task_vsize, PAGESIZE * mm->total_vm
     */
    vsize = strtoul(array[22], NULL, 10) / 1024;
    
    /* kernel mm_struct, rss is anon_rss + file_rss pages
     */
    rss = strtoul(array[23], NULL, 10) * PAGE_SIZE / 1024;

    // num_threads
    num_threads = strtoul(array[19], NULL, 10);
    
    return 0;
#undef BUF_MAX  
}

int ProcAuxv::Parse()
{
    uint64_t *vec = (uint64_t*)_pf->f_data;
    for (int i=0; i < (int)(_pf->f_size / 8); i+=2) {
        switch (vec[i]) {
            case AT_NULL:
                // end mark
                return 0;
                break;

            case AT_UID:
                uid = vec[i+1];
                break;
           
            case AT_GID:
                gid = vec[i+1];
                break;
            
            case AT_EUID:
                euid = vec[i+1];
                break;
            
            case AT_EGID:
                egid = vec[i+1];
                break;
        }
    }

    return 0;
}

}; // arthur

