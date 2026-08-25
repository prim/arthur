/* Arthur is a field tool belonging to alinode debugger project,
 * normally used to generate corefile, or inspect nodejs variables in live time.
 */

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <climits>      // INT_MAX (b145: -p pid_t 上界)

#include "core.h"
#include "proc.h"
#include "lz4.h"

using namespace arthur;

enum ARTHUR_OP {
    ARTHUR_OP_GENERATE = 0, // process to acore
    ARTHUR_OP_DECOMPRESS,   // acore to corefile
    ARTHUR_OP_MERGE,        // merge acore and core to final corefile
};

struct ArthurCfg {
    pid_t pid;
    ARTHUR_OP op;
    const char *metafile;
    const char *corefile;
    const char *output;
    int mode;
} cfg = {0};

void show_version() 
{
    printf(GIT_VERSION "\n");
}

void help()
{
    const char* help = "Arthur - Alinode Runtime Debugger (" GIT_VERSION ")\n"
    "\n"
    "Capture a corefile,\n"
    "  arthur -p <pid> \n"
    "  arthur -p <pid> -o <filename>\n"
    "  arthur -p <pid> -o <filename> -0|-1|-2|-3\n"
    "\n"
    "Mode (as a getopt option, not a positional argument),\n"
    " -0 : forkcore and lz4 compressed. (default)\n"
    " -1 : same as gcore but lz4 compressed, less file size.\n"
    " -2 : kernel generates a core from the forked child; -o writes a metadata\n"
    "      file (NOT a standalone acore) holding registers/threads. The kernel\n"
    "      core lands in the TARGET's cwd (core_pattern), not here.\n"
    "      NOTE: merge (-m) is not implemented; the metadata file cannot be\n"
    "      merged into a final GNU corefile, so thread/reg data is unrecoverable.\n"
    " -3 : attach to process, write gcore with lz4 compressed on SIGILL, SIGABRT and SIGSEGV\n"
    "      able to write out acorefile when monitoring"
    "\n"
    "Convert acore to corefile,\n"
    "  arthur -c <acore> -o <corefile>\n"
    "\n"
    "Merge support for Mode(2) -- NOT IMPLEMENTED,\n"
    "  arthur -m <acore> <core> -o <corefile>\n"
    "\n"
    "Internal test tools (no -p),\n"
    "  arthur -1 <file>          compress <file> to <file>.z4\n"
    "  arthur -2 <in.z4> <out>   decompress <in.z4> to <out>\n"
    "\n"
    ;

    puts(help);
}

int main(int argc, char *argv[])
{   
    const char *opts = "hvp:mc:o:1234567890";
    struct option longopts[] = {
             { "help", no_argument, NULL, 'h' },
             { "pid", required_argument, NULL, 'p' },
             { "merge", no_argument, NULL, 'm' },
             { "core", required_argument, NULL, 'c' },
             { "output", required_argument, NULL, 'o' },
             { "version", no_argument, NULL, 'v' },
             { NULL, 0, NULL, 0 }
    };

    int ch;
    int mode_set = 0;   // R50-6: 记录 mode 选项个数，冲突检测
    int pid_set = 0;    // R50-29: 是否显式给了 -p（区分"没给"与"给了非法值"）
    while ((ch = getopt_long(argc, argv, opts, longopts, NULL)) != -1) {
        switch (ch) {

        case 'p':   // pid
            // b145 (Codex B145 review): atoi 接受 `-p 123junk` 并操作 pid 123、
            // 超长数字溢出 UB。strtol + 全串 + 正范围校验（真实合法 PID 为正 int）。
            {
                char *end = NULL;
                errno = 0;
                long v = strtol(optarg, &end, 10);
                if (end == optarg || *end != '\0' || errno == ERANGE ||
                    v <= 0 || v > INT_MAX) {
                    error("invalid pid '%s' (must be a positive integer)", optarg);
                    return 2;
                }
                cfg.pid = (pid_t)v;
                pid_set = 1;
            }
            break;

        case 'm':   // merge
            cfg.op = ARTHUR_OP_MERGE;
            break;

        case 'c':   // core
            cfg.op = ARTHUR_OP_DECOMPRESS;
            cfg.metafile = strdup(optarg);
            break;

        case 'o':   // output
            cfg.output = strdup(optarg);
            break;

        case '0':   // forkcore
            cfg.mode = 0;
            mode_set++;
            break;

        case '1':   // gcore
            cfg.mode = 1;
            mode_set++;
            break;

        case '2':   // forkcore by kernel
            cfg.mode = 2;
            mode_set++;
            break;

        case '3':   // monitor
            cfg.mode = 3;
            mode_set++;
            break;

        case 'h':
            help();
            exit(0);
        
        case 'v':
            show_version();
            exit(0); 
        
        default:
            help();
            return -1;
        }
    }

    // R50-6: 多个 mode 选项（-0/-1/-2/-3）同时给出时，原实现"最后一个生效"
    // 静默覆盖（如 `-0 -2` 实际执行 mode 2）。冲突应显式失败。
    if (mode_set > 1) {
        error("conflicting mode options (-0/-1/-2/-3 are mutually exclusive)");
        return -1;
    }
    // R50-29: -p 与 -c/-m 冲突（capture vs decompress/merge）——原实现分支优先级
    // 静默决定，-c/-m 被无视，用户输入错误却执行了另一件事。显式拒绝。
    if (cfg.pid && cfg.op != ARTHUR_OP_GENERATE) {
        error("-p (capture) conflicts with -c/-m (convert/merge)");
        return 2;
    }
    // B181: mode 选项（-0/-1/-2/-3）与 -c/-m 组合时被静默忽略——`-c acore -1 file`
    // 实际执行 decompress（-1 被无视）、`-1 file -m` 落入 merge——与 -p 的 R50-29
    // 检查同 class 的对称缺口（mode 选项在 test 工具里复用：`-1 file` 是 test_compress、
    // `-2 in out` 是 test_decompress，op==GENERATE 时合法，不触发此检查）。
    if (mode_set && cfg.op != ARTHUR_OP_GENERATE) {
        error("mode option (-0/-1/-2/-3) conflicts with -c/-m (convert/merge)");
        return 2;
    }
    // R50-29: -p 0 / -p abc（atoi 得 0）被静默当"无 -p"，落到 test_compress/
    // test_decompress，操作类型被切换。非法 pid 显式拒绝。
    if (pid_set && cfg.pid <= 0) {
        error("invalid pid %d (must be > 0)", cfg.pid);
        return 2;
    }

    Coredump dump(cfg.pid);
    // capture
    if (cfg.pid) {
        char fpath[PATH_MAX];
        const char *fout = cfg.output;
        if (!fout) {
            snprintf(fpath, sizeof(fpath), "acore.%u", cfg.pid);
            fout = fpath; 
        }

        dump.takememspace();
        switch (cfg.mode) {
            case 0: 
                return dump.forkcore(fout, 0);
            case 1: 
                return dump.generate(fout);
            case 2: 
                return dump.forkcore(fout, 1);
            case 3:
                return dump.monitor(fout);
            default: 
                help();
                exit(1);
        }
    }

    // decompress 
    if (cfg.op == ARTHUR_OP_DECOMPRESS) {
        return dump.decompress(cfg.metafile, cfg.output);
    }

    // merge
    if (cfg.op == ARTHUR_OP_MERGE) {
        // merge 未实现（Coredump::merge 只有声明）。避免静默成功误导调用方。
        error("merge (-m) not implemented yet; mode 2 outputs a metadata file that "
              "cannot be merged into a final GNU corefile");
        return -1;
    }

    if (argc == optind) {
        help();
        return 2;
    }

    // test file compress
    if (cfg.mode == 1) {
        // R50-1: 缺输入文件时 argv[optind] 为 NULL——snprintf %s 与 fopen(NULL)
        // 崩溃。显式报错。
        if (optind >= argc) {
            error("test_compress: missing input file");
            return 2;
        }
        const char *file = argv[optind];
        // B182/B183: 用户显式 -o 优先用，不再静默丢弃（原实现写死 <file>.z4）；
        // 无 -o 时输出名动态拼接——原 128 字节栈缓冲对长路径截断，截断后不再等于
        // <file>.z4、可能写到意外路径/同名冲突。
        const char *out = cfg.output;
        char *derived = NULL;
        if (!out) {
            size_t need = strlen(file) + 4;   // ".z4" + NUL
            derived = (char*)malloc(need);
            if (!derived) {
                error("test_compress: out of memory");
                return 2;
            }
            snprintf(derived, need, "%s.z4", file);
            out = derived;
        }
        int rc = dump.test_compress(file, out);
        free(derived);
        return rc;
    } else if (cfg.mode == 2) {
        // R50-1: 缺输入文件时 argv[optind] 为 NULL——fopen(NULL,"rb") 崩溃。
        if (optind >= argc) {
            error("test_decompress: missing input file");
            return 2;
        }
        const char *in_file = argv[optind];
        // B182: test_decompress 同样支持 -o 作输出（原实现只认位置参数、-o 被静默
        // 丢弃，且缺位置输出参数时误报 "missing output file"）。-o 与位置输出同给
        // 视为歧义显式拒绝。
        const char *out_file = cfg.output;
        if (!out_file) {
            if (optind + 1 >= argc) {
                error("test_decompress: missing output file");
                return 2;
            }
            out_file = argv[optind + 1];
        } else if (optind + 1 < argc) {
            error("test_decompress: ambiguous -o and positional output both given");
            return 2;
        }
        return dump.test_decompress(in_file, out_file);
    }

    // R50-6: 无 -p/-c/-m、mode 非 1/2 却带位置参数——原实现静默 return 0
    //（no-op 却报成功，脚本误判）。显式失败。
    error("no operation selected (use -p <pid>, -c <acore>, or -1/-2 for test)");
    help();
    return 2;
}
