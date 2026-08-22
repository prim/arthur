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
    " -2 : same as (1) but corefile by kernel, merge a corefile afterwise.\n"
    "      NOTE: merge (-m) is not implemented; the kernel core alone is usable,\n"
    "      but the metadata file cannot be merged into a final GNU corefile.\n"
    " -3 : attach to process, write gcore with lz4 compressed on SIGSIL, SIGABRT and SIGSEGV\n"
    "      able to write out acorefile when monitoring"
    "\n"
    "Convert acore to corefile,\n"
    "  arthur -c <acore> -o <corefile>\n"
    "\n"
    "Merge support for Mode(2) -- NOT IMPLEMENTED,\n"
    "  arthur -m <acore> <core> -o <corefile>\n"
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
    while ((ch = getopt_long(argc, argv, opts, longopts, NULL)) != -1) {
        switch (ch) {

        case 'p':   // pid
            cfg.pid = atoi(optarg);
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
        char buf[128];
        snprintf(buf, sizeof(buf), "%s.z4", file);
        return dump.test_compress(file, buf);
    } else if (cfg.mode == 2) {
        // R50-1: 缺输出文件时 argv[optind+1] 为 NULL——fopen(NULL,"wb") 崩溃。
        if (optind + 1 >= argc) {
            error("test_decompress: missing output file");
            return 2;
        }
        const char *in_file = argv[optind];
        const char *out_file = argv[optind+1];
        return dump.test_decompress(in_file, out_file);
    }

    // R50-6: 无 -p/-c/-m、mode 非 1/2 却带位置参数——原实现静默 return 0
    //（no-op 却报成功，脚本误判）。显式失败。
    error("no operation selected (use -p <pid>, -c <acore>, or -1/-2 for test)");
    help();
    return 2;
}
