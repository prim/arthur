#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <string>
#include <vector>

#include "core.h"

using namespace arthur;

static void append(std::vector<char>& data, const void *value, size_t size)
{
    const char *bytes = static_cast<const char *>(value);
    data.insert(data.end(), bytes, bytes + size);
}

static std::vector<char> process_payload(bool trailing,
                                         uint16_t version = ACORE_VERSION,
                                         uint32_t uid = 0, uint32_t gid = 0,
                                         uint32_t crash_sig = 0)
{
    std::vector<char> data;
    uint32_t pid = 1234;
    uint32_t core_pid = 0;
    uint32_t threads = 1;
    struct timeval tv = {};
    struct timezone tz = {};
    char uname_buf[512] = {};
    append(data, &pid, sizeof(pid));
    append(data, &core_pid, sizeof(core_pid));
    append(data, &threads, sizeof(threads));
    append(data, &tv, sizeof(tv));
    append(data, &tz, sizeof(tz));
    append(data, uname_buf, sizeof(uname_buf));
    if (version >= 5) {
        append(data, &uid, sizeof(uid));
        append(data, &gid, sizeof(gid));
        append(data, &crash_sig, sizeof(crash_sig));
    }
    if (trailing) {
        data.push_back('X');
    }
    return data;
}

static std::vector<char> thread_payload(bool trailing, int signal = 0,
                                        char fp_valid = 1)
{
    ThreadData td;
    td._pid = 1234;
    td._fp_valid = fp_valid;
    td._siginfo.si_signo = signal;
    std::vector<char> data;
    append(data, &td._pid, sizeof(td._pid));
#ifdef __aarch64__
    append(data, &td._regs.arm64, sizeof(td._regs.arm64));
    append(data, &td._fpregs.arm64, sizeof(td._fpregs.arm64));
#else
    append(data, &td._regs.x64, sizeof(td._regs.x64));
    append(data, &td._fpregs.x64, sizeof(td._fpregs.x64));
#endif
    append(data, &td._siginfo, sizeof(td._siginfo));
#ifndef __aarch64__
    append(data, &td._xstate.x64, sizeof(td._xstate.x64));
#endif
    append(data, &td._fp_valid, sizeof(td._fp_valid));
    append(data, &td._sigpend, sizeof(td._sigpend));
    append(data, &td._sighold, sizeof(td._sighold));
    if (trailing) {
        data.push_back('X');
    }
    return data;
}

static void put_empty_file(Lz4Stream& out, ProcType type)
{
    ProcFile *pf = static_cast<ProcFile *>(calloc(1, sizeof(ProcFile)));
    assert(pf != NULL);
    pf->f_pid = 1234;
    pf->f_type = type;
    assert(out.PutFile(pf) == (int)sizeof(ProcFile));
    free(pf);
}

static void put_file(Lz4Stream& out, ProcType type, const void *data, size_t size)
{
    ProcFile *pf = static_cast<ProcFile *>(calloc(1, sizeof(ProcFile) + size));
    assert(pf != NULL);
    pf->f_size = (uint32_t)size;
    pf->f_pid = 1234;
    pf->f_type = type;
    memcpy(pf->f_data, data, size);
    assert(out.PutFile(pf) == (int)(sizeof(ProcFile) + size));
    free(pf);
}

static std::string stat_payload(unsigned long pending = 0,
                                unsigned long blocked = 0)
{
    std::string stat = "1234 (fixture) S";
    for (int field = 4; field <= 40; field++) {
        if (field == 20) {
            stat.append(" 1");
        } else if (field == 31) {
            stat.append(" " + std::to_string(pending));
        } else if (field == 32) {
            stat.append(" " + std::to_string(blocked));
        } else {
            stat.append(" 0");
        }
    }
    stat.push_back('\n');
    return stat;
}

static void write_stat_stream(const char *path)
{
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    assert(out.Open(path) == 0);
    AcoreHeader header;
    assert(out.WriteRaw(reinterpret_cast<const char *>(&header), sizeof(header)) ==
           (int)sizeof(header));
    out.EnableBlockChecksums();
    const char payload[] = "physical compression statistics";
    assert(out.WriteBlock(payload, sizeof(payload) - 1, BLOCK_TYPE_PROCESS) ==
           (int)sizeof(payload) - 1);
    BlockHeader tail = BlockHeader::TailMark();
    assert(out.WriteRaw(reinterpret_cast<const char *>(&tail), sizeof(tail)) ==
           (int)sizeof(tail));
    out.PrintStat();
    assert(out.Close() == 0);
}

static void finish(Lz4Stream& out)
{
    BlockHeader tail = BlockHeader::TailMark();
    assert(out.WriteRaw(reinterpret_cast<const char *>(&tail), sizeof(tail)) ==
           (int)sizeof(tail));
    assert(out.Close() == 0);
}

static void write_bad_test_stream(const char *path)
{
    static const char magic[] = {'A', 'R', 'T', 'H', 'Z', '4', '\0', '\4'};
    static const char payload[] = "wrong block type\n";
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    assert(out.Open(path) == 0);
    assert(out.WriteRaw(magic, sizeof(magic)) == (int)sizeof(magic));
    out.EnableBlockChecksums();
    assert(out.WriteBlock(payload, sizeof(payload) - 1, BLOCK_TYPE_PROCESS) ==
           (int)sizeof(payload) - 1);
    finish(out);
}

static void write_load_fixture(const char *path, bool excessive_loads,
                               bool wrong_vaddr, bool unaligned_file_offset = false,
                               uint16_t version = ACORE_VERSION,
                               uint32_t uid = 0, uint32_t gid = 0,
                               uint32_t aux_uid = 0, uint32_t aux_gid = 0,
                               uint32_t crash_sig = 0, int thread_sig = 0,
                               char fp_valid = 1,
                               unsigned long stat_pending = 0,
                               unsigned long stat_blocked = 0)
{
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    assert(out.Open(path) == 0);
    AcoreHeader header;
    header.m.version = version;
    assert(out.WriteRaw(reinterpret_cast<const char *>(&header), sizeof(header)) ==
           (int)sizeof(header));
    if (version >= 4) {
        out.EnableBlockChecksums();
    }

    std::vector<char> process =
        process_payload(false, version, uid, gid, crash_sig);
    assert(out.WriteBlock(process.data(), process.size(), BLOCK_TYPE_PROCESS) ==
           (int)process.size());

    const char cmdline[] = "fixture\0";
    put_file(out, PROC_TYPE_CMDLINE, cmdline, sizeof(cmdline) - 1);
    const uint64_t auxv[] = {
        AT_PAGESZ, 4096,
        AT_UID, aux_uid,
        AT_GID, aux_gid,
        AT_NULL, 0,
    };
    put_file(out, PROC_TYPE_AUXV, auxv, sizeof(auxv));
    const char *maps = unaligned_file_offset
        ? "1000-2000 r--p 00000001 08:01 1 /fixture\n"
        : "1000-2000 rw-p 00000000 00:00 0\n";
    put_file(out, PROC_TYPE_MAPS, maps, strlen(maps));
    put_empty_file(out, PROC_TYPE_ENVIRON);
    put_empty_file(out, PROC_TYPE_IO);
    put_empty_file(out, PROC_TYPE_LIMITS);
    if (version >= 6) {
        std::string process_stat = stat_payload();
        put_file(out, PROC_TYPE_STAT, process_stat.data(), process_stat.size());
    }

    std::vector<char> thread = thread_payload(false, thread_sig, fp_valid);
    assert(out.WriteBlock(thread.data(), thread.size(), BLOCK_TYPE_THREAD) ==
           (int)thread.size());
    std::string stat = stat_payload(stat_pending, stat_blocked);
    put_file(out, PROC_TYPE_STAT, stat.data(), stat.size());

    std::vector<char> loads(excessive_loads ? 8192 : 4096, 0);
    assert(out.WriteBlock(loads.data(), loads.size(), BLOCK_TYPE_LOADS) ==
           (int)loads.size());

    if (!excessive_loads) {
        Elf64_Ehdr ehdr;
        ehdr.e_phnum = 1;
        Elf64_Phdr phdr = {};
        phdr.p_type = PT_LOAD;
        phdr.p_flags = PF_R | PF_W;
        phdr.p_offset = 0;
        phdr.p_vaddr = wrong_vaddr ? 0x2000 : 0x1000;
        phdr.p_filesz = 4096;
        phdr.p_memsz = 4096;
        phdr.p_align = 1;
        std::vector<char> elf;
        append(elf, &ehdr, sizeof(ehdr));
        append(elf, &phdr, sizeof(phdr));
        assert(out.WriteBlock(elf.data(), elf.size(), BLOCK_TYPE_ELF) ==
               (int)elf.size());
    }
    finish(out);
}

static void write_bad_process(const char *path, uint16_t version,
                              bool trailing, bool continuation)
{
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    assert(out.Open(path) == 0);
    AcoreHeader header;
    header.m.version = version;
    assert(out.WriteRaw(reinterpret_cast<const char *>(&header), sizeof(header)) ==
           (int)sizeof(header));
    if (version >= 4) {
        out.EnableBlockChecksums();
    }
    std::vector<char> process = process_payload(trailing, version);
    assert(out.WriteBlock(process.data(), process.size(), BLOCK_TYPE_PROCESS) ==
           (int)process.size());
    finish(out);

    if (continuation) {
        FILE *file = fopen(path, "r+b");
        assert(file != NULL);
        assert(fseek(file, sizeof(AcoreHeader), SEEK_SET) == 0);
        int first = fgetc(file);
        assert(first != EOF);
        assert(fseek(file, sizeof(AcoreHeader), SEEK_SET) == 0);
        assert(fputc(first | 1, file) != EOF);
        assert(fclose(file) == 0);
    }
}

static void write_bad_thread(const char *path)
{
    Lz4Stream out(Lz4Stream::LZ4_Compress);
    assert(out.Open(path) == 0);
    AcoreHeader header;
    assert(out.WriteRaw(reinterpret_cast<const char *>(&header), sizeof(header)) ==
           (int)sizeof(header));
    out.EnableBlockChecksums();
    std::vector<char> process = process_payload(false);
    assert(out.WriteBlock(process.data(), process.size(), BLOCK_TYPE_PROCESS) ==
           (int)process.size());
    put_empty_file(out, PROC_TYPE_CMDLINE);
    put_empty_file(out, PROC_TYPE_AUXV);
    put_empty_file(out, PROC_TYPE_MAPS);
    put_empty_file(out, PROC_TYPE_ENVIRON);
    put_empty_file(out, PROC_TYPE_IO);
    put_empty_file(out, PROC_TYPE_LIMITS);
    std::string process_stat = stat_payload();
    put_file(out, PROC_TYPE_STAT, process_stat.data(), process_stat.size());
    std::vector<char> thread = thread_payload(true);
    assert(out.WriteBlock(thread.data(), thread.size(), BLOCK_TYPE_THREAD) ==
           (int)thread.size());
    finish(out);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--empty-stat") == 0) {
        Lz4Stream out(Lz4Stream::LZ4_Compress);
        out.PrintStat();
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--stat") == 0) {
        write_stat_stream(argv[2]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--bad-stream") == 0) {
        write_bad_test_stream(argv[2]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--load-budget") == 0) {
        write_load_fixture(argv[2], true, false);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--wrong-phdr") == 0) {
        write_load_fixture(argv[2], false, true);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--unaligned-file-offset") == 0) {
        write_load_fixture(argv[2], false, false, true);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--valid-load") == 0) {
        write_load_fixture(argv[2], false, false);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--credentials-v5") == 0) {
        write_load_fixture(argv[2], false, false, false, 5,
                           123, 234, 1001, 1002);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--legacy-v4") == 0) {
        write_load_fixture(argv[2], false, false, false, 4,
                           0, 0, 1001, 1002);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--zero-signal-masks") == 0) {
        write_load_fixture(argv[2], false, false, false, ACORE_VERSION,
                           0, 0, 0, 0, 0, 0, 1, 0x40, 0x80);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--invalid-fp") == 0) {
        write_load_fixture(argv[2], false, false, false, ACORE_VERSION,
                           0, 0, 0, 0, 0, 0, 0);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--crash-signal-mismatch") == 0) {
        write_load_fixture(argv[2], false, false, false, ACORE_VERSION,
                           0, 0, 0, 0, SIGSEGV, SIGABRT);
        return 0;
    }
    assert(argc == 4);
    write_bad_process(argv[1], ACORE_VERSION, true, false);
    write_bad_thread(argv[2]);
    write_bad_process(argv[3], 3, false, true);
    return 0;
}
