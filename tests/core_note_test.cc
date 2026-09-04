#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#include "elf.h"

static uint64_t parse_u64(const char *text)
{
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 0);
    assert(end != text && *end == '\0' && errno != ERANGE);
    return (uint64_t)value;
}

static size_t align4(size_t value)
{
    assert(value <= SIZE_MAX - 3);
    return (value + 3) & ~(size_t)3;
}

int main(int argc, char **argv)
{
    assert(argc == 7 || argc == 9 || argc == 11 || argc == 13);
    const uint32_t expected_uid = (uint32_t)parse_u64(argv[2]);
    const uint32_t expected_gid = (uint32_t)parse_u64(argv[3]);
    const uint64_t required_flags = parse_u64(argv[4]);
    const uint64_t forbidden_flags = parse_u64(argv[5]);
    const size_t expected_siginfo = (size_t)parse_u64(argv[6]);
    const bool check_thread_state = argc == 11 || argc == 13;
    const bool check_signals = argc == 9 || argc == 13;
    const uint64_t expected_sigpend = check_thread_state ? parse_u64(argv[7]) : 0;
    const uint64_t expected_sighold = check_thread_state ? parse_u64(argv[8]) : 0;
    const size_t expected_fpregset =
        check_thread_state ? (size_t)parse_u64(argv[9]) : 0;
    const size_t expected_xstate =
        check_thread_state ? (size_t)parse_u64(argv[10]) : 0;
    const int signal_arg = check_thread_state ? 11 : 7;
    const int expected_prstatus_signal =
        check_signals ? (int)parse_u64(argv[signal_arg]) : 0;
    const int expected_siginfo_signal =
        check_signals ? (int)parse_u64(argv[signal_arg + 1]) : 0;

    FILE *file = fopen(argv[1], "rb");
    assert(file != NULL);
    assert(fseek(file, 0, SEEK_END) == 0);
    long length = ftell(file);
    assert(length >= (long)sizeof(Elf64_Ehdr));
    assert(fseek(file, 0, SEEK_SET) == 0);
    std::vector<unsigned char> data((size_t)length);
    assert(fread(data.data(), 1, data.size(), file) == data.size());
    assert(fclose(file) == 0);

    Elf64_Ehdr ehdr;
    memcpy(&ehdr, data.data(), sizeof(ehdr));
    assert(ehdr.e_phentsize == sizeof(Elf64_Phdr));
    assert(ehdr.e_phnum > 0);
    assert(ehdr.e_phoff <= data.size());
    assert((size_t)ehdr.e_phnum <=
           (data.size() - (size_t)ehdr.e_phoff) / sizeof(Elf64_Phdr));

    size_t prpsinfo_count = 0;
    size_t siginfo_count = 0;
    size_t prstatus_count = 0;
    size_t fpregset_count = 0;
    size_t xstate_count = 0;
    uint64_t first_sigpend = 0;
    uint64_t first_sighold = 0;
    int first_prstatus_signal = 0;
    int first_prstatus_info_signal = 0;
    int first_siginfo_signal = 0;
    elf_prpsinfo64 prpsinfo = {};
    for (size_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        memcpy(&phdr, data.data() + (size_t)ehdr.e_phoff +
                      i * sizeof(phdr), sizeof(phdr));
        if (phdr.p_type != PT_NOTE) {
            continue;
        }
        assert(phdr.p_offset <= data.size());
        assert(phdr.p_filesz <= data.size() - (size_t)phdr.p_offset);
        size_t pos = (size_t)phdr.p_offset;
        const size_t end = pos + (size_t)phdr.p_filesz;
        while (pos < end) {
            assert(end - pos >= sizeof(Elf64_Nhdr));
            Elf64_Nhdr nhdr;
            memcpy(&nhdr, data.data() + pos, sizeof(nhdr));
            pos += sizeof(nhdr);
            const size_t name_size = align4(nhdr.n_namesz);
            const size_t desc_size = align4(nhdr.n_descsz);
            assert(name_size <= end - pos);
            pos += name_size;
            assert(desc_size <= end - pos);
            const unsigned char *desc = data.data() + pos;
            if (nhdr.n_type == NT_PRPSINFO) {
                assert(nhdr.n_descsz == sizeof(prpsinfo));
                memcpy(&prpsinfo, desc, sizeof(prpsinfo));
                prpsinfo_count++;
            } else if (nhdr.n_type == NT_SIGINFO) {
                if (siginfo_count == 0) {
                    assert(nhdr.n_descsz == sizeof(siginfo_t));
                    siginfo_t info = {};
                    memcpy(&info, desc, sizeof(info));
                    first_siginfo_signal = info.si_signo;
                }
                siginfo_count++;
            } else if (nhdr.n_type == NT_PRSTATUS) {
                if (prstatus_count == 0) {
#ifdef __aarch64__
                    assert(nhdr.n_descsz == sizeof(arm64_elf_prstatus));
                    arm64_elf_prstatus status = {};
#else
                    assert(nhdr.n_descsz == sizeof(x64_elf_prstatus));
                    x64_elf_prstatus status = {};
#endif
                    memcpy(&status, desc, sizeof(status));
                    first_sigpend = status.pr_sigpend;
                    first_sighold = status.pr_sighold;
                    first_prstatus_signal = status.pr_cursig;
                    first_prstatus_info_signal = status.pr_info.si_signo;
                }
                prstatus_count++;
            } else if (nhdr.n_type == NT_FPREGSET) {
                fpregset_count++;
            } else if (nhdr.n_type == NT_X86_XSTATE) {
                xstate_count++;
            }
            pos += desc_size;
        }
        assert(pos == end);
    }

    assert(prpsinfo_count == 1);
    assert(prstatus_count > 0);
    assert(prpsinfo.pr_uid == expected_uid);
    assert(prpsinfo.pr_gid == expected_gid);
    assert((prpsinfo.pr_flag & required_flags) == required_flags);
    assert((prpsinfo.pr_flag & forbidden_flags) == 0);
    assert(siginfo_count == expected_siginfo);
    if (check_thread_state) {
        assert(first_sigpend == expected_sigpend);
        assert(first_sighold == expected_sighold);
        assert(fpregset_count == expected_fpregset);
        assert(xstate_count == expected_xstate);
    }
    if (check_signals) {
        assert(first_prstatus_signal == expected_prstatus_signal);
        assert(first_prstatus_info_signal == expected_prstatus_signal);
        assert(first_siginfo_signal == expected_siginfo_signal);
    }
    printf("uid=%u gid=%u flags=0x%llx siginfo=%zu prstatus=%zu\n",
           prpsinfo.pr_uid, prpsinfo.pr_gid,
           (unsigned long long)prpsinfo.pr_flag,
           siginfo_count, prstatus_count);
    return 0;
}
