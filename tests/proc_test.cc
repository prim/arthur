#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "proc.h"

using namespace arthur;

static ProcFile *make_proc_file(const void *data, size_t size)
{
    ProcFile *pf = (ProcFile *)calloc(1, sizeof(ProcFile) + size + 1);
    assert(pf != NULL);
    pf->f_size = (uint32_t)size;
    memcpy(pf->f_data, data, size);
    return pf;
}

int main()
{
    char tiny[1];
    bool truncated = true;
    assert(ProcFile::ReadPid(tiny, sizeof(tiny), getpid(), PROC_TYPE_STAT,
                             &truncated) == NULL);
    assert(errno == EINVAL);

    // A proc file that exactly fills the payload area is complete, not
    // truncated. Read the live cmdline once to obtain an ordinary procfs
    // length, then repeat with an exactly sized destination buffer.
    std::vector<char> roomy_proc_buf(4096);
    truncated = true;
    ProcFile *live_cmdline = ProcFile::ReadPid(
        roomy_proc_buf.data(), roomy_proc_buf.size(), getpid(),
        PROC_TYPE_CMDLINE, &truncated);
    assert(live_cmdline != NULL);
    assert(!truncated);
    assert(live_cmdline->f_size > 0);
    const size_t exact_buf_size = live_cmdline->Size() + 1;

    std::vector<char> exact_proc_buf(exact_buf_size);
    truncated = true;
    live_cmdline = ProcFile::ReadPid(
        exact_proc_buf.data(), exact_proc_buf.size(), getpid(),
        PROC_TYPE_CMDLINE, &truncated);
    assert(live_cmdline != NULL);
    assert(!truncated);
    assert(live_cmdline->Size() + 1 == exact_buf_size);

    std::vector<char> short_proc_buf(exact_buf_size - 1);
    truncated = false;
    live_cmdline = ProcFile::ReadPid(
        short_proc_buf.data(), short_proc_buf.size(), getpid(),
        PROC_TYPE_CMDLINE, &truncated);
    assert(live_cmdline != NULL);
    assert(truncated);
    assert(live_cmdline->f_size + 1 ==
           ((ProcFile *)exact_proc_buf.data())->f_size);

    // Linux task names may contain a newline. In /proc/<tid>/stat it remains
    // inside the parenthesized comm field and must not be mistaken for a
    // second stat record.
    assert(prctl(PR_SET_NAME, "line1\nline2", 0, 0, 0) == 0);
    char named_stat_buf[4096];
    ProcFile *named_stat_file = ProcFile::ReadPid(
        named_stat_buf, sizeof(named_stat_buf), getpid(), PROC_TYPE_STAT);
    assert(named_stat_file != NULL);
    ProcStat named_stat(named_stat_file);
    assert(named_stat.Parse() == 0);
    assert(strcmp(named_stat.comm, "line1\nline2") == 0);
    assert(prctl(PR_SET_NAME, "proc_test", 0, 0, 0) == 0);

    ProcMaps empty_maps;
    assert(empty_maps.Parse() == 0);

    std::string path = "/" + std::string(5000, 'x');
    std::string line = "1000-2000 r-xp 00010000 08:01 123 " + path + "\n";
    ProcFile *maps_file = make_proc_file(line.data(), line.size());
    ProcMaps maps(maps_file);
    assert(maps.Parse() == 1);
    assert(maps[0].start_addr == 0x1000);
    assert(maps[0].offset == 0x10000);
    assert(maps[0].name == path);
    free(maps_file);

    std::string partial_maps =
        "1000-2000 r-xp 00000000 08:01 1 /valid\n"
        "this is not a maps record\n";
    maps_file = make_proc_file(partial_maps.data(), partial_maps.size());
    ProcMaps partial(maps_file);
    assert(partial.Parse() < 0);
    free(maps_file);

    std::string nul_maps = "1000-2000 r-xp 00000000 08:01 1 /valid";
    nul_maps.push_back('\0');
    nul_maps.append("/hidden\n");
    maps_file = make_proc_file(nul_maps.data(), nul_maps.size());
    ProcMaps embedded_nul(maps_file);
    assert(embedded_nul.Parse() < 0);
    free(maps_file);

    std::string overlapping_maps =
        "1000-3000 r-xp 00000000 08:01 1 /first\n"
        "2000-4000 rw-p 00000000 08:01 2 /second\n";
    maps_file = make_proc_file(overlapping_maps.data(), overlapping_maps.size());
    ProcMaps overlapping(maps_file);
    assert(overlapping.Parse() < 0);
    free(maps_file);

    std::string excessive_cmdline(16385, '\0');
    ProcFile *cmdline_file = make_proc_file(excessive_cmdline.data(),
                                             excessive_cmdline.size());
    ProcCmdline excessive(cmdline_file);
    assert(excessive.Parse() < 0);
    free(cmdline_file);

    const uint64_t auxv[] = {
        AT_PAGESZ, 65536,
        AT_UID, 1000,
        AT_NULL, 0,
    };
    ProcFile *auxv_file = make_proc_file(auxv, sizeof(auxv));
    ProcAuxv decoded(auxv_file);
    assert(decoded.Parse() == 0);
    assert(decoded.page_size == 65536);
    assert(decoded.uid == 1000);
    free(auxv_file);

    const uint64_t unterminated_auxv[] = {
        AT_PAGESZ, 4096,
        AT_UID, 1000,
    };
    auxv_file = make_proc_file(unterminated_auxv, sizeof(unterminated_auxv));
    ProcAuxv unterminated(auxv_file);
    assert(unterminated.Parse() != 0);
    free(auxv_file);

    const uint64_t trailing_auxv[] = {
        AT_NULL, 0,
        AT_UID, 1000,
    };
    auxv_file = make_proc_file(trailing_auxv, sizeof(trailing_auxv));
    ProcAuxv trailing(auxv_file);
    assert(trailing.Parse() != 0);
    free(auxv_file);

    const uint64_t oversized_uid_auxv[] = {
        AT_UID, UINT64_MAX,
        AT_NULL, 0,
    };
    auxv_file = make_proc_file(oversized_uid_auxv, sizeof(oversized_uid_auxv));
    ProcAuxv oversized_uid(auxv_file);
    assert(oversized_uid.Parse() != 0);
    free(auxv_file);

    const uint64_t invalid_page_auxv[] = {
        AT_PAGESZ, 6144,
        AT_NULL, 0,
    };
    auxv_file = make_proc_file(invalid_page_auxv, sizeof(invalid_page_auxv));
    ProcAuxv invalid_page(auxv_file);
    assert(invalid_page.Parse() != 0);
    free(auxv_file);

    const char valid_status[] =
        "Name:\tfixture\n"
        "Uid:\t123\t456\t789\t1000\n"
        "Gid:\t234\t567\t890\t1001\n";
    ProcFile *status_file = make_proc_file(valid_status,
                                            sizeof(valid_status) - 1);
    ProcStatus valid_credentials(status_file);
    assert(valid_credentials.Parse() == 0);
    assert(valid_credentials.uid == 123);
    assert(valid_credentials.gid == 234);
    free(status_file);

    const char missing_gid_status[] = "Uid:\t1\t2\t3\t4\n";
    status_file = make_proc_file(missing_gid_status,
                                 sizeof(missing_gid_status) - 1);
    ProcStatus missing_gid(status_file);
    assert(missing_gid.Parse() != 0);
    free(status_file);

    const char oversized_status[] =
        "Uid:\t4294967296\t2\t3\t4\n"
        "Gid:\t1\t2\t3\t4\n";
    status_file = make_proc_file(oversized_status,
                                 sizeof(oversized_status) - 1);
    ProcStatus oversized_credentials(status_file);
    assert(oversized_credentials.Parse() != 0);
    free(status_file);

    const char malformed_columns_status[] =
        "Uid:\t1\t2\t3\n"
        "Gid:\t1\t2\t3\t4\n";
    status_file = make_proc_file(malformed_columns_status,
                                 sizeof(malformed_columns_status) - 1);
    ProcStatus malformed_columns(status_file);
    assert(malformed_columns.Parse() != 0);
    free(status_file);

    char stat_buf[4096];
    ProcFile *stat_file = ProcFile::ReadPid(stat_buf, sizeof(stat_buf), getpid(),
                                            PROC_TYPE_STAT);
    assert(stat_file != NULL);
    ProcStat valid_stat(stat_file);
    assert(valid_stat.Parse() == 0);
    assert(valid_stat.pid == getpid());

    std::string invalid_numeric(stat_file->f_data, stat_file->f_size);
    invalid_numeric.replace(0, invalid_numeric.find(' '), "12junk");
    ProcFile *numeric_file = make_proc_file(invalid_numeric.data(),
                                             invalid_numeric.size());
    ProcStat numeric_stat(numeric_file);
    assert(numeric_stat.Parse() != 0);
    free(numeric_file);

    std::string prefixed_pid(stat_file->f_data, stat_file->f_size);
    prefixed_pid.insert(prefixed_pid.find(' '), " ignored");
    ProcFile *prefixed_pid_file = make_proc_file(prefixed_pid.data(),
                                                  prefixed_pid.size());
    ProcStat prefixed_pid_stat(prefixed_pid_file);
    assert(prefixed_pid_stat.Parse() != 0);
    free(prefixed_pid_file);

    std::string long_state(stat_file->f_data, stat_file->f_size);
    size_t stat_close = long_state.rfind(')');
    assert(stat_close != std::string::npos && stat_close + 2 < long_state.size());
    long_state.insert(stat_close + 3, "junk");
    ProcFile *long_state_file = make_proc_file(long_state.data(),
                                                long_state.size());
    ProcStat long_state_stat(long_state_file);
    assert(long_state_stat.Parse() != 0);
    free(long_state_file);

    std::string nul_stat(stat_file->f_data, stat_file->f_size);
    nul_stat.insert(nul_stat.size() / 2, 1, '\0');
    ProcFile *nul_stat_file = make_proc_file(nul_stat.data(), nul_stat.size());
    ProcStat embedded_nul_stat(nul_stat_file);
    assert(embedded_nul_stat.Parse() != 0);
    free(nul_stat_file);

    std::string multiline_stat(stat_file->f_data, stat_file->f_size);
    multiline_stat.append("hidden second record\n");
    ProcFile *multiline_file = make_proc_file(multiline_stat.data(),
                                               multiline_stat.size());
    ProcStat multiline(multiline_file);
    assert(multiline.Parse() != 0);
    free(multiline_file);

    std::string invalid_nice = "1234 (fixture) S";
    for (int field = 4; field <= 40; field++) {
        if (field == 19) {
            invalid_nice.append(" 20");
        } else if (field == 20) {
            invalid_nice.append(" 1");
        } else {
            invalid_nice.append(" 0");
        }
    }
    invalid_nice.push_back('\n');
    ProcFile *nice_file = make_proc_file(invalid_nice.data(), invalid_nice.size());
    ProcStat out_of_range_nice(nice_file);
    assert(out_of_range_nice.Parse() != 0);
    free(nice_file);

    const char invalid_stat[] = "not a proc stat record\n";
    stat_file = make_proc_file(invalid_stat, sizeof(invalid_stat) - 1);
    ProcStat malformed_stat(stat_file);
    assert(malformed_stat.Parse() != 0);
    free(stat_file);
    return 0;
}
