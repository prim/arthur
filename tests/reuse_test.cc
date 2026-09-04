#include <stdint.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <string>

#include "core.h"

using namespace arthur;

static void write_stream(Lz4Stream& out, const char *path, bool with_tail)
{
    static const char payload[] = "stream state reuse";
    assert(out.Open(path) == 0);
    assert(out.WriteBlock(payload, sizeof(payload), BLOCK_TYPE_PROCESS) ==
           (int)sizeof(payload));
    if (with_tail) {
        BlockHeader tail = BlockHeader::TailMark();
        assert(out.WriteRaw(reinterpret_cast<const char *>(&tail), sizeof(tail)) ==
               (int)sizeof(tail));
    }
    assert(out.Close() == 0);
}

static void copy_with_trailing_byte(const char *source, const char *destination)
{
    FILE *in = fopen(source, "rb");
    FILE *out = fopen(destination, "wb");
    assert(in != NULL && out != NULL);
    char buffer[4096];
    for (;;) {
        size_t size = fread(buffer, 1, sizeof(buffer), in);
        if (size != 0) {
            assert(fwrite(buffer, 1, size, out) == size);
        }
        if (size != sizeof(buffer)) {
            assert(feof(in) && !ferror(in));
            break;
        }
    }
    assert(fwrite("X", 1, 1, out) == 1);
    assert(fclose(in) == 0);
    assert(fclose(out) == 0);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        return 2;
    }

    sigset_t before, after;
    assert(sigprocmask(SIG_SETMASK, NULL, &before) == 0);
    std::string monitor_output = std::string(argv[2]) + ".monitor-mask";
    Coredump missing_target(2147483647);
    assert(missing_target.monitor(monitor_output.c_str()) != 0);
    assert(sigprocmask(SIG_SETMASK, NULL, &after) == 0);
    for (int sig = 1; sig < NSIG; sig++) {
        assert(sigismember(&before, sig) == sigismember(&after, sig));
    }

    std::string complete_stream = std::string(argv[2]) + ".complete.z4";
    std::string truncated_stream = std::string(argv[2]) + ".truncated.z4";
    std::string trailing_stream = std::string(argv[2]) + ".trailing.z4";
    Lz4Stream writer(Lz4Stream::LZ4_Compress);
    BlockHeader unopened_hdr;
    assert(writer.SetBlock(BLOCK_TYPE_PROCESS) == -1 && errno == EBADF);
    assert(writer.EnableBlockChecksums() == -1 && errno == EBADF);
    assert(writer.WriteRaw("x", 1) == -1 && errno == EBADF);
    assert(writer.Write("x", 1) == -1 && errno == EBADF);
    assert(writer.WriteBlock("x", 1, BLOCK_TYPE_PROCESS) == -1 && errno == EBADF);
    assert(writer.Flush() == -1 && errno == EBADF);
    assert(writer.Sync() == -1 && errno == EBADF);
    assert(writer.PutFile(NULL) == -1 && errno == EINVAL);

    std::string access_mode_path = std::string(argv[2]) + ".access-mode";
    int access_seed = open(access_mode_path.c_str(),
                           O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(access_seed >= 0);
    assert(write(access_seed, "x", 1) == 1);
    assert(close(access_seed) == 0);
    int read_only_fd = open(access_mode_path.c_str(), O_RDONLY);
    assert(read_only_fd >= 0);
    assert(writer.OpenFd(read_only_fd) == -1 && errno == EBADF);
    assert(fcntl(read_only_fd, F_GETFD) != -1);
    assert(close(read_only_fd) == 0);

    Lz4Stream wrong_direction_reader(Lz4Stream::LZ4_Decompress);
    int write_only_fd = open(access_mode_path.c_str(), O_WRONLY);
    assert(write_only_fd >= 0);
    assert(wrong_direction_reader.OpenFd(write_only_fd) == -1 && errno == EBADF);
    assert(fcntl(write_only_fd, F_GETFD) != -1);
    assert(close(write_only_fd) == 0);

    Block direct_block;
    assert(direct_block.Write(NULL, 0) == 0 && direct_block.Size() == 0);
    assert(direct_block.Read(NULL, 0) == 0 && direct_block.Size() == 0);
    assert(direct_block.Peek(NULL, 0) == 0 && direct_block.Size() == 0);
    assert(direct_block.Write(NULL, 1) == -EINVAL && errno == EINVAL);
    assert(direct_block.Write("x", 1) == 1);
    assert(direct_block.Peek(NULL, 1) == -EINVAL && direct_block.Size() == 1);
    assert(direct_block.Read(NULL, 1) == -EINVAL && direct_block.Size() == 1);

    assert(writer.Open(complete_stream.c_str()) == 0);
    assert(writer.WriteRaw(NULL, 0) == 0);
    std::string rejected_fd_path = std::string(argv[2]) + ".rejected-fd";
    int rejected_fd = open(rejected_fd_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(rejected_fd >= 0);
    assert(writer.OpenFd(rejected_fd) == -1 && errno == EBUSY);
    assert(fcntl(rejected_fd, F_GETFD) != -1);
    assert(close(rejected_fd) == 0);
    assert(writer.ReadRaw(NULL, 0) == -1 && errno == EBADF);
    assert(writer.Peek(NULL, 0) == -1 && errno == EBADF);
    assert(writer.ReadBlock(unopened_hdr) == NULL && errno == EBADF);
    assert(writer.Write(NULL, 1) == -1 && errno == EINVAL);
    assert(writer.WriteBlock(NULL, 1, BLOCK_TYPE_PROCESS) == -1 && errno == EINVAL);
    assert(writer.WriteBlock("x", 1, BLOCK_TYPE_MAX) == -1 && errno == EINVAL);
    assert(writer.Write("x", 1) == 1);
    assert(writer.Close() == 0);

    // Oversized ProcFile metadata must be rejected before the pending PROCESS
    // byte is flushed or any raw size prefix is inserted into the stream.
    std::string proc_size_stream = std::string(argv[2]) + ".proc-size.z4";
    assert(writer.Open(proc_size_stream.c_str()) == 0);
    assert(writer.SetBlock(BLOCK_TYPE_PROCESS) == 0);
    assert(writer.Write("F", 1) == 1);
    long proc_size_pos = writer.Tell();
    assert(proc_size_pos >= 0);
    ProcFile oversized_proc = {};
    oversized_proc.f_size = UINT32_MAX;
    assert(writer.PutFile(&oversized_proc) == -1 && errno == EOVERFLOW);
    assert(writer.Tell() == proc_size_pos);
    oversized_proc.f_size = 64U * 1024U * 1024U;
    assert(writer.PutFile(&oversized_proc) == -1 && errno == EFBIG);
    assert(writer.Tell() == proc_size_pos);
    assert(writer.SetBlock(BLOCK_TYPE_THREAD) == 0);
    assert(writer.Write("T", 1) == 1);
    assert(writer.Flush() == 0);
    BlockHeader proc_size_tail = BlockHeader::TailMark();
    assert(writer.WriteRaw(reinterpret_cast<const char *>(&proc_size_tail),
                           sizeof(proc_size_tail)) == (int)sizeof(proc_size_tail));
    assert(writer.Close() == 0);

    // Changing the logical block type must preserve the pending bytes under
    // their original type. Otherwise PROCESS data is silently relabelled as
    // THREAD data when the shared compression buffer is finally flushed.
    std::string type_boundary_stream =
        std::string(argv[2]) + ".type-boundary.z4";
    assert(writer.Open(type_boundary_stream.c_str()) == 0);
    assert(writer.SetBlock(BLOCK_TYPE_PROCESS) == 0);
    assert(writer.Write("P", 1) == 1);
    assert(writer.SetBlock(BLOCK_TYPE_THREAD) == 0);
    assert(writer.Write("T", 1) == 1);
    assert(writer.Flush() == 0);
    BlockHeader boundary_tail = BlockHeader::TailMark();
    assert(writer.WriteRaw(reinterpret_cast<const char *>(&boundary_tail),
                           sizeof(boundary_tail)) == (int)sizeof(boundary_tail));
    assert(writer.Close() == 0);

    write_stream(writer, complete_stream.c_str(), true);
    write_stream(writer, truncated_stream.c_str(), false);
    write_stream(writer, trailing_stream.c_str(), true);
    int trailing_fd = open(trailing_stream.c_str(), O_WRONLY | O_APPEND);
    assert(trailing_fd >= 0);
    assert(write(trailing_fd, "X", 1) == 1);
    assert(close(trailing_fd) == 0);

    Lz4Stream reader(Lz4Stream::LZ4_Decompress);
    assert(reader.ReadBlock(unopened_hdr) == NULL);
    assert(!reader.LastReadClean() && errno == EBADF);
    assert(reader.GetFile() == NULL && errno == EBADF);
    BlockHeader hdr;
    Block *typed_block = NULL;
    char typed_byte = 0;
    assert(reader.Open(complete_stream.c_str()) == 0);
    assert(reader.ReadRaw(NULL, 0) == 0);
    assert(reader.Peek(NULL, 0) == 0);
    assert(reader.WriteRaw(NULL, 0) == -1 && errno == EBADF);
    assert(reader.Write(NULL, 0) == -1 && errno == EBADF);
    assert(reader.Flush() == -1 && errno == EBADF);
    assert(reader.Sync() == -1 && errno == EBADF);
    assert(reader.ReadBlock(hdr) != NULL);
    assert(reader.ReadBlock(hdr) == NULL && reader.TailSeen());
    assert(reader.Close() == 0);

    // Once physical EOF validation has observed trailing data, retrying the
    // same validation must remain a failure. Consuming the one bad byte and
    // returning success on the second call would make stream validity depend
    // on how many times a caller asks.
    assert(reader.Open(trailing_stream.c_str()) == 0);
    assert(reader.ReadBlock(hdr) != NULL);
    assert(reader.ReadBlock(hdr) == NULL && reader.TailSeen());
    assert(reader.VerifyPhysicalEof() == -1);
    assert(reader.VerifyPhysicalEof() == -1);
    assert(reader.Close() == 0);

    assert(reader.Open(proc_size_stream.c_str()) == 0);
    typed_block = reader.ReadBlock(hdr);
    assert(typed_block != NULL && hdr.block_type == BLOCK_TYPE_PROCESS);
    assert(typed_block->Read(&typed_byte, 1) == 1 && typed_byte == 'F');
    typed_block = reader.ReadBlock(hdr);
    assert(typed_block != NULL && hdr.block_type == BLOCK_TYPE_THREAD);
    assert(typed_block->Read(&typed_byte, 1) == 1 && typed_byte == 'T');
    assert(reader.ReadBlock(hdr) == NULL && reader.TailSeen());
    assert(reader.Close() == 0);

    // Raw protocol bytes must follow pending compressed bytes, not overtake
    // them and leave Close() to append the block after the tail marker.
    std::string raw_boundary_stream =
        std::string(argv[2]) + ".raw-boundary.z4";
    assert(writer.Open(raw_boundary_stream.c_str()) == 0);
    assert(writer.SetBlock(BLOCK_TYPE_STREAM) == 0);
    assert(writer.Write("R", 1) == 1);
    assert(writer.WriteRaw(reinterpret_cast<const char *>(&boundary_tail),
                           sizeof(boundary_tail)) == (int)sizeof(boundary_tail));
    assert(writer.Close() == 0);
    assert(reader.Open(raw_boundary_stream.c_str()) == 0);
    typed_block = reader.ReadBlock(hdr);
    assert(typed_block != NULL && hdr.block_type == BLOCK_TYPE_STREAM);
    assert(typed_block->Read(&typed_byte, 1) == 1 && typed_byte == 'R');
    assert(reader.ReadBlock(hdr) == NULL && reader.TailSeen());
    assert(reader.Close() == 0);

    // A checksummed stream cannot switch layout between blocks. Rejection must
    // leave the original setting active so subsequent blocks remain readable.
    std::string checksum_boundary_stream =
        std::string(argv[2]) + ".checksum-boundary.z4";
    assert(writer.Open(checksum_boundary_stream.c_str()) == 0);
    assert(writer.EnableBlockChecksums() == 0);
    assert(writer.WriteBlock("1", 1, BLOCK_TYPE_STREAM) == 1);
    assert(writer.EnableBlockChecksums(false) == -1 && errno == EBUSY);
    assert(writer.WriteBlock("2", 1, BLOCK_TYPE_STREAM) == 1);
    assert(writer.WriteRaw(reinterpret_cast<const char *>(&boundary_tail),
                           sizeof(boundary_tail)) == (int)sizeof(boundary_tail));
    assert(writer.Close() == 0);
    assert(reader.Open(checksum_boundary_stream.c_str()) == 0);
    assert(reader.EnableBlockChecksums() == 0);
    typed_block = reader.ReadBlock(hdr);
    assert(typed_block != NULL && hdr.block_type == BLOCK_TYPE_STREAM);
    assert(reader.EnableBlockChecksums(false) == -1 && errno == EBUSY);
    assert(typed_block->Read(&typed_byte, 1) == 1 && typed_byte == '1');
    typed_block = reader.ReadBlock(hdr);
    assert(typed_block != NULL && hdr.block_type == BLOCK_TYPE_STREAM);
    assert(typed_block->Read(&typed_byte, 1) == 1 && typed_byte == '2');
    assert(reader.ReadBlock(hdr) == NULL && reader.TailSeen());
    assert(reader.Close() == 0);

    assert(reader.Open(type_boundary_stream.c_str()) == 0);
    typed_block = reader.ReadBlock(hdr);
    assert(typed_block != NULL && hdr.block_type == BLOCK_TYPE_PROCESS);
    assert(typed_block->Read(&typed_byte, 1) == 1 && typed_byte == 'P');
    typed_block = reader.ReadBlock(hdr);
    assert(typed_block != NULL && hdr.block_type == BLOCK_TYPE_THREAD);
    assert(typed_block->Read(&typed_byte, 1) == 1 && typed_byte == 'T');
    assert(reader.ReadBlock(hdr) == NULL && reader.TailSeen());
    assert(reader.Close() == 0);

    assert(reader.Open(truncated_stream.c_str()) == 0);
    assert(!reader.TailSeen());
    assert(reader.ReadRaw(NULL, (size_t)INT32_MAX + 1) == -1);
    assert(reader.ReadBlock(hdr) != NULL);
    assert(reader.ReadBlock(hdr) == NULL && !reader.TailSeen());
    assert(reader.Close() == 0);

    Note oversized(NT_AUXV);
    if (oversized.allocate(SIZE_MAX) != NULL) {
        fprintf(stderr, "oversized note allocation unexpectedly succeeded\n");
        return 1;
    }

    std::string corrupt_acore = std::string(argv[2]) + ".corrupt.acore";
    std::string rejected_core = std::string(argv[2]) + ".rejected.core";
    copy_with_trailing_byte(argv[1], corrupt_acore.c_str());

    Coredump dump(0);
    if (dump.decompress(argv[1], argv[2]) != 0 ||
        dump.decompress(corrupt_acore.c_str(), rejected_core.c_str()) == 0 ||
        access(rejected_core.c_str(), F_OK) == 0 ||
        dump.decompress(argv[1], argv[3]) != 0) {
        fprintf(stderr, "reusing one Coredump instance failed\n");
        return 1;
    }
    return 0;
}
