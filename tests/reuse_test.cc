#include <stdint.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#include <string>
#include <random>
#include <vector>

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

static uint32_t fragment_crc(uint32_t crc, const void *data, size_t size)
{
    const unsigned char *bytes = static_cast<const unsigned char *>(data);
    for (size_t i = 0; i < size; i++) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ ((crc & 1U) ? 0xedb88320U : 0U);
        }
    }
    return crc;
}

static void write_encoded_block(FILE *out, BlockHeader header, const char *data,
                                 size_t size, const char *compressed, int encoded,
                                 bool checksums)
{
    header.size = (uint32_t)encoded;
    assert(fwrite(&header, 1, sizeof(header), out) == sizeof(header));
    assert(fwrite(compressed, 1, encoded, out) == (size_t)encoded);
    if (checksums) {
        uint32_t crc = fragment_crc(0xffffffffU, &header, sizeof(header));
        crc = fragment_crc(crc, data, size) ^ 0xffffffffU;
        assert(fwrite(&crc, 1, sizeof(crc), out) == sizeof(crc));
    }
}

static void write_fragment_block(FILE *out, BlockHeader header,
                                  const char *data, size_t size, bool checksums)
{
    assert(size > 0 && size <= BLOCK_SIZE);
    std::vector<char> compressed(LZ4_compressBound((int)size));
    // Independent LZ4 blocks are valid streaming blocks too.
    int encoded = LZ4_compress_default(data, compressed.data(), (int)size,
                                      (int)compressed.size());
    assert(encoded > 0);
    write_encoded_block(out, header, data, size, compressed.data(), encoded, checksums);
}

static void write_fragmented_file(FILE *out, const char *data, uint32_t size,
                                  size_t fragment, bool checksums)
{
    assert(fwrite(&size, 1, sizeof(size), out) == sizeof(size));
    for (size_t offset = 0; offset < size; offset += fragment) {
        BlockHeader header;
        header.block_type = BLOCK_TYPE_FILE;
        header.prev_cont = offset != 0;
        write_fragment_block(out, header, data + offset,
                              MIN(fragment, size - offset), checksums);
    }
}

static void rewrite_file_fragments(const char *source, const char *destination)
{
    Lz4Stream in(Lz4Stream::LZ4_Decompress);
    assert(in.Open(source) == 0);
    AcoreHeader header;
    assert(in.ReadRaw(reinterpret_cast<char *>(&header), sizeof(header)) == (int)sizeof(header));
    bool checksums = header.m.version >= 4;
    assert(in.EnableBlockChecksums(checksums) == 0);
    FILE *out = fopen(destination, "wb");
    assert(out != NULL);
    assert(fwrite(&header, 1, sizeof(header), out) == sizeof(header));

    BlockHeader block_header;
    Block *block = in.ReadBlock(block_header);
    assert(block && block_header.block_type == BLOCK_TYPE_PROCESS);
    assert(block->Length() >= 3 * sizeof(uint32_t));
    uint32_t threads = 0;
    memcpy(&threads, block->rBuf() + 2 * sizeof(uint32_t), sizeof(threads));
    write_fragment_block(out, block_header, block->rBuf(), block->Length(), checksums);
    auto copy_file = [&]() {
        ProcFile *file = in.GetFile();
        assert(file != NULL);
        write_fragmented_file(out, reinterpret_cast<const char *>(file),
                               (uint32_t)file->Size(), 7, checksums);
        free(file);
    };
    for (unsigned i = 0; i < (header.m.version >= 6 ? 7U : 6U); i++) {
        copy_file();
    }
    for (uint32_t i = 0; i < threads; i++) {
        block = in.ReadBlock(block_header);
        assert(block && block_header.block_type == BLOCK_TYPE_THREAD);
        write_fragment_block(out, block_header, block->rBuf(), block->Length(), checksums);
        copy_file();
    }
    while ((block = in.ReadBlock(block_header)) != NULL) {
        write_fragment_block(out, block_header, block->rBuf(), block->Length(), checksums);
    }
    assert(in.TailSeen() && in.LastReadClean() && in.VerifyPhysicalEof() == 0);
    assert(in.Close() == 0);
    BlockHeader tail = BlockHeader::TailMark();
    assert(fwrite(&tail, 1, sizeof(tail), out) == sizeof(tail));
    assert(fclose(out) == 0);
}

static bool check_file_fragments(const char *prefix)
{
    std::vector<char> files[2];
    for (unsigned i = 0; i < 2; i++) {
        ProcFile header = {};
        header.f_pid = 1234 + i;
        header.f_type = PROC_TYPE_ENVIRON;
        header.f_size = i == 0 ? 2 * BLOCK_SIZE + 17 : 0;
        files[i].resize(header.Size());
        memcpy(files[i].data(), &header, sizeof(header));
        const char entry[] = "VALUE=abcdefghijklmnopqrstuvwxyz";
        for (size_t j = 0; j < header.f_size; j++) {
            files[i][sizeof(header) + j] = entry[j % sizeof(entry)];
        }
        if (header.f_size != 0) {
            files[i].back() = '\0';
        }
    }

    const size_t fragments[] = {BLOCK_SIZE, BLOCK_SIZE / 2, 4096, 7};
    Lz4Stream reader(Lz4Stream::LZ4_Decompress);
    for (unsigned checksums = 0; checksums < 2; checksums++) {
        for (size_t fragment : fragments) {
            std::string path = std::string(prefix) + ".fragments-" +
                std::to_string(fragment) + "-" + std::to_string(checksums);
            FILE *out = fopen(path.c_str(), "wb");
            assert(out != NULL);
            for (const std::vector<char>& file : files) {
                write_fragmented_file(out, file.data(), (uint32_t)file.size(),
                                       fragment, checksums != 0);
            }
            BlockHeader tail = BlockHeader::TailMark();
            assert(fwrite(&tail, 1, sizeof(tail), out) == sizeof(tail));
            assert(fclose(out) == 0);

            assert(reader.Open(path.c_str()) == 0);
            assert(reader.EnableBlockChecksums(checksums != 0) == 0);
            for (const std::vector<char>& file : files) {
                ProcFile *decoded = reader.GetFile();
                if (!decoded) {
                    fprintf(stderr, "valid ProcFile fragments rejected: size=%zu checksums=%u\n",
                            fragment, checksums);
                    return false;
                }
                assert(decoded->Size() == file.size());
                assert(memcmp(decoded, file.data(), file.size()) == 0);
                free(decoded);
            }
            assert(reader.ReadBlock(tail) == NULL && reader.TailSeen() && reader.LastReadClean());
            assert(reader.VerifyPhysicalEof() == 0);
            assert(reader.Close() == 0);
        }
    }
    return true;
}

static bool check_linked_file_fragments(const char *prefix)
{
    const size_t fragments[] = {64, 4096, 16384};
    Lz4Stream reader(Lz4Stream::LZ4_Decompress);
    for (size_t fragment : fragments) {
        ProcFile file_header = {};
        file_header.f_pid = 1234;
        file_header.f_type = PROC_TYPE_ENVIRON;
        file_header.f_size = 10 * BLOCK_SIZE;
        std::vector<char> file(file_header.Size());
        std::mt19937 random(12345);
        for (char& byte : file) {
            byte = (char)random();
        }
        memcpy(file.data(), &file_header, sizeof(file_header));
        for (size_t offset = 2 * fragment; offset < file.size(); offset += 3 * fragment) {
            memcpy(file.data() + offset, file.data() + offset - 2 * fragment,
                   MIN(fragment, file.size() - offset));
        }
        for (unsigned checksums = 0; checksums < 2; checksums++) {
            std::string path = std::string(prefix) + ".linked-" +
                std::to_string(fragment) + "-" + std::to_string(checksums);
            FILE *out = fopen(path.c_str(), "wb");
            assert(out != NULL);
            uint32_t size = (uint32_t)file.size();
            assert(fwrite(&size, 1, sizeof(size), out) == sizeof(size));
            LZ4_stream_t *encoder = LZ4_createStream();
            LZ4_streamDecode_t *reference = LZ4_createStreamDecode();
            assert(encoder && reference && LZ4_setStreamDecode(reference, NULL, 0) == 1);
            std::vector<char> compressed(LZ4_compressBound((int)fragment));
            std::vector<char> decoded(file.size());
            for (size_t offset = 0; offset < file.size(); offset += fragment) {
                size_t length = MIN(fragment, file.size() - offset);
                int encoded = LZ4_compress_fast_continue(encoder, file.data() + offset,
                    compressed.data(), (int)length, (int)compressed.size(), 1);
                assert(encoded > 0);
                if (offset == 2 * fragment) {
                    assert(encoded < (int)length / 2);
                }
                assert(LZ4_decompress_safe_continue(reference, compressed.data(),
                    decoded.data() + offset, encoded, (int)length) == (int)length);
                BlockHeader header;
                header.block_type = BLOCK_TYPE_FILE;
                header.prev_cont = offset != 0;
                write_encoded_block(out, header, file.data() + offset, length,
                                     compressed.data(), encoded, checksums != 0);
            }
            assert(decoded == file);
            LZ4_freeStream(encoder);
            LZ4_freeStreamDecode(reference);
            BlockHeader tail = BlockHeader::TailMark();
            assert(fwrite(&tail, 1, sizeof(tail), out) == sizeof(tail));
            assert(fclose(out) == 0);

            int input_fd = -1;
            if (checksums == 0) {
                input_fd = open(path.c_str(), O_RDONLY);
                assert(input_fd >= 0 && reader.OpenFd(input_fd) == 0);
            } else {
                assert(reader.Open(path.c_str()) == 0);
            }
            assert(reader.EnableBlockChecksums(checksums != 0) == 0);
            ProcFile *actual = reader.GetFile();
            if (!actual) {
                fprintf(stderr, "linked FILE rejected after reference decode passed: size=%zu checksums=%u\n",
                        fragment, checksums);
                return false;
            }
            assert(actual->Size() == file.size());
            assert(memcmp(actual, file.data(), file.size()) == 0);
            free(actual);
            assert(reader.ReadBlock(tail) == NULL && reader.TailSeen() && reader.LastReadClean());
            assert(reader.VerifyPhysicalEof() == 0 && reader.Close() == 0);
            assert(reader.Close() == 0);
            if (input_fd >= 0) {
                assert(fcntl(input_fd, F_GETFD) == -1 && errno == EBADF);
            }
        }
    }
    return true;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        return 2;
    }
    if (!check_file_fragments(argv[2])) {
        return 1;
    }
    if (!check_linked_file_fragments(argv[2])) {
        return 1;
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

    // A real kernel write error must remain visible after the limit is lifted.
    // Empty application buffers do not make the damaged stream complete.
    std::string failed_stream = std::string(argv[2]) + ".write-error.z4";
    assert(writer.Open(failed_stream.c_str()) == 0);
    struct rlimit old_limit;
    assert(getrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    struct sigaction old_action, ignored_action = {};
    ignored_action.sa_handler = SIG_IGN;
    sigemptyset(&ignored_action.sa_mask);
    assert(sigaction(SIGXFSZ, &ignored_action, &old_action) == 0);
    struct rlimit limited = old_limit;
    limited.rlim_cur = 0;
    assert(setrlimit(RLIMIT_FSIZE, &limited) == 0);
    std::string raw_payload(8192, 'x');
    int failed_write = writer.WriteRaw(raw_payload.data(), raw_payload.size());
    assert(setrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    assert(sigaction(SIGXFSZ, &old_action, NULL) == 0);
    assert(failed_write < (int)raw_payload.size() && writer.IsError());
    long failed_position = writer.Tell();
    assert(writer.WriteRaw("x", 1) == -1);
    assert(writer.Write("x", 1) == -1);
    assert(writer.WriteBlock("x", 1, BLOCK_TYPE_STREAM) == -1);
    assert(writer.Flush() == -1 && writer.Sync() == -1);
    assert(writer.Tell() == failed_position);
    assert(writer.Close() == -1);
    assert(writer.Close() == 0);
    assert(writer.Open(failed_stream.c_str()) == 0);
    assert(writer.Write("healthy", 7) == 7);
    assert(writer.Close() == 0);

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
    long tail_end = reader.Tell();
    assert(reader.ReadBlock(hdr) == NULL && reader.LastReadClean());
    assert(reader.Tell() == tail_end);
    assert(reader.VerifyPhysicalEof() == -1);
    assert(reader.VerifyPhysicalEof() == -1);
    long failed_end = reader.Tell();
    assert(reader.ReadBlock(hdr) == NULL && !reader.LastReadClean());
    assert(reader.Tell() == failed_end);
    assert(reader.VerifyPhysicalEof() == -1);
    assert(reader.Close() == 0);

    std::string invalid_block_stream = std::string(argv[2]) + ".invalid-block.z4";
    assert(writer.Open(invalid_block_stream.c_str()) == 0);
    BlockHeader invalid_block;
    invalid_block.block_type = BLOCK_TYPE_STREAM;
    invalid_block.size = 1;
    assert(writer.WriteRaw(reinterpret_cast<const char *>(&invalid_block),
                           sizeof(invalid_block)) == (int)sizeof(invalid_block));
    assert(writer.WriteRaw("\0", 1) == 1); // Decodes to an invalid empty block.
    assert(writer.WriteRaw(reinterpret_cast<const char *>(&boundary_tail),
                           sizeof(boundary_tail)) == (int)sizeof(boundary_tail));
    assert(writer.Close() == 0);
    assert(reader.Open(invalid_block_stream.c_str()) == 0);
    assert(reader.ReadBlock(hdr) == NULL && !reader.LastReadClean());
    long invalid_end = reader.Tell();
    assert(reader.ReadBlock(hdr) == NULL && !reader.LastReadClean());
    assert(!reader.TailSeen() && reader.Tell() == invalid_end);
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
    std::string fragmented_acore = std::string(argv[2]) + ".fragmented.acore";
    rewrite_file_fragments(argv[1], fragmented_acore.c_str());

    Coredump dump(0);
    if (dump.decompress(argv[1], argv[2]) != 0 ||
        dump.decompress(corrupt_acore.c_str(), rejected_core.c_str()) == 0 ||
        access(rejected_core.c_str(), F_OK) == 0 ||
        dump.decompress(fragmented_acore.c_str(), argv[3]) != 0) {
        fprintf(stderr, "reusing one Coredump instance failed\n");
        return 1;
    }
    return 0;
}
