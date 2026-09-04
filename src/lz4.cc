/* supports lz4 compress.
 */

#include <limits.h>
#include <fcntl.h>
#include <array>

#include "inc.h"
#include "lz4.h"

namespace arthur {

static const size_t MAX_PROC_FILE_SIZE = 64 * 1024 * 1024;

const char* szBlockType(BlockType t)
{
#define V(a,b) case a: return b;
    switch (t) {
        BLOCK_TYPE_LIST(V)
        default:
            break;
    }
#undef V
    assert(0);
    return NULL;
}

Lz4Stream::Lz4Stream(lz4_mode mode) :
    _block_index(0), _file(NULL), _enc(NULL), _dec(NULL)
{
    _mode = mode;
    _size_real = 0;
    _size_file = 0;
    _eof_clean = true;
    _tail_seen = false;
    _block_checksums = false;
    // R50-5: _block_type 原未初始化——test_compress 走 Write/Flush 不调 SetBlock，
    // Flush 把垃圾类型写进块头（未定义值）。初始化安全默认值。
    _block_type = BLOCK_TYPE_PROCESS;
}

Lz4Stream::~Lz4Stream()
{
    if (_file) {
        Close();
    }
    ReleaseCodec();
}

void Lz4Stream::ReleaseCodec()
{
    if (_enc) {
        LZ4_freeStream(_enc);
        _enc = NULL;
    }

    if (_dec) {
        LZ4_freeStreamDecode(_dec);
        _dec = NULL;
    }
}

void Lz4Stream::ResetState()
{
    _block_index = 0;
    _block_type = BLOCK_TYPE_PROCESS;
    _size_real = 0;
    _size_file = 0;
    _eof_clean = true;
    _tail_seen = false;
    _block_checksums = false;
    for (size_t i = 0; i < MAX_RING_BUF; i++) {
        _blocks[i].Clear();
    }
}

int Lz4Stream::InitCodec()
{
    if (_mode == LZ4_Compress) {
        _enc = LZ4_createStream();
        if(!_enc) {
            error("Fail to create encode stream");
            return -1;
        }

        LZ4_stream_t *lz4strm = LZ4_initStream(_enc, sizeof(*_enc));
        if(!lz4strm) {
            error("Fail to init encode stream");
            return -1;
        }
    } else if (_mode == LZ4_Decompress) {
        _dec = LZ4_createStreamDecode();
        if(!_dec) {
            error("Fail to create decode stream");
            return -1;
        }

        // 1 for okay and 0 for error
        if(!(LZ4_setStreamDecode(_dec, NULL, 0))) {
            error("Fail to set decode stream ");
            return -1;
        }
    } else {
        assert(0);
    }

    return 0;
}

int Lz4Stream::Open(const char *file)
{
    if (!file) {
        errno = EINVAL;
        error("cannot open an LZ4 stream with a null path");
        return -1;
    }
    if (_file) {
        errno = EBUSY;
        error("cannot reopen an active LZ4 stream");
        return -1;
    }
    ReleaseCodec();
    ResetState();
    _file = fopen(file, _mode == LZ4_Compress ? "wb" : "rb");
    if (!_file) {
        error("Fail to open file: %s", file);
        return -1;
    }
    if (InitCodec() != 0) {
        fclose(_file);
        _file = NULL;
        ReleaseCodec();
        return -1;
    }
    return 0;
}

int Lz4Stream::OpenFd(int fd)
{
    if (fd < 0) {
        errno = EBADF;
        error("cannot open an LZ4 stream from an invalid fd");
        return -1;
    }
    if (_file) {
        errno = EBUSY;
        error("cannot reopen an active LZ4 stream");
        return -1;
    }

    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        error("cannot inspect LZ4 stream fd: %s", strerror(errno));
        return -1;
    }
#ifdef O_PATH
    if (flags & O_PATH) {
        errno = EBADF;
        error("cannot use an O_PATH fd for LZ4 stream I/O");
        return -1;
    }
#endif
    int access_mode = flags & O_ACCMODE;
    bool access_ok = _mode == LZ4_Compress
        ? (access_mode == O_WRONLY || access_mode == O_RDWR)
        : (access_mode == O_RDONLY || access_mode == O_RDWR);
    if (!access_ok) {
        errno = EBADF;
        error("LZ4 stream fd access mode is incompatible with codec direction");
        return -1;
    }

    ReleaseCodec();
    ResetState();
    if (InitCodec() != 0) {
        ReleaseCodec();
        return -1;
    }
    _file = fdopen(fd, _mode == LZ4_Compress ? "wb" : "rb");
    if (!_file) {
        error("Fail to open stream from fd: %s", strerror(errno));
        ReleaseCodec();
        return -1;
    }
    return 0;
}

int Lz4Stream::Sync()
{
    if (!_file || !_enc) {
        errno = EBADF;
        return -1;
    }
    if (Flush() < 0) {
        return -1;
    }
    if (fflush(_file) != 0 || fsync(fileno(_file)) != 0) {
        error("sync output failed (%s)", strerror(errno));
        return -1;
    }
    return 0;
}

int Lz4Stream::Close()
{
    // R50-6: 幂等——双重 Close 曾因 fclose(NULL) 使 arthur 自身段错误
    //（forkcore 失败路径复制了 out.Close(); unlink(); 两组）。NULL 时直接返回。
    // b167/b191 (Codex): 返回 Flush/fclose 错误——关闭期 ENOSPC 不再静默。
    if (!_file) {
        ReleaseCodec();
        return 0;
    }

    int rc = 0;
    if (_enc) {
        // B191: 收尾 Flush 失败（磁盘满/压缩失败）时未密封块静默丢失、acore 截断。
        // dump/test 路径在 WriteTailMark 前已显式 Flush（Close 的 Flush 通常是空
        // 操作），但作为最后防线失败必须报告而非吞掉。
        if (Flush() < 0) {
            error("Close: final flush failed (disk full?), output truncated");
            rc = -1;
        }
    }

    // b191 (Codex B191 review): fclose 才是 stdio 缓冲真正落盘的时机——ENOSPC 可
    // 到此处才暴露，原实现静默吞掉。
    if (fclose(_file) != 0) {
        error("Close: fclose failed (%s), output may be truncated", strerror(errno));
        rc = -1;
    }
    _file = NULL;
    ReleaseCodec();
    return rc;
}

// file postion
int Lz4Stream::Seek(long n)
{
    if (!_file) {
        errno = EBADF;
        return -1;
    }
    return fseek(_file, n, SEEK_SET);
}

long Lz4Stream::Tell()
{
    if (!_file) {
        errno = EBADF;
        return -1;
    }
    return ftell(_file);
}

int Lz4Stream::Peek(char *out, size_t n)
{
    if (!_file || !_dec) {
        errno = EBADF;
        _eof_clean = false;
        return -1;
    }
    if ((!out && n != 0) || n > INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    if (n == 0) {
        return 0;
    }
    long save = Tell();
    if (save < 0) {
        error("peek requires a seekable input stream");
        return -1;
    }
    int rc = ReadRaw(out, n);
    if (Seek(save) != 0) {
        _eof_clean = false;
        error("failed to restore input position after peek");
        return -1;
    }
    return rc;
}

// raw function for file access
int Lz4Stream::WriteRaw(const char *s, size_t n)
{
    // B70: 原 `assert(rc == n)` 在磁盘满短写时 debug 构建 abort（NDEBUG 静默丢）。
    // 改为返回实际写入数，调用方检查。
    if (!_file || !_enc) {
        errno = EBADF;
        return -1;
    }
    if ((!s && n != 0) || n > INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    if (n == 0) {
        return 0;
    }
    // Raw protocol fields delimit compressed block sequences. Preserve bytes
    // already buffered by Write() before inserting the raw field; otherwise a
    // later Close() would emit the compressed block after the raw marker.
    if (!CurrentBlock().isEmpty() && Flush() < 0) {
        return -1;
    }
    size_t written = fwrite(s, 1, n, _file);
    _size_file += written;
    return (int)written;
}

int Lz4Stream::ReadRaw(char *out, size_t n)
{
    if (!_file || !_dec) {
        errno = EBADF;
        return -1;
    }
    if ((!out && n != 0) || n > INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    if (n == 0) {
        return 0;
    }
    return (int)fread(out, 1, n, _file);
}

int Lz4Stream::VerifyPhysicalEof()
{
    if (!_file || _mode != LZ4_Decompress || !_tail_seen) {
        _eof_clean = false;
        error("cannot verify stream end before tail mark");
        return -1;
    }
    if (!_eof_clean) {
        errno = EPROTO;
        error("stream end has already failed physical EOF validation");
        return -1;
    }

    unsigned char trailing = 0;
    size_t rc = fread(&trailing, 1, 1, _file);
    if (rc != 0) {
        _eof_clean = false;
        error("trailing data after tail mark (first byte 0x%02x), stream corrupt",
              trailing);
        return -1;
    }
    if (ferror(_file) || !feof(_file)) {
        _eof_clean = false;
        error("failed to verify physical EOF after tail mark");
        return -1;
    }
    return 0;
}

// write stream
int Lz4Stream::Flush()
{
    if (!_file || !_enc) {
        errno = EBADF;
        return -1;
    }

    // empty 
    Block& block = CurrentBlock();
    if (block.isEmpty()) {
        // do nothing
        return 0; 
    }
 
    // compress and write to fd 
    BlockHeader hdr;
    hdr.block_type = _block_type;
    int rc = Compress(block, hdr);
    if (rc < 0) {
        error("Compress failed.");
        return rc;
    }

    return 0;
}

int Lz4Stream::SetBlock(BlockType type)
{
    if (type < 0 || type >= BLOCK_TYPE_MAX) {
        errno = EINVAL;
        error("invalid LZ4 block type %d", type);
        return -1;
    }
    if (!_file || !_enc) {
        errno = EBADF;
        error("cannot set a block type on an inactive compressor");
        return -1;
    }
    if (type != _block_type && !CurrentBlock().isEmpty()) {
        // Buffered bytes belong to the old type. Seal them before changing the
        // type so metadata cannot be silently relabelled.
        if (Flush() < 0) {
            return -1;
        }
    }
    _block_type = type; 
    return 0;
}

int Lz4Stream::EnableBlockChecksums(bool enabled)
{
    if (!_file || (!_enc && !_dec)) {
        errno = EBADF;
        return -1;
    }
    if (_block_checksums == enabled) {
        return 0;
    }
    if (_block_index != 0 || (_enc && !CurrentBlock().isEmpty())) {
        errno = EBUSY;
        error("cannot change checksum layout after compressed data has started");
        return -1;
    }
    _block_checksums = enabled;
    return 0;
}

/* write s for n bytes to file
 */
int Lz4Stream::Write(const char *s, size_t n)
{
    if (!_file || !_enc) {
        errno = EBADF;
        return -1;
    }
    if (!s && n != 0) {
        errno = EINVAL;
        return -1;
    }

    // B193: 返回类型 int——n 超过 INT_MAX 时下方 return (int)m 截断成负值/垃圾。
    // 当前调用方最大 56 字节（元数据结构），但 Write 是多块循环的公开入口，
    // 防御性 fail-closed。
    if (n > INT_MAX) {
        error("Write: %zu bytes exceeds int return range", n);
        return -1;
    }

    // enough room
    Block& block = CurrentBlock();
    if (n <= block.Available()) {
        //printf("block %d %d\n", block.Available(), block.Size());
        return block.Write(s, n);
    }

    // begin a new block
    // B78: Flush 失败（磁盘满）时当前块未密封，继续写会错位。
    if (Flush() < 0) {
        error("Write: flush failed (disk full?)");
        return -1;
    }

    // one block
    if (n < BLOCK_SIZE) {
        Block& block = CurrentBlock();
        return block.Write(s, n);
    }

    // B78 (Codex B5/B9 review): 原 `assert(0)` 对 n >= BLOCK_SIZE 直接 abort
    //（NDEBUG 下返回 n 却不写数据）。循环切块写入并传播 Flush 错误。
    size_t m = 0;
    while (m < n) {
        size_t j = MIN(BLOCK_SIZE, n - m);
        Block& b = CurrentBlock();
        b.Clear();
        int wrc = b.Write(s + m, j);
        if (wrc < 0) {
            error("Write: block write failed");
            return -1;
        }
        m += wrc;
        if (Flush() < 0) {
            error("Write: flush failed (disk full?)");
            return -1;
        }
    }
    return (int)m;
}

/* write blocks and flush.
 */
int Lz4Stream::WriteBlock(const char *s, size_t n, BlockType t)
{
    int rc;
    size_t m = 0;

    if (!s && n != 0) {
        errno = EINVAL;
        return -1;
    }
    if (t < 0 || t >= BLOCK_TYPE_MAX) {
        errno = EINVAL;
        error("invalid LZ4 block type %d", t);
        return -1;
    }
    if (!_file || !_enc) {
        errno = EBADF;
        return -1;
    }

    // b193 (Codex B193 review): 返回值是 int——n>INT_MAX 时 `return (int)m` 截断成
    // 负值/垃圾。当前调用方单块 ≤ BLOCK_SIZE 不可达，纵深防护与 Write 入口对齐。
    if (n > INT_MAX) {
        error("WriteBlock size %zu exceeds INT_MAX, aborting", n);
        return -1;
    }

    // get a new block
    // B70: Flush 失败（磁盘满）时当前块未密封；继续写会让 acore 错位。传播错误。
    if (Flush() < 0) {
        error("flush previous block failed (disk full?)");
        return -1;
    }

    BlockHeader block_hdr;
    block_hdr.block_type = t;
    for (m = 0; m < n; ) {
        Block& block = CurrentBlock();
        block.Clear();

        rc = block.Write(s+m, MIN(BLOCK_SIZE, n-m));
        if (rc < 0) {
            error("block write failed");
            return -1;
        }

        m += rc;
        rc = Compress(block, block_hdr);
        if (rc <= 0) {
            error("compress block failed (%d)", rc);
            return -1;
        }

        // more than one block
        block_hdr.prev_cont = 1;
    }

    return m;
}

static uint32_t crc32_update(uint32_t crc, const void *data, size_t size)
{
    static const std::array<uint32_t, 256> table = []() {
        std::array<uint32_t, 256> values = {};
        for (uint32_t i = 0; i < values.size(); i++) {
            uint32_t value = i;
            for (int bit = 0; bit < 8; bit++) {
                value = (value >> 1) ^ ((value & 1) ? 0xedb88320U : 0);
            }
            values[i] = value;
        }
        return values;
    }();
    const unsigned char *bytes = static_cast<const unsigned char *>(data);
    for (size_t i = 0; i < size; i++) {
        crc = table[(crc ^ bytes[i]) & 0xff] ^ (crc >> 8);
    }
    return crc;
}

static uint32_t block_checksum(const BlockHeader& hdr, const char *data, size_t size)
{
    uint32_t crc = crc32_update(0xffffffffU, &hdr, sizeof(hdr));
    return crc32_update(crc, data, size) ^ 0xffffffffU;
}

// compress buffer and flush to fd.
int Lz4Stream::Compress(Block& block, BlockHeader& hdr)
{
    char buf[LZ4_COMPRESSBOUND(BLOCK_SIZE)];

    if (block.isEmpty()) {
        return 0;
    }

    // B49: LZ4_compress_fast_continue 返回 int；原用 size_t 存导致 `len < 0`
    // 恒假（-Wall 报 type-limits），错误返回值被当巨大正数写进块头。
    int len = LZ4_compress_fast_continue(_enc, block.rBuf(), buf, block.Length(), sizeof(buf), 1);
    if (len <= 0) {
        error("lz4 compress failed (%d)\n", len);
        return -1;
    }

    // write block header
    hdr.size = len;
    // B64: `rc < 0` 恒假——fwrite 返回 size_t（实际写入数），磁盘满时短写返回
    // 正数而不是负，原检查检测不到，acore 静默截断。改完整长度比较。
    if (fwrite(&hdr, 1, sizeof(hdr), _file) != sizeof(hdr)) {
        error("write block header failed (disk full?)");
        return -1;
    }

    // write compressed data
    if (fwrite(buf, 1, len, _file) != (size_t)len) {
        error("write block data failed (disk full?)");
        return -1;
    }
    if (_block_checksums) {
        uint32_t checksum = block_checksum(hdr, block.rBuf(), block.Length());
        if (fwrite(&checksum, 1, sizeof(checksum), _file) != sizeof(checksum)) {
            error("write block checksum failed (disk full?)");
            return -1;
        }
    }

    _size_real += block.Length();
    _size_file += sizeof(hdr) + len +
        (_block_checksums ? sizeof(uint32_t) : 0);

    dprint("writed %lu, compress = %d", block.Length(), len);
 
    // clear the block 
    block.Clear(); 
    
    // next block
    _block_index++;
    
    return len;
}

/* Read a block
 */
Block* Lz4Stream::ReadBlock(BlockHeader& hdr)
{
    char buf[LZ4_COMPRESSBOUND(BLOCK_SIZE)];
    int rc;

    if (!_file || !_dec) {
        errno = EBADF;
        _eof_clean = false;
        return NULL;
    }

    // next block
    _block_index++;
    Block& block = CurrentBlock(); 
    block.Clear();

    // read out block size
    rc = fread(&hdr, 1, sizeof(hdr), _file);
    if (rc != (int)sizeof(hdr)) {
        // 截断在块头边界：正常 EOF（feof）或损坏 acore，返回 NULL 让调用方结束。
        // b22 (Codex review): fread==0 不只表示 EOF——真实 I/O 错误（ferror）也会
        // 返回 0，不能把它当成干净结束。只有 feof 才是正常 EOF。
        // R50-1: _eof_clean 标记干净结束（块边界 EOF），短读/错误置 false，供
        // test_decompress 区分截断。
        if (rc == 0 && !ferror(_file)) {
            _eof_clean = true;
            return NULL;   // 干净 EOF
        }
        _eof_clean = false;
        error("read block header failed (%d), acore truncated", rc);
        return NULL;
    }

    // tail mark
    if (hdr.isTailMark()) {
        _eof_clean = true;
        _tail_seen = true;
        return NULL;
    }

    // B20: hdr.size 是 19 位字段，最大 524287，但 buf 只有
    // LZ4_COMPRESSBOUND(BLOCK_SIZE)（64KB 输入的最坏压缩后大小 ≈65809）。
    // 合法写入者每块最多 BLOCK_SIZE 未压缩字节，压缩后必 ≤ 该值；
    // 损坏/构造的 acore 可把 hdr.size 设成任意值 → fread 越过栈缓冲。
    if (hdr.size > sizeof(buf)) {
        _eof_clean = false;
        error("block compressed size %u exceeds buffer (%lu), acore corrupt", hdr.size, sizeof(buf));
        return NULL;
    }

    // read out compressed data
    rc = fread(buf, 1, hdr.size, _file);
    if (rc != (int)hdr.size) {
        _eof_clean = false;
        error("read block data failed (%d != %u)", rc, hdr.size);
        return NULL;
    }

    uint32_t stored_checksum = 0;
    if (_block_checksums &&
        fread(&stored_checksum, 1, sizeof(stored_checksum), _file) != sizeof(stored_checksum)) {
        _eof_clean = false;
        error("read block checksum failed, acore truncated");
        return NULL;
    }

    // decompress
    // R50-15 (T3): `rc < 0` 只拒负值——构造的块可解出 0 字节（rc==0），空块被当
    // 成功返回（写侧 Compress 对空块提前返回、从不写 0 字节块，故 rc==0 恒异常）。
    // ReadLoads 会静默写 0 字节继续（最终靠 loads/expected 校验兜底）；统一拒。
    rc = LZ4_decompress_safe_continue(_dec, buf, block.wBuf(), hdr.size, BLOCK_SIZE);
    if (rc <= 0) {
        _eof_clean = false;
        error("decode failed rc = %d\n", rc);
        return NULL;
    }
    block._length = rc;
    if (_block_checksums) {
        uint32_t actual_checksum = block_checksum(hdr, block.rBuf(), block.Length());
        if (actual_checksum != stored_checksum) {
            _eof_clean = false;
            error("block checksum mismatch (%08x != %08x), acore corrupt",
                  actual_checksum, stored_checksum);
            block.Clear();
            return NULL;
        }
    }
    dprint("ReadBlock size(%d), type(%d), data(%d)\n", hdr.size, hdr.block_type, rc);

    return &block;;
}

/* put a proc file to stream
 */
int Lz4Stream::PutFile(ProcFile* pf)
{
    int rc;

    if (!pf) {
        errno = EINVAL;
        return -1;
    }
    if (!_file || !_enc) {
        errno = EBADF;
        return -1;
    }

    // The wire prefix and return value are narrower than ProcFile::Size().
    // Reject the complete object before Flush/WriteRaw so failure leaves the
    // current logical block untouched and cannot create a partial FILE record.
    if ((size_t)pf->f_size > SIZE_MAX - sizeof(ProcFile)) {
        errno = EOVERFLOW;
        error("proc file size overflows size_t");
        return -1;
    }
    size_t serialized_size = sizeof(ProcFile) + (size_t)pf->f_size;
    if (serialized_size > UINT32_MAX || serialized_size > INT_MAX) {
        errno = EOVERFLOW;
        error("proc file size %zu exceeds wire or return range", serialized_size);
        return -1;
    }
    // Keep the writer symmetric with GetFile's corruption/allocation cap.
    // A stream emitted by this implementation must be readable by it.
    if (serialized_size > MAX_PROC_FILE_SIZE) {
        errno = EFBIG;
        error("proc file size %zu exceeds sanity cap", serialized_size);
        return -1;
    }

    // seal the current block
    // B70: Flush 失败（磁盘满）时传播错误。
    if (Flush() < 0) {
        error("flush failed in PutFile (disk full?)");
        return -1;
    }

    // flat size
    uint32_t size = (uint32_t)serialized_size;

    // TBD: remove the Raw size
    // write file size
    // B70: WriteRaw 短写（磁盘满）必须检查——原实现返回值被下一行 WriteBlock 覆盖。
    if (WriteRaw((const char*)&size, sizeof(size)) != (int)sizeof(size)) {
        error("write proc file size failed (disk full?)");
        return -1;
    }

    // write file context
    rc = WriteBlock((const char*)pf, size, BLOCK_TYPE_FILE);
    if (rc < 0) {
        error("write proc file block failed");
        return rc;
    }

    return rc;
}

/* get proc file from stream.
 */
ProcFile* Lz4Stream::GetFile()
{
    int rc;
    uint32_t size;

    if (!_file || !_dec) {
        errno = EBADF;
        _eof_clean = false;
        return NULL;
    }

    // TBD: remove the Raw Size
    // readout the file size
    rc = ReadRaw((char*)&size, sizeof(size));
    if (rc != (int)sizeof(size)) {
        error("read proc file size failed");
        return NULL;
    }

    // B23: size 来自 acore 可构造为任意 32 位值；malloc(huge) 会 OOM/巨量分配。
    // 合法 /proc 文件不会超过 64MB（真实进程 maps 最多几 MB）。超限拒绝。
    if (size > MAX_PROC_FILE_SIZE) {
        error("proc file size %u exceeds sanity cap, acore corrupt", size);
        return NULL;
    }

    // b23 (Codex review): size 为 0..3 时 malloc(size) 只分配几个字节，下方
    // pf->f_size 赋值（4 字节）越过分配边界写堆。合法写入的最小序列化大小是
    // sizeof(ProcFile)（f_size/f_pid/f_type 头，f_data 可为 0 字节），小于即损坏。
    if (size < sizeof(ProcFile)) {
        error("proc file size %u smaller than header, acore corrupt", size);
        return NULL;
    }

    // malloc
    ProcFile *pf = (ProcFile*)malloc(size);
    if (!pf) {
        error("out of memory reading proc file (%u bytes)", size);
        return NULL;
    }

    // read out the file
    BlockHeader hdr;
    char *p = (char*)pf;
    uint32_t i = 0;

    for (; i<size; ) {
        Block *block = ReadBlock(hdr);
        if (!block) {
            break;
        }

        // 损坏 acore 的块类型不匹配：拒绝而非 assert abort
        if (hdr.block_type != BLOCK_TYPE_FILE) {
            error("expected FILE block, got type %u, acore corrupt", hdr.block_type);
            free(pf);
            return NULL;
        }

        // PutFile uses WriteBlock: the first block starts a logical file and
        // every later block is explicitly marked as its continuation. Enforce
        // that boundary so a FILE block cannot be spliced into another object.
        bool expected_cont = (i != 0);
        if ((hdr.prev_cont != 0) != expected_cont) {
            error("FILE block continuation flag mismatch at offset %u (acore corrupt)", i);
            free(pf);
            return NULL;
        }

        // B162: FILE 块解压字节多于文件剩余需求——声明 size 小于实际数据
        //（损坏/恶意 acore）。合法写侧 WriteBlock 把文件切成恰 size 字节，块
        // 内未压缩字节和恒等于 size，多余字节只会来自 bit-flip/伪造。原实现
        // 只读前缀、多余字节静默丢弃（fail-open 不对称：只验"过少"不验"过多"）。
        size_t need = size - i;
        if ((size_t)block->Size() > need) {
            error("FILE block %lu bytes over-provides file size %u (acore corrupt)",
                  (unsigned long)block->Size(), size);
            free(pf);
            return NULL;
        }
        rc = block->Read(p+i, MIN(size-i, BLOCK_SIZE));
        if (rc <= 0) {
            break;   // 读不动了，防死循环
        }
        i += rc;
    }

    // b23 (Codex review): 块序列截断/损坏时 i 达不到 size，返回部分未初始化的
    // ProcFile 会让后续 parser/note 消费 malloc 堆垃圾。必须读满 size 才是干净
    // 成功；否则释放并失败（fail-closed）。干净写入的 FILE 块未压缩字节和恒等于
    // size，因此严格校验不影响正常 acore。
    if (i != size) {
        error("proc file truncated: read %u of %u bytes, acore corrupt", i, size);
        free(pf);
        return NULL;
    }

    // B194: 合法序列化恒有 size == sizeof(ProcFile) + pf->f_size（PutFile 写
    // pf->Size()）。外层 size 前缀被位翻转改大时，GetFile 会越过本文件逻辑
    // 边界吞掉后续 FILE 块的 size 前缀（跨文件错位）；用真实头字段 pf->f_size
    // 做确定性边界证明——改大必不匹配 → fail-closed，杜绝按伪造 f_size 逃逸
    // 的垃圾 ProcFile。改小同样被拒（此前 B37 是钳制继续，现在更严格地拒绝）。
    // 必须在下方 B37 覆盖 pf->f_size 之前检查。
    if (size != sizeof(ProcFile) + pf->f_size) {
        error("proc file size %u mismatch header f_size %u (acore corrupt)",
              size, pf->f_size);
        free(pf);
        return NULL;
    }

    // B37: 损坏 acore 可让内部 f_size 大于实际 malloc 缓冲（size），后续
    // ProcAuxv/ProcCmdline/ProcStat 按 f_size 读会越界。钳制到真实缓冲大小。
    // （size >= sizeof(ProcFile) 已保证上方，f_data 长度即 size - 头部。）
    // 通过 B194 校验后此处恒为 no-op（size - 头部 == pf->f_size），仅作兜底。
    pf->f_size = size - sizeof(ProcFile);

    return pf;
}

void Lz4Stream::PrintStat()
{
    double ratio = _size_real == 0 ? 0.0 :
        (double)_size_file / _size_real * 100;
    info("Compressed %lu bytes into %lu bytes ==> %0.2f%%",
         _size_real, _size_file, ratio);
}

};
