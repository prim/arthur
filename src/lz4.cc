/* supports lz4 compress.
 */

#include "inc.h"
#include "lz4.h"

namespace arthur {

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
}

Lz4Stream::~Lz4Stream()
{
    if (_file) {
        Close();
    }

    if (_enc) {
        LZ4_freeStream(_enc);
        _enc = NULL;
    }

    if (_dec) {
        LZ4_freeStreamDecode(_dec);
        _dec = NULL;
    }
}

int Lz4Stream::Open(const char *file) 
{   
    if (_mode == LZ4_Compress) {
        _file = fopen(file, "wb");
        if (!_file) {
            error("Fail to open file: %s", file);
            return -1;
        }

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
        _file = fopen(file, "rb");
        if (!_file) {
            error("Fail to open file: %s", file);
            return -1;
        }

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

void Lz4Stream::Close()
{
    if (_enc) {
        Flush();
    }

    fclose(_file);
    _file = NULL;
}

// file postion
int Lz4Stream::Seek(long n)
{
    return fseek(_file, n, SEEK_SET);
}

long Lz4Stream::Tell()
{
    return ftell(_file);
}

int Lz4Stream::Peek(char *out, size_t n)
{
    long save = Tell();
    int rc = ReadRaw(out, n);
    Seek(save);
    return rc;
}

// raw function for file access
int Lz4Stream::WriteRaw(const char *s, size_t n)
{
    // B70: 原 `assert(rc == n)` 在磁盘满短写时 debug 构建 abort（NDEBUG 静默丢）。
    // 改为返回实际写入数，调用方检查。
    return (int)fwrite(s, 1, n, _file);
}

int Lz4Stream::ReadRaw(char *out, size_t n)
{
    return fread(out, 1, n, _file);
}

// write stream
int Lz4Stream::Flush()
{
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
    _block_type = type; 
    return 0;
}

/* write s for n bytes to file
 */
int Lz4Stream::Write(const char *s, size_t n)
{
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

    _size_real += block.Length();
    _size_file += len;

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

    dprint("writed %lu, compress = %lu", block.Length(), len);
 
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
        if (rc == 0 && !ferror(_file)) {
            return NULL;   // 干净 EOF
        }
        error("read block header failed (%d), acore truncated", rc);
        return NULL;
    }

    // tail mark
    if (hdr.isTailMark()) {
        return NULL;
    }

    // B20: hdr.size 是 19 位字段，最大 524287，但 buf 只有
    // LZ4_COMPRESSBOUND(BLOCK_SIZE)（64KB 输入的最坏压缩后大小 ≈65809）。
    // 合法写入者每块最多 BLOCK_SIZE 未压缩字节，压缩后必 ≤ 该值；
    // 损坏/构造的 acore 可把 hdr.size 设成任意值 → fread 越过栈缓冲。
    if (hdr.size > sizeof(buf)) {
        error("block compressed size %u exceeds buffer (%lu), acore corrupt", hdr.size, sizeof(buf));
        return NULL;
    }

    // read out compressed data
    rc = fread(buf, 1, hdr.size, _file);
    if (rc != (int)hdr.size) {
        error("read block data failed (%d != %u)", rc, hdr.size);
        return NULL;
    }

    // decompress 
    rc = LZ4_decompress_safe_continue(_dec, buf, block.wBuf(), hdr.size, BLOCK_SIZE);
    if (rc < 0) {
        error("decode failed rc = %d\n", rc);
        return NULL; 
    }
    block._length = rc;
    dprint("ReadBlock size(%d), type(%d), data(%d)\n", hdr.size, hdr.block_type, rc);

    return &block;;
}

/* put a proc file to stream
 */
int Lz4Stream::PutFile(ProcFile* pf)
{
    int rc;

    // seal the current block
    // B70: Flush 失败（磁盘满）时传播错误。
    if (Flush() < 0) {
        error("flush failed in PutFile (disk full?)");
        return -1;
    }

    // flat size
    uint32_t size = pf->Size();

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

    // TBD: remove the Raw Size
    // readout the file size
    rc = ReadRaw((char*)&size, sizeof(size));
    if (rc != (int)sizeof(size)) {
        error("read proc file size failed");
        return NULL;
    }

    // B23: size 来自 acore 可构造为任意 32 位值；malloc(huge) 会 OOM/巨量分配。
    // 合法 /proc 文件不会超过 64MB（真实进程 maps 最多几 MB）。超限拒绝。
    if (size > 64*1024*1024) {
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

    // B37: 损坏 acore 可让内部 f_size 大于实际 malloc 缓冲（size），后续
    // ProcAuxv/ProcCmdline/ProcStat 按 f_size 读会越界。钳制到真实缓冲大小。
    // （size >= sizeof(ProcFile) 已保证上方，f_data 长度即 size - 头部。）
    pf->f_size = size - sizeof(ProcFile);

    return pf;
}

void Lz4Stream::PrintStat()
{
    info("Compressed %lu bytes into %lu bytes ==> %0.2f", 
            _size_real, _size_file, (double)_size_file/_size_real*100); 
}

};
