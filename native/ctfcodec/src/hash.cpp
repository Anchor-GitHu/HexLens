// hash.cpp —— 哈希 / 校验和算法模块
//
// 包含：MD4(内部，供 NTLM 用) / MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512
//       CRC32 / CRC32C / CRC16(多变体) / Adler-32 / Fletcher-16 / Fletcher-32
//       HMAC-MD5 / HMAC-SHA1 / HMAC-SHA256 / HMAC-SHA512 / NTLM
//
// 设计说明：
//   1. 纯标准库实现，不调用任何系统加密 API，保证跨编译器结果一致。
//   2. 所有哈希共用一个「流式上下文」(StreamHash)，压缩函数各自实现；
//      MD5/SHA-1/SHA-256 家族按 64 字节分块（小端），SHA-384/512 按 128 字节分块（大端）。
//   3. 哈希类算法不可逆，注册时 dec 一律传 nullptr。
#include "common.h"
#include "util.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ctf {
namespace {

// ===========================================================================
// 通用小工具
// ===========================================================================

// 32 位循环左移（移位量按 32 取模，避免移位量为 0/32 时的未定义行为）
inline uint32_t Rotl32(uint32_t x, uint32_t n) {
    n &= 31u;
    if (n == 0) return x;
    return (x << n) | (x >> (32u - n));
}

// 64 位循环左移
inline uint64_t Rotl64(uint64_t x, uint32_t n) {
    n &= 63u;
    if (n == 0) return x;
    return (x << n) | (x >> (64u - n));
}

// 32 位循环右移
inline uint32_t Rotr32(uint32_t x, uint32_t n) {
    n &= 31u;
    if (n == 0) return x;
    return (x >> n) | (x << (32u - n));
}

inline uint32_t LoadLE32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

inline uint32_t LoadBE32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline uint64_t LoadBE64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | static_cast<uint64_t>(p[i]);
    return v;
}

inline void StoreLE32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
}

inline void StoreLE64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
}

inline void StoreBE32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>((v >> (24 - 8 * i)) & 0xFFu);
}

inline void StoreBE64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>((v >> (56 - 8 * i)) & 0xFFu);
}

// 把字节串按指定字节序转成 32 位字数组（len 必须是 4 的倍数）
void BytesToWords32(const uint8_t* p, size_t len, bool big_endian, uint32_t* w) {
    for (size_t i = 0; i < len / 4; ++i) {
        w[i] = big_endian ? LoadBE32(p + i * 4) : LoadLE32(p + i * 4);
    }
}

// ===========================================================================
// 流式哈希通用上下文
//   — 分块压缩，最后补位：先补 0x80，再补 0 到 (block - 长度域) 的倍数，
//     长度域为「累计比特数」的大端/小端表示（16 字节，高 8 字节在前）。
// ===========================================================================
struct StreamHash {
    int      block = 0;         // 分块字节数（64 或 128）
    int      digest_len = 0;    // 摘要字节数
    bool     big_endian = false;  // 长度域与分组字是否按大端解释
    uint8_t  buf[128] = {0};    // 未满一块的残留数据
    size_t   buf_len = 0;       // 残留字节数
    uint64_t total_lo = 0;      // 累计字节数低 64 位
    uint64_t total_hi = 0;      // 累计字节数高 64 位（超过 2^64 字节时用）
    uint32_t h32[8] = {0};      // 32 位家族的中间状态
    uint64_t h64[8] = {0};      // 64 位家族的中间状态
    void (*compress)(StreamHash&, const uint8_t*) = nullptr;  // 压缩函数

    void Update(const uint8_t* data, size_t len) {
        // 累计总长度
        uint64_t old = total_lo;
        total_lo += static_cast<uint64_t>(len);
        if (total_lo < old) ++total_hi;

        if (buf_len > 0) {
            size_t need = static_cast<size_t>(block) - buf_len;
            size_t take = len < need ? len : need;
            for (size_t i = 0; i < take; ++i) buf[buf_len + i] = data[i];
            buf_len += take;
            data += take;
            len -= take;
            if (buf_len == static_cast<size_t>(block)) {
                compress(*this, buf);
                buf_len = 0;
            }
        }
        while (len >= static_cast<size_t>(block)) {
            compress(*this, data);
            data += block;
            len -= static_cast<size_t>(block);
        }
        for (size_t i = 0; i < len; ++i) buf[buf_len + i] = data[i];
        buf_len += len;
    }

    void Final(uint8_t* out) {
        // 累计比特数（低 64 位左移 3，进位并入高位）
        uint64_t bits_hi = (total_hi << 3) | (total_lo >> 61);
        uint64_t bits_lo = total_lo << 3;

        // 长度域大小（字节）：
        //   SHA-384 / SHA-512  —— 16 字节（128 位长度），位于块的最后 16 字节
        //   MD5 / SHA-1 / SHA-256 家族 —— 8 字节（64 位长度），位于块的最后 8 字节
        // 【曾经的 bug】这里原先统一按 16 字节处理，于是长度值被写到 48..55，
        //   而真正的长度域 56..63 留成 0。空消息因为长度本就是 0 而碰巧正确，
        //   任何非空消息的摘要都全错。
        const size_t bs        = static_cast<size_t>(block);
        const size_t len_field = (bs == 128) ? 16 : 8;

        uint8_t blocks[128 * 2] = {0};   // 补位后最多产生 2 个分组
        for (size_t i = 0; i < buf_len; ++i) blocks[i] = buf[i];
        blocks[buf_len] = 0x80;          // 先补一个 1 比特

        // 长度域能否与 0x80 同组：能则总长 1 组，不能则 2 组
        bool   two_blocks = (buf_len + 1 + len_field > bs);
        size_t total      = two_blocks ? bs * 2 : bs;

        // 长度域写在最后一个分组的末尾
        uint8_t* lenpos = blocks + total - len_field;
        if (bs == 128) {
            // SHA-384 / SHA-512：128 位大端
            StoreBE64(lenpos, bits_hi);
            StoreBE64(lenpos + 8, bits_lo);
        } else if (big_endian) {
            // SHA-224 / SHA-256：64 位大端
            StoreBE64(lenpos, bits_lo);
        } else {
            // MD5 / SHA-1：64 位小端
            StoreLE64(lenpos, bits_lo);
        }

        compress(*this, blocks);
        if (two_blocks) compress(*this, blocks + bs);

        // 【曾经的 bug】这里原先直接往 out 写满 32 / 64 字节，
        // 但调用方按 digest_len 分配（md5 只要 16 字节、sha224 只要 28 字节），
        // 越界写会直接踩坏堆。改为先写满临时缓冲再按 digest_len 截断。
        uint8_t full[64];
        if (block == 64) {
            // 输出字节序：MD5 是小端，SHA-1 / SHA-224 / SHA-256 是大端。
            // 【曾经的 bug】这里原先无差别用 StoreLE32，导致 SHA 家族的每个 32 位字
            //   被整体反转（如 ba7816bf 写成 bf1678ba），摘要全错。
            for (int i = 0; i < 8; ++i) {
                if (big_endian) {
                    StoreBE32(full + i * 4, h32[i]);
                } else {
                    StoreLE32(full + i * 4, h32[i]);
                }
            }
        } else {
            for (int i = 0; i < 8; ++i) StoreBE64(full + i * 8, h64[i]);
        }
        for (int i = 0; i < digest_len; ++i) out[i] = full[i];
    }

    void Finish(uint8_t* out) { Final(out); }
};

// ===========================================================================
// MD5（RFC 1321）
// ===========================================================================
const uint32_t kMd5K[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au,
    0xa8304613u, 0xfd469501u, 0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u, 0xf61e2562u, 0xc040b340u,
    0x265e5a51u, 0xe9b6c7aau, 0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u,
    0x676f02d9u, 0x8d2a4c8au, 0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u, 0x289b7ec6u, 0xeaa127fau,
    0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u,
    0xffeff47du, 0x85845dd1u, 0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u};

const uint32_t kMd5S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                            5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

void Md5Compress(StreamHash& c, const uint8_t* blk) {
    uint32_t m[16];
    BytesToWords32(blk, 64, false, m);

    uint32_t a = c.h32[0], b = c.h32[1], cc = c.h32[2], d = c.h32[3];
    for (int i = 0; i < 64; ++i) {
        uint32_t f;
        int      g;
        if (i < 16) {
            f = (b & cc) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & cc);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ cc ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = cc ^ (b | ~d);
            g = (7 * i) % 16;
        }
        f = f + a + kMd5K[i] + m[g];
        a = d;
        d = cc;
        cc = b;
        b = b + Rotl32(f, kMd5S[i]);
    }
    c.h32[0] += a;
    c.h32[1] += b;
    c.h32[2] += cc;
    c.h32[3] += d;
}

void Md5Init(StreamHash& c) {
    c.block      = 64;
    c.digest_len = 16;
    c.big_endian = false;
    c.buf_len    = 0;
    c.total_lo = c.total_hi = 0;
    c.compress   = Md5Compress;
    c.h32[0] = 0x67452301u;
    c.h32[1] = 0xefcdab89u;
    c.h32[2] = 0x98badcfeu;
    c.h32[3] = 0x10325476u;
}

// ===========================================================================
// MD4（RFC 1320）—— 仅用于 NTLM
// ===========================================================================
void Md4Compress(StreamHash& c, const uint8_t* blk) {
    uint32_t x[16];
    BytesToWords32(blk, 64, false, x);

    uint32_t v[4] = {c.h32[0], c.h32[1], c.h32[2], c.h32[3]};

    auto F = [](uint32_t p, uint32_t q, uint32_t r) { return (p & q) | (~p & r); };
    auto G = [](uint32_t p, uint32_t q, uint32_t r) { return (p & q) | (p & r) | (q & r); };
    auto H = [](uint32_t p, uint32_t q, uint32_t r) { return p ^ q ^ r; };

    // 【曾经的 bug】原先的写法是「结果写回 d，然后 a←b, b←c, c←d」，
    //   这与 RFC 1320 的 [ABCD] [DABC] [CDAB] [BCDA] 轮换顺序并不等价，
    //   导致 MD4（以及依赖它的 NTLM）摘要全错。
    // 正确做法：每步都更新 v[0]，然后把 v[0] 移到队尾（即整体右旋一位）。
    //   这样第 2/3/4 步天然分别落在 d / c / b 上，与标准一致。
    auto Step = [&](uint32_t t, uint32_t s) {
        v[0] = Rotl32(t, s);
        uint32_t t0 = v[0], t1 = v[1], t2 = v[2], t3 = v[3];
        v[0] = t3;
        v[1] = t0;
        v[2] = t1;
        v[3] = t2;
    };

    // 第 1 轮：F(x,y,z) = (x & y) | (~x & z)，消息顺序 0..15
    {
        static const uint32_t sr[4] = {3, 7, 11, 19};
        for (int i = 0; i < 16; ++i) {
            Step(v[0] + F(v[1], v[2], v[3]) + x[i], sr[i % 4]);
        }
    }

    // 第 2 轮：G，常数 0x5A827999，消息顺序 0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15
    {
        static const uint32_t sr[4] = {3, 5, 9, 13};
        for (int i = 0; i < 16; ++i) {
            uint32_t k = static_cast<uint32_t>(i / 4) + 4u * static_cast<uint32_t>(i % 4);
            Step(v[0] + G(v[1], v[2], v[3]) + x[k] + 0x5A827999u, sr[i % 4]);
        }
    }

    // 第 3 轮：H(x,y,z) = x ^ y ^ z，常数 0x6ED9EBA1
    {
        static const uint32_t sr[4]    = {3, 9, 11, 15};
        static const uint32_t order[16] = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};
        for (int i = 0; i < 16; ++i) {
            Step(v[0] + H(v[1], v[2], v[3]) + x[order[i]] + 0x6ED9EBA1u, sr[i % 4]);
        }
    }

    c.h32[0] += v[0];
    c.h32[1] += v[1];
    c.h32[2] += v[2];
    c.h32[3] += v[3];
}

void Md4Init(StreamHash& c) {
    c.block      = 64;
    c.digest_len = 16;
    c.big_endian = false;
    c.buf_len    = 0;
    c.total_lo = c.total_hi = 0;
    c.compress   = Md4Compress;
    c.h32[0] = 0x67452301u;
    c.h32[1] = 0xefcdab89u;
    c.h32[2] = 0x98badcfeu;
    c.h32[3] = 0x10325476u;
}

// ===========================================================================
// SHA-1（RFC 3174）
// ===========================================================================
void Sha1Compress(StreamHash& c, const uint8_t* blk) {
    uint32_t w[80];
    BytesToWords32(blk, 64, true, w);
    for (int i = 16; i < 80; ++i) {
        w[i] = Rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = c.h32[0], b = c.h32[1], cc = c.h32[2], d = c.h32[3], e = c.h32[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & cc) | (~b & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ cc ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & cc) | (b & d) | (cc & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ cc ^ d;
            k = 0xCA62C1D6u;
        }
        uint32_t tmp = Rotl32(a, 5) + f + e + k + w[i];
        e  = d;
        d  = cc;
        cc = Rotl32(b, 30);
        b  = a;
        a  = tmp;
    }
    c.h32[0] += a;
    c.h32[1] += b;
    c.h32[2] += cc;
    c.h32[3] += d;
    c.h32[4] += e;
}

void Sha1Init(StreamHash& c) {
    c.block      = 64;
    c.digest_len = 20;
    c.big_endian = true;
    c.buf_len    = 0;
    c.total_lo = c.total_hi = 0;
    c.compress   = Sha1Compress;
    c.h32[0] = 0x67452301u;
    c.h32[1] = 0xEFCDAB89u;
    c.h32[2] = 0x98BADCFEu;
    c.h32[3] = 0x10325476u;
    c.h32[4] = 0xC3D2E1F0u;
}

// ===========================================================================
// SHA-256 / SHA-224（FIPS 180-4）
// ===========================================================================
const uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

void Sha256Compress(StreamHash& c, const uint8_t* blk) {
    uint32_t w[64];
    BytesToWords32(blk, 64, true, w);
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = Rotr32(w[i - 15], 7) ^ Rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = Rotr32(w[i - 2], 17) ^ Rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = c.h32[0], b = c.h32[1], cc = c.h32[2], d = c.h32[3];
    uint32_t e = c.h32[4], f = c.h32[5], g = c.h32[6], h = c.h32[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1    = Rotr32(e, 6) ^ Rotr32(e, 11) ^ Rotr32(e, 25);
        uint32_t ch    = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + kSha256K[i] + w[i];
        uint32_t S0    = Rotr32(a, 2) ^ Rotr32(a, 13) ^ Rotr32(a, 22);
        uint32_t maj   = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t temp2 = S0 + maj;
        h  = g;
        g  = f;
        f  = e;
        e  = d + temp1;
        d  = cc;
        cc = b;
        b  = a;
        a  = temp1 + temp2;
    }
    c.h32[0] += a;
    c.h32[1] += b;
    c.h32[2] += cc;
    c.h32[3] += d;
    c.h32[4] += e;
    c.h32[5] += f;
    c.h32[6] += g;
    c.h32[7] += h;
}

void Sha256Init(StreamHash& c) {
    c.block      = 64;
    c.digest_len = 32;
    c.big_endian = true;
    c.buf_len    = 0;
    c.total_lo = c.total_hi = 0;
    c.compress   = Sha256Compress;
    c.h32[0] = 0x6a09e667u;
    c.h32[1] = 0xbb67ae85u;
    c.h32[2] = 0x3c6ef372u;
    c.h32[3] = 0xa54ff53au;
    c.h32[4] = 0x510e527fu;
    c.h32[5] = 0x9b05688cu;
    c.h32[6] = 0x1f83d9abu;
    c.h32[7] = 0x5be0cd19u;
}

// SHA-224 = SHA-256 换初值 + 截断 28 字节
void Sha224Init(StreamHash& c) {
    Sha256Init(c);
    c.digest_len = 28;
    c.h32[0] = 0xc1059ed8u;
    c.h32[1] = 0x367cd507u;
    c.h32[2] = 0x3070dd17u;
    c.h32[3] = 0xf70e5939u;
    c.h32[4] = 0xffc00b31u;
    c.h32[5] = 0x68581511u;
    c.h32[6] = 0x64f98fa7u;
    c.h32[7] = 0xbefa4fa4u;
}

// ===========================================================================
// SHA-512 / SHA-384（FIPS 180-4）
// ===========================================================================
const uint64_t kSha512K[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull};

void Sha512Compress(StreamHash& c, const uint8_t* blk) {
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) w[i] = LoadBE64(blk + i * 8);
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = Rotl64(w[i - 15], 63) ^ Rotl64(w[i - 15], 56) ^ (w[i - 15] >> 7);
        uint64_t s1 = Rotl64(w[i - 2], 45) ^ Rotl64(w[i - 2], 3) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = c.h64[0], b = c.h64[1], cc = c.h64[2], d = c.h64[3];
    uint64_t e = c.h64[4], f = c.h64[5], g = c.h64[6], h = c.h64[7];
    for (int i = 0; i < 80; ++i) {
        // 【曾经的 bug】Σ0/Σ1 的旋转量写错了（写成了 36/19/28 与 50/43/39）。
        // FIPS 180-4 规定：
        //   Σ0(a) = ROTR^28 ^ ROTR^34 ^ ROTR^39  =>  用左移表示为 ROTL 36/30/25
        //   Σ1(e) = ROTR^14 ^ ROTR^18 ^ ROTR^41  =>  用左移表示为 ROTL 50/46/23
        uint64_t S1    = Rotl64(e, 50) ^ Rotl64(e, 46) ^ Rotl64(e, 23);
        uint64_t ch    = (e & f) ^ (~e & g);
        uint64_t temp1 = h + S1 + ch + kSha512K[i] + w[i];
        uint64_t S0    = Rotl64(a, 36) ^ Rotl64(a, 30) ^ Rotl64(a, 25);
        uint64_t maj   = (a & b) ^ (a & cc) ^ (b & cc);
        uint64_t temp2 = S0 + maj;
        h  = g;
        g  = f;
        f  = e;
        e  = d + temp1;
        d  = cc;
        cc = b;
        b  = a;
        a  = temp1 + temp2;
    }
    c.h64[0] += a;
    c.h64[1] += b;
    c.h64[2] += cc;
    c.h64[3] += d;
    c.h64[4] += e;
    c.h64[5] += f;
    c.h64[6] += g;
    c.h64[7] += h;
}

void Sha512Init(StreamHash& c) {
    c.block      = 128;
    c.digest_len = 64;
    c.big_endian = true;
    c.buf_len    = 0;
    c.total_lo = c.total_hi = 0;
    c.compress   = Sha512Compress;
    c.h64[0] = 0x6a09e667f3bcc908ull;
    c.h64[1] = 0xbb67ae8584caa73bull;
    c.h64[2] = 0x3c6ef372fe94f82bull;
    c.h64[3] = 0xa54ff53a5f1d36f1ull;
    c.h64[4] = 0x510e527fade682d1ull;
    c.h64[5] = 0x9b05688c2b3e6c1full;
    c.h64[6] = 0x1f83d9abfb41bd6bull;
    c.h64[7] = 0x5be0cd19137e2179ull;
}

// SHA-384 = SHA-512 换初值 + 截断 48 字节
void Sha384Init(StreamHash& c) {
    Sha512Init(c);
    c.digest_len = 48;
    c.h64[0] = 0xcbbb9d5dc1059ed8ull;
    c.h64[1] = 0x629a292a367cd507ull;
    c.h64[2] = 0x9159015a3070dd17ull;
    c.h64[3] = 0x152fecd8f70e5939ull;
    c.h64[4] = 0x67332667ffc00b31ull;
    c.h64[5] = 0x8eb44a8768581511ull;
    c.h64[6] = 0xdb0c2e0d64f98fa7ull;
    c.h64[7] = 0x47b5481dbefa4fa4ull;
}

// ===========================================================================
// 统一的「哈希算法描述表」
// ===========================================================================
using InitFn = void (*)(StreamHash&);

enum HashAlgo {
    kMd5 = 0,
    kSha1,
    kSha224,
    kSha256,
    kSha384,
    kSha512,
    kMd4,
    kHashAlgoCount
};

struct HashSpec {
    const char* name;
    InitFn      init;
    size_t      block_size;  // HMAC 用的分块长度
};

const HashSpec kHashSpecs[kHashAlgoCount] = {
    {"md5", Md5Init, 64},
    {"sha1", Sha1Init, 64},
    {"sha224", Sha224Init, 64},
    {"sha256", Sha256Init, 64},
    {"sha384", Sha384Init, 128},
    {"sha512", Sha512Init, 128},
    {"md4", Md4Init, 64},
};

// 一次性算完整摘要
Bytes HashOnce(HashAlgo algo, const Bytes& data) {
    StreamHash c;
    kHashSpecs[algo].init(c);
    if (!data.empty()) c.Update(data.data(), data.size());
    Bytes out(static_cast<size_t>(c.digest_len));
    c.Finish(out.data());
    return out;
}

// 解析 "upper" 参数
bool ParamUpper(const Params& p) { return p.GetInt("upper", 0) != 0; }

// 解析 "raw" 参数（raw=1 输出原始摘要字节，否则输出 hex 串）
bool ParamRaw(const Params& p) { return p.GetInt("raw", 0) != 0; }

// 通用的哈希编解码函数：hex 或原始字节
void HashEncode(HashAlgo algo, const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    Bytes digest = HashOnce(algo, in);
    if (ParamRaw(p)) {
        out = digest;
        return;
    }
    out = ToBytes(HexEncode(digest, ParamUpper(p)));
}

// ===========================================================================
// HMAC（RFC 2104）
// ===========================================================================
Bytes HmacCompute(HashAlgo algo, const Bytes& key, const Bytes& msg) {
    const HashSpec& spec = kHashSpecs[algo];
    const size_t    bs   = spec.block_size;

    // 密钥长度超过分块长度时先哈希一次
    Bytes k = key;
    if (k.size() > bs) k = HashOnce(algo, k);

    // ipad / opad
    Bytes ipad(bs, 0x36), opad(bs, 0x5C);
    for (size_t i = 0; i < k.size(); ++i) {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    // H((K ^ ipad) || msg)
    StreamHash inner;
    spec.init(inner);
    inner.Update(ipad.data(), ipad.size());
    if (!msg.empty()) inner.Update(msg.data(), msg.size());
    Bytes inner_digest(static_cast<size_t>(inner.digest_len));
    inner.Finish(inner_digest.data());

    // H((K ^ opad) || inner)
    StreamHash outer;
    spec.init(outer);
    outer.Update(opad.data(), opad.size());
    outer.Update(inner_digest.data(), inner_digest.size());
    Bytes digest(static_cast<size_t>(outer.digest_len));
    outer.Finish(digest.data());
    return digest;
}

void HmacEncode(HashAlgo algo, const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    Bytes key = p.RequireKey();   // key_hex 优先，否则 key 按 UTF-8 文本
    Bytes mac = HmacCompute(algo, key, in);
    if (ParamRaw(p)) {
        out = mac;
        return;
    }
    out = ToBytes(HexEncode(mac, ParamUpper(p)));
}

// ===========================================================================
// NTLM 哈希 = MD4(UTF-16LE(密码))，其中密码按 UTF-8 文本解释
// ===========================================================================
Bytes Utf8ToUtf16Le(const std::string& s) {
    Bytes out;
    out.reserve(s.size() * 2);
    for (size_t i = 0; i < s.size();) {
        uint32_t cp = 0;
        unsigned char b = static_cast<unsigned char>(s[i]);
        size_t n = 1;
        if (b < 0x80) {
            cp = b;
        } else if ((b & 0xE0) == 0xC0) {
            cp = b & 0x1Fu;
            n  = 2;
        } else if ((b & 0xF0) == 0xE0) {
            cp = b & 0x0Fu;
            n  = 3;
        } else if ((b & 0xF8) == 0xF0) {
            cp = b & 0x07u;
            n  = 4;
        } else {
            // 非法起始字节，按单字节原样处理（容错）
            cp = b;
            n  = 1;
        }
        if (i + n > s.size()) n = 1;  // 截断的多字节序列，容错处理
        for (size_t j = 1; j < n; ++j) {
            cp = (cp << 6) | (static_cast<unsigned char>(s[i + j]) & 0x3Fu);
        }
        i += n;

        if (cp <= 0xFFFF) {
            out.push_back(static_cast<uint8_t>(cp & 0xFFu));
            out.push_back(static_cast<uint8_t>((cp >> 8) & 0xFFu));
        } else {
            // 转成代理对
            uint32_t v = cp - 0x10000u;
            uint16_t hi = static_cast<uint16_t>(0xD800u + (v >> 10));
            uint16_t lo = static_cast<uint16_t>(0xDC00u + (v & 0x3FFu));
            out.push_back(static_cast<uint8_t>(hi & 0xFFu));
            out.push_back(static_cast<uint8_t>(hi >> 8));
            out.push_back(static_cast<uint8_t>(lo & 0xFFu));
            out.push_back(static_cast<uint8_t>(lo >> 8));
        }
    }
    return out;
}

void NtlmEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    std::string pw = Str(in);            // NTLM 的输入是密码文本
    Bytes       u16 = Utf8ToUtf16Le(pw);
    Bytes       digest = HashOnce(kMd4, u16);
    if (ParamRaw(p)) {
        out = digest;
        return;
    }
    out = ToBytes(HexEncode(digest, ParamUpper(p)));
}

// ===========================================================================
// CRC32 / CRC32C
// ===========================================================================
// 反射式 CRC-32：poly 传入的是「反射后的多项式」（标准 CRC-32 = 0xEDB88320）
uint32_t Crc32Reflected(const Bytes& in, uint32_t poly_reflected) {
    uint32_t table[256];
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1u) ? (poly_reflected ^ (c >> 1)) : (c >> 1);
        }
        table[i] = c;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : in) {
        crc = table[(crc ^ b) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

// 解析十六进制/十进制字面量（用于 poly 参数）
uint32_t ParseUint32Literal(const std::string& s, const std::string& what) {
    std::string t = Trim(s);
    if (t.empty()) throw Error("参数 " + what + " 为空");
    int base = 16;
    size_t pos = 0;
    if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
        base = 16;
        pos  = 2;
    } else if (t[0] == '$') {
        base = 16;
        pos  = 1;
    } else {
        // 纯十进制数字且长度不足 8 位时按十进制，否则按十六进制
        bool all_dec = true;
        for (char c : t) {
            if (c < '0' || c > '9') {
                all_dec = false;
                break;
            }
        }
        base = (all_dec && t.size() < 8) ? 10 : 16;
    }
    if (pos >= t.size()) throw Error("参数 " + what + " 不是合法整数: " + t);
    uint64_t v = 0;
    for (size_t i = pos; i < t.size(); ++i) {
        int d = HexVal(t[i]);
        if (base == 10 && (t[i] < '0' || t[i] > '9')) d = -1;
        if (d < 0 || d >= base) throw Error("参数 " + what + " 不是合法整数: " + t);
        v = v * static_cast<uint64_t>(base) + static_cast<uint64_t>(d);
        if (v > 0xFFFFFFFFull) throw Error("参数 " + what + " 超出 32 位范围: " + t);
    }
    return static_cast<uint32_t>(v);
}

void Crc32Encode(const Bytes& in, const Params& p, Bytes& out, uint32_t default_poly) {
    out.clear();
    uint32_t poly = default_poly;
    if (p.Has("poly")) {
        poly = ParseUint32Literal(p.Get("poly"), "poly");
    }
    uint32_t crc = Crc32Reflected(in, poly);
    // 输出 8 位 hex（大端表示：高位在前）
    out = ToBytes(Format("%08x", crc));
    if (ParamUpper(p)) {
        out = ToBytes(ToUpper(Str(out)));
    }
}

// ===========================================================================
// CRC16 常见变体
//   name       poly      init      refin/refout  xorout  check("123456789")
//   modbus     0x8005    0xFFFF    是            0x0000  0x4B37
//   ibm/arc    0x8005    0x0000    是            0x0000  0xBB3D
//   ccitt-false 0x1021   0xFFFF    否            0x0000  0x29B1
//   xmodem     0x1021    0x0000    否            0x0000  0x31C3
//
// 实现方式：反射(refin)变体把多项式取反射值(0x8005->0xA001)后做右移表驱动；
//           非反射变体直接用正常多项式做左移表驱动。两族的 check 值都已用
//           逐位参考实现独立验证过（见最终报告）。
// 注意：xmodem 按「CRC RevEng 目录」的 check 值 0x31C3 定义，即非反射左移；
//       若要的是那种 poly=0x8408 逐位右移的 XMODEM 变体，结果是 0x2189，
//       与目录 check 值不符，故此处不采用。
// ===========================================================================
struct Crc16Spec {
    const char* name;
    uint16_t    poly;       // 正常形式多项式
    uint16_t    init;
    bool        refin;      // 是否反射（refin == refout）
    uint16_t    xorout;
};

const Crc16Spec kCrc16Specs[] = {
    {"modbus", 0x8005, 0xFFFF, true, 0x0000},
    {"ibm", 0x8005, 0x0000, true, 0x0000},
    {"ccitt", 0x1021, 0xFFFF, false, 0x0000},
    {"xmodem", 0x1021, 0x0000, false, 0x0000},
};

uint16_t Reflect16(uint16_t v) {
    uint16_t r = 0;
    for (int i = 0; i < 16; ++i) {
        if (v & (1u << i)) r |= static_cast<uint16_t>(1u << (15 - i));
    }
    return r;
}

uint16_t Crc16Compute(const Bytes& in, const Crc16Spec& spec) {
    uint16_t crc = spec.init;
    if (spec.refin) {
        // 反射：多项式取反射值，表驱动右移
        uint16_t poly = Reflect16(spec.poly);
        uint16_t table[256];
        for (uint32_t i = 0; i < 256; ++i) {
            uint16_t c = static_cast<uint16_t>(i);
            for (int k = 0; k < 8; ++k) {
                c = (c & 1u) ? static_cast<uint16_t>(poly ^ (c >> 1)) : static_cast<uint16_t>(c >> 1);
            }
            table[i] = c;
        }
        for (uint8_t b : in) {
            crc = static_cast<uint16_t>(table[(crc ^ b) & 0xFFu] ^ (crc >> 8));
        }
    } else {
        // 非反射：表驱动左移
        uint16_t table[256];
        for (uint32_t i = 0; i < 256; ++i) {
            uint16_t c = static_cast<uint16_t>(i << 8);
            for (int k = 0; k < 8; ++k) {
                c = (c & 0x8000u) ? static_cast<uint16_t>((c << 1) ^ spec.poly)
                                  : static_cast<uint16_t>(c << 1);
            }
            table[i] = c;
        }
        for (uint8_t b : in) {
            crc = static_cast<uint16_t>(table[((crc >> 8) ^ b) & 0xFFu] ^ (crc << 8));
        }
    }
    return static_cast<uint16_t>(crc ^ spec.xorout);
}

void Crc16Encode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    std::string variant = ToLower(Trim(p.Get("variant", "modbus")));
    if (variant.empty()) variant = "modbus";

    const Crc16Spec* spec = nullptr;
    for (const auto& s : kCrc16Specs) {
        if (variant == s.name) {
            spec = &s;
            break;
        }
    }
    // 常见别名的宽松匹配
    if (!spec) {
        if (variant == "crc16" || variant == "arc") spec = &kCrc16Specs[1];
        if (variant == "ccitt-false" || variant == "ccitt_false" || variant == "false") {
            spec = &kCrc16Specs[2];
        }
        if (variant == "zmodem" || variant == "x-25" || variant == "x25") spec = &kCrc16Specs[3];
    }
    if (!spec) {
        throw Error("未知的 crc16 变体: " + variant +
                    "（可选 modbus / ibm / ccitt / xmodem）");
    }

    uint16_t crc = Crc16Compute(in, *spec);
    out = ToBytes(Format("%04x", static_cast<unsigned>(crc)));
    if (ParamUpper(p)) out = ToBytes(ToUpper(Str(out)));
}

// ===========================================================================
// Adler-32（RFC 1950）
// ===========================================================================
void Adler32Encode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const uint32_t kMod = 65521u;
    uint32_t       a = 1, b = 0;
    for (uint8_t c : in) {
        a = (a + c) % kMod;
        b = (b + a) % kMod;
    }
    uint32_t v = (b << 16) | a;
    out = ToBytes(Format("%08x", v));
    if (ParamUpper(p)) out = ToBytes(ToUpper(Str(out)));
}

// ===========================================================================
// Fletcher-16 / Fletcher-32
// ===========================================================================
void Fletcher16Encode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    uint32_t sum1 = 0, sum2 = 0;
    for (uint8_t c : in) {
        sum1 = (sum1 + c) % 255u;
        sum2 = (sum2 + sum1) % 255u;
    }
    uint32_t v = (sum2 << 8) | sum1;
    out = ToBytes(Format("%04x", v));
    if (ParamUpper(p)) out = ToBytes(ToUpper(Str(out)));
}

void Fletcher32Encode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    uint32_t sum1 = 0, sum2 = 0;
    for (uint8_t c : in) {
        sum1 = (sum1 + c) % 65535u;
        sum2 = (sum2 + sum1) % 65535u;
    }
    uint32_t v = (sum2 << 16) | sum1;
    out = ToBytes(Format("%08x", v));
    if (ParamUpper(p)) out = ToBytes(ToUpper(Str(out)));
}

}  // namespace

// ===========================================================================
// 注册入口
// ===========================================================================
void RegisterHash(Registry& r) {
    // ------------------------------- MD5 家族 -------------------------------
    r.Add("md5", "Hash", "MD5 摘要（128 位），可选 upper / raw", false, true,
          [](const Bytes& in, const Params& p, Bytes& out) { HashEncode(kMd5, in, p, out); },
          nullptr);

    r.Add("sha1", "Hash", "SHA-1 摘要（160 位），可选 upper / raw", false, true,
          [](const Bytes& in, const Params& p, Bytes& out) { HashEncode(kSha1, in, p, out); },
          nullptr);

    r.Add("sha224", "Hash", "SHA-224 摘要（224 位，SHA-256 截断版）", false, true,
          [](const Bytes& in, const Params& p, Bytes& out) { HashEncode(kSha224, in, p, out); },
          nullptr);

    r.Add("sha256", "Hash", "SHA-256 摘要（256 位），可选 upper / raw", false, true,
          [](const Bytes& in, const Params& p, Bytes& out) { HashEncode(kSha256, in, p, out); },
          nullptr);

    r.Add("sha384", "Hash", "SHA-384 摘要（384 位，SHA-512 截断版）", false, true,
          [](const Bytes& in, const Params& p, Bytes& out) { HashEncode(kSha384, in, p, out); },
          nullptr);

    r.Add("sha512", "Hash", "SHA-512 摘要（512 位），可选 upper / raw", false, true,
          [](const Bytes& in, const Params& p, Bytes& out) { HashEncode(kSha512, in, p, out); },
          nullptr);

    // ------------------------------ CRC / 校验和 ----------------------------
    r.Add("crc32", "Hash", "CRC-32/ISO-HDLC 校验和，poly 可换多项式", false, true,
          [](const Bytes& in, const Params& p, Bytes& out) {
              Crc32Encode(in, p, out, 0xEDB88320u);
          },
          nullptr);

    r.Add("crc32c", "Hash", "CRC-32C（Castagnoli，poly=0x82F63B78）", false, true,
          [](const Bytes& in, const Params& p, Bytes& out) {
              // 显式忽略 poly 参数，crc32c 固定用 Castagnoli
              Params q = p;
              q.Set("poly", "0x82F63B78");
              Crc32Encode(in, q, out, 0x82F63B78u);
          },
          nullptr);

    r.Add("crc16", "Hash", "CRC-16 校验和，variant=modbus/ibm/ccitt/xmodem", false, true,
          Crc16Encode, nullptr);

    r.Add("adler32", "Hash", "Adler-32 校验和（zlib 用）", false, true, Adler32Encode, nullptr);

    r.Add("fletcher16", "Hash", "Fletcher-16 校验和（双和模 255）", false, true,
          Fletcher16Encode, nullptr);

    r.Add("fletcher32", "Hash", "Fletcher-32 校验和（双和模 65535）", false, true,
          Fletcher32Encode, nullptr);

    // --------------------------------- HMAC ---------------------------------
    r.Add("hmac-md5", "Hash", "HMAC-MD5，需要 key 或 key_hex", false, true,
          [](const Bytes& in, const Params& p, Bytes& out) { HmacEncode(kMd5, in, p, out); },
          nullptr);

    r.Add("hmac-sha1", "Hash", "HMAC-SHA1，需要 key 或 key_hex", false, true,
          [](const Bytes& in, const Params& p, Bytes& out) { HmacEncode(kSha1, in, p, out); },
          nullptr);

    r.Add("hmac-sha256", "Hash", "HMAC-SHA256，需要 key 或 key_hex", false, true,
          [](const Bytes& in, const Params& p, Bytes& out) { HmacEncode(kSha256, in, p, out); },
          nullptr);

    r.Add("hmac-sha512", "Hash", "HMAC-SHA512，需要 key 或 key_hex", false, true,
          [](const Bytes& in, const Params& p, Bytes& out) { HmacEncode(kSha512, in, p, out); },
          nullptr);

    // --------------------------------- NTLM ---------------------------------
    r.Add("ntlm", "Hash", "NTLM 哈希 = MD4(UTF-16LE(密码))", false, true, NtlmEncode, nullptr);
}

}  // namespace ctf
