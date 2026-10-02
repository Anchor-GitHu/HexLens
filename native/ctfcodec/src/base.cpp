// base.cpp —— Base 家族编解码算法（Base16/32/36/45/58/58check/62/64/85/91/92/100 ...）
//
// 设计约定（与 common.h / util.h 契约一致）：
//   1. 每个 CodecFn 先 out.clear()，失败统一 throw Error("中文错误信息")；
//   2. 解码一律容忍空白与换行（CTF 里粘贴的编码串经常带折行）；
//   3. 全部二进制安全，空输入 -> 空输出，不崩溃；
//   4. 只用标准库，零第三方依赖。
//
// 说明：base58check / radix64 需要摘要与校验，本文件在匿名 namespace 里自带
//       一份精简的 SHA-256 与 CRC-24，避免依赖其他算法模块（hash.cpp 等）。
#include "common.h"
#include "util.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace ctf {
namespace {

// ===========================================================================
// 一、通用小工具
// ===========================================================================

// 判断是否是 ASCII 空白（解码时全部跳过）
bool IsSpaceChar(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

// 参数开关：值非空且不是 "0"/"false"/"no" 视为真
bool ParamFlag(const Params& p, const std::string& key, bool def) {
    if (!p.Has(key)) return def;
    const std::string v = ToLower(Trim(p.Get(key)));
    if (v.empty()) return true;   // "pad" 这种只有键名的写法等于开启
    if (v == "0" || v == "false" || v == "no" || v == "off") return false;
    return true;
}

// 展开 "0-9A-Za-z" 这类区间描述；已经是字面字符表的原样返回
std::string ExpandAlphabetSpec(const std::string& spec) {
    if (spec.size() < 3) return spec;
    std::string out;
    for (size_t i = 0; i + 2 < spec.size() + 1 && i + 3 <= spec.size(); i += 3) {
        if (spec[i + 1] != '-') return spec;   // 不是区间写法，整体按字面处理
        const unsigned char from = static_cast<unsigned char>(spec[i]);
        const unsigned char to = static_cast<unsigned char>(spec[i + 2]);
        if (to < from) return spec;
        for (unsigned char c = from; c <= to; ++c) out.push_back(static_cast<char>(c));
    }
    return out.empty() ? spec : out;
}

// 构造「字符 -> 数值」反查表，非法字符位置为 -1。
// 大小写宽松只对「表里没有同时出现该字母大小写」的字母生效：
//   base32/64 这类大写表用起来可以吃小写输入；
//   base58/base62 这类大小写都算独立数字的表，绝不能折叠（否则 A 与 a 会撞车）。
std::array<int, 256> MakeLut(const std::string& alphabet) {
    std::array<int, 256> lut;
    lut.fill(-1);
    for (size_t i = 0; i < alphabet.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(alphabet[i]);
        Require(lut[c] < 0, Format("数字表中存在重复字符 '%c'", alphabet[i]));
        lut[c] = static_cast<int>(i);
    }

    bool hasUpper[26] = {false};
    bool hasLower[26] = {false};
    for (unsigned char c : alphabet) {
        if (c >= 'A' && c <= 'Z') hasUpper[c - 'A'] = true;
        if (c >= 'a' && c <= 'z') hasLower[c - 'a'] = true;
    }
    for (int k = 0; k < 26; ++k) {
        if (hasUpper[k] && hasLower[k]) continue;   // 大小写都是独立数字，不折叠
        const unsigned char up = static_cast<unsigned char>('A' + k);
        const unsigned char lo = static_cast<unsigned char>('a' + k);
        if (hasUpper[k] && lut[lo] < 0) lut[lo] = lut[up];
        if (hasLower[k] && lut[up] < 0) lut[up] = lut[lo];
    }
    return lut;
}

// 校验自定义数字表：长度足够、无重复字符、无空白
void ValidateAlphabet(const std::string& alphabet, size_t need, const char* what) {
    Require(alphabet.size() >= need, Format("%s 长度至少需要 %zu 个字符", what, need));
    std::array<bool, 256> seen{};
    for (unsigned char c : alphabet) {
        Require(!IsSpaceChar(static_cast<char>(c)), Format("%s 不能包含空白字符", what));
        Require(!seen[c], Format("%s 中存在重复字符 '%c'", what, c));
        seen[c] = true;
    }
}

// 去掉字符串里的所有 ASCII 空白（解码入口统一预处理）
std::string StripSpace(const Bytes& in) {
    std::string s;
    s.reserve(in.size());
    for (uint8_t c : in) {
        if (!IsSpaceChar(static_cast<char>(c))) s.push_back(static_cast<char>(c));
    }
    return s;
}

// 只去掉换行/制表/回车等控制空白，保留普通空格。
// base45 的字母表里 ' '(索引 36) 是合法符号，必须用这个版本做预处理。
std::string StripWhiteKeepSpace(const Bytes& in) {
    std::string s;
    s.reserve(in.size());
    for (uint8_t c : in) {
        const char ch = static_cast<char>(c);
        if (ch == ' ') {
            s.push_back(ch);
        } else if (!IsSpaceChar(ch)) {
            s.push_back(ch);
        }
    }
    return s;
}

// 去掉首尾的 ASCII 空白（含空格），中间原样保留
std::string TrimAscii(const std::string& s) {
    size_t b = 0;
    size_t e = s.size();
    while (b < e && IsSpaceChar(s[b])) ++b;
    while (e > b && IsSpaceChar(s[e - 1])) --e;
    return s.substr(b, e - b);
}

// ===========================================================================
// 二、字母表常量
// ===========================================================================
const char* kAlphaBase32Std = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const char* kAlphaBase32Hex = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
const char* kAlphaBase64Std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char* kAlphaBase64Url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const char* kAlphaBase45 =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
const char* kAlphaBase58Flickr =
    "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
const char* kAlphaZ85 =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
const char* kAlphaBase85Rfc =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
const char* kAlphaBase91 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\"";
const char* kAlphaBase92 =
    "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
    "abcdefghijklmnopqrstuvwxyz{|}~";

// ===========================================================================
// 三、SHA-256（仅内部使用：base58check 的 4 字节双哈希校验和）
//     以及 CRC-24（radix64 / OpenPGP 校验行）
// ===========================================================================
uint32_t RotR32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

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

// 单块压缩函数
void Sha256Block(uint32_t h[8], const uint8_t* block) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i * 4 + 0]) << 24) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(block[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 =
            RotR32(w[i - 15], 7) ^ RotR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 =
            RotR32(w[i - 2], 17) ^ RotR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t s1 = RotR32(e, 6) ^ RotR32(e, 11) ^ RotR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + s1 + ch + kSha256K[i] + w[i];
        uint32_t s0 = RotR32(a, 2) ^ RotR32(a, 13) ^ RotR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

Bytes Sha256(const Bytes& data) {
    uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                     0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

    size_t total = data.size();
    // 填充：0x80 + 若干 0x00，使长度 % 64 == 56，末尾 8 字节大端总比特数
    Bytes msg = data;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0x00);
    uint64_t bits = static_cast<uint64_t>(total) * 8u;
    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<uint8_t>((bits >> (i * 8)) & 0xFFu));
    }

    for (size_t off = 0; off < msg.size(); off += 64) {
        Sha256Block(h, msg.data() + off);
    }

    Bytes out;
    out.reserve(32);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((h[i] >> 24) & 0xFFu));
        out.push_back(static_cast<uint8_t>((h[i] >> 16) & 0xFFu));
        out.push_back(static_cast<uint8_t>((h[i] >> 8) & 0xFFu));
        out.push_back(static_cast<uint8_t>(h[i] & 0xFFu));
    }
    return out;
}

Bytes DoubleSha256(const Bytes& data) { return Sha256(Sha256(data)); }

// CRC-24（OpenPGP，多项式 0x1864CFB，初值 0xB704CE）
uint32_t Crc24(const Bytes& data) {
    uint32_t crc = 0xB704CEu;
    for (uint8_t byte : data) {
        crc ^= static_cast<uint32_t>(byte) << 16;
        for (int i = 0; i < 8; ++i) {
            crc <<= 1;
            if (crc & 0x1000000u) crc ^= 0x1864CFBu;
        }
    }
    return crc & 0xFFFFFFu;
}

// ===========================================================================
// 四、通用「大数进制」编解码（base36/58/62/85rfc/92 共用）
//     BigIntBaseConvert 会丢掉前导零，所以这里自己数前导零再拼回去。
// ===========================================================================

// --- 大数与字节串互转 ---
//
// 为什么不用 util.h 的 BigIntBaseConvert 一步到位？
//   它按「数字串」解释输入，从 base=16 转到 base=B 时会碰到两个坑：
//     1) 十六进制串中间/开头出现 '0' 时会被判成非法数字（base16 下 '0' 明明是 0）；
//     2) 前导零会被吃掉，无法还原原始字节长度。
//   所以这里把字节串按高字节优先拆成 base B 的「大端数字数组」，自己做长除法，
//   既能保留前导零（前导零字节单独计数），也不会误判任何字符。

// 把 body 转成 base 进制数字串（大端在前），全程只用 0..base-1 的数值，不依赖字符表
std::string ToBaseDigits(const Bytes& body, int base) {
    if (body.empty()) return std::string();
    Require(base >= 2 && base <= 256, "内部错误：进制超出范围");

    std::vector<int> v;
    v.reserve(body.size() + 1);
    v.push_back(0);   // 大端开始为 0，第一步会把第一个字节塞进去
    for (uint8_t byte : body) {
        int carry = byte;
        for (size_t i = v.size(); i-- > 0;) {
            const int cur = v[i] * 256 + carry;
            v[i] = cur % base;
            carry = cur / base;
        }
        while (carry > 0) {
            v.insert(v.begin(), carry % base);
            carry /= base;
        }
    }

    // 去掉前导零（保留至少一位）
    size_t start = 0;
    while (start + 1 < v.size() && v[start] == 0) ++start;
    std::string digits;
    digits.reserve(v.size() - start);
    for (size_t i = start; i < v.size(); ++i) {
        digits.push_back(static_cast<char>(v[i]));
    }
    return digits;
}

// base 进制数字串（大端）-> 字节数组（相当于 base -> 256 的长除法）
Bytes FromBaseDigits(const std::vector<int>& digits, int base) {
    if (digits.empty()) return Bytes();
    Require(base >= 2 && base <= 256, "内部错误：进制超出范围");

    std::vector<uint8_t> v;
    v.push_back(0);
    for (int d : digits) {
        Require(d >= 0 && d < base, "大数进制转换内部错误：数字超出进制范围");
        int carry = d;
        for (size_t i = v.size(); i-- > 0;) {
            const int cur = v[i] * base + carry;
            v[i] = static_cast<uint8_t>(cur % 256);
            carry = cur / 256;
        }
        while (carry > 0) {
            v.insert(v.begin(), static_cast<uint8_t>(carry % 256));
            carry /= 256;
        }
    }
    size_t start = 0;
    while (start + 1 < v.size() && v[start] == 0) ++start;
    return Bytes(v.begin() + static_cast<std::ptrdiff_t>(start), v.end());
}

// 取数字表：first 为「代表零值」的字符
Bytes DecodeBigInt(const std::string& data,
                   int                base,
                   const std::string& alphabet,
                   char               first) {
    // 逐字符映射成数值（MakeLut 已经做了大小写不敏感）
    const std::array<int, 256> lut = MakeLut(alphabet);
    size_t zeros = 0;
    while (zeros < data.size() && data[zeros] == first) ++zeros;

    std::vector<int> digits;
    digits.reserve(data.size());
    for (size_t i = zeros; i < data.size(); ++i) {
        const int d = lut[static_cast<unsigned char>(data[i])];
        Require(d >= 0 && d < base,
                Format("Base 解码遇到不属于字母表的字符 '%c'(位置 %zu)", data[i], i));
        digits.push_back(d);
    }
    // 去掉前导零数值（前导零字符已经单独记成 zeros 了）
    size_t start = 0;
    while (start < digits.size() && digits[start] == 0) ++start;
    const std::vector<int> trimmed(digits.begin() + static_cast<std::ptrdiff_t>(start),
                                   digits.end());

    Bytes out(zeros, 0x00);
    const Bytes tail = FromBaseDigits(trimmed, base);
    out.insert(out.end(), tail.begin(), tail.end());
    return out;
}

// 编码：返回数字串；data 全为零字节时输出若干个 first 字符
std::string EncodeBigInt(const Bytes& data,
                         int          base,
                         const std::string& alphabet,
                         char         first) {
    if (data.empty()) return std::string();

    size_t zeros = 0;
    while (zeros < data.size() && data[zeros] == 0x00) ++zeros;

    const Bytes body(data.begin() + static_cast<std::ptrdiff_t>(zeros), data.end());
    std::string s = ToBaseDigits(body, base);
    for (char& c : s) c = alphabet[static_cast<size_t>(static_cast<unsigned char>(c))];
    s.insert(s.begin(), zeros, first);
    return s;
}

// ===========================================================================
// 五、通用「位打包」编解码（base32 / base64 家族共用）
// ===========================================================================

// bitsPerChar 位一个字符；先算出全部内容字符，再按需补 '=' 与折行
void PackEncode(const Bytes&       in,
                Bytes&             out,
                const std::string& alphabet,
                int                bitsPerChar,
                bool               pad,
                int                lineLen) {
    out.clear();
    const size_t nBits = static_cast<size_t>(bitsPerChar);
    Bytes body;

    uint32_t buf = 0;
    size_t bitsLeft = 0;
    for (uint8_t b : in) {
        buf = (buf << 8) | b;
        bitsLeft += 8;
        while (bitsLeft >= nBits) {
            bitsLeft -= nBits;
            body.push_back(static_cast<uint8_t>(
                alphabet[static_cast<size_t>((buf >> bitsLeft) & ((1u << nBits) - 1u))]));
        }
    }
    if (bitsLeft > 0) {
        body.push_back(static_cast<uint8_t>(alphabet[static_cast<size_t>(
            (buf << (nBits - bitsLeft)) & ((1u << nBits) - 1u))]));
    }

    // 一个完整组（LCM(8, bitsPerChar)/8 字节）对应多少个输出字符
    size_t outGroup = 0;
    for (size_t t = nBits;; t += nBits) {
        if (t % 8 == 0) {
            outGroup = t / nBits;
            break;
        }
    }
    if (pad && outGroup > 0) {
        while (body.size() % outGroup != 0) body.push_back(static_cast<uint8_t>('='));
    }

    if (lineLen <= 0) {
        out.assign(body.begin(), body.end());
        return;
    }
    // 折行：只在行与行之间插 '\n'，末尾不留空行
    out.reserve(body.size() + body.size() / static_cast<size_t>(lineLen) + 1);
    const size_t perLine = static_cast<size_t>(lineLen);
    for (size_t i = 0; i < body.size(); ++i) {
        if (i > 0 && i % perLine == 0) out.push_back(static_cast<uint8_t>('\n'));
        out.push_back(body[i]);
    }
}

// 通用位打包解码
void DecodeBitPacked(const Bytes&        in,
                     Bytes&              out,
                     const std::string&  alphabet,
                     int                 bitsPerChar,
                     bool                tolerantTail,
                     const std::string&  extraChars = std::string()) {
    out.clear();
    std::array<int, 256> lut = MakeLut(alphabet);
    const size_t nBits = static_cast<size_t>(bitsPerChar);
    const size_t maxVal = (size_t{1} << nBits) - 1;

    // extraChars 里的字符是「同义字符」：第 i 个字符与 alphabet 的第
    // (k + i) 个字符等价，k = alphabet.size() - extraChars.size()。
    // 典型用途：base64 解码同时接受 +/ 与 -_。
    if (!extraChars.empty()) {
        Require(extraChars.size() <= alphabet.size(),
                "内部错误：同义字符数量超过字母表长度");
        const size_t base = alphabet.size() - extraChars.size();
        for (size_t i = 0; i < extraChars.size(); ++i) {
            const unsigned char c = static_cast<unsigned char>(extraChars[i]);
            if (lut[c] >= 0) continue;   // 已在表内（或已被更早的同义字符占用）
            lut[c] = static_cast<int>(base + i);
        }
    }

    uint32_t buf = 0;
    size_t bitsLeft = 0;
    for (uint8_t raw : in) {
        const char c = static_cast<char>(raw);
        if (IsSpaceChar(c) || c == '=') continue;   // 容忍折行与异常填充
        const int v = lut[static_cast<unsigned char>(c)];
        Require(v >= 0, Format("遇到非法字符 '%c'(0x%02X)", c, raw));
        // 数值必须放得进 bitsPerChar 位，否则下面按位与会被静默截断
        Require(static_cast<size_t>(v) <= maxVal,
                Format("字符 '%c' 的数值 %d 超出 %d 位表示范围，字母表配置有误", c, v,
                       bitsPerChar));
        buf = (buf << nBits) | static_cast<uint32_t>(v);
        bitsLeft += nBits;
        if (bitsLeft >= 8) {
            bitsLeft -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bitsLeft) & 0xFFu));
        }
    }
    // 收尾：剩余位只能是补出来的 0（不额外报错，宽松处理）
    if (bitsLeft > 0 && (buf & ((1u << bitsLeft) - 1u)) != 0 && !tolerantTail) {
        // 非零尾巴说明数据被截断或位序不对，这里给出明确错误
        throw Error("输入尾部存在非零填充位，数据可能被截断或损坏");
    }
}

// ===========================================================================
// 六、base16
// ===========================================================================
void Base16Enc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const bool upper = ParamFlag(p, "upper", false);
    out = ToBytes(HexEncode(in, upper));
}

void Base16Dec(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    // 宽松解析：容忍空白/换行/逗号/冒号/短横线/下划线以及 0x \x % 前缀
    int hi = -1;
    for (size_t i = 0; i < in.size(); ++i) {
        const char c = static_cast<char>(in[i]);
        if (IsSpaceChar(c) || c == ',' || c == ':' || c == '-' || c == '_') continue;
        if (c == '0' && i + 1 < in.size() &&
            (in[i + 1] == 'x' || in[i + 1] == 'X')) {
            ++i;
            continue;
        }
        if (c == '\\' && i + 1 < in.size() &&
            (in[i + 1] == 'x' || in[i + 1] == 'X')) {
            ++i;
            continue;
        }
        if (c == '%' && i + 1 < in.size()) continue;
        const int v = HexVal(c);
        Require(v >= 0, Format("Base16 含非法字符 '%c'(位置 %zu)", c, i));
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    Require(hi < 0, "Base16 输入长度为奇数，无法组成完整字节");
}

// ===========================================================================
// 七、base32 / base32hex（RFC 4648，5 bit 一字符）
// ===========================================================================
void RegisterBase32Style(Registry& r,
                         const std::string& name,
                         const std::string& help,
                         const char*        alphabet,
                         std::initializer_list<const char*> aliases) {
    const std::string alpha(alphabet);
    r.Add(name, "Base", help, true, true,
          [alpha](const Bytes& in, const Params& p, Bytes& out) {
              const bool pad = ParamFlag(p, "pad", true);
              PackEncode(in, out, alpha, 5, pad, 0);
          },
          [alpha](const Bytes& in, const Params&, Bytes& out) {
              DecodeBitPacked(in, out, alpha, 5, false);
          },
          aliases);
}

// ===========================================================================
// 八、base36（大数进制）
// ===========================================================================
void Base36Enc(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    out = ToBytes(EncodeBigInt(in, 36, kAlphaDigits36, '0'));
}

void Base36Dec(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    std::string s = StripSpace(in);
    // 容忍 0x 前缀（有些工具会带）
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
    if (s.empty()) return;
    const std::array<int, 256> lut = MakeLut(kAlphaDigits36);
    for (size_t i = 0; i < s.size(); ++i) {
        int v = lut[static_cast<unsigned char>(s[i])];
        Require(v >= 0 && v < 36, Format("Base36 含非法字符 '%c'(位置 %zu)", s[i], i));
    }
    out = DecodeBigInt(s, 36, kAlphaDigits36, '0');
}

// ===========================================================================
// 九、base45（RFC 9285）
// ===========================================================================
void Base45Enc(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    const std::string alpha(kAlphaBase45);
    size_t i = 0;
    while (i + 1 < in.size()) {
        unsigned v = (static_cast<unsigned>(in[i]) << 8) | in[i + 1];
        out.push_back(static_cast<uint8_t>(alpha[v % 45]));
        out.push_back(static_cast<uint8_t>(alpha[(v / 45) % 45]));
        out.push_back(static_cast<uint8_t>(alpha[v / 2025]));
        i += 2;
    }
    if (i < in.size()) {
        unsigned v = in[i];
        out.push_back(static_cast<uint8_t>(alpha[v % 45]));
        out.push_back(static_cast<uint8_t>(alpha[v / 45]));
    }
}

void Base45Dec(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    const std::string alpha(kAlphaBase45);
    const std::array<int, 256> lut = MakeLut(alpha);
    // 注意：字母表里 ' ' 本身是合法符号（索引 36），不能当空白整串删掉；
    // 只去掉换行/制表，并把首尾空白裁掉（CTF 里粘贴常带首尾空格与折行）
    const std::string s = StripWhiteKeepSpace(ToBytes(TrimAscii(Str(in))));

    std::vector<int> v;
    v.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        const int d = lut[static_cast<unsigned char>(s[i])];
        Require(d >= 0, Format("Base45 含非法字符 '%c'(位置 %zu)", s[i], i));
        v.push_back(d);
    }

    // 编码时从前往后两字节一组，因此只有「末尾」可能出现 2 字符组
    size_t i = 0;
    while (i + 3 <= v.size()) {
        const unsigned val = static_cast<unsigned>(v[i]) +
                             static_cast<unsigned>(v[i + 1]) * 45u +
                             static_cast<unsigned>(v[i + 2]) * 2025u;
        Require(val <= 0xFFFFu, "Base45 三元组数值溢出，数据非法");
        out.push_back(static_cast<uint8_t>((val >> 8) & 0xFFu));
        out.push_back(static_cast<uint8_t>(val & 0xFFu));
        i += 3;
    }
    const size_t rest = v.size() - i;
    Require(rest != 1, "Base45 输入长度非法（剩余 1 个字符，无法组成字节）");
    if (rest == 2) {
        const unsigned val =
            static_cast<unsigned>(v[i]) + static_cast<unsigned>(v[i + 1]) * 45u;
        Require(val <= 0xFFu, "Base45 双字符组数值溢出，数据非法");
        out.push_back(static_cast<uint8_t>(val));
    }
}

// ===========================================================================
// 十、base58 / base58check
//     alphabet=btc(默认) / ripple / flickr
// ===========================================================================
std::string Base58Alphabet(const Params& p) {
    const std::string name = ToLower(Trim(p.Get("alphabet", "btc")));
    if (name == "btc" || name == "bitcoin" || name == "base58") return kAlphaBase58;
    if (name == "ripple" || name == "xrp") return kAlphaBase58Ripple;
    if (name == "flickr") return kAlphaBase58Flickr;
    // 也允许直接传 58 个字符的自定义字母表
    if (name.size() >= 58) {
        ValidateAlphabet(name, 58, "alphabet");
        return name;
    }
    throw Error("未知的 base58 字母表: " + name + "（可选 btc / ripple / flickr）");
}

void Base58Enc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string alpha = Base58Alphabet(p);
    out = ToBytes(EncodeBigInt(in, 58, alpha, alpha[0]));
}

void Base58Dec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string alpha = Base58Alphabet(p);
    const std::string s = StripSpace(in);
    if (s.empty()) return;
    const std::array<int, 256> lut = MakeLut(alpha);
    for (size_t i = 0; i < s.size(); ++i) {
        Require(lut[static_cast<unsigned char>(s[i])] >= 0,
                Format("Base58 含非法字符 '%c'(位置 %zu)", s[i], i));
    }
    out = DecodeBigInt(s, 58, alpha, alpha[0]);
}

void Base58CheckEnc(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    Bytes payload = in;
    const Bytes sum = DoubleSha256(in);
    payload.insert(payload.end(), sum.begin(), sum.begin() + 4);

    const std::string alpha(kAlphaBase58);
    // 只把「真实 payload 的前导零字节」计成前导零字符；
    // 校验和字节自带的前导零不能算，否则解码时会误判长度。
    size_t zeros = 0;
    while (zeros < in.size() && in[zeros] == 0x00) ++zeros;
    const Bytes body(payload.begin() + static_cast<std::ptrdiff_t>(zeros), payload.end());
    const std::string digits = EncodeBigInt(body, 58, alpha, alpha[0]);
    out.assign(zeros, static_cast<uint8_t>(alpha[0]));
    out.insert(out.end(), digits.begin(), digits.end());
}

void Base58CheckDec(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    const std::string alpha(kAlphaBase58);
    const std::string s = StripSpace(in);
    if (s.empty()) return;
    const std::array<int, 256> lut = MakeLut(alpha);
    for (size_t i = 0; i < s.size(); ++i) {
        Require(lut[static_cast<unsigned char>(s[i])] >= 0,
                Format("Base58Check 含非法字符 '%c'(位置 %zu)", s[i], i));
    }
    // 与编码对称：前导的零值字符还原成前导零字节，其余交给大数还原
    const Bytes raw = DecodeBigInt(s, 58, alpha, alpha[0]);

    Require(raw.size() >= 4, "Base58Check 数据太短（至少需要 4 字节校验和）");

    const Bytes payload(raw.begin(), raw.end() - 4);
    const Bytes got(raw.end() - 4, raw.end());
    const Bytes sum = DoubleSha256(payload);
    Require(std::equal(got.begin(), got.end(), sum.begin()),
            "Base58Check 校验和不匹配（数据被篡改或不是 base58check）");
    out = payload;
}

// ===========================================================================
// 十一、base62（大数进制，默认 0-9A-Za-z）
// ===========================================================================
std::string Base62Alphabet(const Params& p) {
    const std::string name = p.Get("alphabet", "");
    if (name.empty() || ToLower(Trim(name)) == "std" || ToLower(Trim(name)) == "default") {
        return kAlphaDigits62;
    }
    const std::string expanded = ExpandAlphabetSpec(name);
    ValidateAlphabet(expanded, 62, "alphabet");
    return expanded;
}

void Base62Enc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string alpha = Base62Alphabet(p);
    out = ToBytes(EncodeBigInt(in, 62, alpha, alpha[0]));
}

void Base62Dec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string alpha = Base62Alphabet(p);
    const std::string s = StripSpace(in);
    if (s.empty()) return;
    const std::array<int, 256> lut = MakeLut(alpha);
    for (size_t i = 0; i < s.size(); ++i) {
        Require(lut[static_cast<unsigned char>(s[i])] >= 0,
                Format("Base62 含非法字符 '%c'(位置 %zu)", s[i], i));
    }
    out = DecodeBigInt(s, 62, alpha, alpha[0]);
}

// ===========================================================================
// 十二、base64 家族（标准 / url / radix64 / bcrypt / crypt）
// ===========================================================================

// 取 base64 字母表：url=1 用 URL-safe；alphabet=... 可显式覆盖（>=64 字符）
std::string Base64Alphabet(const Params& p, bool urlDefault) {
    const std::string custom = p.Get("alphabet", "");
    if (!custom.empty()) {
        // 允许写 "0-9A-Za-z" 这类区间描述，也允许直接给 64 个字符
        const std::string expanded = ExpandAlphabetSpec(custom);
        ValidateAlphabet(expanded, 64, "alphabet");
        return expanded;
    }
    if (urlDefault || ParamFlag(p, "url", false)) return kAlphaBase64Url;
    return kAlphaBase64Std;
}

// url-safe 与非 url-safe 经常混用：解码时把另一套的第 62/63 个字符当作同义字符。
// 注意不能直接改字母表本身，否则标准字符会被挤掉（+ / 会解不出来）。
std::string Base64AliasChars(const Params& p, bool urlDefault) {
    const std::string alpha = Base64Alphabet(p, urlDefault);
    if (alpha.size() < 64) return std::string();
    if (alpha[62] == '+' && alpha[63] == '/') return "-_";
    if (alpha[62] == '-' && alpha[63] == '_') return "+/";
    return std::string();
}

void Base64Enc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string alpha = Base64Alphabet(p, false);
    bool pad = ParamFlag(p, "pad", true);
    if (ParamFlag(p, "nopad", false)) pad = false;
    const int lineLen = p.GetInt("line", 0);
    Require(lineLen >= 0, "line 参数不能为负数");
    PackEncode(in, out, alpha, 6, pad, lineLen);
}

void Base64Dec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    DecodeBitPacked(in, out, Base64Alphabet(p, ParamFlag(p, "url", false)), 6, true,
                    Base64AliasChars(p, ParamFlag(p, "url", false)));
}

void Base64UrlEnc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string alpha = Base64Alphabet(p, true);
    bool pad = ParamFlag(p, "pad", false);          // base64url 默认不补 '='
    if (ParamFlag(p, "nopad", false)) pad = false;
    const int lineLen = p.GetInt("line", 0);
    Require(lineLen >= 0, "line 参数不能为负数");
    PackEncode(in, out, alpha, 6, pad, lineLen);
}

void Base64UrlDec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    DecodeBitPacked(in, out, Base64Alphabet(p, true), 6, true, Base64AliasChars(p, true));
}

// --- OpenPGP Radix-64：base64 + CRC24 校验行 ---
void Radix64Enc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string alpha = Base64Alphabet(p, false);
    const int lineLen = p.GetInt("line", 64);       // PGP 惯例 64 字符一行
    Require(lineLen >= 0, "line 参数不能为负数");

    Bytes body;
    PackEncode(in, body, alpha, 6, true, lineLen);
    // 校验行必须独占一行
    if (!body.empty() && body.back() != static_cast<uint8_t>('\n')) {
        body.push_back(static_cast<uint8_t>('\n'));
    }
    // CRC24 用标准 base64 表输出 4 个字符（AAAA 表示 0）
    const uint32_t crc = Crc24(in);
    Bytes crcBits;
    crcBits.push_back(static_cast<uint8_t>((crc >> 16) & 0xFFu));
    crcBits.push_back(static_cast<uint8_t>((crc >> 8) & 0xFFu));
    crcBits.push_back(static_cast<uint8_t>(crc & 0xFFu));
    Bytes crcText;
    PackEncode(crcBits, crcText, kAlphaBase64Std, 6, true, 0);

    out = body;
    out.push_back(static_cast<uint8_t>('='));
    out.insert(out.end(), crcText.begin(), crcText.end());
}

void Radix64Dec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();

    // 去掉空白后取末尾校验行：格式为 body + "\n=" + 4 个 base64 字符
    const std::string s = StripSpace(in);
    if (s.empty()) return;

    Require(s.size() >= 5, "Radix64 数据太短（至少需要校验行 =XXXX）");
    Require(s[s.size() - 5] == '=',
            "Radix64 缺少 CRC24 校验行（应以 =XXXX 结尾）");

    // 校验行固定是最后 5 个字符；正文里可能还带 base64 的尾部 '=' 填充，先剥掉
    const std::string crcStr = s.substr(s.size() - 4);
    std::string bodyStr = s.substr(0, s.size() - 5);
    while (!bodyStr.empty() && bodyStr.back() == '=') bodyStr.pop_back();

    const std::array<int, 256> lut = MakeLut(kAlphaBase64Std);
    uint32_t crcVal = 0;
    for (char c : crcStr) {
        int v = lut[static_cast<unsigned char>(c)];
        Require(v >= 0, Format("Radix64 校验行含非法字符 '%c'", c));
        crcVal = (crcVal << 6) | static_cast<uint32_t>(v);
    }
    crcVal &= 0xFFFFFFu;

    Bytes body = ToBytes(bodyStr);
    DecodeBitPacked(body, out, Base64Alphabet(p, false), 6, true, Base64AliasChars(p, false));

    Require(Crc24(out) == crcVal, "Radix64 CRC24 校验失败（数据被篡改或不是 radix64）");
}

// --- bcrypt / crypt(3)：固定字母表、无填充 ---
void EncodeBase64NoPad(const Bytes&       in,
                       Bytes&             out,
                       const std::string& alphabet) {
    out.clear();
    size_t i = 0;
    while (i + 3 <= in.size()) {
        uint32_t v = (static_cast<uint32_t>(in[i]) << 16) |
                     (static_cast<uint32_t>(in[i + 1]) << 8) |
                     static_cast<uint32_t>(in[i + 2]);
        out.push_back(static_cast<uint8_t>(alphabet[(v >> 18) & 0x3Fu]));
        out.push_back(static_cast<uint8_t>(alphabet[(v >> 12) & 0x3Fu]));
        out.push_back(static_cast<uint8_t>(alphabet[(v >> 6) & 0x3Fu]));
        out.push_back(static_cast<uint8_t>(alphabet[v & 0x3Fu]));
        i += 3;
    }
    const size_t rest = in.size() - i;
    if (rest == 1) {
        uint32_t v = static_cast<uint32_t>(in[i]) << 16;
        out.push_back(static_cast<uint8_t>(alphabet[(v >> 18) & 0x3Fu]));
        out.push_back(static_cast<uint8_t>(alphabet[(v >> 12) & 0x3Fu]));
    } else if (rest == 2) {
        uint32_t v = (static_cast<uint32_t>(in[i]) << 16) |
                     (static_cast<uint32_t>(in[i + 1]) << 8);
        out.push_back(static_cast<uint8_t>(alphabet[(v >> 18) & 0x3Fu]));
        out.push_back(static_cast<uint8_t>(alphabet[(v >> 12) & 0x3Fu]));
        out.push_back(static_cast<uint8_t>(alphabet[(v >> 6) & 0x3Fu]));
    }
}

void RegisterFixedBase64(Registry& r,
                         const std::string& name,
                         const std::string& help,
                         const char*        alphabet,
                         std::initializer_list<const char*> aliases) {
    const std::string alpha(alphabet);
    r.Add(name, "Base", help, true, false,
          [alpha](const Bytes& in, const Params&, Bytes& out) {
              EncodeBase64NoPad(in, out, alpha);
          },
          [alpha](const Bytes& in, const Params&, Bytes& out) {
              DecodeBitPacked(in, out, alpha, 6, true);
          },
          aliases);
}

// ===========================================================================
// 十三、base85 家族
// ===========================================================================

// --- Adobe Ascii85 ---
void Ascii85Enc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const bool wrap = ParamFlag(p, "wrap", false);   // 是否加 <~ ~> 包裹
    const int lineLen = p.GetInt("line", 0);
    Require(lineLen >= 0, "line 参数不能为负数");

    if (wrap) {
        out.push_back(static_cast<uint8_t>('<'));
        out.push_back(static_cast<uint8_t>('~'));
    }
    size_t linePos = 0;
    auto put = [&](uint8_t c) {
        out.push_back(c);
        if (lineLen > 0) {
            ++linePos;
            if (linePos == static_cast<size_t>(lineLen)) {
                out.push_back(static_cast<uint8_t>('\n'));
                linePos = 0;
            }
        }
    };

    size_t i = 0;
    while (i + 4 <= in.size()) {
        uint32_t v = (static_cast<uint32_t>(in[i]) << 24) |
                     (static_cast<uint32_t>(in[i + 1]) << 16) |
                     (static_cast<uint32_t>(in[i + 2]) << 8) |
                     static_cast<uint32_t>(in[i + 3]);
        if (v == 0) {
            put(static_cast<uint8_t>('z'));   // 四个零字节的简写
        } else {
            char tmp[5];
            for (int k = 4; k >= 0; --k) {
                tmp[k] = static_cast<char>('!' + (v % 85u));
                v /= 85u;
            }
            for (int k = 0; k < 5; ++k) put(static_cast<uint8_t>(tmp[k]));
        }
        i += 4;
    }
    const size_t rest = in.size() - i;
    if (rest > 0) {
        uint8_t group[4] = {0, 0, 0, 0};
        for (size_t k = 0; k < rest; ++k) group[k] = in[i + k];
        uint32_t v = (static_cast<uint32_t>(group[0]) << 24) |
                     (static_cast<uint32_t>(group[1]) << 16) |
                     (static_cast<uint32_t>(group[2]) << 8) |
                     static_cast<uint32_t>(group[3]);
        char tmp[5];
        for (int k = 4; k >= 0; --k) {
            tmp[k] = static_cast<char>('!' + (v % 85u));
            v /= 85u;
        }
        for (size_t k = 0; k <= rest; ++k) {   // rest+1 个字符
            put(static_cast<uint8_t>(tmp[k]));
        }
    }
    if (wrap) {
        put(static_cast<uint8_t>('~'));
        put(static_cast<uint8_t>('>'));
    }
}

void Ascii85Dec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const bool keepUnknown = ParamFlag(p, "strict", false);

    std::string s;
    s.reserve(in.size());
    for (uint8_t raw : in) {
        char c = static_cast<char>(raw);
        if (IsSpaceChar(c)) continue;
        s.push_back(c);
    }
    // 去掉可选的 <~ ~> 包裹
    if (s.size() >= 2 && s[0] == '<' && s[1] == '~') s = s.substr(2);
    if (s.size() >= 2 && s.compare(s.size() - 2, 2, "~>") == 0) {
        s = s.substr(0, s.size() - 2);
    }

    uint32_t tuple = 0;
    int count = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c == 'z' && count == 0) {
            out.insert(out.end(), 4, 0x00);   // z 代表四个零字节
            continue;
        }
        if (c == 'y' && count == 0) {
            out.insert(out.end(), 4, static_cast<uint8_t>(' '));   // y = 4 个空格
            continue;
        }
        if (c < '!' || c > 'u') {
            if (keepUnknown) continue;   // 宽松：忽略无法识别的字符（如 ~> 残留）
            throw Error(Format("Ascii85 含非法字符 '%c'(0x%02X)", c,
                               static_cast<unsigned char>(c)));
        }
        tuple = tuple * 85u + static_cast<uint32_t>(c - '!');
        if (++count == 5) {
            Require(tuple <= 0xFFFFFFFFu, "Ascii85 数值溢出，数据非法");
            out.push_back(static_cast<uint8_t>((tuple >> 24) & 0xFFu));
            out.push_back(static_cast<uint8_t>((tuple >> 16) & 0xFFu));
            out.push_back(static_cast<uint8_t>((tuple >> 8) & 0xFFu));
            out.push_back(static_cast<uint8_t>(tuple & 0xFFu));
            tuple = 0;
            count = 0;
        }
    }
    if (count == 1) {
        throw Error("Ascii85 尾部剩余 1 个字符，无法还原任何字节");
    }
    if (count > 1) {
        const int saved = count;
        for (int k = count; k < 5; ++k) tuple = tuple * 85u + 84u;   // 用 'u' 补足
        Require(tuple <= 0xFFFFFFFFu, "Ascii85 尾部数值溢出，数据非法");
        uint8_t bytes[4] = {
            static_cast<uint8_t>((tuple >> 24) & 0xFFu),
            static_cast<uint8_t>((tuple >> 16) & 0xFFu),
            static_cast<uint8_t>((tuple >> 8) & 0xFFu),
            static_cast<uint8_t>(tuple & 0xFFu)};
        for (int k = 0; k < saved - 1; ++k) out.push_back(bytes[k]);
    }
}

// --- ZeroMQ Z85 ---
void Z85Enc(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    Require(in.size() % 4 == 0,
            Format("Z85 要求输入长度为 4 的倍数，当前为 %zu 字节", in.size()));
    const std::string alpha(kAlphaZ85);
    out.reserve(in.size() / 4 * 5);
    for (size_t i = 0; i < in.size(); i += 4) {
        uint32_t v = (static_cast<uint32_t>(in[i]) << 24) |
                     (static_cast<uint32_t>(in[i + 1]) << 16) |
                     (static_cast<uint32_t>(in[i + 2]) << 8) |
                     static_cast<uint32_t>(in[i + 3]);
        char tmp[5];
        for (int k = 4; k >= 0; --k) {
            tmp[k] = alpha[v % 85u];
            v /= 85u;
        }
        for (int k = 0; k < 5; ++k) out.push_back(static_cast<uint8_t>(tmp[k]));
    }
}

void Z85Dec(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    const std::string alpha(kAlphaZ85);
    const std::array<int, 256> lut = MakeLut(alpha);
    const std::string s = StripSpace(in);
    Require(s.size() % 5 == 0,
            Format("Z85 编码串长度必须是 5 的倍数，当前为 %zu", s.size()));
    out.reserve(s.size() / 5 * 4);
    for (size_t i = 0; i < s.size(); i += 5) {
        uint32_t v = 0;
        for (size_t k = 0; k < 5; ++k) {
            const char c = s[i + k];
            int d = lut[static_cast<unsigned char>(c)];
            Require(d >= 0, Format("Z85 含非法字符 '%c'(位置 %zu)", c, i + k));
            v = v * 85u + static_cast<uint32_t>(d);
        }
        Require(v <= 0xFFFFFFFFu, "Z85 五元组数值溢出，数据非法");
        out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
        out.push_back(static_cast<uint8_t>(v & 0xFFu));
    }
}

// --- RFC 1924（大数进制，64 字符表）---
void Base85RfcEnc(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    out = ToBytes(EncodeBigInt(in, 85, kAlphaBase85Rfc, kAlphaBase85Rfc[0]));
}

void Base85RfcDec(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    const std::string s = StripSpace(in);
    if (s.empty()) return;
    const std::array<int, 256> lut = MakeLut(kAlphaBase85Rfc);
    for (size_t i = 0; i < s.size(); ++i) {
        Require(lut[static_cast<unsigned char>(s[i])] >= 0,
                Format("Base85(RFC1924) 含非法字符 '%c'(位置 %zu)", s[i], i));
    }
    out = DecodeBigInt(s, 85, kAlphaBase85Rfc, kAlphaBase85Rfc[0]);
}

// ===========================================================================
// 十四、base91（Joachim Henke）
// ===========================================================================
void Base91Enc(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    const std::string alpha(kAlphaBase91);
    uint32_t b = 0;       // 位缓冲
    int n = 0;            // 缓冲里的位数
    int v = -1;           // 待输出的值（13 或 14 位一组）
    for (uint8_t byte : in) {
        b |= static_cast<uint32_t>(byte) << n;
        n += 8;
        if (n > 13) {
            v = static_cast<int>(b & 8191u);
            if (v > 88) {
                b >>= 13;
                n -= 13;
            } else {
                v = static_cast<int>(b & 16383u);
                b >>= 14;
                n -= 14;
            }
            out.push_back(static_cast<uint8_t>(alpha[static_cast<size_t>(v % 91)]));
            out.push_back(static_cast<uint8_t>(alpha[static_cast<size_t>(v / 91)]));
        }
    }
    if (n > 0) {
        out.push_back(static_cast<uint8_t>(alpha[static_cast<size_t>(b % 91u)]));
        if (n > 7 || b > 90u) {
            out.push_back(static_cast<uint8_t>(alpha[static_cast<size_t>(b / 91u)]));
        }
    }
}

void Base91Dec(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    const std::string alpha(kAlphaBase91);
    const std::array<int, 256> lut = MakeLut(alpha);

    uint32_t b = 0;
    int n = 0;
    int v = -1;
    for (uint8_t raw : in) {
        const char c = static_cast<char>(raw);
        if (IsSpaceChar(c)) continue;
        const int d = lut[static_cast<unsigned char>(c)];
        Require(d >= 0, Format("Base91 含非法字符 '%c'(0x%02X)", c, raw));
        if (v < 0) {
            v = d;
        } else {
            v += d * 91;
            b |= static_cast<uint32_t>(v) << n;
            n += (v & 8191) > 88 ? 13 : 14;
            while (n > 7) {
                out.push_back(static_cast<uint8_t>(b & 0xFFu));
                b >>= 8;
                n -= 8;
            }
            v = -1;
        }
    }
    if (v >= 0) {
        b |= static_cast<uint32_t>(v) << n;
        n += 7;
        while (n > 7) {
            out.push_back(static_cast<uint8_t>(b & 0xFFu));
            b >>= 8;
            n -= 8;
        }
    }
}

// ===========================================================================
// 十五、base92（91 个字符的数字表 + 大数进制转换）
// ===========================================================================
void Base92Enc(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    out = ToBytes(EncodeBigInt(in, 91, kAlphaBase92, kAlphaBase92[0]));
}

void Base92Dec(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    const std::string s = StripSpace(in);
    if (s.empty()) return;
    const std::array<int, 256> lut = MakeLut(kAlphaBase92);
    for (size_t i = 0; i < s.size(); ++i) {
        Require(lut[static_cast<unsigned char>(s[i])] >= 0,
                Format("Base92 含非法字符 '%c'(0x%02X)", s[i],
                       static_cast<unsigned char>(s[i])));
    }
    out = DecodeBigInt(s, 91, kAlphaBase92, kAlphaBase92[0]);
}

// ===========================================================================
// 十六、base100（每字节 -> 一个 U+1F400..U+1F4FF 的 emoji）
// ===========================================================================
const uint32_t kBase100First = 0x1F400u;   // 🐀

void Base100Enc(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    out.reserve(in.size() * 4);
    for (uint8_t b : in) {
        const uint32_t cp = kBase100First + b;
        out.push_back(static_cast<uint8_t>(0xF0u | ((cp >> 18) & 0x07u)));
        out.push_back(static_cast<uint8_t>(0x80u | ((cp >> 12) & 0x3Fu)));
        out.push_back(static_cast<uint8_t>(0x80u | ((cp >> 6) & 0x3Fu)));
        out.push_back(static_cast<uint8_t>(0x80u | (cp & 0x3Fu)));
    }
}

void Base100Dec(const Bytes& in, const Params&, Bytes& out) {
    out.clear();
    size_t i = 0;
    while (i < in.size()) {
        const uint8_t c0 = in[i];
        // 跳过空白（含全角空格、换行）
        if (c0 == ' ' || c0 == '\t' || c0 == '\r' || c0 == '\n') {
            ++i;
            continue;
        }
        // 解析一个 UTF-8 序列
        size_t len = 0;
        uint32_t cp = 0;
        if ((c0 & 0x80u) == 0) {
            len = 1;
            cp = c0;
        } else if ((c0 & 0xE0u) == 0xC0u) {
            len = 2;
            cp = c0 & 0x1Fu;
        } else if ((c0 & 0xF0u) == 0xE0u) {
            len = 3;
            cp = c0 & 0x0Fu;
        } else if ((c0 & 0xF8u) == 0xF0u) {
            len = 4;
            cp = c0 & 0x07u;
        } else {
            throw Error(Format("Base100 输入不是合法 UTF-8（首字节 0x%02X）", c0));
        }
        Require(i + len <= in.size(), "Base100 输入 UTF-8 序列被截断");
        for (size_t k = 1; k < len; ++k) {
            const uint8_t cc = in[i + k];
            Require((cc & 0xC0u) == 0x80u,
                    Format("Base100 输入 UTF-8 续字节非法（0x%02X）", cc));
            cp = (cp << 6) | (cc & 0x3Fu);
        }
        if (len == 3 &&
            (cp == 0x3000u || cp == 0x00A0u)) {   // 全角空格 / 不换行空格
            i += len;
            continue;
        }
        Require(cp >= kBase100First && cp <= kBase100First + 0xFFu,
                Format("Base100 码点 U+%04X 不在 U+1F400..U+1F4FF 范围内", cp));
        out.push_back(static_cast<uint8_t>(cp - kBase100First));
        i += len;
    }
}

}  // namespace

// ===========================================================================
// 十七、注册入口
// ===========================================================================
void RegisterBase(Registry& r) {
    // --- base16 ---
    r.Add("base16", "Base", "RFC4648 Base16（十六进制），upper=1 输出大写", true, true,
          Base16Enc, Base16Dec, {"hex", "base16upper"});

    // --- base32 / base32hex ---
    RegisterBase32Style(r, "base32", "RFC4648 Base32（A-Z2-7），pad=0 不补 '='", kAlphaBase32Std,
                        {});
    RegisterBase32Style(r, "base32hex", "RFC4648 Base32 扩展十六进制表（0-9A-V），pad 可关闭",
                        kAlphaBase32Hex, {"base32ext"});

    // --- base36 ---
    r.Add("base36", "Base", "Base36（0-9A-Z），大数进制转换，可处理超长数字串", true, false,
          Base36Enc, Base36Dec, {});

    // --- base45 ---
    r.Add("base45", "Base", "RFC 9285 Base45（二维码用，字母表含空格与 $%*+-./:）", true,
          false, Base45Enc, Base45Dec, {});

    // --- base58 / base58check ---
    r.Add("base58", "Base", "Base58（比特币字母表），保持前导零字节，alphabet=btc/ripple/flickr",
          true, true, Base58Enc, Base58Dec, {"base58btc"});
    r.Add("base58check", "Base", "Base58Check：base58 + 4 字节双 SHA256 校验和", true, false,
          Base58CheckEnc, Base58CheckDec, {});

    // --- base62 ---
    r.Add("base62", "Base", "Base62（0-9A-Za-z，可用 alphabet 自定义），大数进制转换", true,
          true, Base62Enc, Base62Dec, {});

    // --- base64 / base64url ---
    r.Add("base64", "Base", "标准 Base64，支持 alphabet/url/nopad/line 参数", true, true,
          Base64Enc, Base64Dec, {});
    r.Add("base64url", "Base", "URL 安全 Base64（-_），默认不补 '='", true, true, Base64UrlEnc,
          Base64UrlDec, {"base64-url", "b64url"});

    // --- base85 家族 ---
    r.Add("base85", "Base", "Adobe Ascii85(85)，z 表示四零字节，wrap=1 加 <~ ~>", true, true,
          Ascii85Enc, Ascii85Dec, {"ascii85", "base85ascii"});
    r.Add("z85", "Base", "ZeroMQ Z85，输入长度必须是 4 的倍数", true, false, Z85Enc, Z85Dec,
          {"base85z85"});
    r.Add("base85rfc", "Base", "RFC 1924 Base85 字母表（大数进制）", true, false, Base85RfcEnc,
          Base85RfcDec, {"rfc1924"});

    // --- base91 / base92 / base100 ---
    r.Add("base91", "Base", "basE91（Joachim Henke，13/14 位分组）", true, false, Base91Enc,
          Base91Dec, {"base91"});
    r.Add("base92", "Base", "Base92（91 字符数字表，大数进制转换）", true, false, Base92Enc,
          Base92Dec, {});
    r.Add("base100", "Base", "Base100：每字节映射为 U+1F400+byte 的 emoji（UTF-8）", true,
          false, Base100Enc, Base100Dec, {});

    // --- radix64 / bcrypt64 / crypt64 ---
    r.Add("radix64", "Base", "OpenPGP Radix-64：Base64 + CRC24 校验行 =XXXX", true, true,
          Radix64Enc, Radix64Dec, {"pgp", "base64pgp"});
    RegisterFixedBase64(r, "bcrypt64", "bcrypt 自定义字母表 Base64（./A-Za-z0-9），无填充",
                        "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                        {"bcrypt-base64"});
    RegisterFixedBase64(r, "crypt64", "crypt(3) 字母表 Base64（./0-9A-Za-z），无填充",
                        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                        {"crypt-base64"});
}

}  // namespace ctf
