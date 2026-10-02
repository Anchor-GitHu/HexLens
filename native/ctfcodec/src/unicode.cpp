// unicode.cpp —— Unicode 相关算法模块
// ---------------------------------------------------------------------------
// 覆盖三块内容：
//   A. UTF 编码转换（UTF-16/32 LE/BE、UTF-8 回解、RFC 2152 UTF-7 / Modified UTF-7）
//   B. Windows 代码页转换（GBK / GB18030 / Big5 / Shift-JIS / CP1252，走 Win32 API）
//   C. 码点与转义表示 + 隐写类（codepoint / unicode-escape / percent-u /
//      numeric-entity / mysql-escape / zero-width / unicode-tag / variation-selector）
//
// 约定：本模块所有「文本侧」一律按 UTF-8 解释。
//   严格方向（A/B 类编码、代码页转换）遇到非法 UTF-8 直接抛 Error；
//   解析型解码器（codepoint / unicode-escape / percent-u / numeric-entity）
//   采取「安全降级」：无法识别的片段原样保留，不抛异常，方便处理半截数据。
// ---------------------------------------------------------------------------
#include "common.h"
#include "util.h"

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace ctf {
namespace {

// ===========================================================================
// 一、UTF-8 与码点互转（所有 A/C/D 类算法的基础，只在这里实现一次）
// ===========================================================================

// 单次解码结果：ok=false 表示该位置不是合法 UTF-8 序列的开头。
struct Rune {
    uint32_t cp    = 0;
    size_t   width = 0;   // 该码点占用的字节数
    bool     ok    = false;
};

// 把一个合法标量值编码成 UTF-8 字节
std::string Utf8FromCodepoint(uint32_t cp) {
    std::string s;
    if (cp < 0x80u) {
        s.push_back(static_cast<char>(cp));
    } else if (cp < 0x800u) {
        s.push_back(static_cast<char>(0xC0u | (cp >> 6)));
        s.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else if (cp < 0x10000u) {
        s.push_back(static_cast<char>(0xE0u | (cp >> 12)));
        s.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
        s.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    } else {
        s.push_back(static_cast<char>(0xF0u | (cp >> 18)));
        s.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
        s.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
        s.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    }
    return s;
}

// 是不是 Unicode 标量值（拒绝代理区 U+D800..U+DFFF 与 > U+10FFFF）
bool IsScalarValue(uint32_t cp) {
    if (cp > 0x10FFFFu) return false;
    if (cp >= 0xD800u && cp <= 0xDFFFu) return false;
    return true;
}

// 在位置 i 处解码一个码点；拒绝过长编码与非法码点。
Rune DecodeRune(const std::string& s, size_t i) {
    Rune          r;
    unsigned char b0 = static_cast<unsigned char>(s[i]);
    if (b0 < 0x80u) {
        r.cp    = b0;
        r.width = 1;
        r.ok    = true;
        return r;
    }
    int      need = 0;
    uint32_t cp   = 0;
    if ((b0 & 0xE0u) == 0xC0u) {
        need = 1;
        cp   = b0 & 0x1Fu;
    } else if ((b0 & 0xF0u) == 0xE0u) {
        need = 2;
        cp   = b0 & 0x0Fu;
    } else if ((b0 & 0xF8u) == 0xF0u) {
        need = 3;
        cp   = b0 & 0x07u;
    } else {
        return r;   // 0x80-0xBF 续字节，或 0xF8-0xFF 非法首字节
    }
    if (i + static_cast<size_t>(need) >= s.size()) return r;   // 被截断
    for (int k = 1; k <= need; ++k) {
        unsigned char bk = static_cast<unsigned char>(s[i + static_cast<size_t>(k)]);
        if ((bk & 0xC0u) != 0x80u) return r;
        cp = (cp << 6) | (bk & 0x3Fu);
    }
    if (need == 1 && cp < 0x80u) return r;        // 过长编码
    if (need == 2 && cp < 0x800u) return r;
    if (need == 3 && cp < 0x10000u) return r;
    if (!IsScalarValue(cp)) return r;             // 代理区 / 越界
    r.cp    = cp;
    r.width = static_cast<size_t>(need) + 1;
    r.ok    = true;
    return r;
}

// 严格解码：任何非法 UTF-8 都抛 Error。
std::vector<uint32_t> Utf8Decode(const Bytes& in, const std::string& what) {
    const std::string     s = Str(in);
    std::vector<uint32_t> cps;
    cps.reserve(in.size());
    size_t i = 0;
    while (i < s.size()) {
        Rune r = DecodeRune(s, i);
        if (!r.ok) {
            throw Error(Format("%s 不是合法 UTF-8（偏移 %zu 处字节 0x%02X）", what.c_str(), i,
                               static_cast<unsigned>(static_cast<unsigned char>(s[i]))));
        }
        cps.push_back(r.cp);
        i += r.width;
    }
    return cps;
}

// 宽松解码：非法字节按 U+FFFD 安全降级（用于解析型/扫描型解码器）。
std::vector<uint32_t> Utf8DecodeLenient(const Bytes& in) {
    const std::string     s = Str(in);
    std::vector<uint32_t> cps;
    cps.reserve(in.size());
    size_t i = 0;
    while (i < s.size()) {
        Rune r = DecodeRune(s, i);
        if (r.ok) {
            cps.push_back(r.cp);
            i += r.width;
        } else {
            cps.push_back(0xFFFDu);
            ++i;
        }
    }
    return cps;
}

// 码点序列 -> UTF-8 字节。遇到非法码点抛 Error。
Bytes Utf8Encode(const std::vector<uint32_t>& cps, const std::string& what) {
    Bytes out;
    out.reserve(cps.size() * 2);
    for (uint32_t cp : cps) {
        if (!IsScalarValue(cp)) {
            throw Error(Format("%s 含非法码点 U+%04X（代理区或超出 U+10FFFF）", what.c_str(),
                               static_cast<unsigned>(cp)));
        }
        std::string b = Utf8FromCodepoint(cp);
        out.insert(out.end(), b.begin(), b.end());
    }
    return out;
}

const uint8_t kUtf8Bom[3] = {0xEF, 0xBB, 0xBF};

bool BytesStartWith(const Bytes& b, const uint8_t* p, size_t n) {
    if (b.size() < n) return false;
    for (size_t i = 0; i < n; ++i) {
        if (b[i] != p[i]) return false;
    }
    return true;
}

// 去掉开头的 UTF-8 BOM（EF BB BF）
Bytes StripUtf8Bom(const Bytes& in) {
    if (BytesStartWith(in, kUtf8Bom, 3)) return Bytes(in.begin() + 3, in.end());
    return in;
}

// ===========================================================================
// 二、UTF-16 / UTF-32 辅助
// ===========================================================================

void AppendU16LE(Bytes& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
}

void AppendU16BE(Bytes& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
}

void AppendU32LE(Bytes& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
}

void AppendU32BE(Bytes& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
}

// 码点 -> UTF-16 码元序列（BMP 外拆成代理对）
std::vector<uint16_t> Utf16Units(const std::vector<uint32_t>& cps) {
    std::vector<uint16_t> u;
    u.reserve(cps.size());
    for (uint32_t cp : cps) {
        if (!IsScalarValue(cp)) {
            throw Error(Format("含非法码点 U+%04X，无法编码为 UTF-16", static_cast<unsigned>(cp)));
        }
        if (cp < 0x10000u) {
            u.push_back(static_cast<uint16_t>(cp));
        } else {
            uint32_t v = cp - 0x10000u;
            u.push_back(static_cast<uint16_t>(0xD800u + (v >> 10)));
            u.push_back(static_cast<uint16_t>(0xDC00u + (v & 0x3FFu)));
        }
    }
    return u;
}

// UTF-16 码元序列 -> 码点序列；孤立代理一律抛 Error
std::vector<uint32_t> Utf16ToCodepoints(const std::vector<uint16_t>& u, const std::string& what) {
    std::vector<uint32_t> cps;
    cps.reserve(u.size());
    for (size_t i = 0; i < u.size(); ++i) {
        uint16_t w = u[i];
        if (w >= 0xD800u && w <= 0xDBFFu) {
            if (i + 1 >= u.size() || u[i + 1] < 0xDC00u || u[i + 1] > 0xDFFFu) {
                throw Error(Format("%s 含孤立的高代理 U+%04X", what.c_str(),
                                   static_cast<unsigned>(w)));
            }
            uint32_t cp = 0x10000u + ((static_cast<uint32_t>(w) - 0xD800u) << 10) +
                          (static_cast<uint32_t>(u[i + 1]) - 0xDC00u);
            cps.push_back(cp);
            ++i;
        } else if (w >= 0xDC00u && w <= 0xDFFFu) {
            throw Error(Format("%s 含孤立的低代理 U+%04X", what.c_str(), static_cast<unsigned>(w)));
        } else {
            cps.push_back(w);
        }
    }
    return cps;
}

// 把「unit 字节定长码元」的字节流拆成码元序列
std::vector<uint32_t> SplitFixedUnits(const Bytes& in, size_t unit, bool bigEndian,
                                      const std::string& what) {
    if (!in.empty() && in.size() % unit != 0) {
        throw Error(Format("%s 字节长度 %zu 不是 %zu 的整数倍", what.c_str(), in.size(), unit));
    }
    std::vector<uint32_t> units;
    units.reserve(in.size() / unit);
    for (size_t off = 0; off + unit <= in.size(); off += unit) {
        uint32_t v = 0;
        for (size_t k = 0; k < unit; ++k) {
            // 大端：低地址是高位；小端：低地址是低位
            size_t        idx     = bigEndian ? (off + k) : (off + (unit - 1 - k));
            unsigned char byteVal = in[idx];
            v                     = (v << 8) | static_cast<uint32_t>(byteVal);
        }
        units.push_back(v);
    }
    return units;
}

// ===========================================================================
// 三、A 类：UTF-16 / UTF-32 编码
// ===========================================================================

Bytes Utf16LeEncode(const Bytes& in, bool bom) {
    std::vector<uint16_t> u = Utf16Units(Utf8Decode(in, "输入"));
    Bytes                 out;
    out.reserve(u.size() * 2 + 2);
    if (bom) AppendU16LE(out, 0xFEFFu);
    for (uint16_t w : u) AppendU16LE(out, w);
    return out;
}

Bytes Utf16BeEncode(const Bytes& in, bool bom) {
    std::vector<uint16_t> u = Utf16Units(Utf8Decode(in, "输入"));
    Bytes                 out;
    out.reserve(u.size() * 2 + 2);
    if (bom) AppendU16BE(out, 0xFEFFu);
    for (uint16_t w : u) AppendU16BE(out, w);
    return out;
}

Bytes Utf32LeEncode(const Bytes& in, bool bom) {
    std::vector<uint32_t> cps = Utf8Decode(in, "输入");
    Bytes                 out;
    out.reserve(cps.size() * 4 + 4);
    if (bom) AppendU32LE(out, 0xFEFFu);
    for (uint32_t cp : cps) AppendU32LE(out, cp);
    return out;
}

Bytes Utf32BeEncode(const Bytes& in, bool bom) {
    std::vector<uint32_t> cps = Utf8Decode(in, "输入");
    Bytes                 out;
    out.reserve(cps.size() * 4 + 4);
    if (bom) AppendU32BE(out, 0xFEFFu);
    for (uint32_t cp : cps) AppendU32BE(out, cp);
    return out;
}

// ===========================================================================
// 四、A 类：toutf8 —— UTF-16/32 任意端序 -> UTF-8
// ===========================================================================

// 探测 BOM：返回 0=没有 / 16=UTF-16 / 32=UTF-32，并给出端序与 BOM 长度
int DetectBom(const Bytes& d, bool& bigEndian, size_t& bomLen) {
    bomLen = 0;
    if (d.size() >= 4 && d[0] == 0xFF && d[1] == 0xFE && d[2] == 0x00 && d[3] == 0x00) {
        bigEndian = false;
        bomLen    = 4;
        return 32;
    }
    if (d.size() >= 4 && d[0] == 0x00 && d[1] == 0x00 && d[2] == 0xFE && d[3] == 0xFF) {
        bigEndian = true;
        bomLen    = 4;
        return 32;
    }
    if (d.size() >= 2 && d[0] == 0xFF && d[1] == 0xFE) {
        bigEndian = false;
        bomLen    = 2;
        return 16;
    }
    if (d.size() >= 2 && d[0] == 0xFE && d[1] == 0xFF) {
        bigEndian = true;
        bomLen    = 2;
        return 16;
    }
    return 0;
}

Bytes Toutf8Decode(const Bytes& in, const std::string& fromSpec, bool outBom) {
    // 先去 UTF-8 BOM（本模块的文本侧约定是 UTF-8）
    const Bytes data = StripUtf8Bom(in);

    bool     be   = false;
    size_t   skip = 0;
    uint32_t bits = 0;   // 16 或 32

    // 1) BOM 是最明确的信号，优先级最高：
    //    这样各种 UTF-32 常量不会被误判成 UTF-16，也能自动纠正端序。
    int bomBits = DetectBom(data, be, skip);
    if (bomBits != 0) {
        bits = static_cast<uint32_t>(bomBits);
    } else if (fromSpec == "auto" || fromSpec.empty()) {
        // 2) 无 BOM 且未指定 from：兜底为 UTF-16LE（最常见的无 BOM 形式）
        bits = 16;
    } else if (fromSpec == "utf16le" || fromSpec == "utf16be" || fromSpec == "utf32le" ||
               fromSpec == "utf32be") {
        bits = (fromSpec.compare(0, 5, "utf32") == 0) ? 32u : 16u;
        be   = (fromSpec.compare(fromSpec.size() - 2, 2, "be") == 0);
    } else {
        throw Error("from 只支持 auto/utf16le/utf16be/utf32le/utf32be，收到: " + fromSpec);
    }

    Bytes body(data.begin() + static_cast<std::ptrdiff_t>(skip), data.end());
    Bytes result;


    if (bits == 16) {
        std::vector<uint32_t> units = SplitFixedUnits(body, 2, be, "UTF-16 输入");
        std::vector<uint16_t> u;
        u.reserve(units.size());
        for (uint32_t v : units) u.push_back(static_cast<uint16_t>(v));
        result = Utf8Encode(Utf16ToCodepoints(u, "UTF-16 输入"), "UTF-16 输入");
    } else {
        std::vector<uint32_t> cps = SplitFixedUnits(body, 4, be, "UTF-32 输入");
        for (uint32_t cp : cps) {
            // UTF-32 里每个码元必须本身是合法标量值（拒绝代理区与 > U+10FFFF）
            if (cp > 0x10FFFFu || (cp >= 0xD800u && cp <= 0xDFFFu)) {
                throw Error(Format("UTF-32 输入含非法码点 U+%04X", static_cast<unsigned>(cp)));
            }
        }
        result = Utf8Encode(cps, "UTF-32 输入");
    }

    if (outBom) {
        Bytes withBom(kUtf8Bom, kUtf8Bom + 3);
        withBom.insert(withBom.end(), result.begin(), result.end());
        return withBom;
    }
    return result;
}

// ===========================================================================
// 五、A 类：RFC 2152 UTF-7（含 Modified UTF-7 / IMAP 变体）
// ===========================================================================

const char* kUtf7Base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// UTF-7 的 base64（RFC 2152 §3）：把「UTF-16BE 字节流」按标准 base64 编码，
// 只是省略 '=' 填充。也就是每 3 字节 -> 4 字符、余 2 字节 -> 3 字符、余 1 字节 -> 2 字符。
std::string Base64EncodeUtf7(const std::vector<uint16_t>& units) {
    Bytes raw;
    raw.reserve(units.size() * 2);
    for (uint16_t w : units) AppendU16BE(raw, w);

    std::string out;
    size_t      i = 0;
    while (i + 3 <= raw.size()) {
        uint32_t v = (static_cast<uint32_t>(raw[i]) << 16) |
                     (static_cast<uint32_t>(raw[i + 1]) << 8) | static_cast<uint32_t>(raw[i + 2]);
        out.push_back(kUtf7Base64[(v >> 18) & 0x3Fu]);
        out.push_back(kUtf7Base64[(v >> 12) & 0x3Fu]);
        out.push_back(kUtf7Base64[(v >> 6) & 0x3Fu]);
        out.push_back(kUtf7Base64[v & 0x3Fu]);
        i += 3;
    }
    size_t rest = raw.size() - i;
    if (rest == 1) {
        uint32_t v = static_cast<uint32_t>(raw[i]) << 16;
        out.push_back(kUtf7Base64[(v >> 18) & 0x3Fu]);
        out.push_back(kUtf7Base64[(v >> 12) & 0x3Fu]);
    } else if (rest == 2) {
        uint32_t v =
            (static_cast<uint32_t>(raw[i]) << 16) | (static_cast<uint32_t>(raw[i + 1]) << 8);
        out.push_back(kUtf7Base64[(v >> 18) & 0x3Fu]);
        out.push_back(kUtf7Base64[(v >> 12) & 0x3Fu]);
        out.push_back(kUtf7Base64[(v >> 6) & 0x3Fu]);
    }
    return out;
}

// UTF-7 变体 base64 解码（无 '=' 填充，忽略空白）
Bytes Base64DecodeUtf7(const std::string& s) {
    Bytes    out;
    uint32_t acc  = 0;
    int      bits = 0;
    for (char ch : s) {
        if (ch == '=' || ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t') continue;
        const char* p = std::strchr(kUtf7Base64, ch);
        if (p == nullptr || ch == '\0') {
            throw Error(Format("UTF-7 段中含非法 base64 字符 '%c'", ch));
        }
        acc = (acc << 6) | static_cast<uint32_t>(p - kUtf7Base64);
        bits += 6;
        while (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFFu));
        }
    }
    // 剩下的必须是 0 填充位（合法编码只可能是 2/4/6 位余量）
    if (bits != 0 && (acc & ((1u << bits) - 1u)) != 0) {
        throw Error("UTF-7 段的 base64 尾部填充位非零，数据已损坏");
    }
    return out;
}

// UTF-16BE 字节 -> UTF-8 字节（一个 "+...-" 段的内容）
Bytes Utf7SectionToUtf8(const std::string& b64) {
    Bytes                 be = Base64DecodeUtf7(b64);
    std::vector<uint16_t> units;
    units.reserve(be.size() / 2);
    for (size_t k = 0; k + 1 < be.size(); k += 2) {
        units.push_back(static_cast<uint16_t>((static_cast<uint16_t>(be[k]) << 8) | be[k + 1]));
    }
    return Utf8Encode(Utf16ToCodepoints(units, "UTF-7 段"), "UTF-7 段");
}

Bytes Utf7Encode(const Bytes& in, bool imap) {
    std::vector<uint32_t> cps = Utf8Decode(in, "输入");
    std::string           out;
    std::vector<uint16_t> pending;

    auto flush = [&]() {
        if (pending.empty()) return;
        out += "+";
        out += Base64EncodeUtf7(pending);
        out += "-";
        pending.clear();
    };

    for (uint32_t cp : cps) {
        bool direct = false;
        if (imap) {
            // Modified UTF-7：可打印 ASCII（含 '+'）除 '&' 外都直接表示
            direct = (cp >= 0x20u && cp <= 0x7Eu && cp != 0x26u);
        } else {
            // RFC 2152：集合 D 之外的都编码；'+' 也编码，保证往返无歧义
            direct = (cp >= 0x20u && cp <= 0x7Eu) &&
                     std::strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                                 "0123456789'(),-./:?",
                                 static_cast<int>(cp)) != nullptr;
        }
        if (direct) {
            flush();
            out.push_back(static_cast<char>(cp));
            continue;
        }
        if (imap && cp == 0x26u) {          // '&' -> "&-"
            flush();
            out += "&-";
            continue;
        }
        for (uint16_t w : Utf16Units(std::vector<uint32_t>{cp})) pending.push_back(w);
    }
    flush();
    return ToBytes(out);
}

Bytes Utf7Decode(const Bytes& in, bool imap) {
    const std::string s = Str(StripUtf8Bom(in));
    size_t            i = 0;
    Bytes             out;

    while (i < s.size()) {
        char c = s[i];

        if (imap) {
            if (c == '&') {
                ++i;
                std::string b64;
                while (i < s.size() && s[i] != '-' && s[i] != '&') {
                    b64.push_back(s[i]);
                    ++i;
                }
                if (i < s.size() && s[i] == '-') ++i;
                if (b64.empty()) {
                    out.push_back(static_cast<uint8_t>('&'));   // "&-" -> '&'
                } else {
                    Bytes seg = Utf7SectionToUtf8(b64);
                    out.insert(out.end(), seg.begin(), seg.end());
                }
            } else {
                out.push_back(static_cast<uint8_t>(c));
                ++i;
            }
            continue;
        }

        if (c == '+') {
            ++i;
            std::string b64;
            while (i < s.size() && s[i] != '-' && s[i] != '+') {
                b64.push_back(s[i]);
                ++i;
            }
            if (i < s.size() && s[i] == '-') ++i;
            if (b64.empty()) {
                out.push_back(static_cast<uint8_t>('+'));       // "+-" -> '+'
            } else {
                Bytes seg = Utf7SectionToUtf8(b64);
                out.insert(out.end(), seg.begin(), seg.end());
            }
        } else if (c == '-') {
            ++i;   // 可选连字符：非段尾出现时忽略
        } else {
            out.push_back(static_cast<uint8_t>(c));
            ++i;
        }
    }
    return out;
}

// ===========================================================================
// 六、B 类：Windows 代码页转换
// ===========================================================================

std::string WinErrText() {
    DWORD e = GetLastError();
    return "（Win32 错误码 " + std::to_string(static_cast<unsigned long>(e)) + "）";
}

// UTF-8 -> 宽字符；非法 UTF-8 抛 Error
std::wstring Utf8ToWide(const Bytes& in) {
    if (in.empty()) return std::wstring();
    const char* src = reinterpret_cast<const char*>(in.data());
    int         len = static_cast<int>(in.size());
    int         n   = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, src, len, nullptr, 0);
    if (n <= 0) throw Error("输入不是合法 UTF-8" + WinErrText());
    std::wstring w(static_cast<size_t>(n), L'\0');
    int          got = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, src, len, &w[0], n);
    if (got <= 0) throw Error("UTF-8 -> UTF-16 转换失败" + WinErrText());
    w.resize(static_cast<size_t>(got));
    return w;
}

// 宽字符 -> 目标代码页。
// 注意：WC_ERR_INVALID_CHARS 在 Win32 上只对 CP_UTF8/CP_UTF7 有效，
//       CP936/950/932/1252 传它会直接返回 ERROR_INVALID_FLAGS(1004)，
//       所以这里统一 flags=0（无法表示的字符由系统替换成 '?'），
//       再用「转回去比对」来判断是否真的发生了有损替换。
Bytes WideToCodePageRaw(const std::wstring& w, UINT cp, const std::string& cpLabel) {
    const wchar_t* src = w.empty() ? L"" : w.c_str();
    int            len = static_cast<int>(w.size());
    int n = WideCharToMultiByte(cp, 0, src, len, nullptr, 0, nullptr, nullptr);
    if (n <= 0) throw Error("转换为 " + cpLabel + " 失败" + WinErrText());
    Bytes out(static_cast<size_t>(n));
    int   got = WideCharToMultiByte(cp, 0, src, len, reinterpret_cast<char*>(out.data()), n,
                                    nullptr, nullptr);
    if (got <= 0) throw Error("转换为 " + cpLabel + " 失败" + WinErrText());
    out.resize(static_cast<size_t>(got));
    return out;
}

// 目标代码页字节 -> 宽字符（严格：非法字节序列报错）
std::wstring CodePageToWide(const Bytes& in, UINT cp, const std::string& cpLabel) {
    if (in.empty()) return std::wstring();
    const char* src = reinterpret_cast<const char*>(in.data());
    int         len = static_cast<int>(in.size());
    int         n   = MultiByteToWideChar(cp, MB_ERR_INVALID_CHARS, src, len, nullptr, 0);
    if (n <= 0) throw Error("非法 " + cpLabel + " 字节序列" + WinErrText());
    std::wstring w(static_cast<size_t>(n), L'\0');
    int          got = MultiByteToWideChar(cp, MB_ERR_INVALID_CHARS, src, len, &w[0], n);
    if (got <= 0) throw Error("非法 " + cpLabel + " 字节序列" + WinErrText());
    w.resize(static_cast<size_t>(got));
    return w;
}

std::string CpLabel(UINT cp) {
    switch (cp) {
        case 936:   return "GBK(936)";
        case 54936: return "GB18030(54936)";
        case 950:   return "Big5(950)";
        case 932:   return "Shift-JIS(932)";
        case 1252:  return "CP1252";
        default:    return "CP" + std::to_string(static_cast<unsigned long>(cp));
    }
}

// 宽字符 -> UTF-8
Bytes WideToUtf8(const std::wstring& w, const std::string& cpLabel) {
    if (w.empty()) return Bytes();
    int m = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0,
                                nullptr, nullptr);
    if (m <= 0) throw Error(cpLabel + " -> UTF-8 转换失败" + WinErrText());
    Bytes out(static_cast<size_t>(m));
    int   got2 = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                     reinterpret_cast<char*>(out.data()), m, nullptr, nullptr);
    if (got2 <= 0) throw Error(cpLabel + " -> UTF-8 转换失败" + WinErrText());
    out.resize(static_cast<size_t>(got2));
    return out;
}

Bytes CodePageEncode(const Bytes& in, UINT cp, bool lossy) {
    if (in.empty()) return Bytes();   // Win32 对空缓冲区调用会返回 ERROR_INVALID_PARAMETER
    std::string cpLabel = CpLabel(cp);
    std::wstring w      = Utf8ToWide(in);
    Bytes        raw    = WideToCodePageRaw(w, cp, cpLabel);

    if (lossy) return raw;

    // 严格模式：把结果转回 UTF-8 与原始输入逐字节比对，据此判断是否发生有损替换。
    // （不依赖「替换成了 '?'」这个系统默认行为，也不受源文本本来就含 '?' 的干扰。）
    Bytes back = WideToUtf8(CodePageToWide(raw, cp, cpLabel), cpLabel);
    if (back != in) {
        throw Error("输入含 " + cpLabel + " 无法表示的字符（可加 replace=1 用 '?' 替换）");
    }
    return raw;
}

Bytes CodePageDecode(const Bytes& in, UINT cp) {
    if (in.empty()) return Bytes();
    std::string cpLabel = CpLabel(cp);
    std::wstring w      = CodePageToWide(in, cp, cpLabel);
    return WideToUtf8(w, cpLabel);
}

// ===========================================================================
// 七、C 类：码点 / 转义表示
// ===========================================================================

std::string HexPad(uint32_t cp, int width) { return Format("%0*X", width, static_cast<unsigned>(cp)); }

std::string CodePointToken(uint32_t cp, bool lower) {
    std::string h = HexPad(cp, 4);
    std::string prefix = "U+";
    if (lower) {
        h      = ToLower(h);
        prefix = "u+";
    }
    return prefix + h;
}

// 读一段十六进制（最多 maxDigits 位），返回是否至少读到 1 位
bool ReadHexRun(const std::string& s, size_t& i, int maxDigits, uint32_t& v, int& count) {
    v     = 0;
    count = 0;
    while (i < s.size() && count < maxDigits && IsHexDigit(s[i])) {
        v = (v << 4) | static_cast<uint32_t>(HexVal(s[i]));
        ++i;
        ++count;
    }
    return count > 0;
}

// ------------------------------- codepoint --------------------------------

Bytes CodepointEncode(const Bytes& in, const std::string& sep, bool lower) {
    std::vector<uint32_t> cps = Utf8Decode(in, "输入");
    std::string           s;
    for (size_t i = 0; i < cps.size(); ++i) {
        if (i) s += sep;
        s += CodePointToken(cps[i], lower);
    }
    return ToBytes(s);
}

Bytes CodepointDecode(const Bytes& in, const std::string& sep) {
    const std::string     s = Str(in);
    std::vector<uint32_t> cps;
    size_t                i       = 0;
    unsigned char         sepLead = 0;
    if (!sep.empty()) sepLead = static_cast<unsigned char>(sep[0]);

    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == ';' ||
            (sepLead != 0 && c == sepLead)) {
            ++i;
            continue;
        }
        // U+XXXX
        if ((c == 'U' || c == 'u') && i + 1 < s.size() && s[i + 1] == '+') {
            i += 2;
            uint32_t v     = 0;
            int      count = 0;
            if (!ReadHexRun(s, i, 8, v, count)) throw Error("U+ 后面缺少十六进制码点");
            cps.push_back(v);
            continue;
        }
        // \uXXXX / \u{...} / \UXXXXXXXX
        if (c == '\\' && i + 1 < s.size() && (s[i + 1] == 'u' || s[i + 1] == 'U')) {
            bool wide = (s[i + 1] == 'U');
            i += 2;
            uint32_t v     = 0;
            int      count = 0;
            if (i < s.size() && s[i] == '{') {
                ++i;
                while (i < s.size() && s[i] != '}') {
                    if (!IsHexDigit(s[i])) throw Error("\\u{...} 中含非法字符");
                    v = (v << 4) | static_cast<uint32_t>(HexVal(s[i]));
                    ++i;
                    ++count;
                }
                if (i >= s.size()) throw Error("\\u{...} 缺少 '}'");
                ++i;
            } else {
                ReadHexRun(s, i, wide ? 8 : 4, v, count);
            }
            if (count == 0) throw Error("\\u 后面缺少十六进制码点");
            cps.push_back(v);
            continue;
        }
        // 裸十六进制 token：贪婪吃十六进制字符后按长度判定
        if (IsHexDigit(s[i])) {
            size_t   start = i;
            uint32_t v     = 0;
            int      count = 0;
            ReadHexRun(s, i, 8, v, count);
            if (count == 4 || count == 5 || count == 6 || count == 8) {
                cps.push_back(v);
            } else if (count == 2) {
                // "4142" 这种按字节连写：两个字符一个字节
                cps.push_back(static_cast<uint32_t>(HexVal(s[start]) * 16 + HexVal(s[start + 1])));
            } else if (count == 1) {
                if (v != 0) {
                    throw Error(Format("码点 token 长度不合法（1 位十六进制）: %s",
                                       s.substr(start, static_cast<size_t>(count)).c_str()));
                }
                cps.push_back(0);
            } else {
                throw Error(Format("码点十六进制位数不合法（%d 位）: %s", count,
                                   s.substr(start, static_cast<size_t>(count)).c_str()));
            }
            continue;
        }
        // 其它字符原样保留
        Rune r = DecodeRune(s, i);
        if (r.ok) {
            cps.push_back(r.cp);
            i += r.width;
        } else {
            cps.push_back(0xFFFDu);
            ++i;
        }
    }
    // 码点列表里可能用 UTF-16 代理对写法（U+D83D U+DE00），这里合并回 BMP 外码点
    std::vector<uint32_t> merged;
    merged.reserve(cps.size());
    for (size_t k = 0; k < cps.size(); ++k) {
        uint32_t cp = cps[k];
        if (cp >= 0xD800u && cp <= 0xDBFFu && k + 1 < cps.size() && cps[k + 1] >= 0xDC00u &&
            cps[k + 1] <= 0xDFFFu) {
            merged.push_back(0x10000u + ((cp - 0xD800u) << 10) + (cps[k + 1] - 0xDC00u));
            ++k;
            continue;
        }
        if (cp >= 0xD800u && cp <= 0xDFFFu) {
            throw Error(Format("codepoint 解码出现孤立代理 U+%04X", static_cast<unsigned>(cp)));
        }
        merged.push_back(cp);
    }
    return Utf8Encode(merged, "codepoint 解码结果");
}

// ---------------------------- unicode-escape ------------------------------

Bytes UnicodeEscapeEncode(const Bytes& in, bool lower) {
    std::vector<uint16_t> u = Utf16Units(Utf8Decode(in, "输入"));
    std::string           s;
    s.reserve(u.size() * 6);
    for (uint16_t w : u) {
        std::string h = Format("%04X", static_cast<unsigned>(w));
        if (lower) h = ToLower(h);
        s += "\\u";
        s += h;
    }
    return ToBytes(s);
}

Bytes UnicodeEscapeDecode(const Bytes& in) {
    const std::string     s = Str(in);
    std::vector<uint32_t> cps;
    size_t                i = 0;

    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '\\' && i + 1 < s.size() && (s[i + 1] == 'u' || s[i + 1] == 'U')) {
            bool wide = (s[i + 1] == 'U');
            i += 2;
            uint32_t v     = 0;
            int      count = 0;
            if (i < s.size() && s[i] == '{') {
                ++i;
                while (i < s.size() && s[i] != '}') {
                    if (!IsHexDigit(s[i])) throw Error("\\u{...} 中含非法字符");
                    v = (v << 4) | static_cast<uint32_t>(HexVal(s[i]));
                    ++i;
                    ++count;
                }
                if (i >= s.size()) throw Error("\\u{...} 缺少 '}'");
                ++i;
            } else {
                ReadHexRun(s, i, wide ? 8 : 4, v, count);
                if (count < (wide ? 8 : 4)) {
                    throw Error("Unicode 转义序列的十六进制位数不足");
                }
            }
            if (count == 0) throw Error("\\u 后面缺少十六进制码点");
            cps.push_back(v);
            continue;
        }
        Rune r = DecodeRune(s, i);
        if (r.ok) {
            cps.push_back(r.cp);
            i += r.width;
        } else {
            cps.push_back(0xFFFDu);
            ++i;
        }
    }

    // 合并 UTF-16 代理对
    Bytes out;
    for (size_t k = 0; k < cps.size(); ++k) {
        uint32_t cp = cps[k];
        if (cp >= 0xD800u && cp <= 0xDBFFu && k + 1 < cps.size() && cps[k + 1] >= 0xDC00u &&
            cps[k + 1] <= 0xDFFFu) {
            uint32_t merged = 0x10000u + ((cp - 0xD800u) << 10) + (cps[k + 1] - 0xDC00u);
            Bytes    b = Utf8Encode(std::vector<uint32_t>{merged}, "unicode-escape 解码结果");
            out.insert(out.end(), b.begin(), b.end());
            ++k;
            continue;
        }
        if (cp >= 0xD800u && cp <= 0xDFFFu) {
            throw Error(Format("unicode-escape 解码出现孤立代理 U+%04X",
                               static_cast<unsigned>(cp)));
        }
        Bytes b = Utf8Encode(std::vector<uint32_t>{cp}, "unicode-escape 解码结果");
        out.insert(out.end(), b.begin(), b.end());
    }
    return out;
}

// ------------------------------- percent-u --------------------------------

Bytes PercentUEncode(const Bytes& in) {
    std::vector<uint16_t> u = Utf16Units(Utf8Decode(in, "输入"));
    std::string           s;
    s.reserve(u.size() * 6);
    for (uint16_t w : u) s += Format("%%u%04X", static_cast<unsigned>(w));
    return ToBytes(s);
}

Bytes PercentUDecode(const Bytes& in) {
    const std::string s = Str(in);
    // 先按「%uXXXX 是 UTF-16 码元，普通文本是完整码点」分开收集
    std::vector<uint16_t> units;
    std::vector<uint32_t> pendingCps;   // 非 %u 部分解出的码点（已完整）
    size_t                i = 0;

    auto FlushCps = [&]() {
        for (uint32_t cp : pendingCps) {
            for (uint16_t w : Utf16Units(std::vector<uint32_t>{cp})) units.push_back(w);
        }
        pendingCps.clear();
    };

    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if ((c == '%' || c == '\\') && i + 1 < s.size() && (s[i + 1] == 'u' || s[i + 1] == 'U')) {
            i += 2;
            uint32_t v     = 0;
            int      count = 0;
            ReadHexRun(s, i, 4, v, count);
            if (count < 4) throw Error("%uXXXX 的十六进制位数不足 4 位");
            units.push_back(static_cast<uint16_t>(v));
            continue;
        }
        Rune r = DecodeRune(s, i);
        if (r.ok) {
            pendingCps.push_back(r.cp);
            i += r.width;
        } else {
            pendingCps.push_back(0xFFFDu);
            ++i;
        }
        FlushCps();   // 普通字符不参与代理对拼接
    }
    return Utf8Encode(Utf16ToCodepoints(units, "percent-u 解码结果"), "percent-u 解码结果");
}

// ---------------------------- numeric-entity ------------------------------

Bytes NumericEntityEncode(const Bytes& in, bool hex) {
    std::vector<uint32_t> cps = Utf8Decode(in, "输入");
    std::string           s;
    for (uint32_t cp : cps) {
        if (hex) {
            s += Format("&#x%X;", static_cast<unsigned>(cp));
        } else {
            s += Format("&#%u;", static_cast<unsigned>(cp));
        }
    }
    return ToBytes(s);
}

Bytes NumericEntityDecode(const Bytes& in) {
    const std::string     s = Str(in);
    std::vector<uint32_t> cps;
    size_t                i = 0;
    while (i < s.size()) {
        if (s[i] == '&' && i + 1 < s.size() && s[i + 1] == '#') {
            size_t   p     = i + 2;
            uint32_t v     = 0;
            int      count = 0;
            if (p < s.size() && (s[p] == 'x' || s[p] == 'X')) {
                ++p;
                while (p < s.size() && count < 8 && IsHexDigit(s[p])) {
                    v = (v << 4) | static_cast<uint32_t>(HexVal(s[p]));
                    ++p;
                    ++count;
                }
            } else {
                while (p < s.size() && count < 8 && s[p] >= '0' && s[p] <= '9') {
                    v = v * 10u + static_cast<uint32_t>(s[p] - '0');
                    ++p;
                    ++count;
                }
            }
            if (count == 0 || p >= s.size() || s[p] != ';') {
                cps.push_back('&');   // 不是合法实体，'&' 原样输出
                ++i;
                continue;
            }
            cps.push_back(v);
            i = p + 1;
            continue;
        }
        Rune r = DecodeRune(s, i);
        if (r.ok) {
            cps.push_back(r.cp);
            i += r.width;
        } else {
            cps.push_back(0xFFFDu);
            ++i;
        }
    }
    return Utf8Encode(cps, "numeric-entity 解码结果");
}

// ----------------------------- mysql-escape -------------------------------

Bytes MysqlEscapeEncode(const Bytes& in) {
    std::string s;
    s.reserve(in.size() * 2);
    for (uint8_t b : in) {
        switch (b) {
            case 0x00: s += "\\0"; break;
            case 0x08: s += "\\b"; break;
            case 0x09: s += "\\t"; break;
            case 0x0A: s += "\\n"; break;
            case 0x0D: s += "\\r"; break;
            case 0x1A: s += "\\Z"; break;
            case 0x22: s += "\\\""; break;
            case 0x27: s += "\\'"; break;
            case 0x5C: s += "\\\\"; break;
            default:
                if (b < 0x20u || b == 0x7Fu) {
                    s += Format("\\x%02X", static_cast<unsigned>(b));
                } else {
                    s.push_back(static_cast<char>(b));
                }
                break;
        }
    }
    return ToBytes(s);
}

Bytes MysqlEscapeDecode(const Bytes& in) {
    Bytes  out;
    size_t i = 0;
    while (i < in.size()) {
        uint8_t b = in[i];
        if (b != static_cast<uint8_t>('\\')) {
            out.push_back(b);
            ++i;
            continue;
        }
        if (i + 1 >= in.size()) throw Error("MySQL 转义串以孤立的反斜杠结尾");
        char c = static_cast<char>(in[i + 1]);
        switch (c) {
            case '0': out.push_back(0x00); i += 2; break;
            case 'b': out.push_back(0x08); i += 2; break;
            case 't': out.push_back(0x09); i += 2; break;
            case 'n': out.push_back(0x0A); i += 2; break;
            case 'v': out.push_back(0x0B); i += 2; break;
            case 'f': out.push_back(0x0C); i += 2; break;
            case 'r': out.push_back(0x0D); i += 2; break;
            case 'Z': out.push_back(0x1A); i += 2; break;
            case '\\': out.push_back(0x5C); i += 2; break;
            case '\'': out.push_back(0x27); i += 2; break;
            case '"': out.push_back(0x22); i += 2; break;
            case '%': out.push_back('%');   i += 2; break;
            case '_': out.push_back('_');   i += 2; break;
            case 'x':
            case 'X': {
                if (i + 3 >= in.size() || !IsHexDigit(static_cast<char>(in[i + 2])) ||
                    !IsHexDigit(static_cast<char>(in[i + 3]))) {
                    throw Error("\\xNN 转义后面缺少两个十六进制位");
                }
                int v = HexVal(static_cast<char>(in[i + 2])) * 16 +
                        HexVal(static_cast<char>(in[i + 3]));
                out.push_back(static_cast<uint8_t>(v));
                i += 4;
                break;
            }
            default:
                throw Error(Format("未知的 MySQL 转义: \\%c", c));
        }
    }
    return out;
}

// ===========================================================================
// 八、D 类：隐写
// ===========================================================================

const uint32_t kZWJ  = 0x200Du;   // 零宽连接符：当分隔符用
const uint32_t kZWNJ = 0x200Cu;   // 零宽非连接符：bit = 1
const uint32_t kZWSP = 0x200Bu;   // 零宽空格：bit = 0

bool IsZeroWidth(uint32_t cp) { return cp == kZWJ || cp == kZWNJ || cp == kZWSP; }

Bytes ZeroWidthEncode(const Bytes& in, bool useSep, const std::string& cover) {
    std::vector<uint32_t> cps;
    cps.reserve(in.size() * 8 + 8);
    for (uint8_t b : in) {
        for (int bit = 7; bit >= 0; --bit) {
            cps.push_back(((b >> bit) & 1u) ? kZWNJ : kZWSP);
        }
        if (useSep) cps.push_back(kZWJ);
    }

    if (cover.empty()) return Utf8Encode(cps, "零宽字符隐写输出");

    std::vector<uint32_t> coverCps = Utf8DecodeLenient(ToBytes(cover));
    for (uint32_t cp : coverCps) {
        if (IsZeroWidth(cp)) {
            throw Error("掩护文本 cover 含零宽字符（U+200B/U+200C/U+200D），会破坏还原");
        }
    }
    std::vector<uint32_t> mixed;
    mixed.reserve(coverCps.size() + cps.size());
    size_t ci = 0;
    for (size_t k = 0; k < coverCps.size(); ++k) {
        if (ci < cps.size()) mixed.push_back(cps[ci++]);
        mixed.push_back(coverCps[k]);
    }
    while (ci < cps.size()) mixed.push_back(cps[ci++]);
    return Utf8Encode(mixed, "零宽字符隐写输出");
}

Bytes ZeroWidthDecode(const Bytes& in) {
    std::vector<uint32_t> cps = Utf8DecodeLenient(in);
    Bytes                 out;
    int                   acc  = 0;
    int                   bits = 0;
    for (uint32_t cp : cps) {
        if (cp == kZWJ) continue;   // 分隔符，忽略
        if (cp != kZWSP && cp != kZWNJ) continue;
        acc = (acc << 1) | (cp == kZWNJ ? 1 : 0);
        ++bits;
        if (bits == 8) {
            out.push_back(static_cast<uint8_t>(acc & 0xFF));
            acc  = 0;
            bits = 0;
        }
    }
    if (bits != 0) {
        throw Error(Format("零宽字符流不是 8 的整数倍（多出 %d 个 bit），无法还原为字节", bits));
    }
    return out;
}

// ------------------------------- unicode-tag ------------------------------

const uint32_t kTagBase = 0xE0000u;   // Unicode Tags 区起始

Bytes UnicodeTagEncode(const Bytes& in, bool bom) {
    std::vector<uint32_t> cps;
    cps.reserve(in.size() + 1);
    if (bom) cps.push_back(0xFEFFu);
    for (uint8_t b : in) cps.push_back(kTagBase + b);
    return Utf8Encode(cps, "Unicode Tags 隐写输出");
}

Bytes UnicodeTagDecode(const Bytes& in) {
    std::vector<uint32_t> cps = Utf8DecodeLenient(in);
    Bytes                 out;
    for (uint32_t cp : cps) {
        if (cp >= kTagBase && cp <= kTagBase + 0x7Fu) out.push_back(static_cast<uint8_t>(cp - kTagBase));
    }
    if (out.empty()) {
        throw Error("输入中没有发现 Unicode Tags 区字符（U+E0000..U+E007F），无法解码");
    }
    return out;
}

// --------------------------- variation-selector ---------------------------
// 每字节两个 nibble：高 nibble -> U+FE00..U+FE0F，低 nibble -> U+E0100..U+E010F
const uint32_t kVsBase    = 0xFE00u;
const uint32_t kVsSupBase = 0xE0100u;

Bytes VariationSelectorEncode(const Bytes& in) {
    std::vector<uint32_t> cps;
    cps.reserve(in.size() * 2);
    for (uint8_t b : in) {
        cps.push_back(kVsBase + ((b >> 4) & 0x0Fu));
        cps.push_back(kVsSupBase + (b & 0x0Fu));
    }
    return Utf8Encode(cps, "变体选择符隐写输出");
}

Bytes VariationSelectorDecode(const Bytes& in) {
    std::vector<uint32_t> cps = Utf8DecodeLenient(in);
    std::vector<int>      nibbles;
    for (uint32_t cp : cps) {
        if (cp >= kVsBase && cp <= kVsBase + 0x0Fu) {
            nibbles.push_back(static_cast<int>(cp - kVsBase));
        } else if (cp >= kVsSupBase && cp <= kVsSupBase + 0x0Fu) {
            nibbles.push_back(static_cast<int>(cp - kVsSupBase));
        }
    }
    if (nibbles.size() % 2 != 0) {
        throw Error(Format("变体选择符个数为奇数（%zu），无法配对成字节", nibbles.size()));
    }
    Bytes out;
    out.reserve(nibbles.size() / 2);
    for (size_t i = 0; i + 1 < nibbles.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((nibbles[i] << 4) | nibbles[i + 1]));
    }
    return out;
}

// ===========================================================================
// 九、包装函数（统一 out.clear() 与参数解析）
// ===========================================================================

void DoUtfEncode(const Bytes& in, const Params& p, Bytes& out, int kind) {
    out.clear();
    bool bom = p.GetInt("bom", 0) != 0;
    switch (kind) {
        case 0:  out = Utf16LeEncode(in, bom); break;
        case 1:  out = Utf16BeEncode(in, bom); break;
        case 2:  out = Utf32LeEncode(in, bom); break;
        default: out = Utf32BeEncode(in, bom); break;
    }
}

// toutf16le / toutf16be / toutf32le / toutf32be 的解码方向：
// 目标编码字节 -> UTF-8 文本（BOM 优先；from= 可强制指定；不带 BOM 时按本算法的端序）。
void DoUtfDecode(const Bytes& in, const Params& p, Bytes& out, int kind) {
    out.clear();
    std::string forced = ToLower(Trim(p.Get("from", "")));
    if (forced.empty()) {
        switch (kind) {
            case 0:  forced = "utf16le"; break;
            case 1:  forced = "utf16be"; break;
            case 2:  forced = "utf32le"; break;
            default: forced = "utf32be"; break;
        }
    }
    out = Toutf8Decode(in, forced, p.GetInt("bom", 0) != 0);
}

void DoToutf8(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    std::string from = ToLower(Trim(p.Get("from", "auto")));
    if (from.empty()) from = "auto";
    out = Toutf8Decode(in, from, p.GetInt("bom", 0) != 0);
}

void DoUtf7Enc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    out = Utf7Encode(in, p.GetInt("imap", 0) != 0);
}

void DoUtf7Dec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    out = Utf7Decode(in, p.GetInt("imap", 0) != 0);
}

void DoCodePageEnc(const Bytes& in, const Params& p, Bytes& out, UINT cp) {
    out.clear();
    out = CodePageEncode(in, cp, p.GetInt("replace", 0) != 0);
}

void DoCodePageDec(const Bytes& in, const Params& p, Bytes& out, UINT cp) {
    out.clear();
    (void)p;
    out = CodePageDecode(in, cp);
}

void DoCodepointEnc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    out = CodepointEncode(in, p.Get("sep", " "), p.GetInt("lower", 0) != 0);
}

void DoCodepointDec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    out = CodepointDecode(in, p.Get("sep", " "));
}

void DoUnicodeEscapeEnc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    out = UnicodeEscapeEncode(in, p.GetInt("lower", 0) != 0);
}

void DoUnicodeEscapeDec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out = UnicodeEscapeDecode(in);
}

void DoPercentUEnc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out = PercentUEncode(in);
}

void DoPercentUDec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out = PercentUDecode(in);
}

void DoNumericEntityEnc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    out = NumericEntityEncode(in, p.GetInt("base", 10) == 16);
}

void DoNumericEntityDec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out = NumericEntityDecode(in);
}

void DoMysqlEscapeEnc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out = MysqlEscapeEncode(in);
}

void DoMysqlEscapeDec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out = MysqlEscapeDecode(in);
}

void DoZeroWidthEnc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    out = ZeroWidthEncode(in, p.GetInt("sep", 0) != 0, p.Get("cover", ""));
}

void DoZeroWidthDec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out = ZeroWidthDecode(in);
}

void DoUnicodeTagEnc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    out = UnicodeTagEncode(in, p.GetInt("bom", 0) != 0);
}

void DoUnicodeTagDec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out = UnicodeTagDecode(in);
}

void DoVariationSelectorEnc(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out = VariationSelectorEncode(in);
}

void DoVariationSelectorDec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out = VariationSelectorDecode(in);
}

}  // namespace

// ===========================================================================
// 十、注册（唯一对外入口）
// ===========================================================================
void RegisterUnicode(Registry& r) {
    // ------------------------- A. UTF 编码转换 -------------------------
    // UTF-16/32 的「编码」和「解码」共用同一个变换（两个方向互逆），
    // 因此 Codec::enc 与 Codec::dec 指向同一实现。
    r.Add("toutf16le", "Unicode",
          "UTF-8 文本 <-> UTF-16LE 字节（bom=1 加 BOM，解码自动识别 BOM）", true, false,
          [](const Bytes& in, const Params& p, Bytes& out) { DoUtfEncode(in, p, out, 0); },
          [](const Bytes& in, const Params& p, Bytes& out) { DoUtfDecode(in, p, out, 0); },
          {"utf16le"});

    r.Add("toutf16be", "Unicode",
          "UTF-8 文本 <-> UTF-16BE 字节（bom=1 加 BOM，解码自动识别 BOM）", true, false,
          [](const Bytes& in, const Params& p, Bytes& out) { DoUtfEncode(in, p, out, 1); },
          [](const Bytes& in, const Params& p, Bytes& out) { DoUtfDecode(in, p, out, 1); },
          {"utf16be"});

    r.Add("toutf32le", "Unicode",
          "UTF-8 文本 <-> UTF-32LE 字节（bom=1 加 BOM，解码自动识别 BOM）", true, false,
          [](const Bytes& in, const Params& p, Bytes& out) { DoUtfEncode(in, p, out, 2); },
          [](const Bytes& in, const Params& p, Bytes& out) { DoUtfDecode(in, p, out, 2); },
          {"utf32le"});

    r.Add("toutf32be", "Unicode",
          "UTF-8 文本 <-> UTF-32BE 字节（bom=1 加 BOM，解码自动识别 BOM）", true, false,
          [](const Bytes& in, const Params& p, Bytes& out) { DoUtfEncode(in, p, out, 3); },
          [](const Bytes& in, const Params& p, Bytes& out) { DoUtfDecode(in, p, out, 3); },
          {"utf32be"});

    r.Add("toutf8", "Unicode",
          "UTF-16/32 字节 -> UTF-8（BOM 自动识别；from= 可强制指定）", true, false, DoToutf8,
          DoToutf8, {});

    r.Add("utf7", "Unicode", "RFC 2152 UTF-7 编码（imap=1 切换 Modified UTF-7 变体）", true, false,
          DoUtf7Enc, DoUtf7Dec, {"utf-7"});

    // ------------------------- B. 代码页转换 -------------------------
    r.Add("gbk", "Unicode", "GBK(936) 与 UTF-8 互转", true, false,
          [](const Bytes& in, const Params& p, Bytes& out) { DoCodePageEnc(in, p, out, 936); },
          [](const Bytes& in, const Params& p, Bytes& out) { DoCodePageDec(in, p, out, 936); },
          {"cp936"});

    r.Add("gb18030", "Unicode", "GB18030(54936) 与 UTF-8 互转", true, false,
          [](const Bytes& in, const Params& p, Bytes& out) { DoCodePageEnc(in, p, out, 54936); },
          [](const Bytes& in, const Params& p, Bytes& out) { DoCodePageDec(in, p, out, 54936); },
          {"cp54936"});

    r.Add("big5", "Unicode", "Big5(950) 与 UTF-8 互转", true, false,
          [](const Bytes& in, const Params& p, Bytes& out) { DoCodePageEnc(in, p, out, 950); },
          [](const Bytes& in, const Params& p, Bytes& out) { DoCodePageDec(in, p, out, 950); },
          {"cp950"});

    r.Add("shift-jis", "Unicode", "Shift-JIS(932) 与 UTF-8 互转", true, false,
          [](const Bytes& in, const Params& p, Bytes& out) { DoCodePageEnc(in, p, out, 932); },
          [](const Bytes& in, const Params& p, Bytes& out) { DoCodePageDec(in, p, out, 932); },
          {"sjis", "cp932"});

    r.Add("latin1", "Unicode",
          "CP1252(Latin-1) 与 UTF-8 互转（replace=1 时无法表示的字符变 ?）", true, false,
          [](const Bytes& in, const Params& p, Bytes& out) { DoCodePageEnc(in, p, out, 1252); },
          [](const Bytes& in, const Params& p, Bytes& out) { DoCodePageDec(in, p, out, 1252); },
          {"iso8859-1", "cp1252"});

    // ------------------------- C. 码点 / 转义 -------------------------
    r.Add("codepoint", "Unicode", "文本 <-> U+XXXX 码点列表（sep= 分隔符，lower=1 小写）", true,
          false, DoCodepointEnc, DoCodepointDec, {"u-plus"});

    r.Add("unicode-escape", "Unicode",
          "文本 -> \\uXXXX 转义（BMP 外自动拆 UTF-16 代理对）", true, false, DoUnicodeEscapeEnc,
          DoUnicodeEscapeDec, {"u-escape", "uescape"});

    r.Add("percent-u", "Unicode", "文本 -> %uXXXX（按 UTF-16 码元，BMP 外拆代理对）", true, false,
          DoPercentUEnc, DoPercentUDec, {"percentu", "%u"});

    r.Add("numeric-entity", "Unicode",
          "文本 -> HTML 数字实体（base=10/16，默认 10；解码两种都收）", true, false,
          DoNumericEntityEnc, DoNumericEntityDec, {"numentity", "html-numeric"});

    r.Add("mysql-escape", "Unicode",
          "MySQL 字符串转义（\\0 \\n \\r \\\\ \\' \\\" \\Z 与 \\xNN）", true, false,
          DoMysqlEscapeEnc, DoMysqlEscapeDec, {});

    // --------------------------- D. 隐写 -----------------------------
    r.Add("zero-width", "Unicode",
          "零宽字符隐写（每字节 8 bit；sep=1 加 U+200D 分隔，cover= 掩护文本）", true, false,
          DoZeroWidthEnc, DoZeroWidthDec, {"zerowidth", "zw"});

    r.Add("unicode-tag", "Unicode", "Unicode Tags 区隐写（每字节 -> U+E0000+byte，bom=1 加 BOM）",
          true, false, DoUnicodeTagEnc, DoUnicodeTagDec, {"tagsmuggle", "tag"});

    r.Add("variation-selector", "Unicode",
          "变体选择符隐写（高 nibble -> U+FE00+n，低 nibble -> U+E0100+n）", true, false,
          DoVariationSelectorEnc, DoVariationSelectorDec, {"vs-selector"});
}
}  // namespace ctf
