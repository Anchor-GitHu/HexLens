// text.cpp —— Text 分类算法：URL / HTML / 转义 / uuencode / punycode / JWT / 文本变换
//
// 设计约定：
//   * 编码输出一律为 ASCII 文本；解码一律容忍换行、空白与大小写。
//   * 任何失败都抛 ctf::Error，不 exit / abort / printf。
//   * C++17 + 纯标准库，无第三方依赖。
#include "common.h"
#include "util.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

namespace ctf {
namespace {

// ===========================================================================
// 通用小工具
// ===========================================================================

// 十六进制数字表（大小写两种）
const char* const kHexLower = "0123456789abcdef";
const char* const kHexUpper = "0123456789ABCDEF";

inline char HexDigit(unsigned v, bool upper) {
    return (upper ? kHexUpper : kHexLower)[v & 0x0F];
}

inline bool IsAsciiAlpha(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

inline bool IsAsciiDigit(char c) {
    return c >= '0' && c <= '9';
}

inline bool IsAsciiAlnum(uint8_t c) { return IsAsciiAlpha(static_cast<char>(c)) || IsAsciiDigit(static_cast<char>(c)); }

// RFC 3986 unreserved：A-Za-z0-9-_.~
inline bool IsUnreserved(uint8_t c) {
    if (IsAsciiAlnum(c)) return true;
    return c == '-' || c == '_' || c == '.' || c == '~';
}

// 去掉字符串首尾空白
std::string RTrim(const std::string& s) {
    size_t e = s.size();
    while (e > 0 && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(0, e);
}

// 十进制无符号数 -> 字符串（避免依赖 to_string 的额外开销与本地化）
std::string UIntToStr(unsigned long long v) {
    if (v == 0) return "0";
    std::string s;
    while (v > 0) {
        s.push_back(static_cast<char>('0' + (v % 10)));
        v /= 10;
    }
    std::reverse(s.begin(), s.end());
    return s;
}

// 用十六进制追加一个字节（不含前缀）
void AppendHexByte(std::string& out, uint8_t v, bool upper) {
    out.push_back(HexDigit(v >> 4, upper));
    out.push_back(HexDigit(v, upper));
}

// ===========================================================================
// UTF-8：码点 <-> 字节序列（严格校验，非法序列抛 Error）
// ===========================================================================

// 把 UTF-8 字节序列解析成码点序列；非法序列抛 Error
std::vector<uint32_t> Utf8ToCodepoints(const Bytes& in) {
    std::vector<uint32_t> cps;
    size_t i = 0;
    const size_t n = in.size();
    while (i < n) {
        uint8_t c = in[i];
        uint32_t cp = 0;
        size_t need = 0;         // 后续续字节个数
        uint32_t minv = 0;       // 该长度合法的最小码点（拒绝过长编码）
        if (c < 0x80) {
            cp   = c;
            need = 0;
            minv = 0;
        } else if ((c & 0xE0) == 0xC0) {
            cp   = c & 0x1Fu;
            need = 1;
            minv = 0x80;
        } else if ((c & 0xF0) == 0xE0) {
            cp   = c & 0x0Fu;
            need = 2;
            minv = 0x800;
        } else if ((c & 0xF8) == 0xF0) {
            cp   = c & 0x07u;
            need = 3;
            minv = 0x10000;
        } else {
            throw Error(Format("不是合法的 UTF-8 序列（位置 %zu）", i));
        }
        if (i + need >= n) {
            throw Error("UTF-8 序列被截断");
        }
        for (size_t k = 1; k <= need; ++k) {
            uint8_t cc = in[i + k];
            if ((cc & 0xC0) != 0x80) throw Error("UTF-8 续字节格式错误");
            cp = (cp << 6) | (cc & 0x3Fu);
        }
        if (need > 0 && cp < minv) throw Error("UTF-8 存在过长编码");
        if (cp > 0x10FFFFu) throw Error("UTF-8 码点超出范围");
        if (cp >= 0xD800u && cp <= 0xDFFFu) throw Error("UTF-8 含非法代理区码点");
        cps.push_back(cp);
        i += need + 1;
    }
    return cps;
}

// 把一个码点追加为 UTF-8 字节
void AppendUtf8(Bytes& out, uint32_t cp) {
    if (cp < 0x80u) {
        out.push_back(static_cast<uint8_t>(cp));
    } else if (cp < 0x800u) {
        out.push_back(static_cast<uint8_t>(0xC0u | (cp >> 6)));
        out.push_back(static_cast<uint8_t>(0x80u | (cp & 0x3Fu)));
    } else if (cp < 0x10000u) {
        out.push_back(static_cast<uint8_t>(0xE0u | (cp >> 12)));
        out.push_back(static_cast<uint8_t>(0x80u | ((cp >> 6) & 0x3Fu)));
        out.push_back(static_cast<uint8_t>(0x80u | (cp & 0x3Fu)));
    } else {
        out.push_back(static_cast<uint8_t>(0xF0u | (cp >> 18)));
        out.push_back(static_cast<uint8_t>(0x80u | ((cp >> 12) & 0x3Fu)));
        out.push_back(static_cast<uint8_t>(0x80u | ((cp >> 6) & 0x3Fu)));
        out.push_back(static_cast<uint8_t>(0x80u | (cp & 0x3Fu)));
    }
}

// ===========================================================================
// url —— 百分号编码
// ===========================================================================

// 编码输出是 ASCII；丢弃编码输出中因人为折行出现的 CR/LF，
// 但保留空格与制表符（uuencode/xxencode 里空格是合法的编码字符）。
std::string StripLineBreaks(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c != '\r' && c != '\n') out.push_back(c);
    }
    return out;
}

Bytes UrlEncodeBytes(const Bytes& in, const std::string& extraSafe, bool spacePlus, bool upper) {
    // 预置保留表：只要出现在 extraSafe 里的字符都原样输出
    bool keep[256] = {false};
    for (unsigned char c : extraSafe) keep[c] = true;

    Bytes out;
    out.reserve(in.size() * 2);
    for (uint8_t b : in) {
        if (b == ' ' && spacePlus) {
            out.push_back(static_cast<uint8_t>('+'));
            continue;
        }
        if (IsUnreserved(b) || keep[b]) {
            out.push_back(b);
            continue;
        }
        out.push_back('%');
        out.push_back(static_cast<uint8_t>(HexDigit(b >> 4, upper)));
        out.push_back(static_cast<uint8_t>(HexDigit(b, upper)));
    }
    return out;
}

Bytes UrlDecodeBytes(const Bytes& in, bool plusAsSpace) {
    Bytes out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        uint8_t c = in[i];
        // 容忍换行与空白：解码时直接忽略（编码输出可能被折行粘贴）
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (c == '%') {
            if (i + 2 >= in.size()) {
                throw Error(Format("百分号编码不完整：位置 %zu 的 '%%' 后缺少两位十六进制", i));
            }
            int hi = HexVal(static_cast<char>(in[i + 1]));
            int lo = HexVal(static_cast<char>(in[i + 2]));
            if (hi < 0 || lo < 0) {
                throw Error(Format("百分号编码含非法十六进制：位置 %zu", i));
            }
            out.push_back(static_cast<uint8_t>((hi << 4) | lo));
            i += 2;
            continue;
        }
        if (c == '+' && plusAsSpace) {
            out.push_back(static_cast<uint8_t>(' '));
            continue;
        }
        out.push_back(c);
    }
    return out;
}

void UrlEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string safe  = p.Get("safe", "");
    const bool        plus  = IEquals(p.Get("space", ""), "plus");
    const bool        upper = p.GetInt("upper", 0) != 0;
    out = UrlEncodeBytes(in, safe, plus, upper);
}

void UrlDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const bool plus = p.GetInt("plus", 1) != 0;
    out = UrlDecodeBytes(in, plus);
}

// 一次「百分号编码」，但把 '%' 本身也编成 %25（这就是双重编码的第一层效果）。
// 于是 enc 一次 = 一层，dec 一次 = 剥一层；要真正的双重编码就自己套两次 enc
// （第二次会把第一层产出的 '%' 再编成 %25），与 CTF 里「一层一层剥」一致。
void UrlDoubleEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const bool upper = p.GetInt("upper", 0) != 0;
    Bytes stage;
    stage.reserve(in.size() * 2);
    for (uint8_t b : in) {
        if (IsUnreserved(b)) {
            stage.push_back(b);
        } else {
            stage.push_back('%');
            stage.push_back(static_cast<uint8_t>(HexDigit(b >> 4, upper)));
            stage.push_back(static_cast<uint8_t>(HexDigit(b, upper)));
        }
    }
    out.swap(stage);
}

void UrlDoubleDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    // 只剥一层，与 UrlDoubleEncode 的一次调用对称（想全解开就再多调几次）
    out = UrlDecodeBytes(in, p.GetInt("plus", 1) != 0);
}

// ===========================================================================
// html —— HTML 实体
// ===========================================================================

const char* const kNamedEntityChars = "&<>\"'";

const char* const kNamedEntityTable[][2] = {
    {"&amp;",  "&"},  {"&lt;",   "<"},  {"&gt;",   ">"},  {"&quot;", "\""},
    {"&#39;",  "'"},  {"&apos;", "'"},  {"&nbsp;", "\xC2\xA0"},
};

// 解码一个数字实体，成功返回 true 并推进 pos
bool DecodeNumericEntity(const std::string& s, size_t& pos, std::string& out) {
    size_t i = pos;
    if (i >= s.size() || s[i] != '#') return false;
    ++i;
    uint32_t base = 10;
    if (i < s.size() && (s[i] == 'x' || s[i] == 'X')) {
        base = 16;
        ++i;
    }
    uint32_t val = 0;
    size_t   digits = 0;
    while (i < s.size()) {
        int dv = HexVal(s[i]);
        if (dv < 0 || static_cast<uint32_t>(dv) >= base) break;
        val = val * base + static_cast<uint32_t>(dv);
        if (val > 0x10FFFFu) {
            throw Error("HTML 数字实体的码点超出 Unicode 范围");
        }
        ++i;
        ++digits;
    }
    if (digits == 0) return false;           // 形如 "&#;" 不是实体
    if (i >= s.size() || s[i] != ';') return false;
    // 数值 <= 255 时按「原始字节」输出，这样 all=1 的逐字节数字实体能完美往返；
    // 更大的值才当作 Unicode 码点编码成 UTF-8（如 &#x4E2D; -> 中）。
    if (val <= 0xFFu) {
        out.push_back(static_cast<char>(static_cast<unsigned char>(val)));
    } else {
        Bytes b;
        AppendUtf8(b, val);
        out.append(reinterpret_cast<const char*>(b.data()), b.size());
    }
    pos = i + 1;
    return true;
}

// 解码 "&...;"（含命名与数字实体），返回消费的字符数；不是合法实体返回 0
size_t DecodeOneEntity(const std::string& s, size_t pos, std::string& out) {
    if (pos >= s.size() || s[pos] != '&') return 0;
    // 实体长度有上限，避免把超长文本当实体扫描
    size_t limit = std::min(s.size(), pos + 34);
    // 先试命名实体
    for (const auto& e : kNamedEntityTable) {
        std::string name = e[0];
        if (pos + name.size() <= s.size() && s.compare(pos, name.size(), name) == 0) {
            out += e[1];
            return name.size();
        }
    }
    if (pos + 1 < s.size() && s[pos + 1] == '#') {
        size_t p = pos + 1;
        size_t before = out.size();
        if (DecodeNumericEntity(s, p, out)) return p - pos;
        out.resize(before);
        return 0;
    }
    // 容错：扫描到 ';'，若是已知实体名则支持大小写宽松匹配
    size_t semi = s.find(';', pos + 1);
    if (semi != std::string::npos && semi < limit) {
        std::string name = ToLower(s.substr(pos, semi - pos + 1));
        for (const auto& e : kNamedEntityTable) {
            if (name == ToLower(std::string(e[0]))) {
                out += e[1];
                return semi - pos + 1;
            }
        }
    }
    return 0;
}

void HtmlEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const bool all = p.GetInt("all", 0) != 0;
    std::string s;
    s.reserve(in.size() * 2);
    for (uint8_t b : in) {
        // 五个特殊字符始终用命名实体，保证输出可读且可逆
        const char* named = nullptr;
        switch (b) {
            case '&': named = "&amp;";  break;
            case '<': named = "&lt;";   break;
            case '>': named = "&gt;";   break;
            case '"': named = "&quot;"; break;
            case '\'': named = "&#39;"; break;
            default: break;
        }
        if (named != nullptr) {
            s += named;
            continue;
        }
        if (all && (b < 0x20 || b > 0x7E)) {
            s += "&#";
            s += UIntToStr(b);
            s += ";";
            continue;
        }
        s.push_back(static_cast<char>(b));
    }
    out.assign(s.begin(), s.end());
}

void HtmlDecode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    const std::string s(in.begin(), in.end());
    std::string r;
    r.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] == '&') {
            size_t used = DecodeOneEntity(s, i, r);
            if (used > 0) {
                i += used;
                continue;
            }
        }
        r.push_back(s[i]);
        ++i;
    }
    out.assign(r.begin(), r.end());
}

// ===========================================================================
// css-escape —— CSS 十六进制转义
// ===========================================================================

void CssEncode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    std::string s;
    s.reserve(in.size() * 4);
    for (uint8_t b : in) {
        s.push_back('\\');
        AppendHexByte(s, b, false);
        s.push_back(' ');            // 尾随空格作为分隔符
    }
    out.assign(s.begin(), s.end());
}

void CssDecode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    const std::string s(in.begin(), in.end());
    std::vector<uint8_t> r;
    size_t i = 0;
    while (i < s.size()) {
        // CSS 的十六进制转义以 '\' 开头，反斜杠后可跟换行（续行）后仍是十六进制
        if (s[i] == '\\' && i + 1 < s.size() && HexVal(s[i + 1]) >= 0) {
            size_t   j = i + 1;
            unsigned v = 0;
            int      count = 0;
            while (j < s.size() && count < 6 && HexVal(s[j]) >= 0) {
                v = v * 16u + static_cast<unsigned>(HexVal(s[j]));
                ++j;
                ++count;
            }
            if (i + 1 < s.size() && s[i + 1] == '\r' && i + 2 < s.size() && s[i + 2] == '\n') {
                // 反斜杠 + CRLF + 十六进制（极少见，宽容处理）
                j = i + 3;
                v = 0;
                count = 0;
                while (j < s.size() && count < 6 && HexVal(s[j]) >= 0) {
                    v = v * 16u + static_cast<unsigned>(HexVal(s[j]));
                    ++j;
                    ++count;
                }
            }
            if (v > 0xFFu) throw Error(Format("CSS 转义值 0x%X 超出单字节范围", v));
            r.push_back(static_cast<uint8_t>(v));
            // 吃掉一个可选的分隔空白
            if (j < s.size() && (s[j] == ' ' || s[j] == '\t')) ++j;
            else if (j < s.size() && s[j] == '\r' && j + 1 < s.size() && s[j + 1] == '\n') j += 2;
            else if (j < s.size() && s[j] == '\n') ++j;
            i = j;
            continue;
        }
        // 容忍换行/空白（编码输出可能被折行）
        if (s[i] == '\r' || s[i] == '\n' || s[i] == ' ' || s[i] == '\t') {
            ++i;
            continue;
        }
        r.push_back(static_cast<uint8_t>(s[i]));
        ++i;
    }
    out.assign(r.begin(), r.end());
}

// ===========================================================================
// c-escape / octal-escape / escape-bash —— 反斜杠转义族
// ===========================================================================

void CEscapeEncode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    std::string s;
    s.reserve(in.size() * 2);
    for (uint8_t b : in) {
        switch (b) {
            case '\n': s += "\\n";  break;
            case '\r': s += "\\r";  break;
            case '\t': s += "\\t";  break;
            case '\\': s += "\\\\"; break;
            case '"':  s += "\\\""; break;
            case '\0': s += "\\0";  break;
            default:
                if (b < 0x20 || b == 0x7F) {
                    s += "\\x";
                    AppendHexByte(s, b, false);
                } else {
                    s.push_back(static_cast<char>(b));
                }
                break;
        }
    }
    out.assign(s.begin(), s.end());
}

// 通用反斜杠转义解码：识别 \n \r \t \0 \\ \" \' \a \b \f \v \xNN \NNN(八进制) \uXXXX
Bytes EscapeDecodeCore(const Bytes& in, size_t start, size_t end, bool allowUnknownPassthrough) {
    const std::string s(in.begin(), in.end());
    std::vector<uint8_t> r;
    r.reserve(end > start ? end - start : 0);
    size_t i = start;
    while (i < end) {
        if (s[i] != '\\') {
            r.push_back(static_cast<uint8_t>(s[i]));
            ++i;
            continue;
        }
        if (i + 1 >= end) throw Error("转义序列不完整：结尾处的单个反斜杠");
        char c = s[i + 1];
        size_t j = i + 2;
        switch (c) {
            case 'n':  r.push_back('\n'); i = j; continue;
            case 'r':  r.push_back('\r'); i = j; continue;
            case 't':  r.push_back('\t'); i = j; continue;
            case 'a':  r.push_back('\a'); i = j; continue;
            case 'b':  r.push_back('\b'); i = j; continue;
            case 'f':  r.push_back('\f'); i = j; continue;
            case 'v':  r.push_back('\v'); i = j; continue;
            case '\\': r.push_back('\\'); i = j; continue;
            case '"':  r.push_back('"');  i = j; continue;
            case '\'': r.push_back('\''); i = j; continue;
            case '?':  r.push_back('?');  i = j; continue;
            case '\r':
                // 反斜杠 + CRLF/LF 续行：整段丢弃
                if (j < end && s[j] == '\n') ++j;
                i = j;
                continue;
            case '\n':
                i = j;
                continue;
            case 'x': {
                unsigned v = 0;
                int      count = 0;
                size_t   k = j;
                while (k < end && count < 2 && HexVal(s[k]) >= 0) {
                    v = v * 16u + static_cast<unsigned>(HexVal(s[k]));
                    ++k;
                    ++count;
                }
                if (count == 0) throw Error("\\x 转义后缺少十六进制数字");
                r.push_back(static_cast<uint8_t>(v));
                i = k;
                continue;
            }
            case 'u':
            case 'U': {
                size_t want = (c == 'u') ? 4u : 8u;
                unsigned v = 0;
                size_t   k = j;
                size_t   count = 0;
                while (k < end && count < want && HexVal(s[k]) >= 0) {
                    v = v * 16u + static_cast<unsigned>(HexVal(s[k]));
                    ++k;
                    ++count;
                }
                if (count < want) throw Error("\\u 转义位数不足");
                if (v > 0x10FFFFu) throw Error("\\u 码点超出 Unicode 范围");
                AppendUtf8(r, v);
                i = k;
                continue;
            }
            default:
                if (c >= '0' && c <= '7') {
                    // 八进制：贪婪吃最多 3 位；但 '\0' 后若不是八进制数字，就只算 NUL 本身
                    // （C 的 \0 语义，保证 "A\0B" 与 "\000" 都能正确解出）
                    size_t   k = i + 1;
                    unsigned v = 0;
                    int      count = 0;
                    while (k < end && count < 3 && s[k] >= '0' && s[k] <= '7') {
                        unsigned nv = v * 8u + static_cast<unsigned>(s[k] - '0');
                        if (count == 0 && c == '0' && s[k] != '0') {
                            break;      // \0 后面紧跟非零八进制数字：只当 NUL
                        }
                        v = nv;
                        ++k;
                        ++count;
                    }
                    if (count == 0) {
                        v = 0;          // '\0' + 非八进制字符
                    }
                    if (v > 0xFFu) {
                        throw Error(Format("八进制转义 \\%s 超出单字节范围", s.substr(i + 1, 3).c_str()));
                    }
                    r.push_back(static_cast<uint8_t>(v));
                    i = k;
                    continue;
                }
                if (allowUnknownPassthrough) {
                    // 未知转义：原样保留（HTML/CSS 等文本里反斜杠很常见）
                    r.push_back('\\');
                    r.push_back(static_cast<uint8_t>(c));
                    i = j;
                    continue;
                }
                throw Error(Format("不认识的转义序列：\\%c", c));
        }
    }
    return Bytes(r.begin(), r.end());
}

void CEscapeDecode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out = EscapeDecodeCore(in, 0, in.size(), false);
}

void OctalEscapeEncode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    std::string s;
    s.reserve(in.size() * 4);
    for (uint8_t b : in) {
        s.push_back('\\');
        s.push_back(static_cast<char>('0' + ((b >> 6) & 0x07)));
        s.push_back(static_cast<char>('0' + ((b >> 3) & 0x07)));
        s.push_back(static_cast<char>('0' + (b & 0x07)));
    }
    out.assign(s.begin(), s.end());
}

void BashEscapeEncode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    if (in.empty()) return;                  // 空输入 -> 空输出
    std::string s;
    s.reserve(in.size() * 4 + 3);
    s += "$'";
    for (uint8_t b : in) {
        s += "\\x";
        AppendHexByte(s, b, false);
    }
    s += "'";
    out.assign(s.begin(), s.end());
}

void BashEscapeDecode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    std::string s = Trim(std::string(in.begin(), in.end()));
    size_t start = 0;
    size_t end   = s.size();
    if (end >= 3 && s.compare(0, 2, "$'") == 0 && s[end - 1] == '\'') {
        start = 2;
        end   = end - 1;
    } else if (end >= 2 && s[0] == '\'' && s[end - 1] == '\'') {
        start = 1;
        end   = end - 1;
    }
    out = EscapeDecodeCore(in, start, end, false);
}

// ===========================================================================
// quoted-printable —— RFC 2045
// ===========================================================================

void QpEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    if (in.empty()) return;                  // 空输入 -> 空输出
    int lineWidth = p.GetInt("line", 76);
    if (lineWidth < 4 || lineWidth > 998) {
        throw Error("参数 line 必须在 4..998 之间");
    }

    // 只在超过折行宽度时才插入软换行（尾随 "=" + CRLF），不额外补行尾 CRLF：
    // 这样单行文本的输出保持"最小且干净"，与库内自检向量一致。
    std::string result;
    std::string line;
    for (size_t i = 0; i < in.size(); ++i) {
        uint8_t b = in[i];
        std::string tok;
        if ((b >= 0x21 && b <= 0x7E && b != '=')) {
            tok.push_back(static_cast<char>(b));
        } else if ((b == ' ' || b == '\t') && i + 1 != in.size()) {
            tok.push_back(static_cast<char>(b));      // 非行尾空白可原样输出
        } else {
            // 其余（含 '='、行尾空白、不可打印字节）一律用 =XX 表示
            tok.push_back('=');
            tok.push_back(HexDigit(b >> 4, true));
            tok.push_back(HexDigit(b, true));
        }
        if (line.size() + tok.size() > static_cast<size_t>(lineWidth) - 1) {
            line.push_back('=');                      // 软换行
            result += line;
            result += "\r\n";
            line.clear();
        }
        line += tok;
    }
    result += line;
    out.assign(result.begin(), result.end());
}

void QpDecode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    // 确定有效数据末尾：去掉「最后一行结尾附加的 CRLF」，但若这个 CRLF 前面正好是
    // 软换行的 '=' 则必须保留（那是正文的一部分）。行尾空白不能丢，因为 QP 里
    // 行尾空白属于正文（编码器会把它写成 =20/=09）。
    size_t e = in.size();
    if (e >= 2 && in[e - 2] == '\r' && in[e - 1] == '\n') {
        size_t t = e - 2;
        // "=\r\n" 结尾说明后面还有续行；而 CRLF 前面已经是换行符时，这个 CRLF 是
        // 正文自身的行尾，不能丢。两种情况都保留这个 CRLF。
        bool soft = (t > 0 && in[t - 1] == '=');
        bool contentEnd = (t > 0 && (in[t - 1] == '\n' || in[t - 1] == '\r'));
        if (!soft && !contentEnd) e = t;
    }
    const size_t n = e;

    std::vector<uint8_t> r;
    r.reserve(n);
    size_t i = 0;
    while (i < n) {
        uint8_t c = in[i];
        if (c == '=') {
            if (i + 1 < n && in[i + 1] == '\r' && i + 2 < n && in[i + 2] == '\n') {  // =CRLF
                i += 3;
                continue;
            }
            if (i + 1 < n && in[i + 1] == '\n') {          // =LF
                i += 2;
                continue;
            }
            if (i + 1 >= n) {                              // 末尾孤立的 '='：宽容丢弃
                i = n;
                continue;
            }
            if (in[i + 1] == '\r' && i + 2 >= n) {          // 末尾孤立 "=\r"
                i = n;
                continue;
            }
            int hi = HexVal(static_cast<char>(in[i + 1]));
            int lo = (i + 2 < n) ? HexVal(static_cast<char>(in[i + 2])) : -1;
            if (hi < 0 || lo < 0) throw Error("quoted-printable 中含非法的 =XX 转义");
            r.push_back(static_cast<uint8_t>((hi << 4) | lo));
            i += 3;
            continue;
        }
        if (c == '\r' && i + 1 < n && in[i + 1] == '\n') {   // 硬换行统一成 LF
            r.push_back('\n');
            i += 2;
            continue;
        }
        r.push_back(c);
        ++i;
    }
    out.assign(r.begin(), r.end());
}

// ===========================================================================
// uuencode / xxencode
// ===========================================================================

// uuencode 的值表：char -> 6bit，长度字符用 ((c - 32) & 0x3F)
int UuVal(uint8_t c) { return static_cast<int>((c - 32) & 0x3F); }

// 经典 uuencode 的 6bit 字母表
std::string UuValueChars() {
    std::string t(64, ' ');
    for (int v = 0; v < 64; ++v) t[static_cast<size_t>(v)] = static_cast<char>(v + 32);
    return t;
}

// xxencode 的字母表
const char* const kXxAlpha =
    "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// uu / xx 共用的编码主体。vc 是 6bit 值 -> 字符的字母表（长度必须是 64）；
// lenOffset >= 0 时长度字符用 (len & 0x3F) + lenOffset，否则用字母表查表。
std::string BuildUuEncode(const Bytes& in, const std::string& vc, int lenOffset,
                          const std::string& header, const std::string& trailer) {
    std::string out;
    out += header;
    out += "\r\n";
    const size_t kLineBytes = 45;
    size_t pos = 0;
    while (pos < in.size()) {
        size_t chunk = std::min(kLineBytes, in.size() - pos);
        if (lenOffset >= 0) {
            out.push_back(static_cast<char>((chunk & 0x3F) + static_cast<size_t>(lenOffset)));
        } else {
            out.push_back(vc[chunk & 0x3F]);
        }
        size_t groups = (chunk + 2) / 3;
        for (size_t g = 0; g < groups; ++g) {
            uint8_t b0 = 0, b1 = 0, b2 = 0;
            size_t  base = pos + g * 3;
            if (base < in.size()) b0 = in[base];
            if (base + 1 < in.size()) b1 = in[base + 1];
            if (base + 2 < in.size()) b2 = in[base + 2];
            unsigned triple = (static_cast<unsigned>(b0) << 16) |
                              (static_cast<unsigned>(b1) << 8) |
                              static_cast<unsigned>(b2);
            out.push_back(vc[(triple >> 18) & 0x3F]);
            out.push_back(vc[(triple >> 12) & 0x3F]);
            out.push_back(vc[(triple >> 6) & 0x3F]);
            out.push_back(vc[triple & 0x3F]);
        }
        out += "\r\n";
        pos += chunk;
    }
    out += trailer;
    out += "\r\n";
    return out;
}

// 通用的 uu/xx 解码。valFn: 数据字符 -> 6bit 值（非法返回 -1）
template <typename ValFn>
Bytes DecodeUuLike(const Bytes& in, ValFn valFn) {
    const std::string s(in.begin(), in.end());
    std::vector<uint8_t> r;
    size_t i = 0;
    while (i <= s.size()) {
        size_t nl = s.find('\n', i);
        std::string line = (nl == std::string::npos) ? s.substr(i) : s.substr(i, nl - i);
        i = (nl == std::string::npos) ? s.size() + 1 : nl + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();

        // 注意：不能 RTrim 掉行尾空格——' '(0x20) 是 uu/xx 的合法编码字符（值 0）。
        // 先跳过行首空白，再读长度字符。
        size_t p = 0;
        while (p < line.size() && (line[p] == ' ' || line[p] == '\t')) ++p;
        if (p >= line.size()) continue;                      // 空行
        if (line.compare(p, 5, "begin") == 0) continue;      // 头行
        if (line.compare(p, 3, "end") == 0) break;           // 尾行
        if (line[p] == '`') continue;                        // 经典 uuencode 的零长度行

        int n = valFn(static_cast<uint8_t>(line[p]));
        if (n < 0) throw Error("uuencode/xxencode 行首长度字符非法");
        if (n > 45) throw Error("uuencode/xxencode 行长超过 45 字节");
        ++p;

        // 取出这一行实际承载的数据字符。注意：' ' 既是分隔符又是合法编码字符
        // （值 0），无法区分，所以按「整行长度」判断是否够用：长度字符本身占 1
        // 个字符，其余位置都算数据；另外允许行内出现制表符等空白（忽略）。
        std::string payload;
        payload.reserve(line.size() > p ? line.size() - p : 0);
        for (size_t k = p; k < line.size(); ++k) {
            unsigned char ch = static_cast<unsigned char>(line[k]);
            if (ch == '\t' || ch == '\r') continue;
            payload.push_back(static_cast<char>(ch));
        }

        size_t needChars = static_cast<size_t>((n + 2) / 3) * 4;
        if (line.size() < 1 + needChars) throw Error("uuencode/xxencode 数据行长度不足");
        if (payload.size() < needChars) throw Error("uuencode/xxencode 数据行数据不足");

        size_t produced = 0;
        for (size_t k = 0; k + 3 < payload.size() && produced < static_cast<size_t>(n); k += 4) {
            int v0 = valFn(static_cast<uint8_t>(payload[k]));
            int v1 = valFn(static_cast<uint8_t>(payload[k + 1]));
            int v2 = valFn(static_cast<uint8_t>(payload[k + 2]));
            int v3 = valFn(static_cast<uint8_t>(payload[k + 3]));
            if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
                throw Error("uuencode/xxencode 数据行含非法编码字符");
            }
            unsigned triple = (static_cast<unsigned>(v0) << 18) |
                              (static_cast<unsigned>(v1) << 12) |
                              (static_cast<unsigned>(v2) << 6) |
                              static_cast<unsigned>(v3);
            uint8_t b0 = static_cast<uint8_t>((triple >> 16) & 0xFF);
            uint8_t b1 = static_cast<uint8_t>((triple >> 8) & 0xFF);
            uint8_t b2 = static_cast<uint8_t>(triple & 0xFF);
            if (produced < static_cast<size_t>(n)) { r.push_back(b0); ++produced; }
            if (produced < static_cast<size_t>(n)) { r.push_back(b1); ++produced; }
            if (produced < static_cast<size_t>(n)) { r.push_back(b2); ++produced; }
        }
        if (produced < static_cast<size_t>(n)) throw Error("uuencode/xxencode 数据行数据不足");
    }
    return Bytes(r.begin(), r.end());
}

void UuEncodeFn(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    if (in.empty()) return;                  // 空输入 -> 空输出
    const std::string s = BuildUuEncode(in, UuValueChars(), 32, "begin 644 file", "`");
    out.assign(s.begin(), s.end());
    const std::string tail = "end\r\n";
    out.insert(out.end(), tail.begin(), tail.end());
}

void UuDecodeFn(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out = DecodeUuLike(in, [](uint8_t c) { return UuVal(c); });
}

int XxVal(uint8_t c) {
    size_t idx = std::string(kXxAlpha).find(static_cast<char>(c));
    return (idx == std::string::npos) ? -1 : static_cast<int>(idx);
}

void XxEncodeFn(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    if (in.empty()) return;                  // 空输入 -> 空输出
    std::string s = BuildUuEncode(in, kXxAlpha, -1, "begin 644 file", "");
    if (s.size() >= 2 && s.compare(s.size() - 2, 2, "\r\n") == 0) s.erase(s.size() - 2);
    s += "+\r\n";                            // xxencode 的零长度行
    s += "end\r\n";
    out.assign(s.begin(), s.end());
}

void XxDecodeFn(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out = DecodeUuLike(in, [](uint8_t c) { return XxVal(c); });
}

// ===========================================================================
// punycode —— RFC 3492
// ===========================================================================

const unsigned kPunyBase        = 36;
const unsigned kPunyTMin        = 1;
const unsigned kPunyTMax        = 26;
const unsigned kPunySkew        = 38;
const unsigned kPunyDamp        = 700;
const unsigned kPunyInitialBias = 72;
const unsigned kPunyInitialN    = 128;
const uint32_t kPunyMaxInt      = 0x7FFFFFFFu;
const uint32_t kPunyMaxCp       = 0x10FFFFu;

// RFC 3492 的 adapt：编码/解码共用的偏差自适应
unsigned PunyAdapt(uint64_t delta, unsigned numPoints, bool firstTime) {
    delta /= firstTime ? kPunyDamp : 2;
    delta += delta / numPoints;
    unsigned k = 0;
    while (delta > ((kPunyBase - kPunyTMin) * kPunyTMax) / 2) {
        delta /= (kPunyBase - kPunyTMin);
        k += kPunyBase;
    }
    return k + static_cast<unsigned>(((kPunyBase - kPunyTMin + 1) * delta) / (delta + kPunySkew));
}

int PunyDigitToBasic(uint32_t d) {
    // 0..25 -> 'a'..'z'，26..35 -> '0'..'9'
    return (d < 26u) ? static_cast<int>('a' + d) : static_cast<int>('0' + (d - 26u));
}

int PunyBasicToDigit(uint32_t cp) {
    if (cp >= 'a' && cp <= 'z') return static_cast<int>(cp - 'a');
    if (cp >= 'A' && cp <= 'Z') return static_cast<int>(cp - 'A');
    if (cp >= '0' && cp <= '9') return static_cast<int>(cp - '0' + 26);
    return -1;
}

Bytes PunyEncodeBytes(const Bytes& in) {
    const std::vector<uint32_t> cps = Utf8ToCodepoints(in);

    std::vector<uint32_t> basic;
    basic.reserve(cps.size());
    for (uint32_t cp : cps) {
        if (cp < kPunyInitialN) basic.push_back(cp);
    }

    std::string out;
    out.reserve(in.size() * 2);
    for (uint32_t cp : basic) out.push_back(static_cast<char>(cp));
    size_t h = basic.size();
    if (h > 0) out.push_back('-');
    if (h == cps.size()) return Bytes(out.begin(), out.end());   // 全 basic，直接加 '-' 收尾

    uint64_t n   = kPunyInitialN;
    uint64_t delta = 0;
    unsigned bias = kPunyInitialBias;

    while (h < cps.size()) {
        // 取下一个待编码的最小码点
        uint64_t m = kPunyMaxInt;
        for (uint32_t cp : cps) {
            if (cp >= n && cp < m) m = cp;
        }
        if (m == kPunyMaxInt) throw Error("punycode 编码失败：找不到可编码的码点");
        if (m - n > (kPunyMaxInt - delta) / (h + 1)) {
            throw Error("punycode 编码溢出（输入过长或码点过大）");
        }
        delta += (m - n) * (h + 1);
        n = m;
        for (uint32_t cp : cps) {
            if (cp < n) {
                if (++delta > kPunyMaxInt) throw Error("punycode 编码溢出");
            } else if (cp == n) {
                uint64_t q = delta;
                for (unsigned k = kPunyBase;; k += kPunyBase) {
                    unsigned t = 0;
                    if (k <= bias) t = kPunyTMin;
                    else if (k >= bias + kPunyTMax) t = kPunyTMax;
                    else t = k - bias;
                    if (q < t) break;
                    out.push_back(static_cast<char>(PunyDigitToBasic(
                        static_cast<uint32_t>(t + (q - t) % (kPunyBase - t)))));
                    q = (q - t) / (kPunyBase - t);
                }
                out.push_back(static_cast<char>(PunyDigitToBasic(static_cast<uint32_t>(q))));
                bias = PunyAdapt(delta, static_cast<unsigned>(h + 1), h == basic.size());
                delta = 0;
                ++h;
            }
        }
        ++delta;
        ++n;
    }
    return Bytes(out.begin(), out.end());
}

Bytes PunyDecodeBytes(const Bytes& in) {
    std::string s(in.begin(), in.end());
    // 容忍折行；只去掉尾部空白，保留串内与串首空白（' ' 是合法的 basic code point）
    s = RTrim(StripLineBreaks(s));
    // 容忍 xn-- 前缀（RFC 3492 只定义纯 punycode，这里做输入宽松处理）
    if (s.size() > 4 && IEquals(s.substr(0, 4), "xn--")) s = s.substr(4);
    if (s.empty()) return Bytes();

    std::vector<uint32_t> output;
    size_t delim = s.rfind('-');
    if (delim != std::string::npos) {
        for (size_t i = 0; i < delim; ++i) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (c >= 0x80) throw Error("punycode 基本段含非 ASCII 字符");
            output.push_back(c);
        }
    }
    size_t pos = (delim == std::string::npos) ? 0 : delim + 1;

    uint64_t n    = kPunyInitialN;
    uint64_t i    = 0;
    unsigned bias = kPunyInitialBias;

    while (pos < s.size()) {
        uint64_t oldi = i;
        uint64_t w    = 1;
        for (unsigned k = kPunyBase;; k += kPunyBase) {
            if (pos >= s.size()) throw Error("punycode 解码：输入意外结束");
            int digit = PunyBasicToDigit(static_cast<unsigned char>(s[pos]));
            if (digit < 0) throw Error(Format("punycode 含非法字符 '%c'", s[pos]));
            ++pos;
            if (static_cast<uint64_t>(digit) > (kPunyMaxInt - i) / w) {
                throw Error("punycode 解码溢出");
            }
            i += static_cast<uint64_t>(digit) * w;
            unsigned t = 0;
            if (k <= bias) t = kPunyTMin;
            else if (k >= bias + kPunyTMax) t = kPunyTMax;
            else t = k - bias;
            if (static_cast<uint64_t>(digit) < t) break;
            if (w > kPunyMaxInt / (kPunyBase - t)) throw Error("punycode 解码溢出");
            w *= (kPunyBase - t);
        }
        uint64_t outLen = output.size() + 1;
        bias = PunyAdapt(i - oldi, static_cast<unsigned>(outLen), oldi == 0);
        if (i / outLen > kPunyMaxInt - n) throw Error("punycode 解码溢出");
        n += i / outLen;
        i %= outLen;
        if (n > kPunyMaxCp) throw Error("punycode 解码得到的码点超出 Unicode 范围");
        output.insert(output.begin() + static_cast<std::ptrdiff_t>(i), static_cast<uint32_t>(n));
        ++i;
    }

    Bytes out;
    out.reserve(output.size() * 2);
    for (uint32_t cp : output) AppendUtf8(out, cp);
    return out;
}

void PunyEncodeFn(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    out = PunyEncodeBytes(in);
}

void PunyDecodeFn(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    out = PunyDecodeBytes(in);
}

// ===========================================================================
// jwt —— 解析（不可逆）
// ===========================================================================

// 宽松的 base64url 解码：容忍换行/空白与缺失的 '=' 填充
Bytes Base64UrlDecode(const std::string& seg) {
    static int lut[256];
    static bool lutReady = false;
    if (!lutReady) {
        for (int i = 0; i < 256; ++i) lut[i] = -1;
        const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (int i = 0; i < 64; ++i) lut[static_cast<unsigned char>(alpha[i])] = i;
        lutReady = true;
    }

    Bytes out;
    out.reserve(seg.size() * 3 / 4 + 3);
    unsigned acc = 0;
    int      bits = 0;
    for (unsigned char c : seg) {
        if (c == '=' || std::isspace(c)) continue;       // 忽略填充与空白
        int v = lut[c];
        if (v < 0) {
            throw Error(Format("JWT 段不是合法的 base64url 字符：'%c'", static_cast<char>(c)));
        }
        acc = (acc << 6) | static_cast<unsigned>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFFu));
        }
    }
    return out;
}

void JwtDecode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    const std::string s = Trim(std::string(in.begin(), in.end()));
    if (s.empty()) throw Error("JWT 输入为空");

    std::vector<std::string> parts = Split(s, '.');
    if (parts.size() != 3) {
        throw Error(Format("JWT 格式错误：按 '.' 分割得到 %zu 段，应为 3 段（header.payload.signature）",
                           parts.size()));
    }

    const Bytes hdr = Base64UrlDecode(parts[0]);
    const Bytes pay = Base64UrlDecode(parts[1]);

    std::string r;
    r += "Header: ";
    r.append(reinterpret_cast<const char*>(hdr.data()), hdr.size());
    r += "\nPayload: ";
    r.append(reinterpret_cast<const char*>(pay.data()), pay.size());
    r += "\nSignature: ";
    r += parts[2];
    out.assign(r.begin(), r.end());
}

// ===========================================================================
// leet —— 1337 speak
// ===========================================================================

void LeetEncode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    Bytes r;
    r.reserve(in.size());
    for (uint8_t b : in) {
        switch (b) {
            case 'a': r.push_back('4'); break;
            case 'A': r.push_back('4'); break;
            case 'b': r.push_back('8'); break;
            case 'B': r.push_back('8'); break;
            case 'e': r.push_back('3'); break;
            case 'E': r.push_back('3'); break;
            case 'g': r.push_back('6'); break;
            case 'G': r.push_back('6'); break;
            case 'i': r.push_back('1'); break;
            case 'I': r.push_back('1'); break;
            case 'l': r.push_back('1'); break;
            case 'L': r.push_back('1'); break;
            case 'o': r.push_back('0'); break;
            case 'O': r.push_back('0'); break;
            case 's': r.push_back('5'); break;
            case 'S': r.push_back('5'); break;
            case 't': r.push_back('7'); break;
            case 'T': r.push_back('7'); break;
            case 'z': r.push_back('2'); break;
            case 'Z': r.push_back('2'); break;
            default:  r.push_back(b);  break;
        }
    }
    out.swap(r);
}

void LeetDecode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    Bytes r;
    r.reserve(in.size());
    for (uint8_t b : in) {
        switch (b) {
            case '4': r.push_back('a'); break;
            case '8': r.push_back('b'); break;
            case '3': r.push_back('e'); break;
            case '6': r.push_back('g'); break;
            case '1': r.push_back('i'); break;   // 有歧义：1 -> i
            case '0': r.push_back('o'); break;   // 有歧义：0 -> o
            case '5': r.push_back('s'); break;
            case '7': r.push_back('t'); break;
            case '2': r.push_back('z'); break;
            default:  r.push_back(b);  break;
        }
    }
    out.swap(r);
}

// ===========================================================================
// reverse —— 字节 / UTF-8 字符反转
// ===========================================================================

void ReverseCodec(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string mode = ToLower(p.Get("mode", "char"));
    if (mode == "byte" || mode == "bytes") {
        out.assign(in.rbegin(), in.rend());
        return;
    }
    if (mode != "char" && mode != "chars" && mode != "utf8" && mode != "utf-8") {
        throw Error("参数 mode 只能是 byte 或 char");
    }
    std::vector<uint32_t> cps = Utf8ToCodepoints(in);
    std::reverse(cps.begin(), cps.end());
    out.reserve(in.size());
    for (uint32_t cp : cps) AppendUtf8(out, cp);
}

// ===========================================================================
// upper / lower / swapcase
// ===========================================================================

void UpperEncode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    out.reserve(in.size());
    for (uint8_t b : in) {
        out.push_back(static_cast<uint8_t>((b >= 'a' && b <= 'z') ? (b - 'a' + 'A') : b));
    }
}

void LowerEncode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    out.reserve(in.size());
    for (uint8_t b : in) {
        out.push_back(static_cast<uint8_t>((b >= 'A' && b <= 'Z') ? (b - 'A' + 'a') : b));
    }
}

void SwapCaseCodec(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    out.reserve(in.size());
    for (uint8_t b : in) {
        if (b >= 'a' && b <= 'z') out.push_back(static_cast<uint8_t>(b - 'a' + 'A'));
        else if (b >= 'A' && b <= 'Z') out.push_back(static_cast<uint8_t>(b - 'A' + 'a'));
        else out.push_back(b);
    }
}

// ===========================================================================
// nato —— 北约音标字母表
// ===========================================================================

const char* const kNatoTable[][2] = {
    {"A", "Alfa"},    {"B", "Bravo"},   {"C", "Charlie"}, {"D", "Delta"},
    {"E", "Echo"},    {"F", "Foxtrot"}, {"G", "Golf"},    {"H", "Hotel"},
    {"I", "India"},   {"J", "Juliett"}, {"K", "Kilo"},    {"L", "Lima"},
    {"M", "Mike"},    {"N", "November"},{"O", "Oscar"},   {"P", "Papa"},
    {"Q", "Quebec"},  {"R", "Romeo"},   {"S", "Sierra"},  {"T", "Tango"},
    {"U", "Uniform"}, {"V", "Victor"},  {"W", "Whiskey"}, {"X", "Xray"},
    {"Y", "Yankee"},  {"Z", "Zulu"},
    // 常见变体写法也一并支持（解码时使用；编码永远用上表的标准写法）
    {"X", "X-ray"},   {"J", "Juliet"},  {"A", "Alpha"},
};

void NatoEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string sep   = p.Get("sep", " ");
    const bool        lower = p.GetInt("lower", 0) != 0;
    std::string r;
    bool first = true;
    for (uint8_t b : in) {
        if (IsAsciiAlpha(static_cast<char>(b))) {
            char upper = static_cast<char>(std::toupper(static_cast<unsigned char>(b)));
            std::string word;
            for (const auto& e : kNatoTable) {
                if (e[0][0] == upper) { word = e[1]; break; }
            }
            if (word.empty()) throw Error("北约字母表内部错误：缺少字母 " + std::string(1, upper));
            if (!first) r += sep;
            r += lower ? ToLower(word) : word;
            first = false;
            continue;
        }
        if (b == ' ') {
            // 空格原样保留（同时会自然形成分隔）
            r.push_back(' ');
            first = false;
            continue;
        }
        throw Error(Format("北约音标编码只接受字母与空格，遇到字节 0x%02X", b));
    }
    out.assign(r.begin(), r.end());
}

void NatoDecode(const Bytes& in, const Params& p, Bytes& out) {
    (void)p;
    out.clear();
    const std::string s(in.begin(), in.end());
    std::string r;
    std::string tok;
    auto flush = [&]() {
        if (tok.empty()) return;
        std::string key = ToLower(tok);
        bool found = false;
        for (const auto& e : kNatoTable) {
            if (key == ToLower(std::string(e[1]))) {
                r += e[0];
                found = true;
                break;
            }
        }
        if (!found) throw Error("无法识别的北约音标单词: " + tok);
        tok.clear();
    };
    for (char c : s) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            flush();
            continue;
        }
        tok.push_back(c);
    }
    flush();
    out.assign(r.begin(), r.end());
}

}  // namespace

// ===========================================================================
// 注册
// ===========================================================================

void RegisterText(Registry& r) {
    // ---- URL ----
    r.Add("url", "Text", "URL 百分号编码（默认只保留 A-Za-z0-9-_.~）", true, true,
          UrlEncode, UrlDecode, {"percent", "urlencode"});
    r.Add("urldouble", "Text", "双重 URL 百分号编码（% 也编成 %25，一次解一层）", true, false,
          UrlDoubleEncode, UrlDoubleDecode, {"urldoubleencode"});

    // ---- HTML / CSS / C 转义 ----
    r.Add("html", "Text", "HTML 实体编码（all=1 时非 ASCII 用数字实体）", true, true,
          HtmlEncode, HtmlDecode, {"htmlentity", "htmlencode"});
    r.Add("css-escape", "Text", "CSS 十六进制转义（\\XX 形式）", true, false,
          CssEncode, CssDecode, {"cssescape"});
    r.Add("c-escape", "Text", "C 字符串转义（\\n \\r \\t \\\\ \\\" \\0 \\xNN）", true, false,
          CEscapeEncode, CEscapeDecode, {"cescape"});
    r.Add("octal-escape", "Text", "八进制转义（每字节 \\NNN）", true, false,
          OctalEscapeEncode, CEscapeDecode, {"octescape"});

    // ---- 传输编码 ----
    r.Add("quoted-printable", "Text", "RFC 2045 quoted-printable 编码（line 控制折行宽度）", true, true,
          QpEncode, QpDecode, {"qp", "quotedprintable"});
    r.Add("uuencode", "Text", "经典 uuencode（begin 644 file ... end）", true, false,
          UuEncodeFn, UuDecodeFn, {"uu"});
    r.Add("xxencode", "Text", "xxencode（字母表 +-0-9A-Za-z）", true, false,
          XxEncodeFn, XxDecodeFn, {"xx"});

    // ---- 国际化域名 ----
    r.Add("punycode", "Text", "RFC 3492 Punycode 纯编解码（解码容忍 xn-- 前缀）", true, false,
          PunyEncodeFn, PunyDecodeFn);

    // ---- JWT ----
    r.Add("jwt", "Text", "解析 JWT：输出 Header / Payload JSON 与原始签名段（不校验签名）", false, false,
          nullptr, JwtDecode);

    // ---- 文本变换 ----
    r.Add("leet", "Text", "1337 speak（a->4 b->8 e->3 g->6 i/l->1 o->0 s->5 t->7 z->2）", true, false,
          LeetEncode, LeetDecode, {"1337"});
    r.Add("reverse", "Text", "字符串反转（mode=char 按 UTF-8 字符，mode=byte 按字节）", true, true,
          ReverseCodec, ReverseCodec, {"strrev", "rev"});
    r.Add("upper", "Text", "转大写（不可逆）", false, false, UpperEncode, nullptr, {"toupper"});
    r.Add("lower", "Text", "转小写（不可逆）", false, false, LowerEncode, nullptr, {"tolower"});
    r.Add("swapcase", "Text", "大小写互换（可逆）", true, false, SwapCaseCodec, SwapCaseCodec);
    r.Add("nato", "Text", "北约音标字母表（sep 分隔符，lower=1 小写）", true, true,
          NatoEncode, NatoDecode, {"nato-alphabet"});
    r.Add("escape-bash", "Text", "ANSI-C 引用 $'\\x41' 形式", true, false,
          BashEscapeEncode, BashEscapeDecode, {"bash-escape", "ansic"});
}

}  // namespace ctf
