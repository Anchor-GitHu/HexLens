// classic.cpp —— Classic 分类：古典 / 趣味密码
//   morse 培根 a1z26 波利比奥斯 敲击码 盲文 猪圈 旗语 ASCII 二进制 书本密码
//
// 设计约定：
//   1. 本模块面向「可读文本」，编码输出 UTF-8 文本，解码容忍大小写混用、多余空白；
//   2. 所有失败一律抛 ctf::Error（中文信息），绝不写 stdout / 调用 exit；
//   3. 辅助函数全部放在匿名 namespace，对外只暴露 RegisterClassic。
#include "common.h"
#include "util.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ctf {

// ===========================================================================
// 匿名 namespace：本文件内部使用的字符 / UTF-8 辅助
// ===========================================================================
namespace {

// ------------------------------ 单字符判定 --------------------------------

bool IsSpaceChar(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

bool IsDigitChar(char c) { return c >= '0' && c <= '9'; }

// ------------------------------ UTF-8 ------------------------------------

// 从 s[off] 起解一个码点，同时把 off 推进到下一个码点起点；非法字节按单字节处理并返回 -1
int32_t Utf8Next(const std::string& s, size_t& off) {
    if (off >= s.size()) return -1;
    const unsigned char c0 = static_cast<unsigned char>(s[off]);

    if (c0 < 0x80) {
        ++off;
        return static_cast<int32_t>(c0);
    }

    size_t len = 0;
    int32_t cp = -1;
    if (c0 >= 0xC2 && c0 <= 0xDF) {
        len = 2;
        cp  = c0 & 0x1F;
    } else if (c0 >= 0xE0 && c0 <= 0xEF) {
        len = 3;
        cp  = c0 & 0x0F;
    } else if (c0 >= 0xF0 && c0 <= 0xF4) {
        len = 4;
        cp  = c0 & 0x07;
    } else {
        ++off;   // 非法首字节
        return -1;
    }

    if (off + len > s.size()) {   // 被截断的多字节序列
        ++off;
        return -1;
    }
    for (size_t i = 1; i < len; ++i) {
        unsigned char cc = static_cast<unsigned char>(s[off + i]);
        if ((cc & 0xC0) != 0x80) {   // 非法续字节
            ++off;
            return -1;
        }
        cp = (cp << 6) | (cc & 0x3F);
    }
    off += len;

    if ((len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000)) return -1;   // 过长编码
    if (cp >= 0xD800 && cp <= 0xDFFF) return -1;                            // 代理区
    if (cp > 0x10FFFF) return -1;
    return cp;
}

// 把码点按 UTF-8 追加到字节串
void AppendUtf8(uint32_t cp, Bytes& out) {
    if (cp < 0x80) {
        out.push_back(static_cast<uint8_t>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<uint8_t>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<uint8_t>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<uint8_t>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<uint8_t>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<uint8_t>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<uint8_t>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<uint8_t>(0x80 | (cp & 0x3F)));
    }
}

void AppendChar(char c, Bytes& out) { out.push_back(static_cast<uint8_t>(c & 0xFF)); }

void AppendStr(const std::string& s, Bytes& out) {
    out.insert(out.end(), s.begin(), s.end());
}

// 参数值必须是「恰好一个字符」（ASCII）或「恰好一个码点」（UTF-8），否则报错
void RequireOneSymbol(const std::string& s, const std::string& what) {
    if (s.empty()) throw Error("参数 " + what + " 不能为空");
    size_t off = 0;
    int32_t cp = Utf8Next(s, off);
    if (cp < 0 || off != s.size()) throw Error("参数 " + what + " 必须是单个字符");
}

// 取分隔符参数：允许空串（表示不插分隔符）或任意长度字符串
std::string GetSepStr(const Params& p, const std::string& key, const std::string& def) {
    const std::string s = p.Get(key, def);
    if (s.size() == 1) {
        size_t off = 0;
        int32_t cp = Utf8Next(s, off);
        if (cp < 0) throw Error("参数 " + key + " 不是合法 UTF-8");
    }
    return s;
}

// 单字符分隔符版本：空串返回 '\0'（表示不插分隔符）；多字符只取首字符
char GetSepChar(const Params& p, const std::string& key, const std::string& def) {
    const std::string s = p.Get(key, def);
    return s.empty() ? '\0' : s[0];
}

// ===========================================================================
// 1. 摩尔斯电码
// ===========================================================================
// 字符表与编码表必须逐项对齐（摩尔斯电码行内顺序：数字 0-9，再标点）
const char* const kMorseChar =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,?'!/()&:;=+-_\"$@";
const char* const kMorseCode[] = {
    ".-", "-...", "-.-.", "-..", ".", "..-.", "--.", "....", "..",      // A-I
    ".---", "-.-", ".-..", "--", "-.", "---", ".--.", "--.-", ".-.",    // J-R
    "...", "-", "..-", "...-", ".--", "-..-", "-.--", "--..",            // S-Z
    "-----", ".----", "..---", "...--", "....-", ".....", "-....",       // 0-5
    "--...", "---..", "----.",                                          // 6-9
    ".-.-.-", "--..--", "..--..", ".----.", "-.-.--", "-..-.",          // . , ? ' ! /
    "-.--.", "-.--.-", ".-...", "---...", "-.-.-.", "-...-",            // ( ) & : ; =
    ".-.-.", "-....-", "..--.-", ".-..-.", "...-..-", ".--.-."          // + - _ " $ @
};
// 字符表长度（编码表与字符表逐项对齐，均为 54 项；编码表没有哨兵项）
const size_t kMorseCount = sizeof(kMorseCode) / sizeof(kMorseCode[0]);
static_assert(sizeof(kMorseCode) / sizeof(kMorseCode[0]) == 54,
              "kMorseCode 必须与 kMorseChar 一一对应（54 项）");

// 解码前把各种「像划/像点」的字符统一成 '\x01'（划）和 '.'（点）。
// 用 '\x01' 而不是 '-' 作中间记号：用户可能把 dash 设成 '-'、'_' 或 '−' 等，
// 若这里写死成 '-'，自定义的划反而会被替换掉，导致整段解析错乱。
std::string NormalizeMorseDots(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        size_t off = i;
        int32_t cp = Utf8Next(s, off);
        if (cp == 0x2212 || cp == 0x2013 || cp == 0x2014 || cp == 0x2015 || cp == '-') {
            out.push_back('\x01');   // − – — ― -
        } else if (cp == 0x00B7 || cp == 0x2022 || cp == 0x2027 || cp == 0x30FB) {  // · • ‧ ・
            out.push_back('.');
        } else {
            out.append(s, i, off - i);
        }
        i = off;
    }
    return out;
}

void MorseEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string dash = p.Get("dash", "-");
    const std::string dot  = p.Get("dot", ".");
    const char        sep  = GetSepChar(p, "sep", " ");
    const std::string wsep = GetSepStr(p, "wordsep", "/");
    const std::string spc  = p.Get("space", "/");
    RequireOneSymbol(dash, "dash");
    RequireOneSymbol(dot, "dot");
    if (spc.size() == 1) {
        size_t off = 0;
        int32_t cp0 = Utf8Next(spc, off);
        if (cp0 < 0) throw Error("参数 space 不是合法 UTF-8");
    }

    const std::string text = Str(in);
    bool first = true;   // 还没输出过任何字母
    for (char raw : text) {
        unsigned char uc = static_cast<unsigned char>(raw);
        if (uc >= 0x80) throw Error("morse 编码只支持 ASCII 文本输入");
        if (IsSpaceChar(raw)) {
            // 一段空白整体输出成 "sep + wordsep"（即 "-- / -..."），
            // 这既是规范写法，也让解码器能把它识别成词分隔。
            if (first) continue;
            if (sep) AppendChar(sep, out);
            AppendStr(wsep, out);
            continue;
        }
        char up = raw;
        if (up >= 'a' && up <= 'z') up = static_cast<char>(up - 'a' + 'A');
        const char* pos = (up == '\0') ? nullptr : std::strchr(kMorseChar, up);
        if (!pos) throw Error(Format("morse 不支持的字符 '%c'", raw));
        if (!first && sep) AppendChar(sep, out);
        for (const char* s = kMorseCode[pos - kMorseChar]; *s; ++s) {
            AppendStr(*s == '-' ? dash : dot, out);
        }
        first = false;
    }
    (void)spc;   // space 语义与 wordsep 一致：空白段输出 sep + wordsep
}

// 摩尔斯「码 -> 字符」的键必须同时编码长度和位序列：
// 只编码位序列会让 "...."(H)、".."(I)、"-----"(0) 等碰撞到同一个键。
// 最长码为 6 个符号（key < 2^9），把长度放在第 9~14 位即可保证键 < 65536。
uint32_t MorseKey(const std::string& code) {
    uint32_t key = 0;
    for (char c : code) key = key * 2u + (c == '-' ? 1u : 0u);
    if (code.size() > 31) throw Error("摩尔斯码过长: " + code);
    return (static_cast<uint32_t>(code.size()) << 9) | key;
}

void MorseDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string dash = p.Get("dash", "-");
    const std::string dot  = p.Get("dot", ".");
    RequireOneSymbol(dash, "dash");
    RequireOneSymbol(dot, "dot");
    const char tokDash = dash[0];
    const char tokDot  = dot[0];

    // 反查表：键 = (长度 << 16) | 位序列，0 表示未定义
    std::vector<char> rev(65536, '\0');
    for (size_t i = 0; i < kMorseCount; ++i) {
        rev[MorseKey(kMorseCode[i])] = kMorseChar[i];
    }

    const std::string text = NormalizeMorseDots(Str(in));

    // 词分隔用「延迟到下一个字母前面补空格」的方式实现：
    //   字母分隔（单个空白）      -> 只结束当前码
    //   词分隔（'/'、'|'、3+ 空白）-> 结束当前码，并在下一个字母前补一个空格
    std::string code;         // 当前摩尔斯串（已归一为 '-' / '.'）
    bool wordBreak = false;   // 下一个字母前是否要先补空格
    bool haveLetter = false;  // 是否已经输出过字母

    auto EmitLetter = [&]() {
        if (code.empty()) return;
        const char ch = rev[MorseKey(code)];
        if (ch == '\0') throw Error("无法识别的摩尔斯码: " + code);
        if (wordBreak && haveLetter && !out.empty() && out.back() != ' ') AppendChar(' ', out);
        AppendChar(ch, out);
        code.clear();
        wordBreak  = false;
        haveLetter = true;
    };

    size_t i = 0;
    while (i < text.size()) {
        const char c = text[i];

        if (c == '\x01' || c == tokDash) {   // 划（含各种破折号/减号变体）
            code.push_back('-');
            ++i;
            continue;
        }
        if (c == '.' || c == tokDot) {       // 点（含 · 等变体）
            code.push_back('.');
            ++i;
            continue;
        }        if (IsSpaceChar(c)) {
            size_t j = i;
            while (j < text.size() && IsSpaceChar(text[j])) ++j;
            EmitLetter();
            if (j - i >= 3) wordBreak = true;   // 连续 3+ 空白视为词分隔
            i = j;
            continue;
        }
        if (c == '/' || c == '|') {   // '/'、'|' 一律视为词分隔
            EmitLetter();
            wordBreak = true;
            ++i;
            continue;
        }
        // 其它字符（如 'x'、下划线）：字母边界，但会产生一个新字母，
        // 因此这里不提交当前码（由后续符号处理时提交）
        ++i;
    }
    EmitLetter();
}

// ===========================================================================
// 2. 培根密码
// ===========================================================================
const char* const kBacon24 = "ABCDEFGHIKLMNOPQRSTUVWXYZ";                       // 24 字母表（无 J）
const char* const kBacon26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";                      // 26 字母表
const char* const kBacon24Code[24] = {
    "AAAAA", "AAAAB", "AAABA", "AAABB", "AABAA", "AABAB", "AABBA", "AABBB",
    "ABAAA", "ABAAB", "ABABA", "ABABB", "ABBAA", "ABBAB", "ABBBA", "ABBBB",
    "BAAAA", "BAAAB", "BAABA", "BAABB", "BABAA", "BABAB", "BABBA", "BABBB"
};
const char* const kBacon26Code[26] = {
    "AAAAA", "AAAAB", "AAABA", "AAABB", "AABAA", "AABAB", "AABBA", "AABBB",
    "ABAAA", "ABAAB", "ABABA", "ABABB", "ABBAA", "ABBAB", "ABBBA", "ABBBB",
    "BAAAA", "BAAAB", "BAABA", "BAABB", "BABAA", "BABAB", "BABBA", "BABBB",
    "BAAAA", "BAAAB"
};

void BaconEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const int version = p.GetInt("version", 24);
    if (version != 24 && version != 26) throw Error("bacon 参数 version 只能是 24 或 26");
    const std::string style = ToLower(p.Get("style", "ab"));
    if (style != "ab" && style != "01") throw Error("bacon 参数 style 只能是 ab 或 01");
    const char lo = (style == "ab") ? 'A' : '0';
    const char hi = (style == "ab") ? 'B' : '1';

    const std::string text = ToUpper(Str(in));
    for (char c : text) {
        if (!IsSpaceChar(c) && !(c >= 'A' && c <= 'Z')) {
            throw Error(Format("bacon 只支持 A-Z 字母输入，遇到 '%c'", c));
        }
    }
    for (char c : text) {
        if (c < 'A' || c > 'Z') continue;   // 跳过空白
        size_t idx = 0;
        if (version == 24) {
            if (c == 'J') c = 'I';
            if (c == 'V') c = 'U';
            idx = static_cast<size_t>(std::strchr(kBacon24, c) - kBacon24);
        } else {
            idx = static_cast<size_t>(c - 'A');
        }
        const char* code = (version == 24) ? kBacon24Code[idx] : kBacon26Code[idx];
        for (const char* s = code; *s; ++s) AppendChar(*s == 'A' ? lo : hi, out);
    }
}

void BaconDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const int version = p.GetInt("version", 24);
    if (version != 24 && version != 26) throw Error("bacon 参数 version 只能是 24 或 26");

    // 只保留 A/B（大小写混用均可），其余空白忽略
    std::string bits;
    const std::string text = ToUpper(Str(in));
    for (char c : text) {
        if (c == 'A' || c == 'B') {
            bits.push_back(c);
        } else if (c == '0' || c == '1') {
            bits.push_back(c == '0' ? 'A' : 'B');
        } else if (!IsSpaceChar(c)) {
            throw Error(Format("bacon 输入含非法字符 '%c'", c));
        }
    }
    if (bits.size() % 5 != 0) throw Error("bacon 输入长度不是 5 的倍数");
    for (size_t i = 0; i + 5 <= bits.size(); i += 5) {
        const std::string g = bits.substr(i, 5);
        bool found = false;
        if (version == 24) {
            for (size_t k = 0; k < 24; ++k) {
                if (g == kBacon24Code[k]) {
                    AppendChar(kBacon24[k], out);
                    found = true;
                    break;
                }
            }
        } else {
            for (size_t k = 0; k < 26; ++k) {
                if (g == kBacon26Code[k]) {
                    AppendChar(kBacon26[k], out);
                    found = true;
                    break;
                }
            }
        }
        if (!found) throw Error("非法的培根分组: " + g);
    }
}

// ===========================================================================
// 3. A1Z26
// ===========================================================================
// 无分隔输入（如 "1213"）的拆分：每段取 1~2 位，尽量得到 ≤26 的合法值；
// 结果可能有多个候选，用 '\n' 分隔全部输出。
// 贪心顺序：先尝试 2 位（更长的数字优先），再尝试 1 位。
void SplitA1Z26Digits(const std::string& digits,
                      size_t                pos,
                      std::vector<int>&     cur,
                      std::vector<std::string>& results,
                      bool&                 overflow) {
    if (results.size() > 256) {
        overflow = true;
        return;
    }
    if (pos >= digits.size()) {
        std::string s;
        for (size_t i = 0; i < cur.size(); ++i) {
            if (i) s += " ";
            s += std::to_string(cur[i]);
        }
        results.push_back(s);
        return;
    }
    if (digits[pos] == '0') return;   // 前导 0 非法：A1Z26 没有 0

    if (pos + 1 < digits.size() && digits[pos + 1] != '0') {
        int two = (digits[pos] - '0') * 10 + (digits[pos + 1] - '0');
        if (two >= 1 && two <= 26) {
            cur.push_back(two);
            SplitA1Z26Digits(digits, pos + 2, cur, results, overflow);
            cur.pop_back();
        }
    }
    int one = digits[pos] - '0';
    if (one >= 1 && one <= 26) {
        cur.push_back(one);
        SplitA1Z26Digits(digits, pos + 1, cur, results, overflow);
        cur.pop_back();
    }
}

void A1Z26Encode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const char sep = GetSepChar(p, "sep", "-");
    const bool pad = p.GetInt("pad", 0) != 0;

    const std::string text = ToUpper(Str(in));
    bool first = true;
    for (char c : text) {
        if (IsSpaceChar(c)) continue;
        if (c < 'A' || c > 'Z') throw Error(Format("a1z26 只支持字母输入，遇到 '%c'", c));
        if (!first && sep) AppendChar(sep, out);
        const int v = c - 'A' + 1;
        AppendStr(pad ? Format("%02d", v) : std::to_string(v), out);
        first = false;
    }
}

// 把一段纯数字拆成「全部候选」（每候选是一行用空格分隔的数字）
std::vector<std::string> SplitA1Z26Segment(const std::string& digits) {
    std::vector<int>         cur;
    std::vector<std::string> results;
    bool overflow = false;
    SplitA1Z26Digits(digits, 0, cur, results, overflow);
    if (overflow) throw Error("a1z26 无分隔输入的可能拆分过多，请显式加分隔符");
    if (results.empty()) throw Error("a1z26 无法拆分: " + digits);
    return results;
}

void A1Z26Decode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    const std::string text = Str(in);

    bool hasSep = false;   // 出现了数字/空白之外的字符 -> 视为显式分隔
    for (char c : text) {
        if (!IsDigitChar(c) && !IsSpaceChar(c)) {
            hasSep = true;
            break;
        }
    }

    // 逐段解析：显式分隔时每段就是一个数字，输出用空格连接；
    // 纯数字输入没有分段信息，输出「全部候选拆分」（每行一个候选）
    std::vector<std::string> segs;
    if (hasSep) {
        std::string seg;
        for (char c : text) {
            if (IsDigitChar(c)) {
                seg.push_back(c);
            } else if (!seg.empty()) {
                segs.push_back(seg);
                seg.clear();
            }
        }
        if (!seg.empty()) segs.push_back(seg);
        for (size_t i = 0; i < segs.size(); ++i) {
            if (segs[i].size() > 2) {
                throw Error(Format("a1z26 数字超出 1-26 范围: %s", segs[i].c_str()));
            }
            const int v = std::atoi(segs[i].c_str());
            if (v < 1 || v > 26) {
                throw Error(Format("a1z26 数字超出 1-26 范围: %s", segs[i].c_str()));
            }
            // 【曾经的 bug】这里原先把 std::to_string(v) 写回 out，
            // 于是 "1-2-3" 解出来还是 "1 2 3"，根本没变成字母。
            AppendChar(static_cast<char>('A' + v - 1), out);
        }
        return;
    }

    std::string digits;
    for (char c : text) {
        if (IsDigitChar(c)) digits.push_back(c);
    }
    if (digits.empty()) return;

    const std::vector<std::string> results = SplitA1Z26Segment(digits);
    for (size_t i = 0; i < results.size(); ++i) {
        if (i) AppendChar('\n', out);
        AppendStr(results[i], out);
    }
}

// ===========================================================================
// 4. 波利比奥斯方阵（5x5）
// ===========================================================================
const char* const kPolybiusDefaultKey = "ABCDEFGHIKLMNOPQRSTUVWXYZ";   // 无 J

std::string BuildPolybiusSquare(const std::string& keyParam) {
    std::string key = ToUpper(keyParam.empty() ? std::string(kPolybiusDefaultKey) : keyParam);
    std::string sq;
    auto Push = [&](char c) {
        if (c < 'A' || c > 'Z') return;
        if (c == 'J') c = 'I';   // 5x5 方阵里 J 与 I 合并
        if (sq.find(c) == std::string::npos) sq.push_back(c);
    };
    for (char c : key) Push(c);
    for (char c = 'A'; c <= 'Z'; ++c) Push(c);
    if (sq.size() != 25) throw Error("polybius 方阵构造失败（需要 25 个唯一字母）");
    return sq;
}

void PolybiusEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string sq  = BuildPolybiusSquare(p.Get("key", ""));
    const char sep = GetSepChar(p, "sep", "");
    const bool zero = p.GetInt("zero", 0) != 0;
    const int base = zero ? 0 : 1;

    const std::string text = ToUpper(Str(in));
    bool first = true;
    for (char c : text) {
        if (IsSpaceChar(c)) continue;
        if (c < 'A' || c > 'Z') throw Error(Format("polybius 只支持字母输入，遇到 '%c'", c));
        if (c == 'J') c = 'I';
        const size_t idx = sq.find(c);
        if (idx == std::string::npos) throw Error(Format("字母 '%c' 不在方阵中", c));
        if (!first && sep) AppendChar(sep, out);
        AppendStr(std::to_string(static_cast<int>(idx / 5) + base), out);
        AppendStr(std::to_string(static_cast<int>(idx % 5) + base), out);
        first = false;
    }
}

void PolybiusDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string sq = BuildPolybiusSquare(p.Get("key", ""));
    const bool zero = p.GetInt("zero", 0) != 0;
    const int base = zero ? 0 : 1;

    std::string digits;
    for (char c : Str(in)) {
        if (IsDigitChar(c)) digits.push_back(c);
    }
    if (digits.size() % 2 != 0) throw Error("polybius 坐标位数必须成对");
    for (size_t i = 0; i + 2 <= digits.size(); i += 2) {
        const int r = digits[i] - '0' - base;
        const int c = digits[i + 1] - '0' - base;
        if (r < 0 || r > 4 || c < 0 || c > 4) {
            throw Error(Format("polybius 坐标越界: %c%c", digits[i], digits[i + 1]));
        }
        AppendChar(sq[static_cast<size_t>(r * 5 + c)], out);
    }
}

// ===========================================================================
// 5. 敲击码（Tap code）
// ===========================================================================
void TapCodeEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string style = ToLower(p.Get("style", "dot"));
    if (style != "dot" && style != "num") throw Error("tap-code 参数 style 只能是 dot 或 num");
    const char sep = GetSepChar(p, "sep", " ");

    const std::string text = ToUpper(Str(in));
    bool first = true;
    for (char ch : text) {
        if (IsSpaceChar(ch)) continue;
        if (ch < 'A' || ch > 'Z') throw Error(Format("tap-code 只支持字母输入，遇到 '%c'", ch));
        if (ch == 'K') ch = 'C';   // 敲击码经典做法：K 与 C 同格
        const int idx = ch - 'A';
        const int row = idx / 5 + 1;
        const int col = idx % 5 + 1;
        if (!first && sep) AppendChar(sep, out);
        if (style == "dot") {
            for (int i = 0; i < row; ++i) AppendChar('.', out);
            AppendChar(' ', out);
            for (int i = 0; i < col; ++i) AppendChar('.', out);
        } else {
            AppendChar(static_cast<char>('0' + row), out);
            AppendChar(static_cast<char>('0' + col), out);
        }
        first = false;
    }
}

void TapCodeDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    const std::string text = Str(in);

    // 把点类字符与 x/X 归一为 '.'；空白统一成 ' '（它是「点组」的分隔符，必须保留），
    // 逗号等常见分隔符当作字母分隔，'/'、'|' 保留为词分隔
    std::string norm;
    size_t i = 0;
    while (i < text.size()) {
        unsigned char c = static_cast<unsigned char>(text[i]);
        if (c < 0x80) {
            char ch = text[i];
            if (ch == 'x' || ch == 'X' || ch == '.' || ch == '*' || ch == 'o' || ch == 'O') {
                norm.push_back('.');
            } else if (IsSpaceChar(ch)) {
                norm.push_back(' ');
            } else if (ch == '/' || ch == '|') {
                norm.push_back(ch);
            } else if (ch == ',' || ch == ';' || ch == '-') {
                norm.push_back(' ');   // 常见分隔符一律当字母分隔
            } else if (IsDigitChar(ch)) {
                norm.push_back(ch);
            } else {
                norm.push_back(ch);    // 其余留给后面报错
            }
            ++i;
            continue;
        }
        size_t off = i;
        int32_t cp = Utf8Next(text, off);
        if (cp == 0x00B7 || cp == 0x2022 || cp == 0x25CF || cp == 0x25AA || cp == 0x30FB) {
            norm.push_back('.');
        } else if (cp == 0x3000) {   // 全角空格
            norm.push_back(' ');
        }
        i = off;
    }
    if (norm.empty()) return;

    bool numeric = false;
    for (char c : norm) {
        if (IsDigitChar(c)) numeric = true;
    }
    if (numeric) {
        std::string digits;
        for (char c : norm) {
            if (IsDigitChar(c)) digits.push_back(c);
        }
        if (digits.size() % 2 != 0) throw Error("tap-code 数字形式必须成对");
        for (size_t k = 0; k + 2 <= digits.size(); k += 2) {
            const int row = digits[k] - '0';
            const int col = digits[k + 1] - '0';
            // 数字形式既可能是纯数字行列，也可能是「点数」写法，这里按位数判读
            if (row >= 1 && row <= 5 && col >= 1 && col <= 5) {
                AppendChar(static_cast<char>('A' + (row - 1) * 5 + (col - 1)), out);
            } else {
                throw Error(Format("tap-code 行列越界: %c%c", digits[k], digits[k + 1]));
            }
        }
        return;
    }

    // 点写法：空白分隔「点组」，每两组合成一个字母；'/'、'|' 是词分隔
    std::vector<int> runs;   // 正数 = 点组长度，-1 = 词分隔标记
    int run = 0;
    for (char c : norm) {
        if (c == '.') {
            ++run;
        } else if (c == ' ') {
            if (run > 0) {
                runs.push_back(run);
                run = 0;
            }
        } else if (c == '/' || c == '|') {
            if (run > 0) {
                runs.push_back(run);
                run = 0;
            }
            runs.push_back(-1);
        } else {
            throw Error(Format("tap-code 输入含非法字符 '%c'", c));
        }
    }
    if (run > 0) runs.push_back(run);
    // 去掉开头的分隔标记
    size_t st = 0;
    while (st < runs.size() && runs[st] == -1) ++st;

    std::vector<int> letters;
    bool wordBreak = false;
    for (size_t k = st; k < runs.size();) {
        if (runs[k] == -1) {
            wordBreak = true;
            ++k;
            continue;
        }
        if (k + 1 >= runs.size() || runs[k + 1] == -1) {
            throw Error("tap-code 点组数量不足，无法配对成字母");
        }
        const int row = runs[k];
        const int col = runs[k + 1];
        if (row < 1 || row > 5 || col < 1 || col > 5) {
            throw Error(Format("tap-code 行列越界: %d,%d", row, col));
        }
        if (wordBreak && !letters.empty()) letters.push_back(-1);
        wordBreak = false;
        letters.push_back((row - 1) * 5 + (col - 1));
        k += 2;
    }
    for (size_t k = 0; k < letters.size(); ++k) {
        if (letters[k] == -1) {
            AppendChar(' ', out);
        } else {
            AppendChar(static_cast<char>('A' + letters[k]), out);
        }
    }
}

// ===========================================================================
// 6. 盲文（Braille）
// ===========================================================================
const uint32_t kBrailleSign  = 0x2800;   // 盲文空白
const uint32_t kBrailleCaps  = 0x2820;   // ⠠ 大写标记
const uint32_t kBrailleNum   = 0x283C;   // ⠼ 数字标记

// 数字 0-9 用 a-j 表示：1=a(0) ... 9=i(8) 0=j(9)
const uint32_t kBrailleDigit[10] = {9, 0, 1, 2, 3, 4, 5, 6, 7, 8};
// 反查表：a-j 的下标 -> 数字字符（与 kBrailleDigit 互为逆映射）
const char kBrailleDigitInv[10] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};

void BrailleEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const bool caps = p.GetInt("caps", 0) != 0;
    const std::string text = Str(in);

    bool lastWasDigit = false;   // 连续数字共用一个 ⠼ 数字标记
    size_t i = 0;
    while (i < text.size()) {
        size_t off = i;
        int32_t cp = Utf8Next(text, off);
        if (cp >= 0 && cp < 0x80) {
            const char c = static_cast<char>(cp);
            if (IsSpaceChar(c)) {
                AppendUtf8(kBrailleSign, out);   // 空白用盲文空白表示
                lastWasDigit = false;
            } else if (c >= 'A' && c <= 'Z') {
                if (caps) AppendUtf8(kBrailleCaps, out);
                AppendUtf8(0x2800 + 1 + static_cast<uint32_t>(c - 'A'), out);
                lastWasDigit = false;
            } else if (c >= 'a' && c <= 'z') {
                AppendUtf8(0x2800 + 1 + static_cast<uint32_t>(c - 'a'), out);
                lastWasDigit = false;
            } else if (IsDigitChar(c)) {
                if (!lastWasDigit) AppendUtf8(kBrailleNum, out);   // 数字标记 + a-j
                AppendUtf8(0x2800 + 1 + kBrailleDigit[c - '0'], out);
                lastWasDigit = true;
            } else {
                throw Error(Format("braille 不支持的字符 '%c'", c));
            }
        } else if (cp >= 0x2800 && cp <= 0x28FF) {
            AppendUtf8(static_cast<uint32_t>(cp), out);   // 已经是盲文，原样保留
            lastWasDigit = false;
        } else if (cp == 0x00A0) {
            AppendUtf8(kBrailleSign, out);                // 不换行空格
            lastWasDigit = false;
        } else if (cp < 0) {
            throw Error("braille 输入含非法 UTF-8 序列");
        } else {
            throw Error("braille 只支持 ASCII 文本或盲文字符输入");
        }
        i = off;
    }
}

void BrailleDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    const std::string text = Str(in);

    bool numMode = false;
    bool capNext = false;
    size_t i = 0;
    while (i < text.size()) {
        size_t off = i;
        int32_t cp = Utf8Next(text, off);
        if (cp < 0) {
            ++i;   // 非法字节直接跳过，尽量容错
            continue;
        }
        i = off;
        if (cp < 0x80) {
            if (IsSpaceChar(cp)) AppendChar(' ', out);
            continue;   // 其它 ASCII 直接忽略
        }
        if (cp == static_cast<int32_t>(kBrailleNum)) {
            numMode = true;
            continue;
        }
        if (cp == static_cast<int32_t>(kBrailleCaps)) {
            capNext = true;
            continue;
        }
        if (cp == static_cast<int32_t>(kBrailleSign)) {
            AppendChar(' ', out);
            numMode = false;
            capNext = false;
            continue;
        }
        if (cp >= 0x2801 && cp <= 0x281A) {
            const int idx = cp - 0x2801;   // 0..25 -> a..z
            if (numMode) {
                // 数字标记后进入数字模式：后续 a-j 都是数字，直到空白/字母标记结束
                if (idx > 9) throw Error("盲文数字标记后面必须是 a-j");
                // 用与编码同一张表反查，保证编解码永远一致
                AppendChar(kBrailleDigitInv[idx], out);
            } else if (capNext) {
                AppendChar(static_cast<char>('A' + idx), out);
                capNext = false;
            } else {
                AppendChar(static_cast<char>('a' + idx), out);
            }
            continue;
        }
        throw Error(Format("无法识别的盲文字符 U+%04X", static_cast<unsigned>(cp)));
    }
}

// ===========================================================================
// 7. 猪圈密码（自洽的几何符号表）
// ===========================================================================
// 26 个字母 -> 26 个互不相同的几何字符（单码点，便于 UTF-8 编解码）
// 注意：· (U+00B7) 被保留作空白分隔符，因此符号表里不得再出现它
const char* const kPigpenChars[26] = {
    "\xE2\x8A\x94",  // ⊔  A
    "\xE2\x8A\x93",  // ⊓  B
    "\xE2\x8A\x8F",  // ⊏  C
    "\xE2\x8A\x90",  // ⊐  D
    "\xE2\x8C\x90",  // ⌐  E
    "\xC2\xAC",      // ¬  F
    "\xE2\x88\xA8",  // ∨  G
    "\xE2\x88\xA7",  // ∧  H
    "\xE2\x97\x8B",  // ○  I
    "\xE2\x97\x8F",  // ●  J
    "\xE2\x96\xA1",  // □  K
    "\xE2\x96\xA0",  // ■  L
    "\xE2\x96\xB3",  // △  M
    "\xE2\x96\xB2",  // ▲  N
    "\xE2\x96\xBD",  // ▽  O
    "\xE2\x96\xBC",  // ▼  P
    "\xE2\x97\x87",  // ◇  Q
    "\xE2\x97\x86",  // ◆  R
    "\xE2\x98\x86",  // ☆  S
    "\xE2\x98\x85",  // ★  T
    "\xE2\x8A\x9E",  // ⊞  U
    "\xE2\x8A\x95",  // ⊕  V
    "\xE2\x8A\x9A",  // ⊚  W
    "\xE2\x8A\x99",  // ⊙  X
    "\xE2\x8A\x98",  // ⊘  Y
    "\xE2\x8A\x96"   // ⊖  Z
};
const uint32_t kPigpenSpace = 0x00B7;   // ·  表示空白

void PigpenEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    const std::string text = Str(in);
    size_t i = 0;
    while (i < text.size()) {
        size_t off = i;
        int32_t cp = Utf8Next(text, off);
        if (cp < 0) throw Error("pigpen 输入含非法 UTF-8 序列");
        if (cp < 0x80) {
            const char c = static_cast<char>(cp);
            if (IsSpaceChar(c)) {
                AppendUtf8(kPigpenSpace, out);
            } else if (c >= 'A' && c <= 'Z') {
                AppendStr(kPigpenChars[c - 'A'], out);
            } else if (c >= 'a' && c <= 'z') {
                AppendStr(kPigpenChars[c - 'a'], out);
            } else {
                AppendChar(c, out);   // 其它可见 ASCII 原样保留
            }
        } else if (cp == static_cast<int32_t>(kPigpenSpace)) {
            AppendUtf8(kPigpenSpace, out);
        } else {
            AppendUtf8(static_cast<uint32_t>(cp), out);   // 已是符号，原样保留
        }
        i = off;
    }
}

void PigpenDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    std::string tbl;   // 按 1 个码点一组拼接符号表
    std::vector<size_t> tblOff;
    for (int k = 0; k < 26; ++k) {
        tblOff.push_back(tbl.size());
        tbl += kPigpenChars[k];
    }

    const std::string text = Str(in);
    size_t i = 0;
    while (i < text.size()) {
        size_t off = i;
        int32_t cp = Utf8Next(text, off);
        if (cp < 0) {
            ++i;
            continue;
        }
        if (cp == static_cast<int32_t>(kPigpenSpace)) {
            AppendChar(' ', out);
            i = off;
            continue;
        }
        if (cp < 0x80) {
            if (IsSpaceChar(cp)) AppendChar(' ', out);
            i = off;
            continue;
        }
        // 在多字节符号表里找
        const std::string sym = text.substr(i, off - i);
        int found = -1;
        for (int k = 0; k < 26; ++k) {
            if (sym == kPigpenChars[k]) {
                found = k;
                break;
            }
        }
        if (found < 0) throw Error(Format("无法识别的猪圈符号 U+%04X", static_cast<unsigned>(cp)));
        AppendChar(static_cast<char>('A' + found), out);
        i = off;
    }
}

// ===========================================================================
// 8. 旗语（Semaphore）
// ===========================================================================
// 8 个方位：1 正上，顺时针 2..8；A = 11，之后按方位对递增
const char* const kSemaphoreCode[26] = {
    "11", "12", "13", "14", "15", "16", "17",
    "21", "22", "23", "24", "25", "26", "27",
    "31", "32", "33", "34", "35",
    "41", "42", "43", "44", "45",
    "51", "52"
};

void SemaphoreEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const char sep = GetSepChar(p, "sep", "-");
    const std::string text = ToUpper(Str(in));
    bool first = true;
    for (char c : text) {
        if (IsSpaceChar(c)) continue;
        if (c < 'A' || c > 'Z') throw Error(Format("semaphore 只支持字母输入，遇到 '%c'", c));
        if (!first && sep) AppendChar(sep, out);
        AppendStr(kSemaphoreCode[c - 'A'], out);
        first = false;
    }
}

void SemaphoreDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    std::string digits;
    for (char c : Str(in)) {
        if (IsDigitChar(c)) digits.push_back(c);
    }
    if (digits.size() % 2 != 0) throw Error("semaphore 方位数字必须成对");
    for (size_t i = 0; i + 2 <= digits.size(); i += 2) {
        const int a = digits[i] - '0';
        const int b = digits[i + 1] - '0';
        if (a < 1 || a > 8 || b < 1 || b > 8) {
            throw Error(Format("semaphore 方位越界（应为 1-8）: %c%c", digits[i], digits[i + 1]));
        }
        int found = -1;
        for (int k = 0; k < 26; ++k) {
            if (kSemaphoreCode[k][0] == digits[i] && kSemaphoreCode[k][1] == digits[i + 1]) {
                found = k;
                break;
            }
        }
        if (found < 0) throw Error(Format("非法的旗语方位组合: %c%c", digits[i], digits[i + 1]));
        AppendChar(static_cast<char>('A' + found), out);
    }
}

// ===========================================================================
// 9. ASCII 二进制
// ===========================================================================
void AsciiBinaryEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const int bits = p.GetInt("bits", 8);
    const bool msb = p.GetInt("msb", 1) != 0;
    if (bits != 7 && bits != 8) throw Error("ascii-binary 参数 bits 只能是 7 或 8");

    bool first = true;
    for (uint8_t v : in) {
        if (bits == 7 && v > 0x7F) {
            throw Error(Format("ascii-binary bits=7 无法表示字节 0x%02X", v));
        }
        if (!first) AppendChar(' ', out);
        for (int k = 0; k < bits; ++k) {
            const int shift = msb ? (bits - 1 - k) : k;
            AppendChar(((v >> shift) & 1) ? '1' : '0', out);
        }
        first = false;
    }
}

void AsciiBinaryDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const int bits = p.GetInt("bits", 8);
    const bool msb = p.GetInt("msb", 1) != 0;
    if (bits != 7 && bits != 8) throw Error("ascii-binary 参数 bits 只能是 7 或 8");

    std::string bitsStr;
    for (char c : Str(in)) {
        if (c == '0' || c == '1') bitsStr.push_back(c);
    }
    if (bitsStr.empty()) return;
    if (bitsStr.size() % static_cast<size_t>(bits) != 0) {
        throw Error(Format("ascii-binary 二进制位数不是 %d 的倍数", bits));
    }
    for (size_t i = 0; i + static_cast<size_t>(bits) <= bitsStr.size();
         i += static_cast<size_t>(bits)) {
        int v = 0;
        for (int k = 0; k < bits; ++k) {
            const int shift = msb ? (bits - 1 - k) : k;
            if (bitsStr[i + static_cast<size_t>(k)] == '1') v |= (1 << shift);
        }
        out.push_back(static_cast<uint8_t>(v));
    }
}

// ===========================================================================
// 10. 书本密码（Book code）
// ===========================================================================

void BookCodeEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string book = p.RequireStr("book");
    const std::string mode = ToLower(p.Get("mode", "index"));
    if (mode != "index" && mode != "linecol") {
        throw Error("book-code 参数 mode 只能是 index 或 linecol");
    }

    // 预建「字符 -> 首次出现位置」索引
    std::map<uint32_t, size_t> firstAt;
    size_t i = 0;
    std::vector<std::pair<uint32_t, size_t>> occ;   // (码点, 字符序号)
    while (i < book.size()) {
        size_t off = i;
        int32_t cp = Utf8Next(book, off);
        if (cp < 0) {
            ++i;
            continue;
        }
        const uint32_t u = static_cast<uint32_t>(cp);
        if (firstAt.find(u) == firstAt.end()) firstAt[u] = occ.size();
        occ.push_back({u, occ.size()});
        i = off;
    }

    // 位置索引：linecol 模式需要行列
    std::vector<int> lineOf(occ.size(), 0), colOf(occ.size(), 0);
    {
        int line = 1, col = 1;
        size_t k = 0, o = 0;
        int32_t prev = 0;
        (void)prev;
        while (k < book.size() && o < occ.size()) {
            size_t off = k;
            int32_t cp = Utf8Next(book, off);
            if (cp < 0) {
                ++k;
                continue;
            }
            if (cp == '\r') {
                if (off < book.size() && book[off] == '\n') ++off;
                ++line;
                col = 1;
                k = off;
                continue;
            }
            if (cp == '\n') {
                ++line;
                col = 1;
                k = off;
                continue;
            }
            lineOf[o] = line;
            colOf[o]  = col;
            ++col;
            ++o;
            k = off;
        }
    }

    const std::string text = Str(in);
    bool first = true;
    size_t n = 0;
    while (n < text.size()) {
        size_t off = n;
        int32_t cp = Utf8Next(text, off);
        if (cp < 0) throw Error("book-code 输入含非法 UTF-8 序列");
        const uint32_t u = static_cast<uint32_t>(cp);
        auto it = firstAt.find(u);
        if (it == firstAt.end()) {
            throw Error(Format("book-code: 字符 U+%04X 不在 book 中", static_cast<unsigned>(u)));
        }
        const size_t idx = it->second;
        if (!first) AppendChar(' ', out);
        if (mode == "index") {
            AppendStr(std::to_string(static_cast<long long>(idx) + 1), out);
        } else {
            AppendStr(std::to_string(lineOf[idx]), out);
            AppendChar(',', out);
            AppendStr(std::to_string(colOf[idx]), out);
        }
        first = false;
        n = off;
    }
}

void BookCodeDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    const std::string book = p.RequireStr("book");

    // 展平成「字符数组」，index 模式按 1 基序号取
    std::vector<std::string> chars;
    std::vector<int>         lineOf, colOf;
    std::vector<std::string> lineText;
    {
        std::string cur;
        int line = 1, col = 1;
        size_t k = 0;
        while (k < book.size()) {
            size_t off = k;
            int32_t cp = Utf8Next(book, off);
            if (cp < 0) {
                ++k;
                continue;
            }
            if (cp == '\r' || cp == '\n') {
                if (cp == '\r' && off < book.size() && book[off] == '\n') ++off;
                lineText.push_back(cur);
                cur.clear();
                ++line;
                col = 1;
                k = off;
                continue;
            }
            chars.push_back(book.substr(k, off - k));
            lineOf.push_back(line);
            colOf.push_back(col);
            cur.append(book, k, off - k);
            ++col;
            k = off;
        }
        lineText.push_back(cur);
    }

    // 解析 token：可能是 "12" 或 "3,5"
    const std::string text = Str(in);
    size_t i = 0;
    bool first = true;
    while (i < text.size()) {
        while (i < text.size() && (IsSpaceChar(text[i]) || text[i] == ';')) ++i;
        if (i >= text.size()) break;
        std::string tok;
        while (i < text.size() && !IsSpaceChar(text[i]) && text[i] != ';') {
            tok.push_back(text[i]);
            ++i;
        }
        if (tok.empty()) continue;

        long long line = -1, col = -1;
        size_t comma = tok.find_first_of(",:");
        if (comma != std::string::npos) {
            line = std::strtoll(tok.c_str(), nullptr, 10);
            col  = std::strtoll(tok.c_str() + comma + 1, nullptr, 10);
        } else {
            long long idx = std::strtoll(tok.c_str(), nullptr, 10);
            if (idx < 1 || static_cast<size_t>(idx) > chars.size()) {
                throw Error(Format("book-code 序号越界: %s", tok.c_str()));
            }
            if (!first) AppendChar(' ', out);
            AppendStr(chars[static_cast<size_t>(idx - 1)], out);
            first = false;
            continue;
        }
        if (line < 1 || static_cast<size_t>(line) > lineText.size()) {
            throw Error(Format("book-code 行号越界: %s", tok.c_str()));
        }
        const std::string& ln = lineText[static_cast<size_t>(line - 1)];
        if (col < 1) throw Error(Format("book-code 列号越界: %s", tok.c_str()));
        // 按码点取第 col 个字符
        size_t k = 0;
        long long cc = 1;
        bool ok = false;
        while (k < ln.size()) {
            size_t off = k;
            (void)Utf8Next(ln, off);
            if (cc == col) {
                if (!first) AppendChar(' ', out);
                AppendStr(ln.substr(k, off - k), out);
                first = false;
                ok = true;
                break;
            }
            ++cc;
            k = off;
        }
        if (!ok) throw Error(Format("book-code 列号越界: %s", tok.c_str()));
    }
}

}  // namespace

// ===========================================================================
// 注册入口
// ===========================================================================
void RegisterClassic(Registry& r) {
    r.Add("morse", "Classic",
          "国际摩尔斯电码（字母空格分隔，单词用 / 分隔）",
          true, true, MorseEncode, MorseDecode, {"morsecode"});

    r.Add("bacon", "Classic",
          "培根密码：24/26 字母表，A/B（或 0/1）五位一组",
          true, true, BaconEncode, BaconDecode, {"baconian"});

    r.Add("a1z26", "Classic",
          "A=1..Z=26 数字替换（支持 -/空格/逗号或无分隔）",
          true, true, A1Z26Encode, A1Z26Decode, {"alphabet-number"});

    r.Add("polybius", "Classic",
          "波利比奥斯方阵 5x5 坐标编码（J 并入 I）",
          true, true, PolybiusEncode, PolybiusDecode, {"polybius-square"});

    r.Add("tap-code", "Classic",
          "敲击码：5x5 方阵，用点/数字表示行列",
          true, true, TapCodeEncode, TapCodeDecode, {"tapcode", "knock"});

    r.Add("braille", "Classic",
          "盲文点字：a-z 映射到 U+2801 起，支持数字与大写标记",
          true, true, BrailleEncode, BrailleDecode, {"braillecode"});

    r.Add("pigpen", "Classic",
          "猪圈密码：26 个几何符号与字母一一对应",
          true, false, PigpenEncode, PigpenDecode, {"pigpen-cipher"});

    r.Add("semaphore", "Classic",
          "旗语：每个字母用两个方位数字（1-8）表示",
          true, true, SemaphoreEncode, SemaphoreDecode, {"semaphore-flag"});

    r.Add("ascii-binary", "Classic",
          "字符 ASCII 码的 7/8 位二进制（空格分隔）",
          true, true, AsciiBinaryEncode, AsciiBinaryDecode, {});

    r.Add("book-code", "Classic",
          "书本密码：用 book 文本中的序号或行列位置表示字符",
          true, true, BookCodeEncode, BookCodeDecode, {});
}

}  // namespace ctf
