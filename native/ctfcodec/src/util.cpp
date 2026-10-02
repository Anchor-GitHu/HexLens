// util.cpp —— 通用小工具实现
#include "util.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace ctf {

const char* kAlphaDigits62    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const char* kAlphaDigits36    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char* kAlphaBase58      = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const char* kAlphaBase58Ripple = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

// ------------------------------ 字符串 ------------------------------------

std::string ToLower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::string ToUpper(std::string s) {
    for (char& c : s) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    return s;
}

std::string Trim(const std::string& s) {
    size_t b = 0, e = s.size();
    auto sp = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
    };
    while (b < e && sp(s[b])) ++b;
    while (e > b && sp(s[e - 1])) --e;
    return s.substr(b, e - b);
}

bool IEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
}

bool StartsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool EndsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::vector<std::string> Split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

std::string Replace(const std::string& s, const std::string& from, const std::string& to) {
    if (from.empty()) return s;
    std::string out;
    size_t pos = 0;
    while (true) {
        size_t p = s.find(from, pos);
        if (p == std::string::npos) {
            out.append(s, pos, std::string::npos);
            break;
        }
        out.append(s, pos, p - pos);
        out += to;
        pos = p + from.size();
    }
    return out;
}

std::string Format(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = std::vsnprintf(nullptr, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(ap2);
        return std::string();
    }
    std::string s(static_cast<size_t>(n), '\0');
    std::vsnprintf(&s[0], static_cast<size_t>(n) + 1, fmt, ap2);
    va_end(ap2);
    return s;
}

std::string Str(const Bytes& b) {
    return std::string(b.begin(), b.end());
}

Bytes ToBytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

Bytes Concat(const Bytes& a, const Bytes& b) {
    Bytes out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

// ------------------------------ 十六进制 ----------------------------------

bool IsHexDigit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string HexEncode(const Bytes& b, bool upper) {
    static const char* lo = "0123456789abcdef";
    static const char* up = "0123456789ABCDEF";
    const char* tbl = upper ? up : lo;
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t c : b) {
        s.push_back(tbl[c >> 4]);
        s.push_back(tbl[c & 0x0F]);
    }
    return s;
}

Bytes HexDecode(const std::string& s) {
    Bytes out;
    out.reserve(s.size() / 2);
    int hi = -1;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        // 跳过常见分隔与前缀：空白 , : - _ 换行
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == ':' ||
            c == '-' || c == '_') {
            continue;
        }
        // 前缀 0x / \x / %  直接跳过
        if ((c == '0' && i + 1 < s.size() && (s[i + 1] == 'x' || s[i + 1] == 'X')) ||
            (c == '\\' && i + 1 < s.size() && (s[i + 1] == 'x' || s[i + 1] == 'X')) ||
            (c == '%' && i + 1 < s.size())) {
            ++i;
            continue;
        }
        int v = HexVal(c);
        if (v < 0) {
            throw Error(Format("十六进制串含非法字符 '%c' (位置 %zu)", c, i));
        }
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    if (hi >= 0) throw Error("十六进制串长度为奇数，无法组成完整字节");
    return out;
}

Bytes ParseByteLiteral(const std::string& s) {
    if (StartsWith(s, "hex:")) return HexDecode(s.substr(4));
    if (StartsWith(s, "str:")) return ToBytes(s.substr(4));
    if (StartsWith(s, "raw:")) return ToBytes(s.substr(4));
    return ToBytes(s);
}

// ------------------------------ 断言/解析 ---------------------------------

void Require(bool cond, const std::string& msg) {
    if (!cond) throw Error(msg);
}

int ParseInt(const std::string& s, const std::string& what) {
    std::string t = Trim(s);
    if (t.empty()) throw Error("参数 " + what + " 不是合法整数（空）");
    char* end = nullptr;
    long v = std::strtol(t.c_str(), &end, 10);
    if (end == t.c_str() || *end != '\0') {
        throw Error("参数 " + what + " 不是合法整数: " + t);
    }
    return static_cast<int>(v);
}

// --------------------------- 大数任意进制转换 ------------------------------
// 思路：把输入串按 alphabet 转成「数字值数组」，再反复做「除 to_base 取余」，
//       全程只用小整数除法，天然支持任意长度（CTF 里那种几百位十进制）。
std::string BigIntBaseConvert(const std::string& digits,
                              int                from_base,
                              int                to_base,
                              const std::string& alphabet) {
    if (from_base == 0) from_base = static_cast<int>(alphabet.size());
    if (from_base < 2 || from_base > 64) throw Error("非法源进制（2..64）");
    if (to_base < 2 || to_base > 64) throw Error("非法目标进制（2..64）");
    if (static_cast<int>(alphabet.size()) < from_base ||
        static_cast<int>(alphabet.size()) < to_base) {
        throw Error("数字表长度不足以表示指定的进制");
    }

    // 去掉常见的 0x / 前导空白
    std::string in = Trim(digits);
    if (in.size() > 2 && in[0] == '0' && (in[1] == 'x' || in[1] == 'X')) in = in.substr(2);
    if (in.empty()) return "0";

    // 建立字符 -> 数值映射（大小写不敏感）
    std::string alpha = alphabet;
    std::vector<int> lut(256, -1);
    for (size_t i = 0; i < alpha.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(alpha[i]);
        if (lut[c] < 0) lut[c] = static_cast<int>(i);
        if (c >= 'a' && c <= 'z') {
            unsigned char u = static_cast<unsigned char>(c - 'a' + 'A');
            if (lut[u] < 0) lut[u] = static_cast<int>(i);
        } else if (c >= 'A' && c <= 'Z') {
            unsigned char l = static_cast<unsigned char>(c - 'A' + 'a');
            if (lut[l] < 0) lut[l] = static_cast<int>(i);
        }
    }

    // 转换成值数组（大端在前）
    std::vector<int> v;
    v.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(in[i]);
        // 容忍下划线/空格分隔
        if (c == '_' || c == ' ' || c == '\t') continue;
        int d = lut[c];
        if (d < 0 || d >= from_base) {
            throw Error(Format("字符 '%c' 不是 %d 进制的合法数字", in[i], from_base));
        }
        v.push_back(d);
    }
    if (v.empty()) return "0";

    // 反复除 to_base
    std::string out;
    size_t start = 0;
    while (start < v.size()) {
        int rem = 0;
        std::vector<int> q;
        q.reserve(v.size());
        for (size_t i = start; i < v.size(); ++i) {
            int cur = rem * from_base + v[i];
            int d   = cur / to_base;
            rem     = cur % to_base;
            if (!q.empty() || d != 0) q.push_back(d);
        }
        out.push_back(alphabet[static_cast<size_t>(rem)]);
        v.swap(q);
        start = 0;
    }
    if (out.empty()) out = "0";
    std::reverse(out.begin(), out.end());
    return out;
}

}  // namespace ctf
