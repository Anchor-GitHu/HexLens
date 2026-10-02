// magic.cpp —— 编码自动识别（CTF 里拿到一串东西先问「这是什么」）
//
// 思路：先做廉价的字符集/模式匹配给出基础分，再对可疑候选真正试解码一次，
//       如果解出来是可读文本就加分并附上预览。
// 输出 JSON 数组，按分数降序。
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <string>
#include <vector>

#include "common.h"
#include "util.h"

namespace ctf {

namespace {

struct Cand {
    std::string alg;
    int         score = 0;
    std::string reason;
    std::string preview;
};

// 判断一段字节是否「像可读文本」
bool IsPrintable(const std::string& s) {
    if (s.empty()) return false;
    size_t ok = 0;
    for (unsigned char c : s) {
        if ((c >= 32 && c < 127) || c == '\n' || c == '\r' || c == '\t') {
            ++ok;
        } else if (c >= 0x80) {
            // 粗略放行 UTF-8 高位字节（中文等），但要排除连续乱码
            ++ok;
        }
    }
    return ok * 100 / s.size() >= 92;
}

bool AllIn(const std::string& s, const std::string& set) {
    if (s.empty()) return false;
    for (char c : s) {
        if (set.find(c) == std::string::npos) return false;
    }
    return true;
}

size_t CountOf(const std::string& s, char c) {
    size_t n = 0;
    for (char x : s) {
        if (x == c) ++n;
    }
    return n;
}

bool ContainsSub(const std::string& s, const std::string& sub) {
    return s.find(sub) != std::string::npos;
}

// 试解码：成功返回 true
bool TryDecode(const char* alg, const std::string& in, std::string& out) {
    try {
        const Codec* c = Registry::Instance().Find(alg);
        if (!c || !c->dec) return false;
        Bytes o;
        Params p;
        c->dec(ToBytes(in), p, o);
        out = Str(o);
        return true;
    } catch (...) {
        return false;
    }
}

std::string Preview(const std::string& s, size_t maxLen = 60) {
    std::string out;
    for (char c : s) {
        if (out.size() >= maxLen) {
            out += "...";
            break;
        }
        if (c == '\n') {
            out += "\\n";
        } else if (c == '\r') {
            out += "\\r";
        } else if (c == '\t') {
            out += "\\t";
        } else if (static_cast<unsigned char>(c) < 32) {
            out += '.';
        } else {
            out += c;
        }
    }
    return out;
}

std::string JsonEscape(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 32) {
                    out += Format("\\u%04x", c);
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

void Add(std::vector<Cand>& v, const std::string& alg, int score, const std::string& reason,
         const std::string& preview = "") {
    Cand c;
    c.alg     = alg;
    c.score   = score;
    c.reason  = reason;
    c.preview = preview;
    v.push_back(c);
}

}  // namespace

std::string MagicAnalyze(const std::string& text) {
    EnsureInitialized();

    std::string t = Trim(text);
    std::vector<Cand> cands;

    if (t.empty()) return "[]";

    const size_t n = t.size();

    // ---------------------------------------------------------------- 隐写类
    // 零宽字符 U+200B / U+200C / U+200D
    if (ContainsSub(t, "\xE2\x80\x8B") || ContainsSub(t, "\xE2\x80\x8C")) {
        std::string dec;
        if (TryDecode("zero-width", t, dec)) {
            Add(cands, "zero-width", 95, "含零宽字符 U+200B/U+200C，疑似零宽隐写", Preview(dec));
        } else {
            Add(cands, "zero-width", 85, "含零宽字符 U+200B/U+200C");
        }
    }

    // Unicode Tags 区 U+E0000..U+E007F（UTF-8: F3 A0 80 80 ..）
    if (ContainsSub(t, "\xF3\xA0")) {
        std::string dec;
        if (TryDecode("unicode-tag", t, dec)) {
            Add(cands, "unicode-tag", 95, "含 Unicode Tags 区不可见字符，疑似 tag 隐写",
                Preview(dec));
        }
    }

    // ------------------------------------------------------------------ JWT
    if (CountOf(t, '.') == 2) {
        auto parts = Split(t, '.');
        bool okChars = true;
        for (auto& seg : parts) {
            if (!AllIn(seg, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/")) {
                okChars = false;
                break;
            }
        }
        if (okChars && !parts[0].empty()) {
            std::string hdr;
            std::string seg = parts[0];
            // 补 padding 再解
            while (seg.size() % 4) seg += "=";
            std::string tmp;
            Params p;
            p.Set("url", "1");
            try {
                const Codec* c = Registry::Instance().Find("base64");
                Bytes o;
                c->dec(ToBytes(seg), p, o);
                tmp = Str(o);
            } catch (...) {
            }
            if (ContainsSub(tmp, "\"alg\"") || ContainsSub(tmp, "\"typ\"")) {
                Add(cands, "jwt", 98, "三段式 base64url，首段解出 JWT 头 {\"alg\":...}", Preview(tmp));
            }
        }
    }

    // ------------------------------------------------------- Unicode 转义系列
    if (ContainsSub(t, "\\u") || ContainsSub(t, "\\U")) {
        std::string dec;
        if (TryDecode("unicode-escape", t, dec)) {
            Add(cands, "unicode-escape", 88, "含 \\uXXXX 转义序列", Preview(dec));
        }
    }
    if (ContainsSub(t, "%u") || ContainsSub(t, "%U")) {
        std::string dec;
        if (TryDecode("percent-u", t, dec)) {
            Add(cands, "percent-u", 86, "含 %uXXXX 转义序列", Preview(dec));
        }
    }
    if (ContainsSub(t, "U+") || ContainsSub(t, "u+")) {
        std::string dec;
        if (TryDecode("codepoint", t, dec)) {
            Add(cands, "codepoint", 85, "含 U+XXXX 码点表示", Preview(dec));
        }
    }

    // ------------------------------------------------------------------ URL
    if (t.find('%') != std::string::npos) {
        size_t okSeq = 0;
        for (size_t i = 0; i + 2 < t.size(); ++i) {
            if (t[i] == '%' && IsHexDigit(t[i + 1]) && IsHexDigit(t[i + 2])) ++okSeq;
        }
        if (okSeq > 0) {
            std::string dec;
            int sc = 80;
            std::string why = Format("含 %d 个 %%XX 转义序列", (int)okSeq);
            if (TryDecode("url", t, dec)) {
                sc = 85;
                if (IsPrintable(dec)) {
                    sc = 90;
                    why += "，解码后可读";
                }
                Add(cands, "url", sc, why, Preview(dec));
            } else {
                Add(cands, "url", sc, why);
            }
            if (TryDecode("urldouble", t, dec)) {
                Add(cands, "urldouble", 70, "可能是双重 URL 编码（解开一层后仍是 %XX）",
                    Preview(dec));
            }
        }
    }

    // ------------------------------------------------------------------ HTML
    if (t.find('&') != std::string::npos && t.find(';') != std::string::npos) {
        std::string dec;
        if (TryDecode("html", t, dec) && dec != t) {
            Add(cands, "html", 85, "含 HTML 实体（&...;）", Preview(dec));
        }
    }

    // ---------------------------------------------------------------- Morse
    {
        bool morseOk = true;
        size_t sig = 0;
        for (char c : t) {
            if (c == '.' || c == '-' || c == '_' || c == ' ' || c == '/' || c == '\n' ||
                c == '\r' || c == '\t' || c == '|') {
                if (c == '.' || c == '-' || c == '_') ++sig;
            } else {
                morseOk = false;
                break;
            }
        }
        if (morseOk && sig >= 2) {
            std::string dec;
            if (TryDecode("morse", t, dec)) {
                Add(cands, "morse", 92, "仅由 . - / 空格组成，疑似摩尔斯电码", Preview(dec));
            }
        }
    }

    // ---------------------------------------------------------------- 盲文
    if (ContainsSub(t, "\xE2\xA0") || ContainsSub(t, "\xE2\xA1")) {
        std::string dec;
        if (TryDecode("braille", t, dec)) {
            Add(cands, "braille", 88, "含 Unicode 盲文字符 U+28xx", Preview(dec));
        }
    }

    // ------------------------------------------------------------ 二进制/八进制
    {
        std::string body;
        for (char c : t) {
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ',') continue;
            body += c;
        }
        if (!body.empty() && AllIn(body, "01")) {
            if (body.size() % 8 == 0 && body.size() >= 8) {
                std::string dec;
                Params p;
                p.Set("stream", "1");
                try {
                    const Codec* c = Registry::Instance().Find("binary");
                    Bytes o;
                    c->dec(ToBytes(body), p, o);
                    dec = Str(o);
                } catch (...) {
                }
                Add(cands, "binary", 80, "仅由 0/1 组成且长度是 8 的倍数（二进制字节流）",
                    Preview(dec));
            } else if (body.size() % 7 == 0) {
                Add(cands, "binary", 60, "仅由 0/1 组成，长度是 7 的倍数（可能是 7 位 ASCII）");
            }
        }
        if (!body.empty() && AllIn(body, "01234567") && body.size() >= 3) {
            std::string dec;
            if (TryDecode("octal", t, dec) && IsPrintable(dec)) {
                Add(cands, "octal", 72, "仅由 0-7 组成", Preview(dec));
            }
        }
    }

    // ------------------------------------------------------------------ 十六进制
    {
        std::string body;
        for (char c : t) {
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ',' || c == '\\' ||
                c == 'x' || c == 'X') {
                continue;
            }
            body += c;
        }
        bool looksHexPrefix = ContainsSub(t, "0x") || ContainsSub(t, "\\x");
        if (!body.empty() && body.size() >= 4 && AllIn(body, "0123456789abcdefABCDEF") &&
            body.size() % 2 == 0) {
            std::string dec;
            if (TryDecode("base16", t, dec)) {
                int sc = looksHexPrefix ? 85 : 70;
                std::string why = "仅由十六进制字符组成，长度为偶数";
                if (IsPrintable(dec)) {
                    sc = std::max(sc, 78);
                    why += "，字节可读";
                }
                Add(cands, "base16", sc, why, Preview(dec));
            }
        }
    }

    // ------------------------------------------------------------------ Base64
    {
        std::string body = t;
        body.erase(std::remove_if(body.begin(), body.end(), [](char c) {
                       return c == '\n' || c == '\r' || c == ' ' || c == '\t';
                   }),
                   body.end());
        bool b64chars = AllIn(body, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_");
        if (b64chars && body.size() >= 8 && body.size() % 4 == 0) {
            bool urlSafe = body.find('-') != std::string::npos || body.find('_') != std::string::npos;
            const char* alg = urlSafe ? "base64url" : "base64";
            std::string dec;
            if (TryDecode(alg, t, dec)) {
                int sc = 62;
                std::string why = "Base64 字符集且长度为 4 的倍数";
                if (IsPrintable(dec)) {
                    sc = 88;
                    why += "，解码后可读文本";
                }
                Add(cands, alg, sc, why, Preview(dec));
            }
        }

        // -------------------------------------------------------------- Base32
        std::string up = ToUpper(body);
        up.erase(std::remove(up.begin(), up.end(), '='), up.end());
        if (!up.empty() && AllIn(up, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") && up.size() >= 8) {
            std::string dec;
            if (TryDecode("base32", t, dec)) {
                int sc = 60;
                std::string why = "符合 Base32 字符集（A-Z2-7）";
                if (IsPrintable(dec)) {
                    sc = 82;
                    why += "，解码后可读";
                }
                Add(cands, "base32", sc, why, Preview(dec));
            }
        }

        // -------------------------------------------------------------- Base58
        if (!body.empty() && AllIn(body, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz") &&
            body.size() >= 8) {
            std::string dec;
            if (TryDecode("base58", t, dec)) {
                int sc = 55;
                std::string why = "符合 Base58 字符集（无 0OIl）";
                if (IsPrintable(dec)) {
                    sc = 75;
                    why += "，解码后可读";
                }
                Add(cands, "base58", sc, why, Preview(dec));
            }
        }
    }

    // -------------------------------------------------------- Base85 / Base91
    if (t.find('~') != std::string::npos || t.find('!') != std::string::npos) {
        std::string dec;
        if (TryDecode("base85", t, dec) && IsPrintable(dec)) {
            Add(cands, "base85", 70, "含 Ascii85 特征字符", Preview(dec));
        }
    }

    // ---------------------------------------------------------------- A1Z26
    {
        auto parts = Split(t, '-');
        if (parts.size() >= 2) {
            bool ok = true;
            std::string dec;
            for (auto& s : parts) {
                if (s.empty()) continue;
                if (!AllIn(s, "0123456789")) {
                    ok = false;
                    break;
                }
                int v = std::atoi(s.c_str());
                if (v < 1 || v > 26) {
                    ok = false;
                    break;
                }
                dec += static_cast<char>('A' + v - 1);
            }
            if (ok && !dec.empty()) {
                Add(cands, "a1z26", 75, "形如 1-26 的数字序列（A1Z26）", Preview(dec));
            }
        }
    }

    // ---------------------------------------------------------------- Base62
    if (!t.empty() && AllIn(t, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") &&
        n >= 8) {
        std::string dec;
        if (TryDecode("base62", t, dec) && IsPrintable(dec)) {
            Add(cands, "base62", 60, "仅由字母数字组成（可能是 Base62/Base36）", Preview(dec));
        }
    }

    // 排序取前 8
    std::stable_sort(cands.begin(), cands.end(),
                     [](const Cand& a, const Cand& b) { return a.score > b.score; });
    if (cands.size() > 8) cands.resize(8);

    std::string out = "[";
    for (size_t i = 0; i < cands.size(); ++i) {
        if (i) out += ",";
        out += "{\"alg\":\"" + JsonEscape(cands[i].alg) + "\",\"score\":" +
               std::to_string(cands[i].score) + ",\"reason\":\"" + JsonEscape(cands[i].reason) +
               "\",\"preview\":\"" + JsonEscape(cands[i].preview) + "\"}";
    }
    out += "]";
    return out;
}

}  // namespace ctf
