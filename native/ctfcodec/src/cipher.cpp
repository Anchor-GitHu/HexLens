// cipher.cpp —— 经典密码算法模块（Cipher）
//
// 覆盖：移位/替换（凯撒、ROT 家族、Atbash、单表替换、仿射）、
//       多表替换（维吉尼亚、Beaufort、变体 Beaufort、自动密钥、Porta、
//                 Gronsfeld、Running Key）、
//       置换（栅栏、斯巴达棒、列置换、块反转）、
//       矩阵/多字母（Playfair、Bifid、Hill 2x2）、
//       异或（循环异或、单字节异或、单字节爆破、已知明文推密钥）、
//       其他（Enigma I、RC4、Vernam/OTP）。
//
// 统一约定：
//   * 面向字母的算法默认只变换字母，非字母字节原样保留；参数 keep=0 时
//     丢弃所有非字母字节，只输出字母。ROT5 以数字为目标、ROT47 以可打印
//     ASCII 为目标，keep 语义同构（keep=0 时只输出被变换的字符）。
//   * 所有失败路径抛 ctf::Error（中文信息），绝不 exit/abort/printf。
#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "common.h"
#include "util.h"

namespace ctf {
namespace {

// ===========================================================================
// 一、通用小工具
// ===========================================================================

// 是否为英文字母
inline bool IsAlpha(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

// 字母 -> 0..25（大小写不敏感），非字母返回 -1
inline int LetterIdx(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    return -1;
}

// 0..25 的序号还原成字母，upper 决定大小写
inline uint8_t LetterFrom(int v, bool upper) {
    int m = ((v % 26) + 26) % 26;
    return static_cast<uint8_t>((upper ? 'A' : 'a') + m);
}

// 保持大小写的字母位移（shift 可为负）
inline uint8_t ShiftOneLetter(uint8_t c, int shift) {
    if (c >= 'A' && c <= 'Z') {
        return static_cast<uint8_t>('A' + (((c - 'A' + shift) % 26 + 26) % 26));
    }
    if (c >= 'a' && c <= 'z') {
        return static_cast<uint8_t>('a' + (((c - 'a' + shift) % 26 + 26) % 26));
    }
    return c;
}

// 取一个正整型参数（缺失时抛「缺少必需参数」，<=0 时抛自定义信息）
int RequirePositiveInt(const Params& p, const std::string& k) {
    int v = p.RequireInt(k);
    if (v <= 0) throw Error("参数 " + k + " 必须是正整数");
    return v;
}

// keep 参数：默认 1（非目标字节原样保留），0 表示只输出被变换的字节
int KeepFlag(const Params& p) { return p.GetInt("keep", 1); }

// ---------------------------------------------------------------------------
// 逐字节映射框架：is_target 决定哪些字节参与变换；
// keep=1 时非目标字节原样保留，keep=0 时丢弃。
// ---------------------------------------------------------------------------
template <typename MapFn, typename TargetFn>
void MapText(const Bytes& in, const MapFn& map, const TargetFn& is_target, bool drop_other,
             Bytes& out) {
    out.clear();
    out.reserve(in.size());
    for (uint8_t c : in) {
        if (is_target(c)) {
            out.push_back(map(c));
        } else if (!drop_other) {
            out.push_back(c);
        }
    }
}

// 字母位移类的快捷封装（凯撒 / ROT-n / ROT13）
void MapLettersByShift(const Bytes& in, int shift, bool keep, Bytes& out) {
    MapText(
        in, [shift](uint8_t c) { return ShiftOneLetter(c, shift); },
        [](uint8_t c) { return IsAlpha(c); }, keep == 0, out);
}

// 密钥流来源：给定「已处理的目标字母序号」返回该位置的密钥值
using KeySource = std::function<int(size_t)>;

// 多表替换的统一循环
//   mode: 0 = C=(P+K)  维吉尼亚；1 = C=(K-P) Beaufort；2 = C=(P-K) 变体
void RunPolyMode(const Bytes& in, const KeySource& keysrc, int mode, bool keep, Bytes& out) {
    out.clear();
    out.reserve(in.size());
    size_t pos = 0;
    for (uint8_t c : in) {
        int idx = LetterIdx(c);
        if (idx < 0) {
            if (keep != 0) out.push_back(c);
            continue;
        }
        bool upper = (c <= 'Z');
        int  k     = ((keysrc(pos) % 26) + 26) % 26;
        ++pos;

        int r;
        if (mode == 1) {
            r = k - idx;
        } else if (mode == 2) {
            r = idx - k;
        } else {
            r = idx + k;
        }
        out.push_back(LetterFrom(r, upper));
    }
}

// 把密钥串里的字母抽成 0..25 序列（忽略所有非字母字符）
std::vector<int> KeyLetters(const std::string& s) {
    std::vector<int> v;
    v.reserve(s.size());
    for (char raw : s) {
        int idx = LetterIdx(static_cast<uint8_t>(raw));
        if (idx >= 0) v.push_back(idx);
    }
    Require(!v.empty(), "密钥中没有任何字母");
    return v;
}

// 把密钥串里的数字抽成序列（忽略空格/逗号/连字符等分隔符）
std::vector<int> KeyDigits(const std::string& s) {
    std::vector<int> v;
    for (char raw : s) {
        if (raw == ' ' || raw == '\t' || raw == '\r' || raw == '\n' || raw == ',' ||
            raw == '-' || raw == '_') {
            continue;
        }
        if (raw < '0' || raw > '9') {
            throw Error("Gronsfeld 的 key 必须是数字串（0-9）");
        }
        v.push_back(raw - '0');
    }
    Require(!v.empty(), "Gronsfeld 的 key 为空");
    return v;
}

// 输入里是否含有字母
bool HasLetter(const Bytes& in) {
    for (uint8_t c : in) {
        if (IsAlpha(c)) return true;
    }
    return false;
}

// 输入里字母的个数
size_t CountLetters(const Bytes& in) {
    size_t n = 0;
    for (uint8_t c : in) {
        if (IsAlpha(c)) ++n;
    }
    return n;
}

// ===========================================================================
// 二、数论小工具
// ===========================================================================

// 扩展欧几里得求模逆（a 关于 m 的逆），不存在时返回 -1
int ModInverse(int a, int m) {
    a       = ((a % m) + m) % m;
    int t   = 0, newt = 1;
    int r   = m, newr = a;
    while (newr != 0) {
        int q = r / newr;
        int tmp;
        tmp = t - q * newt; t = newt; newt = tmp;
        tmp = r - q * newr; r = newr; newr = tmp;
    }
    if (r != 1) return -1;
    return ((t % m) + m) % m;
}

// 解析 substitution 的 key：需恰好 26 个互不相同的字母（可含分隔符）
std::array<char, 26> ParseSubstKey(const std::string& key) {
    std::array<char, 26> tbl{};
    std::array<bool, 26> used{};
    used.fill(false);
    size_t n = 0;
    for (char raw : key) {
        int idx = LetterIdx(static_cast<uint8_t>(raw));
        if (idx < 0) continue;
        Require(!used[static_cast<size_t>(idx)], "替换表 key 中出现重复字母");
        used[static_cast<size_t>(idx)] = true;
        Require(n < 26, "替换表 key 的字母超过 26 个");
        tbl[n++] = static_cast<char>('A' + idx);
    }
    Require(n == 26, "替换表 key 必须恰好包含 26 个互不相同的字母");
    return tbl;
}

// 解析逗号/空格分隔的整数列表（Hill 的 key="3,3,2,5"）
std::vector<int> ParseIntList(const std::string& s) {
    std::vector<int> vals;
    std::string      cur;
    auto flush = [&]() {
        std::string t = Trim(cur);
        if (!t.empty()) vals.push_back(ParseInt(t, "key"));
        cur.clear();
    };
    for (char c : s) {
        if (c == ',' || c == ' ' || c == '\t' || c == ';' || c == '|' || c == '/') {
            flush();
        } else {
            cur.push_back(c);
        }
    }
    flush();
    return vals;
}

// ===========================================================================
// 三、组 1：移位 / 替换
// ===========================================================================

void CaesarEnc(const Bytes& in, const Params& p, Bytes& out) {
    MapLettersByShift(in, p.RequireInt("shift"), KeepFlag(p) != 0, out);
}
void CaesarDec(const Bytes& in, const Params& p, Bytes& out) {
    MapLettersByShift(in, -p.RequireInt("shift"), KeepFlag(p) != 0, out);
}
void RotNEnc(const Bytes& in, const Params& p, Bytes& out) {
    MapLettersByShift(in, p.RequireInt("shift"), KeepFlag(p) != 0, out);
}
void RotNDec(const Bytes& in, const Params& p, Bytes& out) {
    MapLettersByShift(in, -p.RequireInt("shift"), KeepFlag(p) != 0, out);
}
void Rot13Enc(const Bytes& in, const Params& p, Bytes& out) {
    MapLettersByShift(in, 13, KeepFlag(p) != 0, out);
}

// ---- rot5：只移数字 0-9（自逆） ----
void Rot5Enc(const Bytes& in, const Params& p, Bytes& out) {
    bool keep = KeepFlag(p) != 0;
    MapText(
        in, [](uint8_t c) { return static_cast<uint8_t>('0' + (((c - '0') + 5) % 10)); },
        [](uint8_t c) { return c >= '0' && c <= '9'; }, !keep, out);
}

// ---- rot18：ROT13 + ROT5（自逆） ----
void Rot18Enc(const Bytes& in, const Params& p, Bytes& out) {
    bool keep = KeepFlag(p) != 0;
    MapText(
        in,
        [](uint8_t c) {
            if (IsAlpha(c)) return ShiftOneLetter(c, 13);
            return static_cast<uint8_t>('0' + (((c - '0') + 5) % 10));
        },
        [](uint8_t c) { return IsAlpha(c) || (c >= '0' && c <= '9'); }, !keep, out);
}

// ---- rot47：可打印 ASCII 33..126（自逆） ----
void Rot47Enc(const Bytes& in, const Params& p, Bytes& out) {
    bool keep = KeepFlag(p) != 0;
    MapText(
        in,
        [](uint8_t c) {
            if (c >= 33 && c <= 126) return static_cast<uint8_t>(33 + (((c - 33) + 47) % 94));
            return c;
        },
        [](uint8_t c) { return c >= 33 && c <= 126; }, !keep, out);
}

// ---- atbash：字母表反转（自逆） ----
void AtbashEnc(const Bytes& in, const Params& p, Bytes& out) {
    bool keep = KeepFlag(p) != 0;
    MapText(
        in,
        [](uint8_t c) {
            if (c >= 'A' && c <= 'Z') return static_cast<uint8_t>('Z' - (c - 'A'));
            return static_cast<uint8_t>('z' - (c - 'a'));
        },
        [](uint8_t c) { return IsAlpha(c); }, !keep, out);
}

// ---- substitution：单表替换 ----
void SubstitutionEnc(const Bytes& in, const Params& p, Bytes& out) {
    std::array<char, 26> tbl  = ParseSubstKey(p.RequireStr("key"));
    bool                 keep = KeepFlag(p) != 0;
    MapText(
        in,
        [&tbl](uint8_t c) {
            char m = tbl[static_cast<size_t>(LetterIdx(c))];
            return static_cast<uint8_t>(c <= 'Z' ? m : (m - 'A' + 'a'));
        },
        [](uint8_t c) { return IsAlpha(c); }, !keep, out);
}

void SubstitutionDec(const Bytes& in, const Params& p, Bytes& out) {
    std::array<char, 26> tbl = ParseSubstKey(p.RequireStr("key"));
    std::array<char, 26> inv{};
    for (size_t i = 0; i < 26; ++i) {
        inv[static_cast<size_t>(tbl[i] - 'A')] = static_cast<char>('A' + i);
    }
    bool keep = KeepFlag(p) != 0;
    MapText(
        in,
        [&inv](uint8_t c) {
            char m = inv[static_cast<size_t>(LetterIdx(c))];
            return static_cast<uint8_t>(c <= 'Z' ? m : (m - 'A' + 'a'));
        },
        [](uint8_t c) { return IsAlpha(c); }, !keep, out);
}

// ---- affine：E(x) = (a*x + b) mod 26 ----
struct AffineKey {
    int a  = 1;
    int b  = 0;
    int ia = 1;   // a 关于 26 的模逆
};

void AffinePrepare(const Params& p, AffineKey& k) {
    k.a = ((p.RequireInt("a") % 26) + 26) % 26;
    k.b = ((p.RequireInt("b") % 26) + 26) % 26;
    Require(k.a != 0, "仿射密码的参数 a 不能是 26 的倍数");
    int ia = ModInverse(k.a, 26);
    Require(ia >= 0,
            "仿射密码要求 gcd(a,26)==1（a 只能取 1,3,5,7,9,11,15,17,19,21,23,25）");
    k.ia = ia;
}

void AffineEnc(const Bytes& in, const Params& p, Bytes& out) {
    AffineKey k;
    AffinePrepare(p, k);
    bool keep = KeepFlag(p) != 0;
    MapText(
        in,
        [&k](uint8_t c) {
            int idx = LetterIdx(c);
            return LetterFrom(k.a * idx + k.b, c <= 'Z');
        },
        [](uint8_t c) { return IsAlpha(c); }, !keep, out);
}

void AffineDec(const Bytes& in, const Params& p, Bytes& out) {
    AffineKey k;
    AffinePrepare(p, k);
    bool keep = KeepFlag(p) != 0;
    MapText(
        in,
        [&k](uint8_t c) {
            int idx = LetterIdx(c);
            return LetterFrom(k.ia * (idx - k.b), c <= 'Z');
        },
        [](uint8_t c) { return IsAlpha(c); }, !keep, out);
}

// ===========================================================================
// 四、组 2：多表替换
// ===========================================================================

void VigenereEnc(const Bytes& in, const Params& p, Bytes& out) {
    std::vector<int> key = KeyLetters(p.RequireStr("key"));
    size_t           n   = key.size();
    RunPolyMode(in, [&key, n](size_t i) { return key[i % n]; }, 0, KeepFlag(p) != 0, out);
}
void VigenereDec(const Bytes& in, const Params& p, Bytes& out) {
    std::vector<int> key = KeyLetters(p.RequireStr("key"));
    size_t           n   = key.size();
    RunPolyMode(in, [&key, n](size_t i) { return key[i % n]; }, 2, KeepFlag(p) != 0, out);
}
void BeaufortEnc(const Bytes& in, const Params& p, Bytes& out) {
    std::vector<int> key = KeyLetters(p.RequireStr("key"));
    size_t           n   = key.size();
    RunPolyMode(in, [&key, n](size_t i) { return key[i % n]; }, 1, KeepFlag(p) != 0, out);
}
void VariantBeaufortEnc(const Bytes& in, const Params& p, Bytes& out) {
    std::vector<int> key = KeyLetters(p.RequireStr("key"));
    size_t           n   = key.size();
    RunPolyMode(in, [&key, n](size_t i) { return key[i % n]; }, 2, KeepFlag(p) != 0, out);
}

// ---- autokey：密钥用完后接明文自身 ----
void AutokeyEnc(const Bytes& in, const Params& p, Bytes& out) {
    std::vector<int> key  = KeyLetters(p.RequireStr("key"));
    bool             keep = KeepFlag(p) != 0;
    size_t           n    = key.size();

    out.clear();
    out.reserve(in.size());
    std::vector<int> produced;   // 已产出的明文（0..25）
    produced.reserve(in.size());
    for (uint8_t c : in) {
        int idx = LetterIdx(c);
        if (idx < 0) {
            if (keep) out.push_back(c);
            continue;
        }
        size_t pos = produced.size();
        int    k   = (pos < n) ? key[pos] : produced[pos - n];
        produced.push_back(idx);
        out.push_back(LetterFrom(idx + k, c <= 'Z'));
    }
}

void AutokeyDec(const Bytes& in, const Params& p, Bytes& out) {
    std::vector<int> key  = KeyLetters(p.RequireStr("key"));
    bool             keep = KeepFlag(p) != 0;
    size_t           n    = key.size();

    out.clear();
    out.reserve(in.size());
    std::vector<int> plain;   // 已解出的明文（0..25）
    plain.reserve(in.size());
    for (uint8_t c : in) {
        int idx = LetterIdx(c);
        if (idx < 0) {
            if (keep) out.push_back(c);
            continue;
        }
        size_t pos = plain.size();
        int    k   = (pos < n) ? key[pos] : plain[pos - n];
        int    r   = ((idx - k) % 26 + 26) % 26;
        plain.push_back(r);
        out.push_back(LetterFrom(r, c <= 'Z'));
    }
}

// ---- porta：13 组对换表（自逆），密钥字母 A/N 同表，B/O 同表 …… ----
// 每一行是「半张对换表」：明文字母 i 映射到 row[i]-'A'。
// 两半互为对方的行内逆映射，因此整表自逆。
const char* const kPorta[13] = {
    "NOPQRSTUVWXYZABCDEFGHIJKLM",   // A,B
    "OPQRSTUVWXYZNMABCDEFGHIJKL",   // C,D
    "PQRSTUVWXYZNOLMABCDEFGHIJK",   // E,F
    "QRSTUVWXYZNOPKLMABCDEFGHIJ",   // G,H
    "RSTUVWXYZNOPQJKLMABCDEFGHI",   // I,J
    "STUVWXYZNOPQRIJKLMABCDEFGH",   // K,L
    "TUVWXYZNOPQRSHIJKLMABCDEFG",   // M,N
    "UVWXYZNOPQRSTGHIJKLMABCDEF",   // O,P
    "VWXYZNOPQRSTUFGHIJKLMABCDE",   // Q,R
    "WXYZNOPQRSTUVEFGHIJKLMABCD",   // S,T
    "XYZNOPQRSTUVWDEFGHIJKLMABC",   // U,V
    "YZNOPQRSTUVWCDEFGHIJKLMAB",    // W,X
    "ZNOPQRSTUVWXBCDEFGHIJKLMA",    // Y,Z
};

void PortaEnc(const Bytes& in, const Params& p, Bytes& out) {
    std::vector<int> key  = KeyLetters(p.RequireStr("key"));
    size_t           n    = key.size();
    bool             keep = KeepFlag(p) != 0;

    out.clear();
    out.reserve(in.size());
    size_t pos = 0;
    for (uint8_t c : in) {
        int idx = LetterIdx(c);
        if (idx < 0) {
            if (keep) out.push_back(c);
            continue;
        }
        int         k     = key[pos % n];
        const char* row   = kPorta[k / 2];
        int         mapped = row[idx] - 'A';
        ++pos;
        out.push_back(LetterFrom(mapped, c <= 'Z'));
    }
}

// ---- gronsfeld：密钥是数字串 ----
void GronsfeldEnc(const Bytes& in, const Params& p, Bytes& out) {
    std::vector<int> key = KeyDigits(p.RequireStr("key"));
    size_t           n   = key.size();
    RunPolyMode(in, [&key, n](size_t i) { return key[i % n]; }, 0, KeepFlag(p) != 0, out);
}
void GronsfeldDec(const Bytes& in, const Params& p, Bytes& out) {
    std::vector<int> key = KeyDigits(p.RequireStr("key"));
    size_t           n   = key.size();
    RunPolyMode(in, [&key, n](size_t i) { return key[i % n]; }, 2, KeepFlag(p) != 0, out);
}

// ---- running-key：密钥是长文本，字母数需 >= 输入中的字母数 ----
std::vector<int> RunningKeyLetters(const Bytes& in, const Params& p) {
    std::vector<int> key  = KeyLetters(p.RequireStr("key"));
    size_t           need = CountLetters(in);
    Require(key.size() >= need,
            Format("running-key 的 key 长度不足：需要至少 %zu 个字母，实际 %zu 个", need,
                   key.size()));
    return key;
}

void RunningKeyEnc(const Bytes& in, const Params& p, Bytes& out) {
    std::vector<int> key = RunningKeyLetters(in, p);
    RunPolyMode(in, [&key](size_t i) { return key[i]; }, 0, KeepFlag(p) != 0, out);
}
void RunningKeyDec(const Bytes& in, const Params& p, Bytes& out) {
    std::vector<int> key = RunningKeyLetters(in, p);
    RunPolyMode(in, [&key](size_t i) { return key[i]; }, 2, KeepFlag(p) != 0, out);
}

// ===========================================================================
// 五、组 3：置换类
// ===========================================================================

// 生成每个位置所属的轨号（含起始偏移 offset）
std::vector<int> RailPattern(size_t len, int rails, int offset) {
    std::vector<int> pat(len, 0);
    if (rails <= 1) return pat;
    int period = 2 * (rails - 1);
    int r      = ((offset % period) + period) % period;
    int dir    = 1;
    if (r >= rails) {
        r   = period - r;
        dir = -1;
    }
    for (size_t i = 0; i < len; ++i) {
        pat[i] = r;
        if (r + dir < 0 || r + dir >= rails) dir = -dir;
        r += dir;
    }
    return pat;
}

void RailFenceEnc(const Bytes& in, const Params& p, Bytes& out) {
    int rails = RequirePositiveInt(p, "rails");
    int off   = p.GetInt("offset", 0);

    out.clear();
    if (in.empty()) return;
    if (rails == 1) {
        out = in;
        return;
    }
    std::vector<int> pat = RailPattern(in.size(), rails, off);
    out.reserve(in.size());
    for (int r = 0; r < rails; ++r) {
        for (size_t i = 0; i < in.size(); ++i) {
            if (pat[i] == r) out.push_back(in[i]);
        }
    }
}

void RailFenceDec(const Bytes& in, const Params& p, Bytes& out) {
    int rails = RequirePositiveInt(p, "rails");
    int off   = p.GetInt("offset", 0);

    out.clear();
    if (in.empty()) return;
    if (rails == 1) {
        out = in;
        return;
    }
    std::vector<int> pat = RailPattern(in.size(), rails, off);

    // 每行字符数 + 各行的密文起始位置
    std::vector<size_t> cnt(static_cast<size_t>(rails), 0);
    for (size_t i = 0; i < pat.size(); ++i) ++cnt[static_cast<size_t>(pat[i])];
    std::vector<size_t> cursor(static_cast<size_t>(rails), 0);
    size_t              acc = 0;
    for (int r = 0; r < rails; ++r) {
        cursor[static_cast<size_t>(r)] = acc;
        acc += cnt[static_cast<size_t>(r)];
    }
    Require(acc == in.size(), "内部错误：栅栏各行长度之和与输入不符");

    out.assign(in.size(), 0);
    for (size_t i = 0; i < pat.size(); ++i) {
        size_t r = static_cast<size_t>(pat[i]);
        out[i]   = in[cursor[r]++];
    }
}

// ---- scytale：按 n 列写出（行优先），再按列读出 ----
void ScytaleEnc(const Bytes& in, const Params& p, Bytes& out) {
    int    n    = RequirePositiveInt(p, "n");
    size_t cols = static_cast<size_t>(n);

    out.clear();
    if (in.empty()) return;
    if (cols >= in.size()) {
        out = in;   // 只有一行，写读一致
        return;
    }
    size_t rows = (in.size() + cols - 1) / cols;
    out.reserve(in.size());
    for (size_t c = 0; c < cols; ++c) {
        for (size_t r = 0; r < rows; ++r) {
            size_t idx = r * cols + c;
            if (idx < in.size()) out.push_back(in[idx]);
        }
    }
}

void ScytaleDec(const Bytes& in, const Params& p, Bytes& out) {
    int    n    = RequirePositiveInt(p, "n");
    size_t cols = static_cast<size_t>(n);

    out.clear();
    if (in.empty()) return;
    if (cols >= in.size()) {
        out = in;
        return;
    }
    size_t rows = (in.size() + cols - 1) / cols;
    // 前 rem 列长度为 rows，其余为 rows-1
    size_t rem = in.size() % cols;
    if (rem == 0) rem = cols;

    std::vector<size_t> colLen(cols, rows);
    for (size_t c = rem; c < cols; ++c) colLen[c] = rows - 1;

    out.assign(in.size(), 0);
    size_t pos = 0;
    for (size_t c = 0; c < cols; ++c) {
        for (size_t r = 0; r < colLen[c]; ++r) {
            out[r * cols + c] = in[pos++];
        }
    }
}

// ---- columnar：列置换 ----
// 密钥词各列的读取顺序（按字母升序，同字母按出现先后）
std::vector<size_t> ColumnOrder(const std::string& key) {
    std::vector<size_t> order;
    std::vector<char>   letters;
    for (size_t i = 0; i < key.size(); ++i) {
        char u = key[i];
        if (u >= 'a' && u <= 'z') u = static_cast<char>(u - 'a' + 'A');
        if (u < 'A' || u > 'Z') continue;
        order.push_back(i);
        letters.push_back(u);
    }
    Require(!order.empty(), "列置换的 key 必须至少包含一个字母");
    std::stable_sort(order.begin(), order.end(),
                     [&letters](size_t a, size_t b) { return letters[a] < letters[b]; });
    return order;
}

// 每列实际参与读取的格子数（无填充时最后一行右侧留空）。
//   total : 明文长度（不含 pad 补齐）
std::vector<size_t> ColumnLengths(size_t total, size_t cols, bool usePad) {
    size_t rows = (total + cols - 1) / cols;
    std::vector<size_t> colLen(cols, rows);
    if (usePad) return colLen;
    size_t rem = total % cols;
    if (rem == 0) return colLen;
    for (size_t c = rem; c < cols; ++c) colLen[c] = rows - 1;
    return colLen;
}

void ColumnarEnc(const Bytes& in, const Params& p, Bytes& out) {
    std::string key = p.RequireStr("key");
    std::string pad = p.Get("pad", std::string());
    Require(pad.size() <= 1, "参数 pad 只能是单个字符");

    std::vector<size_t> order  = ColumnOrder(key);
    size_t              cols   = order.size();
    bool                usePad = !pad.empty();

    out.clear();
    if (in.empty()) return;

    // 按「行优先」把字符填进矩形；有 pad 时最后一行不足处用 pad 字符补齐。
    // 无 pad 时最后一行右侧留空（不写入任何字节，解密端按列长规则跳过）。
    size_t              rows   = (in.size() + cols - 1) / cols;
    std::vector<size_t> colLen = ColumnLengths(in.size(), cols, usePad);

    std::vector<uint8_t> grid(rows * cols, usePad ? static_cast<uint8_t>(pad[0]) : 0);
    for (size_t i = 0; i < in.size(); ++i) grid[(i / cols) * cols + (i % cols)] = in[i];

    // 按密钥决定的列顺序逐列读，只读每列的实际长度
    out.reserve(in.size());
    for (size_t oi = 0; oi < cols; ++oi) {
        size_t c = order[oi];
        for (size_t r = 0; r < colLen[c]; ++r) out.push_back(grid[r * cols + c]);
    }
}

void ColumnarDec(const Bytes& in, const Params& p, Bytes& out) {
    std::string key = p.RequireStr("key");
    std::string pad = p.Get("pad", std::string());
    Require(pad.size() <= 1, "参数 pad 只能是单个字符");

    std::vector<size_t> order  = ColumnOrder(key);
    size_t              cols   = order.size();
    bool                usePad = !pad.empty();

    out.clear();
    if (in.empty()) return;

    size_t              rows   = 0;
    std::vector<size_t> colLen;
    size_t              plainLen = in.size();
    if (usePad) {
        // 有填充：密文长度就是完整的 rows x cols（每列等长）。
        rows     = in.size() / cols;
        plainLen = in.size();
        Require(rows * cols == in.size(), "列置换密文长度必须是密钥字母数的整数倍");
        colLen.assign(cols, rows);
    } else {
        // 无填充：密文长度等于明文长度，用它反推列长（最后一行右侧留空）
        colLen = ColumnLengths(in.size(), cols, false);
        size_t total = 0;
        for (size_t c = 0; c < cols; ++c) total += colLen[c];
        Require(total == in.size(), "内部错误：列置换列长之和与输入不符");
        rows = (in.size() + cols - 1) / cols;
    }

    // 按读取顺序把密文还原到各列，再按行读出
    std::vector<uint8_t> grid(rows * cols, 0);
    size_t               pos = 0;
    for (size_t oi = 0; oi < cols; ++oi) {
        size_t c = order[oi];
        for (size_t r = 0; r < colLen[c]; ++r) {
            grid[r * cols + c] = in[pos++];
        }
    }
    out.reserve(plainLen);
    for (size_t i = 0; i < plainLen; ++i) {
        out.push_back(grid[(i / cols) * cols + (i % cols)]);
    }

    // 有填充：把末尾连续的 pad 字符去掉，还原原始明文
    if (usePad && !pad.empty()) {
        uint8_t pc = static_cast<uint8_t>(pad[0]);
        while (!out.empty() && out.back() == pc) out.pop_back();
    }
}

// ---- reverse-block：块内字节反转 ----
void ReverseBlockEnc(const Bytes& in, const Params& p, Bytes& out) {
    size_t block = static_cast<size_t>(RequirePositiveInt(p, "block"));
    out.clear();
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); i += block) {
        size_t end = std::min(i + block, in.size());
        for (size_t j = end; j > i; --j) out.push_back(in[j - 1]);
    }
}

// ===========================================================================
// 六、组 4：矩阵 / 多字母
// ===========================================================================

// ----- Playfair 5x5 方阵（I/J 合并） -----
struct PlayfairGrid {
    std::array<char, 25> cell{};
    std::array<int, 26>  pos{};   // 字母 0..25 -> 0..24（J 视同 I）

    PlayfairGrid() { pos.fill(0); }
};

PlayfairGrid BuildPlayfair(const std::string& key) {
    PlayfairGrid         g;
    std::array<bool, 26> used{};
    used.fill(false);
    std::string all = key + "ABCDEFGHIKLMNOPQRSTUVWXYZ";   // 池中无 J
    size_t      n   = 0;
    for (char raw : all) {
        int idx = LetterIdx(static_cast<uint8_t>(raw));
        if (idx < 0) continue;
        if (idx == 9) idx = 8;   // J -> I
        if (used[static_cast<size_t>(idx)]) continue;
        used[static_cast<size_t>(idx)] = true;
        g.cell[n++]                    = static_cast<char>('A' + idx);
    }
    Require(n == 25, "内部错误：Playfair 方阵不足 25 格");
    for (size_t i = 0; i < 25; ++i) {
        g.pos[static_cast<size_t>(g.cell[i] - 'A')] = static_cast<int>(i);
    }
    g.pos[9] = g.pos[8];   // J 同 I
    return g;
}

// 只保留字母并转大写，J->I
std::string PlayfairNormalize(const Bytes& in) {
    std::string s;
    s.reserve(in.size());
    for (uint8_t c : in) {
        int idx = LetterIdx(c);
        if (idx < 0) continue;
        if (idx == 9) idx = 8;
        s.push_back(static_cast<char>('A' + idx));
    }
    return s;
}

// 同对重复字母之间插 X，末尾为奇数时补 X，然后两两成对
std::vector<std::pair<int, int>> PlayfairPairs(const std::string& s) {
    std::vector<int> v;
    v.reserve(s.size());
    for (char c : s) v.push_back(c - 'A');

    std::vector<int> seq;
    seq.reserve(v.size() + 2);
    for (size_t i = 0; i < v.size(); ++i) {
        if (!seq.empty() && (seq.size() % 2 == 1) && seq.back() == v[i]) {
            seq.push_back(23);   // X
        }
        seq.push_back(v[i]);
    }
    if (seq.size() % 2 == 1) seq.push_back(23);

    std::vector<std::pair<int, int>> pairs;
    pairs.reserve(seq.size() / 2);
    for (size_t i = 0; i + 1 < seq.size(); i += 2) {
        pairs.emplace_back(seq[i], seq[i + 1]);
    }
    return pairs;
}

void PlayfairEnc(const Bytes& in, const Params& p, Bytes& out) {
    PlayfairGrid g = BuildPlayfair(p.RequireStr("key"));
    out.clear();
    if (!HasLetter(in)) return;

    std::vector<std::pair<int, int>> pairs = PlayfairPairs(PlayfairNormalize(in));
    out.reserve(pairs.size() * 2);
    for (const auto& pr : pairs) {
        int p1 = g.pos[static_cast<size_t>(pr.first)];
        int p2 = g.pos[static_cast<size_t>(pr.second)];
        int r1 = p1 / 5, c1 = p1 % 5;
        int r2 = p2 / 5, c2 = p2 % 5;
        if (r1 == r2) {
            c1 = (c1 + 1) % 5;
            c2 = (c2 + 1) % 5;
        } else if (c1 == c2) {
            r1 = (r1 + 1) % 5;
            r2 = (r2 + 1) % 5;
        } else {
            std::swap(c1, c2);
        }
        out.push_back(static_cast<uint8_t>(g.cell[static_cast<size_t>(r1 * 5 + c1)]));
        out.push_back(static_cast<uint8_t>(g.cell[static_cast<size_t>(r2 * 5 + c2)]));
    }
}

void PlayfairDec(const Bytes& in, const Params& p, Bytes& out) {
    PlayfairGrid g = BuildPlayfair(p.RequireStr("key"));
    out.clear();
    if (!HasLetter(in)) return;

    std::string s = PlayfairNormalize(in);
    if (s.size() % 2 == 1) s.push_back('X');

    std::vector<char> res;
    res.reserve(s.size());
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int p1 = g.pos[static_cast<size_t>(s[i] - 'A')];
        int p2 = g.pos[static_cast<size_t>(s[i + 1] - 'A')];
        int r1 = p1 / 5, c1 = p1 % 5;
        int r2 = p2 / 5, c2 = p2 % 5;
        if (r1 == r2) {
            c1 = (c1 + 4) % 5;
            c2 = (c2 + 4) % 5;
        } else if (c1 == c2) {
            r1 = (r1 + 4) % 5;
            r2 = (r2 + 4) % 5;
        } else {
            std::swap(c1, c2);
        }
        res.push_back(g.cell[static_cast<size_t>(r1 * 5 + c1)]);
        res.push_back(g.cell[static_cast<size_t>(r2 * 5 + c2)]);
    }

    // 去掉编码期补的 X：只有当解出的串长度为奇数时才必定是末尾填充
    // （编码先按同对插 X，再对奇数长度补一个 X）。长度为偶数时末尾的 X
    // 无法与明文里的 X 区分，保留不动 —— 见最终说明中的有损性取舍。
    if (!res.empty() && res.back() == 'X' && res.size() % 2 == 1) {
        res.pop_back();
    }
    out.assign(res.begin(), res.end());
}

// ----- Bifid：Polybius 坐标行列分离 -----
void BuildPolybius5(const std::string& key, std::array<char, 25>& sq) {
    std::array<bool, 26> used{};
    used.fill(false);
    std::string all = key + "ABCDEFGHIKLMNOPQRSTUVWXYZ";   // 池中无 J
    size_t      n   = 0;
    for (char raw : all) {
        int idx = LetterIdx(static_cast<uint8_t>(raw));
        if (idx < 0) continue;
        if (idx == 9) idx = 8;
        if (used[static_cast<size_t>(idx)]) continue;
        used[static_cast<size_t>(idx)] = true;
        // 方阵里存的是「字母表下标」（0..25，J 已并入 I=8），
        // 这样 pos[字母表下标] 可以直接查到格号，不受 J 被剔除的错位影响。
        sq[n++] = static_cast<char>(idx);
    }
    Require(n == 25, "内部错误：Polybius 方阵不足 25 格");
}

// 字母表下标 -> 坐标值 r*5+c
void PolybiusIndexOf(const std::array<char, 25>& sq, std::array<int, 26>& pos) {
    pos.fill(0);
    for (size_t i = 0; i < 25; ++i) {
        pos[static_cast<size_t>(sq[i])] = static_cast<int>(i);
    }
    pos[9] = pos[8];   // J 同 I
}

void BifidCore(const Bytes& in, const Params& p, bool decrypt, Bytes& out) {
    (void)decrypt;   // Bifid 自逆：加密与解密是同一个变换
    std::array<char, 25> sq{};
    std::array<int, 26>  pos{};
    BuildPolybius5(p.Get("key", std::string()), sq);
    PolybiusIndexOf(sq, pos);

    int period = p.GetInt("period", 0);
    Require(period >= 0, "参数 period 不能为负数");

    // 骨架：记录每个字母的原始大小写，非字母位置按 keep 处理
    std::vector<int> vals;      // 抽出的字母 0..25（J 已并入 I）
    std::vector<int> upperFlag; // 对应字母是否原本大写
    for (uint8_t c : in) {
        int idx = LetterIdx(c);
        if (idx < 0) continue;
        if (idx == 9) idx = 8;
        vals.push_back(idx);
        upperFlag.push_back(c <= 'Z' ? 1 : 0);
    }

    bool keep = KeepFlag(p) != 0;
    out.clear();
    if (vals.empty()) {
        if (keep) {
            for (uint8_t c : in) {
                if (LetterIdx(c) < 0) out.push_back(c);
            }
        }
        return;
    }

    size_t block = (period > 0) ? static_cast<size_t>(period) : vals.size();
    if (block == 0) block = vals.size();

    std::vector<int> res;
    res.reserve(vals.size());
    for (size_t s = 0; s < vals.size(); s += block) {
        size_t e = std::min(s + block, vals.size());
        size_t m = e - s;

        // 先把这一组的字母都换成格号，并把格号摊成数字流 (r0,c0,r1,c1,...)
        std::vector<int> digits;
        digits.reserve(m * 2);
        for (size_t i = 0; i < m; ++i) {
            int v = pos[static_cast<size_t>(vals[s + i])];   // 格号 0..24
            digits.push_back(v / 5);                         // 行
            digits.push_back(v % 5);                         // 列
        }

        // 编码：行号连排在前、列号连排在后，再相邻两位成对取格号。
        //        flat = (r0..r_{m-1}, c0..c_{m-1})，取 (flat[2i], flat[2i+1])
        // 解码：是上一步的逆 —— 把数字流前 m 个当行、后 m 个当列再配对。
        //        取 (digits[i], digits[m+i])
        std::vector<int> cells(m, 0);
        if (!decrypt) {
            std::vector<int> ordered(m * 2, 0);
            for (size_t i = 0; i < m; ++i) {
                ordered[i]     = digits[2 * i];       // 行号全部在前
                ordered[m + i] = digits[2 * i + 1];   // 列号全部在后
            }
            for (size_t i = 0; i < m; ++i) {
                cells[i] = ordered[2 * i] * 5 + ordered[2 * i + 1];
            }
        } else {
            for (size_t i = 0; i < m; ++i) {
                cells[i] = digits[i] * 5 + digits[m + i];
            }
        }
        for (size_t i = 0; i < m; ++i) {
            res.push_back(sq[static_cast<size_t>(cells[i])]);   // 格号 -> 字母表下标
        }
    }
    Require(res.size() == vals.size(), "内部错误：Bifid 输出长度不符");

    size_t k = 0;
    for (uint8_t c : in) {
        if (LetterIdx(c) < 0) {
            if (keep) out.push_back(c);
            continue;
        }
        out.push_back(LetterFrom(res[k], upperFlag[k] != 0));
        ++k;
    }
}

void BifidEnc(const Bytes& in, const Params& p, Bytes& out) { BifidCore(in, p, false, out); }
void BifidDec(const Bytes& in, const Params& p, Bytes& out) { BifidCore(in, p, true, out); }

// ----- Hill 2x2 -----
struct HillKey {
    int m[4]{};     // [0]=a [1]=b [2]=c [3]=d
    int inv[4]{};   // 逆矩阵
};

void HillPrepare(const Params& p, HillKey& k) {
    std::vector<int> vals = ParseIntList(p.RequireStr("key"));
    Require(vals.size() == 4, "Hill 的 key 必须是 4 个整数，例如 key=3,3,2,5");
    for (int i = 0; i < 4; ++i) {
        k.m[i] = ((vals[static_cast<size_t>(i)] % 26) + 26) % 26;
    }
    int det    = ((k.m[0] * k.m[3] - k.m[1] * k.m[2]) % 26 + 26) % 26;
    int detInv = ModInverse(det, 26);
    Require(detInv >= 0, "Hill 密钥矩阵的行列式与 26 不互质（gcd(det,26)!=1），无法求逆");

    k.inv[0] = (detInv * k.m[3]) % 26;
    k.inv[1] = (detInv * ((-k.m[1] % 26) + 26)) % 26;
    k.inv[2] = (detInv * ((-k.m[2] % 26) + 26)) % 26;
    k.inv[3] = (detInv * k.m[0]) % 26;
}

void HillCore(const Bytes& in, const Params& p, bool decrypt, Bytes& out) {
    HillKey k;
    HillPrepare(p, k);

    // 抽出字母与大小写，非字母位置按 keep 保留
    std::vector<int> vals, upperFlag;
    for (uint8_t c : in) {
        int idx = LetterIdx(c);
        if (idx < 0) continue;
        vals.push_back(idx);
        upperFlag.push_back(c <= 'Z' ? 1 : 0);
    }

    bool keep = KeepFlag(p) != 0;
    out.clear();
    if (vals.empty()) {
        if (keep) {
            for (uint8_t c : in) {
                if (LetterIdx(c) < 0) out.push_back(c);
            }
        }
        return;
    }

    // 补位到偶数长度（用 X）。补出来的这一位会一起参与矩阵运算，
    // 因此加密结果的字母数 = 输入字母数（奇数时自动多出一个 X）。
    size_t n = vals.size();
    if (n % 2 == 1) {
        vals.push_back(23);
        upperFlag.push_back(1);
    }

    size_t           total = vals.size();   // 含补位，必为偶数
    std::vector<int> res(total, 0);
    for (size_t i = 0; i + 1 < total; i += 2) {
        int x1 = vals[i];
        int x2 = vals[i + 1];
        if (!decrypt) {
            res[i]     = ((k.m[0] * x1 + k.m[1] * x2) % 26 + 26) % 26;
            res[i + 1] = ((k.m[2] * x1 + k.m[3] * x2) % 26 + 26) % 26;
        } else {
            res[i]     = ((k.inv[0] * x1 + k.inv[1] * x2) % 26 + 26) % 26;
            res[i + 1] = ((k.inv[2] * x1 + k.inv[3] * x2) % 26 + 26) % 26;
        }
    }

    // 解密时去掉编码期补的那个 X：
    //   加密只对「字母数为奇数」的输入补一个 X，因此解密结果长度为偶数时
    //   末位那个 X 必定是填充。
    //   （明文本身长度为偶数且以 X 结尾时无法与填充区分，属有损处理。）
    size_t resLen = res.size();
    if (decrypt && resLen % 2 == 0 && res[resLen - 1] == 23) --resLen;

    // 回填：把变换结果按原输入的非字母骨架放回去。
    // 加密时结果比槽位多一个（补位那一位），循环结束后补上；
    // 解密时多出的那一位按 resLen 截断，不会输出。
    size_t k2 = 0;
    for (uint8_t c : in) {
        if (LetterIdx(c) < 0) {
            if (keep) out.push_back(c);
            continue;
        }
        out.push_back(LetterFrom(res[k2], upperFlag[k2] != 0));
        ++k2;
    }
    while (k2 < resLen) {
        out.push_back(LetterFrom(res[k2], upperFlag[k2] != 0));
        ++k2;
    }
}

void HillEnc(const Bytes& in, const Params& p, Bytes& out) { HillCore(in, p, false, out); }
void HillDec(const Bytes& in, const Params& p, Bytes& out) { HillCore(in, p, true, out); }

// ===========================================================================
// 七、组 5：XOR 与异或类
// ===========================================================================

void XorCore(const Bytes& in, const Bytes& key, Bytes& out) {
    Require(!key.empty(), "密钥不能为空");
    out.clear();
    out.resize(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        out[i] = static_cast<uint8_t>(in[i] ^ key[i % key.size()]);
    }
}

void XorEnc(const Bytes& in, const Params& p, Bytes& out) { XorCore(in, p.RequireKey(), out); }

// 单字节密钥：byte=N 优先，其次 key=N（0..255）或单字符 key
uint8_t ResolveSingleByte(const Params& p) {
    if (p.Has("byte")) {
        int v = p.RequireInt("byte");
        Require(v >= 0 && v <= 255, "参数 byte 必须在 0..255 之间");
        return static_cast<uint8_t>(v);
    }
    Bytes k = p.RequireKey();
    if (k.size() == 1) return k[0];
    // 多字符时尝试按十进制整数解释
    std::string s(k.begin(), k.end());
    int         v = ParseInt(s, "key");
    Require(v >= 0 && v <= 255, "单字节异或的 key 必须在 0..255 之间（或用 byte=65）");
    return static_cast<uint8_t>(v);
}

void XorSingleEnc(const Bytes& in, const Params& p, Bytes& out) {
    uint8_t b = ResolveSingleByte(p);
    out.clear();
    out.resize(in.size());
    for (size_t i = 0; i < in.size(); ++i) out[i] = static_cast<uint8_t>(in[i] ^ b);
}

// 英文单字母频率（百分比），用于爆破打分
double EnglishFreq(size_t i) {
    static const double kFreq[26] = {
        8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41,
        6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07};
    return kFreq[i];
}

// 打分：可打印占比 + 字母频率贴合度（卡方） + 常见二元组加分
double ScorePlaintext(const Bytes& b) {
    if (b.empty()) return -1e9;
    size_t printable = 0, letter = 0, space = 0, other = 0;
    for (uint8_t c : b) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            ++space;
        } else if (c >= 32 && c <= 126) {
            ++printable;
            if (IsAlpha(c)) ++letter;
        } else {
            ++other;
        }
    }
    double n     = static_cast<double>(b.size());
    double score = 100.0 * (static_cast<double>(printable) + static_cast<double>(space)) / n;
    score -= 300.0 * static_cast<double>(other) / n;
    score += 40.0 * static_cast<double>(space) / n;

    double chi = 400.0;
    if (letter > 0) {
        std::array<size_t, 26> cnt{};
        cnt.fill(0);
        for (uint8_t c : b) {
            if (!IsAlpha(c)) continue;
            int idx = LetterIdx(c);
            cnt[static_cast<size_t>(idx)]++;
        }
        chi = 0.0;
        for (size_t i = 0; i < 26; ++i) {
            double obs = 100.0 * static_cast<double>(cnt[i]) / static_cast<double>(letter);
            double exp = EnglishFreq(i);
            double d   = obs - exp;
            chi += d * d / (exp > 0.0 ? exp : 0.01);
        }
    }
    score += std::max(0.0, 60.0 - chi * 0.12);

    int bonus = 0;
    for (size_t i = 0; i + 1 < b.size(); ++i) {
        unsigned char x = b[i], y = b[i + 1];
        if (x >= 'A' && x <= 'Z') x = static_cast<unsigned char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<unsigned char>(y - 'A' + 'a');
        if ((x == 't' && y == 'h') || (x == 'h' && y == 'e') || (x == 'i' && y == 'n') ||
            (x == 'e' && y == 'r') || (x == 'a' && y == 'n') || (x == 'r' && y == 'e') ||
            (x == 'o' && y == 'n') || (x == 'e' && y == ' ') || (x == ' ' && y == 't') ||
            (x == 't' && y == ' ')) {
            ++bonus;
        }
    }
    score += 4.0 * static_cast<double>(bonus);
    return score;
}

// 可打印预览（不可打印字节显示为 '.'，超长截断）
std::string PreviewText(const Bytes& b, size_t maxLen) {
    std::string s;
    s.reserve(std::min(maxLen, b.size()));
    for (uint8_t c : b) {
        if (s.size() >= maxLen) break;
        s.push_back((c >= 32 && c <= 126) ? static_cast<char>(c) : '.');
    }
    return s;
}

// 单字节异或爆破（不可逆算法，注册为 enc + dec=nullptr）
void XorBruteEnc(const Bytes& in, const Params& p, Bytes& out) {
    int top = p.GetInt("top", 10);
    int lo  = p.GetInt("min", 0);
    int hi  = p.GetInt("max", 255);
    if (top <= 0) top = 1;
    Require(lo >= 0 && lo <= 255, "参数 min 必须在 0..255 之间");
    Require(hi >= 0 && hi <= 255, "参数 max 必须在 0..255 之间");
    Require(lo <= hi, "参数 min 不能大于 max");

    struct Cand {
        int         key;
        double      score;
        std::string preview;
        int         order;
    };
    std::vector<Cand> cands;
    Bytes             buf;
    int               order = 0;
    for (int k = lo; k <= hi; ++k) {
        buf.resize(in.size());
        for (size_t i = 0; i < in.size(); ++i) {
            buf[i] = static_cast<uint8_t>(in[i] ^ static_cast<uint8_t>(k));
        }
        cands.push_back(Cand{k, ScorePlaintext(buf), PreviewText(buf, 60), order++});
    }
    std::stable_sort(cands.begin(), cands.end(),
                     [](const Cand& a, const Cand& b) { return a.score > b.score; });

    out.clear();
    size_t limit = std::min<size_t>(static_cast<size_t>(top), cands.size());
    for (size_t i = 0; i < limit; ++i) {
        std::string line = Format("key=0x%02x(%d) score=%.2f : %s\n", cands[i].key, cands[i].key,
                                  cands[i].score, cands[i].preview.c_str());
        out.insert(out.end(), line.begin(), line.end());
    }
}

// 已知明文（crib）推密钥
void XorKnownPlaintextEnc(const Bytes& in, const Params& p, Bytes& out) {
    std::string crib = p.RequireStr("crib");
    Require(!crib.empty(), "参数 crib 不能为空");
    Bytes cb(crib.begin(), crib.end());

    out.clear();
    if (in.empty()) return;

    Bytes  key;
    size_t lim = std::min(in.size(), cb.size());
    key.reserve(lim);
    for (size_t i = 0; i < lim; ++i) {
        key.push_back(static_cast<uint8_t>(in[i] ^ cb[i]));
    }
    // 若密钥明显是重复的短周期，收缩到最小周期
    for (size_t per = 1; per * 2 <= key.size(); ++per) {
        bool ok = true;
        for (size_t i = per; i < key.size(); ++i) {
            if (key[i] != key[i - per]) {
                ok = false;
                break;
            }
        }
        if (ok) {
            key.resize(per);
            break;
        }
    }

    std::string head = "key(hex)=" + HexEncode(key) + "\n";
    out.insert(out.end(), head.begin(), head.end());

    Bytes full;
    full.resize(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        full[i] = static_cast<uint8_t>(in[i] ^ key[i % key.size()]);
    }
    std::string body = "plaintext=" + PreviewText(full, 200) + "\n";
    out.insert(out.end(), body.begin(), body.end());
}

// ===========================================================================
// 八、组 6：其他（Enigma / RC4 / Vernam）
// ===========================================================================

// Enigma I 的 I..V 转子：走线 + 缺口字母
struct EnigmaRotor {
    const char* wiring;
    char        notch;
};

const EnigmaRotor kEnigmaRotors[5] = {
    {"EKMFLGDQVZNTOWYHXUSPAIBRCJ", 'Q'},   // I
    {"AJDKSIRUXBLHWTMCQGZNPYFVOE", 'E'},   // II
    {"BDFHJLCPRTXVZNYEIWGAKMUSQO", 'V'},   // III
    {"ESOVPZJAYQUIRHXLNFTGKDCMWB", 'J'},   // IV
    {"VZBRGITYUPSDNHLXAWMJQOFECK", 'Z'},   // V
};

const char* const kEnigmaReflectorB = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

// setting：当前窗口字母；ring：环设置（都是 0..25）
inline int EnigmaForward(int c, const EnigmaRotor& rot, int setting, int ring) {
    int off = ((setting - ring) % 26 + 26) % 26;
    int e   = ((c + off) % 26 + 26) % 26;
    int w   = rot.wiring[e] - 'A';
    return ((w - off) % 26 + 26) % 26;
}
inline int EnigmaBackward(int c, const EnigmaRotor& rot, int setting, int ring) {
    int off = ((setting - ring) % 26 + 26) % 26;
    int w   = ((c + off) % 26 + 26) % 26;
    for (int e = 0; e < 26; ++e) {
        if (rot.wiring[e] - 'A' == w) return ((e - off) % 26 + 26) % 26;
    }
    return c;
}

// 转子串 "123"：三个数字，从左转子到右转子
std::vector<int> ParseEnigmaRotors(const std::string& s) {
    std::vector<int> v;
    for (char c : s) {
        if (c >= '1' && c <= '5') {
            v.push_back(c - '1');
        } else if (c == ' ' || c == ',' || c == '-' || c == '_') {
            continue;
        } else {
            throw Error("Enigma 的 rotors 参数只能是 1..5 组成的数字串，例如 123");
        }
    }
    Require(v.size() == 3, "Enigma 的 rotors 必须指定 3 个转子（本项目实现三转子机）");
    Require(v[0] != v[1] && v[1] != v[2] && v[0] != v[2], "Enigma 的三个转子不能重复");
    return v;
}

// "AAA" 这类 3 字母串
std::array<int, 3> ParseEnigmaLetters(const std::string& s, const std::string& what) {
    std::vector<int> v;
    for (char c : s) {
        int idx = LetterIdx(static_cast<uint8_t>(c));
        if (idx >= 0) v.push_back(idx);
    }
    Require(v.size() == 3, "Enigma 的 " + what + " 必须是 3 个字母，例如 AAA");
    return {v[0], v[1], v[2]};
}

// 插线板 "A:Y B:Z" / "AY BZ" / "AYBZ"，也接受 "AA:BB"
std::array<int, 26> ParseEnigmaPlug(const std::string& s) {
    std::array<int, 26> m{};
    for (int i = 0; i < 26; ++i) m[static_cast<size_t>(i)] = i;

    std::vector<int> letters;
    for (char c : s) {
        int idx = LetterIdx(static_cast<uint8_t>(c));
        if (idx >= 0) letters.push_back(idx);
    }
    Require(letters.size() % 2 == 0, "Enigma 的 plug 参数必须成对出现，例如 A:Y B:Z");
    for (size_t i = 0; i + 1 < letters.size(); i += 2) {
        int a = letters[i], b = letters[i + 1];
        Require(a != b, "Enigma 的 plug 不能把字母连到它自己");
        Require(m[static_cast<size_t>(a)] == a && m[static_cast<size_t>(b)] == b,
                "Enigma 的 plug 中同一个字母只能出现一次");
        m[static_cast<size_t>(a)] = b;
        m[static_cast<size_t>(b)] = a;
    }
    return m;
}

void EnigmaCore(const Bytes& in, const Params& p, Bytes& out) {
    std::vector<int>    rotSel = ParseEnigmaRotors(p.Get("rotors", "123"));
    std::array<int, 3>  pos    = ParseEnigmaLetters(p.Get("positions", "AAA"), "positions");
    std::array<int, 3>  ring   = ParseEnigmaLetters(p.Get("rings", "AAA"), "rings");
    std::array<int, 26> plug   = ParseEnigmaPlug(p.Get("plug", ""));

    const EnigmaRotor& R0 = kEnigmaRotors[static_cast<size_t>(rotSel[0])];
    const EnigmaRotor& R1 = kEnigmaRotors[static_cast<size_t>(rotSel[1])];
    const EnigmaRotor& R2 = kEnigmaRotors[static_cast<size_t>(rotSel[2])];

    out.clear();
    out.reserve(in.size());
    for (uint8_t ch : in) {
        int idx = LetterIdx(ch);
        if (idx < 0) {
            out.push_back(ch);   // 非字母原样输出，且不驱动转子
            continue;
        }

        // 步进（含中转子在缺口位带动左转子的双步进）
        if (pos[1] == R1.notch - 'A') {
            pos[0] = (pos[0] + 1) % 26;
            pos[1] = (pos[1] + 1) % 26;
        } else if (pos[2] == R2.notch - 'A') {
            pos[1] = (pos[1] + 1) % 26;
        }
        pos[2] = (pos[2] + 1) % 26;

        int c = plug[static_cast<size_t>(idx)];
        c     = EnigmaForward(c, R2, pos[2], ring[2]);
        c     = EnigmaForward(c, R1, pos[1], ring[1]);
        c     = EnigmaForward(c, R0, pos[0], ring[0]);
        c     = kEnigmaReflectorB[c] - 'A';
        c     = EnigmaBackward(c, R0, pos[0], ring[0]);
        c     = EnigmaBackward(c, R1, pos[1], ring[1]);
        c     = EnigmaBackward(c, R2, pos[2], ring[2]);
        out.push_back(static_cast<uint8_t>('A' + plug[static_cast<size_t>(c)]));
    }
}

// ---- RC4（二进制安全，加解密同一函数） ----
void Rc4Core(const Bytes& in, const Bytes& key, Bytes& out) {
    Require(!key.empty(), "RC4 的 key 不能为空");

    std::array<uint8_t, 256> s{};
    for (int i = 0; i < 256; ++i) s[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + s[static_cast<size_t>(i)] + key[static_cast<size_t>(i) % key.size()]) & 0xFF;
        std::swap(s[static_cast<size_t>(i)], s[static_cast<size_t>(j)]);
    }

    out.clear();
    out.resize(in.size());
    int i2 = 0;
    j      = 0;
    for (size_t n = 0; n < in.size(); ++n) {
        i2 = (i2 + 1) & 0xFF;
        j  = (j + s[static_cast<size_t>(i2)]) & 0xFF;
        std::swap(s[static_cast<size_t>(i2)], s[static_cast<size_t>(j)]);
        uint8_t ks =
            s[static_cast<size_t>((s[static_cast<size_t>(i2)] + s[static_cast<size_t>(j)]) & 0xFF)];
        out[n] = static_cast<uint8_t>(in[n] ^ ks);
    }
}

// RC4 的注册入口适配（CodecFn 签名带 Params）
void Rc4Codec(const Bytes& in, const Params& p, Bytes& out) { Rc4Core(in, p.RequireKey(), out); }

// ---- Vernam / OTP：key_hex 长度必须 >= 输入长度 ----
void VernamCore(const Bytes& in, const Params& p, Bytes& out) {
    Bytes key = p.RequireKey();
    Require(key.size() >= in.size(),
            Format("Vernam/OTP 的密钥长度不足：需要 %zu 字节，实际 %zu 字节", in.size(),
                   key.size()));
    out.clear();
    out.resize(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        out[i] = static_cast<uint8_t>(in[i] ^ key[i]);
    }
}

}  // namespace

// ===========================================================================
// 九、注册
// ===========================================================================
void RegisterCipher(Registry& r) {
    // ---------------- 组 1：移位 / 替换 ----------------
    r.Add("caesar", "Cipher", "凯撒位移：只移动字母，保持大小写与非字母", true, true, CaesarEnc,
          CaesarDec, {"caesarcipher"});
    r.Add("rot-n", "Cipher", "通用 ROT：字母表内循环位移 shift 位", true, true, RotNEnc, RotNDec,
          {"rotn"});
    r.Add("rot13", "Cipher", "ROT13：字母移 13 位，自逆", true, false, Rot13Enc, Rot13Enc);
    r.Add("rot5", "Cipher", "ROT5：数字 0-9 移 5 位，自逆", true, false, Rot5Enc, Rot5Enc);
    r.Add("rot18", "Cipher", "ROT18：字母 ROT13 + 数字 ROT5，自逆", true, false, Rot18Enc,
          Rot18Enc);
    r.Add("rot47", "Cipher", "ROT47：可打印 ASCII(33-126) 移 47 位，自逆", true, false, Rot47Enc,
          Rot47Enc);
    r.Add("atbash", "Cipher", "Atbash：字母表反转（A<->Z），自逆", true, false, AtbashEnc,
          AtbashEnc);
    r.Add("substitution", "Cipher", "单表替换：key 为 26 个字母的密文字母表", true, true,
          SubstitutionEnc, SubstitutionDec, {"monoalphabetic", "simple-sub"});
    r.Add("affine", "Cipher", "仿射密码 E(x)=(a*x+b) mod 26，要求 gcd(a,26)=1", true, true,
          AffineEnc, AffineDec, {"affinecipher"});

    // ---------------- 组 2：多表替换 ----------------
    r.Add("vigenere", "Cipher", "维吉尼亚密码：密钥循环做字母位移", true, true, VigenereEnc,
          VigenereDec, {"vigenerecipher"});
    r.Add("beaufort", "Cipher", "Beaufort 变体：C=(K-P) mod 26，自逆", true, true, BeaufortEnc,
          BeaufortEnc);
    r.Add("variant-beaufort", "Cipher", "变体 Beaufort：C=(P-K) mod 26", true, true,
          VariantBeaufortEnc, VigenereEnc, {"variantbeaufort"});
    r.Add("autokey", "Cipher", "自动密钥：密钥用完后接明文自身", true, true, AutokeyEnc,
          AutokeyDec, {"autokeycipher"});
    r.Add("porta", "Cipher", "Porta 密码：13 组对换表，自逆", true, true, PortaEnc, PortaEnc,
          {"portacipher"});
    r.Add("gronsfeld", "Cipher", "Gronsfeld：key 为数字串，按位做数字位移", true, true,
          GronsfeldEnc, GronsfeldDec);
    r.Add("running-key", "Cipher", "Running Key：key 为与明文等长的长文本", true, true,
          RunningKeyEnc, RunningKeyDec, {"runningkey"});

    // ---------------- 组 3：置换 ----------------
    r.Add("railfence", "Cipher", "栅栏密码：按 W 型轨迹读取，支持起始偏移", true, true,
          RailFenceEnc, RailFenceDec, {"rail-fence", "zigzag"});
    r.Add("scytale", "Cipher", "斯巴达棒：按 n 列写出再按列读", true, true, ScytaleEnc,
          ScytaleDec);
    r.Add("columnar", "Cipher", "列置换：按密钥词字母序决定列的读取顺序", true, true,
          ColumnarEnc, ColumnarDec, {"columnartransposition", "ct"});
    r.Add("reverse-block", "Cipher", "按固定块大小反转块内字节顺序", true, true, ReverseBlockEnc,
          ReverseBlockEnc, {"blockrev"});

    // ---------------- 组 4：矩阵 / 多字母 ----------------
    r.Add("playfair", "Cipher", "Playfair 密码：5x5 方阵（I/J 合并），按对处理", true, true,
          PlayfairEnc, PlayfairDec);
    r.Add("bifid", "Cipher", "Bifid 密码：Polybius 坐标行列分离，可指定 period", true, false,
          BifidEnc, BifidDec);
    r.Add("hill", "Cipher", "Hill 密码 2x2：key 为 4 个整数，如 3,3,2,5", true, true, HillEnc,
          HillDec, {"hillcipher"});

    // ---------------- 组 5：XOR ----------------
    r.Add("xor", "Cipher", "循环异或：key 或 key_hex，二进制安全", true, true, XorEnc, XorEnc);
    r.Add("xor-single", "Cipher", "单字节异或：key 为 1 字节或 byte=65", true, true, XorSingleEnc,
          XorSingleEnc, {"xor1"});
    r.Add("xor-brute", "Cipher", "单字节异或暴力枚举：按可打印占比+字母频率打分排序",
          false, false, XorBruteEnc, nullptr, {"single-byte-xor-brute"});
    r.Add("xor-known-plaintext", "Cipher", "已知明文（crib）推 XOR 密钥并输出明文预览",
          false, true, XorKnownPlaintextEnc, nullptr, {"xor-crib"});

    // ---------------- 组 6：其他 ----------------
    r.Add("enigma", "Cipher", "Enigma I 三转子机（I-V 转子 + 反射器 B + 插线板）", true, false,
          EnigmaCore, EnigmaCore);
    r.Add("rc4", "Cipher", "RC4 流密码：key 为密钥，二进制安全", true, true, Rc4Codec, Rc4Codec,
          {"arc4"});
    r.Add("vernam", "Cipher", "Vernam/OTP：逐字节异或，key_hex 长度需 >= 输入", true, true,
          VernamCore, VernamCore, {"otp"});
}

}  // namespace ctf
