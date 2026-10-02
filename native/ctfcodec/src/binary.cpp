// binary.cpp —— 二进制表示、数值进制与位操作
//
// 与 Base 家族的区别：这里处理的是「字节 <-> 数字/位」的表示转换，
// 而不是把字节流当作整体做进制编码。
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#include "common.h"
#include "util.h"

namespace ctf {
namespace {

// ===========================================================================
// 通用工具
// ===========================================================================

// 按「空白 / 逗号 / 分号」切分 token（解析数字序列时用）
std::vector<std::string> Tokens(const std::string& s) {
    std::vector<std::string> out;
    std::string              cur;
    for (char c : s) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == ';') {
            if (!cur.empty()) {
                out.push_back(cur);
                cur.clear();
            }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// 去掉所有空白与逗号
std::string StripSeps(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == ';' || c == '_') {
            continue;
        }
        out.push_back(c);
    }
    return out;
}

// 解析一个固定进制的数字串成字节（每 width 个数字一个字节）
Bytes DecodeFixedWidth(const std::string& body, int base, int width, const char* algoName) {
    Bytes out;
    if (body.empty()) return out;
    if (body.size() % static_cast<size_t>(width) != 0) {
        throw Error(Format("%s：数字串长度 %zu 不是 %d 的整数倍，无法按字节切分", algoName,
                           body.size(), width));
    }
    for (size_t i = 0; i < body.size(); i += static_cast<size_t>(width)) {
        unsigned v = 0;
        for (int j = 0; j < width; ++j) {
            char c = body[i + static_cast<size_t>(j)];
            int  d;
            if (c >= '0' && c <= '9') {
                d = c - '0';
            } else if (base == 16 && c >= 'a' && c <= 'f') {
                d = c - 'a' + 10;
            } else if (base == 16 && c >= 'A' && c <= 'F') {
                d = c - 'A' + 10;
            } else {
                throw Error(Format("%s：出现非法字符 '%c'", algoName, c));
            }
            if (d >= base) {
                throw Error(Format("%s：字符 '%c' 不是 %d 进制的合法数字", algoName, c, base));
            }
            v = v * static_cast<unsigned>(base) + static_cast<unsigned>(d);
        }
        if (v > 255) {
            throw Error(Format("%s：数值 %u 超出一个字节（0-255）", algoName, v));
        }
        out.push_back(static_cast<uint8_t>(v));
    }
    return out;
}

// 把输入解析成字节序列：先按 token 解析（每个 token 一个字节），
// 若只有一个 token 再按固定宽度切分。这样 "101 102" 和 "101102" 都能解。
Bytes DecodeNumberSequence(const Bytes& in, int base, int width, const char* algoName) {
    std::string              s = Str(in);
    std::vector<std::string> toks = Tokens(s);

    // 过滤掉纯空 token
    std::vector<std::string> real;
    for (auto& t : toks) {
        if (!t.empty()) real.push_back(t);
    }
    if (real.empty()) return Bytes();

    if (real.size() > 1) {
        Bytes out;
        for (auto& t : real) {
            std::string body = t;
            // 容忍 0x / 0o / 0b 前缀
            if (body.size() > 2 && body[0] == '0' &&
                (body[1] == 'x' || body[1] == 'X' || body[1] == 'o' || body[1] == 'O' ||
                 body[1] == 'b' || body[1] == 'B')) {
                body = body.substr(2);
            }
            Bytes one = DecodeFixedWidth(body, base, static_cast<int>(body.size()), algoName);
            if (one.size() != 1) {
                throw Error(Format("%s：分段 '%s' 解析出的字节数不是 1", algoName, t.c_str()));
            }
            out.push_back(one[0]);
        }
        return out;
    }

    std::string body = real[0];
    if (body.size() > 2 && body[0] == '0' &&
        (body[1] == 'x' || body[1] == 'X' || body[1] == 'o' || body[1] == 'O' || body[1] == 'b' ||
         body[1] == 'B')) {
        body = body.substr(2);
    }
    return DecodeFixedWidth(body, base, width, algoName);
}

// ===========================================================================
// binary / octal / decimal
// ===========================================================================
void BinaryEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    int         bits = p.GetInt("bits", 8);   // 保留参数位，当前只支持 8
    std::string sep  = p.Get("sep", " ");
    if (bits != 8) throw Error("binary：目前只支持 bits=8");

    std::string s;
    for (size_t i = 0; i < in.size(); ++i) {
        if (i) s += sep;
        for (int b = 7; b >= 0; --b) s += ((in[i] >> b) & 1) ? '1' : '0';
    }
    out = ToBytes(s);
}

void BinaryDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    std::string body = StripSeps(Str(in));
    if (body.empty()) return;

    // 允许含 0b 前缀
    if (body.size() > 2 && body[0] == '0' && (body[1] == 'b' || body[1] == 'B')) body = body.substr(2);

    for (char c : body) {
        if (c != '0' && c != '1') throw Error(Format("binary：出现非 0/1 字符 '%c'", c));
    }

    // 长度不是 8 的倍数时，按 7 位 ASCII 尝试（CTF 里很常见）
    if (body.size() % 8 != 0 && body.size() % 7 == 0) {
        for (size_t i = 0; i < body.size(); i += 7) {
            unsigned v = 0;
            for (int j = 0; j < 7; ++j) v = (v << 1) | static_cast<unsigned>(body[i + j] - '0');
            out.push_back(static_cast<uint8_t>(v));
        }
        return;
    }
    out = DecodeFixedWidth(body, 2, 8, "binary");
}

void OctalEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    std::string sep    = p.Get("sep", " ");
    bool        prefix = p.GetInt("prefix", 0) != 0;
    std::string s;
    for (size_t i = 0; i < in.size(); ++i) {
        if (i) s += sep;
        if (prefix) s += "0o";
        s += Format("%03o", in[i]);
    }
    out = ToBytes(s);
}

void OctalDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    std::string s = Str(in);
    // 去掉 0o / 0O 前缀
    std::string cleaned;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '0' && i + 1 < s.size() && (s[i + 1] == 'o' || s[i + 1] == 'O')) {
            ++i;
            continue;
        }
        cleaned.push_back(s[i]);
    }
    out = DecodeNumberSequence(ToBytes(cleaned), 8, 3, "octal");
}

void DecimalEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    std::string sep = p.Get("sep", " ");
    std::string s;
    for (size_t i = 0; i < in.size(); ++i) {
        if (i) s += sep;
        s += Format("%u", static_cast<unsigned>(in[i]));
    }
    out = ToBytes(s);
}

void DecimalDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    std::vector<std::string> toks = Tokens(Str(in));
    for (auto& t : toks) {
        if (t.empty()) continue;
        int v = ParseInt(t, "decimal");
        if (v < 0 || v > 255) throw Error(Format("decimal：数值 %d 超出一个字节（0-255）", v));
        out.push_back(static_cast<uint8_t>(v));
    }
}

// ===========================================================================
// hex-bytes：\x41\x42 形式
// ===========================================================================
void HexBytesEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    bool        upper  = p.GetInt("upper", 0) != 0;
    std::string prefix = p.Get("prefix", "\\x");
    std::string sep    = p.Get("sep", "");
    static const char* lo = "0123456789abcdef";
    static const char* up = "0123456789ABCDEF";
    const char*        tb = upper ? up : lo;

    std::string s;
    for (size_t i = 0; i < in.size(); ++i) {
        if (i) s += sep;
        s += prefix;
        s.push_back(tb[in[i] >> 4]);
        s.push_back(tb[in[i] & 0x0F]);
    }
    out = ToBytes(s);
}

void HexBytesDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    // util.h 的 HexDecode 已经容忍 \x / 0x / % / 空白 / 逗号 / 冒号
    out = HexDecode(Str(in));
}

// ===========================================================================
// base-convert：任意进制（大数）
// ===========================================================================
void BaseConvertCore(const Bytes& in, const Params& p, Bytes& out, bool encode) {
    out.clear();
    if (!encode) {
        // 解码方向同样支持 from/to，语义就是「反过来转」
    }
    int from = p.GetInt("from", 0);
    int to   = p.GetInt("to", 0);
    if (from == 0 || to == 0) throw Error("base-convert：必须提供 from 与 to 参数，如 from=10;to=16");
    if (from < 2 || from > 64 || to < 2 || to > 64) {
        throw Error("base-convert：进制必须在 2..64 之间");
    }

    std::string alphabet = p.Get("alphabet", "");
    if (alphabet.empty()) alphabet = kAlphaDigits62;
    if (static_cast<int>(alphabet.size()) < from || static_cast<int>(alphabet.size()) < to) {
        throw Error("base-convert：alphabet 长度不足以表示指定的进制");
    }

    std::string digits = Trim(Str(in));
    std::string result = BigIntBaseConvert(digits, from, to, alphabet);
    if (p.GetInt("upper", 0) != 0) result = ToUpper(result);
    out = ToBytes(result);
}

void BaseConvertEnc(const Bytes& in, const Params& p, Bytes& out) { BaseConvertCore(in, p, out, true); }

void BaseConvertDec(const Bytes& in, const Params& p, Bytes& out) {
    // 解码即把 from / to 互换
    Params q = p;
    int    from = p.GetInt("from", 0);
    int    to   = p.GetInt("to", 0);
    if (from && to) {
        q.Set("from", std::to_string(to));
        q.Set("to", std::to_string(from));
    }
    BaseConvertCore(in, q, out, false);
}

// ===========================================================================
// BCD（8421）
// ===========================================================================
void BcdEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    bool        packed = p.GetInt("packed", 1) != 0;
    std::string s      = Str(in);

    // 只保留十进制数字
    std::string digits;
    for (char c : s) {
        if (c >= '0' && c <= '9') {
            digits.push_back(c);
        } else if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == '-') {
            continue;
        } else {
            throw Error(Format("bcd：出现非十进制数字字符 '%c'", c));
        }
    }
    if (digits.empty()) return;

    if (!packed) {
        // 非紧缩：每个数字一个字节（低 4 位）
        for (char c : digits) out.push_back(static_cast<uint8_t>(c - '0'));
        return;
    }

    // 紧缩：两位数字一字节，奇数长度时前面补 0
    if (digits.size() % 2 != 0) digits = "0" + digits;
    for (size_t i = 0; i < digits.size(); i += 2) {
        uint8_t hi = static_cast<uint8_t>(digits[i] - '0');
        uint8_t lo = static_cast<uint8_t>(digits[i + 1] - '0');
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
}

void BcdDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    bool packed = p.GetInt("packed", 1) != 0;
    std::string s;
    if (packed) {
        for (uint8_t b : in) {
            uint8_t hi = static_cast<uint8_t>(b >> 4);
            uint8_t lo = static_cast<uint8_t>(b & 0x0F);
            if (hi > 9 || lo > 9) {
                throw Error(Format("bcd：字节 0x%02X 不是合法 BCD（半字节超出 0-9）", b));
            }
            s.push_back(static_cast<char>('0' + hi));
            s.push_back(static_cast<char>('0' + lo));
        }
    } else {
        for (uint8_t b : in) {
            if (b > 9) throw Error(Format("bcd：字节 %u 不是合法 BCD 数字", b));
            s.push_back(static_cast<char>('0' + b));
        }
    }
    out = ToBytes(s);
}

// ===========================================================================
// Gray 码
// ===========================================================================
void GrayEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out.reserve(in.size());
    for (uint8_t b : in) out.push_back(static_cast<uint8_t>(b ^ (b >> 1)));
}

void GrayDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out.reserve(in.size());
    for (uint8_t g : in) {
        uint8_t b = g;
        b ^= static_cast<uint8_t>(b >> 1);
        b ^= static_cast<uint8_t>(b >> 2);
        b ^= static_cast<uint8_t>(b >> 4);
        out.push_back(b);
    }
}

// ===========================================================================
// bits：连续位流
// ===========================================================================
void BitsEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    bool msb = p.GetInt("msb", 1) != 0;
    std::string s;
    for (uint8_t b : in) {
        for (int i = 0; i < 8; ++i) {
            int bit = msb ? ((b >> (7 - i)) & 1) : ((b >> i) & 1);
            s += bit ? '1' : '0';
        }
    }
    out = ToBytes(s);
}

void BitsDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    bool        msb  = p.GetInt("msb", 1) != 0;
    std::string body = StripSeps(Str(in));
    if (body.empty()) return;

    if (body.size() % 8 != 0) {
        // 补足到 8 的倍数（低位补 0），这样用户少打几位也能解
        while (body.size() % 8 != 0) body += '0';
    }
    for (char c : body) {
        if (c != '0' && c != '1') throw Error(Format("bits：出现非 0/1 字符 '%c'", c));
    }
    for (size_t i = 0; i < body.size(); i += 8) {
        uint8_t v = 0;
        for (int j = 0; j < 8; ++j) {
            int bit = body[i + static_cast<size_t>(j)] - '0';
            if (msb) {
                v = static_cast<uint8_t>((v << 1) | bit);
            } else {
                v = static_cast<uint8_t>(v | (bit << j));
            }
        }
        out.push_back(v);
    }
}

// ===========================================================================
// 字节序 / 位操作
// ===========================================================================
int BlockSize(const Params& p, const char* algo, int def) {
    int size = p.GetInt("size", def);
    if (size != 2 && size != 4 && size != 8) {
        throw Error(Format("%s：size 只能是 2 / 4 / 8（当前 %d）", algo, size));
    }
    return size;
}

void ByteSwap(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    int size = BlockSize(p, "byteswap", 4);
    // 最后一个不完整块原样保留
    size_t full = in.size() / static_cast<size_t>(size) * static_cast<size_t>(size);
    out.reserve(in.size());
    for (size_t i = 0; i < full; i += static_cast<size_t>(size)) {
        for (int j = size - 1; j >= 0; --j) out.push_back(in[i + static_cast<size_t>(j)]);
    }
    for (size_t i = full; i < in.size(); ++i) out.push_back(in[i]);
}

void BitReverse(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out.reserve(in.size());
    for (uint8_t b : in) {
        uint8_t r = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & (1u << i)) r = static_cast<uint8_t>(r | (1u << (7 - i)));
        }
        out.push_back(r);
    }
}

void NibbleSwap(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    out.reserve(in.size());
    for (uint8_t b : in) {
        out.push_back(static_cast<uint8_t>((b << 4) | (b >> 4)));
    }
}

// ===========================================================================
// 时间戳
// ===========================================================================
// Howard Hinnant 的 civil 算法：与 1970-01-01 的天数互转，跨编译器结果一致
int64_t DaysFromCivil(int y, unsigned m, unsigned d) {
    y -= (m <= 2) ? 1 : 0;
    const int64_t  era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153u * (m > 2 ? (m - 3u) : (m + 9u)) + 2u) / 5u + d - 1u;
    const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

void CivilFromDays(int64_t z, int& y, unsigned& m, unsigned& d) {
    z += 719468;
    const int64_t  era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
    const int64_t  yy  = static_cast<int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
    const unsigned mp  = (5u * doy + 2u) / 153u;
    d = doy - (153u * mp + 2u) / 5u + 1u;
    m = (mp < 10u) ? (mp + 3u) : (mp - 9u);
    y = static_cast<int>(yy + (m <= 2 ? 1 : 0));
}

// 本地时区相对 UTC 的偏移（秒），失败返回 0
int LocalOffsetSeconds() {
    // 用标准 C 的 localtime/gmtime：MSVC 与 MinGW 都可用，也避开了
    // localtime_r（MinGW 在严格 ANSI 模式下不声明）与 localtime_s 的平台差异。
    // 它们返回静态缓冲区，所以取出后立刻拷贝，不让第二次调用覆盖第一次的结果。
    std::time_t now = std::time(nullptr);
    std::tm*    ltp = std::localtime(&now);
    if (!ltp) return 0;
    std::tm lt = *ltp;
    std::tm* gtp = std::gmtime(&now);
    if (!gtp) return 0;
    std::tm gt = *gtp;

    int64_t lo = DaysFromCivil(lt.tm_year + 1900, static_cast<unsigned>(lt.tm_mon + 1),
                               static_cast<unsigned>(lt.tm_mday)) *
                     86400 +
                 lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec;
    int64_t go = DaysFromCivil(gt.tm_year + 1900, static_cast<unsigned>(gt.tm_mon + 1),
                               static_cast<unsigned>(gt.tm_mday)) *
                     86400 +
                 gt.tm_hour * 3600 + gt.tm_min * 60 + gt.tm_sec;
    return static_cast<int>(lo - go);
}

std::string FormatEpoch(int64_t epoch, const std::string& fmt) {
    int64_t days = epoch / 86400;
    int64_t secs = epoch % 86400;
    if (secs < 0) {
        secs += 86400;
        --days;
    }
    int      y = 0;
    unsigned m = 0, d = 0;
    CivilFromDays(days, y, m, d);
    int hh = static_cast<int>(secs / 3600);
    int mm = static_cast<int>((secs % 3600) / 60);
    int ss = static_cast<int>(secs % 60);

    std::string out;
    for (size_t i = 0; i < fmt.size(); ++i) {
        if (fmt[i] == '%' && i + 1 < fmt.size()) {
            char c = fmt[++i];
            switch (c) {
                case 'Y': out += Format("%04d", y); break;
                case 'm': out += Format("%02u", m); break;
                case 'd': out += Format("%02u", d); break;
                case 'H': out += Format("%02d", hh); break;
                case 'M': out += Format("%02d", mm); break;
                case 'S': out += Format("%02d", ss); break;
                case '%': out += '%'; break;
                default:
                    out += '%';
                    out += c;
                    break;
            }
        } else {
            out.push_back(fmt[i]);
        }
    }
    return out;
}

// 解析 "YYYY-MM-DD HH:MM:SS" 这类时间（分隔符 [/ .] 与 'T' 都接受）
int64_t ParseTimeString(const std::string& raw) {
    std::string s;
    for (char c : raw) {
        if (c == 'T') {
            s.push_back(' ');
        } else if (c == '/' || c == '.') {
            s.push_back('-');
        } else {
            s.push_back(c);
        }
    }

    int      y = 0;
    unsigned mo = 0, da = 0, hh = 0, mi = 0, ss = 0;
    int n = std::sscanf(s.c_str(), "%d-%u-%u %u:%u:%u", &y, &mo, &da, &hh, &mi, &ss);
    if (n < 3) throw Error("timestamp：无法解析时间，期望形如 2024-01-31 12:34:56");
    if (mo < 1 || mo > 12 || da < 1 || da > 31 || hh > 23 || mi > 59 || ss > 60) {
        throw Error("timestamp：时间字段超出合法范围");
    }
    int64_t days = DaysFromCivil(y, mo, da);
    return days * 86400 + static_cast<int64_t>(hh) * 3600 + static_cast<int64_t>(mi) * 60 + ss;
}

// 编码方向：时间字符串 -> 时间戳数字
void TimestampEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    int64_t     t  = ParseTimeString(Trim(Str(in)));
    std::string tz = ToLower(p.Get("tz", "utc"));
    if (tz == "local") t -= LocalOffsetSeconds();
    out = ToBytes(Format("%lld", static_cast<long long>(t)));
}

// 解码方向：时间戳数字 -> 时间字符串
void TimestampDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    std::string s = Trim(Str(in));
    if (s.empty()) throw Error("timestamp：输入为空");
    long long t = 0;
    try {
        size_t used = 0;
        t = std::stoll(s, &used);
        if (used != s.size()) throw Error("bad");
    } catch (...) {
        throw Error("timestamp：输入不是合法整数时间戳");
    }

    std::string unit = ToLower(p.Get("unit", "s"));
    if (unit == "ms") t /= 1000;
    else if (unit == "us") t /= 1000000;

    std::string tz = ToLower(p.Get("tz", "utc"));
    if (tz == "local") t += LocalOffsetSeconds();

    std::string fmt = p.Get("fmt", "%Y-%m-%d %H:%M:%S");
    out = ToBytes(FormatEpoch(static_cast<int64_t>(t), fmt));
}

// ===========================================================================
// IPv4 / IPv6
// ===========================================================================
// 编码：点分十进制 -> 32 位整数
void IpEncode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    std::string s = Trim(Str(in));
    unsigned    a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        throw Error("ip：期望形如 192.168.1.1 的 IPv4 地址");
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) throw Error("ip：每段必须在 0-255 之间");
    uint64_t v = (static_cast<uint64_t>(a) << 24) | (b << 16) | (c << 8) | d;
    out = ToBytes(Format("%llu", static_cast<unsigned long long>(v)));
}

// 解码：32 位整数 -> 点分十进制
void IpDecode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    std::string s = Trim(Str(in));
    unsigned long long v = 0;
    try {
        size_t used = 0;
        v = std::stoull(s, &used);
        if (used != s.size()) throw Error("bad");
    } catch (...) {
        throw Error("ip：输入不是合法整数");
    }
    if (v > 0xFFFFFFFFull) throw Error("ip：数值超出 IPv4 范围（最大 4294967295）");
    out = ToBytes(Format("%u.%u.%u.%u", static_cast<unsigned>((v >> 24) & 0xFF),
                         static_cast<unsigned>((v >> 16) & 0xFF),
                         static_cast<unsigned>((v >> 8) & 0xFF),
                         static_cast<unsigned>(v & 0xFF)));
}

// 解析 IPv6（支持 :: 缩写），失败返回 false
bool ParseIpv6(const std::string& raw, uint8_t out[16]) {
    std::string s = raw;
    // 去掉可能的方括号与 scope id
    if (!s.empty() && s.front() == '[') {
        size_t e = s.find(']');
        if (e != std::string::npos) s = s.substr(1, e - 1);
    }
    size_t pct = s.find('%');
    if (pct != std::string::npos) s = s.substr(0, pct);

    // 处理内嵌 IPv4（如 ::ffff:192.168.1.1）
    uint8_t v4[4] = {0, 0, 0, 0};
    bool    hasV4 = false;
    size_t  lastColon = s.rfind(':');
    if (lastColon != std::string::npos) {
        std::string tail = s.substr(lastColon + 1);
        if (tail.find('.') != std::string::npos) {
            unsigned a = 0, b = 0, c = 0, d = 0;
            if (std::sscanf(tail.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
            if (a > 255 || b > 255 || c > 255 || d > 255) return false;
            v4[0] = static_cast<uint8_t>(a);
            v4[1] = static_cast<uint8_t>(b);
            v4[2] = static_cast<uint8_t>(c);
            v4[3] = static_cast<uint8_t>(d);
            hasV4  = true;
            s      = s.substr(0, lastColon);   // 剩下的部分只含十六进制组
        }
    }

    std::vector<uint16_t> head, tail;
    std::vector<uint16_t>* cur = &head;
    size_t                 i   = 0;

    // 空串（"::" 被切后的情况）直接进入尾部
    while (i < s.size()) {
        if (s[i] == ':') {
            if (i + 1 < s.size() && s[i + 1] == ':') {
                if (cur == &tail) return false;   // 出现两个 "::"
                cur = &tail;
                i += 2;
                continue;
            }
            if (i == 0) return false;
            ++i;
            continue;
        }
        size_t j = i;
        while (j < s.size() && s[j] != ':') ++j;
        std::string grp = s.substr(i, j - i);
        if (grp.empty() || grp.size() > 4) return false;
        uint32_t v = 0;
        for (char c : grp) {
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else return false;
            v = v * 16 + static_cast<uint32_t>(d);
        }
        cur->push_back(static_cast<uint16_t>(v));
        i = j;
    }

    size_t v4groups = hasV4 ? 2 : 0;   // 内嵌 IPv4 占两组
    size_t total    = head.size() + tail.size() + v4groups;
    if (total > 8) return false;
    bool hasAbbrev = (s.find("::") != std::string::npos);
    if (!hasAbbrev && total != 8) return false;

    std::vector<uint16_t> full;
    for (uint16_t g : head) full.push_back(g);
    size_t zeros = 8 - total;
    for (size_t k = 0; k < zeros; ++k) full.push_back(0);
    for (uint16_t g : tail) full.push_back(g);
    if (hasV4) {
        full.push_back(static_cast<uint16_t>((v4[0] << 8) | v4[1]));
        full.push_back(static_cast<uint16_t>((v4[2] << 8) | v4[3]));
    }
    if (full.size() != 8) return false;

    for (int k = 0; k < 8; ++k) {
        out[k * 2]     = static_cast<uint8_t>(full[k] >> 8);
        out[k * 2 + 1] = static_cast<uint8_t>(full[k] & 0xFF);
    }
    return true;
}

// 格式化为 RFC 5952 风格（最长的零组用 :: 压缩）
std::string FormatIpv6(const uint8_t in[16]) {
    uint16_t g[8];
    for (int i = 0; i < 8; ++i) {
        g[i] = static_cast<uint16_t>((in[i * 2] << 8) | in[i * 2 + 1]);
    }

    int bestStart = -1, bestLen = 0;
    for (int i = 0; i < 8;) {
        if (g[i] == 0) {
            int j = i;
            while (j < 8 && g[j] == 0) ++j;
            if (j - i > bestLen) {
                bestLen   = j - i;
                bestStart = i;
            }
            i = j;
        } else {
            ++i;
        }
    }
    if (bestLen < 2) {
        bestStart = -1;
        bestLen   = 0;
    }

    std::string out;
    for (int i = 0; i < 8; ++i) {
        if (bestStart >= 0 && i == bestStart) {
            // 压缩段必须写成两个冒号：前面若已有内容，此时 out 并不以 ':' 结尾
            // （冒号是加在下一组之前的），只加一个会得到 "2001:db8:1" 这种错地址。
            out += "::";
            i += bestLen - 1;
            continue;
        }
        if (!out.empty() && out.back() != ':') out += ":";
        out += Format("%x", g[i]);
    }
    if (out.empty()) out = "::";
    return out;
}

// 编码：IPv6 文本 -> 32 位十六进制串
void Ipv6Encode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    uint8_t buf[16];
    if (!ParseIpv6(Trim(Str(in)), buf)) throw Error("ipv6：无法解析该 IPv6 地址");
    std::string s = HexEncode(Bytes(buf, buf + 16), p.GetInt("upper", 0) != 0);
    out = ToBytes(s);
}

// 解码：32 位十六进制串 -> IPv6 文本（也接受带冒号的输入做规范化）
void Ipv6Decode(const Bytes& in, const Params& p, Bytes& out) {
    out.clear();
    (void)p;
    std::string s = Trim(Str(in));
    if (s.find(':') != std::string::npos) {
        uint8_t buf[16];
        if (!ParseIpv6(s, buf)) throw Error("ipv6：无法解析该 IPv6 地址");
        out = ToBytes(FormatIpv6(buf));
        return;
    }
    Bytes b = HexDecode(s);
    if (b.size() != 16) {
        throw Error(Format("ipv6：十六进制长度应为 32（16 字节），当前 %zu", b.size()));
    }
    out = ToBytes(FormatIpv6(b.data()));
}

}  // namespace

void RegisterBinary(Registry& r) {
    r.Add("binary", "Binary", "每字节 8 位二进制串，sep 分隔（编码时自动识别 7 位 ASCII）", true,
          true, BinaryEncode, BinaryDecode, {"bin"});
    r.Add("octal", "Binary", "每字节 3 位八进制，prefix=1 加 0o 前缀", true, true, OctalEncode,
          OctalDecode, {"oct"});
    r.Add("decimal", "Binary", "每字节十进制（0-255），sep 分隔", true, true, DecimalEncode,
          DecimalDecode, {"dec"});
    r.Add("hex-bytes", "Binary", "\\x41\\x42 形式，解码容忍 0x/\\x/裸十六进制/空白", true, true,
          HexBytesEncode, HexBytesDecode, {"hexdump", "hexescape"});
    r.Add("base-convert", "Binary", "任意进制大数转换，需 from 与 to 参数（2..64）", true, true,
          BaseConvertEnc, BaseConvertDec, {"radix", "radix-convert"});
    r.Add("bcd", "Binary", "8421 BCD 编码，packed=0 关闭紧缩（每个数字一字节）", true, true,
          BcdEncode, BcdDecode);
    r.Add("gray", "Binary", "格雷码：g = b ^ (b >> 1)", true, false, GrayEncode, GrayDecode,
          {"graycode", "gray-code"});
    r.Add("bits", "Binary", "连续位流字符串（无分隔），msb=0 低位在前", true, true, BitsEncode,
          BitsDecode, {"bitstring", "bitstream", "bit-stream"});
    r.Add("byteswap", "Binary", "按块反转字节序（大端 <-> 小端），size=2/4/8", true, true,
          ByteSwap, ByteSwap, {"endian", "bswap"});
    r.Add("bitreverse", "Binary", "每字节内 8 个比特反转", true, false, BitReverse, BitReverse,
          {"bit-reverse"});
    r.Add("nibbleswap", "Binary", "每字节高低 4 位交换", true, false, NibbleSwap, NibbleSwap,
          {"nibble-swap"});
    r.Add("timestamp", "Binary",
          "Unix 时间戳 <-> 可读时间（编码 = 时间转时间戳，解码 = 时间戳转时间）", true, true,
          TimestampEncode, TimestampDecode, {"unixtime", "unix-time"});
    r.Add("ip", "Binary", "IPv4：编码 = 点分十进制转整数，解码 = 整数转点分十进制", true, false,
          IpEncode, IpDecode, {"ipv4"});
    r.Add("ipv6", "Binary",
          "IPv6：编码 = 地址转 32 位十六进制，解码 = 十六进制转压缩地址形式", true, false,
          Ipv6Encode, Ipv6Decode);
}

}  // namespace ctf
