// selftest.cpp —— 内置自检：已知向量 + 全算法往返
//
// 这是「产物必验」的落地：交给用户之前，先自己把所有算法跑一遍。
// 返回失败数量，报告为 JSON。
#include <string>
#include <vector>

#include "common.h"
#include "util.h"

namespace ctf {

namespace {

struct Result {
    std::string name;
    std::string detail;
    bool        ok = false;
};

// 统一执行：成功返回 true，结果放 out
bool Run(const std::string& alg, bool encode, const std::string& in, const std::string& params,
         std::string& out, std::string& err) {
    try {
        const Codec* c = Registry::Instance().Find(alg);
        if (!c) {
            err = "算法不存在: " + alg;
            return false;
        }
        const CodecFn& fn = encode ? c->enc : c->dec;
        if (!fn) {
            err = std::string(encode ? "不支持编码" : "不支持解码（不可逆）") + ": " + alg;
            return false;
        }
        Bytes o;
        Params p = Params::Parse(params);
        fn(ToBytes(in), p, o);
        out = Str(o);
        return true;
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
}

// 显示用：不可打印字节转成 \xNN
std::string Vis(const std::string& s, size_t maxLen = 80) {
    std::string out;
    for (unsigned char c : s) {
        if (out.size() >= maxLen) {
            out += "...";
            break;
        }
        if (c >= 32 && c < 127) {
            out += static_cast<char>(c);
        } else {
            out += Format("\\x%02x", c);
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

// ---------------------------------------------------------------------------
// 已知向量：alg / params / 输入 / 期望输出（hex: 前缀表示按字节比较）
// ---------------------------------------------------------------------------
struct Vector {
    const char* alg;
    const char* params;
    const char* input;
    const char* want;
};

const Vector kEncodeVectors[] = {
    // Base 家族
    {"base16", nullptr, "Hi", "4869"},
    {"base32", nullptr, "foobar", "MZXW6YTBOI======"},
    {"base64", nullptr, "hello", "aGVsbG8="},
    {"base64url", nullptr, "hi?", "aGk_"},
    {"base58", nullptr, "hello", "Cn8eVZg"},
    {"base85", nullptr, "hello", "BOu!rDZ"},
    {"base45", nullptr, "AB", "BB8"},
    {"base36", nullptr, "hello", "5PZCSZU7"},

    // Text
    {"url", nullptr, "a b", "a%20b"},
    {"html", nullptr, "<a>", "&lt;a&gt;"},
    {"quoted-printable", nullptr, "\xE4\xB8\xAD", "=E4=B8=AD"},
    {"leet", nullptr, "leet", "1337"},

    // Classic
    {"morse", nullptr, "SOS", "... --- ..."},
    {"bacon", nullptr, "ABC", "AAAAAAAAABAAABA"},
    {"a1z26", nullptr, "ABC", "1-2-3"},
    {"polybius", nullptr, "ABC", "111213"},

    // Cipher
    {"caesar", "shift=3", "HELLO", "KHOOR"},
    {"rot13", nullptr, "HELLO", "URYYB"},
    {"rot47", nullptr, "Hello", "w6==@"},
    {"atbash", nullptr, "HELLO", "SVOOL"},
    {"affine", "a=5;b=8", "AFFINE", "IHHWVC"},
    {"vigenere", "key=LEMON", "ATTACKATDAWN", "LXFOPVEFRNHR"},
    {"railfence", "rails=3", "WEAREDISCOVEREDFLEEATONCE", "WECRLTEERDSOEEFEAOCAIVDEN"},
    {"xor", "key=K", "hi", "hex:2322"},

    // Binary
    {"binary", nullptr, "A", "01000001"},
    {"hex-bytes", nullptr, "AB", "\\x41\\x42"},
    {"base-convert", "from=10;to=16", "255", "FF"},
    {"base-convert", "from=2;to=10", "11111111", "255"},
    {"timestamp", nullptr, "2024-01-01 00:00:00", "1704067200"},
    {"timestamp", nullptr, "1970-01-01 00:00:00", "0"},
    {"ip", nullptr, "192.168.1.1", "3232235777"},
    {"ip", nullptr, "0.0.0.0", "0"},
    {"ip", nullptr, "255.255.255.255", "4294967295"},
    {"ipv6", nullptr, "::1", "00000000000000000000000000000001"},

    // Unicode
    {"toutf16le", nullptr, "hi", "hex:68006900"},
    {"toutf32be", nullptr, "hi", "hex:0000006800000069"},
    {"codepoint", nullptr, "\xE4\xB8\xAD", "U+4E2D"},

    // Hash（不可逆，只测编码）
    {"md5", nullptr, "abc", "900150983cd24fb0d6963f7d28e17f72"},
    {"md5", nullptr, "", "d41d8cd98f00b204e9800998ecf8427e"},
    {"sha1", nullptr, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
    {"sha256", nullptr, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"sha256", nullptr, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"sha512", nullptr, "abc",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3"
     "c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
    {"crc32", nullptr, "123456789", "cbf43926"},
    {"crc32c", nullptr, "123456789", "e3069283"},
    {"crc16", "variant=modbus", "123456789", "4b37"},
    {"adler32", nullptr, "Wikipedia", "11e60398"},
    {"ntlm", nullptr, "password", "8846f7eaee8fb117ad06bdd830b7586c"},
};

// ---------------------------------------------------------------------------
// 往返测试：enc 后 dec 必须回到原样。每种算法给一份「它支持的字符集」的输入。
// ---------------------------------------------------------------------------
struct RoundTrip {
    const char* alg;
    const char* params;
    const char* input;
};

const RoundTrip kRoundTrips[] = {
    // Base
    {"base16", nullptr, "Hello, World! 123"},
    {"base32", nullptr, "Hello, World! 123"},
    {"base32hex", nullptr, "Hello, World! 123"},
    {"base36", nullptr, "HelloWorld123"},
    {"base45", nullptr, "Hello, World! 123"},
    {"base58", nullptr, "Hello, World! 123"},
    {"base58check", nullptr, "Hello!"},
    {"base62", nullptr, "Hello, World! 123"},
    {"base64", nullptr, "Hello, World! 123 \xE4\xB8\xAD\xE6\x96\x87"},
    {"base64url", nullptr, "Hello, World! 123"},
    {"base85", nullptr, "Hello, World! 123"},
    {"z85", nullptr, "HelloWorld123456"},
    {"base85rfc", nullptr, "Hello, World! 123"},
    {"base91", nullptr, "Hello, World! 123"},
    {"base92", nullptr, "Hello, World! 123"},
    {"base100", nullptr, "Hello, World! 123"},
    {"radix64", nullptr, "Hello, World! 123"},
    {"bcrypt64", nullptr, "Hello, World! 123"},
    {"crypt64", nullptr, "Hello, World! 123"},

    // Text
    {"url", nullptr, "Hello, World! 123&x=1"},
    {"urldouble", nullptr, "Hello, World! 123"},
    {"html", nullptr, "Hello <b>World</b> & 'quotes'"},
    {"css-escape", nullptr, "Hello, World!"},
    {"c-escape", nullptr, "Hello\tWorld\n"},
    {"octal-escape", nullptr, "Hello, World!"},
    {"quoted-printable", nullptr, "Hello, World! \xE4\xB8\xAD\xE6\x96\x87"},
    {"uuencode", nullptr, "Hello, World! 123"},
    {"xxencode", nullptr, "Hello, World! 123"},
    {"punycode", nullptr, "b\xC3\xBC" "cher"},
    // 注意：leet 是有损映射（'l' 和 'i' 都编成 '1'），无法往返，所以只做编码方向的向量测试
    {"reverse", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87"},
    {"swapcase", nullptr, "Hello World"},

    // Unicode
    {"toutf16le", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87"},
    {"toutf16be", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87"},
    {"toutf32le", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87"},
    {"toutf32be", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87"},
    {"utf7", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87"},
    {"gbk", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87"},
    {"gb18030", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87"},
    {"big5", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87"},
    {"latin1", nullptr, "Hello World"},
    {"codepoint", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87"},
    {"unicode-escape", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87 \xF0\x9F\x98\x80"},
    {"percent-u", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87"},
    {"numeric-entity", nullptr, "Hello \xE4\xB8\xAD\xE6\x96\x87"},
    {"mysql-escape", nullptr, "Hello 'World'\n"},
    {"zero-width", nullptr, "secret"},
    {"unicode-tag", nullptr, "secret"},
    {"variation-selector", nullptr, "secret"},

    // Classic
    {"morse", nullptr, "SOS HELP"},
    {"bacon", nullptr, "HELLO"},
    {"a1z26", nullptr, "HELLO"},
    {"polybius", nullptr, "HELLO"},
    {"tap-code", nullptr, "HELLO"},
    {"braille", nullptr, "hello"},
    {"semaphore", nullptr, "HELLO"},
    {"ascii-binary", nullptr, "Hello"},
    {"pigpen", nullptr, "HELLO"},

    // Cipher
    {"caesar", "shift=13", "Hello, World!"},
    {"rot-n", "shift=7", "Hello, World!"},
    {"rot13", nullptr, "Hello, World!"},
    {"rot5", nullptr, "Hello, 12345!"},
    {"rot18", nullptr, "Hello, 12345!"},
    {"rot47", nullptr, "Hello, World! 123"},
    {"atbash", nullptr, "Hello, World!"},
    {"substitution", "key=QWERTYUIOPASDFGHJKLZXCVBNM", "HELLOWORLD"},
    {"affine", "a=5;b=8", "HELLOWORLD"},
    {"vigenere", "key=LEMON", "ATTACKATDAWN"},
    {"beaufort", "key=LEMON", "ATTACKATDAWN"},
    {"variant-beaufort", "key=LEMON", "ATTACKATDAWN"},
    {"autokey", "key=QUEENLY", "ATTACKATDAWN"},
    {"porta", "key=LEMON", "ATTACKATDAWN"},
    {"gronsfeld", "key=3141", "ATTACKATDAWN"},
    {"running-key", "key=HOWDOESITWORK", "ATTACKATDAWN"},
    {"railfence", "rails=3", "WEAREDISCOVEREDFLEEATONCE"},
    {"scytale", "n=5", "WEAREDISCOVEREDFLEEATONCE"},
    {"columnar", "key=ZEBRA", "HELLOWORLD"},
    {"reverse-block", "block=3", "HELLOWORLD"},
    {"playfair", "key=MONARCHY", "HELOWORD"},
    {"bifid", "key=MONARCHY", "HELLOWORLD"},
    {"hill", "key=3,3,2,5", "HELOWORD"},
    {"xor", "key=secret", "Hello, World!"},
    {"xor-single", "byte=42", "Hello, World!"},
    {"rc4", "key=secret", "Hello, World!"},
    {"vernam", "key_hex=00112233445566778899aabbccddeeff0011223344", "HelloWorld"},
    {"enigma", "rotors=123;positions=AAA", "HELLOWORLD"},

    // Binary
    {"binary", nullptr, "Hello"},
    {"octal", nullptr, "Hello"},
    {"decimal", nullptr, "Hello"},
    {"hex-bytes", nullptr, "Hello, World!"},
    {"bcd", nullptr, "12345678"},
    {"gray", nullptr, "Hello"},
    {"bits", nullptr, "Hello"},
    {"byteswap", "size=4", "HelloWorld12"},
    {"bitreverse", nullptr, "Hello"},
    {"nibbleswap", nullptr, "Hello"},
    {"ip", nullptr, "192.168.1.1"},
    {"ipv6", nullptr, "2001:db8::1"},
};

}  // namespace

int RunSelfTest(std::string& report) {
    EnsureInitialized();

    std::vector<Result> results;
    int passed = 0;
    int failed = 0;

    // ---- 已知向量 ----
    for (const auto& v : kEncodeVectors) {
        Result r;
        r.name = std::string("enc ") + v.alg + (v.params ? std::string(" [") + v.params + "]" : "");
        std::string got, err;
        if (!Run(v.alg, true, v.input, v.params ? v.params : "", got, err)) {
            r.ok     = false;
            r.detail = "执行失败: " + err;
            ++failed;
        } else {
            std::string want = v.want;
            bool        isHex = StartsWith(want, "hex:");
            if (isHex) want = want.substr(4);

            std::string gotCmp, wantCmp;
            if (isHex) {
                gotCmp  = HexEncode(ToBytes(got), false);
                wantCmp = ToLower(want);
            } else {
                gotCmp  = got;
                wantCmp = want;
            }

            if (gotCmp == wantCmp) {
                r.ok = true;
                ++passed;
            } else {
                r.ok     = false;
                r.detail = "期望 [" + Vis(wantCmp) + "] 实际 [" + Vis(gotCmp) + "]";
                ++failed;
            }
        }
        results.push_back(r);
    }

    // ---- 往返测试 ----
    for (const auto& t : kRoundTrips) {
        Result r;
        r.name = std::string("roundtrip ") + t.alg +
                 (t.params ? std::string(" [") + t.params + "]" : "");

        std::string enc, err;
        if (!Run(t.alg, true, t.input, t.params ? t.params : "", enc, err)) {
            r.ok     = false;
            r.detail = "编码失败: " + err;
            ++failed;
            results.push_back(r);
            continue;
        }
        std::string dec;
        if (!Run(t.alg, false, enc, t.params ? t.params : "", dec, err)) {
            r.ok       = false;
            r.detail   = "解码失败: " + err + "（编码结果 " + Vis(enc, 40) + "）";
            ++failed;
            results.push_back(r);
            continue;
        }
        if (dec == t.input) {
            r.ok = true;
            ++passed;
        } else {
            r.ok       = false;
            r.detail   = "往返不一致: 原始 [" + Vis(t.input, 40) + "] -> 编码 [" + Vis(enc, 40) +
                         "] -> 解码 [" + Vis(dec, 40) + "]";
            ++failed;
        }
        results.push_back(r);
    }

    // ---- 生成 JSON 报告 ----
    std::string js = "{\"total\":" + std::to_string(passed + failed) +
                     ",\"passed\":" + std::to_string(passed) +
                     ",\"failed\":" + std::to_string(failed) + ",\"failures\":[";
    bool first = true;
    for (const auto& r : results) {
        if (r.ok) continue;
        if (!first) js += ",";
        first = false;
        js += "{\"case\":\"" + JsonEscape(r.name) + "\",\"detail\":\"" + JsonEscape(r.detail) +
              "\"}";
    }
    js += "]}";
    report = js;
    return failed;
}

}  // namespace ctf
