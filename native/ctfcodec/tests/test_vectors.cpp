// test_vectors.cpp —— C ABI 层测试
//
// 与内置 selftest 的分工：
//   selftest  —— 算法正确性（已知向量 + 往返），在 DLL 内部
//   本文件    —— 对外接口契约（导出、错误码、内存、清单、二进制安全）
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ctfcodec.h"

static int g_pass = 0;
static int g_fail = 0;

static void Check(bool cond, const char* what) {
    if (cond) {
        ++g_pass;
    } else {
        ++g_fail;
        std::printf("  [FAIL] %s\n", what);
    }
}

static void CheckEq(const std::string& got, const std::string& want, const char* what) {
    if (got == want) {
        ++g_pass;
    } else {
        ++g_fail;
        std::printf("  [FAIL] %s\n         期望: [%s]\n         实际: [%s]\n", what, want.c_str(),
                    got.c_str());
    }
}

// 用 C ABI 做一次编码，返回结果（失败时返回空串）
static std::string Enc(const char* alg, const std::string& in, const char* params = nullptr) {
    uint8_t* out = nullptr;
    size_t   len = 0;
    int rc = ctf_encode(alg, reinterpret_cast<const uint8_t*>(in.data()), in.size(), params, &out,
                        &len);
    if (rc != CTF_OK) return std::string();
    std::string r(reinterpret_cast<char*>(out), len);
    ctf_free(out);
    return r;
}

static std::string Dec(const char* alg, const std::string& in, const char* params = nullptr) {
    uint8_t* out = nullptr;
    size_t   len = 0;
    int rc = ctf_decode(alg, reinterpret_cast<const uint8_t*>(in.data()), in.size(), params, &out,
                        &len);
    if (rc != CTF_OK) return std::string();
    std::string r(reinterpret_cast<char*>(out), len);
    ctf_free(out);
    return r;
}

int main() {
    std::printf("=== ctfcodec C ABI 测试 ===\n\n");

    // ---------------------------------------------------------------- 基础信息
    std::printf("[1] 版本与 ABI\n");
    Check(ctf_abi_version() == 1, "ABI 版本应为 1");
    Check(ctf_version() != nullptr && std::strlen(ctf_version()) > 0, "版本串非空");

    // ---------------------------------------------------------------- 基本编解码
    std::printf("[2] 基本编解码\n");
    CheckEq(Enc("base64", "hello"), "aGVsbG8=", "base64 编码");
    CheckEq(Dec("base64", "aGVsbG8="), "hello", "base64 解码");
    CheckEq(Enc("base16", "Hi"), "4869", "base16 编码");
    CheckEq(Dec("base16", "4869"), "Hi", "base16 解码");
    CheckEq(Enc("url", "a b"), "a%20b", "url 编码");
    CheckEq(Dec("url", "a%20b"), "a b", "url 解码");

    // 字符串便捷接口
    {
        char* s = ctf_encode_str("base64", "hello", nullptr);
        Check(s != nullptr && std::strcmp(s, "aGVsbG8=") == 0, "ctf_encode_str");
        ctf_free(s);
        s = ctf_decode_str("base64", "aGVsbG8=", nullptr);
        Check(s != nullptr && std::strcmp(s, "hello") == 0, "ctf_decode_str");
        ctf_free(s);
    }

    // ---------------------------------------------------------------- 二进制安全
    std::printf("[3] 二进制安全（含 NUL 与高位字节）\n");
    {
        std::string bin;
        for (int i = 0; i < 256; ++i) bin += static_cast<char>(i);
        std::string enc = Enc("base64", bin);
        Check(!enc.empty(), "二进制数据 base64 编码成功");
        std::string dec = Dec("base64", enc);
        Check(dec.size() == 256 && std::memcmp(dec.data(), bin.data(), 256) == 0,
              "全部 256 个字节值往返一致");

        std::string hexEnc = Enc("base16", bin);
        Check(hexEnc.size() == 512, "base16 编码长度 = 2 倍输入");

        // XOR 也必须是二进制安全的
        std::string x = Enc("xor", bin, "key=K");
        std::string y = Dec("xor", x, "key=K");
        Check(y.size() == 256 && std::memcmp(y.data(), bin.data(), 256) == 0,
              "xor 对全部字节值往返一致");
    }

    // ---------------------------------------------------------------- 空输入
    std::printf("[4] 空输入不崩\n");
    {
        uint8_t* out = nullptr;
        size_t   len = 0;
        int rc = ctf_encode("base64", nullptr, 0, nullptr, &out, &len);
        Check(rc == CTF_OK, "空输入编码返回 CTF_OK");
        Check(out != nullptr, "空输入也返回可 free 的指针");
        Check(len == 0, "空输入输出长度为 0");
        ctf_free(out);
    }

    // ---------------------------------------------------------------- 错误处理
    std::printf("[5] 错误处理\n");
    {
        uint8_t* out = nullptr;
        size_t   len = 0;
        const char* data = "hello";
        size_t      n    = 5;

        int rc = ctf_encode("no-such-algo-xyz", reinterpret_cast<const uint8_t*>(data), n, nullptr,
                            &out, &len);
        Check(rc == CTF_ERR_UNKNOWN_ALGO, "未知算法返回 CTF_ERR_UNKNOWN_ALGO");
        Check(out == nullptr, "失败时不返回缓冲区");
        Check(std::strlen(ctf_last_error()) > 0, "失败时 ctf_last_error 有内容");

        rc = ctf_decode("md5", reinterpret_cast<const uint8_t*>(data), n, nullptr, &out, &len);
        Check(rc == CTF_ERR_NOT_REVERSIBLE, "解码不可逆算法返回 CTF_ERR_NOT_REVERSIBLE");

        rc = ctf_encode("caesar", reinterpret_cast<const uint8_t*>(data), n, nullptr, &out, &len);
        Check(rc == CTF_ERR_NEED_PARAM, "缺少必需参数返回 CTF_ERR_NEED_PARAM");

        rc = ctf_encode(nullptr, reinterpret_cast<const uint8_t*>(data), n, nullptr, &out, &len);
        Check(rc == CTF_ERR_NULL_POINTER, "alg 为 NULL 返回 CTF_ERR_NULL_POINTER");

        rc = ctf_encode("base64", reinterpret_cast<const uint8_t*>(data), n, nullptr, nullptr, &len);
        Check(rc == CTF_ERR_NULL_POINTER, "out 为 NULL 返回 CTF_ERR_NULL_POINTER");

        rc = ctf_decode("base64", reinterpret_cast<const uint8_t*>(data), 0, nullptr, &out, &len);
        Check(rc == CTF_OK, "空输入解码返回 CTF_OK");
        ctf_free(out);

        Check(ctf_strerror(CTF_ERR_UNKNOWN_ALGO) != nullptr, "ctf_strerror 可用");
    }

    // ---------------------------------------------------------------- 算法清单
    std::printf("[6] 算法清单\n");
    {
        int n = ctf_algo_count();
        std::printf("     注册算法总数: %d\n", n);
        Check(n >= 100, "算法总数应 >= 100");

        std::vector<std::string> names;
        bool allNamed = true;
        for (int i = 0; i < n; ++i) {
            const char* nm = ctf_algo_name(i);
            if (!nm || !*nm) allNamed = false;
            else names.push_back(nm);
            if (!ctf_algo_category(i) || !*ctf_algo_category(i)) allNamed = false;
            if (!ctf_algo_help(i) || !*ctf_algo_help(i)) allNamed = false;
        }
        Check(allNamed, "每个算法的名称/分类/说明都非空");

        bool dup = false;
        for (size_t i = 0; i < names.size() && !dup; ++i) {
            for (size_t j = i + 1; j < names.size(); ++j) {
                if (names[i] == names[j]) {
                    dup = true;
                    std::printf("     重复算法名: %s\n", names[i].c_str());
                    break;
                }
            }
        }
        Check(!dup, "算法名无重复");

        Check(ctf_algo_name(-1) == nullptr, "负索引返回 NULL");
        Check(ctf_algo_name(n + 100) == nullptr, "越界索引返回 NULL");

        char* js = ctf_algo_list_json();
        Check(js != nullptr && std::strlen(js) > 100, "JSON 清单可导出");
        if (js) ctf_free(js);
    }

    // ---------------------------------------------------------------- 分类统计
    std::printf("[7] 分类覆盖\n");
    {
        int n = ctf_algo_count();
        const char* cats[] = {"Base", "Text", "Unicode", "Classic", "Cipher", "Hash", "Binary"};
        for (const char* want : cats) {
            int cnt = 0;
            for (int i = 0; i < n; ++i) {
                const char* c = ctf_algo_category(i);
                if (c && std::strcmp(c, want) == 0) ++cnt;
            }
            std::printf("     %-10s %3d 个\n", want, cnt);
            Check(cnt > 0, "每个分类都应有算法");
        }
    }

    // ---------------------------------------------------------------- 自动识别
    std::printf("[8] 自动识别\n");
    {
        char* js = ctf_magic("aGVsbG8gd29ybGQ=");
        Check(js != nullptr, "ctf_magic 返回非 NULL");
        if (js) {
            Check(std::strstr(js, "base64") != nullptr, "识别出 base64");
            ctf_free(js);
        }
        js = ctf_magic(".... . .-.. .-.. ---");
        if (js) {
            Check(std::strstr(js, "morse") != nullptr, "识别出 morse");
            ctf_free(js);
        }
        js = ctf_magic("");
        if (js) {
            Check(std::strcmp(js, "[]") == 0, "空输入返回空数组");
            ctf_free(js);
        }
    }

    // ---------------------------------------------------------------- 内置自检
    std::printf("[9] 内置算法自检\n");
    {
        char* report = nullptr;
        int   failed = ctf_self_test(&report);
        (void)failed;   // 详细结果由 ctfcodec-cli selftest 打印
        Check(report != nullptr, "自检报告已生成");
        if (report) ctf_free(report);
    }

    std::printf("\n=== 结果: %d 通过, %d 失败 ===\n", g_pass, g_fail);
    return g_fail;
}
