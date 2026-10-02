// api.cpp —— 对外 C ABI 导出层
//
// 职责：
//   1. 把 C++ 异常统一翻译成状态码，绝不让异常穿过 DLL 边界（会直接崩掉宿主进程）
//   2. 统一内存管理：库内 malloc，调用方 ctf_free
//   3. 提供线程局部的错误信息
//
// 注意：本文件是导出函数的定义处，必须启用 dllexport（否则头文件里的声明会变成
//       dllimport，GCC 直接报 "definition is marked dllimport"）。
#ifndef CTFCODEC_BUILD
#define CTFCODEC_BUILD
#endif

#include <cstdlib>
#include <cstring>
#include <string>

#include "common.h"
#include "ctfcodec.h"
#include "util.h"

using namespace ctf;

// magic.cpp / selftest.cpp 提供的内部入口
namespace ctf {
std::string MagicAnalyze(const std::string& text);
int         RunSelfTest(std::string& report);
}  // namespace ctf

namespace {

// 线程局部错误信息：多线程调用时互不干扰
thread_local std::string g_lastError;

int Fail(int code, const std::string& msg) {
    g_lastError = msg;
    return code;
}

// 根据错误文本粗分类，让调用方能区分「缺参数」和「输入非法」
int ClassifyError(const std::string& msg) {
    if (msg.find("缺少必需参数") != std::string::npos) return CTF_ERR_NEED_PARAM;
    if (msg.find("未知算法") != std::string::npos) return CTF_ERR_UNKNOWN_ALGO;
    if (msg.find("不可逆") != std::string::npos) return CTF_ERR_NOT_REVERSIBLE;
    return CTF_ERR_BAD_INPUT;
}

// 内部通用执行体
int DoOp(bool               encode,
         const char*        alg,
         const uint8_t*     in,
         size_t             in_len,
         const char*        params,
         uint8_t**          out,
         size_t*            out_len) {
    if (!alg || !out || !out_len) {
        return Fail(CTF_ERR_NULL_POINTER, "alg / out / out_len 不能为 NULL");
    }
    if (!in && in_len > 0) {
        return Fail(CTF_ERR_NULL_POINTER, "in 为 NULL 但 in_len 非 0");
    }
    *out     = nullptr;
    *out_len = 0;
    g_lastError.clear();

    try {
        EnsureInitialized();

        const Codec* codec = Registry::Instance().Find(alg);
        if (!codec) {
            return Fail(CTF_ERR_UNKNOWN_ALGO, std::string("未知算法: ") + alg);
        }
        if (encode && !codec->enc) {
            return Fail(CTF_ERR_INTERNAL, std::string("算法 ") + codec->name + " 不支持编码");
        }
        if (!encode && !codec->dec) {
            return Fail(CTF_ERR_NOT_REVERSIBLE,
                        std::string("算法 ") + codec->name + " 不可逆（只能编码，不能解码）");
        }

        Bytes inBytes;
        if (in_len > 0) inBytes.assign(in, in + in_len);

        Params p = Params::Parse(params ? params : "");

        Bytes outBytes;
        if (encode) {
            codec->enc(inBytes, p, outBytes);
        } else {
            codec->dec(inBytes, p, outBytes);
        }

        // 即使输出为空也返回一块可 free 的内存，避免调用方写 if (p) free(p) 之外的判断
        size_t n    = outBytes.size();
        uint8_t* buf = static_cast<uint8_t*>(std::malloc(n ? n : 1));
        if (!buf) return Fail(CTF_ERR_INTERNAL, "内存分配失败");
        if (n) std::memcpy(buf, outBytes.data(), n);

        *out     = buf;
        *out_len = n;
        return CTF_OK;
    } catch (const Error& e) {
        return Fail(ClassifyError(e.what()), e.what());
    } catch (const std::bad_alloc&) {
        return Fail(CTF_ERR_INTERNAL, "内存分配失败");
    } catch (const std::exception& e) {
        return Fail(CTF_ERR_INTERNAL, std::string("内部异常: ") + e.what());
    } catch (...) {
        return Fail(CTF_ERR_INTERNAL, "未知内部异常");
    }
}

// 字符串版公共实现
char* DoOpStr(bool encode, const char* alg, const char* text, const char* params) {
    if (!text) {
        Fail(CTF_ERR_NULL_POINTER, "text 不能为 NULL");
        return nullptr;
    }
    uint8_t* buf = nullptr;
    size_t   len = 0;
    int rc = DoOp(encode, alg, reinterpret_cast<const uint8_t*>(text), std::strlen(text), params,
                  &buf, &len);
    if (rc != CTF_OK) return nullptr;

    // 追加 NUL 结尾，方便直接当字符串用
    char* s = static_cast<char*>(std::malloc(len + 1));
    if (!s) {
        std::free(buf);
        Fail(CTF_ERR_INTERNAL, "内存分配失败");
        return nullptr;
    }
    if (len) std::memcpy(s, buf, len);
    s[len] = '\0';
    std::free(buf);
    return s;
}

}  // namespace

// ===========================================================================
// 导出实现
// ===========================================================================

extern "C" {

CTF_API int CTF_CALL ctf_abi_version(void) { return 1; }

CTF_API const char* CTF_CALL ctf_version(void) { return "1.0.0"; }

CTF_API int CTF_CALL ctf_encode(const char*    alg,
                                const uint8_t* in,
                                size_t         in_len,
                                const char*    params,
                                uint8_t**      out,
                                size_t*        out_len) {
    return DoOp(true, alg, in, in_len, params, out, out_len);
}

CTF_API int CTF_CALL ctf_decode(const char*    alg,
                                const uint8_t* in,
                                size_t         in_len,
                                const char*    params,
                                uint8_t**      out,
                                size_t*        out_len) {
    return DoOp(false, alg, in, in_len, params, out, out_len);
}

CTF_API char* CTF_CALL ctf_encode_str(const char* alg, const char* text, const char* params) {
    return DoOpStr(true, alg, text, params);
}

CTF_API char* CTF_CALL ctf_decode_str(const char* alg, const char* text, const char* params) {
    return DoOpStr(false, alg, text, params);
}

CTF_API void CTF_CALL ctf_free(void* p) { std::free(p); }

CTF_API const char* CTF_CALL ctf_last_error(void) { return g_lastError.c_str(); }

CTF_API const char* CTF_CALL ctf_strerror(int code) {
    switch (code) {
        case CTF_OK:                 return "成功";
        case CTF_ERR_UNKNOWN_ALGO:   return "未知算法名";
        case CTF_ERR_BAD_INPUT:      return "输入数据不合法";
        case CTF_ERR_NEED_PARAM:     return "缺少必需参数";
        case CTF_ERR_NOT_REVERSIBLE: return "该算法不可逆";
        case CTF_ERR_INTERNAL:       return "内部错误";
        case CTF_ERR_NULL_POINTER:   return "空指针参数";
        default:                     return "未知状态码";
    }
}

CTF_API int CTF_CALL ctf_algo_count(void) {
    try {
        EnsureInitialized();
        return static_cast<int>(Registry::Instance().All().size());
    } catch (...) {
        return 0;
    }
}

namespace {
// 统一的越界安全检查
const Codec* CodecAt(int index) {
    EnsureInitialized();
    const auto& all = Registry::Instance().All();
    if (index < 0 || static_cast<size_t>(index) >= all.size()) return nullptr;
    return &all[static_cast<size_t>(index)];
}
}  // namespace

CTF_API const char* CTF_CALL ctf_algo_name(int index) {
    try {
        const Codec* c = CodecAt(index);
        return c ? c->name.c_str() : nullptr;
    } catch (...) {
        return nullptr;
    }
}

CTF_API const char* CTF_CALL ctf_algo_category(int index) {
    try {
        const Codec* c = CodecAt(index);
        return c ? c->category.c_str() : nullptr;
    } catch (...) {
        return nullptr;
    }
}

CTF_API const char* CTF_CALL ctf_algo_help(int index) {
    try {
        const Codec* c = CodecAt(index);
        return c ? c->help.c_str() : nullptr;
    } catch (...) {
        return nullptr;
    }
}

CTF_API int CTF_CALL ctf_algo_reversible(int index) {
    try {
        const Codec* c = CodecAt(index);
        return c ? (c->reversible ? 1 : 0) : -1;
    } catch (...) {
        return -1;
    }
}

CTF_API int CTF_CALL ctf_algo_needs_param(int index) {
    try {
        const Codec* c = CodecAt(index);
        return c ? (c->needs_param ? 1 : 0) : -1;
    } catch (...) {
        return -1;
    }
}

CTF_API char* CTF_CALL ctf_algo_list_json(void) {
    try {
        EnsureInitialized();
        std::string s = "[";
        bool first = true;
        for (const auto& c : Registry::Instance().All()) {
            if (!first) s += ",";
            first = false;
            s += "{\"name\":\"" + c.name + "\",\"category\":\"" + c.category + "\",\"help\":\"" +
                 c.help + "\",\"reversible\":" + (c.reversible ? "true" : "false") +
                 ",\"needs_param\":" + (c.needs_param ? "true" : "false") + "}";
        }
        s += "]";
        char* buf = static_cast<char*>(std::malloc(s.size() + 1));
        if (!buf) return nullptr;
        std::memcpy(buf, s.c_str(), s.size() + 1);
        return buf;
    } catch (...) {
        return nullptr;
    }
}

CTF_API char* CTF_CALL ctf_magic(const char* text) {
    if (!text) {
        Fail(CTF_ERR_NULL_POINTER, "text 不能为 NULL");
        return nullptr;
    }
    try {
        std::string s = MagicAnalyze(text);
        char* buf = static_cast<char*>(std::malloc(s.size() + 1));
        if (!buf) return nullptr;
        std::memcpy(buf, s.c_str(), s.size() + 1);
        return buf;
    } catch (const std::exception& e) {
        Fail(CTF_ERR_INTERNAL, e.what());
        return nullptr;
    } catch (...) {
        Fail(CTF_ERR_INTERNAL, "内部异常");
        return nullptr;
    }
}

CTF_API int CTF_CALL ctf_self_test(char** report) {
    if (report) *report = nullptr;
    try {
        std::string r;
        int failed = RunSelfTest(r);
        if (report) {
            char* buf = static_cast<char*>(std::malloc(r.size() + 1));
            if (buf) std::memcpy(buf, r.c_str(), r.size() + 1);
            *report = buf;
        }
        return failed;
    } catch (const std::exception& e) {
        Fail(CTF_ERR_INTERNAL, e.what());
        return -1;
    } catch (...) {
        Fail(CTF_ERR_INTERNAL, "内部异常");
        return -1;
    }
}

}  // extern "C"
