// common.h —— 内部公共类型：字节容器、参数表、编解码器注册表
//
// 所有算法模块都只依赖本文件和 util.h，不要引入其他模块的头文件。
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace ctf {

using Bytes = std::vector<uint8_t>;

// 统一错误类型：任何编解码失败都抛它，C ABI 层负责捕获并转成状态码。
class Error : public std::runtime_error {
public:
    explicit Error(const std::string& msg) : std::runtime_error(msg) {}
};

// ---------------------------------------------------------------------------
// Params —— 参数表
//   字符串形式："key=SECRET;shift=3;alphabet=ABC"
//   值里允许出现 '='，但 ';' 需要转义（用 "\\;"），实际使用中极少遇到。
// ---------------------------------------------------------------------------
class Params {
public:
    Params() = default;

    static Params Parse(const std::string& spec);

    bool        Has(const std::string& k) const;
    std::string Get(const std::string& k, const std::string& def = std::string()) const;
    int         GetInt(const std::string& k, int def) const;
    void        Set(const std::string& k, const std::string& v);

    // 取密钥：优先 "key_hex"（十六进制字面量），否则用 "key"（UTF-8 文本）。
    Bytes       GetKey() const;

    // 取整型参数，缺失或非法时抛 ctF::Error（用于必填参数）
    int         RequireInt(const std::string& k) const;
    std::string RequireStr(const std::string& k) const;
    Bytes       RequireKey() const;

    const std::map<std::string, std::string>& Raw() const { return kv_; }
    std::string Dump() const;

private:
    std::map<std::string, std::string> kv_;
};

// ---------------------------------------------------------------------------
// 编解码函数签名
//   in  : 输入字节
//   p   : 参数
//   out : 输出字节（追加或覆盖由实现决定，建议先 out.clear()）
//   失败时抛 ctf::Error
// ---------------------------------------------------------------------------
using CodecFn = std::function<void(const Bytes& in, const Params& p, Bytes& out)>;

struct Codec {
    std::string name;                 // 规范名（小写，全局唯一）
    std::string category;             // Base / Text / Unicode / Classic / Cipher / Hash / Binary
    std::string help;                 // 一句话说明
    bool        reversible = true;    // 是否可逆
    bool        needs_param = false;  // 是否需要 params（密钥/字母表/位移）
    CodecFn     enc;                  // 编码函数（可为 nullptr 表示不支持）
    CodecFn     dec;                  // 解码函数（不可逆时为 nullptr）
};

// ---------------------------------------------------------------------------
// Registry —— 全局算法注册表（Meyers singleton，线程安全初始化）
// ---------------------------------------------------------------------------
class Registry {
public:
    static Registry& Instance();

    void Add(const std::string&                name,
             const std::string&                category,
             const std::string&                help,
             bool                              reversible,
             bool                              needs_param,
             CodecFn                           enc,
             CodecFn                           dec,
             std::initializer_list<const char*> aliases = {});

    // 大小写不敏感查找，支持别名；未找到返回 nullptr
    const Codec* Find(const std::string& name) const;

    const std::vector<Codec>& All() const { return codecs_; }
    std::vector<std::string>  Names() const;

private:
    Registry() = default;

    std::vector<Codec>            codecs_;
    std::map<std::string, size_t> index_;   // lower(name) 及别名 -> codecs_ 下标
};

// 确保所有算法模块已注册（幂等，首次调用时完成注册）
void EnsureInitialized();

// 各算法模块的注册入口，由 registry.cpp 统一调用
void RegisterBase(Registry& r);
void RegisterText(Registry& r);
void RegisterUnicode(Registry& r);
void RegisterClassic(Registry& r);
void RegisterCipher(Registry& r);
void RegisterHash(Registry& r);
void RegisterBinary(Registry& r);

}  // namespace ctf
