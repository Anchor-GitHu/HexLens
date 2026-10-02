// registry.cpp —— 算法注册表实现
#include "common.h"

#include "util.h"

namespace ctf {

Registry& Registry::Instance() {
    static Registry inst;   // C++11 起局部静态初始化线程安全
    return inst;
}

void Registry::Add(const std::string&                name,
                   const std::string&                category,
                   const std::string&                help,
                   bool                              reversible,
                   bool                              needs_param,
                   CodecFn                           enc,
                   CodecFn                           dec,
                   std::initializer_list<const char*> aliases) {
    std::string key = ToLower(name);
    if (index_.count(key)) {
        // 重名是编程错误，直接抛出让开发者立刻发现
        throw Error("算法名重复注册: " + name);
    }

    Codec c;
    c.name        = key;
    c.category    = category;
    c.help        = help;
    c.reversible  = reversible;
    c.needs_param = needs_param;
    c.enc         = std::move(enc);
    c.dec         = std::move(dec);

    size_t idx = codecs_.size();
    codecs_.push_back(std::move(c));
    index_[key] = idx;

    for (const char* a : aliases) {
        if (!a || !*a) continue;
        std::string ak = ToLower(a);
        if (index_.count(ak)) continue;   // 别名冲突时静默忽略，不影响主名
        index_[ak] = idx;
    }
}

const Codec* Registry::Find(const std::string& name) const {
    auto it = index_.find(ToLower(name));
    if (it == index_.end()) return nullptr;
    return &codecs_[it->second];
}

std::vector<std::string> Registry::Names() const {
    std::vector<std::string> v;
    v.reserve(codecs_.size());
    for (const auto& c : codecs_) v.push_back(c.name);
    return v;
}

// 全局初始化：所有算法模块在这里挂载（只跑一次）
static void InitAll() {
    static bool done = false;
    if (done) return;
    done = true;

    Registry& r = Registry::Instance();
    RegisterBase(r);
    RegisterText(r);
    RegisterUnicode(r);
    RegisterClassic(r);
    RegisterCipher(r);
    RegisterHash(r);
    RegisterBinary(r);
}

// 供 api.cpp 调用，确保注册表已填充
void EnsureInitialized() { InitAll(); }

}  // namespace ctf
