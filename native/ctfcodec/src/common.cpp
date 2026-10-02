// common.cpp —— Params 参数解析实现
#include "common.h"

#include <cctype>
#include <cstdlib>

#include "util.h"

namespace ctf {

Params Params::Parse(const std::string& spec) {
    Params p;
    if (spec.empty()) return p;

    // 按 ';' 切分，但支持 "\;" 转义；再按第一个 '=' 切 key/value
    std::string cur;
    std::vector<std::string> items;
    for (size_t i = 0; i < spec.size(); ++i) {
        char c = spec[i];
        if (c == '\\' && i + 1 < spec.size()) {
            cur.push_back(spec[++i]);
        } else if (c == ';') {
            items.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) items.push_back(cur);

    for (const auto& it : items) {
        if (it.empty()) continue;
        size_t eq = it.find('=');
        std::string k, v;
        if (eq == std::string::npos) {
            k = Trim(it);          // 只有键名时视为布尔开关，值为 "1"
            v = "1";
        } else {
            k = Trim(it.substr(0, eq));
            v = it.substr(eq + 1);  // 值不做 Trim，保留尾部空格（可能是密钥一部分）
        }
        if (!k.empty()) p.kv_[ToLower(k)] = v;
    }
    return p;
}

void Params::Set(const std::string& k, const std::string& v) { kv_[ToLower(k)] = v; }

bool Params::Has(const std::string& k) const { return kv_.find(ToLower(k)) != kv_.end(); }

std::string Params::Get(const std::string& k, const std::string& def) const {
    auto it = kv_.find(ToLower(k));
    return it == kv_.end() ? def : it->second;
}

int Params::GetInt(const std::string& k, int def) const {
    auto it = kv_.find(ToLower(k));
    if (it == kv_.end() || it->second.empty()) return def;
    return ParseInt(it->second, k);
}

int Params::RequireInt(const std::string& k) const {
    auto it = kv_.find(ToLower(k));
    if (it == kv_.end() || it->second.empty()) {
        throw Error("缺少必需参数: " + k);
    }
    return ParseInt(it->second, k);
}

std::string Params::RequireStr(const std::string& k) const {
    auto it = kv_.find(ToLower(k));
    if (it == kv_.end() || it->second.empty()) {
        throw Error("缺少必需参数: " + k);
    }
    return it->second;
}

Bytes Params::GetKey() const {
    // key_hex 优先（十六进制字面量），否则 key 按 UTF-8 文本处理
    auto it = kv_.find("key_hex");
    if (it != kv_.end() && !it->second.empty()) {
        return HexDecode(it->second);
    }
    it = kv_.find("key");
    if (it != kv_.end()) {
        return ToBytes(it->second);
    }
    return Bytes();
}

Bytes Params::RequireKey() const {
    Bytes k = GetKey();
    if (k.empty()) throw Error("缺少必需参数: key（或 key_hex）");
    return k;
}

std::string Params::Dump() const {
    std::string s;
    for (const auto& kv : kv_) {
        if (!s.empty()) s += ";";
        s += kv.first + "=" + kv.second;
    }
    return s;
}

}  // namespace ctf
