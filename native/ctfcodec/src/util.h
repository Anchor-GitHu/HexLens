// util.h —— 无依赖的小工具：进制、十六进制、字符串处理、大数进制转换
#pragma once

#include <string>
#include <vector>

#include "common.h"

namespace ctf {

// ------------------------------ 字符串 ------------------------------------
std::string ToLower(std::string s);
std::string ToUpper(std::string s);
std::string Trim(const std::string& s);
bool        IEquals(const std::string& a, const std::string& b);
bool        StartsWith(const std::string& s, const std::string& prefix);
bool        EndsWith(const std::string& s, const std::string& suffix);
std::vector<std::string> Split(const std::string& s, char sep);
std::string Replace(const std::string& s, const std::string& from, const std::string& to);
std::string Format(const char* fmt, ...);

// 字节 <-> 字符串（原样映射，不做编码转换）
std::string Str(const Bytes& b);
Bytes       ToBytes(const std::string& s);
Bytes       Concat(const Bytes& a, const Bytes& b);

// ------------------------------ 十六进制 ----------------------------------
bool        IsHexDigit(char c);
int         HexVal(char c);                                  // 非法返回 -1
std::string HexEncode(const Bytes& b, bool upper = false);
// 宽松解析：容忍空白、逗号、换行、0x / \x / % 前缀；长度为奇数时抛 Error
Bytes       HexDecode(const std::string& s);
// 解析 "hex:4142" / "str:AB" / 裸文本（默认按 UTF-8 文本）
Bytes       ParseByteLiteral(const std::string& s);

// ------------------------------ 断言/解析 ---------------------------------
void        Require(bool cond, const std::string& msg);
int         ParseInt(const std::string& s, const std::string& what);

// --------------------------- 大数任意进制转换 ------------------------------
// digits    : 输入数字串（不含前缀），字符大小写不敏感地按 alphabet 解释
// from_base : 输入进制（2..64），若为 0 则用 alphabet.size()
// to_base   : 输出进制（2..64）
// alphabet  : 数字表，长度必须 >= max(from_base, to_base)
// 内部用「大数除基取余」实现，可处理任意长度输入（CTF 里常见超长十进制）。
std::string BigIntBaseConvert(const std::string& digits,
                              int                from_base,
                              int                to_base,
                              const std::string& alphabet);

// 标准数字表
extern const char* kAlphaDigits62;    // 0-9 A-Z a-z
extern const char* kAlphaDigits36;    // 0-9 A-Z
extern const char* kAlphaBase58;      // 比特币字母表
extern const char* kAlphaBase58Ripple;

}  // namespace ctf
