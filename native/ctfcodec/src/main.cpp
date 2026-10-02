// main.cpp —— ctfcodec 配套命令行程序
//
// 只依赖 include/ctfcodec.h（纯 C ABI），所以它同时也是「DLL 能被外部程序正常调用」
// 的活体验证：如果导出符号或调用约定有问题，这个程序链接/运行就会炸。
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "ctfcodec.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
// 必须：否则 windows.h 会定义 min/max 宏，把下面的 std::min 拆成语法错误
#define NOMINMAX
#include <windows.h>   // 必须先于 shellapi.h（后者依赖 windef.h 里的 EXTERN_C 等宏）
#include <shellapi.h>
#endif

namespace {

// ---------------------------------------------------------------------------
// Windows 下 argv 是 ANSI（中文系统为 GBK），必须走宽字符命令行再转 UTF-8，
// 否则中文参数进到库里就成乱码。
// ---------------------------------------------------------------------------
std::vector<std::string> GetArgsUtf8(int argc, char** argv) {
#ifdef _WIN32
    (void)argc;
    (void)argv;
    int      wargc = 0;
    LPWSTR*  wargv  = CommandLineToArgvW(GetCommandLineW(), &wargc);
    std::vector<std::string> out;
    if (!wargv) return out;
    for (int i = 0; i < wargc; ++i) {
        int n = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
        std::string s(n > 0 ? n - 1 : 0, '\0');
        if (n > 1) WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, &s[0], n, nullptr, nullptr);
        out.push_back(s);
    }
    LocalFree(wargv);
    return out;
#else
    return std::vector<std::string>(argv, argv + argc);
#endif
}

void SetupConsole() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
}

// ---------------------------------------------------------------------------
// 参数解析
// ---------------------------------------------------------------------------
struct Args {
    std::vector<std::string> pos;      // 位置参数
    std::vector<std::string> params;   // --param k=v
    std::string              file;     // --file
    std::string              cipherKey;  // --key
    bool                     inHex   = false;
    bool                     outHex  = false;
    bool                     raw     = false;
    bool                     showAll = false;   // brute --all
    int                      top     = 20;      // brute 显示条数
    bool                     bad     = false;
    std::string              badMsg;
};

bool StartsWithS(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

Args ParseArgs(const std::vector<std::string>& args, size_t from) {
    Args a;
    bool noMoreOpts = false;
    for (size_t i = from; i < args.size(); ++i) {
        const std::string& s = args[i];
        if (noMoreOpts) {
            a.pos.push_back(s);
            continue;
        }
        if (s == "--") {
            noMoreOpts = true;
        } else if (s == "--in-hex") {
            a.inHex = true;
        } else if (s == "--out-hex") {
            a.outHex = true;
        } else if (s == "--raw") {
            a.raw = true;
        } else if (s == "--all") {
            a.showAll = true;
        } else if ((s == "-p" || s == "--param") && i + 1 < args.size()) {
            a.params.push_back(args[++i]);
        } else if (StartsWithS(s, "--param=")) {
            a.params.push_back(s.substr(8));
        } else if ((s == "-k" || s == "--key") && i + 1 < args.size()) {
            a.params.push_back(std::string("key=") + args[++i]);
        } else if ((s == "-f" || s == "--file") && i + 1 < args.size()) {
            a.file = args[++i];
        } else if ((s == "-n" || s == "--top") && i + 1 < args.size()) {
            a.top = std::atoi(args[++i].c_str());
        } else if (!s.empty() && s[0] == '-' && s != "-") {
            a.bad    = true;
            a.badMsg = "未知选项: " + s;
            return a;
        } else {
            a.pos.push_back(s);
        }
    }
    return a;
}

std::string JoinParams(const std::vector<std::string>& v) {
    std::string s;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) s += ";";
        s += v[i];
    }
    return s;
}

bool ReadFileBytes(const std::string& path, std::string& out) {
#ifdef _WIN32
    int n = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    std::wstring w(n > 0 ? n - 1 : 0, L'\0');
    if (n > 1) MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &w[0], n);
    FILE* f = _wfopen(w.c_str(), L"rb");
#else
    FILE* f = std::fopen(path.c_str(), "rb");
#endif
    if (!f) return false;
    out.clear();
    char buf[8192];
    size_t r;
    while ((r = std::fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, r);
    std::fclose(f);
    return true;
}

std::string ReadStdin() {
    std::string out;
    char        buf[8192];
    size_t      r;
    while ((r = std::fread(buf, 1, sizeof(buf), stdin)) > 0) out.append(buf, r);
    return out;
}

// hex 字符串 -> 字节
std::string FromHex(const std::string& s) {
    std::string out;
    int         hi = -1;
    auto        val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (char c : s) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        int v = val(c);
        if (v < 0) continue;
        if (hi < 0) {
            hi = v;
        } else {
            out += static_cast<char>((hi << 4) | v);
            hi = -1;
        }
    }
    return out;
}

bool IsMostlyText(const std::string& s) {
    if (s.empty()) return true;
    size_t bad = 0;
    for (unsigned char c : s) {
        if (c == 0) return false;
        if (c < 32 && c != '\n' && c != '\r' && c != '\t') ++bad;
    }
    return bad * 100 <= s.size() * 2;
}

void PrintBytes(const std::string& data, bool forceHex, bool raw) {
    if (forceHex || !IsMostlyText(data)) {
        static const char* hexd = "0123456789abcdef";
        std::string h;
        h.reserve(data.size() * 2);
        for (unsigned char c : data) {
            h += hexd[c >> 4];
            h += hexd[c & 15];
        }
        std::fwrite(h.data(), 1, h.size(), stdout);
        std::fputc('\n', stdout);
        if (!forceHex) {
            std::fprintf(stderr, "[提示] 结果含不可打印字节，已用 hex 显示（--raw 可强制输出原始字节）\n");
        }
    } else {
        std::fwrite(data.data(), 1, data.size(), stdout);
        if (!raw) std::fputc('\n', stdout);
    }
}

// ---------------------------------------------------------------------------
// 命令实现
// ---------------------------------------------------------------------------
void PrintList(const std::string& filter) {
    int n = ctf_algo_count();
    std::printf("共 %d 个算法（版本 %s）\n\n", n, ctf_version());

    std::string lastCat;
    for (int i = 0; i < n; ++i) {
        const char* cat = ctf_algo_category(i);
        const char* nm  = ctf_algo_name(i);
        const char* hp  = ctf_algo_help(i);
        if (!cat || !nm) continue;
        if (!filter.empty() && filter != cat && filter != nm) continue;
        if (filter.empty() && lastCat != cat) {
            std::printf("== %s ==\n", cat);
            lastCat = cat;
        }
        const char* flags = "";
        if (!ctf_algo_reversible(i)) flags = " [不可逆]";
        else if (ctf_algo_needs_param(i)) flags = " [可带参数]";
        std::printf("  %-18s %s%s\n", nm, hp ? hp : "", flags);
    }
}

int PrintInfo(const std::string& alg) {
    int n = ctf_algo_count();
    for (int i = 0; i < n; ++i) {
        const char* nm = ctf_algo_name(i);
        if (!nm || alg != nm) continue;
        std::printf("算法   : %s\n分类   : %s\n说明   : %s\n可逆   : %s\n需参数 : %s\n", nm,
                    ctf_algo_category(i), ctf_algo_help(i),
                    ctf_algo_reversible(i) ? "是" : "否",
                    ctf_algo_needs_param(i) ? "是" : "否");
        return 0;
    }
    // 没找到：用一次真实调用来触发「未知算法」错误信息，顺便让用户看到确切原因
    uint8_t* out = nullptr;
    size_t   len = 0;
    ctf_encode(alg.c_str(), nullptr, 0, nullptr, &out, &len);
    std::fprintf(stderr, "找不到算法: %s\n%s\n", alg.c_str(), ctf_last_error());
    return 1;
}

int DoCodec(bool encode, const std::string& alg, std::string input, const Args& a) {
    if (a.inHex) input = FromHex(input);

    std::string params = JoinParams(a.params);
    uint8_t*    out    = nullptr;
    size_t      len    = 0;
    int         rc     = encode
                             ? ctf_encode(alg.c_str(), reinterpret_cast<const uint8_t*>(input.data()),
                                          input.size(), params.empty() ? nullptr : params.c_str(), &out, &len)
                             : ctf_decode(alg.c_str(), reinterpret_cast<const uint8_t*>(input.data()),
                                          input.size(), params.empty() ? nullptr : params.c_str(), &out, &len);
    if (rc != CTF_OK) {
        std::fprintf(stderr, "错误: %s (%s, code=%d)\n", ctf_last_error(), ctf_strerror(rc), rc);
        return 1;
    }
    std::string result(reinterpret_cast<char*>(out), len);
    ctf_free(out);
    PrintBytes(result, a.outHex, a.raw);
    return 0;
}

int DoMagic(const std::string& text) {
    char* js = ctf_magic(text.c_str());
    if (!js) {
        std::fprintf(stderr, "错误: %s\n", ctf_last_error());
        return 1;
    }
    std::string s = js;
    ctf_free(js);

    // 极简解析：逐项抽取字段，避免引入 JSON 库
    size_t pos = 0;
    int    idx = 0;
    std::printf("编码识别结果（按可能性排序）：\n");
    while (true) {
        size_t algPos = s.find("\"alg\":\"", pos);
        if (algPos == std::string::npos) break;
        algPos += 7;
        size_t algEnd = s.find('"', algPos);
        std::string alg = s.substr(algPos, algEnd - algPos);

        size_t scPos = s.find("\"score\":", algEnd);
        int    score = 0;
        if (scPos != std::string::npos) score = std::atoi(s.c_str() + scPos + 8);

        size_t rPos = s.find("\"reason\":\"", algEnd);
        std::string reason;
        if (rPos != std::string::npos) {
            rPos += 10;
            size_t rEnd = s.find('"', rPos);
            reason = s.substr(rPos, rEnd - rPos);
        }
        size_t pPos = s.find("\"preview\":\"", algEnd);
        std::string preview;
        if (pPos != std::string::npos) {
            pPos += 11;
            size_t pEnd = s.find('"', pPos);
            preview = s.substr(pPos, pEnd - pPos);
        }

        ++idx;
        std::printf("  %2d. %-16s 置信度 %3d%%  %s\n", idx, alg.c_str(), score, reason.c_str());
        if (!preview.empty()) std::printf("      预览: %s\n", preview.c_str());

        pos = algEnd;
    }
    if (idx == 0) std::printf("  （没有识别出已知编码特征）\n");
    return 0;
}

// 暴力尝试：把所有能解码的算法都试一遍，挑出结果可读的，按可信度排序
int DoBrute(const std::string& input, const Args& a) {
    struct Hit {
        std::string alg;
        std::string preview;
        int         score = 0;
    };

    // 去掉所有空白，用于识别「只是把分隔符吃掉」的伪结果
    auto Squash = [](const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') o += c;
        }
        return o;
    };
    const std::string squashedIn = Squash(input);

    const int        n = ctf_algo_count();
    std::vector<Hit> hits;
    std::printf("对 %zu 字节输入尝试自动解码...\n\n", input.size());

    for (int i = 0; i < n; ++i) {
        const char* nm = ctf_algo_name(i);
        if (!nm || !ctf_algo_reversible(i)) continue;
        // 注意：这里**不**用 ctf_algo_needs_param 过滤。
        // 很多算法（base64/url/hex 等）参数是可选的，但标记上不好区分「可选」和
        // 「必需」，靠 needs_param 一刀切会让 brute 漏掉最常见的编码。
        // 直接试解码，缺参数的算法自然会失败被跳过。

        uint8_t* out = nullptr;
        size_t   len = 0;
        if (ctf_decode(nm, reinterpret_cast<const uint8_t*>(input.data()), input.size(), nullptr,
                       &out, &len) != CTF_OK) {
            continue;
        }
        std::string r(reinterpret_cast<char*>(out), len);
        ctf_free(out);

        if (r.empty() || r == input) continue;
        if (!IsMostlyText(r)) continue;
        // 过滤伪结果：url / css-escape 这类对普通文本是恒等变换，
        // 解出来的只是把空格搬走，不是真的解码。
        if (Squash(r) == squashedIn) continue;

        size_t printable = 0, alnum = 0;
        for (unsigned char c : r) {
            if (c >= 32 && c < 127) ++printable;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) ++alnum;
        }
        const int pct = static_cast<int>(printable * 100 / r.size());
        if (pct < 85) continue;

        // 打分：可打印占比为主，字母数字占比为辅（真正的明文通常两者都高）
        Hit h;
        h.alg   = nm;
        h.score = pct * 2 + static_cast<int>(alnum * 100 / r.size());

        for (char c : r) {
            if (h.preview.size() >= 70) {
                h.preview += "...";
                break;
            }
            if (c == '\n') h.preview += "\\n";
            else if (c == '\r') h.preview += "\\r";
            else if (c == '\t') h.preview += "\\t";
            else h.preview += c;
        }
        hits.push_back(std::move(h));
    }

    std::stable_sort(hits.begin(), hits.end(),
                     [](const Hit& x, const Hit& y) { return x.score > y.score; });

    const size_t top  = static_cast<size_t>(a.top < 1 ? 1 : a.top);
    const size_t show = a.showAll ? hits.size() : std::min(hits.size(), top);
    for (size_t i = 0; i < show; ++i) {
        std::printf("  %2zu. [%-16s] %s\n", i + 1, hits[i].alg.c_str(), hits[i].preview.c_str());
    }

    if (hits.empty()) {
        std::printf("  没有可读的解码结果。可以试试: magic <数据> 或 enc/dec 指定算法。\n");
    } else {
        std::printf("\n共 %zu 个算法解出可读结果", hits.size());
        if (show < hits.size()) std::printf("，上面按可信度显示前 %zu 条（--all 看全部）", show);
        std::printf("。\n");
    }
    return 0;
}

int DoSelfTest() {
    char* report = nullptr;
    int   failed = ctf_self_test(&report);
    std::string js = report ? report : "";
    if (report) ctf_free(report);

    auto getInt = [&](const std::string& key) -> int {
        size_t p = js.find("\"" + key + "\":");
        if (p == std::string::npos) return -1;
        return std::atoi(js.c_str() + p + key.size() + 3);
    };

    std::printf("自检结果: 总计 %d, 通过 %d, 失败 %d\n", getInt("total"), getInt("passed"),
                getInt("failed"));
    if (failed > 0) {
        std::printf("\n失败项:\n");
        size_t pos = js.find("\"failures\":[");
        while (pos != std::string::npos) {
            size_t c = js.find("\"case\":\"", pos);
            if (c == std::string::npos) break;
            c += 8;
            size_t ce = js.find('"', c);
            std::string cs = js.substr(c, ce - c);
            size_t d = js.find("\"detail\":\"", ce);
            std::string ds;
            if (d != std::string::npos) {
                d += 10;
                size_t de = js.find('"', d);
                ds = js.substr(d, de - d);
            }
            std::printf("  ✗ %s\n      %s\n", cs.c_str(), ds.c_str());
            pos = ce;
        }
    }
    return failed;
}

void PrintHelp() {
    std::printf(
        "ctfcodec —— CTF 常用编码/解码工具  v%s\n"
        "\n"
        "用法:\n"
        "  ctfcodec-cli                          进入交互模式\n"
        "  ctfcodec-cli list [分类|算法名]       列出全部算法\n"
        "  ctfcodec-cli info <算法>              查看算法详情\n"
        "  ctfcodec-cli enc <算法> [文本]        编码\n"
        "  ctfcodec-cli dec <算法> [文本]        解码\n"
        "  ctfcodec-cli magic <文本>             自动识别编码类型\n"
        "  ctfcodec-cli brute <文本>             暴力尝试所有解码\n"
        "  ctfcodec-cli selftest                 运行内置自检\n"
        "\n"
        "通用选项:\n"
        "  -p, --param k=v    传参数（可多次），如 -p shift=3 -p key=SECRET\n"
        "  -k, --key <密钥>   等价于 --param key=<密钥>\n"
        "  -f, --file <文件>  从文件读取输入（二进制安全）\n"
        "      --in-hex       输入是十六进制串\n"
        "      --out-hex      输出以十六进制显示\n"
        "      --raw          输出原始字节，不追加换行\n"
        "  -n, --top <N>      brute 显示前 N 条（默认 20）\n"
        "      --all          brute 显示全部\n"
        "  -                    从标准输入读取\n"
        "\n"
        "示例:\n"
        "  ctfcodec-cli enc base64 \"hello world\"\n"
        "  ctfcodec-cli dec base64 aGVsbG8gd29ybGQ=\n"
        "  ctfcodec-cli enc caesar \"HELLO\" -p shift=3\n"
        "  ctfcodec-cli enc xor \"secret\" -k mykey --out-hex\n"
        "  ctfcodec-cli dec gbk --in-hex D6D0\n"
        "  echo aGVsbG8= | ctfcodec-cli dec base64\n"
        "  ctfcodec-cli magic \"aGVsbG8gd29ybGQ=\"\n"
        "\n",
        ctf_version());
}

// ---------------------------------------------------------------------------
// 交互模式
// ---------------------------------------------------------------------------
std::vector<std::string> Tokenize(const std::string& line) {
    std::vector<std::string> v;
    std::string              cur;
    bool                     inQuote = false;
    char                     qc      = 0;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (inQuote) {
            if (c == qc) {
                inQuote = false;
            } else if (c == '\\' && i + 1 < line.size()) {
                cur += line[++i];
            } else {
                cur += c;
            }
        } else if (c == '"' || c == '\'') {
            inQuote = true;
            qc      = c;
        } else if (c == ' ' || c == '\t') {
            if (!cur.empty()) {
                v.push_back(cur);
                cur.clear();
            }
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) v.push_back(cur);
    return v;
}

int Repl() {
    std::string curAlg;
    std::vector<std::string> params;

    std::printf("ctfcodec v%s 交互模式。输入 help 查看命令，exit 退出。\n", ctf_version());
    std::printf("提示: 先用 use <算法> 选定算法，之后直接输入文本即可编码。\n\n");

    std::string line;
    while (true) {
        std::string prompt = curAlg.empty() ? "ctf> " : ("ctf[" + curAlg + "]> ");
        std::printf("%s", prompt.c_str());
        std::fflush(stdout);
        if (!std::getline(std::cin, line)) break;
        if (!line.empty() && line.back() == '\r') line.pop_back();

        auto tok = Tokenize(line);
        if (tok.empty()) continue;

        std::string cmd = tok[0];
        if (cmd == "exit" || cmd == "quit" || cmd == "q") break;

        if (cmd == "help" || cmd == "?") {
            std::printf(
                "命令:\n"
                "  use <算法>          设定当前算法（之后直接输入文本 = 编码）\n"
                "  enc <算法> <文本>   编码\n"
                "  dec <算法> <文本>   解码\n"
                "  raw <文本>          用当前算法解码（等价 dec <当前算法>）\n"
                "  param k=v           添加参数（如 param shift=3）\n"
                "  params              查看当前参数；clear 清空参数\n"
                "  list [分类]         列出算法\n"
                "  info <算法>         查看算法详情\n"
                "  magic <文本>        自动识别\n"
                "  brute <文本>        暴力尝试解码\n"
                "  selftest            运行自检\n"
                "  hex <文本>          把文本转成十六进制\n"
                "  unhex <十六进制>    把十六进制转回文本\n"
                "  exit                退出\n");
            continue;
        }

        if (cmd == "list") {
            PrintList(tok.size() > 1 ? tok[1] : "");
            continue;
        }
        if (cmd == "selftest") {
            DoSelfTest();
            continue;
        }
        if (cmd == "use") {
            if (tok.size() < 2) {
                std::printf("用法: use <算法>\n");
            } else {
                curAlg = tok[1];
                std::printf("当前算法: %s\n", curAlg.c_str());
            }
            continue;
        }
        if (cmd == "param") {
            for (size_t i = 1; i < tok.size(); ++i) params.push_back(tok[i]);
            std::printf("参数已设置\n");
            continue;
        }
        if (cmd == "params") {
            std::printf("当前参数: %s\n", JoinParams(params).c_str());
            continue;
        }
        if (cmd == "clear") {
            params.clear();
            std::printf("参数已清空\n");
            continue;
        }
        if (cmd == "hex") {
            std::string text = line.substr(line.find("hex") + 3);
            while (!text.empty() && text[0] == ' ') text.erase(0, 1);
            for (unsigned char c : text) std::printf("%02x", c);
            std::printf("\n");
            continue;
        }
        if (cmd == "unhex") {
            std::string text = line.substr(line.find("unhex") + 5);
            while (!text.empty() && text[0] == ' ') text.erase(0, 1);
            std::string r = FromHex(text);
            PrintBytes(r, false, false);
            continue;
        }
        if (cmd == "magic" || cmd == "brute" || cmd == "info") {
            std::string rest = line.substr(cmd.size());
            while (!rest.empty() && rest[0] == ' ') rest.erase(0, 1);
            if (cmd == "magic") DoMagic(rest);
            else if (cmd == "brute") DoBrute(rest, Args());
            else PrintInfo(rest);
            continue;
        }

        // enc / dec / raw
        Args a;
        a.params = params;
        bool        encode = true;
        std::string text;
        std::string alg;

        if (cmd == "enc" || cmd == "dec") {
            encode = (cmd == "enc");
            if (tok.size() < 3) {
                std::printf("用法: %s <算法> <文本>\n", cmd.c_str());
                continue;
            }
            alg  = tok[1];
            text = line.substr(line.find(tok[1]) + tok[1].size());
            while (!text.empty() && text[0] == ' ') text.erase(0, 1);
        } else if (cmd == "raw") {
            if (curAlg.empty()) {
                std::printf("请先用 use <算法> 指定算法\n");
                continue;
            }
            encode = false;
            alg    = curAlg;
            text   = line.substr(3);
            while (!text.empty() && text[0] == ' ') text.erase(0, 1);
        } else {
            // 直接输入文本：用当前算法编码
            if (curAlg.empty()) {
                std::printf("未知命令: %s（输入 help 查看帮助）\n", cmd.c_str());
                continue;
            }
            encode = true;
            alg    = curAlg;
            text   = line;
        }

        // 去掉包裹的引号
        if (text.size() >= 2 && ((text.front() == '"' && text.back() == '"') ||
                                 (text.front() == '\'' && text.back() == '\''))) {
            text = text.substr(1, text.size() - 2);
        }
        DoCodec(encode, alg, text, a);
    }

    std::printf("再见 (・∀・)\n");
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    SetupConsole();
    std::vector<std::string> args = GetArgsUtf8(argc, argv);

    if (args.size() <= 1) return Repl();

    const std::string& cmd = args[1];
    if (cmd == "help" || cmd == "-h" || cmd == "--help") {
        PrintHelp();
        return 0;
    }
    if (cmd == "version" || cmd == "--version" || cmd == "-v") {
        std::printf("ctfcodec %s (ABI %d, 算法 %d 个)\n", ctf_version(), ctf_abi_version(),
                    ctf_algo_count());
        return 0;
    }

    Args a = ParseArgs(args, 2);
    if (a.bad) {
        std::fprintf(stderr, "%s\n", a.badMsg.c_str());
        return 2;
    }

    // 准备输入：--file > 位置参数 > stdin
    auto PrepareInput = [&](size_t posIndex) -> std::string {
        if (!a.file.empty()) {
            std::string data;
            if (!ReadFileBytes(a.file, data)) {
                std::fprintf(stderr, "无法读取文件: %s\n", a.file.c_str());
                std::exit(3);
            }
            return data;
        }
        if (a.pos.size() > posIndex) {
            std::string s = a.pos[posIndex];
            for (size_t i = posIndex + 1; i < a.pos.size(); ++i) s += " " + a.pos[i];
            if (s == "-") return ReadStdin();
            return s;
        }
        return ReadStdin();
    };

    if (cmd == "list") {
        PrintList(a.pos.empty() ? "" : a.pos[0]);
        return 0;
    }
    if (cmd == "info") {
        if (a.pos.empty()) {
            std::fprintf(stderr, "用法: ctfcodec-cli info <算法>\n");
            return 2;
        }
        return PrintInfo(a.pos[0]);
    }
    if (cmd == "magic") {
        return DoMagic(PrepareInput(0));
    }
    if (cmd == "brute") {
        return DoBrute(PrepareInput(0), a);
    }
    if (cmd == "selftest" || cmd == "test") {
        return DoSelfTest();
    }
    if (cmd == "enc" || cmd == "dec") {
        if (a.pos.empty()) {
            std::fprintf(stderr, "用法: ctfcodec-cli %s <算法> [文本]\n", cmd.c_str());
            return 2;
        }
        std::string input = PrepareInput(1);
        return DoCodec(cmd == "enc", a.pos[0], input, a);
    }

    std::fprintf(stderr, "未知命令: %s\n运行 ctfcodec-cli help 查看用法。\n", cmd.c_str());
    return 2;
}
