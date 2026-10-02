# ctfcodec —— CTF 常用编码 / 解码库

一个 Windows 平台上的 C++ 编解码库（DLL）+ 配套命令行工具，覆盖 CTF 比赛中常见的
**Base 家族、文本转义、Unicode/代码页、古典编码、经典密码、哈希摘要、二进制表示**。

设计目标就三条：**接口统一**、**二进制安全**、**不依赖第三方库**。

---

## 目录

- [1. 交付内容](#1-交付内容)
- [2. 构建](#2-构建)
- [3. 命令行工具用法](#3-命令行工具用法)
- [4. DLL 接口（C ABI）](#4-dll-接口c-abi)
- [5. 从其他语言调用](#5-从其他语言调用)
- [6. 算法清单](#6-算法清单)
- [7. 设计说明](#7-设计说明)
- [8. 测试与验证](#8-测试与验证)
- [9. 已知限制](#9-已知限制)

---

## 1. 交付内容

```
ctfcodec/
├── include/
│   └── ctfcodec.h          对外 C 头文件（唯一需要分发的头）
├── src/
│   ├── common.h/.cpp       参数表 Params
│   ├── util.h/.cpp         十六进制、大数进制转换等工具
│   ├── registry.cpp        算法注册表
│   ├── api.cpp             ★ C ABI 导出层
│   ├── magic.cpp           编码自动识别
│   ├── selftest.cpp        内置已知向量 + 往返自检
│   ├── base.cpp            Base16/32/36/45/58/62/64/85/91/92/100...
│   ├── text.cpp            URL / HTML / QP / UUencode / Punycode / JWT...
│   ├── unicode.cpp         UTF-8/16/32、GBK/Big5、零宽字符隐写...
│   ├── classic.cpp         摩尔斯 / 培根 / 波利比奥斯 / 盲文 / 敲击码...
│   ├── cipher.cpp          凯撒 / 维吉尼亚 / 栅栏 / Playfair / Enigma / XOR...
│   ├── hash.cpp            MD5 / SHA-1/2 / CRC / Adler / HMAC / NTLM
│   ├── binary.cpp          任意进制 / BCD / Gray / 位操作 / IP / 时间戳
│   └── main.cpp            ★ 配套命令行程序
├── tests/
│   └── test_vectors.cpp    C ABI 契约测试
├── examples/
│   └── ctfcodec.py         Python ctypes 封装 + 演示
├── CMakeLists.txt
├── CMakePresets.json
└── build.ps1               一键构建脚本
```

构建产物（`build-msvc/bin/` 或 `build-mingw/bin/`）：

| 文件 | 说明 |
|---|---|
| `ctfcodec.dll` | 编码库本体 |
| `ctfcodec.lib` / `libctfcodec.a` | 导入库（C/C++ 静态链接用） |
| `ctfcodec-cli.exe` | 配套命令行工具（动态调用 DLL） |
| `ctfcodec-tests.exe` | C ABI 契约测试 |

---

## 2. 构建

### 环境要求

- Windows 10/11 x64
- CMake ≥ 3.16
- 任选一套编译器：
  - **MSVC**（Visual Studio 2019/2022/2026，需含「使用 C++ 的桌面开发」工作负载）
  - **MinGW-w64 g++ ≥ 8**（如 Strawberry Perl 自带、MSYS2、w64devkit）
- Ninja（MSVC 路线需要；MinGW 路线用自带的 mingw32-make）

### 一键构建（推荐）

```powershell
# MSVC 构建 + 自动跑测试
.\build.ps1 -Test

# 用 MinGW 构建
.\build.ps1 -Toolchain mingw -Test

# 两套编译器都构建（交叉验证，最保险）
.\build.ps1 -Toolchain both -Test

# 清空重建
.\build.ps1 -Clean -Test
```

### 手动构建

```powershell
# MSVC（先在「x64 Native Tools Command Prompt」里，或手动 call vcvars64.bat）
cmake -S . -B build-msvc -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-msvc --parallel

# MinGW
cmake -S . -B build-mingw -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build-mingw --parallel
```

### 完全不用 CMake 的保底方案

某些环境里 CMake 的 Ninja 生成器会在「编译器 ABI 探测」阶段挂住（表现为
`build-msvc/CMakeFiles/CMakeScratch/*/.ninja_lock` 长期不释放）。这时可以直接调编译器：

```powershell
# --- MinGW：注意必须加 -static，否则 DLL 会依赖 libwinpthread-1.dll ---
$core = @('common','util','registry','api','magic','selftest',
          'base','text','unicode','classic','cipher','hash','binary') |
        ForEach-Object { "src/$_.cpp" }

g++ -std=c++17 -I include -I src -O2 -DCTFCODEC_BUILD -static -shared `
    -o build/bin/ctfcodec.dll $core "-Wl,--out-implib,build/lib/libctfcodec.a"

g++ -std=c++17 -I include -O2 src/main.cpp -L build/bin -lctfcodec `
    -o build/bin/ctfcodec-cli.exe
```

```bat
:: --- MSVC：在 vcvars64.bat 环境里执行 ---
cl /nologo /std:c++17 /EHsc /utf-8 /O2 /MT /DCTFCODEC_BUILD /Iinclude /Isrc /LD ^
   src\common.cpp src\util.cpp src\registry.cpp src\api.cpp src\magic.cpp ^
   src\selftest.cpp src\base.cpp src\text.cpp src\unicode.cpp src\classic.cpp ^
   src\cipher.cpp src\hash.cpp src\binary.cpp ^
   /Fe:build-msvc\bin\ctfcodec.dll /link /IMPLIB:build-msvc\bin\ctfcodec.lib

:: CLI 需要额外链接 shell32（CommandLineToArgvW，用于正确读取中文命令行）
cl /nologo /std:c++17 /EHsc /utf-8 /O2 /MT /Iinclude src\main.cpp ^
   /Fe:build-msvc\bin\ctfcodec-cli.exe /link build-msvc\bin\ctfcodec.lib shell32.lib
```

> 注意：`main.cpp` **不能**编进 DLL（它含 `main`，且依赖 shell32），它是独立的 CLI 目标。

### 只想要 DLL 给别人用

分发这三个文件即可，**目标机器不需要装 VC 运行库，也不需要 MinGW 运行库**
（MSVC 走 `/MT`，MinGW 走 `-static`）：

```
ctfcodec.dll
ctfcodec.lib        （给 C/C++ 调用方）
include\ctfcodec.h  （给 C/C++ 调用方）
```

可以用 `objdump -p ctfcodec.dll | findstr "DLL Name"` 核对，正常应只剩
`KERNEL32.dll` 与 `api-ms-win-crt-*`（后者是 Windows 10+ 自带的 UCRT）。

---

## 3. 命令行工具用法

### 直接命令

```powershell
ctfcodec-cli                            # 无参数进入交互模式
ctfcodec-cli list                       # 列出全部算法
ctfcodec-cli list Base                  # 只看某个分类
ctfcodec-cli info base64                # 查看某个算法详情
ctfcodec-cli enc <算法> [文本]           # 编码
ctfcodec-cli dec <算法> [文本]           # 解码
ctfcodec-cli magic <文本>                # 自动识别这是什么编码
ctfcodec-cli brute <文本>                # 暴力尝试所有解码，挑出可读结果
ctfcodec-cli selftest                   # 跑内置自检
```

### 常用示例

```powershell
# 基础编解码
ctfcodec-cli enc base64 "hello world"          # aGVsbG8gd29ybGQ=
ctfcodec-cli dec base64 aGVsbG8gd29ybGQ=       # hello world

# 带参数的算法（-p 可重复）
ctfcodec-cli enc caesar "HELLO" -p shift=3     # KHOOR
ctfcodec-cli enc vigenere "ATTACKATDAWN" -p key=LEMON
ctfcodec-cli enc xor "secret" -k mykey --out-hex

# 二进制数据处理
ctfcodec-cli dec gbk --in-hex D6D0             # 中
ctfcodec-cli enc base64 -f photo.png --out-hex

# 管道（CTF 里最常用）
echo aGVsbG8gd29ybGQ= | ctfcodec-cli dec base64
Get-Content data.txt -Raw | ctfcodec-cli magic

# 自动识别 + 暴力破解
ctfcodec-cli magic "aGVsbG8gd29ybGQ="
ctfcodec-cli brute "01001000 01101001"
```

### 交互模式

直接运行 `ctfcodec-cli`，进入 REPL：

```
ctfcodec v1.0.0 交互模式。输入 help 查看命令，exit 退出。

ctf> use base64            # 选定当前算法
ctf[base64]> hello         # 之后直接输入文本 = 用当前算法编码
aGVsbG8=
ctf[base64]> raw aGVsbG8=  # 用当前算法解码
hello
ctf[base64]> param shift=3 # 加参数（对带参数的算法有用）
ctf[base64]> use caesar
ctf[caesar]> HELLO
KHOOR
ctf[caesar]> magic KHOOR
...
ctf[caesar]> exit
```

交互模式支持命令：`use / enc / dec / raw / param / params / clear / list / info / magic /
brute / selftest / hex / unhex / help / exit`。

### 通用选项

| 选项 | 说明 |
|---|---|
| `-p, --param k=v` | 传参数，可重复，如 `-p shift=3 -p alphabet=...` |
| `-k, --key <密钥>` | 等价于 `--param key=<密钥>` |
| `-f, --file <文件>` | 从文件读取输入（二进制安全） |
| `--in-hex` | 输入按十六进制串解释 |
| `--out-hex` | 输出以十六进制显示 |
| `--raw` | 输出原始字节，不追加换行 |
| `-n, --top <N>` | `brute` 显示前 N 条 |
| `--all` | `brute` 显示全部结果 |
| `-` | 从标准输入读取 |

---

## 4. DLL 接口（C ABI）

全部导出函数都是 `extern "C" __cdecl`，**任何语言都能直接调用**。

### 核心函数

```c
/* 编码 / 解码：输入输出都是字节 + 长度，二进制安全 */
int ctf_encode(const char* alg, const uint8_t* in, size_t in_len,
               const char* params, uint8_t** out, size_t* out_len);
int ctf_decode(const char* alg, const uint8_t* in, size_t in_len,
               const char* params, uint8_t** out, size_t* out_len);

/* 便捷字符串版：输入 NUL 结尾，输出需用 ctf_free 释放 */
char* ctf_encode_str(const char* alg, const char* text, const char* params);
char* ctf_decode_str(const char* alg, const char* text, const char* params);

void ctf_free(void* p);              /* 释放上面所有返回的指针 */
```

**参数 `params` 格式**：`"k=v;k=v"`，例如 `"shift=3"`、`"key=SECRET"`、`"key_hex=0011aabb"`、
`"alphabet=ABC...;pad=0"`。

### 算法清单

```c
int         ctf_algo_count(void);
const char* ctf_algo_name(int index);
const char* ctf_algo_category(int index);
const char* ctf_algo_help(int index);
int         ctf_algo_reversible(int index);   /* 1 可逆 / 0 不可逆 */
int         ctf_algo_needs_param(int index);  /* 1 需要参数 */
char*       ctf_algo_list_json(void);         /* 全部清单 JSON */
```

### 自动识别与自检

```c
/* 返回 JSON 数组：[{"alg":"base64","score":88,"reason":"...","preview":"..."}] */
char* ctf_magic(const char* text);

/* 跑内置已知向量 + 往返测试，返回失败项数（0 = 全过）；report 为 JSON 报告 */
int ctf_self_test(char** report);
```

### 错误处理

```c
const char* ctf_last_error(void);   /* 线程局部，最后一次错误详情（中文） */
const char* ctf_strerror(int code); /* 状态码 -> 说明 */
```

| 状态码 | 值 | 含义 |
|---|---|---|
| `CTF_OK` | 0 | 成功 |
| `CTF_ERR_UNKNOWN_ALGO` | -1 | 算法名不存在 |
| `CTF_ERR_BAD_INPUT` | -2 | 输入不合法 |
| `CTF_ERR_NEED_PARAM` | -3 | 缺少必需参数 |
| `CTF_ERR_NOT_REVERSIBLE` | -4 | 该算法不可逆（如哈希） |
| `CTF_ERR_INTERNAL` | -5 | 内部错误 |
| `CTF_ERR_NULL_POINTER` | -6 | 传了空指针 |

> 库内所有异常都在 DLL 边界被捕获，**不会让 C++ 异常穿透到宿主进程**。

### C 使用示例

```c
#include <stdio.h>
#include "ctfcodec.h"

int main(void) {
    /* 编码 */
    char* b64 = ctf_encode_str("base64", "hello world", NULL);
    if (b64) { printf("%s\n", b64); ctf_free(b64); }

    /* 带参数 */
    char* caesar = ctf_encode_str("caesar", "HELLO", "shift=3");
    if (caesar) { printf("%s\n", caesar); ctf_free(caesar); }

    /* 二进制安全接口 */
    uint8_t* out = NULL; size_t len = 0;
    int rc = ctf_encode("base16", (const uint8_t*)"\x00\xff", 2, NULL, &out, &len);
    if (rc == CTF_OK) { printf("%.*s\n", (int)len, out); ctf_free(out); }

    return 0;
}
```

编译（MinGW）：`gcc demo.c -Iinclude -Lbuild-mingw/bin -lctfcodec -o demo.exe`

---

## 5. 从其他语言调用

### Python（ctypes，无需第三方库）

```python
from ctfcodec import CTFCodec     # examples/ctfcodec.py

c = CTFCodec(r"build-msvc\bin\ctfcodec.dll")
print(c.encode("base64", "hello world"))        # aGVsbG8gd29ybGQ=
print(c.decode("base64", "aGVsbG8gd29ybGQ="))   # hello world
print(c.encode("caesar", "HELLO", {"shift": 3}))
print(c.encode_bytes("base16", b"\x00\xff"))    # 二进制安全
print(c.magic("aGVsbG8gd29ybGQ="))              # 自动识别
```

直接运行示例看效果：

```powershell
python examples\ctfcodec.py
```

### C#

```csharp
using System;
using System.Runtime.InteropServices;
using System.Text;

class Demo {
    [DllImport("ctfcodec.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern IntPtr ctf_encode_str(string alg, string text, string par);
    [DllImport("ctfcodec.dll", CallingConvention = CallingConvention.Cdecl)]
    static extern void ctf_free(IntPtr p);

    static string Enc(string alg, string text, string par = null) {
        IntPtr p = ctf_encode_str(alg, text, par);
        if (p == IntPtr.Zero) return null;
        string s = Marshal.PtrToStringAnsi(p);
        ctf_free(p);
        return s;
    }

    static void Main() {
        Console.WriteLine(Enc("base64", "hello world"));
        Console.WriteLine(Enc("caesar", "HELLO", "shift=3"));
    }
}
```

### Go / Rust / Java(JNA) / 易语言

都是同样的 C ABI：按 `ctf_encode_str` 的函数签名声明即可。注意 `__cdecl` 调用约定。

---

## 6. 算法清单

<!-- ALGO_LIST_START -->

共 **127** 个算法，按分类列出。备注列的「可带参数」表示该算法接受 params（并非一定必需，缺必需参数时会返回 CTF_ERR_NEED_PARAM）。

### Base

| 算法 | 说明 | 备注 |
|---|---|---|
| `base16` | RFC4648 Base16（十六进制），upper=1 输出大写 | 可带参数 |
| `base32` | RFC4648 Base32（A-Z2-7），pad=0 不补 '=' | 可带参数 |
| `base32hex` | RFC4648 Base32 扩展十六进制表（0-9A-V），pad 可关闭 | 可带参数 |
| `base36` | Base36（0-9A-Z），大数进制转换，可处理超长数字串 |  |
| `base45` | RFC 9285 Base45（二维码用，字母表含空格与 $%*+-./:） |  |
| `base58` | Base58（比特币字母表），保持前导零字节，alphabet=btc/ripple/flickr | 可带参数 |
| `base58check` | Base58Check：base58 + 4 字节双 SHA256 校验和 |  |
| `base62` | Base62（0-9A-Za-z，可用 alphabet 自定义），大数进制转换 | 可带参数 |
| `base64` | 标准 Base64，支持 alphabet/url/nopad/line 参数 | 可带参数 |
| `base64url` | URL 安全 Base64（-_），默认不补 '=' | 可带参数 |
| `base85` | Adobe Ascii85(85)，z 表示四零字节，wrap=1 加 <~ ~> | 可带参数 |
| `z85` | ZeroMQ Z85，输入长度必须是 4 的倍数 |  |
| `base85rfc` | RFC 1924 Base85 字母表（大数进制） |  |
| `base91` | basE91（Joachim Henke，13/14 位分组） |  |
| `base92` | Base92（91 字符数字表，大数进制转换） |  |
| `base100` | Base100：每字节映射为 U+1F400+byte 的 emoji（UTF-8） |  |
| `radix64` | OpenPGP Radix-64：Base64 + CRC24 校验行 =XXXX | 可带参数 |
| `bcrypt64` | bcrypt 自定义字母表 Base64（./A-Za-z0-9），无填充 |  |
| `crypt64` | crypt(3) 字母表 Base64（./0-9A-Za-z），无填充 |  |

### Text

| 算法 | 说明 | 备注 |
|---|---|---|
| `url` | URL 百分号编码（默认只保留 A-Za-z0-9-_.~） | 可带参数 |
| `urldouble` | 双重 URL 百分号编码（% 也编成 %25，一次解一层） |  |
| `html` | HTML 实体编码（all=1 时非 ASCII 用数字实体） | 可带参数 |
| `css-escape` | CSS 十六进制转义（\XX 形式） |  |
| `c-escape` | C 字符串转义（\n \r \t \\ \" \0 \xNN） |  |
| `octal-escape` | 八进制转义（每字节 \NNN） |  |
| `quoted-printable` | RFC 2045 quoted-printable 编码（line 控制折行宽度） | 可带参数 |
| `uuencode` | 经典 uuencode（begin 644 file ... end） |  |
| `xxencode` | xxencode（字母表 +-0-9A-Za-z） |  |
| `punycode` | RFC 3492 Punycode 纯编解码（解码容忍 xn-- 前缀） |  |
| `jwt` | 解析 JWT：输出 Header / Payload JSON 与原始签名段（不校验签名） | 不可逆 |
| `leet` | 1337 speak（a->4 b->8 e->3 g->6 i/l->1 o->0 s->5 t->7 z->2） |  |
| `reverse` | 字符串反转（mode=char 按 UTF-8 字符，mode=byte 按字节） | 可带参数 |
| `upper` | 转大写（不可逆） | 不可逆 |
| `lower` | 转小写（不可逆） | 不可逆 |
| `swapcase` | 大小写互换（可逆） |  |
| `nato` | 北约音标字母表（sep 分隔符，lower=1 小写） | 可带参数 |
| `escape-bash` | ANSI-C 引用 $'\x41' 形式 |  |

### Unicode

| 算法 | 说明 | 备注 |
|---|---|---|
| `toutf16le` | UTF-8 文本 <-> UTF-16LE 字节（bom=1 加 BOM，解码自动识别 BOM） |  |
| `toutf16be` | UTF-8 文本 <-> UTF-16BE 字节（bom=1 加 BOM，解码自动识别 BOM） |  |
| `toutf32le` | UTF-8 文本 <-> UTF-32LE 字节（bom=1 加 BOM，解码自动识别 BOM） |  |
| `toutf32be` | UTF-8 文本 <-> UTF-32BE 字节（bom=1 加 BOM，解码自动识别 BOM） |  |
| `toutf8` | UTF-16/32 字节 -> UTF-8（BOM 自动识别；from= 可强制指定） |  |
| `utf7` | RFC 2152 UTF-7 编码（imap=1 切换 Modified UTF-7 变体） |  |
| `gbk` | GBK(936) 与 UTF-8 互转 |  |
| `gb18030` | GB18030(54936) 与 UTF-8 互转 |  |
| `big5` | Big5(950) 与 UTF-8 互转 |  |
| `shift-jis` | Shift-JIS(932) 与 UTF-8 互转 |  |
| `latin1` | CP1252(Latin-1) 与 UTF-8 互转（replace=1 时无法表示的字符变 ?） |  |
| `codepoint` | 文本 <-> U+XXXX 码点列表（sep= 分隔符，lower=1 小写） |  |
| `unicode-escape` | 文本 -> \uXXXX 转义（BMP 外自动拆 UTF-16 代理对） |  |
| `percent-u` | 文本 -> %uXXXX（按 UTF-16 码元，BMP 外拆代理对） |  |
| `numeric-entity` | 文本 -> HTML 数字实体（base=10/16，默认 10；解码两种都收） |  |
| `mysql-escape` | MySQL 字符串转义（\0 \n \r \\ \' \" \Z 与 \xNN） |  |
| `zero-width` | 零宽字符隐写（每字节 8 bit；sep=1 加 U+200D 分隔，cover= 掩护文本） |  |
| `unicode-tag` | Unicode Tags 区隐写（每字节 -> U+E0000+byte，bom=1 加 BOM） |  |
| `variation-selector` | 变体选择符隐写（高 nibble -> U+FE00+n，低 nibble -> U+E0100+n） |  |

### Classic

| 算法 | 说明 | 备注 |
|---|---|---|
| `morse` | 国际摩尔斯电码（字母空格分隔，单词用 / 分隔） | 可带参数 |
| `bacon` | 培根密码：24/26 字母表，A/B（或 0/1）五位一组 | 可带参数 |
| `a1z26` | A=1..Z=26 数字替换（支持 -/空格/逗号或无分隔） | 可带参数 |
| `polybius` | 波利比奥斯方阵 5x5 坐标编码（J 并入 I） | 可带参数 |
| `tap-code` | 敲击码：5x5 方阵，用点/数字表示行列 | 可带参数 |
| `braille` | 盲文点字：a-z 映射到 U+2801 起，支持数字与大写标记 | 可带参数 |
| `pigpen` | 猪圈密码：26 个几何符号与字母一一对应 |  |
| `semaphore` | 旗语：每个字母用两个方位数字（1-8）表示 | 可带参数 |
| `ascii-binary` | 字符 ASCII 码的 7/8 位二进制（空格分隔） | 可带参数 |
| `book-code` | 书本密码：用 book 文本中的序号或行列位置表示字符 | 可带参数 |

### Cipher

| 算法 | 说明 | 备注 |
|---|---|---|
| `caesar` | 凯撒位移：只移动字母，保持大小写与非字母 | 可带参数 |
| `rot-n` | 通用 ROT：字母表内循环位移 shift 位 | 可带参数 |
| `rot13` | ROT13：字母移 13 位，自逆 |  |
| `rot5` | ROT5：数字 0-9 移 5 位，自逆 |  |
| `rot18` | ROT18：字母 ROT13 + 数字 ROT5，自逆 |  |
| `rot47` | ROT47：可打印 ASCII(33-126) 移 47 位，自逆 |  |
| `atbash` | Atbash：字母表反转（A<->Z），自逆 |  |
| `substitution` | 单表替换：key 为 26 个字母的密文字母表 | 可带参数 |
| `affine` | 仿射密码 E(x)=(a*x+b) mod 26，要求 gcd(a,26)=1 | 可带参数 |
| `vigenere` | 维吉尼亚密码：密钥循环做字母位移 | 可带参数 |
| `beaufort` | Beaufort 变体：C=(K-P) mod 26，自逆 | 可带参数 |
| `variant-beaufort` | 变体 Beaufort：C=(P-K) mod 26 | 可带参数 |
| `autokey` | 自动密钥：密钥用完后接明文自身 | 可带参数 |
| `porta` | Porta 密码：13 组对换表，自逆 | 可带参数 |
| `gronsfeld` | Gronsfeld：key 为数字串，按位做数字位移 | 可带参数 |
| `running-key` | Running Key：key 为与明文等长的长文本 | 可带参数 |
| `railfence` | 栅栏密码：按 W 型轨迹读取，支持起始偏移 | 可带参数 |
| `scytale` | 斯巴达棒：按 n 列写出再按列读 | 可带参数 |
| `columnar` | 列置换：按密钥词字母序决定列的读取顺序 | 可带参数 |
| `reverse-block` | 按固定块大小反转块内字节顺序 | 可带参数 |
| `playfair` | Playfair 密码：5x5 方阵（I/J 合并），按对处理 | 可带参数 |
| `bifid` | Bifid 密码：Polybius 坐标行列分离，可指定 period |  |
| `hill` | Hill 密码 2x2：key 为 4 个整数，如 3,3,2,5 | 可带参数 |
| `xor` | 循环异或：key 或 key_hex，二进制安全 | 可带参数 |
| `xor-single` | 单字节异或：key 为 1 字节或 byte=65 | 可带参数 |
| `xor-brute` | 单字节异或暴力枚举：按可打印占比+字母频率打分排序 | 不可逆 |
| `xor-known-plaintext` | 已知明文（crib）推 XOR 密钥并输出明文预览 | 不可逆 |
| `enigma` | Enigma I 三转子机（I-V 转子 + 反射器 B + 插线板） |  |
| `rc4` | RC4 流密码：key 为密钥，二进制安全 | 可带参数 |
| `vernam` | Vernam/OTP：逐字节异或，key_hex 长度需 >= 输入 | 可带参数 |

### Hash

| 算法 | 说明 | 备注 |
|---|---|---|
| `md5` | MD5 摘要（128 位），可选 upper / raw | 不可逆 |
| `sha1` | SHA-1 摘要（160 位），可选 upper / raw | 不可逆 |
| `sha224` | SHA-224 摘要（224 位，SHA-256 截断版） | 不可逆 |
| `sha256` | SHA-256 摘要（256 位），可选 upper / raw | 不可逆 |
| `sha384` | SHA-384 摘要（384 位，SHA-512 截断版） | 不可逆 |
| `sha512` | SHA-512 摘要（512 位），可选 upper / raw | 不可逆 |
| `crc32` | CRC-32/ISO-HDLC 校验和，poly 可换多项式 | 不可逆 |
| `crc32c` | CRC-32C（Castagnoli，poly=0x82F63B78） | 不可逆 |
| `crc16` | CRC-16 校验和，variant=modbus/ibm/ccitt/xmodem | 不可逆 |
| `adler32` | Adler-32 校验和（zlib 用） | 不可逆 |
| `fletcher16` | Fletcher-16 校验和（双和模 255） | 不可逆 |
| `fletcher32` | Fletcher-32 校验和（双和模 65535） | 不可逆 |
| `hmac-md5` | HMAC-MD5，需要 key 或 key_hex | 不可逆 |
| `hmac-sha1` | HMAC-SHA1，需要 key 或 key_hex | 不可逆 |
| `hmac-sha256` | HMAC-SHA256，需要 key 或 key_hex | 不可逆 |
| `hmac-sha512` | HMAC-SHA512，需要 key 或 key_hex | 不可逆 |
| `ntlm` | NTLM 哈希 = MD4(UTF-16LE(密码)) | 不可逆 |

### Binary

| 算法 | 说明 | 备注 |
|---|---|---|
| `binary` | 每字节 8 位二进制串，sep 分隔（编码时自动识别 7 位 ASCII） | 可带参数 |
| `octal` | 每字节 3 位八进制，prefix=1 加 0o 前缀 | 可带参数 |
| `decimal` | 每字节十进制（0-255），sep 分隔 | 可带参数 |
| `hex-bytes` | \x41\x42 形式，解码容忍 0x/\x/裸十六进制/空白 | 可带参数 |
| `base-convert` | 任意进制大数转换，需 from 与 to 参数（2..64） | 可带参数 |
| `bcd` | 8421 BCD 编码，packed=0 关闭紧缩（每个数字一字节） | 可带参数 |
| `gray` | 格雷码：g = b ^ (b >> 1) |  |
| `bits` | 连续位流字符串（无分隔），msb=0 低位在前 | 可带参数 |
| `byteswap` | 按块反转字节序（大端 <-> 小端），size=2/4/8 | 可带参数 |
| `bitreverse` | 每字节内 8 个比特反转 |  |
| `nibbleswap` | 每字节高低 4 位交换 |  |
| `timestamp` | Unix 时间戳 <-> 可读时间（编码 = 时间转时间戳，解码 = 时间戳转时间） | 可带参数 |
| `ip` | IPv4：编码 = 点分十进制转整数，解码 = 整数转点分十进制 |  |
| `ipv6` | IPv6：编码 = 地址转 32 位十六进制，解码 = 十六进制转压缩地址形式 |  |


<!-- ALGO_LIST_END -->

---

## 7. 设计说明

### 为什么用纯 C ABI 导出？

C++ 没有跨编译器稳定的 ABI（MSVC 与 MinGW 的 name mangling、STL 布局都不一样）。
导出 `extern "C"` 函数后，**同一个 DLL 可以被 C/C++/C#/Python/Go/Java 调用**，
也避免了「用 MSVC 编译 DLL、用 MinGW 编译调用方」这类组合踩坑。

### 为什么所有算法共用一对 encode/decode 函数？

如果每个算法导出独立函数（`ctf_base64_encode`、`ctf_base64_decode`……200 多个），
清单会迅速膨胀且难以扩展。改成 `ctf_encode(alg, ...)` 后：

- 新增算法只需注册，导出表不变；
- 调用方可以按名字查表（`ctf_algo_list_json`）动态驱动；
- 带密钥/字母表的算法走统一的 `params` 字符串。

### 「不可逆」是如何表达的？

哈希类算法 `dec` 指针为 `nullptr`，调用 `ctf_decode("md5", ...)` 会返回
`CTF_ERR_NOT_REVERSIBLE`，而不是静默失败。`ctf_algo_reversible()` 可以提前查询。

### 编码宽容度

CTF 里粘贴过来的数据经常带换行、空格、大小写混乱。解码器普遍做了容错：

- Base16/32/64/58 解码忽略换行、空格、`0x`/`\x` 前缀；
- URL 解码同时认 `+`（可关）和 `%XX`；
- 摩尔斯解码同时认 `-`/`_`/`−` 和 `.`/`·`，`/`、`|`、连续空格都当词分隔；
- 十六进制解码容忍 `41 42`、`0x4142`、`\x41\x42`、`41,42` 各种写法。

---

## 8. 测试与验证

三层验证，缺一不可：

| 层次 | 位置 | 验证什么 |
|---|---|---|
| 已知向量 | `src/selftest.cpp` | 算法实现是否**正确**（对照标准向量） |
| 往返一致性 | `src/selftest.cpp` | 每个可逆算法 `dec(enc(x)) == x` |
| C ABI 契约 | `tests/test_vectors.cpp` | 导出、错误码、内存、二进制安全、清单完整性 |

运行：

```powershell
build-msvc\bin\ctfcodec-tests.exe     # C ABI 契约测试
build-msvc\bin\ctfcodec-cli.exe selftest   # 算法自检（含逐条失败详情）
```

或用 CTest：

```powershell
ctest --test-dir build-msvc --output-on-failure
```

### 实测结果

| 验证项 | 方法 | 结果 |
|---|---|---|
| 算法正确性 + 往返 | `ctfcodec-cli selftest` | **145 项通过 / 0 失败** |
| C ABI 契约 | `ctfcodec-tests.exe` | **44 项通过 / 0 失败** |
| MSVC 兼容 | cl 14.51 编译全部源文件 | 0 错误 |
| MinGW 兼容 | g++ 13.2 编译全部源文件 | 0 错误 0 警告 |
| 导出符号 | `dumpbin /exports` / `objdump -p` | 18 个纯 C 符号，两套编译器完全一致 |
| Python 调用 | `python examples/ctfcodec.py` | 通过（含 145 项内置自检） |
| DLL 外部依赖 | `objdump -p ctfcodec.dll` | 仅 `KERNEL32.dll` + UCRT，无 libwinpthread / VC 运行库 |

### 开发中实际发现并修复的缺陷

以下问题都是**被上面的测试跑出来的**，不是靠肉眼审出来的。列在这里是为了说明
「为什么现在这个库可以信」，也提醒后续维护者别再踩：

| 文件 | 缺陷 | 症状 |
|---|---|---|
| `hash.cpp` | 长度域一律按 16 字节处理 | `md5("")` 碰巧对、`md5("abc")` 全错（长度被写到 48..55，真正的 56..63 留成 0） |
| `hash.cpp` | 摘要输出未按 `digest_len` 截断 | 越界写，堆损坏（退出码 `0xC0000374`） |
| `hash.cpp` | SHA 家族输出误用小端 | 摘要中每个 32 位字整体反转（`ba7816bf` 写成 `bf1678ba`） |
| `hash.cpp` | SHA-512 的 Σ0/Σ1 旋转量写错 | sha384 / sha512 摘要全错 |
| `hash.cpp` | MD4 用「结果写回 d 再整体轮转」 | 与 RFC 1320 的 `[ABCD][DABC][CDAB][BCDA]` 不等价，NTLM 全错 |
| `classic.cpp` | morse 反查表只有 65536 项 | 键为 `(长度 << 16) \| 位序列`，索引必然越界 → 解码直接段错误 |
| `classic.cpp` | a1z26 解码把数字写回输出 | `dec a1z26 1-2-3` 得到 `1 2 3` 而不是 `ABC` |
| `binary.cpp` | IPv6 零组压缩只输出一个冒号 | `2001:db8::1` 被写成 `2001:db8:1` |
| `unicode.cpp` | 残留调试 `fprintf(stderr, ...)` | 每次 unicode-tag 调用都往 stderr 喷十六进制 |

> 另外也有几个「测试用例自己写错、库里实现其实是对的」的例子（`base36`、
> `hmac-sha256`、`xor`、`bacon` 的期望值），这些是靠 Python/独立实现交叉核对后
> 改正测试用例、而不是改库来「凑答案」的。

---

## 9. 已知限制

- **哈希类算法不可逆**：`md5`/`sha*`/`crc*`/`hmac-*` 只有编码方向。
- **代码页转换依赖 Windows API**：`gbk`/`big5`/`shift-jis` 走 `MultiByteToWideChar`，
  因此本库是 Windows 专用的；纯算法部分（Base、古典密码等）本身可移植。
- **`brute` 会尝试所有可逆算法**：它对每个算法直接试解码，失败（例如缺密钥）就跳过，
  而不是靠 `needs_param` 预先过滤——因为很多算法的参数是可选的，一刀切会漏掉
  最常见的 `base64`。需要注意它也因此可能给出一些「凑巧可读」的噪声结果。
- **`jwt` 算法只解析不验签**：它拆开 header/payload 给你看，签名校验请配合 `hmac-sha256`。
- **`magic` 是启发式打分**：给的是「最可能是什么」的排序建议，不是保证；
  真正的确认还是要 `dec` 出来看。
- 本项目面向 CTF 解题与教学，**不是密码学安全实现**（没有常量时间保证、没有侧信道防护），
  不要用于生产环境的加密需求。
