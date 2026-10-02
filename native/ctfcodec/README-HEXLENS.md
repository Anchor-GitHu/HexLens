# native/ctfcodec —— 本项目内置的原生编码库

HexLens 的「编码」视图依赖这个库：**127 个算法 / 7 大类**
（Base、Text、Unicode、Classic、Cipher、Hash、Binary），C++17 实现，导出**纯 C ABI**。

**源码完整地放在本目录**（`include/` `src/` `tests/` `examples/`），
顶层 `CMakeLists.txt` 用 CMake 就地编出 `ctfcodec.dll` —— 不依赖任何外部项目，也不依赖预编译二进制。

## 目录

| 路径 | 内容 |
|---|---|
| `include/ctfcodec.h` | 公开头文件（C ABI，18 个导出函数） |
| `src/` | 实现（base / text / unicode / classic / cipher / hash / binary / magic / api / registry …） |
| `tests/test_vectors.cpp` | 标准向量自检（145 项） |
| `examples/` | C 与 Python 调用示例 |
| `CMakeLists.txt` | 构建定义 |

## 怎么构建

由 HexLens 的构建脚本统一驱动：

```powershell
cmake -S C:\HexLens -B C:\HexLens\build -G Ninja   # 配置（只需一次）
cmake --build C:\HexLens\build                     # 原生库 → Core → App → Tests
```

也可以单独构建（需要 CMake ≥ 3.16 + C++17 编译器）：

```powershell
cd native\ctfcodec
.\build.ps1                    # MSVC
.\build.ps1 -Toolchain mingw   # MinGW
```

## 产物去哪

顶层 `CMakeLists.txt` 把编好的 `ctfcodec.dll` 放到 `src/HexLens.App/lib/`，
再由 `HexLens.App.csproj` 用 `Link="ctfcodec.dll"` 平铺到程序输出目录（exe 同目录）。

⚠️ **必须平铺，不能留在 `lib\` 子目录**：`DllImport` 只在 exe 同目录查找，放进子目录会加载失败。

`lib/*.dll` **不是源码，不入库**（`.gitignore` 已排除）——它由本目录的源码构建产生。
没有 C++ 编译器时构建不会中断，只是「编码识别」功能显示为不可用，其余分析能力不受影响。

## CMakeLists 里的一处设置

```cmake
set_target_properties(ctfcodec PROPERTIES PREFIX "")
```

**原因**：MinGW 默认给共享库加 `lib` 前缀，产出 `libctfcodec.dll`；
而 C# 侧的 `DllImport("ctfcodec.dll")` 只认这个名字（MSVC 本来不加前缀）。
去掉前缀让两套工具链的产物名一致。

## 已知问题

`ctf_algo_list_json()` 导出的 JSON 在 help 文本含反斜杠时**没有转义**
（如 `"help":"CSS 十六进制转义（\XX 形式）"`），任何严格 JSON 解析器都会拒绝整份清单。
HexLens 因此改用逐项 API（`ctf_algo_count/name/category/help/...`）读取算法清单，绕开了这个接口。
