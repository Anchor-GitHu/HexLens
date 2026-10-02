cmake_minimum_required(VERSION 3.16)
project(ctfcodec VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# 所有产物集中到 build/bin，CLI 与 DLL 同目录，省得还得手动 copy
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ---------------------------------------------------------------------------
# 源码清单
# ---------------------------------------------------------------------------
set(CTFCODEC_SOURCES
  src/common.cpp        # 参数表
  src/util.cpp          # 通用工具 + 大数进制转换
  src/registry.cpp      # 算法注册表
  src/api.cpp           # C ABI 导出层
  src/magic.cpp         # 编码自动识别
  src/selftest.cpp      # 内置已知向量自检

  src/base.cpp          # Base 家族
  src/text.cpp          # URL / HTML / QP / UU / Punycode / JWT ...
  src/unicode.cpp       # UTF / 代码页 / 零宽字符
  src/classic.cpp       # 摩尔斯 / 培根 / 波利比奥斯 / 盲文 ...
  src/cipher.cpp        # 凯撒 / 维吉尼亚 / 栅栏 / Playfair / XOR ...
  src/hash.cpp          # MD5 / SHA / CRC / HMAC
  src/binary.cpp        # 任意进制 / BCD / Gray / 位操作
)

# ---------------------------------------------------------------------------
# 共享库 ctfcodec.dll
# ---------------------------------------------------------------------------
add_library(ctfcodec SHARED ${CTFCODEC_SOURCES})
target_include_directories(ctfcodec
  PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(ctfcodec PRIVATE CTFCODEC_BUILD)

# 去掉共享库的 "lib" 前缀。MinGW 默认产出 libctfcodec.dll，而 C# 侧的
# DllImport("ctfcodec.dll") 只认这个名字（MSVC 本来就不加前缀）。
# 不统一的话，用 MinGW 编出来的库在 HexLens 里根本加载不到。
# 这是本副本相对上游唯一的改动，见 README-HEXLENS.md。
set_target_properties(ctfcodec PROPERTIES PREFIX "")

# ---------------------------------------------------------------------------
# 配套命令行程序 ctfcodec-cli.exe（动态链接上面的 DLL，顺带验证导出符号）
# ---------------------------------------------------------------------------
add_executable(ctfcodec-cli src/main.cpp)
target_include_directories(ctfcodec-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(ctfcodec-cli PRIVATE ctfcodec)
if(WIN32)
  # CommandLineToArgvW 在 shell32 里（用来正确拿到 UTF-8 命令行参数）
  target_link_libraries(ctfcodec-cli PRIVATE shell32)
endif()

# ---------------------------------------------------------------------------
# 测试程序
# ---------------------------------------------------------------------------
enable_testing()
add_executable(ctfcodec-tests tests/test_vectors.cpp)
target_link_libraries(ctfcodec-tests PRIVATE ctfcodec)
add_test(NAME vectors COMMAND ctfcodec-tests)

# ---------------------------------------------------------------------------
# 编译选项
# ---------------------------------------------------------------------------
if(MSVC)
  add_compile_options(/utf-8 /W3 /EHsc /MP)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
  # /MT 静态运行库：目标机器不需要装 VC 运行库就能用这个 DLL
  set_property(TARGET ctfcodec ctfcodec-cli ctfcodec-tests
               PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
  add_compile_options(-Wall -Wextra -Wno-unused-parameter)
  # MinGW 默认动态链接 libstdc++ / libgcc / libwinpthread，
  # 而 libwinpthread-1.dll 在多数机器上并不存在 —— Python ctypes、C# 等
  # 宿主进程加载 DLL 时会直接失败（"找不到指定的模块"）。
  # 这里统一静态链接，让 ctfcodec.dll 只依赖系统自带的 KERNEL32 + UCRT。
  add_link_options(-static)
endif()
