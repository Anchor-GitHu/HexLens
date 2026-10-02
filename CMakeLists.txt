# =============================================================================
#  HexLens —— 顶层 CMake 构建
#
#  设计说明
#  --------
#  这个项目由两部分组成，CMake 在其中扮演的角色并不相同：
#
#    ① 原生编码库（native/ctfcodec，C++17）—— CMake 的**原生领域**，
#       直接 add_subdirectory 编出 ctfcodec.dll。
#
#    ② C# / WPF 应用（src/、tests/）—— CMake **没有原生 C# 支持**
#       （3.29 仍未把 C# 作为一等语言）。所以这里把 CMake 当作**编排层**：
#       用 add_custom_target 调 dotnet CLI，并显式声明它们之间的依赖顺序。
#
#  最终效果：一条 `cmake --build` 就能走完「原生库 → Core → App → Tests → 跑测试」全流程，
#  不再需要单独的 PowerShell 脚本。
#
#  用法
#  ----
#    cmake -S . -B build -G Ninja
#    cmake --build build                 # 默认目标：编全部 + 跑测试
#    cmake --build build --target publish   # 额外产出 dist/ 里的两个版本
#    ctest --test-dir build              # 跑原生库自带的标准向量自检
# =============================================================================

cmake_minimum_required(VERSION 3.16)

project(HexLens
        VERSION 1.2.0
        DESCRIPTION "CTF 向十六进制编辑器与藏匿文件自动识别"
        LANGUAGES CXX)

# ⚠️ 必须写在**顶层**：enable_testing() 只对「调用它的那个目录及其子目录」生效，
#    只在 native/ctfcodec 里调用的话，`ctest --test-dir build` 会报 "No tests were found"。
enable_testing()

# ── 构建配置 ────────────────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "构建类型" FORCE)
endif()

set(HEXLENS_DOTNET_CONFIG "Debug" CACHE STRING "dotnet 的配置（Debug / Release）")
set(HEXLENS_RUN_TESTS     ON      CACHE BOOL   "构建后是否运行 C# 测试")

# 整个仓库里 dotnet 的家目录都限制在仓库内 —— 离线/沙箱环境下更稳，
# 也不往用户目录里写东西（这一点原来的 build.ps1 也是这么做的）。
set(HEXLENS_DOTNET_HOME "${CMAKE_SOURCE_DIR}/.dotnet")
set(HEXLENS_NUGET_DIR   "${CMAKE_SOURCE_DIR}/.nuget/packages")

set(HEXLENS_CORE_PROJECT  "${CMAKE_SOURCE_DIR}/src/HexLens.Core/HexLens.Core.csproj")
set(HEXLENS_APP_PROJECT   "${CMAKE_SOURCE_DIR}/src/HexLens.App/HexLens.App.csproj")

# ── 测试套件是可选的 ────────────────────────────────────────────────────────
#   本仓库**只跟踪主程序**（src/ + native/ + 构建入口），tests/ 属于开发用周边，
#   不随仓库分发。所以这里要先探测：目录不存在就整块跳过测试目标，
#   否则 clone 下来会直接构建失败。
set(HEXLENS_TESTS_PROJECT "${CMAKE_SOURCE_DIR}/tests/HexLens.Tests/HexLens.Tests.csproj")
set(HEXLENS_TESTS_EXE     "${CMAKE_SOURCE_DIR}/tests/HexLens.Tests/bin/${HEXLENS_DOTNET_CONFIG}/net10.0/HexLens.Tests.exe")

if(EXISTS "${HEXLENS_TESTS_PROJECT}")
  set(HEXLENS_HAS_TESTS ON)
else()
  set(HEXLENS_HAS_TESTS OFF)
  message(STATUS "tests/ 不存在 —— 跳过测试目标（本仓库只跟踪主程序）")
endif()

# DllImport("ctfcodec.dll") 只在 exe 同目录查找，所以原生库必须落到这里，
# 再由 csproj 平铺到输出目录（详见 native/ctfcodec/README-HEXLENS.md）。
set(HEXLENS_APP_LIB_DIR "${CMAKE_SOURCE_DIR}/src/HexLens.App/lib")

find_program(HEXLENS_DOTNET NAMES dotnet)

if(NOT HEXLENS_DOTNET)
  message(FATAL_ERROR "未找到 dotnet CLI —— 构建 C# 部分需要 .NET SDK（本项目用 net10.0）")
endif()

message(STATUS "dotnet          : ${HEXLENS_DOTNET}")
message(STATUS "dotnet 配置      : ${HEXLENS_DOTNET_CONFIG}")

# ⚠️⚠️ 路径必须全是 ASCII —— 这是本项目最容易踩的构建坑，先说清楚。
#
#   GNU 工具链（Ninja / MinGW Make）在 Windows 上**处理不了非 ASCII 路径**，报错形如：
#     ninja: error: FindFirstFileExA(.../记事本/...): The filename, directory name,
#            or volume label syntax is incorrect.
#     mingw32-make[2]: stat: .../common.cpp: Illegal byte sequence
#
#   更坑的是它的表现：**首次全新建能过，第二次增量构建必挂** —— 很容易误判成"偶发"。
#
#   解法：给项目建一个纯 ASCII 路径的 junction，然后从那里构建：
#     New-Item -ItemType Junction -Path C:\HexLens -Target "<本项目真实路径>"
#     cmake -S C:\HexLens -B C:\HexLens\build -G Ninja
#   junction 是透明的，产物仍然落在真实目录里，不需要移动任何文件。
#
#   这里不做自动检测（CMake 正则处理 Unicode 不可靠，容易误报），
#   改成无条件提示一次 —— 路径没问题的话这行字可以忽略。
if(WIN32)
  message(STATUS "路径提示         : 若本路径含中文/非 ASCII 字符，Ninja/MinGW 的增量构建会失败，")
  message(STATUS "                   请建 ASCII junction 后从那里构建（见 CMakeLists.txt 顶部注释）")
endif()

# ── ① 原生编码库 ────────────────────────────────────────────────────────────
# native/ctfcodec 自带 cmake_minimum_required / project()，作为子目录加入时
# 会重设 CMAKE_RUNTIME_OUTPUT_DIRECTORY 等变量 —— 这里先存后恢复，避免影响顶层。
set(_saved_runtime_dir "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
set(_saved_library_dir "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
set(_saved_archive_dir "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}")

add_subdirectory(native/ctfcodec ${CMAKE_BINARY_DIR}/native)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${_saved_runtime_dir}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${_saved_library_dir}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${_saved_archive_dir}")

# ── ② 把编好的 DLL 放到 C# 项目要求的位置 ──────────────────────────────────
add_custom_command(
  OUTPUT  "${HEXLENS_APP_LIB_DIR}/ctfcodec.dll"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${HEXLENS_APP_LIB_DIR}"
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different
          "$<TARGET_FILE:ctfcodec>" "${HEXLENS_APP_LIB_DIR}/ctfcodec.dll"
  DEPENDS ctfcodec
  COMMENT "原生库 → src/HexLens.App/lib/ctfcodec.dll"
  VERBATIM)

add_custom_target(hexlens-native-dep
                  DEPENDS "${HEXLENS_APP_LIB_DIR}/ctfcodec.dll")

# ── dotnet 构建的公共封装 ──────────────────────────────────────────────────
# 说明：CMake 不解析 .csproj 的依赖，所以每个目标都要显式写出它依赖谁，
#       否则并行构建时 App 可能在 Core 之前开跑。
function(hexlens_add_dotnet_target name project)
  cmake_parse_arguments(ARG "" "" "DEPENDS" ${ARGN})

  add_custom_target(${name}
    COMMAND "${CMAKE_COMMAND}" -E env
            "DOTNET_CLI_HOME=${HEXLENS_DOTNET_HOME}"
            "NUGET_PACKAGES=${HEXLENS_NUGET_DIR}"
            "DOTNET_NOLOGO=1"
            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1"
            "${HEXLENS_DOTNET}" build "${project}"
            -c "${HEXLENS_DOTNET_CONFIG}" --nologo -v q
    COMMENT "dotnet build ${project}"
    USES_TERMINAL
    VERBATIM)

  if(ARG_DEPENDS)
    add_dependencies(${name} ${ARG_DEPENDS})
  endif()
endfunction()

# ── ③ C# 部分：Core → App（Tests 可选）─────────────────────────────────────
hexlens_add_dotnet_target(hexlens-core  "${HEXLENS_CORE_PROJECT}")

hexlens_add_dotnet_target(hexlens-app   "${HEXLENS_APP_PROJECT}"
                          DEPENDS hexlens-core hexlens-native-dep)

if(HEXLENS_HAS_TESTS)
  hexlens_add_dotnet_target(hexlens-tests "${HEXLENS_TESTS_PROJECT}"
                            DEPENDS hexlens-core)
endif()

# ── ④ 跑测试 ────────────────────────────────────────────────────────────────
if(HEXLENS_HAS_TESTS)
  add_custom_target(hexlens-test
    COMMAND "${HEXLENS_TESTS_EXE}"
    DEPENDS hexlens-tests
    COMMENT "运行 HexLens 核心测试"
    USES_TERMINAL
    VERBATIM)
endif()

# 原生库的标准向量自检（native/ctfcodec 里已经 add_test 注册过）
add_custom_target(hexlens-native-test
  COMMAND "$<TARGET_FILE:ctfcodec-tests>"
  DEPENDS ctfcodec-tests
  COMMENT "运行原生库标准向量自检"
  USES_TERMINAL
  VERBATIM)

# ── ⑤ 发布（产出 dist/ 里的小版与大版）────────────────────────────────────
add_custom_target(hexlens-publish
  COMMAND "${CMAKE_COMMAND}" -E env
          "DOTNET_CLI_HOME=${HEXLENS_DOTNET_HOME}"
          "NUGET_PACKAGES=${HEXLENS_NUGET_DIR}"
          "DOTNET_NOLOGO=1"
          "${HEXLENS_DOTNET}" publish "${HEXLENS_APP_PROJECT}"
          -c Release -o "${CMAKE_SOURCE_DIR}/dist/HexLens-lite" --no-self-contained --nologo -v q
  COMMAND "${CMAKE_COMMAND}" -E env
          "DOTNET_CLI_HOME=${HEXLENS_DOTNET_HOME}"
          "NUGET_PACKAGES=${HEXLENS_NUGET_DIR}"
          "DOTNET_NOLOGO=1"
          "${HEXLENS_DOTNET}" publish "${HEXLENS_APP_PROJECT}"
          -c Release -o "${CMAKE_SOURCE_DIR}/dist/HexLens-full" -r win-x64
          --self-contained true --nologo -v q
  # 发布包里不要调试符号（.pdb）：
  #   ① 它是给调试器用的，使用者用不上；
  #   ② 会记录源码路径 —— 本项目已确认 pdb 里只有 SourceLink 的映射配置
  #      （形如 C:\HexLens\* → GitHub 提交 URL），不含真实用户目录，
  #      但没必要往外带，顺手清掉更干净。
  COMMAND "${CMAKE_COMMAND}" -E rm -f
          "${CMAKE_SOURCE_DIR}/dist/HexLens-lite/HexLens.App.pdb"
          "${CMAKE_SOURCE_DIR}/dist/HexLens-lite/HexLens.Core.pdb"
          "${CMAKE_SOURCE_DIR}/dist/HexLens-full/HexLens.App.pdb"
          "${CMAKE_SOURCE_DIR}/dist/HexLens-full/HexLens.Core.pdb"
  DEPENDS hexlens-native-dep
  COMMENT "发布 dist/HexLens-lite 与 dist/HexLens-full（并去掉 .pdb）"
  USES_TERMINAL
  VERBATIM)

# ── 默认目标 ────────────────────────────────────────────────────────────────
# 不带参数构建时：编原生库 → 编 C# 主程序（有 tests 的话再跑测试）。
# 用 ALL 让 `cmake --build build` 直接得到完整产物。
add_custom_target(hexlens-all ALL
  COMMENT "HexLens：原生库 → Core → App"
  VERBATIM)

add_dependencies(hexlens-all hexlens-app hexlens-native-test)

if(HEXLENS_HAS_TESTS)
  add_dependencies(hexlens-all hexlens-tests)
  if(HEXLENS_RUN_TESTS)
    add_dependencies(hexlens-all hexlens-test)
  endif()
endif()

message(STATUS "tests/ 已存在      : ${HEXLENS_HAS_TESTS}")
message(STATUS "构建后运行 C# 测试: ${HEXLENS_RUN_TESTS}")
