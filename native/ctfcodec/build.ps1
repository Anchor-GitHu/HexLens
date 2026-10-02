# build.ps1 —— ctfcodec 一键构建脚本
#
# 用法：
#   .\build.ps1                     # 用 MSVC 构建（默认）
#   .\build.ps1 -Toolchain mingw    # 用 MinGW-w64 g++ 构建
#   .\build.ps1 -Toolchain both     # 两套都构建（交叉验证）
#   .\build.ps1 -Clean              # 先清空构建目录
#   .\build.ps1 -Test               # 构建后跑测试 + 自检
#
[CmdletBinding()]
param(
    [ValidateSet('msvc', 'mingw', 'both')]
    [string]$Toolchain = 'msvc',
    [switch]$Clean,
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Set-Location $root

function Find-VcVars {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $inst = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($inst) {
            $p = Join-Path $inst 'VC\Auxiliary\Build\vcvars64.bat'
            if (Test-Path $p) { return $p }
        }
    }
    foreach ($v in @("${env:ProgramFiles}\Microsoft Visual Studio", "${env:ProgramFiles(x86)}\Microsoft Visual Studio")) {
        if (-not (Test-Path $v)) { continue }
        $found = Get-ChildItem $v -Directory -ErrorAction SilentlyContinue |
                 ForEach-Object { Join-Path $_.FullName 'VC\Auxiliary\Build\vcvars64.bat' } |
                 Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($found) { return $found }
    }
    return $null
}

function Build-Msvc {
    Write-Host "`n=== 使用 MSVC 构建 ===" -ForegroundColor Cyan
    $vcvars = Find-VcVars
    if (-not $vcvars) { throw "找不到 vcvars64.bat，MSVC 工具链不可用" }
    Write-Host "vcvars: $vcvars"

    $dir = Join-Path $root 'build-msvc'
    if ($Clean -and (Test-Path $dir)) { Remove-Item $dir -Recurse -Force }

    # 必须先进 vcvars 环境，Ninja 才找得到 cl.exe
    # ⚠️ 若这一步长时间无反应（可检查 $dir\CMakeFiles\CMakeScratch\*\ 下是否残留
    #    .ninja_lock），说明 CMake 的编译器探测被 Ninja 的锁卡住了。
    #    这不是代码问题：请改用 .\build.ps1 -Toolchain mingw，
    #    或用 README「完全不用 CMake 的保底方案」里的直接编译命令。
    $cmd = @(
        "call `"$vcvars`" >nul",
        "cmake -S `"$root`" -B `"$dir`" -G Ninja -DCMAKE_BUILD_TYPE=Release",
        "cmake --build `"$dir`" --parallel"
    ) -join ' && '
    cmd /c $cmd
    if ($LASTEXITCODE -ne 0) { throw "MSVC 构建失败 (exit $LASTEXITCODE)" }
    Write-Host "产物: $dir\bin" -ForegroundColor Green
    return $dir
}

function Build-Mingw {
    Write-Host "`n=== 使用 MinGW-w64 构建 ===" -ForegroundColor Cyan
    if (-not (Get-Command g++ -ErrorAction SilentlyContinue)) { throw "PATH 里找不到 g++" }
    g++ --version | Select-Object -First 1

    $dir = Join-Path $root 'build-mingw'
    if ($Clean -and (Test-Path $dir)) { Remove-Item $dir -Recurse -Force }

    cmake -S $root -B $dir -G 'MinGW Makefiles' -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++
    if ($LASTEXITCODE -ne 0) { throw "MinGW 配置失败" }
    cmake --build $dir --parallel
    if ($LASTEXITCODE -ne 0) { throw "MinGW 构建失败 (exit $LASTEXITCODE)" }
    Write-Host "产物: $dir\bin" -ForegroundColor Green
    return $dir
}

function Run-Checks($dir) {
    Write-Host "`n--- 测试: $dir ---" -ForegroundColor Cyan
    $tests = Join-Path $dir 'bin\ctfcodec-tests.exe'
    $cli   = Join-Path $dir 'bin\ctfcodec-cli.exe'
    if (Test-Path $tests) {
        & $tests
        Write-Host "C ABI 测试退出码: $LASTEXITCODE"
    }
    if (Test-Path $cli) {
        & $cli selftest
        Write-Host "算法自检退出码: $LASTEXITCODE"
    }
}

$dirs = @()
switch ($Toolchain) {
    'msvc'  { $dirs += Build-Msvc }
    'mingw' { $dirs += Build-Mingw }
    'both'  { $dirs += (Build-Msvc); $dirs += (Build-Mingw) }
}

if ($Test) {
    foreach ($d in $dirs) { Run-Checks $d }
}

Write-Host "`n完成。" -ForegroundColor Green
