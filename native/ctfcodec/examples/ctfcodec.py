#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ctfcodec Python 调用示例 / 封装

演示如何用 ctypes 调用 ctfcodec.dll。不需要任何第三方库，Python 3.6+ 即可。

用法：
    python ctfcodec.py                 # 跑一遍演示
    from ctfcodec import CTFCodec      # 当模块用

    c = CTFCodec(r"C:\\path\\to\\ctfcodec.dll")
    c.encode("base64", "hello")        # -> 'aGVsbG8='
    c.decode("base64", "aGVsbG8=")     # -> 'hello'
    c.encode("caesar", "HELLO", shift=3)
    c.magic("aGVsbG8=")
"""
import ctypes
import json
import os
import sys

# ---------------------------------------------------------------- 状态码
CTF_OK = 0
CTF_ERR_UNKNOWN_ALGO = -1
CTF_ERR_BAD_INPUT = -2
CTF_ERR_NEED_PARAM = -3
CTF_ERR_NOT_REVERSIBLE = -4
CTF_ERR_INTERNAL = -5
CTF_ERR_NULL_POINTER = -6


class CTFCodecError(Exception):
    """库返回负状态码时抛出，携带状态码与库内的错误文本。"""

    def __init__(self, code, message):
        super().__init__("[%d] %s" % (code, message))
        self.code = code
        self.message = message


class CTFCodec:
    def __init__(self, dll_path=None):
        self.dll_path = dll_path or self._find_dll()
        self.lib = ctypes.CDLL(self.dll_path)
        self._bind()
        if self.lib.ctf_abi_version() != 1:
            raise RuntimeError("DLL ABI 版本不匹配: %d" % self.lib.ctf_abi_version())

    # ------------------------------------------------------------ 定位 DLL
    @staticmethod
    def _find_dll():
        here = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(here, "ctfcodec.dll"),
            os.path.join(here, "..", "build-mingw", "bin", "ctfcodec.dll"),
            os.path.join(here, "..", "build-msvc", "bin", "ctfcodec.dll"),
            os.path.join(here, "..", "build", "bin", "ctfcodec.dll"),
            os.path.join(here, "..", "bin", "ctfcodec.dll"),
        ]
        for p in candidates:
            if os.path.isfile(p):
                return os.path.abspath(p)
        # 交给系统去 PATH 里找
        return "ctfcodec.dll"

    # -------------------------------------------------------------- 绑定
    def _bind(self):
        L = self.lib
        u8p = ctypes.POINTER(ctypes.c_uint8)

        L.ctf_abi_version.restype = ctypes.c_int
        L.ctf_version.restype = ctypes.c_char_p

        L.ctf_encode.argtypes = [
            ctypes.c_char_p, u8p, ctypes.c_size_t, ctypes.c_char_p,
            ctypes.POINTER(u8p), ctypes.POINTER(ctypes.c_size_t),
        ]
        L.ctf_encode.restype = ctypes.c_int
        L.ctf_decode.argtypes = list(L.ctf_encode.argtypes)
        L.ctf_decode.restype = ctypes.c_int

        L.ctf_encode_str.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        L.ctf_encode_str.restype = ctypes.c_void_p
        L.ctf_decode_str.argtypes = list(L.ctf_encode_str.argtypes)
        L.ctf_decode_str.restype = ctypes.c_void_p

        L.ctf_free.argtypes = [ctypes.c_void_p]
        L.ctf_free.restype = None

        L.ctf_last_error.restype = ctypes.c_char_p
        L.ctf_strerror.argtypes = [ctypes.c_int]
        L.ctf_strerror.restype = ctypes.c_char_p

        L.ctf_algo_count.restype = ctypes.c_int
        for fn in ("ctf_algo_name", "ctf_algo_category", "ctf_algo_help"):
            getattr(L, fn).argtypes = [ctypes.c_int]
            getattr(L, fn).restype = ctypes.c_char_p
        for fn in ("ctf_algo_reversible", "ctf_algo_needs_param"):
            getattr(L, fn).argtypes = [ctypes.c_int]
            getattr(L, fn).restype = ctypes.c_int

        L.ctf_algo_list_json.restype = ctypes.c_void_p
        L.ctf_magic.argtypes = [ctypes.c_char_p]
        L.ctf_magic.restype = ctypes.c_void_p
        L.ctf_self_test.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        L.ctf_self_test.restype = ctypes.c_int

    # ------------------------------------------------------------ 内部工具
    def _take_string(self, ptr):
        """把库返回的 char* 取成 Python str 并释放。"""
        if not ptr:
            return None
        try:
            return ctypes.string_at(ptr).decode("utf-8", "replace")
        finally:
            self.lib.ctf_free(ptr)

    def _last_error(self):
        e = self.lib.ctf_last_error()
        return e.decode("utf-8", "replace") if e else ""

    @staticmethod
    def _build_params(params):
        if not params:
            return None
        if isinstance(params, dict):
            parts = []
            for k, v in params.items():
                if isinstance(v, bytes):
                    v = v.hex()
                    k = k + "_hex" if not k.endswith("_hex") else k
                parts.append("%s=%s" % (k, v))
            return ";".join(parts).encode("utf-8")
        return str(params).encode("utf-8")

    # -------------------------------------------------------------- 核心 API
    def _op(self, is_encode, alg, data, params=None):
        """原始字节接口。data 是 bytes，返回 bytes。"""
        if isinstance(data, str):
            data = data.encode("utf-8")
        buf = ctypes.create_string_buffer(data, len(data)) if data else None
        out = ctypes.POINTER(ctypes.c_uint8)()
        out_len = ctypes.c_size_t(0)
        fn = self.lib.ctf_encode if is_encode else self.lib.ctf_decode
        rc = fn(alg.encode("utf-8"), ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint8)) if buf else None,
                len(data), self._build_params(params), ctypes.byref(out), ctypes.byref(out_len))
        if rc != CTF_OK:
            raise CTFCodecError(rc, self._last_error())
        try:
            return ctypes.string_at(ctypes.cast(out, ctypes.c_void_p), out_len.value)
        finally:
            self.lib.ctf_free(ctypes.cast(out, ctypes.c_void_p))

    def encode_bytes(self, alg, data, params=None):
        return self._op(True, alg, data, params)

    def decode_bytes(self, alg, data, params=None):
        return self._op(False, alg, data, params)

    def encode(self, alg, text, params=None):
        """文本 -> 文本（UTF-8）"""
        return self.encode_bytes(alg, text, params).decode("utf-8", "replace")

    def decode(self, alg, text, params=None):
        return self.decode_bytes(alg, text, params).decode("utf-8", "replace")

    # -------------------------------------------------------------- 便捷方法
    def magic(self, text):
        """返回识别结果列表 [{alg, score, reason, preview}, ...]"""
        ptr = self.lib.ctf_magic(text.encode("utf-8"))
        if not ptr:
            raise CTFCodecError(-99, self._last_error())
        return json.loads(self._take_string(ptr))

    def algo_list(self):
        ptr = self.lib.ctf_algo_list_json()
        if not ptr:
            raise CTFCodecError(-99, self._last_error())
        return json.loads(self._take_string(ptr))

    def algo_names(self):
        return [self.lib.ctf_algo_name(i).decode()
                for i in range(self.lib.ctf_algo_count())]

    def self_test(self):
        ptr = ctypes.c_void_p()
        failed = self.lib.ctf_self_test(ctypes.byref(ptr))
        report = json.loads(self._take_string(ptr.value)) if ptr.value else {}
        return failed, report

    def version(self):
        return self.lib.ctf_version().decode()


# ------------------------------------------------------------------ 演示
def _demo():
    print("ctfcodec Python 示例")
    try:
        c = CTFCodec()
    except OSError as e:
        print("加载 DLL 失败: %s" % e)
        print("请先编译项目，或把 ctfcodec.dll 放到本脚本同目录。")
        return 1

    print("DLL: %s" % c.dll_path)
    print("版本: %s  算法数: %d\n" % (c.version(), len(c.algo_names())))

    cases = [
        ("base64",  "hello world", None),
        ("base32",  "hello world", None),
        ("base16",  "hello world", None),
        ("base58",  "hello world", None),
        ("base85",  "hello world", None),
        ("base91",  "hello world", None),
        ("url",     "a b&c=d", None),
        ("html",    "<script>", None),
        ("morse",   "SOS", None),
        ("a1z26",   "HELLO", None),
        ("caesar",  "HELLO", {"shift": 3}),
        ("rot13",   "HELLO", None),
        ("vigenere", "ATTACKATDAWN", {"key": "LEMON"}),
        ("xor",     "secret", {"key": "mykey"}),
        ("hex-bytes", "AB", None),
        ("binary",  "AB", None),
        ("md5",     "abc", None),
        ("sha256",  "abc", None),
        ("crc32",   "123456789", None),
    ]
    for alg, text, params in cases:
        try:
            enc = c.encode(alg, text, params)
            show = enc if len(enc) < 60 else enc[:57] + "..."
            try:
                back = c.decode(alg, enc, params)
                back_show = " OK" if back == text else " <- 往返不一致: %r" % back
            except CTFCodecError:
                back_show = " (不可逆)"
            print("%-12s %-16r -> %s%s" % (alg, text, show, back_show))
        except CTFCodecError as e:
            print("%-12s 失败: %s" % (alg, e))

    print("\n自动识别 aGVsbG8gd29ybGQ= :")
    for item in c.magic("aGVsbG8gd29ybGQ="):
        print("  %-14s %3d%%  %s" % (item["alg"], item["score"], item["reason"]))

    failed, report = c.self_test()
    print("\n自带自检: 共 %d, 通过 %d, 失败 %d"
          % (report.get("total", 0), report.get("passed", 0), report.get("failed", 0)))
    return failed


if __name__ == "__main__":
    sys.exit(0 if _demo() == 0 else 1)
