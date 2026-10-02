/*
 * demo.c —— ctfcodec.dll 的纯 C 调用示例
 *
 * 编译（MinGW）：
 *   gcc demo.c -I..\include -L..\build-mingw\bin -lctfcodec -o demo.exe
 *   （运行时需要 ctfcodec.dll 与 demo.exe 同目录，或位于 PATH）
 *
 * 编译（MSVC，在 vcvars 环境里）：
 *   cl demo.c /I..\include /link ..\build-msvc\bin\ctfcodec.lib
 */
#include <stdio.h>
#include <string.h>

#include "ctfcodec.h"

/* 演示：编码并打印 */
static void show_encode(const char* alg, const char* text, const char* params) {
    char* r = ctf_encode_str(alg, text, params);
    if (r) {
        printf("  %-14s %-22s -> %s\n", alg, text, r);
        ctf_free(r);
    } else {
        printf("  %-14s %-22s -> [错误] %s\n", alg, text, ctf_last_error());
    }
}

/* 演示：编码再解码，验证往返 */
static void show_roundtrip(const char* alg, const char* text, const char* params) {
    char* enc = ctf_encode_str(alg, text, params);
    if (!enc) {
        printf("  %-14s 编码失败: %s\n", alg, ctf_last_error());
        return;
    }
    char* dec = ctf_decode_str(alg, enc, params);
    if (!dec) {
        printf("  %-14s 解码失败: %s\n", alg, ctf_last_error());
        ctf_free(enc);
        return;
    }
    printf("  %-14s %-20s -> %-30s -> %s\n", alg, text, enc, dec);
    ctf_free(enc);
    ctf_free(dec);
}

int main(void) {
    printf("ctfcodec v%s (ABI %d)\n", ctf_version(), ctf_abi_version());
    printf("已注册算法: %d 个\n\n", ctf_algo_count());

    /* ---------- 1. 基本编码 ---------- */
    printf("[1] 基本编码\n");
    show_encode("base64", "hello world", NULL);
    show_encode("base32", "hello world", NULL);
    show_encode("base16", "hello world", NULL);
    show_encode("base58", "hello world", NULL);
    show_encode("url", "a b&c=d", NULL);
    show_encode("morse", "SOS", NULL);

    /* ---------- 2. 带参数的算法 ---------- */
    printf("\n[2] 带参数的算法\n");
    show_encode("caesar", "HELLO", "shift=3");
    show_encode("vigenere", "ATTACKATDAWN", "key=LEMON");
    show_encode("xor", "secret", "key=mykey");
    show_encode("md5", "abc", NULL);
    show_encode("sha256", "abc", NULL);

    /* ---------- 3. 往返一致性 ---------- */
    printf("\n[3] 往返一致性\n");
    show_roundtrip("base64", "hello world", NULL);
    show_roundtrip("base85", "hello world", NULL);
    show_roundtrip("caesar", "HELLO", "shift=3");
    show_roundtrip("railfence", "WEAREDISCOVEREDFLEEATONCE", "rails=3");

    /* ---------- 4. 二进制安全 ---------- */
    printf("\n[4] 二进制安全（含 NUL 与 0xFF）\n");
    {
        const unsigned char raw[] = {0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F};
        unsigned char*     out    = NULL;
        size_t             len    = 0;
        int rc = ctf_encode("base16", raw, sizeof(raw), NULL, &out, &len);
        if (rc == CTF_OK) {
            printf("  原始字节 -> base16: %.*s\n", (int)len, (char*)out);
            ctf_free(out);
        }

        out = NULL;
        len = 0;
        rc  = ctf_encode("base64", raw, sizeof(raw), NULL, &out, &len);
        if (rc == CTF_OK) {
            printf("  原始字节 -> base64: %.*s\n", (int)len, (char*)out);

            /* 解回来验证完全一致 */
            unsigned char* back     = NULL;
            size_t         back_len = 0;
            if (ctf_decode("base64", out, len, NULL, &back, &back_len) == CTF_OK) {
                int same = (back_len == sizeof(raw)) && (memcmp(back, raw, back_len) == 0);
                printf("  解码回来: %s (%zu 字节)\n", same ? "完全一致 ✓" : "不一致 ✗", back_len);
                ctf_free(back);
            }
            ctf_free(out);
        }
    }

    /* ---------- 5. 错误处理 ---------- */
    printf("\n[5] 错误处理\n");
    {
        char* r = ctf_encode_str("no-such-algo", "x", NULL);
        printf("  未知算法: 返回 %s, 错误码说明 = %s\n", r ? "非空" : "NULL",
               ctf_strerror(CTF_ERR_UNKNOWN_ALGO));

        r = ctf_decode_str("md5", "d41d8cd98f00b204e9800998ecf8427e", NULL);
        printf("  解码 md5: 返回 %s（不可逆，符合预期）\n", r ? "非空" : "NULL");
        if (r) ctf_free(r);

        r = ctf_encode_str("caesar", "HELLO", NULL);
        printf("  caesar 缺 shift: %s\n", r ? "非空" : ctf_last_error());
        if (r) ctf_free(r);
    }

    /* ---------- 6. 自动识别 ---------- */
    printf("\n[6] 自动识别 aGVsbG8gd29ybGQ=\n");
    {
        char* js = ctf_magic("aGVsbG8gd29ybGQ=");
        if (js) {
            printf("  %s\n", js);
            ctf_free(js);
        }
    }

    /* ---------- 7. 遍历算法清单（前 15 个） ---------- */
    printf("\n[7] 算法清单（前 15 个）\n");
    {
        int n = ctf_algo_count();
        int lim = n < 15 ? n : 15;
        for (int i = 0; i < lim; ++i) {
            printf("  %-16s [%-8s] %s%s\n", ctf_algo_name(i), ctf_algo_category(i),
                   ctf_algo_help(i), ctf_algo_reversible(i) ? "" : "  (不可逆)");
        }
        printf("  ... 共 %d 个\n", n);
    }

    printf("\n演示结束。\n");
    return 0;
}
