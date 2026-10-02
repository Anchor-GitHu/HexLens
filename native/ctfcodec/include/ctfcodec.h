/*
 * ctfcodec.h —— CTF 常用编码/解码库 公共 C 接口
 * ---------------------------------------------------------------------------
 * 设计要点：
 *   1. 全部导出函数使用 C ABI（extern "C" + __cdecl），任何语言都能直接调用
 *      （Python ctypes / C# DllImport / Go cgo / 易语言 / VB6 ...）。
 *   2. 输入输出都是「字节 + 长度」，二进制安全，不依赖 NUL 结尾。
 *   3. 带密钥/字母表的算法统一通过 params 字符串传参，
 *      格式："key=SECRET;shift=3;alphabet=ABC..."，不需要为每个算法单独导出。
 *   4. 库内部分配的输出缓冲区必须用 ctf_free() 释放（内部是 malloc）。
 *
 * 编译期宏：
 *   CTFCODEC_BUILD   —— 编译 DLL 时由构建系统定义（dllexport）
 *   CTFCODEC_STATIC  —— 静态链接时定义，取消 dllimport
 */
#ifndef CTFCODEC_H
#define CTFCODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(_WIN64)
#  if defined(CTFCODEC_STATIC)
#    define CTF_API
#  elif defined(CTFCODEC_BUILD)
#    define CTF_API __declspec(dllexport)
#  else
#    define CTF_API __declspec(dllimport)
#  endif
#  define CTF_CALL __cdecl
#else
#  define CTF_API __attribute__((visibility("default")))
#  define CTF_CALL
#endif

/* ------------------------------- 状态码 -------------------------------- */
#define CTF_OK                    0   /* 成功 */
#define CTF_ERR_UNKNOWN_ALGO     -1   /* 算法名不存在 */
#define CTF_ERR_BAD_INPUT        -2   /* 输入不合法（非法字符 / 长度错误等） */
#define CTF_ERR_NEED_PARAM       -3   /* 缺少必需参数（如 key / shift） */
#define CTF_ERR_NOT_REVERSIBLE   -4   /* 该算法不可逆（如哈希） */
#define CTF_ERR_INTERNAL         -5   /* 内部错误 */
#define CTF_ERR_NULL_POINTER     -6   /* 传入了空指针 */

/* ------------------------------ 版本信息 ------------------------------- */
CTF_API int         CTF_CALL ctf_abi_version(void);   /* 当前为 1 */
CTF_API const char* CTF_CALL ctf_version(void);       /* 如 "1.0.0" */

/* --------------------------- 核心编解码接口 ---------------------------- */
/*
 * alg    : 算法名，大小写不敏感，支持别名（见 ctfcodec-cli list）
 * in     : 输入数据（可为 NULL，当 in_len 为 0 时）
 * in_len : 输入长度（字节）
 * params : 可选参数串 "k=v;k=v"，无参数传 NULL
 * out    : [出参] 库内 malloc 的缓冲区，成功时必须用 ctf_free 释放
 * out_len: [出参] 输出字节数
 *
 * 返回 CTF_OK 或负的错误码；失败时 *out = NULL, *out_len = 0。
 * 出错详情用 ctf_last_error() 取（线程局部）。
 */
CTF_API int CTF_CALL ctf_encode(const char*    alg,
                                const uint8_t* in,
                                size_t         in_len,
                                const char*    params,
                                uint8_t**      out,
                                size_t*        out_len);

CTF_API int CTF_CALL ctf_decode(const char*    alg,
                                const uint8_t* in,
                                size_t         in_len,
                                const char*    params,
                                uint8_t**      out,
                                size_t*        out_len);

/* ------------------------- 便捷的字符串版本 ---------------------------- */
/*
 * 输入按 NUL 结尾的 UTF-8 字符串处理，输出也是 NUL 结尾（内部可能含 0 字节，
 * 但字符串接口的使用者通常只关心文本结果）。
 * 返回值需用 ctf_free 释放；失败返回 NULL 并设置 ctf_last_error()。
 */
CTF_API char* CTF_CALL ctf_encode_str(const char* alg, const char* text, const char* params);
CTF_API char* CTF_CALL ctf_decode_str(const char* alg, const char* text, const char* params);

/* --------------------------- 内存与错误信息 ---------------------------- */
CTF_API void        CTF_CALL ctf_free(void* p);
CTF_API const char* CTF_CALL ctf_last_error(void);   /* 线程局部，无需释放 */
CTF_API const char* CTF_CALL ctf_strerror(int code); /* 状态码 -> 说明 */

/* ----------------------------- 算法清单 -------------------------------- */
CTF_API int         CTF_CALL ctf_algo_count(void);
CTF_API const char* CTF_CALL ctf_algo_name(int index);      /* 越界返回 NULL */
CTF_API const char* CTF_CALL ctf_algo_category(int index);
CTF_API const char* CTF_CALL ctf_algo_help(int index);
CTF_API int         CTF_CALL ctf_algo_reversible(int index);  /* 1 可逆 / 0 不可逆 */
/*
 * 1 表示该算法接受 params —— 注意这里是「接受」而非「必需」：
 * 有些算法参数是可选的（如 base64 的 alphabet、binary 的 sep），会使用默认值；
 * 有些则是必需的（如 caesar 的 shift、xor 的 key、base-convert 的 from/to）。
 * 具体某个算法的必需参数写在 ctf_algo_help() 里，缺参数时调用会返回
 * CTF_ERR_NEED_PARAM 并在 ctf_last_error() 说明缺了什么。
 */
CTF_API int         CTF_CALL ctf_algo_needs_param(int index);
/* 导出整个清单为 JSON 数组字符串，需用 ctf_free 释放 */
CTF_API char*       CTF_CALL ctf_algo_list_json(void);

/* ----------------------------- 自动识别 -------------------------------- */
/*
 * 对输入做「像什么编码」的启发式打分，返回 JSON 数组字符串（需 ctf_free）。
 * 每项：{"alg":"base64","score":95,"reason":"...","preview":"..."}
 * 仅给建议，不做自动解码。
 */
CTF_API char* CTF_CALL ctf_magic(const char* text);

/* ------------------------------ 自检 ----------------------------------- */
/*
 * 跑内置已知向量 + 往返测试。report 若不为 NULL 则接收详细报告
 * （JSON，需 ctf_free）。返回失败项数，0 表示全部通过。
 */
CTF_API int CTF_CALL ctf_self_test(char** report);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CTFCODEC_H */
