# 匹配与识别原理

> 这份文档讲的是 **HexLens 内部所有"匹配/判定"到底怎么做的** —— 不是功能说明，
> 而是把每个阈值、每条判据、以及"为什么是这个值"摊开。
>
> 所有阈值与实现细节均**从代码提取**（标注了所在文件）。改动判定逻辑时请同步本文。
>
> 姊妹文档：[ctfcodec 的 `docs/MATCHING.md`](../../../Coding/ctfcodec/docs/MATCHING.md)
> —— 那讲的是**编码识别**（magic/brute）；本文讲的是**文件识别与藏匿检测**。

---

## 0. 全景：这里有多少种"匹配"

HexLens 的判定分散在十来个模块里，但它们可以归成四层：

| 层 | 在解决什么问题 | 主要模块 |
|---|---|---|
| **结构层** | 这是不是一个文件？多长？在哪结束？ | `SignatureDatabase`、`FormatSizers` |
| **位置层** | 它是"主文件"还是"藏在别人身体里"？ | `CarveScanner`、`StructuredHitDetector` |
| **统计层** | 这段数据"像什么"（文本/压缩/加密/噪声）？ | `EntropyCalculator`、`ByteStatistics`、`Base64Probe`、`CipherFieldDetector` |
| **语义层** | 它"意味着什么"（是 flag 吗？是密文该找密码吗？） | `ClueEngine`、`StringExtractor`、`XorBruteForcer` |

**四层的关系**：结构层给事实，位置层剔除巧合，统计层给出倾向，语义层翻译成人能用的结论。
**越靠下越依赖启发式，所以越需要"宁可不报"的纪律。**

---

## 1. 签名匹配（结构层）

**文件**：`src/HexLens.Core/Formats/SignatureDatabase.cs`

### 1.1 锚点（MagicAnchor）

```csharp
public sealed record MagicAnchor(byte[] Pattern, int RelativeOffset = 0, byte[]? Mask = null, string? Note = null);
```

一个格式可以有**多个锚点**，且每个锚点可以带**掩码**：

| 字段 | 作用 |
|---|---|
| `Pattern` | 要匹配的字节序列 |
| `RelativeOffset` | 该锚点相对文件起点的偏移（用于「偏移在中间」的格式） |
| `Mask` | 逐字节掩码：`0x00` 处**必须**匹配，`0xFF` 处忽略 |
| `Note` | 给这条锚点附一句说明（出现在线索里） |

**掩码的实际用法**（来自签名库）：

```csharp
// WebP：RIFF????WEBP —— 中间 4 字节是长度，必须用掩码忽略
A("52 49 46 46 00 00 00 00 57 45 42 50", 0, "FF FF FF FF 00 00 00 00 FF FF FF FF")
```

值得注意的实现细节：**掩码首字节为 `0x00` 的锚点会在建索引时被跳过**（`BuildBuckets`）——
因为它没有固定的首字节，无法进"按首字节分桶"的索引。

### 1.2 单遍桶扫描

```
Buckets : Dictionary<byte, List<(FileSignature, MagicAnchor, int)>>
```

按**锚点首字节**分桶。扫描时对缓冲区走一遍，每个位置只用查一次字典
（`data[i]` → 桶 → 逐个比对）。**复杂度 O(n × 平均桶长)，与签名总数弱相关。**

这就是为什么签名库有 93 处锚点定义、扫描仍然很快。

### 1.3 两套匹配入口

| 方法 | 用途 |
|---|---|
| `Scan(data, start, length, maxPerSignature)` | 全缓冲扫描，返回**所有**命中（可限制同一签名最多几处，防噪声型签名刷屏） |
| `IdentifyAt(data, offset)` | 只看**某个偏移**上是不是某个格式的开头（"这里是不是文件头"） |

### 1.4 校验器（Validator）

有些格式光有魔术字节不够（比如同为首字节的容器格式），签名定义里可以挂一个
`SignatureValidator` 委托做二次确认。带校验器的签名 `BaseConfidence` 会降到 `Medium`。

---

## 2. 长度推导匹配（结构层）

**文件**：`src/HexLens.Core/Formats/FormatSizers.cs`（+ `ArchiveSizers.cs`）

"找到文件头"只是一半，**知道它在哪结束**才是能裁切/嵌套判定的前提。

### 2.1 策略表（20 种）

| 策略 | 判定方式 | 置信度 |
|---|---|---|
| `PngToIend` | 沿 chunk 链走到 `IEND` | High |
| `JpegToEoi` | 走到 `FF D9` | High |
| `GifToTrailer` | 走到 `3B` 尾标记 | High |
| `BmpSize` | 读 `offset 2` 的 4 字节长度 | High |
| `RiffSize` | 读 `offset 4` 的 4 字节长度 + 8 | High |
| `PdfToEof` | 找 `%%EOF` | High |
| `SqlitePages` | 页大小 × 页数 | High |
| `PcapStream` | 遍历包记录 | High |
| `EbmlSize` | 解析 EBML 变长整数 | High |
| `ZipToEocd` | 往后找 EOCD（`PK\x05\x06`），读中央目录偏移 | High |
| `GzipStream` | **逐字节供流给 `DeflateStream`**，精确知道 deflate 消耗多少字节 | High |
| `XzStream` / `SevenZipStream` / `RarStream` / `TarBlocks` / `ZstdStream` | 各自的流式结构 | High / Medium |
| `ToEndOfFile` | 没有结束标记 → 延伸到缓冲区末尾 | **Medium** |
| `Fixed` | 固定长度格式 | High |
| `_ => EstimateUnknown` | 兜底：按下一个签名或末尾估算 | **Low** |

### 2.2 为什么 GZIP 要"逐字节供流"

GZIP 的尾部 CRC32/ISIZE **紧跟**在 deflate 数据之后。
`DeflateStream` 默认会**预读**，多读一个字节就会把边界算错。
所以这里实现了一个"每次只交出 1 字节"的流，让解压器按需拉取，从而精确计数。

**这是"知道自己在哪结束"和"猜自己在哪结束"的分界线。**

### 2.3 解压炸弹防护

归档测量有两个上限（`ArchiveSizers.cs`）：
- **解压探测上限**：防止解压炸弹把内存吃干
- **逐字节精确供流的 gzip 上限**：超过就退回估算，避免 UI 卡顿

---

## 3. 结构化命中判定（位置层 · 防误报的核心）

**文件**：`src/HexLens.Core/Formats/StructuredHitDetector.cs`

### 3.1 为什么需要它

> 像 ICO 的 `00 00 01 00`、ESE 的 `EF CD AB 89` 这类**短魔数**，
> 在随机或打乱的位流里撞上的概率并不低。

位平面扫描与反转探测如果只看魔数，**一次能报出十几条噪声，把真正的载荷淹掉**。
实测数据（记在代码注释里）：

| | 命中数 | 真命中 |
|---|---|---|
| 加此判据**前** | 12 条 | 1 条 |
| 加此判据**后** | **1 条** | **正是真载荷** |

### 3.2 两条判据

```
① 命中位置必须靠近开头 —— maxHeadOffset = 64
② 长度必须能被该格式的结构推导出来（requireMeasurableLength）
```

外加：`MinimumConfidence = Confidence.Medium`、`maxCandidates = 16`。

### 3.3 选择逻辑

```csharp
// 越靠前越可信；同偏移时置信度高者优先
if (best is null
    || candidate.Offset < best.Offset
    || (candidate.Offset == best.Offset && candidate.Confidence > best.Match.Confidence))
```

**直觉**：文件都是从自己的第 0 字节开始的。在一个候选缓冲区的第 3000 字节处发现
"这里有个 PNG 头"，那更可能是巧合而不是"载荷从第 3000 字节开始"。

`requireMeasurableLength` 在**探测阶段可以放宽**（探测窗口可能小于真实载荷），
但在最终判定时必须为真。

---

## 4. 裁切与嵌套判定（位置层）

**文件**：`src/HexLens.Core/Carving/CarveScanner.cs`

```csharp
public bool IsEmbedded => Offset > 0;      // 不在文件开头 = 藏在别人里面
public bool IsNested   => NestingDepth > 0; // 被别的文件区间包住
```

| 组合 | 含义 | 处理 |
|---|---|---|
| `IsEmbedded && !IsNested` | **藏在容器里但不在归档内部** | **优先展示**（最可疑） |
| `IsNested` | 在 ZIP/PNG 等合法容器内部 | 降权（可能是正常内容） |
| 都不满足 | 主文件自身 | 作为 `top` 用于尾部判定 |

排序规则：

```csharp
Files.OrderByDescending(f => f.IsEmbedded && !f.IsNested)
```

**这条排序是整个线索列表"有用"的前提** —— 真藏匿排在正常嵌套前面。

---

## 5. 位平面穷举匹配（结构层 + 统计层）

**文件**：`src/HexLens.Core/Stego/LsbExtractor.cs`

藏 LSB 的参数很多，**猜一个不如全试一遍**：

```
位平面      plane ∈ [0, BitPlanes)
通道        单通道 / 通道组（RGBA 时补 [2,1,0] = B,G,R 顺序）
位序        正序 / 反转（ReverseBits）
扫描序      行 / 列
方向        正序 / 逆序（Reverse）
```

### 5.1 两阶段：先探测，后全量

```
① 小窗探测  只取开头一小段跑全部参数组合
② 命中才全量提取
```

**这是性能的关键**：不这么做，一个 4K 图要把所有组合都跑满。

### 5.2 两个上限

| 常量 | 值 | 作用 |
|---|---|---|
| `DefaultMaxPayload` | 64 MiB | 单次载荷上限 |
| `MinTextRun` | **20** | 明文载荷判定的最短连续可打印段 |

---

## 6. 明文载荷判定（统计层）

位流里**没有文件签名**时，也可能藏了明文（`flag{...}` 之类）—— 这在 CTF 里比藏整个文件更常见。

判据：

```
① 找「最长连续可打印段」≥ MinTextRun (20 字节)
② 或匹配 flag{...} 一类正则
③ 载荷后面的 0 填充不影响判定 ← 这条很重要
```

**第 ③ 条是踩出来的**：位流提取出来的载荷后面常常跟着一串 0（因为载体像素剩余位是空的），
如果要求"整段可打印"就会漏检。

---

## 7. 编码识别与可读性打分（统计层）

**文件**：`src/HexLens.App/Interop/CtfCodec`（P/Invoke 调用内置原生库，127 个算法）

判定分两步：

```
① magic：原生库的 20 条特征规则表给出候选 + 打分
② 试解码：HexLens 侧真的解一次，再用「可读性」给分排序
```

**为什么要自己再打一次分**：原生库的 magic 打分只看"输入长得像什么"，不看"解出来是什么"。
一个 base64 串恰好也符合 base58 的字符集，光看输入分不出来 —— **必须解码后看结果**。

（这条链路的细节与已知缺陷见姊妹文档 ctfcodec 的 `MATCHING.md`：那里记录了
`IsPrintable` 无条件放行高位字节导致 base64/base58 霸榜等 5 个问题。）

---

## 8. Base64 探测（统计层）

**文件**：`src/HexLens.Core/Analysis/Base64Probe.cs`

```csharp
public const int ReadableThreshold = 80;   // 「可读文本」阈值
public const int AcceptThreshold   = 55;   // 「接受为 Base64」阈值
public const int MinLength         = 16;   // 最短长度
```

### 8.1 两个阈值不同，是有意的

| 阈值 | 用途 |
|---|---|
| `AcceptThreshold = 55` | **够格被认成 Base64**（宽） |
| `ReadableThreshold = 80` | **解码结果算「可读文本」**（严） |

**为什么要分开**：解码结果可能是**二进制文件**（PNG/ZIP），那种情况可读分很低，
但它显然是"有价值的 Base64"。用一个阈值会把这类全漏掉。

### 8.2 字符集

```csharp
c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/'
```

### 8.3 带前缀的情况

`keyV2hhdCB...` 这种（`key` 之后才是 Base64）也能识别 ——
**这是从线索与界面共用的判定**（同一份 `Base64Probe`），避免两处判定不一致。

---

## 9. 熵与高熵区（统计层）

**文件**：`src/HexLens.Core/Analysis/EntropyCalculator.cs`

```csharp
public bool IsHighEntropy => Entropy >= 7.0;   // 压缩/加密
public bool IsLowEntropy  => Entropy <= 0.5;   // 填充/重复
```

### 9.1 为什么高熵阈值是 7.0 而不是 7.9

> 压缩数据块通常 7.5 以上，文本约 4–5，**7.0 是安全分界**。

### 9.2 小样本的熵陷阱 ⚠️

**256 字节小块的熵本身在 7.28 附近波动**（样本量越小方差越大）。
所以连续区间的判定用**更大的块**：

| 块大小 | 随机数据均值 | 判定稳定性 |
|---|---|---|
| 256 B | ~7.28 | 差（频繁失手） |
| **1024 B** | **~7.6** | **稳** |

`FindHighEntropyRegions` 默认 `blockSize = 1024` 就是这个原因。

**而这个陷阱还有更狠的形式**：48 字节即使**完全随机**，熵上限也只有 `log2(48) ≈ 5.58`
—— 任何绝对阈值都会把"短密文"整类漏掉。见 §10。

---

## 10. 疑似加密字段（统计层）

**文件**：`src/HexLens.Core/Analysis/CipherFieldDetector.cs`

### 10.1 它**不做什么**（最重要）

**它不猜算法。** 密文没有头部，任何声称"从字节看出这是 AES"的工具都在编。
它能给的只有一句有用的话：**"这里不是文件碎片，是一段需要密钥的密文，块长 16，去别处找密码。"**

### 10.2 判据（全部是结构性事实）

| # | 判据 | 常量 |
|---|---|---|
| ① | 无已知文件头 | `SignatureDatabase.IdentifyAt` 无命中 |
| ② | 熵接近**该长度上限** | `MinNormalizedEntropy = **0.85**` |
| ③ | 长度规整（命中块长或摘要长度） | 块长 16 / 8；摘要 16/20/28/32/48/64 |
| ④ | 长度不大 | `MinCipherLength = 16`、`MaxCipherLength = 4096` |

### 10.3 ⚠️ 两个阈值都是踩出来的

**坑一：不能用绝对熵阈值。**
48 字节完全随机时熵只有 `log2(48) ≈ 5.58`。用 `> 7.5` 去卡，**整个"短密文"类别全被漏掉**
（BUUCTF snake 题就是这么漏过去的）。→ 改为**按该长度可达上限归一化**：`熵 / log2(min(n, 256))`。

**坑二：归一化后阈值也不能贴太近。**
256 字节随机数据实测归一化只有 **~90%**（256 个样本里唯一值通常只有 ~160 个，
这是样本量决定的，不是不够随机）。卡 0.93 会再漏一次。→ 取值 **0.85**
（普通文本一般在 0.75 以下，分界仍然清楚）。

### 10.4 块长的**检查顺序有意义**

```csharp
private static readonly (int Block, string Family)[] BlockCipherFamilies =
[
    (16, "16 字节块：AES / Serpent / Twofish / SM4 / Camellia / ARIA"),
    (8,  "8 字节块：DES / 3DES / Blowfish / CAST5"),
];
```

48 既能被 8 整除也能被 16 整除 —— **必须先判 16**，否则会给出"8 字节块 DES"这种误导结论
（早期版本用 `Dictionary` 遍历，顺序不定，就出过这个问题）。

### 10.5 输出的是"该往哪找"

线索正文会明确列出：
- 长度整除哪个块长、要不要 IV
- **"密文没有头部，任何声称能从字节直接看出 AES/Serpent 的说法都不可信"**
- 常见来源：题目给了密码 → 试分组密码（ECB 与 CBC 都要试）；
  没给密码但很短 → 试 XOR 爆破；长度像摘要 → 那是哈希，不该解密

---

## 11. XOR 暴力破解打分（语义层）

**文件**：`src/HexLens.Core/Analysis/XorBruteForcer.cs`

遍历 256 个单字节密钥本身没有难度，**难的是挑出哪个对**：

| 证据 | 权重 | 说明 |
|---|---|---|
| 可打印字符占比 | `× 40` | 基础分 |
| **开头撞上已知文件签名** | **+60** | 最强的结构性证据 |
| **含 `flag{` / `ctf{` 等关键词** | **+80** | CTF 的"标准答案" |
| 丢弃门槛 | `< 25` | 低于此直接不进候选列表 |

```csharp
private const int ScoreWindow   = 4096;   // 打分只看前 4 KiB
private const int PreviewLength = 64;     // 预览长度
```

**为什么"文件签名 +60"排在"可打印 ×40"之上**：可打印比例高的东西太多了（比如一段英文），
而"解密后开头正好是 PNG 魔数"这种事**几乎不可能是巧合**。

### 11.1 ⚠️ 阈值别卡在"看起来像"上

**踩过的坑**：BUUCTF snake 题的正确答案（明文尾部有 12 个 `0x00` 填充）
可读率被拉到 **75%**，而当时的判据是 `> 85%` —— **正确答案被自己的阈值挡在门外**。

**教训**：用启发式打分筛选时**宁可多列几个候选让人眼看**，也别用一个漂亮的阈值把真答案滤掉。

---

## 12. CRC 校验匹配（结构层）

**文件**：`src/HexLens.Core/Analysis/PngCrcChecker.cs`

PNG 每个 chunk 末尾有 4 字节 CRC32，覆盖 **「块类型 + 块数据」**（不含长度字段）。

```
偏移   length(4)  type(4)  data(length)  crc(4)
                └──────── CRC 覆盖这里 ────────┘
```

- **存储字节序：大端**（写回时必须按大端排）
- 越界检查在算 CRC 之前做（长度字段本身也可能被改坏）
- 遇到 `IEND` 停止

**为什么值得单做**：手改宽高/像素后 CRC 必错，而**多数查看器遇 CRC 错直接拒开**，
看起来像"文件坏了"，实际写回 4 字节即可。

**交叉验证过**：实现结果与 Python `zlib` 一致（同一坏块均算出 `0xA183E1BC`）。

---

## 13. 类型 / 扩展名匹配（语义层）

**文件**：`src/HexLens.Core/Clues/ClueEngine.cs`（⑩ 与 ⑩-b 两段）

这两段**互补，别混**：

| 线索 | 场景 | 解法 |
|---|---|---|
| ⑩ `扩展名与实际类型不符` | **认得出内容**、但扩展名骗人 | 改**扩展名** |
| ⑩-b `.{ext} 的文件头不是 …… 的签名` | **扩展名说是什么**、但文件头不像 | 改**文件头**（提供一键修复） |

⑩-b 用 `SignatureDatabase.GetByExtension(ext)` **反查**"这个后缀通常该是什么格式"，
再比对开头字节，给出 `WritePayload` 动作（携带正确签名，可一键写回）。

> ⚠️ **⑩-b 的第一版是死代码**：当初把"改文件头"挂在 ⑩ 上，而 ⑩ 的前提是"内容识别成功" ——
> 识别成功了文件头必然正确，"开头字节不符"永远不成立。**是造测试样本时发现的**
> （想造一个"识别成功但头不对"的文件，造不出来）。

---

## 14. 搜索匹配（语义层）

**文件**：`src/HexLens.Core/Analysis/SearchEngine.cs`

| 模式 | 语法 |
|---|---|
| 十六进制 | `4D 5A ?? ?? 50 45` —— **`??` 表示一个任意字节**（十六进制编辑器通行写法） |
| 文本 | 直接匹配 |
| 正则 | 支持 `IgnoreCase` / `CultureInvariant` |
| 上限 | `maxHits = 20000` |

**注意**：单个 `?` 视为**非法**（只有 `??` 是一个字节的通配）—— 避免有人以为 `?`
是"可选一个字符"而写出错误模式还以为搜到了。

---

## 15. 阈值总表

改任何一条判据前，请先看这张表（都是从代码提取的实际值）：

| 模块 | 常量 | 值 | 含义 |
|---|---|---|---|
| `StructuredHitDetector` | `maxHeadOffset` | **64** | 命中离头部多远还算"文件开头" |
| | `MinimumConfidence` | Medium | 低于此不算结构化命中 |
| | `maxCandidates` | 16 | 单次最多检查的候选数 |
| `Base64Probe` | `AcceptThreshold` | **55** | 认成 Base64 的门槛 |
| | `ReadableThreshold` | **80** | 解码结果算"可读文本"的门槛 |
| | `MinLength` | 16 | 最短长度 |
| `EntropyCalculator` | 高熵 | **≥ 7.0** | 压缩/加密 |
| | 低熵 | **≤ 0.5** | 填充/重复 |
| | `FindHighEntropyRegions.blockSize` | **1024** | 块太小判不稳 |
| `LsbExtractor` | `DefaultMaxPayload` | 64 MiB | 载荷上限 |
| | `MinTextRun` | **20** | 明文段最短长度 |
| `CipherFieldDetector` | `MinNormalizedEntropy` | **0.85** | 归一化熵门槛 |
| | `MinCipherLength` | 16 | 太短没有统计意义 |
| | `MaxCipherLength` | 4096 | 再长就按压缩流看 |
| `XorBruteForcer` | 可打印权重 | × 40 | |
| | 文件签名加分 | **+60** | |
| | flag 关键词加分 | **+80** | |
| | 丢弃门槛 | **< 25** | |
| | `ScoreWindow` | 4096 | 打分窗口 |
| `StringExtractor` | `DefaultMinLength` | 6 | 最短字符串长度 |
| `SearchEngine` | `maxHits` | 20000 | 搜索命中上限 |

---

## 16. 已知局限（诚实列出）

| 局限 | 说明 |
|---|---|
| **JPEG / TIFF 不做像素级位平面** | 没有自带 JPEG 解码器；而且有损压缩本身会毁掉 LSB |
| **PNG Adam7 隔行图像**只做结构分析 | 明确报"暂不支持"，**不会静默给错结果** |
| **疑似加密字段认不出算法** | 设计上就不猜 —— 密文没有头部，猜就是编 |
| **XOR 只覆盖单字节 + 少量常见短密钥** | 完整循环密钥恢复需要先求密钥长度，是另一件事 |
| **CRC 只做了 PNG** | GZIP 的 CRC 需要先解压才能校验，成本高于收益；ZIP 只对 stored 条目可校 |
| **编码识别不处理 > 8 KiB 的选区** | 只提示不做（性能取舍） |
| **短魔数格式（ICO/ESE 等）仍可能误判** | 结构化命中判定大幅降低，但没有归零 |

---

## 17. 一页速查

```
找到一段数据，先问四个问题：

① 它有没有已知文件头？
     有 → 是文件。用 FormatSizers 推长度 → 得到 [start, end]
     无 → 可能是密文（§10）或截断数据

② 它在文件的什么位置？
     不在开头 → IsEmbedded：藏在别人里面，可疑
     被别的文件区间包住 → IsNested：可能是正常嵌套，降权

③ 它"像什么"？
     熵 ≥ 7.0            → 压缩/加密
     熵归一化 ≥ 0.85 且无头 → 疑似密文（提示找密码）
     Base64 字符集且解码可读 → Base64

④ 它"意味着什么"？
     含 flag{...}        → 直接给结论
     位置靠近某个文件头   → 可能是嵌套/附加
     什么都不是          → 别报
```

**贯穿始终的一条纪律**：

> **判据要能"不报"。** 误报比漏报更贵 —— 一次报 12 条噪声，
> 真载荷就被淹了。所有阈值都朝"宁可漏报"的方向取，并且**阈值必须按样本特性留余量**
> （小样本的熵有上限、密文尾部有填充、块长判定有顺序）。
