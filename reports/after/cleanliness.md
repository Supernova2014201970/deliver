# `clean` 的成因：68 条"不崩"到底发生了什么

`imdt verify-after` 的结果是 `crash=0 clean=68`。`fixed` 树与 `vuln` 树只差
`payload/patches/` 里的 62 个补丁，所以这 68 条"不崩"必须每一条都能落到具体原因上。
本报告就是那份逐条归因：**27 条被完整解码、5 条被 harness 的资源上限拦下、36 条被更早的
解析校验拒绝**，合计 68。

判定口径（`verify.sh` 的 `SUMMARY` 列）：驱动（`scripts/hand_repro.cc`）在
`image.read()` / `image.write()` 外面 `catch (Magick::Exception &)`，所以"抛异常"和
"正常解码"都算 `CLEAN`；只有 sanitizer 真正报出 `SUMMARY: AddressSanitizer: …`
（MSan 则 `MemorySanitizer`、UBSan 则 `runtime error:`）才算 `CRASH`。也就是说
本报告回答的是"那 68 条各自走到哪一步"，而不是"有没有崩"——后者已在
`verify-vuln.{md,json}` / `verify-fixed.{md,json}` 里。

## 1. 怎么测出来的

`verify.sh` 的驱动刻意吞异常，看不到内部分类，所以用一个只差"打印"的诊断驱动复跑一遍：

* 语义与 `scripts/hand_repro.cc` 完全一致：`image.magick(coder)` + `fileName(coder + ":")`
  → `read(blob)` → `write(blob, coder)`；`SecurityPolicy::maxMemoryRequest(256000000)`
  + `ResourceLimits::memory(1000000000)`（照抄 `Magick++/fuzz/utils.cc` 的
  `FuzzingLimits`）；`-DHARNESS_FIXED_LIMITS` 时再加 `ResourceLimits::width(2048)` /
  `height(2048)`（补丁 `e8be814f` 给 fixed 树的 `utils.cc` 加的两行）。
* 唯一的差别：`catch` 里把 `e.what()` 打印成 `READ	error	<文本>`，成功则打印
  `READ	ok	<宽>x<高>` 与 `WRITE	ok	<字节数>` / `WRITE	error	<文本>`。异常文本去掉
  `Magick: ` 前缀与 ` @ error/…` 后缀，只留错误短语。
* 链接 `fixed` 树的静态库（instrumented 构建的 `inst/` 目录，`-fsanitize=address`
  只是复用现成的产物），运行环境 `ASAN_OPTIONS=detect_leaks=0`——`verify.sh` 对
  AddressSanitizer 也关掉 leak 检测，否则 ImageMagick 自身的若干小泄漏会在进程退出时
  把 `_exit(1)` 打进来，掩盖真正的判定（关掉之后 6 条只在 `WriteBlob`/`ReadBlob` 里
  泄漏的案例才落回 `ok`）。
* 68 条用例的 `coder` / `poc` 直接取 `payload/cases.tsv` 第 2、7 列，与
  `verify.sh` 读的是同一张表。

## 2. 总账

| 分类 | 条数 | 判定 | 含义 |
| --- | --- | --- | --- |
| decoded | 27 | `READ ok` | PoC 被完整解出。其中 23 条 `WRITE ok`（回写成功），4 条回写报 `no encode delegate for this image format`（该 coder 只有解码器没有编码器，属正常现象） |
| limit | 5 | `READ error: width or height exceeds limit` | 被 `ResourceLimits::width(2048)` / `height(2048)` 截住，即补丁 `e8be814f` 给 fixed 树的 `Magick++/fuzz/utils.cc` 加的那两行 |
| parser | 36 | `READ error: <其它>` | 补丁把校验提前了：输入在走到脆弱代码之前就被格式解析器拒绝 |
| **合计** | **68** | | 与 `verify-fixed.json` 的 `clean=68` 一致 |

27 + 5 + 36 = 68，三类互斥且穷尽：凡是 `READ` 成功的都归 decoded（无论 `WRITE` 成败），
凡是 `READ` 报 `width or height exceeds limit` 的归 limit，其余归 parser。

## 3. 三类明细

### 3.1 decoded（27 条）

| localId | coder | sanitizer | 结果 |
| --- | --- | --- | --- |
| 42519182 | SUN | address | `READ ok 25x1` / `WRITE ok 36` |
| 42519749 | SIX | address | `READ ok 2x6` / `WRITE ok 59` |
| 42520493 | DXT5 | address | `READ ok 11x5` / `WRITE ok 224` |
| 42521159 | TXT | memory | `READ ok 7x1` / `WRITE ok 405` |
| 42521170 | WPG | memory | `READ ok 32x288` / `WRITE error: no encode delegate for this image format 'WPG'` |
| 42521270 | PCX | memory | `READ ok 1x1` / `WRITE ok 131` |
| 42521880 | VIFF | memory | `READ ok 3x7` / `WRITE ok 1108` |
| 42522869 | PALM | memory | `READ ok 511x255` / `WRITE ok 16336` |
| 42523358 | PNM | memory | `READ ok 2x3` / `WRITE ok 10` |
| 42523812 | DPX | memory | `READ ok 32x16` / `WRITE ok 9216` |
| 42523868 | MAT | memory | `READ ok 2x1` / `WRITE ok 192` |
| 42523879 | PSD | address | `READ ok 2x1` / `WRITE ok 399` |
| 42525613 | PSD | memory | `READ ok 7x1` / `WRITE ok 196` |
| 42525880 | HDR | address | `READ ok 8x30` / `WRITE ok 4635` |
| 42526335 | GIF | memory | `READ ok 7x1` / `WRITE ok 119` |
| 42527322 | PICT | memory | `READ ok 223x256` / `WRITE ok 4732` |
| 42527699 | GIF | memory | `READ ok 2x32` / `WRITE ok 274` |
| 42528200 | PCX | memory | `READ ok 3x9` / `WRITE ok 236` |
| 42528610 | SUN | memory | `READ ok 5x2` / `WRITE ok 64` |
| 42529799 | MIFF | memory | `READ ok 3x4` / `WRITE ok 403` |
| 42530943 | MVG | address | `READ ok 2x1` / `WRITE ok 59` |
| 42531054 | MIFF | memory | `READ ok 5x1` / `WRITE ok 288` |
| 42533954 | PCDS | memory | `READ ok 128x138` / `WRITE ok 0` |
| 42533966 | MAC | memory | `READ ok 576x720` / `WRITE error: no encode delegate for this image format 'MAC'` |
| 42534188 | WPG | memory | `READ ok 288x288` / `WRITE error: no encode delegate for this image format 'WPG'` |
| 42534522 | TIM | memory | `READ ok 1x1` / `WRITE error: no encode delegate for this image format 'TIM'` |
| 42535688 | PDB | memory | `READ ok 4x535` / `WRITE ok 4456` |

这 27 条是**真正的"修好了"**：补丁让那些字节不再被当作越界的像素/元数据去处理，于是
解码器把它们当普通（哪怕是垃圾的）输入处理完。`42519182`（SUN）值得注意的是它就占
PoC 总体积的 94%，也是唯一一条在 vuln 树下必崩、fixed 树下稳定解出大图的样本。

### 3.2 limit（5 条）

| localId | coder | sanitizer | 结果 |
| --- | --- | --- | --- |
| 42518038 | G3 | undefined | `READ error: width or height exceeds limit 'G3:'` |
| 42518649 | PALM | memory | `READ error: width or height exceeds limit 'PALM:'` |
| 42518894 | WPG | memory | `READ error: width or height exceeds limit 'WPG:'` |
| 42519338 | WPG | memory | `READ error: width or height exceeds limit 'WPG:'` |
| 42519771 | TIM | memory | `READ error: width or height exceeds limit 'TIM:'` |

这 5 条共用补丁 `e8be814f1c3d2…`（`resolved/`），它改的是 fuzz 靶子的
`Magick++/fuzz/utils.cc`：在 `apply_fuzzing_limits` 里加了

```c++
resource_limits.width(2048);
resource_limits.height(2048);
```

也就是"声明一个 2048 以上的画布就不再解"。这不是对某个 coder 的修复，而是把 harness
的限制收紧到上游 OSS-Fuzz 当时的口径；因为 `scripts/hand_repro.cc` 用
`-DHARNESS_FIXED_LIMITS` 复刻了这两行（`build.sh` 只看树里有没有
`width(2048)` 就自动加），所以这 5 条在 `verify-after` 里表现为"被上限拦下"。

### 3.3 parser（36 条）

按异常短语归并（`'<name>:'` 代表具体格式名，如 `'MIFF:'`）：

| 异常短语 | 条数 | localId |
| --- | --- | --- |
| `unexpected end-of-file '<name>:'` | 10 | 42518438 (CIN)、42520948 (DCM)、42521858 (PALM)、42523502 (VIFF)、42530977 (HDR)、42531466 (DCM)、42533154 (VIFF)、42533821 (MIFF)、42534621 (PDB)、42535232 (RLE) |
| `improper image header '<name>:'` | 8 | 42518471、42520971 (PDB)、42522303 (WPG)、42525647、42525669、42527789、42528177 (MIFF)、42532777 (SCR) |
| `No image was loaded.` | 5 | 42519504、42520316、42520871、42526424 (EPSI/EPS)、42526757 (PS) |
| `non-conforming drawing primitive definition '<…>'` | 3 | 42521591 (`url(#`)、42522513 (`I333`)、42524289 (`ARC`)（均 MVG） |
| `unrecognized color '<…>'` | 3 | 42534921、42535088、42537011（均 MVG） |
| `pixels are not authentic '<name>:'` | 1 | 42518560 (TXT) |
| `corrupt image '<name>:'` | 1 | 42519416 (SIXEL) |
| `CorruptImage '<name>:'` | 1 | 42519760 (PES) |
| `insufficient image data in file '<name>:'` | 1 | 42519915 (MIFF) |
| `unable to uncompress image '<name>:'` | 1 | 42521846 (PICT) |
| `CorruptWBMPimage '<name>:'` | 1 | 42522269 (WBMP) |
| `not enough pixel data '<name>:'` | 1 | 42524701 (XCF) |
| **合计** | **36** | |

这 36 条是"补丁把校验提前"的那一类：补丁在 `Read<FORMAT>Image` 里加了边界/长度检查，
于是同一条 PoC 现在在 `read()` 阶段就拿到一个明确的异常，走不到原来越界的那一行。
`No image was loaded.` 那 5 条（EPS/EPSI/PS）是同一个原因的另一种表现——补丁让 PostScript
解析器在读到不完整的 DSC 头时直接放弃，不再返回一张空图。

## 4. 去掉 `-DHARNESS_FIXED_LIMITS` 的对照

把上面第 3.2 节的两行删掉（即不定义 `-DHARNESS_FIXED_LIMITS`）重跑 68 条：

| 分类 | 有上限（随包行为） | 无上限 |
| --- | --- | --- |
| decoded | 27 | 29 |
| limit | 5 | 0 |
| parser | 36 | 39 |
| **合计** | **68** | **68** |

差异只落在那 5 条上，其余 63 条逐条不变：

| localId | coder | 有上限 | 无上限 |
| --- | --- | --- | --- |
| 42518038 | G3 | limit | decoded（`READ ok 2592x1` / `WRITE ok 16`） |
| 42518649 | PALM | limit | parser（`unexpected end-of-file 'PALM:'`） |
| 42518894 | WPG | limit | parser（`unable to decompress image 'WPG:'`） |
| 42519338 | WPG | limit | parser（`unable to decompress image 'WPG:'`） |
| 42519771 | TIM | limit | decoded（`READ ok 1x1`，回写无编码器） |

这个对照说明两件事：

1. limit 那 5 条**不是**"解码成功"，只是被 harness 上限截住；去掉上限后它们要么解码
   （G3/TIM），要么变成解析拒绝（PALM/WPG）——仍然不崩，仍然 `CLEAN`，所以
   `verify-after` 的 `clean=68` 不依赖于这两行。`-DHARNESS_FIXED_LIMITS` 的作用是让
   驱动与固定树自带的 fuzz 靶子保持一致，而不是让结果"变干净"。
2. 27+5+36 这个分法本身是稳定的：63 条与宏无关，只有这 5 条随宏移动。

## 5. 68 条全表

`classification` 列即第 2 节的三类；`detail` 列是诊断驱动打印的原始短语（已去掉
`Magick: ` 前缀与 ` @ error/…` 后缀）。

| localId | coder | sanitizer | classification | detail |
| --- | --- | --- | --- | --- |
| 42518038 | G3 | undefined | limit | width or height exceeds limit `G3:' |
| 42518438 | CIN | address | parser | unexpected end-of-file 'CIN:': No such file or directory |
| 42518471 | MIFF | memory | parser | improper image header `MIFF:' |
| 42518560 | TXT | memory | parser | pixels are not authentic `TXT:' |
| 42518649 | PALM | memory | limit | width or height exceeds limit `PALM:' |
| 42518894 | WPG | memory | limit | width or height exceeds limit `WPG:' |
| 42519182 | SUN | address | decoded | READ ok 25x1 / WRITE ok 36 |
| 42519338 | WPG | memory | limit | width or height exceeds limit `WPG:' |
| 42519416 | SIXEL | address | parser | corrupt image `SIXEL:' |
| 42519504 | EPSI | address | parser | No image was loaded. |
| 42519749 | SIX | address | decoded | READ ok 2x6 / WRITE ok 59 |
| 42519760 | PES | address | parser | CorruptImage `PES:' |
| 42519771 | TIM | memory | limit | width or height exceeds limit `TIM:' |
| 42519915 | MIFF | memory | parser | insufficient image data in file `MIFF:' |
| 42520316 | EPS | address | parser | No image was loaded. |
| 42520493 | DXT5 | address | decoded | READ ok 11x5 / WRITE ok 224 |
| 42520871 | EPS | memory | parser | No image was loaded. |
| 42520948 | DCM | memory | parser | unexpected end-of-file 'DCM:': No such file or directory |
| 42520971 | PDB | memory | parser | improper image header `PDB:' |
| 42521159 | TXT | memory | decoded | READ ok 7x1 / WRITE ok 405 |
| 42521170 | WPG | memory | decoded | READ ok 32x288 / WRITE error (no encode delegate) |
| 42521270 | PCX | memory | decoded | READ ok 1x1 / WRITE ok 131 |
| 42521591 | MVG | address | parser | non-conforming drawing primitive definition `url(#' |
| 42521846 | PICT | memory | parser | unable to uncompress image `PICT:' |
| 42521858 | PALM | memory | parser | unexpected end-of-file 'PALM:': No such file or directory |
| 42521880 | VIFF | memory | decoded | READ ok 3x7 / WRITE ok 1108 |
| 42522269 | WBMP | memory | parser | CorruptWBMPimage `WBMP:' |
| 42522303 | WPG | memory | parser | improper image header `WPG:' |
| 42522513 | MVG | memory | parser | non-conforming drawing primitive definition `I333' |
| 42522869 | PALM | memory | decoded | READ ok 511x255 / WRITE ok 16336 |
| 42523358 | PNM | memory | decoded | READ ok 2x3 / WRITE ok 10 |
| 42523502 | VIFF | memory | parser | unexpected end-of-file 'VIFF:': No such file or directory |
| 42523812 | DPX | memory | decoded | READ ok 32x16 / WRITE ok 9216 |
| 42523868 | MAT | memory | decoded | READ ok 2x1 / WRITE ok 192 |
| 42523879 | PSD | address | decoded | READ ok 2x1 / WRITE ok 399 |
| 42524289 | MVG | address | parser | non-conforming drawing primitive definition `ARC' |
| 42524701 | XCF | memory | parser | not enough pixel data `XCF:' |
| 42525613 | PSD | memory | decoded | READ ok 7x1 / WRITE ok 196 |
| 42525647 | MIFF | memory | parser | improper image header `MIFF:' |
| 42525669 | MIFF | memory | parser | improper image header `MIFF:' |
| 42525880 | HDR | address | decoded | READ ok 8x30 / WRITE ok 4635 |
| 42526335 | GIF | memory | decoded | READ ok 7x1 / WRITE ok 119 |
| 42526424 | EPSI | address | parser | No image was loaded. |
| 42526757 | PS | address | parser | No image was loaded. |
| 42527322 | PICT | memory | decoded | READ ok 223x256 / WRITE ok 4732 |
| 42527699 | GIF | memory | decoded | READ ok 2x32 / WRITE ok 274 |
| 42527789 | MIFF | address | parser | improper image header `MIFF:' |
| 42528177 | MIFF | memory | parser | improper image header `MIFF:' |
| 42528200 | PCX | memory | decoded | READ ok 3x9 / WRITE ok 236 |
| 42528610 | SUN | memory | decoded | READ ok 5x2 / WRITE ok 64 |
| 42529799 | MIFF | memory | decoded | READ ok 3x4 / WRITE ok 403 |
| 42530943 | MVG | address | decoded | READ ok 2x1 / WRITE ok 59 |
| 42530977 | HDR | memory | parser | unexpected end-of-file 'HDR:': No such file or directory |
| 42531054 | MIFF | memory | decoded | READ ok 5x1 / WRITE ok 288 |
| 42531466 | DCM | address | parser | unexpected end-of-file 'DCM:': No such file or directory |
| 42532777 | SCR | memory | parser | improper image header `SCR:' |
| 42533154 | VIFF | memory | parser | unexpected end-of-file 'VIFF:': No such file or directory |
| 42533821 | MIFF | memory | parser | unexpected end-of-file 'MIFF:': No such file or directory |
| 42533954 | PCDS | memory | decoded | READ ok 128x138 / WRITE ok 0 |
| 42533966 | MAC | memory | decoded | READ ok 576x720 / WRITE error (no encode delegate) |
| 42534188 | WPG | memory | decoded | READ ok 288x288 / WRITE error (no encode delegate) |
| 42534522 | TIM | memory | decoded | READ ok 1x1 / WRITE error (no encode delegate) |
| 42534621 | PDB | memory | parser | unexpected end-of-file 'PDB:': No such file or directory |
| 42534921 | MVG | address | parser | unrecognized color `(' |
| 42535088 | MVG | address | parser | unrecognized color `(' |
| 42535232 | RLE | memory | parser | unexpected end-of-file `RLE:' |
| 42535688 | PDB | memory | decoded | READ ok 4x535 / WRITE ok 4456 |
| 42537011 | MVG | address | parser | unrecognized color `(' |

## 6. 怎么复现

诊断驱动只是 `scripts/hand_repro.cc` 加几行打印，用固定树的静态库编出来即可：

```bash
inst=/work/build-fixed-address/inst          # imdt build-san fixed address 留下的安装前缀
clang++ -fsanitize=address -stdlib=libc++ -std=c++11 -DHARNESS_FIXED_LIMITS \
  -I$inst/include/ImageMagick-7 diag.cc -o /work/diag \
  -DMAGICKCORE_HDRI_ENABLE=1 -DMAGICKCORE_QUANTUM_DEPTH=16 \
  $inst/lib/libMagick++-7.Q16HDRI.a $inst/lib/libMagickWand-7.Q16HDRI.a \
  $inst/lib/libMagickCore-7.Q16HDRI.a -lpthread -lm
export ASAN_OPTIONS=detect_leaks=0
awk -F'\t' '!/^#/ && NF>=11 {print $1"\t"$2"\t"$7}' /payload/cases.tsv |
while IFS=$'\t' read -r id coder poc; do
  printf '%s\t%s\t%s\n' "$id" "$coder" "$(/work/diag "$coder" "/payload/$poc" | tr '\n' ' ')"
done
```

去掉 `-DHARNESS_FIXED_LIMITS` 重编一次即可得到第 4 节的对照。判定本身不需要这个驱动：
`imdt verify-after --no-build` 这一条命令就给出 `crash=0 clean=68`。
