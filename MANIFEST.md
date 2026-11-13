# 交付件清单

一个包，两样东西：**源码**（4,987 个文件，103,899,203 字节 ≈ 99.1 MiB，其中 `src/` 下是两棵
源码树 4,832 个文件 / 102,581,306 字节，其余交付件 155 个文件 / 1,317,897 字节）+
**成品镜像 tar**（`im-arvo-2018-01-16.tar`，1,502,612,480 字节 = 1.40 GiB；`docker load`
后 `docker images` 显示 5.54 GB，是解压后的大小；`docker inspect .Size` = 5,535,590,630 B）。

镜像里装的是 **两棵普通源码树** + **62 个显式补丁** + **6 个插桩复现器**：
没有 git 仓库、没有 `vuln`/`fixed` tag、没有 fuzz 靶子、没有 libFuzzer 运行时，
基镜像自带的 `/src/afl`、`/src/honggfuzz`、`/src/libfuzzer`、`/src/afl_testcases.tgz`、
`/src/build.sh` 也在构镜像时删掉了——`ls /src` 恰好只有 `imagemagick-fixed imagemagick-vuln`。

## 0. 四条数据集契约 → 本包的落点

| # | 契约 | 落点 | 实测 |
| --- | --- | --- | --- |
| 1 | 源码可构建；**一个 plain 构建脚本**一次编出漏洞版与修复版；镜像里有 `/src/imagemagick-vuln`、`/src/imagemagick-fixed` | `scripts/build.sh`（33 行 / 22 行有效，`build.sh [vuln\|fixed\|all]`，默认 `all`）；两棵树各自 `./configure` → `make -j$(nproc)`，原地构建 | 干净镜像 `imdt build`：vuln 36 s、fixed 40 s（合计 1 m 16 s）；两棵树 `utilities/magick -version` 都是 `ImageMagick 7.0.7-22 Q16 x86_64`；再跑一次 1 s |
| 2 | 插桩构建脚本简单，且**修前/修后同一个**；验证脚本**只有一个** | `scripts/build-san.sh`（91 / 59 行，`[vuln\|fixed\|all\|DIR] [address\|undefined\|memory\|all]`，接受任意目录）与 `scripts/verify.sh`（107 / 83 行，`[vuln\|fixed\|all\|DIR] [--san] [--expect] [--report]`） | 同一个 `build-san.sh` 编出 6 个 `/out/repro-<tree>-<san>`；同一个 `verify.sh` 判 `vuln` → `crash=68 clean=0`、`fixed` → `crash=0 clean=68` |
| 3 | 每个漏洞的修复是**显式补丁** | `payload/patches/*.patch`（45，上游原样）+ `payload/patches/resolved/*.patch`（17，按基线适配）= 62；`cases.tsv` 的 `patch`/`patch_status`、`vulnerabilities.json` 的 `patch.file` | 68 条案例 → 62 个唯一补丁；`git apply` / `patch -p1` 都能直接落到 vuln 树 |
| 4 | `verify.sh` 简单，且：vuln 全报、fixed 全不报、**只修一个 bug 时只翻它的 PoC** | `verify.sh` 只做三件事：读 `payload/cases.tsv` → 跑每条 PoC → 看有没有 `SUMMARY:`；期望用 `--expect crash\|clean\|any` 表达 | `crash=68 clean=0` / `crash=0 clean=68`；`/work/partial`（vuln + 恰好一个补丁 `9998cd71…`）→ `crash=67 clean=1`，唯一 CLEAN 是 `42518438 CIN`；`verify-one` 对 1 条与 5 条的例子各跑一次，全部 PASS |

## 1. 镜像内布局

```
/src                     111 MB（103,306,298 B）  只有下面两棵树（ls /src 恰好 2 项）
/src/imagemagick-vuln    51,647,227 B   plain 源码树 = 上游 13ffeab + ResetImagePixels 前置补丁
/src/imagemagick-fixed   51,654,975 B   plain 源码树 = vuln + 62 个修复补丁（tree e3f58920…）
/payload                 1.8 MB         cases.tsv、pocs/（68）、patches/（45 + 17）、vulnerabilities.*
/opt/imdt                48 KB          scripts/ 的内容，PATH 里有它
/out                     115,070,896 B  6 个插桩复现器（2 树 × 3 sanitizer）
/work                    空            构建时装到 /work/build-<name>-<san>/
```

两棵树都是普通目录，没有 `.git`；树名就是路径，不需要 `git checkout` 切树。每棵树根下的
`.source-id` 记着它的来历：

```
$ cat /src/imagemagick-vuln/.source-id          $ cat /src/imagemagick-fixed/.source-id
tree      imagemagick-vuln                      tree      imagemagick-fixed
upstream  13ffeabe9abd6c262a8b6bfaeb1e145a420f8e3a
commit    cac8ee0ead0871909046c560a2b0e7b2ac9bb19c
tree_sha  a2e675ea85b01a951d0463c1994f2b2d475a54c6
date      2018-01-16                            date      2018-03-20
```

（`fixed` 的 `commit` 是 `7940a980a4888c83a9cf552ef6cd419a7fce3221`、`tree_sha` 是
`e3f5892044af808ef8eb3472d775d8b450f58628`。这两个提交是构镜像时合成的，只用来给树算
身份，镜像里不留 `.git`。）

`/out` 六个复现器：

| 文件 | 字节 | sanitizer | 编译宏 |
| --- | --- | --- | --- |
| `repro-vuln-address` | 21,540,296 | ASan | — |
| `repro-vuln-undefined` | 12,982,632 | UBSan | — |
| `repro-vuln-memory` | 23,001,648 | MSan | — |
| `repro-fixed-address` | 21,545,944 | ASan | `-DHARNESS_FIXED_LIMITS` |
| `repro-fixed-undefined` | 12,988,600 | UBSan | `-DHARNESS_FIXED_LIMITS` |
| `repro-fixed-memory` | 23,007,680 | MSan | `-DHARNESS_FIXED_LIMITS` |

**镜像里没有**：`/src/imagemagick`（旧方案的 git 仓库）、`/refs`（构镜像的补丁输入）、
`/src/afl`、`/src/honggfuzz`、`/src/libfuzzer`、`/src/afl_testcases.tgz`、`/src/build.sh`
（基镜像自带的 fuzz 工具，构镜像时一并 `rm -rf`）、`prebuilt/`、`encoder_*_fuzzer`、
libFuzzer 运行时。Dockerfile 结尾用 `test ! -e /src/imagemagick`、`test ! -e /refs`、
`test "$(ls /src | tr '\n' ' ')" = "imagemagick-fixed imagemagick-vuln "`、`ls /out | wc -l`
等断言兜住。

## 2. 68 个案例 ↔ 62 个补丁

`cases.tsv` 有 68 行（每条案例一个 PoC），`patch` 列指向 62 个**唯一**补丁：

| 补丁 | 案例数 | 说明 |
| --- | --- | --- |
| `patches/resolved/e8be814f1c3d…` | **5** | 改 `Magick++/fuzz/utils.cc`（`ResourceLimits::width/height(2048)`），5 条案例共用一个"harness 收紧"修复 |
| `patches/60cb93d03a9f…` | **2** | 一个补丁同时修两条案例 |
| `patches/resolved/78eaf41a792b…` | **2** | 同上 |
| 其余 59 个补丁 | 1 | 一条案例一个补丁 |
| **合计** | **68** | 5 + 2 + 2 + 59×1 = 68 |

所以"只修一个 bug"在补丁粒度上意味着：**应用一个补丁，只有它自己的案例（1、2 或 5 条）
从 CRASH 变 CLEAN，其余仍全部 CRASH**。`verify-one.sh` 把这句话跑成断言，`/work/partial`
的实验（第 5 节）把这句话跑成 67/1。

## 3. 文件清单与校验值

| 文件 | 字节 | SHA256 |
| --- | --- | --- |
| `README.md` | 38,376 | `9dcbc821116691d278de5f2b524b7fe6ef2474ec691c4e4fea5f89fd91488a8b` |
| `MANIFEST.md` | — | —（自引用不入表；校验：`sha256sum MANIFEST.md`） |
| `image/Dockerfile` | 6,422 | `eefd5007832db4421cec0a8b6a81df3d248dcc40e54864067c90e966f117f574` |
| `image/build-image.ps1` | 383 | `88ea65825101d5356970a3505ad8d210ce0bb2b2ddcfd61c858b01fb531433eb` |
| `image/refs/combined.patch` | 63,703 | `7e50a7a65ecce55b93933d0ee5b08da233b88ddab1f696148ee561378620447a` |
| `image/refs/prereq-reset-image-pixels.patch` | 3,287 | `111ef45a653f2ba30c7f72d6cd9d424e2b5b09ef157ec1bbdaa15bb5579d0b59` |
| `payload/cases.tsv` | 15,915 | `122f3a130ddd41262e4cc6fa75ab7a52db46ac5e439107eb833bbf54272e985a` |
| `payload/vulnerabilities.json` | 190,573 | `bdb73c97aa3259ef620bd71fcc2731231a7493fad16c4cabaaf55f807be74cc1` |
| `payload/vulnerabilities.csv` | 42,352 | `259c5c0acdcd19d94442ee782a8baf9485229455c44427b090615ed877c66d06` |
| `payload/vulnerabilities.md` | 76,955 | `7c3a2bd964bbaa542b430663ba5df7dc189a33cf00a91c24d433854c9d15802c` |
| `payload/patches/*.patch` | 45 个文件，45,668 B | 逐条：`ls payload/patches/*.patch \| sort \| xargs cat \| sha256sum` = `022cdd38f0ddfd8b25d360ef1bd57e6dc45d15e886437fe38bf7b959151e3171` |
| `payload/patches/resolved/*.patch` | 17 个文件，24,879 B | 逐条：`ls payload/patches/resolved/*.patch \| sort \| xargs cat \| sha256sum` = `4365f05c5cb67f54af21e6023c747e0f652f447eccf5b31f0e7e0341e061f591` |
| `payload/pocs/<localId>/poc` | 68 个文件，697,128 B | 逐条：`find payload/pocs -name poc \| sort \| xargs cat \| sha256sum` = `2abbf0831df2c5997a7d4742c40544abad23a1ddd6addc2c1b8e6bf1b55ebb89` |
| `src/imagemagick-vuln/` | 2,416 个文件，51,286,779 B | 聚合：`cd src/imagemagick-vuln && find . -type f -print0 \| LC_ALL=C sort -z \| xargs -0 sha256sum \| sha256sum` = `4016302aec61d8003066ab742a922766f2517abf44942befff9204f47803173b` |
| `src/imagemagick-fixed/` | 2,416 个文件，51,294,527 B | 同上 = `17a1332c413bfd2d79c45461d8276e45cfd7c12ffd479a9f60be3e6f079a67e0` |
| `scripts/lib.sh` | 4,224 | `8506c2d67a7f6205749c414a5cfe7be257afc8445368bd9a2ff42bd697d06cc6` |
| `scripts/build.sh` | 1,429 | `c0cfa0f7627320a29a7a55b6ce303c78df8789f15e3237aa7f0422fac101c559` |
| `scripts/build-san.sh` | 4,857 | `c5d4ae94ca67ccc4c0aa3340553f77fc18b36f3a92733c2c932ea4dda2ad7d29` |
| `scripts/hand_repro.cc` | 3,015 | `09b9ca6bfb686cbc57540509be16f302fbede42dd26b62cd5c4904e182d18d35` |
| `scripts/verify.sh` | 4,842 | `f9800a71a501d6bd7e5efda15839abc1f4a68bc859087b805217761966088036` |
| `scripts/verify-one.sh` | 4,175 | `840643d03098cd35d8a53b587828a4f4fada2eb6cc862e1c53d617d75e640f3a` |
| `scripts/imdt` | 2,010 | `7f8c894da4d795657c06b6d481a5c912a76a45c2da0a0edaf93557a8d60a5765` |
| `reports/before/verify-vuln.md` | 11,801 | `4141a1de43a7369ae791fb314874dc579917350104178b718e03c2a041c6a78c` |
| `reports/before/verify-vuln.json` | 16,003 | `c12cc0db4734d2217cc807fcd1f10bce11323f55c45e4224f8487ba6bf3fba3a` |
| `reports/after/verify-fixed.md` | 3,107 | `4b93e73c131918e6f12320a462b6df4158a6468efb55f9b15b23c3547005357f` |
| `reports/after/verify-fixed.json` | 7,308 | `5c0ac94942047c29c55c707c75071604171c0c11f5722f4d19e397716e5203a5` |
| `reports/after/cleanliness.md` | 16,372 | `5316205bc73a4cbb55e663f6d0e400b3f0d724f44db0e8de27ff4bec7380adc1` |
| `reports/one/verify-one-9998cd71.md` | 386 | `3f53c86925612262b2bf6ea2e7e726ad563d8ee4f1711fa564448f006e641624` |
| `reports/one/verify-one-9998cd71.json` | 16,347 | `e3b0c480db9ecc8e8b78b201e60facef6ad64fc223bb0ffbe9d40ff0513e6144` |
| `reports/one/verify-one-e8be814f.md` | 467 | `ed8c0fb103ad8e6d9d5e8b986652cf61902a74f87136f39350a0b0d712dd6451` |
| `reports/one/verify-one-e8be814f.json` | 15,824 | `cfe2b7d8b562b4c9e262a50b8592e6f0380f7b05261f9169b4088a5895fbc6d1` |
| `im-arvo-2018-01-16.tar` | 1,502,612,480 | `34d913858e79e0c8cc9cf8115ba247a789310d7d68670de577af46c0d75c103e` |
| `im-arvo-2018-01-16.tar.sha256` | 89 | `a08f8ae8ceba160594a48566ba063289a0169781c6f7470f6f3b4d9e619bb09b` |

```bash
cd deliver
sha256sum README.md payload/cases.tsv payload/vulnerabilities.{json,csv,md} \
          image/Dockerfile image/build-image.ps1 image/refs/*.patch \
          scripts/{lib.sh,build.sh,build-san.sh,hand_repro.cc,verify.sh,verify-one.sh,imdt} \
          reports/before/* reports/after/* reports/one/*
ls payload/patches/*.patch | wc -l                 # 45
ls payload/patches/resolved/*.patch | wc -l        # 17
find payload/pocs -name poc | wc -l                # 68
sha256sum -c im-arvo-2018-01-16.tar.sha256         # 1.5 GB，约 6 秒

# 两棵源码树的聚合校验（每棵树一条命令）
for t in imagemagick-vuln imagemagick-fixed; do
  (cd src/$t && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum)
done
# 期望：vuln   4016302aec61d8003066ab742a922766f2517abf44942befff9204f47803173b
#       fixed  17a1332c413bfd2d79c45461d8276e45cfd7c12ffd479a9f60be3e6f079a67e0
```

整包 **4,989 个文件**（含本文与 tar）；除 `MANIFEST.md` 自身外合计 **1,606,511,683 字节**：
两份源码树 102,581,306 字节（4,832 个文件）、其余交付件 1,317,897 字节、镜像 tar 1,502,612,480 字节。
`src/` 两棵树与成品镜像里的 `/src/imagemagick-{vuln,fixed}` 逐字节一致（两边的聚合值相同）。

## 4. 每个交付件的用途

| 交付件 | 解决的问题 |
| --- | --- |
| 两棵源码树（镜像内 `/src/imagemagick-{vuln,fixed}`） | "改哪个源码"不再靠 git 切 tag：树名就是路径，工具直接改一棵、构建一棵 |
| `scripts/build.sh` | 契约 1 的 plain 构建：**一个脚本编两棵树**，`./configure` + `make -j`，产物 `utilities/magick`；幂等，重跑秒级 |
| `scripts/build-san.sh` | 契约 2 的插桩构建：**修前/修后/工具改过的树只用这一个脚本**，`[TREE] [SAN]` 两个参数，接受目录；`-DHARNESS_FIXED_LIMITS` 依据树里的 `Magick++/fuzz/utils.cc` 自动加；每个 (树, sanitizer) 恰好一个 `/out/repro-<name>-<san>`，并核验二进制里真有 sanitizer 运行时符号 |
| `scripts/verify.sh` | 契约 2/4 的判定：读 `payload/cases.tsv` 跑 68 条，逐行 `CRASH\|CLEAN`，`crash=N clean=M`，`--expect crash\|clean\|any` 决定退出码；写 `.md` + `.json`（机器可读证据） |
| `scripts/verify-one.sh` | 单补丁归因：vuln + **恰好一个**补丁 → 插桩构建 → 跑**全部** 68 条 → 断言只有该补丁的案例变 CLEAN（1/2/5 条），并写 `verify-one-<sha8>.md` |
| `scripts/lib.sh` | 插件式公共函数：sanitizer profile 表、每个 profile 的环境变量、编译 flag、跑一条 PoC（含 MSan 重试）、树目录解析 |
| `scripts/hand_repro.cc` | 唯一复现驱动：`<coder> <poc>` 运行时选 coder，复刻 harness 契约（`magick` + `fileName("<coder>:")` → `read` → `write`，吞 `Magick::Exception`）与 `Magick++/fuzz/utils.cc` 的 fuzzing 限制 |
| `scripts/imdt` | 命令入口：`build` / `build-san` / `verify-before` / `verify-after` / `verify-all` / `verify-one`，`verify-*` 支持 `--no-build` |
| `payload/patches/`（62） | 契约 3 的显式补丁，按 `fix_commit` 命名，可与修复工具自己的改动逐行 diff |
| `payload/pocs/`（68） | PoC 原始字节，未经改写 |
| `payload/cases.tsv` | 对照组（11 列）：`localId coder target sanitizer expect_frame expect_kind poc patch patch_status after_expect fix_commit` |
| `payload/vulnerabilities.*` | 68 条漏洞清单：位置、CWE、描述、`code_snippet`、补丁元数据（`patch.file`） |
| `reports/before/`、`reports/after/` | `crash=68 clean=0` / `crash=0 clean=68` 的实测（md + json） |
| `reports/after/cleanliness.md` | 68 条"clean"的逐条成因：27 解码 / 5 被 harness 上限拦下 / 36 被更早的解析校验拒绝，并给出不带 `-DHARNESS_FIXED_LIMITS` 的对照（29 / 39） |
| `reports/one/` | `verify-one` 的单补丁归因实测（1 条与 5 条共享补丁各一例） |
| `image/Dockerfile` | 从 base 镜像造出两棵树 + 62 个补丁 + 6 个复现器，并在同一层删掉 `/refs` 与基镜像自带的 fuzz 工具目录；两棵树的 tree hash、`ls /src` 只有两项都在构建期断言 |
| `im-arvo-2018-01-16.tar`（+ `.sha256`） | 离线镜像 |

## 5. 交付前的实测记录

在交付镜像 `im-arvo:2018-01-16`（id `688bac9a85c2`）内实测，容器以
`--security-opt seccomp=unconfined` 起，入口是 `imdt`：

| 项 | 结果 |
| --- | --- |
| `ls /src` | 恰好两项：`imagemagick-vuln`、`imagemagick-fixed`（各含 `configure` 1,207,492 B、`Makefile.am` 11,697 B、`.source-id`），**没有** `.git`、没有 `/src/imagemagick`、没有 `/refs`、没有基镜像自带的 `/src/afl`、`/src/honggfuzz`、`/src/libfuzzer`、`/src/afl_testcases.tgz`、`/src/build.sh`；`du -sh /src` = **111 MB**（`du -sb` = 103,306,298 B） |
| `imdt build`（干净镜像，12 核） | vuln **36 s**、fixed **40 s**，合计 **1 m 16 s**；另一次（并发负载下）53 s + 54 s = 1 m 47 s；两棵树都输出 `Version: ImageMagick 7.0.7-22 Q16 x86_64 2026-11-12`；再跑 `imdt build` = **1 s** |
| `imdt build-san` | 三次实测 **6 m 27.8 s** / **7 m 0.3 s**（本次重打，Docker 层 `[8/9]`）/ **8 m 10.2 s**，编出 6 个 `/out/repro-*`（`du -sb /out` = 115,070,896 B）；每个二进制里都有对应的 sanitizer 运行时符号（`__asan_` 159 / `__ubsan_` 46 / `__msan_` 54 个符号） |
| `imdt verify-before --no-build` | `crash=68 clean=0 verdict=PASS`（18 s 冷启动 / 14 s 载入 tar 后重跑）→ `reports/before/verify-vuln.{md,json}` |
| `imdt verify-after --no-build` | `crash=0 clean=68 verdict=PASS`（3 s / 4 s）→ `reports/after/verify-fixed.{md,json}` |
| 部分修复（契约 4 第三句） | `cp -a /src/imagemagick-vuln /work/partial` + `patch -p1` 打 `9998cd71…` → `build-san.sh /work/partial all`（50.7 s address + 2 m 40 s undefined/memory）→ `verify.sh /work/partial --expect any` → **`crash=67 clean=1`**，唯一 `CLEAN 42518438 CIN` |
| 单补丁归因 | `imdt verify-one 42518438`（`9998cd71…`，1 条，4 m 57 s）→ PASS；`imdt verify-one 42518038`（`e8be814f…`，5 条共享，4 m 46 s）→ PASS，5 条全 CLEAN、其余 63 条 CRASH |
| `sha256sum -c im-arvo-2018-01-16.tar.sha256` | `im-arvo-2018-01-16.tar: OK`（1.5 GB，5.8 s） |
| `docker save` / `docker rmi` / `docker load -i` | `docker save` 1,502,612,480 B（62.8 s）；`docker rmi im-arvo:2018-01-16` 后镜像被删（`Deleted: sha256:688bac9a…`），`docker load -i` 61.6 s 输出 `Loaded image: im-arvo:2018-01-16`，ID 仍是 `688bac9a85c2`；重跑 `verify-before`/`verify-after` = `crash=68 clean=0`（14 s）/ `crash=0 clean=68`（4 s） |
| 镜像 | `docker images` 5.54 GB（内容 1.5 GB）；`docker inspect .Size` = 5,535,590,630 B；`/work` 空；`/src` 111 MB 且只有两棵树；`/payload/patches` 45 + 17；`/payload/pocs` 68；`/opt/imdt` 里的脚本与 `deliver/scripts/` 逐字节一致（`verify-one.sh` = `840643d0…`、`build-san.sh` = `c5d4ae94…`） |

单条手工复跑：

```bash
ASAN_OPTIONS=detect_leaks=0 /out/repro-vuln-address  MVG /payload/pocs/42524289/poc   # 期望 SUMMARY:
ASAN_OPTIONS=detect_leaks=0 /out/repro-fixed-address MVG /payload/pocs/42524289/poc   # 期望没有 SUMMARY:
```

## 6. 复现交付件本身

```bash
# 1) 重建镜像（context = deliver/，Dockerfile 自己导出两棵树、编 6 个复现器）
docker build -f deliver/image/Dockerfile -t im-arvo:2018-01-16 deliver

# 2) 验收
docker run -dit --name imarvo --security-opt seccomp=unconfined im-arvo:2018-01-16
docker exec -it imarvo imdt build                    # 两棵树的 plain 构建（约 76 s）
docker exec -it imarvo imdt build-san                # 6 个插桩复现器（约 6.5 min）
docker exec -it imarvo imdt verify-before --no-build --report /tmp/rep/before
docker exec -it imarvo imdt verify-after  --no-build --report /tmp/rep/after
docker exec -it imarvo imdt verify-one 42518438 --report /tmp/rep/one
docker cp imarvo:/tmp/rep/before deliver/reports/before
docker cp imarvo:/tmp/rep/after  deliver/reports/after
docker cp imarvo:/tmp/rep/one    deliver/reports/one

# 3) 导出镜像
docker save im-arvo:2018-01-16 -o deliver/im-arvo-2018-01-16.tar
sha256sum deliver/im-arvo-2018-01-16.tar > deliver/im-arvo-2018-01-16.tar.sha256
```

`image/refs/` 的两份补丁只在构镜像时用（`COPY image/refs/ /refs/`），同一个 `RUN` 里一并 `rm -rf`
掉：`/src/imagemagick`、`/refs`、`/out/*`、`/work/*`，以及基镜像自带的 `/src/afl`、
`/src/honggfuzz`、`/src/libfuzzer`、`/src/afl_testcases.tgz`、`/src/build.sh`——最终镜像里
这些都不存在，`ls /src` 只剩两棵树（Dockerfile 的最后一层用 `test` 断言这一点）。
