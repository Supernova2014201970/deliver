# ImageMagick ARVO 数据集（上游 `13ffeab`，2018-01-16）

一套可离线复现、可被工具驱动改写的 ImageMagick 漏洞数据集：

- **68 条** ARVO 案例，每条一个 PoC；
- **两棵完整、可直接构建的源码树**：`/src/imagemagick-vuln`（漏洞存在）、
  `/src/imagemagick-fixed`（全部修复）；
- **62 个显式修复补丁**（每条的修复单独成文件，可与工具自己的改动逐行 diff）；
- **一个 plain 构建脚本**（两棵树一起编）、**一个插桩构建脚本**（修前/修后同一个）、
  **一个验证脚本**（修前/修后/中间态同一个）。

镜像里没有 git 仓库、没有 tag、没有 fuzz 靶子、没有 libFuzzer 运行时：源码树是两棵普通目录，
补丁是补丁文件，判据是"跑 PoC 有没有 sanitizer 报告"。基镜像自带的 fuzz 相关目录
（`/src/afl`、`/src/honggfuzz`、`/src/libfuzzer`、`/src/afl_testcases.tgz`、`/src/build.sh`）
也在构镜像的同一层里删掉了，`ls /src` 只剩这两棵树。

---

## 0. 这份交付满足的四条数据集契约

| # | 契约要求 | 交付里的落点 | 实测证据 |
| --- | --- | --- | --- |
| 1 | 源码仓库必须可构建；用**一个简单的 plain 构建脚本**一次编出漏洞版和修复版；镜像里要有 `/src/imagemagick-vuln` 与 `/src/imagemagick-fixed` | `scripts/build.sh`（33 行，`build.sh [vuln\|fixed\|all]`，默认 `all`）：`cd /src/imagemagick-<tree>` → `./configure` → `make -j$(nproc)`，产物 `utilities/magick` | 干净镜像上 `imdt build`：vuln **36–53 s**、fixed **40–54 s**（两次实测合计 1 m 16 s / 1 m 47 s）；两棵树各自打印 `Version: ImageMagick 7.0.7-22 Q16 x86_64` |
| 2 | 改完源码后要能**重新插桩构建**并跑全部 PoC；插桩脚本必须简单，且**修前/修后是同一个脚本**；验证脚本同样**只有一个** | `scripts/build-san.sh`（91 行，`build-san.sh [vuln\|fixed\|all\|DIR] [address\|undefined\|memory\|all]`）+ `scripts/verify.sh`（107 行，`verify.sh [vuln\|fixed\|all\|DIR] [--san] [--expect] [--report]`） | `imdt build-san` 用同一个脚本编出 6 个 `/out/repro-<tree>-<san>`；`verify.sh` 同一份代码判 `vuln`（`crash=68`）与 `fixed`（`clean=68`） |
| 3 | 每个漏洞的修复必须是一个**显式补丁**，便于与修复工具的改动 diff | `payload/patches/*.patch`（45 个上游原样）+ `payload/patches/resolved/*.patch`（17 个按基线适配）= 62 个；`cases.tsv` 的 `patch` / `patch_status` 列、`vulnerabilities.json` 的 `patch.file` 指路 | 68 条案例 → 62 个唯一补丁；`patch -p1` / `git apply` 可直接落到 vuln 树上 |
| 4 | `verify.sh` 要简单，并且：vuln 树上每条 PoC 都报；fixed 树上一条都不报；**只修好一个 bug 时，只有它的 PoC 停止报** | `scripts/verify.sh` 只做三件事：读 `payload/cases.tsv` → 跑每条 PoC → 判 `SUMMARY:`；期望由 `--expect crash\|clean\|any` 表达 | `crash=68 clean=0` / `crash=0 clean=68`；`/work/partial` = vuln + 恰好一个补丁（`9998cd71…`）→ `crash=67 clean=1`，唯一 CLEAN 是 `42518438 CIN` |

---

## 1. 包里有什么

```
deliver/
├── README.md                     本文
├── MANIFEST.md                   交付件清单（含每个文件的字节数与 SHA256）
├── src/                          镜像 /src 的同一份内容（离线可直接看/编译，不用 docker）
│   ├── imagemagick-vuln/         2,416 个文件，51,286,779 B（= /src/imagemagick-vuln）
│   │   └── .source-id            上游 13ffeab…、合成提交 cac8ee0…、tree a2e675e…、2018-01-16
│   └── imagemagick-fixed/        2,416 个文件，51,294,527 B（= /src/imagemagick-fixed）
│       └── .source-id            上游 13ffeab…、合成提交 7940a98…、tree e3f58920…、2018-03-20
├── payload/                      → 打进镜像的 /payload
│   ├── vulnerabilities.json      68 条漏洞清单（位置/CWE/描述/代码片段/修复说明/补丁元数据）
│   ├── vulnerabilities.csv       同上，表格版
│   ├── vulnerabilities.md        同上，人读版
│   ├── cases.tsv                 脚本用的对照组（11 列，含 patch / patch_status）
│   ├── patches/<fix_commit>.patch           45 个上游原样补丁
│   ├── patches/resolved/<fix_commit>.patch  17 个按基线适配的补丁（合计 62 个）
│   └── pocs/<localId>/poc        68 个 PoC 原始文件（合计 697,128 B）
├── scripts/                      → 打进镜像的 /opt/imdt（也是 PATH 的一部分）
│   ├── lib.sh                    公共函数（sanitizer profile、env、flags、跑一条 PoC、树目录解析）
│   ├── build.sh                  plain 构建：两棵树，`./configure` + `make -j`
│   ├── build-san.sh              插桩构建：同一脚本编 vuln / fixed / 工具改过的树
│   ├── verify.sh                 验证：68 条案例 → CRASH/CLEAN + 报告（md + json）
│   ├── verify-one.sh             单补丁归因：vuln + 恰好一个补丁 → 跑全部 68 条
│   ├── hand_repro.cc             唯一复现入口（运行时选 coder，复刻 harness 契约）
│   └── imdt                      命令入口：build / build-san / verify-before / verify-after / verify-all / verify-one
├── image/
│   ├── Dockerfile                构建镜像（导出两棵源码树、编译 6 个复现器）
│   ├── build-image.ps1           构建镜像的一行包装
│   └── refs/                     仅构镜像用（打进镜像后在同一个 RUN 层里删除）
│       ├── prereq-reset-image-pixels.patch   3,287 B
│       └── combined.patch                    63,703 B（62 个补丁的并集）
└── reports/                      实测报告
    ├── before/verify-vuln.{md,json}
    ├── after/verify-fixed.{md,json}
    ├── after/cleanliness.md      "clean" 的逐条解释（27/5/36）
    └── one/                      verify-one 的单补丁归因实测
```

镜像 `im-arvo:2018-01-16`（5.54 GB）里：

```
/src                     111 MB（103,306,298 B）；只有下面两棵树，基镜像的 fuzz 目录已删
/src/imagemagick-vuln    plain 源码树（51,647,227 B，51.6 MB）
                           = 上游 13ffeab + ResetImagePixels 前置补丁
                           .source-id: tree/upstream/commit/tree_sha/date
/src/imagemagick-fixed   plain 源码树（51,654,975 B，51.7 MB）
                           = vuln + 62 个修复补丁（tree e3f5892044af808ef8eb3472d775d8b450f58628）
/payload                 payload/ 的内容：68 条案例、68 个 PoC、62 个补丁
/opt/imdt                scripts/ 的内容（PATH 已包含，可直接 `imdt ...`）
/out/repro-<tree>-<san>  6 个插桩复现器（2 树 × 3 sanitizer，共 110 MB）
/work                    空；构建时装到 /work/build-<name>-<san>/
```

两棵树都是**普通目录**：没有 `.git`，没有 tag，也不需要 `git checkout` 就能切换——树名就是路径。
每棵树根下的 `.source-id` 记着它是谁：

```
$ cat /src/imagemagick-fixed/.source-id
tree	imagemagick-fixed
upstream	13ffeabe9abd6c262a8b6bfaeb1e145a420f8e3a
commit	7940a980a4888c83a9cf552ef6cd419a7fce3221
tree_sha	e3f5892044af808ef8eb3472d775d8b450f58628
date	2018-03-20
```

`/refs` 只是构镜像的输入（`COPY image/refs/ /refs/` → 两棵树导出完 → 同一个 RUN 层里删掉）：
构镜像时执行 `rm -rf /src/imagemagick /refs /out/* /work/* /src/afl /src/honggfuzz /src/libfuzzer /src/afl_testcases.tgz /src/build.sh`。
最终镜像里没有 `/refs`，没有 `/src/imagemagick` 这个 git 仓库，也没有基镜像的 fuzz 工具目录；
Dockerfile 结尾用 `ls /src` 恰好等于 `imagemagick-fixed imagemagick-vuln`、`test ! -e /src/imagemagick`、
`test ! -e /refs` 校验。

一个包，两样东西：

| 产物 | 体积 | 作用 |
| --- | --- | --- |
| 源码部分（`src/`、`payload/`、`scripts/`、`image/`、`reports/`、`README.md`） | 约 104 MB | 两份源码树（`src/`，与镜像 `/src` 逐字节一致）+ 68 个 PoC + 62 个补丁 + 脚本 + 报告 + 构镜像的 Dockerfile |
| `im-arvo-2018-01-16.tar`（+ `.sha256`） | 见 `MANIFEST.md` | 离线可用的成品镜像，`docker load` 即得；`docker images` 显示的是解压后大小 |

```bash
sha256sum -c im-arvo-2018-01-16.tar.sha256
docker load -i im-arvo-2018-01-16.tar
docker run -it --security-opt seccomp=unconfined im-arvo:2018-01-16
```

基础镜像在 Dockerfile 里按 **digest** 钉死（`n132/arvo:42518038-vul@sha256:fce885bd…`），
从源码包重建不会随上游重打 tag 而漂移。

`src/imagemagick-vuln/` 与 `src/imagemagick-fixed/` 是从成品镜像里 `docker cp` 出来的同一份
内容（`.git` 没有，`.source-id` 在），所以**不开 docker 也能看源码、跑静态分析、做 diff**：

```bash
diff -ru src/imagemagick-vuln src/imagemagick-fixed | diffstat     # 只差那 62 个修复
cd src/imagemagick-vuln && ./configure --disable-shared --without-perl && make -j"$(nproc)"
```

两者合计约 102.6 MB（4,832 个文件），聚合哈希见 `MANIFEST.md` §2；如果不需要离线源码，
只取除 `src/` 之外的部分（约 1.3 MB + 镜像 tar）。

---

## 2. 快速开始

```bash
# 1) 构建镜像（自带编译；不需要任何预编译产物）
docker build -f deliver/image/Dockerfile -t im-arvo:2018-01-16 deliver

# 2) 起容器（MSan 需要 seccomp=unconfined）
docker run -dit --name imarvo --security-opt seccomp=unconfined im-arvo:2018-01-16

# 3) plain 构建两棵树（工具驱动的那条路径）
docker exec -it imarvo imdt build                     # = build.sh all，约 76 s

# 4) 插桩构建两棵树 × 三套 sanitizer（修前/修后同一个脚本）
docker exec -it imarvo imdt build-san                 # = build-san.sh all all，约 6 分钟

# 5) 验证：修前全崩、修后全不崩
docker exec -it imarvo imdt verify-before --no-build
docker exec -it imarvo imdt verify-after  --no-build

# 6) 单补丁归因（vuln + 恰好一个补丁 → 只有它的 PoC 变成 CLEAN）
docker exec -it imarvo imdt verify-one 42518438
```

`imdt` 的六个子命令就是全部入口：

| 命令 | 等价脚本调用 | 说明 |
| --- | --- | --- |
| `imdt build [vuln\|fixed\|all]` | `build.sh` | plain 构建，默认 `all` |
| `imdt build-san [TREE] [SAN]` | `build-san.sh` | 插桩构建，默认 `all all` |
| `imdt verify-before [--no-build] [opts]` | `build-san.sh vuln all` → `verify.sh vuln --report reports/before` | 期望 `crash=68` |
| `imdt verify-after [--no-build] [opts]` | `build-san.sh fixed all` → `verify.sh fixed --report reports/after` | 期望 `clean=68` |
| `imdt verify-all [--no-build] [opts]` | 上面两个依次跑 | 两次都 PASS 才 exit 0 |
| `imdt verify-one <localId>\|--patch <sha> [opts]` | `verify-one.sh` | 单补丁归因 |

`TREE` 可以是 `vuln` / `fixed` / `all`，也可以是**任意目录**（工具改过的树，例如 `/work/partial`）。
`[opts]` 原样透传给 `verify.sh`：`--san`、`--expect`、`--report`。

预期结果（判据：输出里出现 `SUMMARY:` 记 CRASH，否则 CLEAN）：

| 命令 | 报告 | 总计 | 结论 |
| --- | --- | --- | --- |
| `imdt verify-before --no-build` | `reports/before/verify-vuln.{md,json}` | `crash=68 clean=0` | 68 条全部复现崩溃 |
| `imdt verify-after --no-build` | `reports/after/verify-fixed.{md,json}` | `crash=0 clean=68` | 68 条全部不再崩（成因见 `reports/after/cleanliness.md`：27 解码成功 / 5 被 harness 上限拦下 / 36 被补丁提前拒绝） |
| `imdt verify-one <localId>` | `reports/one/verify-one-<sha>.md` | 68 条 | vuln + 该案例的一个补丁 → 只有它的案例 CLEAN |

只跑一套 sanitizer：

```bash
docker exec -it imarvo imdt verify-before --no-build --san address     # 只跑 ASan 那 20 条
docker exec -it imarvo verify.sh vuln --san memory --report /tmp/rep/mem
```

> `verify.sh` **不构建**，只跑现成产物；产物缺失会直接报错并告诉你该跑哪条 build 命令。

---

## 3. 镜像里的两棵源码树是怎么来的

两棵树由 `image/Dockerfile` 在构建期从基镜像的上游历史里**导出**（导出后历史即被丢弃）：

```bash
git checkout -q -f --detach 13ffeabe9abd6c262a8b6bfaeb1e145a420f8e3a
git apply /refs/prereq-reset-image-pixels.patch
git add -A && git commit -m "baseline 7.0.7-21-82-g13ffeab + ResetImagePixels prerequisite"
#   → cac8ee0ead0871909046c560a2b0e7b2ac9bb19c，tree a2e675ea…
git archive HEAD | tar -x -C /src/imagemagick-vuln            # 导出成一棵普通目录
git apply --3way /refs/combined.patch
git add -A && git commit -m "apply all 62 ImageMagick fixes for the ARVO cases"
#   → 7940a980a4888c83a9cf552ef6cd419a7fce3221，tree e3f5892044af808ef8eb3472d775d8b450f58628
git archive HEAD | tar -x -C /src/imagemagick-fixed
# 历史、构建输入、基镜像的 fuzz 工具都不留在镜像里
rm -rf /src/imagemagick /refs /out/* /work/* \
       /src/afl /src/honggfuzz /src/libfuzzer /src/afl_testcases.tgz /src/build.sh
```

作者/提交者身份与日期在 Dockerfile 里钉死，所以上面两个提交号与 `fixed^{tree}` 每次构建都一样；
构建期用 `test` 校验 `commit`、`tree_sha`、`38 个文件被改动`，任何一条不成立镜像就构建失败。

| 树 | 构成 | 提交（`.source-id` 里） | tree |
| --- | --- | --- | --- |
| `/src/imagemagick-vuln` | `13ffeab` + `prereq-reset-image-pixels.patch` | `cac8ee0ead0871909046c560a2b0e7b2ac9bb19c` | `a2e675ea85b01a951d0463c1994f2b2d475a54c6` |
| `/src/imagemagick-fixed` | vuln + 62 个修复补丁（`combined.patch`） | `7940a980a4888c83a9cf552ef6cd419a7fce3221` | `e3f5892044af808ef8eb3472d775d8b450f58628` |

两棵树之间**只差这 62 个补丁**（`38 files changed, 310 insertions(+), 134 deletions(-)`）。

**为什么是合成提交，而不是两个真实上游提交**：62 个修复提交里有 **19 个** 晚于 ResetImagePixels，
它们的补丁落不到 `13ffeab` 上，直接把 fixed 指向某个真实提交就会因为这些前置依赖丢掉案例；
而最早包含全部 62 个修复的真实上游提交比 `13ffeab` 晚 **665 个提交**，会拖进几百个无关改动，
让"这条案例被哪个补丁修好"不可归因。合成节点让两棵树只差这 62 个补丁，一条不多。

> **版本号更正**：`13ffeab` **不是** tag `7.0.7-22`，而是 `7.0.7-21-82-g13ffeab`（2018-01-16）。
> `utilities/magick -version` 打印的 `7.0.7-22` 来自 `configure.ac` 里的版本号，不是 `git describe`。

没有 git 仓库之后，"看修复"靠补丁文件本身：

```bash
cat /payload/patches/<fix_commit>.patch              # 单条修复的完整补丁
diff -u -r /src/imagemagick-vuln /src/imagemagick-fixed | less   # 62 个补丁的净效果
jq '.vulnerabilities[] | select(.localId=="42518438") | .patch' /payload/vulnerabilities.json
```

`payload/vulnerabilities.json` 的 `patch` 字段保留了上游提交号、状态（`upstream`/`resolved`）、
涉及文件与行数；逐条明细在 `payload/vulnerabilities.md`。

---

## 4. 三个脚本

行数（`wc -l` / 去掉注释与空行后的代码行）：

| 脚本 | 行数 | 代码行 | 作用 |
| --- | --- | --- | --- |
| `build.sh` | 33 | 22 | plain 构建，一次编一棵或两棵树 |
| `build-san.sh` | 91 | 59 | 插桩构建，同一脚本编 vuln / fixed / 工具改过的树 |
| `verify.sh` | 107 | 83 | 跑 68 条案例并写报告，同一脚本判修前/修后/中间态 |
| `verify-one.sh` | 94 | 65 | 单补丁归因 |
| `lib.sh` | 84 | 48 | 公共函数 |
| `imdt` | 41 | 24 | 子命令分发 |

### 4.1 `build.sh` — plain 构建（两棵树一起）

```bash
build.sh [vuln|fixed|all]        # 默认 all
```

对每棵树：`cd /src/imagemagick-<tree>` → `./configure --disable-shared --disable-docs
--disable-openmp --without-perl`（`configure` 是树里自带的，从不重新生成）→ `make -j$(nproc)`，
就地构建，产物 `utilities/magick`。没有 sanitizer、没有 install 前缀、没有复现器。

- **幂等**：`Makefile` 已存在就跳过 configure，`make` 天然增量；第二次跑 0 s。
- **会打印它构建了什么**：`built vuln: /src/imagemagick-vuln/utilities/magick (36s) — Version: ImageMagick 7.0.7-22 Q16 x86_64 …`。
- 编译用基镜像的 `CC=clang`，不做任何插桩——这正是静态分析类工具要驱动的构建。

实测（干净镜像，12 核，两次）：`imdt build` = vuln **36 s** + fixed **40 s**（合计 1 m 16 s），
另一次 53 s + 54 s（合计 1 m 47 s，宿主机同时在跑别的活）；紧接着 `imdt build` 再跑一次 =
**1 s**（configure 跳过、make 无改动）。

### 4.2 `build-san.sh` — 插桩构建（修前/修后同一个脚本）

```bash
build-san.sh [vuln|fixed|all|DIR] [address|undefined|memory|all]    # 默认 all all
build-san.sh vuln address          # 一棵树、一套 sanitizer
build-san.sh /work/partial address # 工具改过的树：任意目录
```

每次构建一个 `(树, sanitizer)` 组合，产出**恰好一个**可执行文件
`/out/repro-<name>-<san>`：`hand_repro.cc` 用该次构建 **install 出来的头文件与静态库** 编译，
插桩参数与整棵树一致。`<name>` 是 `vuln` / `fixed` / 被构建目录的 basename（如 `partial`）。

要点（都是"正确性"而非风格）：

- **copy 构建**：把源码树复制到 `/work/build-<name>-<san>/src`，install 前缀是同级 `inst/`。
  VPATH 构建只在从未配置过的树上可用——`configure` 一旦看到 `$srcdir/config.status`
  就直接报 `source directory already configured`，而 `build.sh` 恰好会留下它。复制时先
  `make distclean`、删掉 `config.status` 与残留 `.o`/`.lo`，避免拿普通 flag 编出来的目标文件。
- **configure 用不带插桩的 flag，插桩只在 `make` 阶段注入**：MSan 插桩过的探测程序在
  configure 阶段跑不起来。
- **每套 sanitizer 单独一个二进制**，从不合并（ASan+UBSan 同编时，fixed 树会报一堆与本次修复
  无关的既有 UB）。
- `-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`、`-fno-omit-frame-pointer`、
  `-gline-tables-only` 与 OSS-Fuzz 一致；MSan 额外 `-L/usr/msan/lib`（镜像里插桩过的 libc++），
  复现器链接显式带 `-stdlib=libc++`。
- **`-DHARNESS_FIXED_LIMITS` 由树自己决定**：`grep -q 'width(2048)' Magick++/fuzz/utils.cc`。
  fixed 树因 `e8be814f` 有这行（`ResourceLimits::width/height(2048)`），vuln 树没有；工具只修
  一个 bug 的中间态也会被正确判断。
- **构建后校验插桩真的在二进制里**：`nm` 落到文件再 `grep __asan_|__msan_|__ubsan_`，
  不在就报错退出。
- **重跑很便宜**：源码指纹（`find -printf '%P %s %T@'`）没变就 `up to date:` 跳过。

实测产物（镜像 `/out`，字节）：

| 文件 | 字节 | 插桩 | harness 上限 |
| --- | --- | --- | --- |
| `repro-vuln-address` | 21,540,296 | ASan | 无 |
| `repro-vuln-undefined` | 12,982,632 | UBSan | 无 |
| `repro-vuln-memory` | 23,001,648 | MSan | 无 |
| `repro-fixed-address` | 21,545,944 | ASan | `-DHARNESS_FIXED_LIMITS` |
| `repro-fixed-undefined` | 12,988,600 | UBSan | `-DHARNESS_FIXED_LIMITS` |
| `repro-fixed-memory` | 23,007,680 | MSan | `-DHARNESS_FIXED_LIMITS` |

合计 115,066,800 B（110 MiB）。镜像构建期串行编完这 6 个：address 43 s、undefined 68 s、
memory 75 s（vuln），fixed 48 / 70 / 69 s；整轮 `imdt build-san` 三次实测 **6 m 28 s**、
**7 m 0 s**（本次重打的镜像，Docker 层 `[8/9]` 420.3 s）与 **8 m 10 s**（与宿主机上其他构建并发）。

### 4.3 `verify.sh` — 验证（修前/修后/中间态同一个脚本）

```bash
verify.sh [vuln|fixed|all|DIR] [--san all|address|undefined|memory]
          [--expect crash|clean|any] [--report DIR]
```

读 `payload/cases.tsv`（68 行，列：`localId coder target sanitizer expect_frame expect_kind
poc patch patch_status after_expect fix_commit`），对每条案例跑对应的复现器，打印一行：

```
CRASH 42518438  CIN    address   SUMMARY: AddressSanitizer: heap-buffer-overflow …/quantum-private.h in PushLongPixel
CLEAN 42518438  CIN    address   -
```

最后 `crash=68 clean=0 verdict=PASS`，写 `DIR/verify-<name>.md` 与 `.json`
（每条案例一行 + 总计 + verdict，机器可读）。

- **判据只有一条**：输出里出现 `SUMMARY:` 就是 CRASH。不看 exit code——ImageMagick 解码失败走
  异常路径，exit 仍是 0；也不比对函数名，因为 ARVO 的措辞在重放时会变。
- **默认期望**：`vuln` → `crash`、`fixed` → `clean`、其它目录（工具改过的树）→ `any`（只报告）。
  `--expect` 可覆盖；期望不满足则 exit 1。
- **`ERROR` 不算 CLEAN**：既没有 `SUMMARY:` 又非 0 退出（MSan 运行时偶发启动即 SIGSEGV）会重试，
  重试仍失败记 `ERROR` 并使 verdict 为 FAIL——否则一个"没跑起来"的漏洞会看起来像"修好了"。
- MSan 用 `setarch x86_64 -R`，每套 sanitizer 有各自的 `ASAN_OPTIONS` / `UBSAN_OPTIONS` /
  `MSAN_OPTIONS`（与 OSS-Fuzz 的运行器一致）。

实测（镜像内，`--no-build`）：`verify-before` **18 s**（冷启动）/ **14 s**（载入 tar 后重跑），
均 `crash=68 clean=0`；`verify-after` **3 s** / **4 s**，均 `crash=0 clean=68`。

---

## 5. 漏洞分布

68 条案例的构成如下。数字由 `payload/cases.tsv`、`payload/vulnerabilities.json` 和
`payload/pocs/*/poc` 现算，每张表都带合计，可自行加总对照 68。

### 按格式（coder）

`format` 与 `coder` 一一对应，共 33 个取值：

| 格式 | 条数 | 格式 | 条数 | 格式 | 条数 |
| --- | --- | --- | --- | --- | --- |
| `MIFF` | 9 | `MVG` | 7 | `WPG` | 5 |
| `PALM` | 3 | `PDB` | 3 | `VIFF` | 3 |
| `DCM` | 2 | `EPS` | 2 | `EPSI` | 2 |
| `GIF` | 2 | `HDR` | 2 | `PCX` | 2 |
| `PICT` | 2 | `PSD` | 2 | `SUN` | 2 |
| `TIM` | 2 | `TXT` | 2 | `CIN` | 1 |
| `DPX` | 1 | `DXT5` | 1 | `G3` | 1 |
| `MAC` | 1 | `MAT` | 1 | `PCDS` | 1 |
| `PES` | 1 | `PNM` | 1 | `PS` | 1 |
| `RLE` | 1 | `SCR` | 1 | `SIX` | 1 |
| `SIXEL` | 1 | `WBMP` | 1 | `XCF` | 1 |
| **合计** | **68** | | | | |

`MIFF`(9)、`MVG`(7)、`WPG`(5) 和 `PALM`/`PDB`/`VIFF`(各 3) 六项就占 30 条；33 个格式里
16 个只出现 1 次，前三个格式合计 21 条（31%）。

### 按 sanitizer

| `cases.tsv` 的 `sanitizer` | `vulnerabilities.json` 的 `sanitizer` | 条数 |
| --- | --- | --- |
| `address` | `asan` | 20 |
| `memory` | `msan` | 47 |
| `undefined` | `ubsan` | 1 |
| **合计** | | **68** |

MSan 47 条（69%）、ASan 20 条（29%）、UBSan 只有 1 条（`42518038`）。这是**案例数**，
不是二进制数：6 个复现器每个 coder 走运行时参数，一个 coder 可以带多条案例。

### 按崩溃类型

| 家族 | `type.crash_type` 取值 | 条数 | CWE（`type.cwe`） |
| --- | --- | --- | --- |
| Use-of-uninitialized-value | `Use-of-uninitialized-value` | 47 | `CWE-457` |
| Heap-buffer-overflow WRITE | `WRITE 8`×3、`WRITE {*}`×3、`WRITE 4`×2 | 8 | `CWE-787` |
| Heap-buffer-overflow READ | `READ 1`×5、`READ 4`×1 | 6 | `CWE-125` |
| Stack-buffer-overflow | `READ 1`、`READ {*}`、`WRITE 1`、`WRITE 8` 各 1 | 4 | `CWE-121`×2、`CWE-125`×2 |
| UNKNOWN | `UNKNOWN WRITE` | 1 | `CWE-787` |
| SEGV | 无（`UNKNOWN WRITE` 在重放时表现为 `SEGV caused by a WRITE`） | 0 | — |
| 其他 | `Index-out-of-bounds`、`Negative-size-param` 各 1 | 2 | `CWE-129`、`CWE-787` |
| **合计** | | **68** | |

47 条（69%）是未初始化读（只对应 `CWE-457`）；其余 21 条是 ASan/UBSan 的越界与非法参数：
堆写 8、堆读 6、栈 4、`UNKNOWN WRITE` 1、`Index-out-of-bounds` 1、`Negative-size-param` 1。

### 按修复点所在目录

| 目录（`code_snippet.file`） | 条数 | 说明 |
| --- | --- | --- |
| `coders/` | 44 | 各格式解码器 |
| `MagickCore/` | 19 | 共享核心（像素存取、属性/配置文件、quantum 导入等） |
| `Magick++/fuzz/` | 5 | fuzz harness 本身（`utils.cc` 的资源上限） |
| 其他 | 0 | — |
| **合计** | **68** | |

44 条（65%）的修复点在 `coders/`，19 条（28%）在 `MagickCore/`，5 条在 harness 里。
另有 42 条的 `code_snippet.file` 与 `location.file`（ARVO 记录的 `#0` 所在文件）不是同一个文件，
所以"修复点在哪"和"崩溃点在哪"两张分布表不会一样。

### 共享修复提交（68 条案例 → 62 个补丁）

| `fix_commit` | 覆盖案例 | 条数 |
| --- | --- | --- |
| `e8be814f` | `42518038` G3、`42518649` PALM、`42518894` WPG、`42519338` WPG、`42519771` TIM | 5 |
| `60cb93d0` | `42523502`、`42533154`（均 VIFF） | 2 |
| `78eaf41a` | `42525647`、`42525669`（均 MIFF） | 2 |
| 其余 59 个提交 | 每条案例一个提交 | 59 |
| **合计** | **68 条案例 → 62 个唯一提交** | **68** |

补丁的粒度是**上游提交**，不是案例：3 个提交各修多条，其余 59 个各修 1 条（5+2+2+59=68）。
所以 `payload/patches/` 里是 62 个文件（45 个上游原样 + `resolved/` 17 个适配版），
`cases.tsv` 的 `patch` 列把每条案例指到它的那一个文件。**打一个补丁，只有它的案例变成 CLEAN**：
`e8be814f` 5 条、`60cb93d0` / `78eaf41a` 各 2 条、其余各 1 条——这条性质由 `verify-one.sh`
对全部 68 条 PoC 实测（第 7 节）。

`e8be814f` 那 5 条的修复写在 `Magick++/fuzz/utils.cc` 里（`ResourceLimits::width(2048)`），
**不是产品代码缺陷**，做漏洞研究时应剔除或降权。

### PoC 体积

| 指标 | 字节 | 案例 |
| --- | --- | --- |
| 最小 | 1 B | `42522269`（WBMP）、`42532777`（SCR），均 MSan 条 |
| 中位数 | 95 B | 排序后第 34/35 位为 81 B、95 B |
| 最大 | 655,416 B | `42519182`（SUN，ASan） |
| **68 个文件合计** | **697,128 B（680.8 KiB）** | 与 `MANIFEST.md` 一致 |

58 条不超过 1 KiB、28 条不超过 64 B，超过 1 KiB 的只有 10 条；最大的 `42519182` 一条就占总体积的 94%，
次大的两条是 `42519760`（PES，9,060 B）与 `42533954`（PCDS，6,144 B）。

---

## 6. "clean" 到底意味着什么（27 / 5 / 36）

`imdt verify-after` 得到 `crash=0 clean=68`。因为 `fixed` 与 `vuln` 只差这 62 个补丁，
68 条"没崩"全部可归因，只是归因的**方式**分三类：

| 分类 | 条数 | 含义 |
| --- | --- | --- |
| decoded / 未崩 | 27 | PoC 被完整解出（23 条 write 也成功，4 条 write 报 `no encode delegate`），没有 sanitizer 报告 |
| `width or height exceeds limit` | 5 | 被 `Magick++/fuzz/utils.cc` 的 `ResourceLimits::width(2048)`/`height(2048)`（补丁 `e8be814f`）拦下 |
| 更早的解析校验拒绝 | 36 | 补丁把校验提前了，输入在到达脆弱代码之前就被拒（`improper image header` 8、`unexpected end-of-file` 10、`No image was loaded.` 5、`non-conforming drawing primitive definition` 3、`unrecognized color` 3、其余 7 种各 1） |
| **合计** | **68** | |

逐条明细（localId / coder / sanitizer / 分类 / 异常文本）在 `reports/after/cleanliness.md`。
`fixed` 侧报告的 `SUMMARY` 列全是 `—`，因为驱动和 fuzz 靶子一样吞掉异常、只留 `SUMMARY:` 作为崩溃信号。

再往下压一层：那 5 条之所以"干净"，靠的是 `-DHARNESS_FIXED_LIMITS`（`build-san.sh` 依据树里
`Magick++/fuzz/utils.cc` 自动加，`verify-one.sh` 构建中间态树时同理）。去掉这个宏重跑 68 条
（plain 构建）：29 条解码成功、39 条抛异常，差异只落在这 5 条上（`42518038` G3、`42519771` TIM
变成解码成功；`42518649` PALM、`42518894`/`42519338` WPG 变成解析拒绝）。详见
`reports/after/cleanliness.md` 第 4 节。

---

## 7. 单个案例怎么验：`verify-one.sh`

`verify-one.sh` 把"这条案例是被哪个补丁修好的"直接跑给你看：

```bash
imdt verify-one 42518438                      # 报告写到 reports/one/verify-one-9998cd71.md
imdt verify-one --patch 78eaf41a --report /tmp/one
imdt verify-one 42518038 --keep               # 保留 /work/one-e8be814f 与 /out/repro-one-*
```

它做的事：

1. `cp -a /src/imagemagick-vuln/. /work/one-<sha8>/` —— 拿一份基线副本（不动 `/src`）；
2. 打**恰好一个**补丁：`git apply`（先 `--check`），失败则 `patch -p1 --forward`；
3. `build-san.sh /work/one-<sha8> all` —— 用数据集在修前/修后用的同一个插桩脚本构三套；
4. `verify.sh /work/one-<sha8> --expect any` —— 跑**全部 68 条**；
5. 断言"变 CLEAN 的集合 == 这个补丁在 `cases.tsv` 里覆盖的集合"（1 条，或 `60cb93d0` /
   `78eaf41a` 的 2 条，或 `e8be814f` 的 5 条），否则 exit 1；
6. 写 `reports/one/verify-one-<sha>.md`，除非 `--keep` 否则清掉 `/work/one-*` 与 `/out/repro-one-*`。

随包的实测样例见 `reports/one/`。

### 只修一个 bug 的中间态（契约第 4 条第 3 句）

不借助 `verify-one.sh`，手工造一个"工具改过的树"也一样：

```bash
cp -a /src/imagemagick-vuln /work/partial
cd /work/partial && patch -p1 < /payload/patches/9998cd719775e90f9989fd1ecaa84647a56c1b57.patch
build-san.sh /work/partial all        # 同一脚本，参数是目录
verify.sh /work/partial               # 默认 --expect any：只报告
```

实测：`crash=67 clean=1`，唯一 CLEAN 是 `42518438 CIN address`——其余 67 条照崩。

---

## 8. 判定标准与报告

`cases.tsv` 是唯一的对照组（11 列）：

| 列 | 含义 |
| --- | --- |
| `localId` | ARVO 案例编号 |
| `coder` | ImageMagick coder 名（大写），运行时传给复现器 |
| `target` | ARVO 记录里的 OSS-Fuzz 靶子名（`encoder_<coder>_fuzzer`），仅供对照；本包不构建它 |
| `sanitizer` | 该条案例用哪套插桩（`address` / `undefined` / `memory`） |
| `expect_frame` | ARVO 记录里的 `#0` 函数名（报告里由 `SUMMARY:` 全文体现） |
| `expect_kind` | ARVO 的 `crash_type` 片段（`heap-buffer-overflow` 等） |
| `poc` | PoC 路径（相对 `/payload`） |
| `patch` | 修这条案例的补丁路径（相对 `/payload`，即 `patches/<fix_commit>.patch` 或 `patches/resolved/<fix_commit>.patch`） |
| `patch_status` | `upstream`（上游原样 45 个）或 `resolved`（按基线适配 17 个） |
| `after_expect` | 恒为 `no-crash`：每条案例在 `fixed` 树上都应无崩溃 |
| `fix_commit` | 修这条案例的上游提交 |

`verify.sh` 读第 1–7 列（跑哪些案例、怎么跑），`verify-one.sh` 读全部 11 列（决定打哪个补丁）。

报告两份，都在 `--report` 指定的目录里：

- `verify-<tree>.md`：元信息（树目录、sanitizer、案例数、时间戳）+ 每行一条案例
  （localId、coder、sanitizer、result、SUMMARY 全文）+ `crash=N clean=M` + verdict；
- `verify-<tree>.json`：同样内容的机器可读版（`totals` / `expect` / `verdict` / `results[]`）。

重新生成并取回：

```bash
docker exec -it imarvo imdt verify-before --no-build --report /tmp/rep/before
docker exec -it imarvo imdt verify-after  --no-build --report /tmp/rep/after
docker cp imarvo:/tmp/rep/before deliver/reports/before
docker cp imarvo:/tmp/rep/after  deliver/reports/after
```

`reports/after/cleanliness.md` 是第三份、人读的报告：它不用 `SUMMARY:` 判定，而是逐条记录
fixed 树上的读/写结果与被吞掉的异常文本，把 68 条"clean"拆成 27/5/36，并给出不带
`-DHARNESS_FIXED_LIMITS` 时的对照（29 解码 / 39 抛异常）。
`reports/one/` 是第四份：`verify-one` 的单补丁归因实测。

---

## 9. 已知限制

1. **本交付集为 68 条**；上游数据里另有 1 条（`42519948`）因修复依赖 7.0.7-23 才引入的
   `Magick::ResourceLimits::listLength`、且修复落在 fuzz harness 里，未纳入本交付集。
2. **两棵树是合成的**：它们不是上游仓库里的两个提交，而是本包用补丁叠出来的
   （vuln = `13ffeab` + 前置补丁，fixed = vuln + 62 个补丁），好处是"只差 62 个补丁"。
   代价是镜像里**不再有 git 历史**：`git show <fix_commit>` 不可用，上游提交的作者/日期/
   消息只在 `payload/vulnerabilities.json` 的 `patch` 字段里；要看"上游原样"的改动请读
   `payload/patches/<fix_commit>.patch`。
3. **5 条"clean"依赖 harness 级上限**：`e8be814f` 给 `Magick++/fuzz/utils.cc` 加了
   `width/height(2048)`，`42518038`（G3）、`42518649`（PALM）、`42518894`、`42519338`（WPG）、
   `42519771`（TIM）的 `fix_commit` 都是它。复现器在 fixed 树上带 `-DHARNESS_FIXED_LIMITS`
   才能复刻这个上限；不带时这 5 条退回 vuln 行为。做漏洞研究时应把这 5 条单列。
4. **补丁有两种状态**：45 个 `upstream`（上游原样）、17 个 `resolved`（上下文按 `13ffeab`
   适配过）。`resolved` 的补丁语义上等价于上游提交，但行号/上下文可能与上游 diff 不完全一致；
   以 `cases.tsv` 的 `patch` 列指向的文件为准——那才是被 `verify-one` 实测过的那个补丁。
5. **判据是"崩溃是否出现"**，不是行为断言。能证明"这个输入在这棵树上触发这个漏洞"，
   不能证明"漏洞只在这一处"；`clean` 的三种成因见第 6 节。
6. **MSan 容器必须 `--security-opt seccomp=unconfined`**，且脚本内部已对 MSan 加
   `setarch x86_64 -R`（老 clang 6 的 MSan 在新内核 + ASLR 下会假崩）。本机的 MSan 运行时还有
   ~15% 概率在启动时直接 SIGSEGV 且无输出，`run_poc` 因此最多重试 10 次，且把"没崩但非 0 退出"
   记为 `ERROR`（判 FAIL），绝不当成 CLEAN。
7. **CWE 是按崩溃类型推导的**，OSS-Fuzz issue 本身没有 CVE/CWE 字段。
8. **`build.sh` 会在源码树里留下构建产物**（`Makefile`、`.o`、`utilities/magick`）。这是"直接
   驱动项目自己的构建"的代价；`build-san.sh` 复制树时会 `make distclean` 并删掉残留目标文件，
   所以插桩构建不受影响。想回到干净状态就重新拉镜像。
9. **没有 fuzz 运行时**：交付集不编 `encoder_<coder>_fuzzer`，也不编/不链 libFuzzer；
   基镜像自带的 `/src/afl`、`/src/honggfuzz`、`/src/libfuzzer`、`/src/afl_testcases.tgz`、
   `/src/build.sh` 在构镜像时一并 `rm -rf`，`/work` 也清空（`/work/engine-*` 不再存在）。
   报告里的 `SUMMARY:` 来自手写驱动的调用路径，而不是 fuzz 靶子的；两者的等价性靠第 10 节
   的契约复刻保证。
10. **手写复现器只复刻契约，不是产品代码入口**：`hand_repro.cc` 照抄 harness 的
    `magick(coder)` + `fileName("<coder>:")` + `read`/`write` + 吞掉 `Magick::Exception`，
    以及 `utils.cc` 的字面限制。

---

## 10. 交付件是否完整

| 你要的东西 | 在哪 |
| --- | --- |
| 漏洞列表 | `payload/vulnerabilities.json`（+ csv/md），68 条 |
| 62 个修复补丁 | `payload/patches/`（45 upstream + `resolved/` 17），逐条 `patch.file` 指路 |
| 两棵可构建的源码树 | 镜像内 `/src/imagemagick-vuln`、`/src/imagemagick-fixed`（各带 `.source-id`，无 `.git`） |
| plain 构建（两棵树一起） | `scripts/build.sh` / `imdt build` |
| 插桩构建（修前/修后同一个脚本） | `scripts/build-san.sh` / `imdt build-san` → `/out/repro-<tree>-<san>` |
| 一个验证脚本（修前/修后/中间态） | `scripts/verify.sh` / `imdt verify-before\|verify-after\|verify-all` |
| 修复前验证 | `imdt verify-before` → `crash=68 clean=0` → `reports/before/` |
| 修复后验证 | `imdt verify-after` → `crash=0 clean=68` → `reports/after/` |
| 只修一个 bug 时只翻一条 | `imdt verify-one <localId>`；或 `build-san.sh <dir>` + `verify.sh <dir>` |
| "clean" 的成因 | `reports/after/cleanliness.md`（27 解码 / 5 harness 上限 / 36 提前拒绝） |
| 单条案例的修复 diff | `payload/patches/<fix_commit>.patch` |

---

## 11. 复现器为什么等价（harness 契约，而不是靶子）

交付集只有一个复现入口：`scripts/hand_repro.cc` → `/out/repro-<tree>-<san>`。
它不是 fuzz 靶子的重新包装，而是把靶子的契约**手抄**了一遍；等价性来自逐条对齐
`Magick++/fuzz/encoder_fuzzer.cc` + `Magick++/fuzz/utils.cc` 做的事：

| harness 做的事 | `hand_repro.cc` 的做法 |
| --- | --- |
| 编译期 `-DFUZZ_IMAGEMAGICK_ENCODER=<CODER>` 固定格式 | 运行期 `argv[1]`，`image.magick(coder)` |
| `image.fileName("<coder>:")`（带冒号，按 coder 选读入器） | 同左，冒号照抄 |
| `image.read(Magick::Blob(data, size))` | 同左：PoC 字节原样进 `Blob` |
| `image.write(&blob, coder)` 回写（编码路径也覆盖） | 同左 |
| `catch (Magick::Exception)` 后正常返回，解析失败不算崩溃 | 同左（read/write 各自吞掉） |
| `utils.cc`：`SecurityPolicy::maxMemoryRequest(256e6)`、`ResourceLimits::memory(1e9)` | 同左，字面数值一致 |
| `utils.cc`（fixed 树，`e8be814f`）：`ResourceLimits::width(2048)` / `height(2048)` | `-DHARNESS_FIXED_LIMITS` 分支，同样两行 |

差异只有一处：coder 从命令行来，而不是编译期常量，所以一个二进制能跑完整个 profile
（68 条 → 6 个二进制，而不是 80 个靶子）。sanitizer 输出、调用链、资源上限、异常语义
都与靶子一致——`/out` 里没有 libFuzzer，也就不用为"运行时本身要不要插桩"操心。

vuln 与 fixed 的资源上限并不相同：fixed 上落了 `e8be814f`，多了 `width/height(2048)`。
靶子从检出树里白拿这个差异，手写驱动得自己追——这就是 `build-san.sh` 用树自己的
`Magick++/fuzz/utils.cc` 判断 `-DHARNESS_FIXED_LIMITS` 的由来；少了它，5 条（`42518038` G3、
`42518649` PALM、`42518894` WPG、`42519338` WPG、`42519771` TIM）的分类会变（2 条解码成功、
3 条被解析拒绝，都不崩），因为这几条修的是 harness，不是产品缺陷。
