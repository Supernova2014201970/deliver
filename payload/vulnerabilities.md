# ImageMagick ARVO 漏洞清单

漏洞节点 `vuln` = `cac8ee0ead08`（基线 `7.0.7-21-82-g13ffeab`，2018-01-16 + `ResetImagePixels` 前提）；修复节点 `fixed` = `7940a980a488`（在 vuln 上应用 62 个修复补丁）。两个节点都是**合成提交**，`fixed` 与 `vuln` 只差这 62 个补丁。
62 个补丁全部随包发布：`payload/patches/<fix_commit>.patch`（45 个上游原样）与`payload/patches/resolved/<fix_commit>.patch`（17 个手工适配）；镜像内的并集是 `image/refs/combined.patch`。机器可读版本：`payload/vulnerabilities.json`、`payload/vulnerabilities.csv`。

逐条归因用 `scripts/verify-one.sh <localId>`：切到 `vuln`、只应用该条案例的补丁、只编该条案例的 sanitizer、跑该 PoC，期望无崩溃。68 条在 `fixed` 上都不再崩溃：27 条解码成功、5 条被 harness 的 `width/height(2048)` 上限拦下（该上限即补丁 `e8be814f`）、36 条被补丁新增的解析校验提前拒绝（见 `reports/after/cleanliness.md`）。

| localId | 格式 | 类型 | CWE | 漏洞位置 | 漏洞描述 | 修复 | 上游提交 | 补丁 | 补丁状态 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 42519749 | SIX | UNKNOWN WRITE | CWE-787 | coders/sixel.c:462 in `sixel_decode` | `coders/sixel.c:462`（`sixel_decode`）：SIX 的 DECGRI 重复指令不管 Pn 取值都把 param[0] 写进 repeat_count，Pn 为 0 时 `imsx < posision_x+repeat_count` 的扩容判断少算一列，随后写 `imbuf[imsx*(posision_y+i)+posision_x]` 越过缓冲区末尾（ASan UNKNOWN WRITE）；修复只在 `param[0] > 1` 时才更新 repeat_count。 | sixel_decode：增加边界或长度校验（+1/-1 行） | `8e5432bdc67c` | `patches/8e5432bdc67c377c620f5d8d3dedfb62854f567c.patch` | upstream |
| 42519182 | SUN | Heap-buffer-overflow WRITE 8 | CWE-787 | MagickCore/quantize.c:3411 in `SetGrayscaleImage` | `MagickCore/quantize.c:3411`（`SetGrayscaleImage`）：colormap_index 一律按 MaxColormapSize(65536) 分配，而伪彩图的 image->colors 可以更大，`colormap_index[(ssize_t) image->colormap[i].alpha]=j` 按下标写入时越过 65536 项数组（heap-buffer-overflow WRITE 8）；修复对 PseudoClass 按 image->colors 分配，其余仍用 MaxColormapSize。 | SetGrayscaleImage：增加边界或长度校验（+6/-2 行） | `bb4e7e891957` | `patches/bb4e7e8919573caf70bd5af3330e991ddbad0c92.patch` | upstream |
| 42519504 | EPSI | Heap-buffer-overflow READ 1 | CWE-125 | MagickCore/xml-tree.c:1525 in `ParseEntities` | `MagickCore/xml-tree.c:1525`（`ParseEntities`）：展开实体时按 extent 字节分配缓冲并复制，算出的长度没有给结尾 NUL 留空间，后续仍按 C 字符串读取就跨过缓冲区（heap-buffer-overflow READ 1）；修复改为按 extent+1 分配并显式写 `p[extent]='\0'`，同时把 extent_xml 的赋值移出“分配成功”分支，避免分配失败时沿用旧指针。 | ParseEntities：增加边界或长度校验（+7/-7 行） | `1f55115e43f7` | `patches/1f55115e43f7276a6d91bd4408dd4a6ef45d6be5.patch` | upstream |
| 42519760 | PES | Stack-buffer-overflow WRITE 8 | CWE-121 | coders/pes.c:624 in `ReadPESImage` | `coders/pes.c:624`（`ReadPESImage`）：拼接块计数先 `j++` 再写 `blocks[j]`，而 blocks 只有 256 项，原来的上限判断 `j >= 256` 在 j 已等于 256 时来不及拦住，`blocks[256]` 写到栈数组之外（stack-buffer-overflow WRITE 8）；修复把上限收到 255 并改用 CorruptImage 报错。 | ReadPESImage：增加边界或长度校验（+2/-2 行） | `3c8e8dbc5f8f` | `patches/3c8e8dbc5f8f617fa902cffaa90368beb96fd8a4.patch` | upstream |
| 42520493 | DXT5 | Heap-buffer-overflow WRITE 4 | CWE-787 | ./MagickCore/pixel-accessor.h:844 in `SetPixelRed` | `coders/dds.c:2113`（`ReadDXT3Pixels`）：DXT3 解块的边界判断把行与列写反（x 比 image->rows、y 比 image->columns），宽高不相等时会写到像素缓存之外（heap-buffer-overflow WRITE 4，崩溃点内联在 pixel-accessor.h 的 SetPixelRed）；修复改为 x 对 image->columns、y 对 image->rows。 | ReadDXT3Pixels：增加边界或长度校验（+1/-1 行） | `147814adf1c6` | `patches/147814adf1c657f647ee7e73027dbedde5ac2467.patch` | upstream |
| 42518038 | G3 | Index-out-of-bounds | CWE-129 | MagickCore/compress.c:835 in `HuffmanEncodeImage` | `MagickCore/compress.c:835`（`HuffmanEncodeImage`）：G3 编码路径上由未受限的图像尺寸导致数组索引越界；上游没有改库代码，只在 `Magick++/fuzz/utils.cc` 的 FuzzingLimits 里把 image width/height 限制为 2048 像素，超限输入在读取阶段即失败，不再进入编码器。 | Magick++/fuzz/utils.cc：在 fuzz harness 设置资源上限（+2/-0 行） | `e8be814f1c3d` | `patches/resolved/e8be814f1c3d267012d2f612b3366bfb5029414d.patch` | resolved |
| 42518649 | PALM | Use-of-uninitialized-value | CWE-457 | MagickCore/pixel.c:6132 in `IsFuzzyEquivalencePixelInfo` | `MagickCore/pixel.c:6132`（`IsFuzzyEquivalencePixelInfo`）：PALM 输入走到该比较函数时读到了未初始化的像素值；上游没有改库代码，只在 `Magick++/fuzz/utils.cc` 的 FuzzingLimits 里把 image width/height 限制为 2048 像素，超限输入在读取阶段即失败。 | Magick++/fuzz/utils.cc：在 fuzz harness 设置资源上限（+2/-0 行） | `e8be814f1c3d` | `patches/resolved/e8be814f1c3d267012d2f612b3366bfb5029414d.patch` | resolved |
| 42518894 | WPG | Use-of-uninitialized-value | CWE-457 | MagickCore/cache.c:3368 in `WritePixelCacheRegion` | `MagickCore/cache.c:3368`（`WritePixelCacheRegion`）：WPG 编码时把未初始化的像素区域写出；上游没有改库代码，只在 `Magick++/fuzz/utils.cc` 的 FuzzingLimits 里把 image width/height 限制为 2048 像素，超限输入在读取阶段即失败。 | Magick++/fuzz/utils.cc：在 fuzz harness 设置资源上限（+2/-0 行） | `e8be814f1c3d` | `patches/resolved/e8be814f1c3d267012d2f612b3366bfb5029414d.patch` | resolved |
| 42519338 | WPG | Use-of-uninitialized-value | CWE-457 | ./MagickCore/colormap-private.h:32 in `ConstrainColormapIndex` | `./MagickCore/colormap-private.h:32`（`ConstrainColormapIndex`）：WPG 解码用未初始化的调色板索引走到该内联函数；上游没有改库代码，只在 `Magick++/fuzz/utils.cc` 的 FuzzingLimits 里把 image width/height 限制为 2048 像素，超限输入在读取阶段即失败。 | Magick++/fuzz/utils.cc：在 fuzz harness 设置资源上限（+2/-0 行） | `e8be814f1c3d` | `patches/resolved/e8be814f1c3d267012d2f612b3366bfb5029414d.patch` | resolved |
| 42519771 | TIM | Use-of-uninitialized-value | CWE-457 | MagickCore/image.c:3700 in `PushColormapIndex` | `MagickCore/image.c:3700`（`PushColormapIndex`）：TIM 解码把未初始化的索引交给了像素写入；上游没有改库代码，只在 `Magick++/fuzz/utils.cc` 的 FuzzingLimits 里把 image width/height 限制为 2048 像素，超限输入在读取阶段即失败。 | Magick++/fuzz/utils.cc：在 fuzz harness 设置资源上限（+2/-0 行） | `e8be814f1c3d` | `patches/resolved/e8be814f1c3d267012d2f612b3366bfb5029414d.patch` | resolved |
| 42520871 | EPS | Use-of-uninitialized-value | CWE-457 | MagickCore/xml-tree.c:1506 in `ParseEntities` | `MagickCore/xml-tree.c:1506`（`ParseEntities`）：extent_xml 分配后直接 CopyMagickString 复制，未清零的尾部字节在实体展开后被当作字符串读取（MSan 未初始化值）；修复在复制前 `ResetMagickMemory(extent_xml,0,extent*sizeof(*extent_xml))`。 | ParseEntities：补齐缓冲区初始化/清零（+2/-0 行） | `82c58c138e2f` | `patches/resolved/82c58c138e2ffc1f170db711b07627ee621c2a22.patch` | resolved |
| 42519416 | SIXEL | Heap-buffer-overflow WRITE {*} | CWE-787 | MagickCore/memory.c:1156 in `ResetMagickMemory` | `coders/sixel.c:489`（`sixel_decode`）：DECGRI 重复绘制时对每行执行 `ResetMagickMemory(imbuf + imsx*y + posision_x, color_index, repeat_count)`，写入起点与长度都没有和 imsx*imsy 的容量核对，越界写破坏了堆（ASan 在 ResetMagickMemory:1156 报 UNKNOWN WRITE）；修复先算出 offset，`offset+repeat_count` 超容量时释放 imbuf 并返回 MagickFalse。 | sixel_decode：增加边界或长度校验（+15/-2 行） | `614d7b140cd0` | `patches/614d7b140cd03a0d38f76ae55a7fcb2c9d76012a.patch` | upstream |
| 42520948 | DCM | Use-of-uninitialized-value | CWE-457 | ./MagickCore/pixel-accessor.h:522 in `IsPixelGray` | `coders/dcm.c:3927`（`ReadDCMImage`）：设定 RGB 色彩空间后直接按 colormap 写像素，未被解码覆盖的像素保持未初始化值（MSan 在 IsPixelGray 处报错）；修复在解析像素前调用 SetImageBackgroundColor 预填背景。 | ReadDCMImage：补齐缓冲区初始化/清零（+1/-0 行） | `4435dbb1f398` | `patches/4435dbb1f398e3bf4ab1c1f8905d42b7701a7cca.patch` | upstream |
| 42520971 | PDB | Use-of-uninitialized-value | CWE-457 | coders/pdb.c:349 in `ReadPDBImage` | `coders/pdb.c:349`（`ReadPDBImage`）：局部 pdb_info 未清零就按字段从文件读取，文件长度不足时残留字段保持未初始化值并被后续使用（MSan 未初始化值）；修复在读之前 `ResetMagickMemory(&pdb_info,0,sizeof(pdb_info))`。 | ReadPDBImage：补齐缓冲区初始化/清零（+1/-0 行） | `487f950075ae` | `patches/487f950075ae21b4634a04cb28c2f47f95d62963.patch` | upstream |
| 42521159 | TXT | Use-of-uninitialized-value | CWE-457 | ./MagickCore/quantum.h:116 in `ScaleQuantumToChar` | `coders/txt.c:464`（`ReadTXTImage`）：先 SetImageBackgroundColor 再 SetImageColorspace，背景像素是按旧色彩空间填的，切换后部分通道没有有效值（MSan 在 ScaleQuantumToChar 处报错）；修复把 SetImageColorspace 提到 SetImageBackgroundColor 之前。 | ReadTXTImage：补齐缓冲区初始化/清零（+1/-1 行） | `089751036261` | `patches/resolved/0897510362611886bfe296f8ab5d9aa1f82558cf.patch` | resolved |
| 42521170 | WPG | Use-of-uninitialized-value | CWE-457 | ./MagickCore/pixel-accessor.h:783 in `SetPixelViaPixelInfo` | `coders/wpg.c:1391`（`ReadWPGImage`）：`ReadBlob(image,ldblk,BImgBuff)` 的返回值被丢弃，文件提前结束时行缓冲只填了一部分，InsertRow 把未初始化的行数据写进像素缓存（MSan 在 SetPixelViaPixelInfo 处报错）；修复检查返回值，读不满即跳出循环。 | ReadWPGImage：调整相关实现（+6/-1 行） | `02eee091d202` | `patches/02eee091d2023d91d15d271ac9e6fe049a6e4c5f.patch` | upstream |
| 42521270 | PCX | Use-of-uninitialized-value | CWE-457 | ./MagickCore/pixel-accessor.h:567 in `IsPixelMonochrome` | `coders/pcx.c:385`（`ReadPCXImage`）：读完 16 色调色板后没有初始化像素缓存，解码未覆盖的像素保持未初始化值（MSan 在 IsPixelMonochrome 处报错）；修复在解析像素前 SetImageBackgroundColor 预填背景。 | ReadPCXImage：补齐缓冲区初始化/清零（+1/-0 行） | `a5136e6c737e` | `patches/a5136e6c737e76e613da9241d7ecb273d84787d0.patch` | upstream |
| 42521591 | MVG | Stack-buffer-overflow WRITE 1 | CWE-121 | MagickCore/token.c:313 in `GetNextToken` | `MagickCore/token.c:313`（`GetNextToken`）：识别 `url(` 时只要求 `strlen(token) > 4`，token 恰为 4 字节时 `i-offset-1` 等于 -1，`token[-1]='\0'` 写到栈缓冲区之前（stack-buffer-overflow WRITE 1）；修复把判断改为 `strlen(token) > 5`。 | GetNextToken：增加边界或长度校验（+1/-1 行） | `c9a75ec387eb` | `patches/c9a75ec387eb3c1f3c9584b97260d72512868b1b.patch` | upstream |
| 42522513 | MVG | Use-of-uninitialized-value | CWE-457 | MagickCore/draw.c:3948 in `GetFillAlpha` | `MagickCore/draw.c:3948`（`GetFillAlpha`）：扫描线求交的循环上界写成 `p->number_points`，y 高于所有顶点时 i 停在 number_points，`q=p->points+i-1` 之后的 `(q+1)->x` 读到 points 数组末尾之外的未初始化项（MSan 未初始化值）；修复把上界收紧到 `number_points-1`。 | GetFillAlpha：调整相关实现（+1/-1 行） | `8bb46b3381f8` | `patches/8bb46b3381f8440fbf90bd88e1909dc83e089790.patch` | upstream |
| 42521846 | PICT | Use-of-uninitialized-value | CWE-457 | ./MagickCore/colormap-private.h:32 in `ConstrainColormapIndex` | `coders/pict.c:459`（`DecodeImage`）：scanline 行缓冲分配后未清零，PICT 行压缩数据解不满一行时残留未初始化字节被当作像素索引（MSan 在 ConstrainColormapIndex 处报错）；修复清零 2*row_bytes 字节。 | DecodeImage：补齐缓冲区初始化/清零（+1/-0 行） | `21baa90e1854` | `patches/21baa90e1854413d109512c3cda5242511e5a14a.patch` | upstream |
| 42521858 | PALM | Use-of-uninitialized-value | CWE-457 | MagickCore/pixel.c:6132 in `IsFuzzyEquivalencePixelInfo` | `coders/palm.c:314`（`ReadPALMImage`）：SetImageExtent 建立像素缓存后没有初始化，解码未覆盖的像素保持未初始化值（MSan 在 IsFuzzyEquivalencePixelInfo 处报错）；修复紧接着调用 SetImageBackgroundColor。 | ReadPALMImage：补齐缓冲区初始化/清零（+1/-0 行） | `ecd8728428d4` | `patches/ecd8728428d460b13821cc8e80aef671011329c7.patch` | upstream |
| 42522869 | PALM | Use-of-uninitialized-value | CWE-457 | ./MagickCore/quantum.h:116 in `ScaleQuantumToChar` | `coders/palm.c:406`（`ReadPALMImage`）：one_row 行缓冲按 MagickMax(bytes_per_row,2*columns) 分配但从不初始化，压缩行数据不足时未初始化字节参与像素计算（MSan 在 ScaleQuantumToChar 处报错）；修复把长度提到 extent 变量并在分配后清零该缓冲。 | ReadPALMImage：调整相关实现（+5/-3 行） | `73c6cc1f8da1` | `patches/73c6cc1f8da1d7f3647056f293c5a10da019c9b7.patch` | upstream |
| 42523358 | PNM | Use-of-uninitialized-value | CWE-457 | ./MagickCore/pixel-accessor.h:487 in `IsPixelEquivalent` | `coders/pnm.c:428`（`ReadPNMImage`）：SetImageExtent 之后没有初始化像素缓存，PNM 数据未覆盖的像素保持未初始化值（MSan 在 IsPixelEquivalent 处报错）；修复立即调用 SetImageBackgroundColor。 | ReadPNMImage：补齐缓冲区初始化/清零（+1/-0 行） | `23246df8dfde` | `patches/23246df8dfdebe0002bf9abfa0a5490238300ad9.patch` | upstream |
| 42523812 | DPX | Use-of-uninitialized-value | CWE-457 | ./MagickCore/quantum-private.h:504 in `ScaleQuantumToShort` | `coders/dpx.c:1134`（`ReadDPXImage`）：建立像素缓存后没有初始化，DPX 各元素解码未覆盖的像素保持未初始化值（MSan 在 ScaleQuantumToShort 处报错）；修复在遍历元素前调用 SetImageBackgroundColor。 | ReadDPXImage：补齐缓冲区初始化/清零（+1/-0 行） | `9e74769caca2` | `patches/9e74769caca25bc62707772ef15de9a510609bf2.patch` | upstream |
| 42523868 | MAT | Use-of-uninitialized-value | CWE-457 | ./MagickCore/pixel-accessor.h:522 in `IsPixelGray` | `coders/mat.c:697`（`ReadMATImageV4`）：SetImageExtent 之后未初始化像素，MAT v4 数据未覆盖的区域保持未初始化值（MSan 在 IsPixelGray 处报错）；修复立即调用 SetImageBackgroundColor。 | ReadMATImageV4：补齐缓冲区初始化/清零（+2/-0 行） | `79ef217ff11a` | `patches/79ef217ff11ad37e45946bb17ab1d4f3311066c7.patch` | upstream |
| 42523879 | PSD | Negative-size-param | CWE-787 | MagickCore/memory.c:726 in `CopyMagickMemory` | `coders/psd.c:3046`（`RemoveResolutionFromResourceBlock`）：删除 8BIM 分辨率块时按 `length-(cnt+12)-(q-datum)` 计算 memcpy 长度，cnt 与剩余长度不一致时结果为负，转成 size_t 变成极大值（负长度 memcpy 造成的越界写）；修复要求该余量必须大于 0 才执行拷贝。 | RemoveResolutionFromResourceBlock：增加边界或长度校验（+2/-1 行） | `6f7924965f38` | `patches/6f7924965f38eeaa43901d6c7b3d7a9157ccd1e1.patch` | upstream |
| 42518560 | TXT | Use-of-uninitialized-value | CWE-457 | MagickCore/cache.c:3954 in `QueueAuthenticPixelCacheNexus` | `coders/txt.c:437`（`ReadTXTImage`）：x_offset/y_offset 在解析出第一个坐标之前未初始化，行内坐标不全时直接参与像素定位（MSan 在 QueueAuthenticPixelCacheNexus 处报错）；修复在解析循环前把两者置为 -1。 | ReadTXTImage：调整相关实现（+2/-0 行） | `169a3ff38425` | `patches/169a3ff38425613b156015c23056c4adf0dbf221.patch` | upstream |
| 42519915 | MIFF | Use-of-uninitialized-value | CWE-457 | MagickCore/locale.c:1518 in `LocaleNCompare` | `coders/miff.c:194`（`PushRunlengthPacket`）：伪彩图 32/16/8 位索引由 `(*p << 8) | *(p+1)` 一类表达式拼出后隐式转换成 ssize_t 传给 ConstrainColormapIndex，符号/类型不匹配使越界索引没有被拦住（MSan 在 LocaleNCompare 处报未初始化值）；修复显式转成 ssize_t 并用 MagickRealType 赋值 pixel->index。 | PushRunlengthPacket：调整相关实现（+71/-46 行） | `008465f1b8eb` | `patches/008465f1b8eb05752f8482e9cc2a073f0e978f09.patch` | upstream |
| 42524289 | MVG | Heap-buffer-overflow WRITE 8 | CWE-787 | MagickCore/draw.c:1666 in `TracePoint` | MVG 的 ARC 图元按包围盒对角线估算点数组容量（2π×对角线 ≈ 21.7 万），而实际点数由角度跨度×半径决定：起始角 -33130° 未归一化、跨 92 圈，TraceEllipse 要写 32.2 万个点，写越界 8 字节。 | DrawImage 把容量系数由 2π 改为 π²，容量 22.3 万→34.6 万，覆盖该 PoC 的 32.2 万点。 | `2ebcbdbaee0a` | `patches/2ebcbdbaee0a9bdfa0f11f9b47774668537ea709.patch` | upstream |
| 42524701 | XCF | Use-of-uninitialized-value | CWE-457 | ./MagickCore/pixel-accessor.h:37 in `ClampPixel` | `coders/xcf.c:669`（`load_level`）：每个 tile 图像建立后没有初始化像素，XCF 压缩数据未覆盖的像素保持未初始化值（MSan 在 ClampPixel 处报错）；修复在读取 tile 数据前对 tile_image 调用 SetImageBackgroundColor。 | load_level：补齐缓冲区初始化/清零（+1/-0 行） | `4fc95b7c4291` | `patches/4fc95b7c4291ec9216929c525cc3e6ed55b39149.patch` | upstream |
| 42518471 | MIFF | Use-of-uninitialized-value | CWE-457 | MagickCore/property.c:1750 in `GetXMPProperty` | `MagickCore/property.c:1742`（`GetXMPProperty`）：取得 xmp profile 后不看长度就直接按固定偏移访问，profile 短于 17 字节时越界读取（heap-buffer-overflow READ 1）；修复在开始解析前增加 `GetStringInfoLength(profile) < 17` 的检查。 | GetXMPProperty：调整相关实现（+2/-0 行） | `af223b025da2` | `patches/af223b025da2ffb56a4e50160448e845f9b5e186.patch` | upstream |
| 42520316 | EPS | Heap-buffer-overflow READ 1 | CWE-125 | MagickCore/xml-tree.c:1722 in `ParseInternalDoctype` | `MagickCore/property.c:1747`（`GetXMPProperty`）：拿到 xmp profile 后不确认内容是否真是 XMP（`<rdf:RDF`/`<rdf:Description`/`<x:`）就按 XMP 结构扫描，内容不符时后续 XML 解析越界读（heap-buffer-overflow READ 1，崩溃点落在 ParseInternalDoctype）；修复先用三次 strstr 判定，不符则释放并返回 MagickFalse。 | GetXMPProperty：增加边界或长度校验（+9/-1 行） | `3b30dbea8817` | `patches/3b30dbea8817d45471ec132014a3bc44e05fdf97.patch` | upstream |
| 42525647 | MIFF | Use-of-uninitialized-value | CWE-457 | MagickCore/property.c:1336 in `GetEXIFProperty` | `coders/miff.c:901`（`ReadMIFFImage`）：读取 profile 数据后不判断 EOFBlob 就 SetImageProfile，文件在 profile 中途结束时未填满的缓冲区被存成图像属性，后续属性解析读取未初始化内容（MSan 在 GetEXIFProperty 处报错）；修复只在未到文件末尾时才设置 profile。 | ReadMIFFImage：调整相关实现（+6/-2 行） | `78eaf41a792b` | `patches/resolved/78eaf41a792bb35a8b9e7ac4f72d86a8cb7d6d0a.patch` | resolved |
| 42525669 | MIFF | Use-of-uninitialized-value | CWE-457 | MagickCore/locale.c:1518 in `LocaleNCompare` | `coders/miff.c:901`（`ReadMIFFImage`）：profile 读到 EOF 后仍被 SetImageProfile 保存，长度与实际数据不符，属性扫描时读到未初始化字节（MSan 在 LocaleNCompare 处报错）；修复加 EOFBlob 判断，只在未到末尾时设置 profile。 | ReadMIFFImage：调整相关实现（+6/-2 行） | `78eaf41a792b` | `patches/resolved/78eaf41a792bb35a8b9e7ac4f72d86a8cb7d6d0a.patch` | resolved |
| 42525880 | HDR | Stack-buffer-overflow READ {*} | CWE-125 | MagickCore/blob.c:5436 in `WriteBlob` | `coders/hdr.c:711`（`WriteHDRImage`）：把图像属性用 `#%s\n` 格式化进固定长度的 header，属性过长时 FormatLocaleString 截断但返回完整长度，WriteBlob 按返回值读取 header 之外的内存（stack-buffer-overflow READ）；修复改用 `%.*s` 并把长度限制在 MagickPathExtent-3。 | WriteHDRImage：增加边界或长度校验（+2/-1 行） | `07e656c7089f` | `patches/07e656c7089f3b3ae30a71a042fb903c83e077b6.patch` | upstream |
| 42521880 | VIFF | Use-of-uninitialized-value | CWE-457 | ./MagickCore/quantum.h:116 in `ScaleQuantumToChar` | `coders/viff.c:329`（`ReadVIFFImage`）：调色板解析之前没有建立并初始化像素缓存，图像数据未覆盖的像素保持未初始化值，编码时被换算成字节写出（MSan 在 ScaleQuantumToChar 处报错）；修复在此处补上 alpha_trait、SetImageExtent 与 SetImageBackgroundColor，并删掉原来留在解析之后的初始化块。 | ReadVIFFImage：调整相关实现（+29/-31 行） | `391d3afd588b` | `patches/resolved/391d3afd588b94f9ee2c5e4a70f5e9197e5afb21.patch` | resolved |
| 42526335 | GIF | Use-of-uninitialized-value | CWE-457 | MagickCore/profile.c:1859 in `Sync8BimProfile` | `MagickCore/profile.c:1834`（`Sync8BimProfile`）：8BIM 资源块里 `count` 与剩余长度用 `count > length` 比较，count 恰好等于 length 时仍执行 `p+=count; length-=count`，长度计数归零且指针落到块尾，后续读取越界拿到未初始化值（MSan 未初始化值）；修复改为 `count >= length` 即返回。 | Sync8BimProfile：调整相关实现（+1/-1 行） | `6d4a20030385` | `patches/6d4a20030385c8e42f7a3fa89c84556b5fc896d7.patch` | upstream |
| 42526424 | EPSI | Heap-buffer-overflow READ 1 | CWE-125 | MagickCore/xml-tree.c:1722 in `ParseInternalDoctype` | `MagickCore/xml-tree.c:1716`（`ParseInternalDoctype`）：只检查 `*xml != '\0'` 就用 strncmp 比较 8 字节的 `<!ENTITY`，剩余不足 8 字节时越过字符串末尾读取（heap-buffer-overflow READ 1）；修复增加 `strlen(xml) > 9` 的前置判断。 | ParseInternalDoctype：增加边界或长度校验（+1/-1 行） | `5f68b29b843b` | `patches/5f68b29b843b3c57f61b34e1db8f3144af458614.patch` | upstream |
| 42526757 | PS | Heap-buffer-overflow READ 1 | CWE-125 | MagickCore/xml-tree.c:2288 in `NewXMLTree` | `coders/ps.c:1009`（`ReadPSImage`）：PS 文件里的 profile 段此前没有从 blob 读入，profile 缓冲区保持未初始化内容，随后 GetXMPProperty/NewXMLTree 把这些字节当 XML 解析并越界读（heap-buffer-overflow READ 1，崩溃点在 NewXMLTree）；修复在解析前按各 profile 的长度 ReadBlob 填入数据并释放 profile 链表。 | ReadPSImage：增加边界或长度校验（+57/-7 行） | `ba9e36555434` | `patches/resolved/ba9e36555434ebe9da38a1341cfd9f304a326348.patch` | resolved |
| 42527322 | PICT | Use-of-uninitialized-value | CWE-457 | ./MagickCore/quantum.h:116 in `ScaleQuantumToChar` | `coders/pict.c:927`（`ReadPICTImage`）：SetImageExtent 之后直接按 opcode 写像素，alpha 通道既不参与解码也未被初始化（MSan 在 ScaleQuantumToChar 处报错）；修复设置 `image->alpha_trait=BlendPixelTrait` 并调用 SetImageBackgroundColor。 | ReadPICTImage：补齐缓冲区初始化/清零（+2/-0 行） | `820e6361927e` | `patches/resolved/820e6361927e3bfa346ce085311d001681863a23.patch` | resolved |
| 42527699 | GIF | Use-of-uninitialized-value | CWE-457 | MagickCore/profile.c:1844 in `Sync8BimProfile` | `MagickCore/string.c:182`（`AcquireStringInfo`）：StringInfo 的 datum 按 length+MagickPathExtent 分配但未清零，超出 length 的尾部字节在按 C 字符串使用时是未初始化的（MSan 在 Sync8BimProfile 处报错）；修复分配后 `memset(string_info->datum,0,length+MagickPathExtent)`，同一补丁也在 BlobToStringInfo 末尾补零。 | AcquireStringInfo：补齐缓冲区初始化/清零（+7/-5 行） | `7a98246a075d` | `patches/resolved/7a98246a075d55f2eb5bad40028a28f3cfdd97c1.patch` | resolved |
| 42527789 | MIFF | Stack-buffer-overflow READ 1 | CWE-125 | MagickCore/color.c:2385 in `QueryColorCompliance` | `MagickCore/color.c:2385`（`QueryColorCompliance`）：`rgb(...)` 形式的颜色名在栈缓冲 colorspace(MagickPathExtent) 里逐字符解析，名字较长时读写越过缓冲区末尾（ASan 报 stack-buffer-overflow READ 1）；修复把缓冲扩到 2*MagickPathExtent，并在复制前 memset 清零。 | QueryColorCompliance：补齐缓冲区初始化/清零（+2/-1 行） | `ff0cea4290cb` | `patches/ff0cea4290cb1421cb174f2f26ca03789377a6fb.patch` | upstream |
| 42528177 | MIFF | Use-of-uninitialized-value | CWE-457 | MagickCore/color.c:2385 in `QueryColorCompliance` | `MagickCore/color.c:2385`（`QueryColorCompliance`）：`rgb(...)` 解析用的栈缓冲只有 MagickPathExtent 字节且未初始化，尾部未写全的字节在逐字符扫描时被当作字符串读取（MSan 未初始化值）；修复扩到 2*MagickPathExtent 并在复制前 memset 清零。 | QueryColorCompliance：补齐缓冲区初始化/清零（+2/-1 行） | `557cb22f90e3` | `patches/resolved/557cb22f90e3543cca8414a1dfa074e0e026e4c3.patch` | resolved |
| 42528200 | PCX | Use-of-uninitialized-value | CWE-457 | ./MagickCore/quantum.h:116 in `ScaleQuantumToChar` | `coders/pcx.c:418`（`ReadPCXImage`）：scanline 缓冲分配后没有清零，RLE 解码未覆盖的字节保持未初始化并被当作颜色索引（MSan 在 ScaleQuantumToChar 处报错）；修复按 `MagickMax(columns,bytes_per_line)*MagickMax(8,planes)` 的长度清零 scanline。 | ReadPCXImage：补齐缓冲区初始化/清零（+2/-0 行） | `fda26c312b8d` | `patches/fda26c312b8d99e0cfaa82233741946c1206de81.patch` | upstream |
| 42528610 | SUN | Use-of-uninitialized-value | CWE-457 | ./MagickCore/quantum.h:116 in `ScaleQuantumToChar` | `coders/sun.c:478`（`ReadSUNImage`）：sun_pixels 只清空了 pixels_length 字节，而后面的按行处理还会用到其后的 image->rows 个字节，这部分保持未初始化（MSan 在 ScaleQuantumToChar 处报错）；修复把清零长度扩到 `(pixels_length+image->rows)*sizeof(*sun_pixels)`。 | ReadSUNImage：补齐缓冲区初始化/清零（+2/-1 行） | `5960b92b652b` | `patches/5960b92b652b51cc53852e7ba3c9b65abceb0452.patch` | upstream |
| 42529799 | MIFF | Use-of-uninitialized-value | CWE-457 | coders/miff.c:2147 in `WriteMIFFImage` | `MagickCore/property.c:4165`（`SetImageProperty`）：设置 density 类属性时直接取 geometry_info.rho/sigma，字符串里没有对应分量时读到未初始化的 sigma 并写进 image->resolution（MSan 报 WriteMIFFImage 处使用未初始化值）；修复只在 flags 含 RhoValue/SigmaValue 时取值，sigma 缺省时沿用已设好的 x。 | SetImageProperty：调整相关实现（+5/-4 行） | `56a19e7ae07f` | `patches/56a19e7ae07f40299f3afd4994d690f2c9b81993.patch` | upstream |
| 42522269 | WBMP | Use-of-uninitialized-value | CWE-457 | coders/wbmp.c:164 in `ReadWBMPImage` | `coders/wbmp.c:159`（`ReadWBMPImage`）：局部 header 未初始化，ReadBlob 返回 0（文件为空）时仍用未初始化的 header 做格式校验和后续解析（MSan 未初始化值）；修复在读之前把 `header=0`。 | ReadWBMPImage：调整相关实现（+1/-0 行） | `21e1ac88739d` | `patches/21e1ac88739dbf99be45782de0dc299b162fcdf5.patch` | upstream |
| 42530943 | MVG | Heap-buffer-overflow WRITE 8 | CWE-787 | MagickCore/draw.c:1666 in `TracePoint` | `MagickCore/draw.c:1770`（`DrawImage`）：primitive_info 的初始容量写死为 6553 点，MVG 图元在首次扩容前就可能写超过该点数，造成堆越界写（崩溃点在 TracePoint）；修复把初始容量提高到 8192。 | DrawImage：增加边界或长度校验（+1/-1 行） | `b78a613f1615` | `patches/resolved/b78a613f16150d6db3b055731211f467756bc412.patch` | resolved |
| 42530977 | HDR | Use-of-uninitialized-value | CWE-457 | coders/hdr.c:485 in `ReadHDRImage` | `coders/hdr.c:403`（`ReadHDRImage`）：行缓冲 pixels 按 4*columns 分配后未清零，RLE 解码没填满整行时残留的 RGBE 分量保持未初始化（MSan 在 ReadHDRImage 处报错）；修复分配后 ResetMagickMemory 清零 4*columns 字节。 | ReadHDRImage：补齐缓冲区初始化/清零（+1/-0 行） | `686c45509c81` | `patches/resolved/686c45509c81d3ecae9cdb34225689b3be97de55.patch` | resolved |
| 42531054 | MIFF | Use-of-uninitialized-value | CWE-457 | coders/miff.c:2240 in `WriteMIFFImage` | `coders/miff.c:517`（`ReadMIFFImage`）：geometry_info 局部变量未初始化就交给后续头部字段（分辨率等）解析使用，最终编码时把未初始化值写进输出（MSan 报 WriteMIFFImage 处使用未初始化值）；修复在解析头部前调用 SetGeometryInfo(&geometry_info)。 | ReadMIFFImage：调整相关实现（+2/-0 行） | `bf04de5d0e66` | `patches/bf04de5d0e66f630dd0c184b478a299854f2d032.patch` | upstream |
| 42531466 | DCM | Heap-buffer-overflow READ 4 | CWE-125 | coders/dcm.c:3964 in `ReadDCMImage` | `coders/dcm.c:3972`（`ReadDCMImage`）：colormap 映射时只判断 `index <= info.max_value`，redmap[i]/graymap[i] 里的负值仍会执行 `info.scale[index]`，向前越界读（heap-buffer-overflow READ 4）；修复增加 `index >= 0` 的下界判断。 | ReadDCMImage：增加边界或长度校验（+4/-4 行） | `e79350c54735` | `patches/e79350c54735fd1051bd0b153ef277a13a7b9618.patch` | upstream |
| 42532777 | SCR | Use-of-uninitialized-value | CWE-457 | coders/scr.c:232 in `ReadSCRImage` | `coders/scr.c:232`（`ReadSCRImage`）：读 6144 字节屏幕区和 768 字节属性区时丢弃 ReadBlob 的返回值，文件短于该长度时 zxscr/zxattr 大部分保持未初始化，随后被当作像素和属性使用（MSan 未初始化值）；修复两处都检查返回值，读不满即抛 CorruptImageError。 | ReadSCRImage：调整相关实现（+4/-1 行） | `164af31c8d4d` | `patches/164af31c8d4d5afd0a5a6a7e27078b5d579adc56.patch` | upstream |
| 42523502 | VIFF | Use-of-uninitialized-value | CWE-457 | MagickCore/image.c:3700 in `PushColormapIndex` | `coders/viff.c:519`（`ReadVIFFImage`）：pixels 缓冲按 MagickMax(number_pixels,max_packets)*bytes_per_pixel 分配但未清零，ReadBlob 读不满时未初始化字节进入像素计算（MSan 在 PushColormapIndex 处报错）；修复分配后清零整块缓冲区。 | ReadVIFFImage：补齐缓冲区初始化/清零（+2/-0 行） | `60cb93d03a9f` | `patches/60cb93d03a9fec83087f803fab877293f1ca12fd.patch` | upstream |
| 42533154 | VIFF | Use-of-uninitialized-value | CWE-457 | coders/viff.c:571 in `ReadVIFFImage` | `coders/viff.c:519`（`ReadVIFFImage`）：pixels 缓冲未初始化就用 ReadBlob 填充，图像数据不足时残留字节被当作调色板索引使用（MSan 未初始化值，崩溃点在 ReadVIFFImage:571）；修复分配后按 MagickMax(number_pixels,max_packets)*bytes_per_pixel 清零。 | ReadVIFFImage：补齐缓冲区初始化/清零（+2/-0 行） | `60cb93d03a9f` | `patches/60cb93d03a9fec83087f803fab877293f1ca12fd.patch` | upstream |
| 42522303 | WPG | Use-of-uninitialized-value | CWE-457 | ./MagickCore/pixel-accessor.h:783 in `SetPixelViaPixelInfo` | `coders/wpg.c:446`（`UnpackWPGRaster`）：BImgBuff 按 ldblk*8 分配后未清零，RLE 解包不足一行时未初始化字节被当作调色板索引写入像素（MSan 在 SetPixelViaPixelInfo 处报错）；修复分配后 ResetMagickMemory 清零该缓冲。 | UnpackWPGRaster：补齐缓冲区初始化/清零（+1/-0 行） | `ce433f8048b1` | `patches/ce433f8048b120b2a0413b4ac3ef59fca35a9788.patch` | upstream |
| 42525613 | PSD | Use-of-uninitialized-value | CWE-457 | ./MagickCore/quantum-private.h:504 in `ScaleQuantumToShort` | `coders/psd.c:1949`（`ReadPSDMergedImage`）：双通道（channels==2）合并图把第二个通道按普通通道索引传给 ReadPSDChannelRLE/ReadPSDChannelRaw，通道数据错位后读到未初始化的通道缓冲（MSan 在 ScaleQuantumToShort 处报错）；修复当 channels==2 时把该通道的 type 置为 -1，按 alpha 通道处理。 | ReadPSDMergedImage：调整相关实现（+9/-2 行） | `79de802e7586` | `patches/resolved/79de802e7586ab4339b7b81e3d3501d5fcffd57a.patch` | resolved |
| 42533821 | MIFF | Use-of-uninitialized-value | CWE-457 | ./MagickCore/quantum.h:116 in `ScaleQuantumToChar` | `coders/miff.c:1249`（`ReadMIFFImage`）：SetImageExtent 之后没有初始化像素缓存，MIFF 数据未覆盖的像素保持未初始化值（MSan 在 ScaleQuantumToChar 处报错）；修复立即调用 SetImageBackgroundColor。 | ReadMIFFImage：补齐缓冲区初始化/清零（+1/-0 行） | `11c7f47df7cb` | `patches/resolved/11c7f47df7cbe2e672c8a975aa1c003d92f4fdc9.patch` | resolved |
| 42518438 | CIN | Heap-buffer-overflow READ 1 | CWE-125 | MagickCore/quantum-import.c:4189 in `ImportQuantumPixels` | `MagickCore/quantum-import.c:2159`（`ImportGrayQuantum`）：循环里先读 4 字节再判断 `x < number_pixels-1`，最后一个像素之后仍执行 PushLongPixel，越过输入缓冲末尾读取（heap-buffer-overflow READ 1，崩溃点内联在 ImportQuantumPixels）；修复把 PushLongPixel 移进 `x++ < number_pixels-1` 分支内。 | ImportGrayQuantum：增加边界或长度校验（+1/-1 行） | `9998cd719775` | `patches/9998cd719775e90f9989fd1ecaa84647a56c1b57.patch` | upstream |
| 42533954 | PCDS | Use-of-uninitialized-value | CWE-457 | ./MagickCore/pixel-accessor.h:37 in `ClampPixel` | `coders/pcd.c:589`（`ReadPCDImage`）：SetImageExtent 之后既不检查返回值也不初始化像素，PCD 数据未覆盖的区域保持未初始化值（MSan 在 ClampPixel 处报错）；修复补上 status 判断并调用 ResetImagePixels。 | ReadPCDImage：补齐缓冲区初始化/清零（+3/-0 行） | `2cf74b529c34` | `patches/2cf74b529c34f2e5915c946e2f4a06f4c292f4c8.patch` | upstream |
| 42533966 | MAC | Use-of-uninitialized-value | CWE-457 | MagickCore/image.c:3700 in `PushColormapIndex` | `coders/mac.c:154`（`ReadMACImage`）：只设了 columns/rows 就按索引写像素，既未调用 SetImageExtent 建立缓存也未初始化，写的是未初始化的像素区域（MSan 在 PushColormapIndex 处报错）；修复补上 SetImageExtent 与 ResetImagePixels，并检查返回值。 | ReadMACImage：补齐缓冲区初始化/清零（+3/-0 行） | `990431dbe768` | `patches/990431dbe7688861ad46a7b8d6cb9d173b429cbd.patch` | upstream |
| 42534188 | WPG | Use-of-uninitialized-value | CWE-457 | ./MagickCore/colormap-private.h:32 in `ConstrainColormapIndex` | `coders/wpg.c:565`（`UnpackWPG2Raster`）：BImgBuff 按 ldblk 分配后未清零，解包数据不足一行时未初始化字节被当作调色板索引（MSan 在 ConstrainColormapIndex 处报错）；修复分配后 `ResetMagickMemory(BImgBuff,0,ldblk*sizeof(*BImgBuff))`。 | UnpackWPG2Raster：补齐缓冲区初始化/清零（+1/-0 行） | `a85ab2609915` | `patches/a85ab26099152be3dab0bd377670abfc815b9fe7.patch` | upstream |
| 42534522 | TIM | Use-of-uninitialized-value | CWE-457 | MagickCore/image.c:3700 in `PushColormapIndex` | `coders/tim.c:252`（`ReadTIMImage`）：只给 columns/rows 赋值，未调用 SetImageExtent 也未初始化像素缓存，随后按索引写像素时落在未初始化区域（MSan 在 PushColormapIndex 处报错）；修复在转换像素前补上 SetImageExtent 与 ResetImagePixels。 | ReadTIMImage：补齐缓冲区初始化/清零（+6/-0 行） | `f472c0ae74c1` | `patches/resolved/f472c0ae74c136284adbbcfe25f628be2da8a02b.patch` | resolved |
| 42534621 | PDB | Use-of-uninitialized-value | CWE-457 | MagickCore/image.c:3700 in `PushColormapIndex` | `coders/pdb.c:420`（`ReadPDBImage`）：像素缓冲按 (packets+257)*rows 分配但未清零，行解码不足时未初始化字节被当作颜色索引（MSan 在 PushColormapIndex 处报错）；修复分配后 ResetMagickMemory 清零整块。 | ReadPDBImage：补齐缓冲区初始化/清零（+1/-0 行） | `0100b8013536` | `patches/0100b8013536d7836566642d69d521fba1d15cf6.patch` | upstream |
| 42534921 | MVG | Heap-buffer-overflow WRITE {*} | CWE-787 | MagickCore/draw.c:1603 in `DrawDashPolygon` | MVG 虚线描边时 DrawDashPolygon 写入的点数超过 dash_polygon 的分配容量，造成堆越界写。 | DrawDashPolygon 的分配式由 2*V+1 改为 2*(V+1)+1，为每个虚线顶点多留 1 个槽位。 | `7a03766efc1f` | `patches/7a03766efc1f45cf13cbd435902d86c3f321368e.patch` | upstream |
| 42535088 | MVG | Heap-buffer-overflow WRITE 4 | CWE-787 | MagickCore/draw.c:1597 in `DrawDashPolygon` | 同一处 dash_polygon 容量仍不足（上一版只多留 1 个顶点），另一组 MVG 虚线参数再次越界写。 | 分配式由 2*(V+1)+1 扩到 2*(V+2)+1，再多留 1 个顶点。 | `3c96caf39133` | `patches/resolved/3c96caf391336735dd15331267694d52a6d3ecd1.patch` | resolved |
| 42535688 | PDB | Use-of-uninitialized-value | CWE-457 | coders/pdb.c:886 in `WritePDBImage` | `coders/pdb.c:854`（`WritePDBImage`）：写 PDB 头用的 512 字节 buffer 未初始化就逐字段填入并整块输出，未赋值的填充字节把未初始化内容写进文件（MSan 在 WritePDBImage:886 处报错）；修复先 `ResetMagickMemory(buffer,0,512*sizeof(*buffer))`。 | ReadPDBImage：补齐缓冲区初始化/清零（+2/-1 行） | `771e54d106ce` | `patches/resolved/771e54d106ce5ff043e7812b4182f3c08a748001.patch` | resolved |
| 42535232 | RLE | Use-of-uninitialized-value | CWE-457 | MagickCore/string.c:697 in `ConstantString` | `coders/rle.c:315`（`ReadRLEImage`）：注释长度 length 直接取自文件，ReadBlob 读不满时仍写 `comment[length-1]='\0'` 并 SetImageProperty，未初始化的注释内容被当作字符串使用（MSan 在 ConstantString 处报错）；修复只有读满 length-1 字节才写入属性。 | ReadRLEImage：调整相关实现（+5/-2 行） | `73aad72d1d28` | `patches/73aad72d1d28170b38014168f523d0ee2941c21e.patch` | upstream |
| 42537011 | MVG | Heap-buffer-overflow WRITE {*} | CWE-787 | MagickCore/draw.c:1597 in `DrawDashPolygon` | 同一处 dash_polygon 分配第三次不足，MVG 虚线在更长顶点序列下越界写。 | 分配式由 2*(V+3)+1 扩到 2*(V+3)+3，多留 1 个顶点并额外 3 个元素。 | `8239e79ee4c8` | `patches/resolved/8239e79ee4c8cc34034838eefe4f34bab02c5fc7.patch` | resolved |

- 案例 68，修复提交 62，补丁文件 62（45 上游 + 17 适配）
- 描述来源：reviewed 4 条（人工核对机制），auto 64 条（按崩溃点+补丁动作生成）
- 代码片段：68 条均带 `code_snippet`（file/function/line/before/after/diff），取自各自修复补丁

## 修复片段

按上表顺序逐条给出所选 hunk 的 diff（最多 12 行，超出时保留首尾）。

**42519749** `coders/sixel.c:462`（`sixel_decode`）
```diff
@@ -377,7 +377,7 @@ MagickBooleanType sixel_decode(unsigned char              /* in */  *p,
             /* DECGRI Graphics Repeat Introducer ! Pn Ch */
             p = get_params(++p, param, &n);
 
-            if (n > 0) {
+            if ((n > 0) && (param[0] > 1)) {
                 repeat_count = param[0];
             }
 
```

**42519182** `MagickCore/quantize.c:3411`（`SetGrayscaleImage`）
```diff
@@ -3318,8 +3318,12 @@ static MagickBooleanType SetGrayscaleImage(Image *image,
   assert(image->signature == MagickCoreSignature);
   if (image->type != GrayscaleType)
     (void) TransformImageColorspace(image,GRAYColorspace,exception);
-  colormap_index=(ssize_t *) AcquireQuantumMemory(MaxColormapSize,
-    sizeof(*colormap_index));
+  if (image->storage_class == PseudoClass)
+    colormap_index=(ssize_t *) AcquireQuantumMemory(image->colors,
+      sizeof(*colormap_index));
+  else
+    colormap_index=(ssize_t *) AcquireQuantumMemory(MaxColormapSize,
+      sizeof(*colormap_index));
   if (colormap_index == (ssize_t *) NULL)
     ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
       image->filename);
```

**42519504** `MagickCore/xml-tree.c:1525`（`ParseEntities`）
```diff
@@ -1484,24 +1484,23 @@ static char *ParseEntities(char *xml,char **entities,int state)
                     offset=(ssize_t) (xml-p);
                     extent=(size_t) (offset+length+strlen(entity));
                     if (p != q)
-                      p=(char *) ResizeQuantumMemory(p,extent,sizeof(*p));
+                      p=(char *) ResizeQuantumMemory(p,extent+1,sizeof(*p));
                     else
                       {
                         char
                           *extent_xml;
 
-                        extent_xml=(char *) AcquireQuantumMemory(extent,
+                        extent_xml=(char *) AcquireQuantumMemory(extent+1,
                           sizeof(*extent_xml));
                         if (extent_xml != (char *) NULL)
-                          {
-                            (void) CopyMagickString(extent_xml,p,extent*
-                              sizeof(*extent_xml));
-                            p= extent_xml;
-                          }
+                          (void) CopyMagickString(extent_xml,p,extent*
+                            sizeof(*extent_xml));
+                        p=extent_xml;
                       }
                     if (p == (char *) NULL)
                       ThrowFatalException(ResourceLimitFatalError,
                         "MemoryAllocationFailed");
+                    p[extent]='\0';
                     xml=p+offset;
                     entity=strchr(xml,';');
                   }
```

**42519760** `coders/pes.c:624`（`ReadPESImage`）
```diff
@@ -547,10 +547,10 @@ static Image *ReadPESImage(const ImageInfo *image_info,ExceptionInfo *exception)
         */
         j++;
         blocks[j].offset=(ssize_t) i;
-        if (j >= 256)
+        if (j >= 255)
           {
             stitches=(PointInfo *) RelinquishMagickMemory(stitches);
-            ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+            ThrowReaderException(ResourceLimitError,"CorruptImage");
           }
         (void) ReadBlobByte(image);
         continue;
```

**42520493** `coders/dds.c:2113`（`ReadDXT3Pixels`）
```diff
@@ -2113,7 +2113,7 @@ static MagickBooleanType ReadDXT3Pixels(Image *image,
       {
         for (i = 0; i < 4; i++)
         {
-          if ((x + i) < (ssize_t) image->rows && (y + j) < (ssize_t) image->columns)
+          if ((x + i) < (ssize_t) image->columns && (y + j) < (ssize_t) image->rows)
             {
               code = (bits >> ((4*j+i)*2)) & 0x3;
               SetPixelRed(image,ScaleCharToQuantum(colors.r[code]),q);
```

**42518038** `Magick++/fuzz/utils.cc:6`（`None`）
```diff
@@ -6,6 +6,8 @@ public:
   FuzzingLimits() {
     Magick::SecurityPolicy::maxMemoryRequest(256000000);
     Magick::ResourceLimits::memory(1000000000);
+    Magick::ResourceLimits::width(2048);
+    Magick::ResourceLimits::height(2048);
   }
 };
 
```

**42518649** `Magick++/fuzz/utils.cc:6`（`None`）
```diff
@@ -6,6 +6,8 @@ public:
   FuzzingLimits() {
     Magick::SecurityPolicy::maxMemoryRequest(256000000);
     Magick::ResourceLimits::memory(1000000000);
+    Magick::ResourceLimits::width(2048);
+    Magick::ResourceLimits::height(2048);
   }
 };
 
```

**42518894** `Magick++/fuzz/utils.cc:6`（`None`）
```diff
@@ -6,6 +6,8 @@ public:
   FuzzingLimits() {
     Magick::SecurityPolicy::maxMemoryRequest(256000000);
     Magick::ResourceLimits::memory(1000000000);
+    Magick::ResourceLimits::width(2048);
+    Magick::ResourceLimits::height(2048);
   }
 };
 
```

**42519338** `Magick++/fuzz/utils.cc:6`（`None`）
```diff
@@ -6,6 +6,8 @@ public:
   FuzzingLimits() {
     Magick::SecurityPolicy::maxMemoryRequest(256000000);
     Magick::ResourceLimits::memory(1000000000);
+    Magick::ResourceLimits::width(2048);
+    Magick::ResourceLimits::height(2048);
   }
 };
 
```

**42519771** `Magick++/fuzz/utils.cc:6`（`None`）
```diff
@@ -6,6 +6,8 @@ public:
   FuzzingLimits() {
     Magick::SecurityPolicy::maxMemoryRequest(256000000);
     Magick::ResourceLimits::memory(1000000000);
+    Magick::ResourceLimits::width(2048);
+    Magick::ResourceLimits::height(2048);
   }
 };
 
```

**42520871** `MagickCore/xml-tree.c:1506`（`ParseEntities`）
```diff
@@ -1494,6 +1494,8 @@ static char *ParseEntities(char *xml,char **entities,int state)
                           sizeof(*extent_xml));
                         if (extent_xml != (char *) NULL)
                           {
+                            ResetMagickMemory(extent_xml,0,extent*
+                              sizeof(*extent_xml));
                             (void) CopyMagickString(extent_xml,p,extent*
                               sizeof(*extent_xml));
                             p= extent_xml;
```

**42519416** `coders/sixel.c:489`（`sixel_decode`）
```diff
@@ -482,7 +489,13 @@ MagickBooleanType sixel_decode(unsigned char              /* in */  *p,
                                 c <<= 1;
                             }
                             for (y = posision_y + i; y < posision_y + i + n; ++y) {
-                                (void) ResetMagickMemory(imbuf + (size_t) imsx * y + posision_x, color_index, repeat_count);
+                                offset=(size_t) imsx * y + posision_x;
+                                if (offset + repeat_count >= (size_t) imsx * imsy)
+                                  {
+                                    imbuf = (unsigned char *) RelinquishMagickMemory(imbuf);
+                                    return (MagickFalse);
+                                  }
+                                (void) ResetMagickMemory(imbuf + offset, color_index, repeat_count);
                             }
                             if (max_x < (posision_x + repeat_count - 1)) {
                                 max_x = posision_x + repeat_count - 1;
```

**42520948** `coders/dcm.c:3927`（`ReadDCMImage`）
```diff
@@ -3927,6 +3927,7 @@ static Image *ReadDCMImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if (status == MagickFalse)
       break;
     image->colorspace=RGBColorspace;
+    (void) SetImageBackgroundColor(image,exception);
     if ((image->colormap == (PixelInfo *) NULL) &&
         (info.samples_per_pixel == 1))
       {
```

**42520971** `coders/pdb.c:349`（`ReadPDBImage`）
```diff
@@ -330,6 +330,7 @@ static Image *ReadPDBImage(const ImageInfo *image_info,ExceptionInfo *exception)
   /*
     Determine if this a PDB image file.
   */
+  (void) ResetMagickMemory(&pdb_info,0,sizeof(pdb_info));
   count=ReadBlob(image,sizeof(pdb_info.name),(unsigned char *) pdb_info.name);
   if (count != sizeof(pdb_info.name))
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
```

**42521159** `coders/txt.c:464`（`ReadTXTImage`）
```diff
@@ -464,8 +464,8 @@ static Image *ReadTXTImage(const ImageInfo *image_info,ExceptionInfo *exception)
     type=ParseCommandOption(MagickColorspaceOptions,MagickFalse,colorspace);
     if (type < 0)
       ThrowReaderException(CorruptImageError,"ImproperImageHeader");
-    (void) SetImageBackgroundColor(image,exception);
     (void) SetImageColorspace(image,(ColorspaceType) type,exception);
+    (void) SetImageBackgroundColor(image,exception);
     GetPixelInfo(image,&pixel);
     range=GetQuantumRange(image->depth);
     for (y=0; y < (ssize_t) image->rows; y++)
```

**42521170** `coders/wpg.c:1391`（`ReadWPGImage`）
```diff
@@ -1391,7 +1391,12 @@ static Image *ReadWPGImage(const ImageInfo *image_info,
 
                     for (i=0; i< (ssize_t) image->rows; i++)
                     {
-                      (void) ReadBlob(image,ldblk,BImgBuff);
+                      ssize_t
+                        count;
+
+                      count=ReadBlob(image,(size_t) ldblk,BImgBuff);
+                      if (count != ldblk)
+                        break;
                       if (InsertRow(image,BImgBuff,i,bpp,exception) == MagickFalse)
                         {
                           if(BImgBuff)
```

**42521270** `coders/pcx.c:385`（`ReadPCXImage`）
```diff
@@ -385,6 +385,7 @@ static Image *ReadPCXImage(const ImageInfo *image_info,ExceptionInfo *exception)
       image->colormap[i].green=ScaleCharToQuantum(*p++);
       image->colormap[i].blue=ScaleCharToQuantum(*p++);
     }
+    (void) SetImageBackgroundColor(image,exception);
     pcx_info.bytes_per_line=ReadBlobLSBShort(image);
     pcx_info.palette_info=ReadBlobLSBShort(image);
     pcx_info.horizontal_screensize=ReadBlobLSBShort(image);
```

**42521591** `MagickCore/token.c:313`（`GetNextToken`）
```diff
@@ -300,7 +300,7 @@ MagickExport void GetNextToken(const char *start,const char **end,
     }
   }
   token[i]='\0';
-  if ((LocaleNCompare(token,"url(",4) == 0) && (strlen(token) > 4))
+  if ((LocaleNCompare(token,"url(",4) == 0) && (strlen(token) > 5))
     {
       ssize_t
         offset;
```

**42522513** `MagickCore/draw.c:3948`（`GetFillAlpha`）
```diff
@@ -3941,7 +3941,7 @@ static double GetFillAlpha(PolygonInfo *polygon_info,const double mid,
         continue;
       }
     i=(ssize_t) MagickMax((double) p->highwater,1.0);
-    for ( ; i < (ssize_t) p->number_points; i++)
+    for ( ; i < (ssize_t) (p->number_points-1); i++)
       if ((double) y <= p->points[i].y)
         break;
     q=p->points+i-1;
```

**42521846** `coders/pict.c:459`（`DecodeImage`）
```diff
@@ -459,6 +459,7 @@ static unsigned char *DecodeImage(Image *blob,Image *image,
       pixels=(unsigned char *) RelinquishMagickMemory(pixels);
       return((unsigned char *) NULL);
     }
+  (void) ResetMagickMemory(scanline,0,2*row_bytes*sizeof(*scanline));
   if (bytes_per_line < 8)
     {
       /*
```

**42521858** `coders/palm.c:314`（`ReadPALMImage`）
```diff
@@ -314,6 +314,7 @@ static Image *ReadPALMImage(const ImageInfo *image_info,
     status=SetImageExtent(image,image->columns,image->rows,exception);
     if (status == MagickFalse)
       return(DestroyImageList(image));
+    (void) SetImageBackgroundColor(image,exception);
     bytes_per_row=ReadBlobMSBShort(image);
     flags=ReadBlobMSBShort(image);
     bits_per_pixel=(size_t) ReadBlobByte(image);
```

**42522869** `coders/palm.c:406`（`ReadPALMImage`）
```diff
@@ -405,10 +406,11 @@ static Image *ReadPALMImage(const ImageInfo *image_info,
     status=SetImageExtent(image,image->columns,image->rows,exception);
     if (status == MagickFalse)
       return(DestroyImageList(image));
-    one_row=(unsigned char *) AcquireQuantumMemory(MagickMax(bytes_per_row,
-      2*image->columns),sizeof(*one_row));
+    extent=MagickMax(bytes_per_row,2*image->columns);
+    one_row=(unsigned char *) AcquireQuantumMemory(extent,sizeof(*one_row));
     if (one_row == (unsigned char *) NULL)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+    (void) ResetMagickMemory(one_row,0,extent*sizeof(*one_row));
     last_row=(unsigned char *) NULL;
     if (compressionType == PALM_COMPRESSION_SCANLINE)
       {
```

**42523358** `coders/pnm.c:428`（`ReadPNMImage`）
```diff
@@ -428,6 +428,7 @@ static Image *ReadPNMImage(const ImageInfo *image_info,ExceptionInfo *exception)
     status=SetImageExtent(image,image->columns,image->rows,exception);
     if (status == MagickFalse)
       return(DestroyImageList(image));
+    (void) SetImageBackgroundColor(image,exception);
     /*
       Convert PNM pixels to runextent-encoded MIFF packets.
     */
```

**42523812** `coders/dpx.c:1134`（`ReadDPXImage`）
```diff
@@ -1134,6 +1134,7 @@ static Image *ReadDPXImage(const ImageInfo *image_info,ExceptionInfo *exception)
   status=SetImageExtent(image,image->columns,image->rows,exception);
   if (status == MagickFalse)
     return(DestroyImageList(image));
+  (void) SetImageBackgroundColor(image,exception);
   for (n=0; n < (ssize_t) dpx.image.number_elements; n++)
   {
     /*
```

**42523868** `coders/mat.c:697`（`ReadMATImageV4`）
```diff
@@ -697,6 +697,7 @@ static Image *ReadMATImageV4(const ImageInfo *image_info,Image *image,
     status=SetImageExtent(image,image->columns,image->rows,exception);
     if (status == MagickFalse)
       return((Image *) NULL);
+    (void) SetImageBackgroundColor(image,exception);
     quantum_info=AcquireQuantumInfo(image_info,image);
     if (quantum_info == (QuantumInfo *) NULL)
       return((Image *) NULL);
```

**42523879** `coders/psd.c:3046`（`RemoveResolutionFromResourceBlock`）
```diff
@@ -3046,7 +3046,8 @@ static void RemoveResolutionFromResourceBlock(StringInfo *bim_profile)
     cnt=PSDQuantum(count);
     if (cnt < 0)
       return;
-    if ((id == 0x000003ed) && (cnt < (ssize_t) (length-12)))
+    if ((id == 0x000003ed) && (cnt < (ssize_t) (length-12)) &&
+        ((ssize_t) length-(cnt+12)-(q-datum)) > 0)
       {
         (void) CopyMagickMemory(q,q+cnt+12,length-(cnt+12)-(q-datum));
         SetStringInfoLength(bim_profile,length-(cnt+12));
```

**42518560** `coders/txt.c:437`（`ReadTXTImage`）
```diff
@@ -437,6 +437,8 @@ static Image *ReadTXTImage(const ImageInfo *image_info,ExceptionInfo *exception)
   (void) ReadBlobString(image,text);
   if (LocaleNCompare((char *) text,MagickID,strlen(MagickID)) != 0)
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
+  x_offset=(-1);
+  y_offset=(-1);
   do
   {
     width=0;
```

**42519915** `coders/miff.c:194`（`PushRunlengthPacket`）
```diff
@@ -194,27 +194,28 @@ static void PushRunlengthPacket(Image *image,const unsigned char *pixels,
   p=pixels;
   if (image->storage_class == PseudoClass)
     {
-      pixel->index=0;
+      pixel->index=0.0;
       switch (image->depth)
       {
         case 32:
         {
-          pixel->index=ConstrainColormapIndex(image,((size_t) *p << 24) |
-            ((size_t) *(p+1) << 16) | ((size_t) *(p+2) << 8) | (size_t) *(p+3),
-            exception);
+          pixel->index=(MagickRealType) ConstrainColormapIndex(image,(ssize_t)
+            (((size_t) *p << 24) | ((size_t) *(p+1) << 16) |
+            ((size_t) *(p+2) << 8) | (size_t) *(p+3)),exception);
           p+=4;
           break;
         }
         case 16:
         {
-          pixel->index=ConstrainColormapIndex(image,(*p << 8) | *(p+1),
-            exception);
+          pixel->index=(MagickRealType) ConstrainColormapIndex(image,(ssize_t)
+            ((*p << 8) | *(p+1)),exception);
           p+=2;
           break;
         }
         case 8:
         {
-          pixel->index=ConstrainColormapIndex(image,*p,exception);
+          pixel->index=(MagickRealType) ConstrainColormapIndex(image,
+            (ssize_t) *p,exception);
           p++;
           break;
         }
```

**42524289** `MagickCore/draw.c:1666`（`TracePoint`）
```diff
@@ -3029,8 +3029,8 @@ MagickExport MagickBooleanType DrawImage(Image *image,const DrawInfo *draw_info,
 
         alpha=bounds.x2-bounds.x1;
         beta=bounds.y2-bounds.y1;
-        radius=hypot((double) alpha,(double) beta);
-        points_extent=2*ceil((double) MagickPI*radius)+6*BezierQuantum+360;
+        radius=hypot(alpha,beta);
+        points_extent=ceil(MagickPI*MagickPI*radius)+6*BezierQuantum+360;
         break;
       }
       default:
```

**42524701** `coders/xcf.c:669`（`load_level`）
```diff
@@ -669,6 +669,7 @@ static MagickBooleanType load_level(Image *image,XCFDocInfo *inDocInfo,
       if (tile_image == (Image *) NULL)
         ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
           image->filename);
+      (void) SetImageBackgroundColor(tile_image,exception);
 
       /* read in the tile */
       switch (inDocInfo->compression)
```

**42518471** `MagickCore/property.c:1750`（`GetXMPProperty`）
```diff
@@ -1742,6 +1742,8 @@ static MagickBooleanType GetXMPProperty(const Image *image,const char *property)
   profile=GetImageProfile(image,"xmp");
   if (profile == (StringInfo *) NULL)
     return(MagickFalse);
+  if (GetStringInfoLength(profile) < 17)
+    return(MagickFalse);
   if ((property == (const char *) NULL) || (*property == '\0'))
     return(MagickFalse);
   xmp_profile=StringInfoToString(profile);
```

**42520316** `MagickCore/property.c:1747`（`GetXMPProperty`）
```diff
@@ -1747,6 +1747,13 @@ static MagickBooleanType GetXMPProperty(const Image *image,const char *property)
   xmp_profile=StringInfoToString(profile);
   if (xmp_profile == (char *) NULL)
     return(MagickFalse);
+  if ((strstr(xmp_profile,"<rdf:RDF") == (char *) NULL) ||
+      (strstr(xmp_profile,"<rdf:Description") == (char *) NULL) ||
+      (strstr(xmp_profile,"<x:") == (char *) NULL))
+    {
+      xmp_profile=DestroyString(xmp_profile);
+      return(MagickFalse);
+    }
   for (p=xmp_profile; *p != '\0'; p++)
     if ((*p == '<') && (*(p+1) == 'x'))
       break;
```

**42525647** `coders/miff.c:901`（`ReadMIFFImage`）
```diff
@@ -901,7 +901,9 @@ static Image *ReadMIFFImage(const ImageInfo *image_info,
                     if (profile == (StringInfo *) NULL)
                       ThrowReaderException(ResourceLimitError,
                         "MemoryAllocationFailed");
-                    (void) SetImageProfile(image,keyword+8,profile,exception);
+                    if (EOFBlob(image) == MagickFalse)
+                      (void) SetImageProfile(image,keyword+8,profile,
+                        exception);
                     profile=DestroyStringInfo(profile);
                     break;
                   }
```

**42525669** `coders/miff.c:901`（`ReadMIFFImage`）
```diff
@@ -901,7 +901,9 @@ static Image *ReadMIFFImage(const ImageInfo *image_info,
                     if (profile == (StringInfo *) NULL)
                       ThrowReaderException(ResourceLimitError,
                         "MemoryAllocationFailed");
-                    (void) SetImageProfile(image,keyword+8,profile,exception);
+                    if (EOFBlob(image) == MagickFalse)
+                      (void) SetImageProfile(image,keyword+8,profile,
+                        exception);
                     profile=DestroyStringInfo(profile);
                     break;
                   }
```

**42525880** `coders/hdr.c:711`（`WriteHDRImage`）
```diff
@@ -711,7 +711,8 @@ static MagickBooleanType WriteHDRImage(const ImageInfo *image_info,Image *image,
   if ((property != (const char *) NULL) &&
       (strchr(property,'\n') == (char *) NULL))
     {
-      count=FormatLocaleString(header,MagickPathExtent,"#%s\n",property);
+      count=FormatLocaleString(header,MagickPathExtent,"#%.*s\n",
+        MagickPathExtent-3,property);
       (void) WriteBlob(image,(size_t) count,(unsigned char *) header);
     }
   property=GetImageProperty(image,"hdr:exposure",exception);
```

**42521880** `coders/viff.c:329`（`ReadVIFFImage`）
```diff
@@ -329,6 +329,12 @@ static Image *ReadVIFFImage(const ImageInfo *image_info,
     image->rows=viff_info.columns;
     image->depth=viff_info.x_bits_per_pixel <= 8 ? 8UL :
       MAGICKCORE_QUANTUM_DEPTH;
+    image->alpha_trait=viff_info.number_data_bands == 4 ? BlendPixelTrait :
+      UndefinedPixelTrait;
+    status=SetImageExtent(image,image->columns,image->rows,exception);
+    if (status == MagickFalse)
+      return(DestroyImageList(image));
+    (void) SetImageBackgroundColor(image,exception);
     /*
       Verify that we can read this VIFF image.
     */
```

**42526335** `MagickCore/profile.c:1859`（`Sync8BimProfile`）
```diff
@@ -1834,7 +1834,7 @@ static MagickBooleanType Sync8BimProfile(Image *image,StringInfo *profile)
       return(MagickFalse);
     id=ReadProfileMSBShort(&p,&length);
     count=(ssize_t) ReadProfileByte(&p,&length);
-    if ((count > (ssize_t) length) || (count < 0))
+    if ((count >= (ssize_t) length) || (count < 0))
       return(MagickFalse);
     p+=count;
     length-=count;
```

**42526424** `MagickCore/xml-tree.c:1722`（`ParseInternalDoctype`）
```diff
@@ -1716,7 +1716,7 @@ static MagickBooleanType ParseInternalDoctype(XMLTreeRoot *root,char *xml,
       xml++;
     if (*xml == '\0')
       break;
-    if (strncmp(xml,"<!ENTITY",8) == 0)
+    if ((strlen(xml) > 9) && (strncmp(xml,"<!ENTITY",8) == 0))
       {
         /*
           Parse entity definitions.
```

**42526757** `coders/ps.c:1009`（`ReadPSImage`）
```diff
@@ -988,6 +1009,35 @@ static Image *ReadPSImage(const ImageInfo *image_info,ExceptionInfo *exception)
           PrependImageToList(&postscript_image,clone_image);
       }
     }
+  if (profiles != (LinkedListInfo *) NULL)
+    {
+      const char
+        *name;
+
+      const StringInfo
+        *profile;
+
+      /*
+        Read image profiles.
+      */
+      ResetLinkedListIterator(profiles);
+      name=(const char *) GetNextValueInLinkedList(profiles);
+      while (name != (const char *) NULL)
+      {
+        profile=GetImageProfile(image,name);
+        if (profile != (StringInfo *) NULL)
+          {
+            register unsigned char
+              *p;
+
+            p=GetStringInfoDatum(profile);
+            count=ReadBlob(image,GetStringInfoLength(profile),p);
+            (void) count;
+          }
+        name=(const char *) GetNextValueInLinkedList(profiles);
+      }
+      profiles=DestroyLinkedList(profiles,RelinquishMagickMemory);
+    }
   do
   {
     (void) CopyMagickString(postscript_image->filename,filename,
```

**42527322** `coders/pict.c:927`（`ReadPICTImage`）
```diff
@@ -927,6 +927,8 @@ static Image *ReadPICTImage(const ImageInfo *image_info,
   status=SetImageExtent(image,image->columns,image->rows,exception);
   if (status == MagickFalse)
     return(DestroyImageList(image));
+  image->alpha_trait=BlendPixelTrait;
+  (void) SetImageBackgroundColor(image,exception);
   /*
     Interpret PICT opcodes.
   */
```

**42527699** `MagickCore/string.c:182`（`AcquireStringInfo`）
```diff
@@ -182,6 +182,7 @@ MagickExport StringInfo *AcquireStringInfo(const size_t length)
       string_info->length+MagickPathExtent,sizeof(*string_info->datum));
   if (string_info->datum == (unsigned char *) NULL)
     ThrowFatalException(ResourceLimitFatalError,"MemoryAllocationFailed");
+  (void) memset(string_info->datum,0,length+MagickPathExtent);
   return(string_info);
 }
 
```

**42527789** `MagickCore/color.c:2385`（`QueryColorCompliance`）
```diff
@@ -2345,7 +2345,7 @@ MagickExport MagickBooleanType QueryColorCompliance(const char *name,
   if (strchr(name,'(') != (char *) NULL)
     {
       char
-        colorspace[MagickPathExtent];
+        colorspace[MagickPathExtent+1];
 
       MagickBooleanType
         icc_color;
```

**42528177** `MagickCore/color.c:2385`（`QueryColorCompliance`）
```diff
@@ -2345,7 +2345,7 @@ MagickExport MagickBooleanType QueryColorCompliance(const char *name,
   if (strchr(name,'(') != (char *) NULL)
     {
       char
-        colorspace[MagickPathExtent];
+        colorspace[2*MagickPathExtent];
 
       MagickBooleanType
         icc_color;
```

**42528200** `coders/pcx.c:418`（`ReadPCXImage`）
```diff
@@ -418,6 +418,8 @@ static Image *ReadPCXImage(const ImageInfo *image_info,ExceptionInfo *exception)
           pixel_info=RelinquishVirtualMemory(pixel_info);
         ThrowPCXException(ResourceLimitError,"MemoryAllocationFailed");
       }
+    (void) ResetMagickMemory(scanline,0,(size_t) MagickMax(image->columns,
+      pcx_info.bytes_per_line)*MagickMax(8,pcx_info.planes)*sizeof(*scanline));
     pixels=(unsigned char *) GetVirtualMemoryBlob(pixel_info);
     (void) ResetMagickMemory(pixels,0,(size_t) pcx_packets*(2*sizeof(*pixels)));
     /*
```

**42528610** `coders/sun.c:478`（`ReadSUNImage`）
```diff
@@ -478,7 +478,8 @@ static Image *ReadSUNImage(const ImageInfo *image_info,ExceptionInfo *exception)
         sun_data=(unsigned char *) RelinquishMagickMemory(sun_data);
         ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
       }
-    ResetMagickMemory(sun_pixels,0,pixels_length*sizeof(*sun_pixels));
+    (void) ResetMagickMemory(sun_pixels,0,(pixels_length+image->rows)*
+      sizeof(*sun_pixels));
     if (sun_info.type == RT_ENCODED)
       {
         status=DecodeImage(sun_data,sun_info.length,sun_pixels,pixels_length);
```

**42529799** `MagickCore/property.c:4165`（`SetImageProperty`）
```diff
@@ -4165,10 +4165,11 @@ MagickExport MagickBooleanType SetImageProperty(Image *image,
             geometry_info;
 
           flags=ParseGeometry(value,&geometry_info);
-          image->resolution.x=geometry_info.rho;
-          image->resolution.y=geometry_info.sigma;
-          if ((flags & SigmaValue) == 0)
-            image->resolution.y=image->resolution.x;
+          if ((flags & RhoValue) != 0)
+            image->resolution.x=geometry_info.rho;
+          image->resolution.y=image->resolution.x;
+          if ((flags & SigmaValue) != 0)
+            image->resolution.y=geometry_info.sigma;
           return(MagickTrue);
         }
       if (LocaleCompare("depth",property) == 0)
```

**42522269** `coders/wbmp.c:164`（`ReadWBMPImage`）
```diff
@@ -159,6 +159,7 @@ static Image *ReadWBMPImage(const ImageInfo *image_info,
       image=DestroyImageList(image);
       return((Image *) NULL);
     }
+  header=0;
   if (ReadBlob(image,2,(unsigned char *) &header) == 0)
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   if (header != 0)
```

**42530943** `MagickCore/draw.c:1666`（`TracePoint`）
```diff
@@ -1770,7 +1770,7 @@ MagickExport MagickBooleanType DrawImage(Image *image,const DrawInfo *draw_info,
       ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
         image->filename);
     }
-  number_points=6553;
+  number_points=8192;
   primitive_info=(PrimitiveInfo *) AcquireQuantumMemory((size_t) number_points,
     sizeof(*primitive_info));
   if (primitive_info == (PrimitiveInfo *) NULL)
```

**42530977** `coders/hdr.c:485`（`ReadHDRImage`）
```diff
@@ -403,6 +403,7 @@ static Image *ReadHDRImage(const ImageInfo *image_info,ExceptionInfo *exception)
     sizeof(*pixels));
   if (pixels == (unsigned char *) NULL)
     ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+  (void) ResetMagickMemory(pixels,0,4*image->columns*sizeof(*pixels));
   for (y=0; y < (ssize_t) image->rows; y++)
   {
     if (image->compression != RLECompression)
```

**42531054** `coders/miff.c:2240`（`WriteMIFFImage`）
```diff
@@ -517,6 +517,7 @@ static Image *ReadMIFFImage(const ImageInfo *image_info,
     /*
       Decode image header;  header terminates one character beyond a ':'.
     */
+    SetGeometryInfo(&geometry_info);
     length=MagickPathExtent;
     options=AcquireString((char *) NULL);
     quantum_format=UndefinedQuantumFormat;
```

**42531466** `coders/dcm.c:3964`（`ReadDCMImage`）
```diff
@@ -3972,7 +3972,7 @@ static Image *ReadDCMImage(const ImageInfo *image_info,ExceptionInfo *exception)
           for (i=0; i < (ssize_t) colors; i++)
           {
             index=redmap[i];
-            if ((info.scale != (Quantum *) NULL) &&
+            if ((info.scale != (Quantum *) NULL) && (index >= 0) &&
                 (index <= (int) info.max_value))
               index=(int) info.scale[index];
             image->colormap[i].red=(MagickRealType) index;
```

**42532777** `coders/scr.c:232`（`ReadSCRImage`）
```diff
@@ -160,8 +160,11 @@ static Image *ReadSCRImage(const ImageInfo *image_info,ExceptionInfo *exception)
   if (status == MagickFalse)
     return(DestroyImageList(image));
   count=ReadBlob(image,6144,(unsigned char *) zxscr);
-  (void) count;
+  if (count != 6144)
+    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   count=ReadBlob(image,768,(unsigned char *) zxattr);
+  if (count != 768)
+    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   for(zonenr=0;zonenr<3;zonenr++)
   {
       for(zoneline=0;zoneline<8;zoneline++)
```

**42523502** `coders/viff.c:519`（`ReadVIFFImage`）
```diff
@@ -519,6 +519,8 @@ static Image *ReadVIFFImage(const ImageInfo *image_info,
       number_pixels,max_packets),bytes_per_pixel*sizeof(*pixels));
     if (pixels == (unsigned char *) NULL)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+    (void) ResetMagickMemory(pixels,0,MagickMax(number_pixels,max_packets)*
+      bytes_per_pixel*sizeof(*pixels));
     count=ReadBlob(image,bytes_per_pixel*max_packets,pixels);
     lsb_first=1;
     if (*(char *) &lsb_first &&
```

**42533154** `coders/viff.c:571`（`ReadVIFFImage`）
```diff
@@ -519,6 +519,8 @@ static Image *ReadVIFFImage(const ImageInfo *image_info,
       number_pixels,max_packets),bytes_per_pixel*sizeof(*pixels));
     if (pixels == (unsigned char *) NULL)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+    (void) ResetMagickMemory(pixels,0,MagickMax(number_pixels,max_packets)*
+      bytes_per_pixel*sizeof(*pixels));
     count=ReadBlob(image,bytes_per_pixel*max_packets,pixels);
     lsb_first=1;
     if (*(char *) &lsb_first &&
```

**42522303** `coders/wpg.c:446`（`UnpackWPGRaster`）
```diff
@@ -446,6 +446,7 @@ static int UnpackWPGRaster(Image *image,int bpp,ExceptionInfo *exception)
   BImgBuff=(unsigned char *) AcquireQuantumMemory((size_t) ldblk,
     8*sizeof(*BImgBuff));
   if(BImgBuff==NULL) return(-2);
+  (void) ResetMagickMemory(BImgBuff,0,(size_t) ldblk*8*sizeof(*BImgBuff));
 
   while(y<(ssize_t) image->rows)
     {
```

**42525613** `coders/psd.c:1949`（`ReadPSDMergedImage`）
```diff
@@ -1949,11 +1949,18 @@ static MagickBooleanType ReadPSDMergedImage(const ImageInfo *image_info,
   status=MagickTrue;
   for (i=0; i < (ssize_t) psd_info->channels; i++)
   {
+    ssize_t
+      type;
+
+    type=i;
+    if ((type == 1) && (psd_info->channels == 2))
+      type=-1;
+
     if (compression == RLE)
-      status=ReadPSDChannelRLE(image,psd_info,i,sizes+(i*image->rows),
+      status=ReadPSDChannelRLE(image,psd_info,type,sizes+(i*image->rows),
         exception);
     else
-      status=ReadPSDChannelRaw(image,psd_info->channels,i,exception);
+      status=ReadPSDChannelRaw(image,psd_info->channels,type,exception);
 
     if (status != MagickFalse)
       status=SetImageProgress(image,LoadImagesTag,i,psd_info->channels);
```

**42533821** `coders/miff.c:1249`（`ReadMIFFImage`）
```diff
@@ -1249,6 +1249,7 @@ static Image *ReadMIFFImage(const ImageInfo *image_info,
     status=SetImageExtent(image,image->columns,image->rows,exception);
     if (status == MagickFalse)
       return(DestroyImageList(image));
+    (void) SetImageBackgroundColor(image,exception);
     /*
       Allocate image pixels.
     */
```

**42518438** `MagickCore/quantum-import.c:4189`（`ImportQuantumPixels`）
```diff
@@ -2159,9 +2159,9 @@ static void ImportGrayQuantum(const Image *image,QuantumInfo *quantum_info,
             p+=quantum_info->pad;
             q+=GetPixelChannels(image);
           }
-          p=PushLongPixel(quantum_info->endian,p,&pixel);
           if (x++ < (ssize_t) (number_pixels-1))
             {
+              p=PushLongPixel(quantum_info->endian,p,&pixel);
               SetPixelGray(image,ScaleAnyToQuantum((pixel >> 2) & 0x3ff,
                 range),q);
               q+=GetPixelChannels(image);
```

**42533954** `coders/pcd.c:589`（`ReadPCDImage`）
```diff
@@ -589,6 +589,9 @@ static Image *ReadPCDImage(const ImageInfo *image_info,ExceptionInfo *exception)
     image->rows<<=1;
   }
   status=SetImageExtent(image,image->columns,image->rows,exception);
+  if (status == MagickFalse)
+    return(DestroyImageList(image));
+  status=ResetImagePixels(image,exception);
   if (status == MagickFalse)
     return(DestroyImageList(image));
   /*
```

**42533966** `coders/mac.c:154`（`ReadMACImage`）
```diff
@@ -154,6 +154,9 @@ static Image *ReadMACImage(const ImageInfo *image_info,ExceptionInfo *exception)
       return(GetFirstImageInList(image));
     }
   status=SetImageExtent(image,image->columns,image->rows,exception);
+  if (status == MagickFalse)
+    return(DestroyImageList(image));
+  status=ResetImagePixels(image,exception);
   if (status == MagickFalse)
     return(DestroyImageList(image));
   /*
```

**42534188** `coders/wpg.c:565`（`UnpackWPG2Raster`）
```diff
@@ -565,6 +565,7 @@ static int UnpackWPG2Raster(Image *image,int bpp,ExceptionInfo *exception)
     sizeof(*BImgBuff));
   if(BImgBuff==NULL)
     return(-2);
+  (void) ResetMagickMemory(BImgBuff,0,ldblk*sizeof(*BImgBuff));
 
   while( y< image->rows)
     {
```

**42534522** `coders/tim.c:252`（`ReadTIMImage`）
```diff
@@ -252,6 +252,12 @@ static Image *ReadTIMImage(const ImageInfo *image_info,ExceptionInfo *exception)
     */
     image->columns=width;
     image->rows=height;
+    status=SetImageExtent(image,image->columns,image->rows,exception);
+    if (status == MagickFalse)
+      return(DestroyImageList(image));
+    status=ResetImagePixels(image,exception);
+    if (status == MagickFalse)
+      return(DestroyImageList(image));
     /*
       Convert TIM raster image to pixel packets.
     */
```

**42534621** `coders/pdb.c:420`（`ReadPDBImage`）
```diff
@@ -420,6 +420,7 @@ static Image *ReadPDBImage(const ImageInfo *image_info,ExceptionInfo *exception)
     sizeof(*pixels));
   if (pixels == (unsigned char *) NULL)
     ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+  (void) ResetMagickMemory(pixels,0,(packets+257UL)*image->rows*sizeof(*pixels));
   switch (pdb_image.version & 0x07) 
   {
     case 0:
```

**42534921** `MagickCore/draw.c:1603`（`DrawDashPolygon`）
```diff
@@ -1520,7 +1520,7 @@ static MagickBooleanType DrawDashPolygon(const DrawInfo *draw_info,
   for (i=0; primitive_info[i].primitive != UndefinedPrimitive; i++) ;
   number_vertices=(size_t) i;
   dash_polygon=(PrimitiveInfo *) AcquireQuantumMemory((size_t)
-    (2UL*number_vertices+1UL),sizeof(*dash_polygon));
+    (2UL*(number_vertices+1UL)+1UL),sizeof(*dash_polygon));
   if (dash_polygon == (PrimitiveInfo *) NULL)
     return(MagickFalse);
   clone_info=CloneDrawInfo((ImageInfo *) NULL,draw_info);
```

**42535088** `MagickCore/draw.c:1597`（`DrawDashPolygon`）
```diff
@@ -1512,7 +1512,7 @@ static MagickBooleanType DrawDashPolygon(const DrawInfo *draw_info,
   for (i=0; primitive_info[i].primitive != UndefinedPrimitive; i++) ;
   number_vertices=(size_t) i;
   dash_polygon=(PrimitiveInfo *) AcquireQuantumMemory((size_t)
-    (2UL*number_vertices+1UL),sizeof(*dash_polygon));
+    (2UL*(number_vertices+2UL)+1UL),sizeof(*dash_polygon));
   if (dash_polygon == (PrimitiveInfo *) NULL)
     return(MagickFalse);
   clone_info=CloneDrawInfo((ImageInfo *) NULL,draw_info);
```

**42535688** `coders/pdb.c:886`（`WritePDBImage`）
```diff
@@ -854,6 +854,7 @@ static MagickBooleanType WritePDBImage(const ImageInfo *image_info,Image *image,
         scanline=(unsigned char *) RelinquishMagickMemory(scanline);
       ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
     }
+  (void) ResetMagickMemory(buffer,0,512*sizeof(*buffer));
   if (IssRGBCompatibleColorspace(image->colorspace) == MagickFalse)
     (void) TransformImageColorspace(image,sRGBColorspace,exception);
   /*
```

**42535232** `coders/rle.c:315`（`ReadRLEImage`）
```diff
@@ -315,8 +315,11 @@ static Image *ReadRLEImage(const ImageInfo *image_info,ExceptionInfo *exception)
             if (comment == (char *) NULL)
               ThrowRLEException(ResourceLimitError,"MemoryAllocationFailed");
             count=ReadBlob(image,length-1,(unsigned char *) comment);
-            comment[length-1]='\0';
-            (void) SetImageProperty(image,"comment",comment,exception);
+            if (count == (length-1))
+              {
+                comment[length-1]='\0';
+                (void) SetImageProperty(image,"comment",comment,exception);
+              }
             comment=DestroyString(comment);
             if ((length & 0x01) == 0)
               (void) ReadBlobByte(image);
```

**42537011** `MagickCore/draw.c:1597`（`DrawDashPolygon`）
```diff
@@ -1512,7 +1512,7 @@ static MagickBooleanType DrawDashPolygon(const DrawInfo *draw_info,
   for (i=0; primitive_info[i].primitive != UndefinedPrimitive; i++) ;
   number_vertices=(size_t) i;
   dash_polygon=(PrimitiveInfo *) AcquireQuantumMemory((size_t)
-    (2UL*number_vertices+1UL),sizeof(*dash_polygon));
+    (2UL*(number_vertices+3UL)+3UL),sizeof(*dash_polygon));
   if (dash_polygon == (PrimitiveInfo *) NULL)
     return(MagickFalse);
   clone_info=CloneDrawInfo((ImageInfo *) NULL,draw_info);
```
