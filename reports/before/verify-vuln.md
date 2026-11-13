# verify — tree `vuln`

| field | value |
| --- | --- |
| tree dir | `/src/imagemagick-vuln` |
| sanitizers | address undefined memory |
| cases | 68 |
| generated | 2026-11-12T14:23:15Z |

| localId | coder | sanitizer | result | SUMMARY |
| --- | --- | --- | --- | --- |
| 42518038 | G3 | undefined | CRASH | SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior MagickCore/compress.c:835:28 in  |
| 42518438 | CIN | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /work/build-vuln-address/src/./MagickCore/quantum-private.h in PushLongPixel |
| 42518471 | MIFF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/property.c:1750:3 in GetXMPProperty |
| 42518560 | TXT | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/cache.c:3954:61 in QueueAuthenticPixelCacheNexus |
| 42518649 | PALM | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/pixel.c:6132:7 in IsFuzzyEquivalencePixelInfo |
| 42518894 | WPG | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/cache.c:3368:11 in WritePixelCacheRegion |
| 42519182 | SUN | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /work/build-vuln-address/src/MagickCore/quantize.c:3411:55 in SetGrayscaleImage |
| 42519338 | WPG | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/colormap-private.h:32:7 in ConstrainColormapIndex |
| 42519416 | SIXEL | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /src/llvm/projects/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cc:27 in __asan_memset |
| 42519504 | EPSI | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /work/build-vuln-address/src/MagickCore/xml-tree.c:1525:19 in ParseEntities |
| 42519749 | SIX | address | CRASH | SUMMARY: AddressSanitizer: SEGV /work/build-vuln-address/src/coders/sixel.c:462:73 in sixel_decode |
| 42519760 | PES | address | CRASH | SUMMARY: AddressSanitizer: stack-buffer-overflow /work/build-vuln-address/src/coders/pes.c:624:19 in ReadPESImage |
| 42519771 | TIM | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/image.c:3775:7 in PushColormapIndex |
| 42519915 | MIFF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/locale.c:1518:10 in LocaleNCompare |
| 42520316 | EPS | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /src/llvm/projects/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:707 in strspn |
| 42520493 | DXT5 | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /work/build-vuln-address/src/./MagickCore/pixel-accessor.h:844:52 in SetPixelRed |
| 42520871 | EPS | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/xml-tree.c:1506:28 in ParseEntities |
| 42520948 | DCM | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/pixel-accessor.h:522:55 in IsPixelGray |
| 42520971 | PDB | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/coders/pdb.c:349:45 in ReadPDBImage |
| 42521159 | TXT | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/quantum.h:116:7 in ScaleQuantumToChar |
| 42521170 | WPG | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/pixel-accessor.h:783:32 in SetPixelViaPixelInfo |
| 42521270 | PCX | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/pixel-accessor.h:567:50 in IsPixelMonochrome |
| 42521591 | MVG | address | CRASH | SUMMARY: AddressSanitizer: stack-buffer-overflow /work/build-vuln-address/src/MagickCore/token.c:313:24 in GetNextToken |
| 42521846 | PICT | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/colormap-private.h:32:7 in ConstrainColormapIndex |
| 42521858 | PALM | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/pixel.c:6132:7 in IsFuzzyEquivalencePixelInfo |
| 42521880 | VIFF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/quantum.h:116:7 in ScaleQuantumToChar |
| 42522269 | WBMP | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/coders/wbmp.c:164:7 in ReadWBMPImage |
| 42522303 | WPG | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/pixel-accessor.h:783:32 in SetPixelViaPixelInfo |
| 42522513 | MVG | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/draw.c:3948:9 in GetFillAlpha |
| 42522869 | PALM | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/quantum.h:116:7 in ScaleQuantumToChar |
| 42523358 | PNM | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/pixel-accessor.h:487:7 in IsPixelEquivalent |
| 42523502 | VIFF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/image.c:3775:7 in PushColormapIndex |
| 42523812 | DPX | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/quantum-private.h:504:7 in ScaleQuantumToShort |
| 42523868 | MAT | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/pixel-accessor.h:522:55 in IsPixelGray |
| 42523879 | PSD | address | CRASH | SUMMARY: AddressSanitizer: negative-size-param /src/llvm/projects/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cc:23 in __asan_memcpy |
| 42524289 | MVG | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /work/build-vuln-address/src/MagickCore/draw.c:1666:30 in TracePoint |
| 42524701 | XCF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/pixel-accessor.h:37:7 in ClampPixel |
| 42525613 | PSD | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/quantum-private.h:504:7 in ScaleQuantumToShort |
| 42525647 | MIFF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/property.c:1336:9 in GetEXIFProperty |
| 42525669 | MIFF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/locale.c:1518:10 in LocaleNCompare |
| 42525880 | HDR | address | CRASH | SUMMARY: AddressSanitizer: stack-buffer-overflow /src/llvm/projects/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cc:23 in __asan_memcpy |
| 42526335 | GIF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/profile.c:1859:9 in Sync8BimProfile |
| 42526424 | EPSI | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /src/llvm/projects/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:707 in strspn |
| 42526757 | PS | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /work/build-vuln-address/src/MagickCore/xml-tree.c:2288:35 in NewXMLTree |
| 42527322 | PICT | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/quantum.h:116:7 in ScaleQuantumToChar |
| 42527699 | GIF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/profile.c:1844:9 in Sync8BimProfile |
| 42527789 | MIFF | address | CRASH | SUMMARY: AddressSanitizer: stack-buffer-overflow /work/build-vuln-address/src/MagickCore/color.c:2385:23 in QueryColorCompliance |
| 42528177 | MIFF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/color.c:2385:11 in QueryColorCompliance |
| 42528200 | PCX | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/quantum.h:116:7 in ScaleQuantumToChar |
| 42528610 | SUN | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/quantum.h:116:7 in ScaleQuantumToChar |
| 42529799 | MIFF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/coders/miff.c:2147:36 in WriteMIFFImage |
| 42530943 | MVG | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /work/build-vuln-address/src/MagickCore/draw.c:1666:30 in TracePoint |
| 42530977 | HDR | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/coders/hdr.c:485:11 in ReadHDRImage |
| 42531054 | MIFF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/coders/miff.c:2240:9 in WriteMIFFImage |
| 42531466 | DCM | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /work/build-vuln-address/src/coders/dcm.c:3964:27 in ReadDCMImage |
| 42532777 | SCR | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/coders/scr.c:232:19 in ReadSCRImage |
| 42533154 | VIFF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/coders/viff.c:571:15 in ReadVIFFImage |
| 42533821 | MIFF | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/quantum.h:116:7 in ScaleQuantumToChar |
| 42533954 | PCDS | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/pixel-accessor.h:37:7 in ClampPixel |
| 42533966 | MAC | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/image.c:3775:7 in PushColormapIndex |
| 42534188 | WPG | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/./MagickCore/colormap-private.h:32:7 in ConstrainColormapIndex |
| 42534522 | TIM | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/image.c:3775:7 in PushColormapIndex |
| 42534621 | PDB | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/image.c:3775:7 in PushColormapIndex |
| 42534921 | MVG | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /src/llvm/projects/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cc:23 in __asan_memcpy |
| 42535088 | MVG | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /src/llvm/projects/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cc:23 in __asan_memcpy |
| 42535232 | RLE | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/MagickCore/string.c:697:13 in ConstantString |
| 42535688 | PDB | memory | CRASH | SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/build-vuln-memory/src/coders/pdb.c:886:15 in WritePDBImage |
| 42537011 | MVG | address | CRASH | SUMMARY: AddressSanitizer: heap-buffer-overflow /src/llvm/projects/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cc:23 in __asan_memcpy |

crash=68 clean=0

**verdict: PASS** — `vuln` expects `crash`
