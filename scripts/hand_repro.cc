/* 手写用例：不包含 encoder_fuzzer.cc，完全按 harness 的语义复刻。
 *
 * 复刻的三件事：
 *   ① 入口   image.magick(coder) + fileName(coder + ":") → read(blob) → write(blob, coder)
 *   ② 限制   SecurityPolicy::maxMemoryRequest(2.56e8) + ResourceLimits::memory(1e9)
 *            （照抄 Magick++/fuzz/utils.cc 的 FuzzingLimits）
 *   ③ 异常   catch(Magick::Exception) 后正常返回，解析失败不算崩溃
 *
 * 与靶子的唯一差别：coder 来自命令行（运行时），而不是 -DFUZZ_IMAGEMAGICK_ENCODER。
 *
 * 编译由同目录下的 build-san.sh 负责（插桩版 → /out/repro-<tree>-<san>）；plain 构建
 * build.sh 只编源码树，不产生复现器。手工等价命令：
 *
 *   clang++ -O1 -gline-tables-only -fno-omit-frame-pointer -stdlib=libc++ -std=c++11 \
 *     -fsanitize=address -I/work/build-vuln-address/inst/include/ImageMagick-7 \
 *     hand_repro.cc -o /tmp/hand_repro \
 *     -DMAGICKCORE_HDRI_ENABLE=1 -DMAGICKCORE_QUANTUM_DEPTH=16 \
 *     /work/build-vuln-address/inst/lib/libMagick++-7.Q16HDRI.a \
 *     /work/build-vuln-address/inst/lib/libMagickWand-7.Q16HDRI.a \
 *     /work/build-vuln-address/inst/lib/libMagickCore-7.Q16HDRI.a -lpthread -lm
 *
 *   /tmp/hand_repro MVG /payload/pocs/42524289/poc
 */
#include <Magick++.h>
#include <Magick++/ResourceLimits.h>
#include <Magick++/SecurityPolicy.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

static void apply_fuzzing_limits() {
  Magick::SecurityPolicy::maxMemoryRequest(256000000);
  Magick::ResourceLimits::memory(1000000000);
#ifdef HARNESS_FIXED_LIMITS
  // fixed 树的 utils.cc 多了这两行（e8be814f），5 条案例靠它们才算"修好"
  Magick::ResourceLimits::width(2048);
  Magick::ResourceLimits::height(2048);
#endif
}

static void run_one(const std::string &coder, const unsigned char *data, size_t size) {
  const Magick::Blob blob(data, size);
  Magick::Image image;
  image.magick(coder);
  image.fileName(coder + ":");
  try {
    image.read(blob);
  } catch (Magick::Exception &) {
    return;
  }
  Magick::Blob out;
  try {
    image.write(&out, coder);
  } catch (Magick::Exception &) {
  }
}

int main(int argc, char **argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: %s <coder> <poc-file>\n", argv[0]);
    return 2;
  }
  FILE *f = std::fopen(argv[2], "rb");
  if (f == NULL) {
    std::fprintf(stderr, "cannot open %s\n", argv[2]);
    return 2;
  }
  std::fseek(f, 0, SEEK_END);
  long size = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  if (size < 0) {
    std::fclose(f);
    return 2;
  }
  unsigned char *buf = (unsigned char *)std::malloc(size > 0 ? (size_t)size : 1);
  if (buf == NULL) {
    std::fclose(f);
    return 2;
  }
  if (size > 0 && std::fread(buf, 1, (size_t)size, f) != (size_t)size) {
    std::fclose(f);
    std::free(buf);
    return 2;
  }
  std::fclose(f);

  apply_fuzzing_limits();
  run_one(argv[1], buf, (size_t)size);
  std::free(buf);
  return 0;
}
