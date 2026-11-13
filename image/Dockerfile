# ImageMagick ARVO dataset image, 2018-01-16 — two plain source trees + 62 patches.
#
# Build (context = the deliver/ directory):
#   docker build -f image/Dockerfile -t im-arvo:2018-01-16 deliver
#
# The base image supplies the 2018-era OSS-Fuzz toolchain (clang 6.0.0, libc++,
# the MSan libc++ in /usr/msan/lib, ImageMagick's build dependencies) plus the
# full upstream history.  That history is used here once and then dropped:
#
#   /src/imagemagick-vuln   = upstream 13ffeab + image/refs/prereq-reset-image-pixels.patch
#                             synthetic commit cac8ee0ead0871909046c560a2b0e7b2ac9bb19c
#                             tree a2e675ea85b01a951d0463c1994f2b2d475a54c6
#   /src/imagemagick-fixed  = vuln + image/refs/combined.patch (all 62 fix patches)
#                             synthetic commit 7940a980a4888c83a9cf552ef6cd419a7fce3221
#                             tree e3f5892044af808ef8eb3472d775d8b450f58628
#
# Both are exported as plain trees with .git removed and a .source-id file, so
# the image carries the sources and the patches, not a ref/tag machinery.
# Why synthetic instead of two real upstream commits: 19 of the 62 fix commits
# postdate ResetImagePixels, so they cannot be applied to 13ffeab at all — a
# real-commit baseline would silently lose those cases.  And the earliest real
# commit that contains all 62 fixes is 665 commits after 13ffeab, which drags in
# that many unrelated changes and destroys per-case attribution.  Synthetic
# nodes keep `fixed` and `vuln` exactly 62 patches apart and nothing else.
# Identity and dates are pinned, so both SHAs above are reproducible.
FROM n132/arvo:42518038-vul@sha256:fce885bd28185e1f08512fad0085714b32526187f7041fb7941965e8fd8de124

COPY payload/ /payload/
COPY scripts/ /opt/imdt/
COPY image/refs/ /refs/

RUN set -eux; \
    cd /src/imagemagick; \
    git config gc.auto 0; \
    export GIT_AUTHOR_NAME="ARVO phase1" GIT_AUTHOR_EMAIL=arvo@localhost; \
    export GIT_COMMITTER_NAME="ARVO phase1" GIT_COMMITTER_EMAIL=arvo@localhost; \
    git checkout -q -f --detach 13ffeabe9abd6c262a8b6bfaeb1e145a420f8e3a; \
    git reset -q --hard 13ffeabe9abd6c262a8b6bfaeb1e145a420f8e3a; \
    git clean -xffdq; \
    git apply /refs/prereq-reset-image-pixels.patch; \
    git add -A; \
    GIT_AUTHOR_DATE=2018-01-16T12:27:52+0100 \
    GIT_COMMITTER_DATE=2018-01-16T12:27:52+0100 \
      git commit -q -m "baseline 7.0.7-21-82-g13ffeab + ResetImagePixels prerequisite"; \
    test "$(git rev-parse HEAD)" = cac8ee0ead0871909046c560a2b0e7b2ac9bb19c; \
    test "$(git rev-parse HEAD^{tree})" = a2e675ea85b01a951d0463c1994f2b2d475a54c6; \
    mkdir -p /src/imagemagick-vuln; \
    git archive HEAD | tar -x -C /src/imagemagick-vuln; \
    printf 'tree\timagemagick-vuln\nupstream\t13ffeabe9abd6c262a8b6bfaeb1e145a420f8e3a\ncommit\tcac8ee0ead0871909046c560a2b0e7b2ac9bb19c\ntree_sha\ta2e675ea85b01a951d0463c1994f2b2d475a54c6\ndate\t2018-01-16\n' \
      > /src/imagemagick-vuln/.source-id; \
    git apply --3way /refs/combined.patch; \
    git add -A; \
    GIT_AUTHOR_DATE=2018-03-20T19:44:04-0400 \
    GIT_COMMITTER_DATE=2018-03-20T19:44:04-0400 \
      git commit -q -m "apply all 62 ImageMagick fixes for the ARVO cases"; \
    test "$(git rev-parse HEAD)" = 7940a980a4888c83a9cf552ef6cd419a7fce3221; \
    test "$(git rev-parse HEAD^{tree})" = e3f5892044af808ef8eb3472d775d8b450f58628; \
    test "$(git diff --name-only HEAD~1 HEAD | wc -l)" = 38; \
    mkdir -p /src/imagemagick-fixed; \
    git archive HEAD | tar -x -C /src/imagemagick-fixed; \
    printf 'tree\timagemagick-fixed\nupstream\t13ffeabe9abd6c262a8b6bfaeb1e145a420f8e3a\ncommit\t7940a980a4888c83a9cf552ef6cd419a7fce3221\ntree_sha\te3f5892044af808ef8eb3472d775d8b450f58628\ndate\t2018-03-20\n' \
      > /src/imagemagick-fixed/.source-id; \
    cd /; \
    rm -rf /src/imagemagick /refs /out/* /work/* /src/afl /src/honggfuzz \
           /src/libfuzzer /src/afl_testcases.tgz /src/build.sh

# The base image sets WORKDIR=/src/imagemagick, and Docker recreates a missing
# WORKDIR before every RUN -- which would bring back the git repo directory that
# the step above has just deleted.  Move out of it here, once.
WORKDIR /opt/imdt

RUN chmod +x /opt/imdt/*.sh /opt/imdt/imdt

# Prebuild the six instrumented reproducers so the image verifies out of the
# box: /out/repro-<tree>-<san>, hand_repro.cc linked against each build's
# installed headers and static libs.  hand_repro.cc is a hand-written driver (no
# fuzz target, no libFuzzer runtime): forced format, Blob read + write back,
# swallowed Magick::Exception, utils.cc limits, plus width/height(2048) on the
# fixed tree (patch e8be814f) selected by that tree's own Magick++/fuzz/utils.cc.
# /work is emptied in the same layer, so `imdt build-san` still runs a real build.
RUN set -eux; \
    /opt/imdt/build-san.sh all all; \
    rm -rf /work/*

ENV SRC=/src \
    PAYLOAD=/payload \
    OUT=/out \
    WORK=/work \
    PATH=/opt/imdt:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/out

# The delivered layout, asserted: two plain buildable trees with no .git and a
# .source-id each, no git repository left behind, no /refs, the full payload and
# the six reproducers.  Nothing here expects an encoder_*_fuzzer.
RUN set -eux; \
    test ! -e /src/imagemagick; \
    test ! -e /refs; \
    test "$(ls /src | tr '\n' ' ')" = "imagemagick-fixed imagemagick-vuln "; \
    for t in vuln fixed; do \
      d=/src/imagemagick-$t; \
      test -f $d/configure; \
      test -f $d/Makefile.am; \
      test -f $d/MagickCore/image.c; \
      test -f $d/.source-id; \
      test ! -e $d/.git; \
      grep -q '^tree' $d/.source-id; \
      grep -q "imagemagick-$t" $d/.source-id; \
      grep -q '13ffeabe9abd6c262a8b6bfaeb1e145a420f8e3a' $d/.source-id; \
    done; \
    grep -q 'e3f5892044af808ef8eb3472d775d8b450f58628' /src/imagemagick-fixed/.source-id; \
    test "$(ls /payload/patches/*.patch | wc -l)" = 45; \
    test "$(ls /payload/patches/resolved/*.patch | wc -l)" = 17; \
    test "$(ls -d /payload/pocs/*/poc | wc -l)" = 68; \
    test "$(ls /out/repro-* | wc -l)" = 6; \
    for t in vuln fixed; do \
      for s in address undefined memory; do \
        test -x /out/repro-$t-$s; \
      done; \
    done; \
    test -z "$(ls -A /work)"

CMD ["/bin/bash"]
