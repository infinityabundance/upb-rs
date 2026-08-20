#!/bin/sh
# Builds the pinned upstream upb oracle (Tier-1 behavioral oracle).
#
#   tools/oracle/build.sh            build libupb + oracle (default Release)
#   tools/oracle/build.sh debug      build with -O0 -g
#   tools/oracle/build.sh asan       build with AddressSanitizer (for courts)
#
# Artifacts:
#   third_party/build/libupb.a       pinned upstream static library
#   tools/oracle/build/oracle        the oracle server executable
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MODE="${1:-release}"

cmake_flags="-Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=OFF -Dprotobuf_BUILD_PROTOC=OFF"
extra_cflags=""
case "$MODE" in
  release) cmake_flags="$cmake_flags -DCMAKE_BUILD_TYPE=Release" ;;
  debug)   cmake_flags="$cmake_flags -DCMAKE_BUILD_TYPE=Debug" ;;
  asan)    cmake_flags="$cmake_flags -DCMAKE_BUILD_TYPE=RelWithDebInfo"
           extra_cflags="-fsanitize=address,undefined -fno-omit-frame-pointer" ;;
  *) echo "unknown mode: $MODE" >&2; exit 1 ;;
esac

cmake -S "$ROOT/third_party/protobuf" -B "$ROOT/third_party/build" $cmake_flags
cmake --build "$ROOT/third_party/build" --target libupb -j"$(nproc)"

mkdir -p "$ROOT/tools/oracle/build"
cc -O2 -Wall -Wextra -I"$ROOT/third_party/protobuf" $extra_cflags \
   -o "$ROOT/tools/oracle/build/oracle" \
   "$ROOT/tools/oracle/src/oracle.c" \
   "$ROOT/third_party/build/libupb.a" \
   "$ROOT/third_party/build/third_party/utf8_range/libutf8_range.a"

echo "oracle built: $ROOT/tools/oracle/build/oracle"
