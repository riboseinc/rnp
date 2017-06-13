#!/bin/bash
set -eux

LD_LIBRARY_PATH="${BOTAN_INSTALL}/lib:${CMOCKA_INSTALL}/lib:${JSON_C_INSTALL}/lib"
LDFLAGS="-L${CMOCKA_INSTALL}/lib -L${JSON_C_INSTALL}/lib"
CFLAGS="-I${CMOCKA_INSTALL}/include -I${JSON_C_INSTALL}/include"

[ "$BUILD_MODE" = "coverage" ] && CFLAGS+=" -O0 --coverage"

# CFLAGS for sanitize and sanitize-leaks
[ "$BUILD_MODE" = "sanitize" -o "$BUILD_MODE" = "sanitize-leaks" ] && CFLAGS+=" \
 -fsanitize=leak,address,undefined   \
 -fno-omit-frame-pointer             \
 -fno-common"

# No leak detection for main sanitize run (only for sanitize-leaks)
[ "$BUILD_MODE" = "sanitize" ] && export ASAN_OPTIONS=detect_leaks=0

export LD_LIBRARY_PATH CFLAGS LDFLAGS

autoreconf -vfi
./configure --with-botan=${BOTAN_INSTALL}
make clean
make -j2

: "${COVERITY_SCAN_BRANCH:=0}"
[[ ${COVERITY_SCAN_BRANCH} = 1 ]] && exit 0

cd src/cmocka
./rnp_tests

