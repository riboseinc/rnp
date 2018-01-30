#!/bin/sh
set -ex

export PATH=/usr/local/bin:$PATH
export LOCAL_BUILDS=${WORKSPACE}/local-builds
export BOTAN_INSTALL="${LOCAL_BUILDS}/builds/botan-install"
export CMOCKA_INSTALL="${LOCAL_BUILDS}/builds/cmocka-install"
export JSONC_INSTALL="${LOCAL_BUILDS}/builds/json-c-install"
export GPG21_INSTALL="${LOCAL_BUILDS}/builds/gpg21-install"
export BUILD_MODE=normal
export CLANG_FORMAT_DIFF="clang-format-diff-4.0"
export CC=gcc
export MAKE=gmake

# TODO: make these read from pkg_info
export AUTOCONF_VERSION=2.69
export AUTOMAKE_VERSION=1.15

# TODO: use this environment variable in test scripts
export GPG=gpg2
