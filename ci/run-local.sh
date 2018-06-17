#!/bin/bash
set -eux

export LOCAL_BUILDS="$HOME/local-builds"
export BOTAN_INSTALL="${LOCAL_BUILDS}/botan-install"
export CMOCKA_INSTALL="${LOCAL_BUILDS}/cmocka-install"
export JSONC_INSTALL="${LOCAL_BUILDS}/jsonc-install"
export GPG_INSTALL="${LOCAL_BUILDS}/gpg-install"
export RNP_INSTALL="${LOCAL_BUILDS}/rnp-install"
export RUBY_RNP_INSTALL="${LOCAL_BUILDS}/ruby-rnp"
export RUBY_RNP_VERSION="v1.0.0"
export CC=clang
export CORES=$(grep -c '^$' /proc/cpuinfo)
ci/install.sh
ci/main.sh

