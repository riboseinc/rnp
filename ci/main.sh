#!/usr/bin/env bash
set -eux

. ci/env.inc.sh

: "${GPG_VERSION:=stable}"
: "${BUILD_MODE:=normal}"

: "${RNP_TESTS=${RNP_TESTS-.*}}"
: "${LD_LIBRARY_PATH:=}"

: "${DIST:=}"
: "${DIST_VERSION:=}"

prepare_build_prerequisites() {
  CMAKE=cmake

  case "${OS}-${CPU}" in
    linux-i386)
      build_and_install_python
      ;;
    linux-*)
      PREFIX=/usr
      ensure_cmake
      ;;
  esac

  export CMAKE
}

prepare_test_env() {
  prepare_build_tool_env

  export LD_LIBRARY_PATH="${GPG_INSTALL}/lib:${BOTAN_INSTALL}/lib:${JSONC_INSTALL}/lib:${RNP_INSTALL}/lib:$LD_LIBRARY_PATH"

  # update dll search path for windows
  if [[ "${OS}" = "msys" ]]; then
    export PATH="${LOCAL_BUILDS}/rnp-build/lib:${LOCAL_BUILDS}/rnp-build/bin:${LOCAL_BUILDS}/rnp-build/src/lib:$PATH"
  fi
}

prepare_tests() {
  : "${COVERITY_SCAN_BRANCH:=0}"
  [[ ${COVERITY_SCAN_BRANCH} = 1 ]] && exit 0

  # workaround macOS SIP
  if [[ "${BUILD_MODE}" != "sanitize" ]] && \
     [[ "${OS}" = "macos" ]]; then
    pushd "$RUBY_RNP_INSTALL"
    cp "${RNP_INSTALL}/lib"/librnp* /usr/local/lib
    popd
  fi
}

build_tests() {
  #  use test costs to prioritize
  mkdir -p "${LOCAL_BUILDS}/rnp-build/Testing/Temporary"
  cp "${rnpsrc}/cmake/CTestCostData.txt" "${LOCAL_BUILDS}/rnp-build/Testing/Temporary"

  local run=run
  case "${DIST_VERSION}" in
    centos-8|fedora-*)
      run=run_in_python_venv
      ;;
  esac

  "${run}" ctest -j"${CTEST_PARALLEL}" -R "$RNP_TESTS" --output-on-failure
  popd
}

main() {
  prepare_test_env
  prepare_build_prerequisites

  export rnpsrc="$PWD"

  mkdir -p "${LOCAL_BUILDS}/rnp-build"
  pushd "${LOCAL_BUILDS}/rnp-build"

  cmakeopts=(
    -DCMAKE_BUILD_TYPE=RelWithDebInfo
    -DBUILD_SHARED_LIBS=yes
    -DCMAKE_INSTALL_PREFIX="${RNP_INSTALL}"
    -DCMAKE_PREFIX_PATH="${BOTAN_INSTALL};${JSONC_INSTALL};${GPG_INSTALL}"
  )

  [[ "${BUILD_MODE}" = "coverage" ]] && cmakeopts+=(-DENABLE_COVERAGE=yes)
  [[ "${BUILD_MODE}" = "sanitize" ]] && cmakeopts+=(-DENABLE_SANITIZERS=yes)
  [ -v "GTEST_SOURCES" ] && cmakeopts+=(-DGTEST_SOURCES="${GTEST_SOURCES}")
  [ -v "DOWNLOAD_GTEST" ] && cmakeopts+=(-DDOWNLOAD_GTEST="${DOWNLOAD_GTEST}")
  [ -v "DOWNLOAD_RUBYRNP" ] && cmakeopts+=(-DDOWNLOAD_RUBYRNP="${DOWNLOAD_RUBYRNP}")
  [ -v "CRYPTO_BACKEND" ] && cmakeopts+=(-DCRYPTO_BACKEND="${CRYPTO_BACKEND}")

  if [[ "${OS}" = "msys" ]]; then
    cmakeopts+=(-G "MSYS Makefiles")
  fi
  build_rnp "${rnpsrc}"
  make_install VERBOSE=1

  prepare_tests
  build_tests
}

main "$@"

exit 0
