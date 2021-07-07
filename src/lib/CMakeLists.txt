# Copyright (c) 2018-2020 Ribose Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

include(GNUInstallDirs)
include(GenerateExportHeader)

# these could probably be optional but are currently not
find_package(BZip2 REQUIRED)
find_package(ZLIB REQUIRED)

# required packages
find_package(JSON-C 0.11 REQUIRED)
if (CRYPTO_BACKEND_BOTAN)
  find_package(Botan2 2.14.0 REQUIRED)
endif()
if (CRYPTO_BACKEND_OPENSSL)
  include(FindOpenSSL)
  find_package(OpenSSL 1.1.1 REQUIRED)
endif()

# generate a config.h
include(CheckIncludeFileCXX)
include(CheckCXXSymbolExists)
check_include_file_cxx(fcntl.h HAVE_FCNTL_H)
check_include_file_cxx(inttypes.h HAVE_INTTYPES_H)
check_include_file_cxx(limits.h HAVE_LIMITS_H)
check_include_file_cxx(stdint.h HAVE_STDINT_H)
check_include_file_cxx(string.h HAVE_STRING_H)
check_include_file_cxx(sys/cdefs.h HAVE_SYS_CDEFS_H)
check_include_file_cxx(sys/cdefs.h HAVE_SYS_MMAN_H)
check_include_file_cxx(sys/resource.h HAVE_SYS_RESOURCE_H)
check_include_file_cxx(sys/stat.h HAVE_SYS_STAT_H)
check_include_file_cxx(sys/types.h HAVE_SYS_TYPES_H)
check_include_file_cxx(sys/param.h HAVE_SYS_PARAM_H)
check_include_file_cxx(unistd.h HAVE_UNISTD_H)
check_include_file_cxx(sys/wait.h HAVE_SYS_WAIT_H)
check_cxx_symbol_exists(mkdtemp "stdlib.h;unistd.h" HAVE_MKDTEMP)
check_cxx_symbol_exists(mkstemp "stdlib.h;unistd.h" HAVE_MKSTEMP)
check_cxx_symbol_exists(realpath stdlib.h HAVE_REALPATH)
check_cxx_symbol_exists(O_BINARY fcntl.h HAVE_O_BINARY)
check_cxx_symbol_exists(_O_BINARY fcntl.h HAVE__O_BINARY)
check_cxx_symbol_exists(_tempnam stdio.h HAVE__TEMPNAM)
set(HAVE_ZLIB_H "${ZLIB_FOUND}")
set(HAVE_BZLIB_H "${BZIP2_FOUND}")
configure_file(config.h.in config.h)
# generate a version.h
configure_file(version.h.in version.h)

if(CRYPTO_BACKEND_BOTAN)
  # check botan's enabled features
  set(CMAKE_REQUIRED_INCLUDES "${BOTAN2_INCLUDE_DIRS}")
  set(_botan_required_features
      # base
      BIGINT FFI HEX_CODEC PGP_S2K
      # symmetric ciphers
      BLOCK_CIPHER AES BLOWFISH CAMELLIA CAST_128 DES IDEA RIPEMD_160
      # cipher modes
      MODE_CBC MODE_CFB
      # RNG
      AUTO_RNG AUTO_SEEDING_RNG HMAC HMAC_DRBG
      # hash
      CRC24 HASH MD5 SHA1 SHA2_32 SHA2_64 SHA3
      # public-key core
      DL_GROUP DL_PUBLIC_KEY_FAMILY ECC_GROUP ECC_PUBLIC_KEY_CRYPTO PUBLIC_KEY_CRYPTO
      # public-key algs
      CURVE_25519 DSA ECDH ECDSA ED25519 ELGAMAL RSA
      # public-key operations etc
      EME_PKCS1v15 EMSA_PKCS1 EMSA_RAW KDF_BASE RFC3394_KEYWRAP SP800_56A
  )
  # SM2 algorithms suite
  if (ENABLE_SM2)
    list(APPEND _botan_required_features SM2 SM3 SM4)
  endif()
  # AEAD algorithms
  if (ENABLE_AEAD)
    list(APPEND _botan_required_features AEAD_EAX AEAD_OCB)
  endif()
  # Twofish
  if (ENABLE_TWOFISH)
    list(APPEND _botan_required_features TWOFISH)
  endif()
  foreach(feature ${_botan_required_features})
    check_cxx_symbol_exists("BOTAN_HAS_${feature}" botan/build.h _botan_has_${feature})
    if (NOT _botan_has_${feature})
      message(FATAL_ERROR "A required botan feature is missing: ${feature}")
    endif()
  endforeach()
  set(CMAKE_REQUIRED_INCLUDES)
endif()

if(CRYPTO_BACKEND_OPENSSL)
  set(CRYPTO_SOURCES
    crypto/bn_ossl.cpp
    crypto/dsa_ossl.cpp
    crypto/ec_curves.cpp
    crypto/ec_ossl.cpp
    crypto/ecdh_utils.cpp
    crypto/ecdh_ossl.cpp
    crypto/ecdsa_ossl.cpp
    crypto/eddsa_ossl.cpp
    crypto/dl_ossl.cpp
    crypto/elgamal_ossl.cpp
    crypto/hash_ossl.cpp
    crypto/hash_crc24.cpp
    crypto/mpi.cpp
    crypto/rng_ossl.cpp
    crypto/rsa_ossl.cpp
    crypto/s2k.cpp
    crypto/s2k_ossl.cpp
    crypto/symmetric_ossl.cpp
    crypto/signatures.cpp
    crypto/mem_ossl.cpp
    crypto/cipher.cpp
    crypto/cipher_ossl.cpp
  )
  if(ENABLE_SM2)
    list(APPEND CRYPTO_SOURCES crypto/sm2_ossl.cpp)
  endif()
elseif(CRYPTO_BACKEND_BOTAN)
  set(CRYPTO_SOURCES
    crypto/bn.cpp
    crypto/dsa.cpp
    crypto/ec_curves.cpp
    crypto/ec.cpp
    crypto/ecdh_utils.cpp
    crypto/ecdh.cpp
    crypto/ecdsa.cpp
    crypto/eddsa.cpp
    crypto/elgamal.cpp
    crypto/hash.cpp
    crypto/mpi.cpp
    crypto/rng.cpp
    crypto/rsa.cpp
    crypto/s2k.cpp
    crypto/symmetric.cpp
    crypto/signatures.cpp
    crypto/mem.cpp
    crypto/cipher.cpp
    crypto/cipher_botan.cpp
  )
  if(ENABLE_SM2)
    list(APPEND CRYPTO_SOURCES crypto/sm2)
  endif()
else()
  message(FATAL_ERROR "Unknown crypto backend: ${CRYPTO_BACKEND}.")
endif()

add_library(librnp-obj OBJECT
  # librepgp
  ../librepgp/stream-armor.cpp
  ../librepgp/stream-common.cpp
  ../librepgp/stream-ctx.cpp
  ../librepgp/stream-dump.cpp
  ../librepgp/stream-key.cpp
  ../librepgp/stream-packet.cpp
  ../librepgp/stream-parse.cpp
  ../librepgp/stream-sig.cpp
  ../librepgp/stream-write.cpp

  # librekey
  ../librekey/key_store_g10.cpp
  ../librekey/key_store_kbx.cpp
  ../librekey/key_store_pgp.cpp
  ../librekey/rnp_key_store.cpp

  # cryptography
  ${CRYPTO_SOURCES}

  # other sources
  crypto.cpp
  fingerprint.cpp
  generate-key.cpp
  key-provider.cpp
  logging.cpp
  misc.cpp
  pass-provider.cpp
  pgp-key.cpp
  rnp.cpp
  $<TARGET_OBJECTS:rnp-common>
)

set_target_properties(librnp-obj PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(librnp-obj
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/src/lib>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/common>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${PROJECT_SOURCE_DIR}/src"
)
target_link_libraries(librnp-obj PRIVATE JSON-C::JSON-C)
if (CRYPTO_BACKEND_BOTAN)
  target_link_libraries(librnp-obj PRIVATE Botan2::Botan2)
elseif (CRYPTO_BACKEND_OPENSSL)
  target_link_libraries(librnp-obj PRIVATE OpenSSL::Crypto)
endif()

set_target_properties(librnp-obj PROPERTIES CXX_VISIBILITY_PRESET hidden)
if (TARGET BZip2::BZip2)
  target_link_libraries(librnp-obj PRIVATE BZip2::BZip2)
endif()
if (TARGET ZLIB::ZLIB)
  target_link_libraries(librnp-obj PRIVATE ZLIB::ZLIB)
endif()
if (BUILD_SHARED_LIBS)
  target_compile_definitions(librnp-obj PRIVATE librnp_EXPORTS)
else()
  target_compile_definitions(librnp-obj PRIVATE RNP_STATIC)
endif()

add_library(librnp $<TARGET_OBJECTS:librnp-obj> $<TARGET_OBJECTS:rnp-common>)
set_target_properties(librnp
  PROPERTIES
    VERSION "${RNP_VERSION}"
    SOVERSION "${RNP_VERSION_MAJOR}"
    PREFIX "lib"
    OUTPUT_NAME "rnp"
)

if (BUILD_SHARED_LIBS)
  add_library(librnp-static STATIC $<TARGET_OBJECTS:librnp-obj> $<TARGET_OBJECTS:rnp-common>)
else()
  add_library(librnp-static ALIAS librnp)
endif()

foreach (prop LINK_LIBRARIES INTERFACE_LINK_LIBRARIES INCLUDE_DIRECTORIES INTERFACE_INCLUDE_DIRECTORIES)
  get_target_property(val librnp-obj ${prop})
  set_property(TARGET librnp PROPERTY ${prop} ${val})
  if (BUILD_SHARED_LIBS)
    set_property(TARGET librnp-static PROPERTY ${prop} ${val})
  endif()
endforeach()

generate_export_header(librnp
  BASE_NAME rnp/rnp
  EXPORT_MACRO_NAME RNP_API
  STATIC_DEFINE RNP_STATIC
)

# This has precedence and can cause some confusion when the binary
# dir one isn't actually being used. To be improved.
if (NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_CURRENT_BINARY_DIR)
  file(REMOVE "${CMAKE_CURRENT_SOURCE_DIR}/config.h")
  file(REMOVE "${CMAKE_CURRENT_SOURCE_DIR}/version.h")
endif()

if (${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.12.0")
  set(namelink_component NAMELINK_COMPONENT development)
else()
  set(namelink_component)
endif()

# add these to the rnp-targets export
install(TARGETS librnp
  EXPORT rnp-targets
  LIBRARY
    DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
    COMPONENT runtime
    ${namelink_component}
  ARCHIVE DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
)

# install dll only for windows
if (WIN32)
  install(TARGETS librnp
    RUNTIME
      DESTINATION "${CMAKE_INSTALL_BINDIR}"
      COMPONENT runtime
  )
endif()

# install headers
install(
  FILES
    "${PROJECT_SOURCE_DIR}/include/rnp/rnp.h"
  COMPONENT
    development
  DESTINATION
    "${CMAKE_INSTALL_INCLUDEDIR}/rnp"
  RENAME
    rnp.h
)
install(
  FILES
    "${PROJECT_SOURCE_DIR}/include/rnp/rnp_err.h"
  COMPONENT
    development
  DESTINATION
    "${CMAKE_INSTALL_INCLUDEDIR}/rnp"
  RENAME
    rnp_err.h
)
install(
  FILES
    "${PROJECT_BINARY_DIR}/src/lib/rnp/rnp_export.h"
  COMPONENT
    development
  DESTINATION
    "${CMAKE_INSTALL_INCLUDEDIR}/rnp"
  RENAME
    rnp_export.h
)

# .cmake installs
set(INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/rnp")

install(EXPORT rnp-targets
  FILE rnp-targets.cmake
  NAMESPACE rnp::
  DESTINATION "${INSTALL_CMAKEDIR}"
  COMPONENT development
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
  "${PROJECT_SOURCE_DIR}/cmake/rnp-config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/rnp-config.cmake"
  INSTALL_DESTINATION "${INSTALL_CMAKEDIR}"
)
write_basic_package_version_file(rnp-config-version.cmake
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion
)
install (
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/rnp-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/rnp-config-version.cmake"
  DESTINATION "${INSTALL_CMAKEDIR}"
  COMPONENT development
)

function(get_linked_libs libsvar dirsvar tgt)
  get_target_property(imported ${tgt} IMPORTED)
  list(APPEND visited_targets ${tgt})
  if (imported)
    get_target_property(linkedlibs ${tgt} INTERFACE_LINK_LIBRARIES)
  else()
    get_target_property(linkedlibs ${tgt} LINK_LIBRARIES)
  endif()
  set(libs)
  foreach (lib ${linkedlibs})
    if (TARGET ${lib})
      list(FIND visited_targets ${lib} visited)
      if ((${visited} EQUAL -1) AND (${CMAKE_SHARED_LIBRARY_PREFIX}))
        # library
        get_target_property(liblocation ${lib} LOCATION)
        get_filename_component(linkedlib ${liblocation} NAME_WE)
        string(REGEX REPLACE "^${CMAKE_SHARED_LIBRARY_PREFIX}" "" linkedlib ${linkedlib})
        get_linked_libs(linkedlibs libdirs ${lib})
        list(APPEND libs ${linkedlib} ${linkedlibs})
        # directory
        get_filename_component(libdir ${liblocation} DIRECTORY)
        list(FIND ${dirsvar} ${libdir} seendir)
        if (${seendir} EQUAL -1)
          list(APPEND ${dirsvar} ${libdir} ${libdirs})
        endif()
      endif()
    endif()
  endforeach()
  set(visited_targets ${visited_targets} PARENT_SCOPE)
  set(${libsvar} ${libs} PARENT_SCOPE)
  set(${dirsvar} ${${dirsvar}} PARENT_SCOPE)
endfunction()

get_linked_libs(libs dirs librnp)
set(linkercmd)
foreach (dir ${dirs})
  string(APPEND linkercmd "-L${dir} ")
endforeach()
foreach (lib ${libs})
  string(APPEND linkercmd "-l${lib} ")
endforeach()
string(STRIP "${linkercmd}" linkercmd)
set(LIBRNP_PRIVATE_LIBS ${linkercmd})

# create a pkgconfig .pc too
find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
  get_target_property(LIBRNP_OUTPUT_NAME librnp OUTPUT_NAME)
  configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/librnp.pc.in"
    "${PROJECT_BINARY_DIR}/librnp.pc"
    @ONLY
  )
  install(
    FILES "${PROJECT_BINARY_DIR}/librnp.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
    COMPONENT development
  )
endif()

# Build and install man page
if (ENABLE_DOC)
  add_adoc_man("${CMAKE_CURRENT_SOURCE_DIR}/librnp.3.adoc" ${RNP_VERSION})
endif()
