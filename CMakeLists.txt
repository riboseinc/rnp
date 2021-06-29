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

# 3.7+ for the BZip2 target in the cmake-bundled finder (basic build)
# 3.8+ for CPACK_RPM_MAIN_COMPONENT (RPM packaging)
# 3.10+ for CPackFreeBSD (FreeBSD packaging)
# 3.10+ for gtest_discover_tests (parallel rnp_tests)
# 3.12+ for NAMELINK_COMPONENT (for better RPM packaging)
# 3.12+ for Python3 find module
# 3.14+ for object library link dependency propagation
cmake_minimum_required(VERSION 3.14)

# contact email, other info
include(cmake/info.cmake)

# determine version
if (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.cmake")
  file(DOWNLOAD https://raw.githubusercontent.com/rnpgp/cmake-versioning/main/version.cmake
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.cmake")
endif()
include(cmake/version.cmake)
determine_version("${CMAKE_CURRENT_SOURCE_DIR}" RNP)

# project name, etc
project(RNP
  VERSION "${RNP_VERSION}"
  LANGUAGES C CXX
  DESCRIPTION "${PACKAGE_DESCRIPTION_SHORT}"
)

# options
option(ENABLE_COVERAGE "Enable code coverage testing.")
option(ENABLE_SANITIZERS "Enable ASan and other sanitizers.")
option(ENABLE_FUZZERS "Enable fuzz targets.")
option(DOWNLOAD_GTEST "Download Googletest" On)
option(DOWNLOAD_RUBYRNP "Download ruby-rnp and run related tests." On)

# tri-state options
set(TRISTATE_VALUES On Off Auto)

set(ENABLE_DOC Auto CACHE STRING "Enable building documentation.")
set_property(CACHE ENABLE_DOC PROPERTY STRINGS ${TRISTATE_VALUES})

# so we can use our bundled finders
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/Modules")

# required modules
include(CTest)

# default to a release build
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
    "Build type. Options are: None Debug Release RelWithDebInfo MinSizeRel."
    FORCE
  )
endif()

# set warning flags at the top level
if(NOT MSVC)
  add_compile_options(
    -Wall -Wextra
    -Wunreachable-code -Wpointer-arith
    -Wmissing-declarations
  )
# relax some warnings a bit
  add_compile_options(
    -Wno-pedantic
    -Wno-ignored-qualifiers
    -Wno-unused-parameter
    -Wno-missing-field-initializers
  )
endif()

# MSYS-specific options
if(MSYS)
  add_compile_options(
    -fstack-protector
    -fopenmp
  )
  link_libraries(
    -fstack-protector
    -fopenmp
  )
endif()

# set a few other things at the top level to prevent incompatibilities
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_definitions(-D_GNU_SOURCE)

if(MSVC_VERSION GREATER_EQUAL "1900")
    include(CheckCXXCompilerFlag)
    CHECK_CXX_COMPILER_FLAG("/std:c++latest" _cpp_latest_flag_supported)
    if (_cpp_latest_flag_supported)
        add_compile_options("/std:c++latest")
    endif()
endif()

if (ENABLE_COVERAGE OR ENABLE_SANITIZERS)
  message("Forcing build type to Debug (for code coverage or sanitizers).")
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type. Forced to Debug." FORCE)
endif()

# coverage
if (ENABLE_COVERAGE)
  if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(FATAL_ERROR "Coverage has only been tested with the GNU compiler.")
  endif()
  add_compile_options(--coverage -O0)
  link_libraries(--coverage)
endif()

# sanitizers
if (ENABLE_SANITIZERS)
  if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Sanitizers have only been tested with the clang compiler.")
  endif()
  add_compile_options(-fsanitize=leak,address,undefined -fno-omit-frame-pointer -fno-common -O1)
  link_libraries(-fsanitize=leak,address,undefined)
endif()

# adoc for man generation
if (ENABLE_DOC)
  include(AdocMan)
endif()

# everything else is in subdirs
add_subdirectory(src/examples)
if (ENABLE_FUZZERS)
  add_subdirectory(src/fuzzing)
  add_compile_options(-DFUZZERS_ENABLED=1)
endif()
add_subdirectory(src/common)
add_subdirectory(src/lib)
add_subdirectory(src/rnp)
add_subdirectory(src/rnpkeys)

# build tests, if desired
if (BUILD_TESTING)
  # Googletest source path
  if (NOT GTEST_SOURCES)
    set(GTEST_SOURCES "" CACHE STRING
    "Path to the Googletest sources in case of download or linking to the precompiled library is disabled."
    FORCE
    )
  else()
    # Canonicalize path to the Googletest sources.
    get_filename_component(GTEST_SOURCES_FULL ${GTEST_SOURCES} REALPATH)
    set(GTEST_SOURCES ${GTEST_SOURCES_FULL})
  endif()
  add_subdirectory(src/tests)
endif()

# cpack packaging (RPM etc)
include(cmake/packaging.cmake)

