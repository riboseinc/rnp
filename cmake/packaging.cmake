# Copyright (c) 2018 Ribose Inc.
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

# this file contains packaging items that aren't likely to change much

# general
set(CPACK_PACKAGE_VENDOR "${PACKAGE_VENDOR}")
set(CPACK_PACKAGE_CONTACT "${PACKAGING_EMAIL}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PACKAGE_DESCRIPTION_SHORT}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}${CPACK_PACKAGE_VERSION}")
set(CPACK_PACKAGE_NAME "${PROJECT_NAME}${PROJECT_VERSION_MAJOR}")

# deb-specific
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "${PACKAGE_URL}")
set(CPACK_DEBIAN_PACKAGE_RELEASE "${DEB_RELEASE_NUM}")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

# rpm-specific
set(CPACK_RPM_PACKAGE_LICENSE "${PACKAGE_LICENSE}")
set(CPACK_RPM_PACKAGE_URL "${PACKAGE_URL}")
set(CPACK_RPM_PACKAGE_RELEASE "${RPM_RELEASE_NUM}${RNP_VERSION_SUFFIX}")
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_RELEASE_DIST ON)
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
set(CPACK_RPM_PACKAGE_DESCRIPTION "${PACKAGE_DESCRIPTION}")
set(CPACK_RPM_PACKAGE_AUTOREQPROV ON)
file(WRITE "${PROJECT_BINARY_DIR}/rpm-ldconfig" "/sbin/ldconfig")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${PROJECT_BINARY_DIR}/rpm-ldconfig")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${PROJECT_BINARY_DIR}/rpm-ldconfig")
# obsolete the original package name, now preferring to append the major ver
set(CPACK_RPM_PACKAGE_OBSOLETES "rnp")

# bsd-specific
set(CPACK_FREEBSD_PACKAGE_MAINTAINER "${PACKAGING_EMAIL}")
set(CPACK_FREEBSD_PACKAGE_ORIGIN "security/rnp")
set(CPACK_FREEBSD_PACKAGE_CATEGORIES security)
set(CPACK_FREEBSD_PACKAGE_DEPS bzip2 json-c botan2)

include(CPack)

