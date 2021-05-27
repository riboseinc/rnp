#!/bin/sh
set -ex

. ci/utils.inc.sh

macos_install() {
  brew update-reset
  # homebrew fails because `openssl` is a symlink while it tries to remove a directory.
  rm /usr/local/Cellar/openssl || true
  # homebrew fails to update python 3.9.1 to 3.9.1.1 due to unlinking failure
  rm /usr/local/bin/2to3 || true
  brew bundle
}

freebsd_install() {
  packages="
    git
    readline
    bash
    gnupg
    devel/pkgconf
    wget
    cmake
    gmake
    autoconf
    automake
    libtool
    gettext-tools
    python
    ruby26
"
  # Note: we assume sudo is already installed
  sudo pkg install -y ${packages}

  cd /usr/ports/devel/ruby-gems
  sudo make -DBATCH RUBY_VER=2.5 install
  cd

  mkdir -p ~/.gnupg
  echo "disable-ipv6" >> ~/.gnupg/dirmngr.conf
  dirmngr </dev/null
  dirmngr --daemon
}

openbsd_install() {
  echo ""
}

netbsd_install() {
  echo ""
}

linux_install_centos() {
  sudo yum -y update
  sudo yum -y -q install epel-release centos-release-scl
  sudo rpm --import https://github.com/riboseinc/yum/raw/master/ribose-packages.pub
  sudo curl -L https://github.com/riboseinc/yum/raw/master/ribose.repo -o /etc/yum.repos.d/ribose.repo
  sudo yum -y -q install sudo wget git cmake3 gcc gcc-c++ make autoconf automake libtool bzip2 gzip \
    ncurses-devel which rh-ruby25 rh-ruby25-ruby-devel bzip2-devel zlib-devel byacc gettext-devel \
    bison ribose-automake116 llvm-toolset-7.0 python3
}

linux_install_ubuntu() {
  sudo apt-get update
  sudo apt-get -y install ruby-dev g++-8 cmake libbz2-dev zlib1g-dev build-essential gettext \
    ruby-bundler libncurses-dev
}

linux_install_debian() {
  build_and_install_automake
  build_and_install_cmake
}

linux_install() {
  local dist=$(get_linux_dist)
  type "linux_install_$dist" | grep -qwi 'function' && "linux_install_$dist"
  true
}

msys_install() {
  packages="
    tar
    zlib-devel
    libbz2-devel
    git
    automake
    autoconf
    libtool
    automake-wrapper
    gnupg2
    make
    pkg-config
    mingw64/mingw-w64-x86_64-cmake
    mingw64/mingw-w64-x86_64-gcc
    mingw64/mingw-w64-x86_64-json-c
    mingw64/mingw-w64-x86_64-python3
  "
  pacman --noconfirm -S --needed ${packages}
  # any version starting with 2.14 up to 2.17.3 caused the application to hang
  # as described in https://github.com/randombit/botan/issues/2582
  # fixed with https://github.com/msys2/MINGW-packages/pull/7640/files
  botan_pkg="mingw-w64-x86_64-libbotan-2.17.3-2-any.pkg.tar.zst"
  pacman --noconfirm -U https://repo.msys2.org/mingw/x86_64/${botan_pkg} || \
  pacman --noconfirm -U https://sourceforge.net/projects/msys2/files/REPOS/MINGW/x86_64/${botan_pkg}

  # msys includes ruby 2.6.1 while we need lower version
  #wget http://repo.msys2.org/mingw/x86_64/mingw-w64-x86_64-ruby-2.5.3-1-any.pkg.tar.xz -O /tmp/ruby-2.5.3.pkg.tar.xz
  #pacman --noconfirm --needed -U /tmp/ruby-2.5.3.pkg.tar.xz
  #rm /tmp/ruby-2.5.3.pkg.tar.xz
}

"$(get_os)_install"
