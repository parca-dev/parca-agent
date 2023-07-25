#!/usr/bin/env bash

# Copyright (c) 2022 The rbperf authors
#
# TODO: This license is not consistent with the license used in the project.
#       Delete the inconsistent license and above line and rerun pre-commit to insert a good license.
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# Copyright 2023 The Parca Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit nounset pipefail

NPROC=$(nproc --all)
ELFUTILS_VERSION="0.189"
ELFUTILS_SHA_512="93a877e34db93e5498581d0ab2d702b08c0d87e4cafd9cec9d6636dfa85a168095c305c11583a5b0fb79374dd93bc8d0e9ce6016e6c172764bcea12861605b71"

ZLIB_VERSION="1.2.13"
ZLIB_SHA256="b3a24de97a8fdbc835b9833169501030b8977031bcb54b3b3ac13740f846ab30"

ZSTD_VERSION="1.5.5"
ZSTD_SHA256="9c4396cc829cfae319a6e2615202e82aad41372073482fce286fac78646d3ee4"

run() {
    "$@" >/dev/null 2>&1
}

STATIC_LIBS_SRC_PATH=${PWD}/dist/static-libs/src
mkdir -p "${STATIC_LIBS_SRC_PATH}"/libz
mkdir -p "${STATIC_LIBS_SRC_PATH}"/elfutils

ARCH=$(go env GOARCH)
STATIC_LIBS_OUT_PATH="${PWD}/dist/static-libs/${ARCH}/"
mkdir -p "${STATIC_LIBS_OUT_PATH}"

run pushd "${STATIC_LIBS_SRC_PATH}"

# Notes:
# * -fpic is not the same as -FPIC
# https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html
#
# * cflags required for clang to compile elfutils
export CFLAGS="-fno-omit-frame-pointer -fpic -Wno-gnu-variable-sized-type-not-at-end -Wno-unused-but-set-parameter"
export CC=clang

echo "=> Building elfutils"
run curl -L -O "https://sourceware.org/pub/elfutils/${ELFUTILS_VERSION}/elfutils-${ELFUTILS_VERSION}.tar.bz2"
if ! sha512sum "elfutils-${ELFUTILS_VERSION}.tar.bz2" | grep -q "$ELFUTILS_SHA_512"; then
    echo "Checksum for elfutils doesn't match"
    exit 1
fi

run tar xjf "elfutils-${ELFUTILS_VERSION}.tar.bz2"

run pushd "elfutils-${ELFUTILS_VERSION}"
run ./configure --prefix="${STATIC_LIBS_SRC_PATH}/elfutils" --disable-debuginfod --disable-libdebuginfod
run make "-j${NPROC}"
run make install
cp "${STATIC_LIBS_SRC_PATH}/elfutils/lib/libelf.a" "${STATIC_LIBS_OUT_PATH}"
run popd

echo "=> Building zlib"
run curl -L -O "https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz"
if ! sha256sum "zlib-${ZLIB_VERSION}.tar.gz" | grep -q "$ZLIB_SHA256"; then
    echo "Checksum for zlib doesn't match"
    exit 1
fi
run tar xzf zlib-${ZLIB_VERSION}.tar.gz

run pushd "zlib-${ZLIB_VERSION}"
run ./configure --prefix="${STATIC_LIBS_SRC_PATH}/libz" >/dev/null
run make "-j${NPROC}" >/dev/null
run make install >/dev/null
cp "${STATIC_LIBS_SRC_PATH}/libz/lib/libz.a" "${STATIC_LIBS_OUT_PATH}"
run popd

echo "=> Building zstd"
run curl -L -O "https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz"
if ! sha256sum "zstd-${ZSTD_VERSION}.tar.gz" | grep -q "$ZSTD_SHA256"; then
    echo "Checksum for zstd doesn't match"
    exit 1
fi
run tar xzf zstd-${ZSTD_VERSION}.tar.gz

run pushd "zstd-${ZSTD_VERSION}"
run make "-j${NPROC}" >/dev/null
run make install PREFIX="${STATIC_LIBS_SRC_PATH}/zstd" >/dev/null
cp "${STATIC_LIBS_SRC_PATH}/zstd/lib/libzstd.a" "${STATIC_LIBS_OUT_PATH}"
run popd

run popd
