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

DEBUG="${DEBUG:-}"
if [ -n "${DEBUG:-}" ]; then
    # Enable for debugging:
    set -x
fi

CC="${CC:-zig cc}"
CXX="${CXX:zig c++}"
ARCH="${ARCH:-amd64}"

NPROC=$(nproc --all)
ELFUTILS_VERSION="0.189"
ELFUTILS_SHA_512="93a877e34db93e5498581d0ab2d702b08c0d87e4cafd9cec9d6636dfa85a168095c305c11583a5b0fb79374dd93bc8d0e9ce6016e6c172764bcea12861605b71"

ZLIB_VERSION="1.3"
ZLIB_SHA256="ff0ba4c292013dbc27530b3a81e1f9a813cd39de01ca5e0f8bf355702efa593e"

ZSTD_VERSION="1.5.5"
ZSTD_SHA256="9c4396cc829cfae319a6e2615202e82aad41372073482fce286fac78646d3ee4"

LOGS_FILE="${PWD}/dist/static-libs/run-logs.txt"
run() {
    if [ -z "${DEBUG:-}" ]; then
        "$@" >/dev/null 2>&1
    else
        "$@" >"$LOGS_FILE" 2>&1
    fi
}

STATIC_LIBS_SRC_PATH=${PWD}/dist/static-libs/src
mkdir -p "${STATIC_LIBS_SRC_PATH}"
STATIC_LIBS_OUT_PATH="${PWD}/dist/static-libs/${ARCH}"
mkdir -p "${STATIC_LIBS_OUT_PATH}"

# Notes:
# * -fpic is not the same as -FPIC
# https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html
#
# TODO(kakkoyun): Move library specific flags to their own build functions.
# * cflags required for clang to compile elfutils
export CFLAGS="-fno-omit-frame-pointer -fpic -Wno-gnu-variable-sized-type-not-at-end -Wno-unused-but-set-parameter -Wno-unused-but-set-variable"

zlib_build() {
    build_artifact="${STATIC_LIBS_OUT_PATH}/libz-${ZLIB_VERSION}/lib/libz.a"

    if [ -f "${build_artifact}" ]; then
        echo "Already built"
        cp "${build_artifact}" "${STATIC_LIBS_OUT_PATH}"
        return
    fi

    zlib="zlib-${ZLIB_VERSION}.tar.gz"
    test -f "$zlib" || run curl -L -O "https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz"
    if ! sha256sum "$zlib" | grep -q "$ZLIB_SHA256"; then
        echo "Checksum for zlib doesn't match"
        exit 1
    fi
    run tar xzf "$zlib"

    mkdir -p "${STATIC_LIBS_OUT_PATH}/libz-${ZLIB_VERSION}"
    run pushd "zlib-${ZLIB_VERSION}"
    run ./configure --prefix="${STATIC_LIBS_OUT_PATH}/libz-${ZLIB_VERSION}"
    run make "-j${NPROC}"
    run make install
    cp "${build_artifact}" "${STATIC_LIBS_OUT_PATH}"
    run popd
}

zstd_build() {
    build_artifact="${STATIC_LIBS_OUT_PATH}/zstd-${ZSTD_VERSION}/lib/libzstd.a"

    if [ -f "${build_artifact}" ]; then
        echo "Already built"
        cp "${build_artifact}" "${STATIC_LIBS_OUT_PATH}"
        return
    fi

    zstd="zstd-${ZSTD_VERSION}.tar.gz"
    test -f "$zstd" || run curl -L -O "https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz"
    if ! sha256sum "$zstd" | grep -q "$ZSTD_SHA256"; then
        echo "Checksum for zstd doesn't match"
        exit 1
    fi
    run tar xzf "$zstd"

    mkdir -p "${STATIC_LIBS_OUT_PATH}/zstd-${ZSTD_VERSION}"
    run pushd "zstd-${ZSTD_VERSION}"
    run make "-j${NPROC}"
    run make install PREFIX="${STATIC_LIBS_OUT_PATH}/zstd-${ZSTD_VERSION}"
    cp "${build_artifact}" "${STATIC_LIBS_OUT_PATH}"
    run popd
}

elf_build() {
    export CFLAGS="${CFLAGS} -I${STATIC_LIBS_OUT_PATH}/libz-${ZLIB_VERSION}/include -I${STATIC_LIBS_OUT_PATH}/zstd-${ZSTD_VERSION}/include"
    export LDFLAGS="${LDFLAGS} -L${STATIC_LIBS_OUT_PATH}"

    build_artifact="${STATIC_LIBS_OUT_PATH}/elfutils-${ELFUTILS_VERSION}/lib/libelf.a"

    if [ -f "${build_artifact}" ]; then
        echo "Already built"
        cp "${build_artifact}" "${STATIC_LIBS_OUT_PATH}"
        return
    fi

    elfutils="elfutils-${ELFUTILS_VERSION}.tar.bz2"
    test -f "$elfutils" || run curl -L -O "https://sourceware.org/pub/elfutils/${ELFUTILS_VERSION}/elfutils-${ELFUTILS_VERSION}.tar.bz2"
    if ! sha512sum "$elfutils" | grep -q "$ELFUTILS_SHA_512"; then
        echo "Checksum for elfutils doesn't match"
        exit 1
    fi
    run tar xjf "$elfutils"

    run pushd "elfutils-${ELFUTILS_VERSION}"

    export BUILD_STATIC=1
    run ./configure --prefix="${STATIC_LIBS_OUT_PATH}/elfutils-${ELFUTILS_VERSION}" --target="$TARGET" --build="$BUILD" --host="$HOST" --disable-debuginfod --disable-libdebuginfod --without-bzlib --without-lzma

    run make -C lib "-j${NPROC}"
    run make -C libelf install "-j${NPROC}"

    cp "${build_artifact}" "${STATIC_LIBS_OUT_PATH}"
    run popd
}

echo "=> Downloading and building static libraries for ${ARCH}"
run pushd "${STATIC_LIBS_SRC_PATH}"

echo "=> Building zlib"
zlib_build

echo "=> Building zstd"
zstd_build

echo "=> Building elfutils"
elf_build

run popd
