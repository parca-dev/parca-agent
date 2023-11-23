#!/usr/bin/env bash
# Copyright 2022-2024 The Parca Authors
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

set -o errexit
set -o pipefail

# TODO: host the kernels ourselves to not use cilium's quotas
download_kernel() {
    kernel_version=$1
    echo "downloading kernel $kernel_version"
    curl -o "kerneltest/kernels/linux-$kernel_version.bz" -s -L -O --fail "https://github.com/cilium/ci-kernels/raw/3cd722e7e9e665b4784f0964b203dbef898bd693/linux-$kernel_version.bz"
}

use_kernel() {
    kernel_version=$1
    if [ ! -f "kerneltest/kernels/linux-$kernel_version.bz" ]; then
        echo "kernel $kernel_version not found"
        download_kernel "$kernel_version"
    fi
}

github_start() {
    kernel_version=$1
    arch=$2
    [[ -z "${GITHUB_ACTIONS}" ]] || echo "::group:: running tests on kernel $kernel_version arch: $arch"
}

github_end() {
    kernel_version=$1
    arch=$2
    [[ -z "${GITHUB_ACTIONS}" ]] || echo "::endgroup:: finished test on kernel $kernel_version arch: $arch"
}

test_info() {
    kernel_version=$1
    arch=$2
    cat <<EOT >"kerneltest/logs/vm_log_$kernel_version_$arch.txt"
============================================================
- date: $(date)
- git revision: $(git rev-parse HEAD)-$(git diff-index --quiet HEAD || echo dirty)
- vm kernel: $kernel_version
- qemu version: $(qemu-system-x86_64 --version | head -1)
============================================================
EOT
}

vm_run() {
    kernel_version=$1
    memory=$2
    arch=$3
    echo "running tests in qemu"
    github_start "$kernel_version" "$arch"
    test_info "$kernel_version" "$arch"
    # kernel.panic=-1 and -no-reboot ensures we won't get stuck on kernel panic.
    qemu-system-x86_64 -no-reboot -append 'printk.devkmsg=on kernel.panic=-1 crashkernel=256M' \
        -nographic -append "console=ttyS0" -m "$memory" -kernel "kerneltest/kernels/linux-$kernel_version.bz" \
        -initrd kerneltest/amd64/amd64-initramfs.cpio | tee -a "kerneltest/logs/vm_log_$kernel_version.txt"
    github_end "$kernel_version" "$arch"
}

vm_run_arm() {
    kernel_version=$1
    memory=$2
    arch=$3
    echo "running tests in qemu"
    github_start "$kernel_version" "$arch"
    test_info "$kernel_version" "$arch"
    # kernel.panic=-1 and -no-reboot ensures we won't get stuck on kernel panic.
    qemu-system-aarch64 -machine virt -cpu cortex-a57 -no-reboot -append 'printk.devkmsg=on kernel.panic=-1 crashkernel=256M' \
        -nographic -append "console=ttyS0" -m "$memory" -kernel "kerneltest/kernels/linux-$kernel_version.bz" \
        -initrd kerneltest/arm64/arm64-initramfs.cpio | tee -a "kerneltest/logs/vm_log_$kernel_version.txt"
    github_end "$kernel_version" "$arch"
}

did_test_pass() {
    kernel_version=$1
    grep PASS "kerneltest/logs/vm_log_$kernel_version.txt" >/dev/null
}

check_executable() {
    executable=$1
    if ! command -v "$executable" &>/dev/null; then
        echo "$executable could not be found"
        exit 1
    fi
}

run_tests() {
    # Initial checks.
    check_executable "curl"
    check_executable "qemu-system-x86_64"
    check_executable "qemu-system-aarch64"

    # Run the tests.
    kernel_versions=("5.4" "5.10" "5.19" "6.1")

    for kernel in "${kernel_versions[@]}"; do
        use_kernel "$kernel"
        # Ensure that the adaptive unwind shard mechanism
        # works in memory constrained environments.
        if [[ "$kernel" == "5.4" ]]; then
            vm_run "$kernel" "0.7G" "x86"
            vm_run_arm "$kernel" "0.7G" "aarch64"
        else
            vm_run "$kernel" "1.5G" "x86"
            vm_run_arm  "$kernel" "1.5G" "aarch64"
        fi
    done

    failed_tests=0
    passed_test=0
    echo "============="
    echo "Test results:"
    echo "============="
    for kernel in "${kernel_versions[@]}"; do
        if did_test_pass "$kernel"; then
            echo "- ✅ $kernel"
            passed_test=$((passed_test + 1))
        else
            echo "- ❌ $kernel"
            failed_tests=$((failed_tests + 1))
        fi
    done

    echo
    echo "Test summary: $passed_test passed, $failed_tests failed"

    if [ "$failed_tests" -gt 0 ]; then
        echo "(See logs in kerneltest/logs/)"
        exit 1
    fi

    # BUG(<= 4.19): The verifier spotted the loop (back-edge) and it's not happy, we need to unroll it here.
    # It works in newer kernels thanks to BPF bounded loops (note this is different from the bpf_loop helper).
    #
    # use_kernel "4.19"
    # run_tests "4.19" "1.5G"
    # did_test_pass "4.19"
}

run_tests
