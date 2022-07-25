{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell rec {
  name = "parca-agent";

  packages = with pkgs; [
    clang_14
    elfutils.dev
    gnumake
    go_1_18
    kubectl
    libxml2.dev
    llvmPackages_14.llvm
    minikube
    pkg-config
    rustup
    zlib.static
  ] ++ (lib.optional stdenv.isLinux [ glibc.dev glibc.static ]);

  shellHook = ''
    export PATH="''${PROJECT_ROOT}/bin:''${CARGO_HOME}/bin:''${PATH}"
    rustup show >/dev/null
  '';

  PROJECT_ROOT = builtins.toString ./.;
  CARGO_HOME = "${PROJECT_ROOT}/tmp/cargo";
  GOBIN = "${PROJECT_ROOT}/bin";
  RUSTUP_HOME = "${PROJECT_ROOT}/tmp/rustup";
  RUST_BACKTRACE = 1;

  # we need to do this as we're using an external LLVM. See: https://github.com/aya-rs/bpf-linker#using-external-llvm
  # TODO(vadorovsky): Remove the LLVM_SYS_140_PREFIX variable once
  # https://gitlab.com/taricorp/llvm-sys.rs/-/merge_requests/22 is merged.
  LLVM_SYS_140_PREFIX = "${pkgs.llvmPackages_14.llvm.dev}";
}

