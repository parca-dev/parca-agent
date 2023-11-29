{ pkgs }:

let
  goTools = pkgs.callPackage (import ./go-tools.nix) { };
in
(pkgs.mkShell.override {
  inherit (pkgs.llvmPackages_14) stdenv;
}) rec {
  name = "parca-agent-devshell";

  # clang-14: error: argument unused during compilation: '--gcc-toolchain=/nix/store/hf2gy3km07d5m0p1lwmja0rg9wlnmyr7-gcc-12.3.0' [-Werror,-Wunused-command-line-argument]
  env.NIX_CFLAGS_COMPILE = "-Wno-unused-command-line-argument";

  packages = with pkgs; [
    bpftools
    docker-machine-kvm2
    elfutils.dev
    glibc.dev
    glibc.static
    go-jsonnet
    goTools.bluebox
    goTools.embedmd
    go_1_21
    gofumpt
    gojsontoyaml
    (golangci-lint.override {
      buildGoModule = buildGo121Module;
    })
    jsonnet-bundler
    kubectl
    llvm_14
    minikube
    pkg-config
    pre-commit
    tilt
    zlib.static
    (zstd.override { static = true; }).dev
  ];
}
