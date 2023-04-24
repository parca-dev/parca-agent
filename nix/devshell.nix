{ pkgs }:

let
  goTools = pkgs.callPackage (import ./go-tools.nix) { };
in
(pkgs.mkShell.override {
  inherit (pkgs.llvmPackages_14) stdenv;
}) rec {
  name = "parca-agent-devshell";

  packages = with pkgs; [
    bpftools
    docker-machine-kvm2
    elfutils.dev
    glibc.dev
    glibc.static
    go-jsonnet
    goTools.bluebox
    goTools.embedmd
    go_1_20
    gofumpt
    gojsontoyaml
    # Build with Go 1.20
    # https://github.com/golangci/golangci-lint/issues/3565
    (golangci-lint.override {
      buildGoModule = buildGo120Module;
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
