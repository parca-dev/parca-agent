{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell rec {
  name = "parca-agent";

  packages = with pkgs; [
    clang
    elfutils.dev
    gnumake
    go_1_18
    kubectl
    llvm
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
}

