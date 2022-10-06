{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell rec {
  name = "parca-agent";

  packages = with pkgs; [
    clang_11
    elfutils.dev
    gnumake
    go_1_18
    kubectl
    llvmPackages_11.llvm
    minikube
    pkg-config
    zlib.static
  ] ++ (lib.optional stdenv.isLinux [ glibc.static ]);

  shellHook = ''
    export PATH="''${PROJECT_ROOT}/bin:''${PATH}"
  '';

  PROJECT_ROOT = builtins.toString ./.;
  GOBIN = "${PROJECT_ROOT}/bin";
}
