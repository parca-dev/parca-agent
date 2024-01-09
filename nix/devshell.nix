{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  name = "parca-agent-devshell";

  # clang-14: error: argument unused during compilation: '--gcc-toolchain=/nix/store/hf2gy3km07d5m0p1lwmja0rg9wlnmyr7-gcc-12.3.0' [-Werror,-Wunused-command-line-argument]
  env.NIX_CFLAGS_COMPILE = "-Wno-unused-command-line-argument";

  packages = with pkgs; [
    # Dependecy management:
    devbox
    direnv

    # Cluster and e2e testing:
    docker-machine-kvm2
    minikube
    tilt
    kubectl

    # Troubleshooting:
    bpftools
  ];
}
