{
  description = "eBPF based always-on profiler auto-discovering targets in Kubernetes and systemd, zero code changes or restarts needed!";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-compat = { url = "github:edolstra/flake-compat"; flake = false; };
  };

  outputs = { self, nixpkgs, ... }:
    let
      pkgs-x86_64-linux = { pkgs = nixpkgs.legacyPackages.x86_64-linux; };
      pkgs-aarch64-linux = { pkgs = nixpkgs.legacyPackages.aarch64-linux; };

      devShell = { pkgs }: import ./nix/devshell.nix { inherit pkgs; };
    in
    {
      devShells.aarch64-linux.default = devShell pkgs-aarch64-linux;
      devShells.x86_64-linux.default = devShell pkgs-x86_64-linux;
    };
}
