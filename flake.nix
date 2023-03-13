{
  description = "eBPF based always-on profiler auto-discovering targets in Kubernetes and systemd, zero code changes or restarts needed!";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;

      version = lib.fileContents ./VERSION + (if builtins.hasAttr "shortRev" self then "" else "-dirty");
      commit = self.rev or "dirty";
      date = self.lastModifiedDate;

      pkgs-x86_64-linux = { pkgs = nixpkgs.legacyPackages.x86_64-linux; };
      pkgs-aarch64-linux = { pkgs = nixpkgs.legacyPackages.aarch64-linux; };
      pkgs-x86_64-linux-X-aarch64-linux = { pkgs = import nixpkgs { localSystem = "x86_64-linux"; crossSystem = "aarch64-linux"; }; };
      pkgs-aarch64-linux-X-x86_64-linux = { pkgs = import nixpkgs { localSystem = "aarch64-linux"; crossSystem = "x86_64-linux"; }; };

      devShell = { pkgs }: import ./nix/devshell.nix { inherit pkgs; };

      bpf = { pkgs }: import ./nix/bpf.nix { inherit pkgs; };
      dockerImage = { pkgs, debug ? false }: import ./nix/docker.nix { inherit pkgs version commit date debug; };
      parcaAgent = { pkgs, static ? true }: import ./nix/build.nix { inherit pkgs version commit date static; };
    in
    {
      devShells.aarch64-linux.default = devShell pkgs-aarch64-linux;
      devShells.x86_64-linux.default = devShell pkgs-x86_64-linux;

      packages.x86_64-linux.bpf = bpf pkgs-x86_64-linux;
      packages.x86_64-linux.bpf-aarch64-linux = bpf pkgs-x86_64-linux-X-aarch64-linux;
      packages.x86_64-linux.default = self.packages."x86_64-linux".parca-agent;
      packages.x86_64-linux.docker-image = dockerImage pkgs-x86_64-linux;
      packages.x86_64-linux.docker-image-debug = dockerImage pkgs-x86_64-linux // { debug = true; };
      packages.x86_64-linux.docker-image-aarch64-linux = dockerImage pkgs-x86_64-linux-X-aarch64-linux;
      packages.x86_64-linux.parca-agent = parcaAgent pkgs-x86_64-linux;
      packages.x86_64-linux.parca-agent-dyn = parcaAgent pkgs-x86_64-linux // { static = false; };
      packages.x86_64-linux.parca-agent-aarch64-linux = parcaAgent pkgs-x86_64-linux-X-aarch64-linux;

      packages.aarch64-linux.bpf = bpf pkgs-aarch64-linux;
      packages.aarch64-linux.bpf-x86_64-linux = bpf pkgs-aarch64-linux-X-x86_64-linux;
      packages.aarch64-linux.default = self.packages."aarch64-linux".parca-agent;
      packages.aarch64-linux.docker-image = dockerImage pkgs-aarch64-linux;
      packages.aarch64-linux.docker-image-debug = dockerImage pkgs-aarch64-linux // { debug = true; };
      packages.aarch64-linux.docker-image-x86_64-linux = dockerImage pkgs-aarch64-linux-X-x86_64-linux;
      packages.aarch64-linux.parca-agent = parcaAgent pkgs-aarch64-linux;
      packages.aarch64-linux.parca-agent-dyn = parcaAgent pkgs-aarch64-linux // { static = false; };
      packages.aarch64-linux.parca-agent-x86_64-linux = parcaAgent pkgs-aarch64-linux-X-x86_64-linux;
    };

  nixConfig = {
    extra-substituters = [
      "https://parca-agent.cachix.org"
    ];
    extra-trusted-public-keys = [
      "parca-agent.cachix.org-1:BmDSovovL+kILZoyXzsrF1ZIR1CD9m58q3kuJk3zBXo="
    ];
  };
}
