{ pkgs }:

let
  inherit (pkgs) pkgsBuildHost pkgsHostTarget;
  libraries = import ./libraries.nix { pkgs = pkgsHostTarget; };
  toBpfArch = platform: {
    "x86_64" = "x86";
    "aarch64" = "arm64";
  }.${platform.parsed.cpu.name} or (throw "Unsupported CPU ${platform.parsed.cpu.name}");
in
pkgsHostTarget.stdenvNoCC.mkDerivation rec {
  name = "parca-agent-bpf";

  src = builtins.path {
    name = "${name}-src";
    # Minimize rebuilds by whitelisting required files only.
    # Note: any file that is not tracked by Git is invisible to Nix flake,
    # thus .gitignore files are respected too.
    path = pkgsBuildHost.nix-gitignore.gitignoreSourcePure [
      # Blacklist everything
      "*"
      # Whitelist directories
      "!/cpu/"
      # Blacklist directories content
      "/cpu/*"
      # Whitelist source code
      "!**/*.c"
      "!**/*.h"
      "!/Makefile"
    ] ../bpf;
  };

  nativeBuildInputs = with pkgsBuildHost.llvmPackages_14; [
    clang-unwrapped
    llvm
    pkgsBuildHost.nukeReferences
  ];

  buildInputs = [ libraries.libbpf ];

  makeFlags = [
    "OUT_DIR=./dist"
    "OUT_BPF=./dist/cpu.bpf.o"
    "LIBBPF_HEADERS=${libraries.libbpf}/include"
    "LINUX_ARCH=${toBpfArch pkgsHostTarget.hostPlatform}"
  ];

  buildPhase = ''
    runHook preBuild
    mkdir -p ./dist
    make $makeFlags
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out

    # Only for the sake of correctness
    nuke-refs ./dist/cpu.bpf.o

    mv ./dist/cpu.bpf.o $out

    runHook postInstall
  '';

  # Not necessary (e.g. strip, patchelf...)
  # https://nixos.org/manual/nixpkgs/stable/#ssec-fixup-phase
  dontFixup = true;
}
