{ pkgs
, version
, commit
, date
, static ? true
}:

let
  inherit (pkgs) lib pkgsBuildHost pkgsHostTarget;
  bpf = pkgsHostTarget.callPackage ./bpf.nix { };
  libraries = import ./libraries.nix { pkgs = pkgsHostTarget; };
in
(pkgsHostTarget.buildGo120Module.override {
  inherit (pkgsHostTarget.llvmPackages_14) stdenv;
}) rec {
  name = "parca-agent";

  src = builtins.path {
    name = "${name}-src";
    # Minimize rebuilds by whitelisting required files only.
    # Note: any file that is not tracked by Git is invisible to Nix flake,
    # thus .gitignore files are respected too.
    path = pkgsBuildHost.nix-gitignore.gitignoreSourcePure [
      # Blacklist everything
      "*"
      # Whitelist directories
      "!/cmd/"
      "!/internal/"
      "!/pkg/"
      "!/vendor/"
      # Whitelist go mod
      "!/go.mod"
      "!/go.sum"
      # Blacklist tests
      "**/*_test.go"
      "testdata"
    ] ../.;
  };
  vendorSha256 = null;

  nativeBuildInputs = with pkgsBuildHost; [
    nukeReferences
  ];

  buildInputs = with libraries; [
    elfutils.dev
    libraries.libbpf
  ] ++ (if static then [
    zlib.static
    pkgsHostTarget.glibc.static
  ] else [
    zlib.dev
    pkgsHostTarget.glibc.dev
  ]);

  env.CGO_LDFLAGS = "-lbpf";

  ldflags = [
    "-X"
    "main.version=${version}"
    "-X"
    "main.commit=${commit}"
    "-X"
    "main.date=${date}"
    "-X"
    "main.goArch=${pkgsHostTarget.go.GOARCH}"
  ] ++ (lib.optional static [ "-extldflags=-static" ]);

  tags = [ "osusergo" "netgo" ];

  subPackages = "cmd/parca-agent";

  preBuild = ''
    export GOFLAGS="$GOFLAGS -v"

    cp -f ${bpf}/cpu.bpf.o ./pkg/profiler/cpu/cpu-profiler.bpf.o
  '';

  # Nuke any references to other Nix store paths
  # https://github.com/NixOS/nixpkgs/blob/master/pkgs/build-support/nuke-references/default.nix#L1-L4
  postBuild = lib.optionalString static ''
    nuke-refs "$GOPATH/bin/parca-agent"
  '';

  # Not necessary and/or desired (e.g. strip, patchelf...)
  # https://nixos.org/manual/nixpkgs/stable/#ssec-fixup-phase
  dontFixup = static;
  dontStrip = true;

  # Do not run Go tests
  doCheck = false;
}
