{ pkgs }:

let
  # Compile C depedencies with clang, frame pointer, and debug info.
  overrideAttrs = previousAttrs: {
    inherit (pkgs.llvmPackages_14) stdenv;
    env = (previousAttrs.env or { }) // {
      NIX_CFLAGS_COMPILE = builtins.toString [
        "-g"
        "-O2"
        "-Werror"
        "-Wall"
        "-fpic"
        "-fno-omit-frame-pointer"
        "-mno-omit-leaf-frame-pointer"
      ];
    };
    dontStip = true;
  };
in
{
  elfutils = pkgs.elfutils.overrideAttrs overrideAttrs;
  libbpf = pkgs.libbpf.overrideAttrs overrideAttrs;
  zlib = pkgs.zlib.overrideAttrs overrideAttrs;
}
