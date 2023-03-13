{ pkgs
, version
, commit
, date
, debug ? false
}:

let
  inherit (pkgs) lib pkgsHostTarget;
  parcaAgent = pkgsHostTarget.callPackage ./build.nix { inherit version commit date; };
in
pkgsHostTarget.dockerTools.buildLayeredImage {
  name = "ghcr.io/parca-dev/parca-agent";
  tag = "v${version}-${pkgsHostTarget.go.GOARCH}" + lib.optionalString debug "-debug";
  contents = [
    pkgsHostTarget.dockerTools.caCertificates
    (pkgsHostTarget.writeTextDir "bin/parca-agent.yaml" (builtins.readFile ../parca-agent.yaml))
    parcaAgent
  ] ++ lib.optional debug [ pkgsHostTarget.delve ];
  config = {
    Cmd = [ "/bin/parca-agent" ];
  } // (lib.optionalAttrs debug {
    Entrypoint = [
      "/bin/dlv"
      "--listen=:40000"
      "--headless=true"
      "--api-version=2"
      "--accept-multiclient"
      "exec"
      "--continue"
      "--"
    ];
  });
}
