{ lib, buildGoModule, fetchFromGitHub }:

{
  bluebox = buildGoModule rec {
    pname = "bluebox";
    version = "0.0.1";

    src = fetchFromGitHub {
      owner = "florianl";
      repo = pname;
      rev = "v${version}";
      sha256 = "sha256-h7NhJ/V0FaMX7F6OG+FJB4h3nSXUE/4ZYeUwoBZo0C0=";
    };

    vendorHash = "sha256-dSYu5Sb6hBTnNE4PXHQK6oGQasCrSu4l7KqhYJxTNDQ=";

    CGO_ENABLED = 0;

    ldflags = [ "-X main.version=${version}" ];

    meta = with lib; {
      description = "bluebox is intended to fast build a low overhead environment to be able to run tests against Linux kernel APIs like netlink or ebpf";
      homepage = "https://github.com/florianl/bluebox";
      license = licenses.mit;
    };
  };

  embedmd = buildGoModule rec {
    pname = "embedmd";
    # v2 is actually broken, import from main points to v1
    version = "1.0.0";

    src = fetchFromGitHub {
      owner = "campoy";
      repo = pname;
      rev = "v${version}";
      sha256 = "sha256-hfMI2d3iRe74nUQ9ydgXUshStk9LFWXkJL1/7ZsEX6g=";
    };

    vendorHash = "sha256-uLhXMwnSHFUUiQlpDw/U6fZvNsRuB4cZhxX4qUtdknA=";

    CGO_ENABLED = 0;

    ldflags = [ "-X main.version=${version}" ];

    # Patches may be a cleaner choice, but substituteInPlace keeps things self-contained
    preCheck = ''
      # Replace embedmd excetable path
      substituteInPlace ./integration_test.go \
        --replace embedmd "$GOPATH/bin/embedmd"

      # Fix expected error message in TestProcess/embedding_code_from_a_bad_URL
      substituteInPlace ./embedmd/embedmd_test.go \
        --replace 'parse https://fakeurl.com\\main.go:' 'parse \"https://fakeurl.com\\\\main.go\":'

      # Replace HTTP URLs, tests run offline.
      substituteInPlace ./sample/docs.md ./sample/result.md \
        --replace 'https://raw.githubusercontent.com/campoy/embedmd/master/sample/' './'
    '';

    meta = with lib; {
      description = "embed code into markdown and keep everything in sync";
      homepage = "https://github.com/campoy/embedmd";
      license = licenses.asl20;
    };
  };
}
