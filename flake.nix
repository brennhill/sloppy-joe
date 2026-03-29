{
  description = "Detect hallucinated, typosquatted, and non-canonical dependencies";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        version = "0.10.0";

        targets = {
          x86_64-linux = {
            target = "x86_64-unknown-linux-musl";
            hash = "sha256-Cct7XvQfo2WjoaDoqXWnq+JDcaOrohDzeWL09cuN9t0=";
          };
          aarch64-linux = {
            target = "aarch64-unknown-linux-musl";
            hash = "sha256-gLKzwabQrw+vP9FjHnBZTBCZsD5I3Is7syC3rmg3Gso=";
          };
          aarch64-darwin = {
            target = "aarch64-apple-darwin";
            hash = "sha256-Z16hQUijApc4tDPX6YFfcjHyyGNbpcmNbpvuYe42iI0=";
          };
        };

        targetInfo = targets.${system};

        src = pkgs.fetchurl {
          url = "https://github.com/brennhill/sloppy-joe/releases/download/v${version}/sloppy-joe-${targetInfo.target}.tar.xz";
          hash = targetInfo.hash;
        };
      in
      {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "sloppy-joe";
          inherit version;
          inherit src;

          nativeBuildInputs = [ pkgs.xz ];

          unpackPhase = ''
            tar xf $src
          '';

          installPhase = ''
            install -Dm755 sloppy-joe $out/bin/sloppy-joe
          '';

          meta = with pkgs.lib; {
            description = "Detect hallucinated, typosquatted, and non-canonical dependencies";
            homepage = "https://github.com/brennhill/sloppy-joe";
            license = licenses.asl20;
            platforms = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
            mainProgram = "sloppy-joe";
          };
        };

        devShells.default = pkgs.mkShell {
          packages = [ self.packages.${system}.default ];
        };
      }
    );
}
