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

        version = "2.0.0";

        targets = {
          x86_64-linux = {
            target = "x86_64-unknown-linux-musl";
            hash = "sha256-mPP1+POMhOwRUSqF0wamSVMWGAdvwsw99s56+B++6U8=";
          };
          aarch64-linux = {
            target = "aarch64-unknown-linux-musl";
            hash = "sha256-3NuDHL0mLtOnPgrdfu0YADGMUuNGNts765ZWqzQ8nLQ=";
          };
          aarch64-darwin = {
            target = "aarch64-apple-darwin";
            hash = "sha256-XBK0V8ZvjYT1nSW9Wvg5pGGiFmDMZK1xJ/bnVoWLg5k=";
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
            tar -xf "$src" --strip-components=1
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
