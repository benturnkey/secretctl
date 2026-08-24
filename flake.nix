{
  description = "CLI for Turnkey Secret Storage";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in {
      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.buildGoModule {
            pname = "secretctl";
            version = "0.1.0";
            src = self;
            vendorHash = "sha256-NMVFHzWd04Dpv5R5Kehsi/9sutCRtv3+Zz6Rw2ysDiA=";
            subPackages = [ "cmd/secretctl" ];
          };
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/secretctl";
          meta.description = "Create and list secrets in Turnkey Secret Storage";
        };
      });

      checks = forAllSystems (system: {
        default = self.packages.${system}.default;
      });

      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go_1_25
              golangci-lint
              gopls
              gotools
            ];
          };
        });
    };
}
