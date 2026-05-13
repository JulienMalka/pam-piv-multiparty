{
  description = "PAM module enforcing multi-party PIV authentication using slot-9a SPKI as per-device identity";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-linux"
      ]
      (
        system:
        let
          lib = nixpkgs.lib;
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfreePredicate = pkg: builtins.elem (lib.getName pkg) [ "oracle-javacard-sdk" ];
          };
          piv-multiparty = pkgs.callPackage ./nix/package.nix { src = self; };
        in
        {
          packages = {
            inherit piv-multiparty;
            default = piv-multiparty;
          };

          devShells.default = pkgs.mkShell {
            inputsFrom = [ piv-multiparty ];
            packages =
              (with pkgs; [
                rustc
                cargo
                clippy
                rustfmt
                rust-analyzer
                pkg-config
              ])
              ++ [ piv-multiparty ];
          };

          formatter = pkgs.nixfmt-tree;

          checks = import ./nix/tests/default.nix {
            inherit pkgs lib;
            inherit (self) nixosModules;
          };
        }
      )
    // {
      nixosModules.default =
        args@{ pkgs, ... }:
        (import ./nix/module.nix {
          piv-multiparty = self.packages.${pkgs.system}.piv-multiparty;
        })
          args;
    };
}
