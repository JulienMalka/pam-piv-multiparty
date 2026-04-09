{
  description = "PAM module enforcing multi-party PIV authentication using slot-9a SPKI as per-device identity";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      system = "x86_64-linux";
      lib = nixpkgs.lib;
      pkgs = import nixpkgs {
        inherit system;
        config.allowUnfreePredicate = pkg: builtins.elem (lib.getName pkg) [ "oracle-javacard-sdk" ];
      };
      piv-multiparty = pkgs.callPackage ./nix/package.nix { src = self; };
    in
    {
      packages.${system} = {
        inherit piv-multiparty;
        default = piv-multiparty;
      };

      nixosModules.default = import ./nix/module.nix { inherit piv-multiparty; };

      devShells.${system}.default = pkgs.mkShell {
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

      formatter.${system} = pkgs.nixfmt-tree;

      checks.${system} = import ./nix/tests/default.nix {
        inherit pkgs lib;
        inherit (self) nixosModules;
      };
    };
}
