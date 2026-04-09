{ pkgs }:

let
  javacard-sdk = pkgs.callPackage ./javacard-sdk.nix { };
  jcardsim = pkgs.callPackage ./jcardsim.nix { inherit javacard-sdk; };
  pivapplet = pkgs.callPackage ./pivapplet.nix { inherit jcardsim; };
in
{
  inherit javacard-sdk jcardsim pivapplet;
}
