{
  pkgs,
  lib,
  nixosModules,
}:

let
  testDeps = import ../test-deps { inherit pkgs; };
in
{
  e2e = pkgs.testers.runNixOSTest (
    import ./e2e.nix {
      inherit lib testDeps;
      multipartyModule = nixosModules.default;
    }
  );
}
