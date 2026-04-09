{ piv-multiparty }:

{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.security.pam.multiparty;

  declarativeAuthfile = cfg.entries != { };

  # JSON Lines: one {"user","group","spki"} object per line.
  renderedAuthfile = lib.concatMapStrings (line: builtins.toJSON line + "\n") (
    lib.flatten (
      lib.mapAttrsToList (
        user: userEntries:
        map (e: {
          inherit user;
          inherit (e) group spki;
        }) userEntries
      ) cfg.entries
    )
  );

  authfileStore = pkgs.writeText "piv-multiparty.jsonl" renderedAuthfile;
  authfilePath =
    if declarativeAuthfile then "${authfileStore}" else "/var/lib/piv-multiparty/authfile";

  moduleArgs = [
    "authfile=${authfilePath}"
    "groups=${lib.concatStringsSep "," cfg.groupOrder}"
    "pkcs11_module=${cfg.pkcs11Module}"
  ]
  ++ lib.optional cfg.debug "debug";

  controlEnum = lib.types.enum [
    "required"
    "sufficient"
    "requisite"
    "optional"
  ];
in
{
  options = {
    security.pam.multiparty = {
      enable = lib.mkEnableOption "PIV-based multi-party authentication";

      groupOrder = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [
          "A"
          "B"
        ];
        description = ''
          Ordered list of group names every authenticating user must
          satisfy at login. Each user listed in `entries` must have at
          least one matching entry per group declared here.
        '';
      };

      entries = lib.mkOption {
        type = lib.types.attrsOf (
          lib.types.listOf (
            lib.types.submodule {
              options = {
                group = lib.mkOption {
                  type = lib.types.str;
                  description = "Group name; must appear in `groupOrder`.";
                };
                spki = lib.mkOption {
                  type = lib.types.str;
                  description = ''
                    Base64-encoded DER `SubjectPublicKeyInfo` of the
                    card's slot-9a public key. Obtain via
                    `scripts/enroll.sh` or:

                      openssl x509 -in slot9a.cert.pem -noout -pubkey \
                        | openssl pkey -pubin -outform DER | base64 -w0
                  '';
                };
              };
            }
          )
        );
        default = { };
        example = lib.literalExpression ''
          {
            alice = [
              { group = "A"; spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."; }
              { group = "B"; spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."; }
            ];
            bob = [
              { group = "A"; spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."; }
              { group = "B"; spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."; }
            ];
          }
        '';
        description = ''
          Authfile entries, keyed by unix username. Every user listed
          here must have at least one entry per group declared in
          `groupOrder`.
        '';
      };

      initialAuthfile = lib.mkOption {
        type = lib.types.lines;
        default = "";
        internal = true;
        visible = false;
      };

      pkcs11Module = lib.mkOption {
        type = lib.types.path;
        default = "${pkgs.opensc}/lib/opensc-pkcs11.so";
        defaultText = lib.literalExpression ''"''${pkgs.opensc}/lib/opensc-pkcs11.so"'';
        description = ''
          Path to the PKCS#11 module the PAM module loads at runtime to
          talk to PIV cards. Defaults to OpenSC, which is vendor-neutral
          and works against YubiKey, canokey, Nitrokey, Feitian, and any
          other PIV-compliant card. 
        '';
      };

      debug = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable verbose syslog logging from the PAM module.";
      };

      control = lib.mkOption {
        type = controlEnum;
        default = "required";
        description = ''
          Default PAM control flag for the multiparty rule on every PAM
          service that sets `multipartyAuth = true`. Override per-service
          via `security.pam.services.<svc>.multipartyControl`.
        '';
      };
    };

    security.pam.services = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule (
          { config, ... }:
          {
            options = {
              multipartyAuth = lib.mkOption {
                type = lib.types.bool;
                default = false;
                description = ''
                  Add a piv-multiparty `auth` rule to this PAM service.
                '';
              };

              multipartyControl = lib.mkOption {
                type = controlEnum;
                default = cfg.control;
                defaultText = lib.literalExpression "config.security.pam.multiparty.control";
                description = ''
                  PAM control flag for this service's multiparty rule.
                  Defaults to the global `security.pam.multiparty.control`.
                '';
              };
            };

            config = lib.mkIf (cfg.enable && config.multipartyAuth) {
              rules.auth.multiparty = {
                order = 10000;
                control = config.multipartyControl;
                modulePath = "${piv-multiparty}/lib/security/pam_piv_multiparty.so";
                args = moduleArgs;
              };
            };
          }
        )
      );
    };
  };

  config = lib.mkIf cfg.enable {
    assertions =
      let
        enabledServices = lib.filterAttrs (_: s: s.multipartyAuth) config.security.pam.services;
        bypassRisk = lib.filterAttrs (
          _: s: s.multipartyControl == "sufficient" && s.unixAuth
        ) enabledServices;
        deadlock = lib.filterAttrs (_: s: s.multipartyControl == "required" && !s.unixAuth) enabledServices;

        usersWithMissingGroups = lib.filterAttrs (
          _: userEntries:
          let
            userGroups = lib.unique (map (e: e.group) userEntries);
          in
          lib.subtractLists userGroups cfg.groupOrder != [ ]
        ) cfg.entries;
      in
      [
        {
          assertion = builtins.length cfg.groupOrder >= 1;
          message = "security.pam.multiparty.groupOrder must declare at least one group.";
        }
        {
          assertion = bypassRisk == { };
          message = ''
            piv-multiparty: the following PAM service(s) have
            `multipartyAuth = true` with `multipartyControl = "sufficient"`
            and `unixAuth = true`, which renders an OR auth stack — anyone
            with the unix password can bypass the multi-party check,
            defeating the module's threat model.

            Affected: ${lib.concatStringsSep ", " (lib.attrNames bypassRisk)}

            Pick one of the safe wirings:
              * AND     — multipartyControl = "required";   unixAuth = true;
              * REPLACE — multipartyControl = "sufficient"; unixAuth = false;
          '';
        }
        {
          assertion = deadlock == { };
          message = ''
            piv-multiparty: the following PAM service(s) have
            `multipartyAuth = true` with `multipartyControl = "required"`
            and `unixAuth = false`, which renders an unconditional failure:
            pam_deny is the only rule after multiparty and always rejects,
            so no one can log in.

            Affected: ${lib.concatStringsSep ", " (lib.attrNames deadlock)}

            Pick one of the safe wirings:
              * AND     — multipartyControl = "required";   unixAuth = true;
              * REPLACE — multipartyControl = "sufficient"; unixAuth = false;
          '';
        }
        {
          assertion = !(declarativeAuthfile && cfg.initialAuthfile != "");
          message = ''
            piv-multiparty: `entries` and `initialAuthfile` are mutually
            exclusive (and `initialAuthfile` is internal — set `entries`).
          '';
        }
        {
          assertion = usersWithMissingGroups == { };
          message = ''
            piv-multiparty: the following user(s) in `entries` are
            missing entries for some group in `groupOrder`. Each user
            must have at least one entry per declared group, otherwise
            their auth always fails at the missing group's stage:

            ${lib.concatStringsSep "\n" (
              lib.mapAttrsToList (
                user: userEntries:
                let
                  missing = lib.subtractLists (lib.unique (map (e: e.group) userEntries)) cfg.groupOrder;
                in
                "  ${user}: missing groups ${lib.concatStringsSep ", " missing}"
              ) usersWithMissingGroups
            )}
          '';
        }
      ];

    services.pcscd.enable = true;

    # Non declarative setup is used for the NixOS test
    systemd.tmpfiles.settings = lib.mkIf (!declarativeAuthfile) {
      "10-piv-multiparty" = {
        "/var/lib/piv-multiparty".d = {
          mode = "0755";
          user = "root";
          group = "root";
        };
        ${authfilePath}.C = {
          mode = "0644";
          user = "root";
          group = "root";
          argument = toString (pkgs.writeText "piv-multiparty-initial-authfile" cfg.initialAuthfile);
        };
      };
    };
  };
}
