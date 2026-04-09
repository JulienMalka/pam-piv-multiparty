# piv-multiparty

`piv-multiparty` is a Linux PAM module that gates an account on the cryptographic approval of **multiple distinct PIV smartcards** (e.g. YubiKeys).
The original use case is multi-party access to sensitive systems: a sudo or a release-key operation that needs two different humans, each tapping their own card, before it proceeds.

The project main advantage over using `pam_u2f` module is that to avoid tracking of physical devices, there is no way to answer two distinct FIDO credentials belong to two distinct physical devices.

## 🔧 How to build

```bash
nix build
```
## ⚙ Usage on NixOS

Add the flake input, then enable the module on whichever PAM services should require multi-party approval.

```nix
{
  imports = [ inputs.piv-multiparty.nixosModules.default ];

  security.pam.multiparty = {
    enable = true;
    groupOrder = [ "A" "B" ];
    entries = {
      alice = [
        { group = "A"; spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+ONSB1e7..."; }  # card A
        { group = "B"; spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsgPtxSI9..."; }  # card B
      ];
    };
  };

  security.pam.services.sudo.multipartyAuth = true;
  security.pam.services.login.multipartyAuth = true;
}
```

That config requires alice to present **two distinct cards** (one bound to group A, one to group B) on every `sudo` or `login`, *in addition* to her unix password. Each card prompts for its own PIN; a successful auth emits an audit line per group to `LOG_AUTH`.

### Enrolment

The package ships an enrolment helper (`bin/piv-multiparty-enroll`) that provisions a card, generates the slot-9a key on-device, and prints the SPKI. With the package installed it's on `PATH`; otherwise run `scripts/enroll.sh` from the repo.

```bash
piv-multiparty-enroll -u alice -g A
```

Copy the printed entry into your NixOS config and `nixos-rebuild switch`.


