{
  multipartyModule,
  testDeps,
  ...
}:

{
  name = "piv-multiparty-e2e";

  nodes.machine =
    { pkgs, ... }:
    let
      vpcd = pkgs.vsmartcard-vpcd;
      jcardsimJar = "${testDeps.jcardsim}/share/java/jcardsim.jar";
      pivAppletJar = "${testDeps.pivapplet}/share/java/pivapplet.jar";

      mkCfg =
        port:
        pkgs.writeText "jcardsim-${toString port}.cfg" ''
          com.licel.jcardsim.card.applet.0.AID=A000000308000010000100
          com.licel.jcardsim.card.applet.0.Class=net.cooperi.pivapplet.PivApplet
          com.licel.jcardsim.card.ATR=3B8880015069764170706C741F
          com.licel.jcardsim.vsmartcard.host=127.0.0.1
          com.licel.jcardsim.vsmartcard.port=${toString port}
        '';

      mkJcardsimUnit = name: port: {
        description = "jcardsim PIV applet (vpcd slot on port ${toString port})";
        after = [
          "pcscd.service"
          "pcscd.socket"
        ];
        wants = [ "pcscd.service" ];
        serviceConfig = {
          ExecStart = "${pkgs.jdk8}/bin/java -noverify -cp ${jcardsimJar}:${pivAppletJar} com.licel.jcardsim.remote.VSmartCard ${mkCfg port}";
          Restart = "on-failure";
          RestartSec = 2;
          StandardOutput = "journal";
          StandardError = "journal";
        };
        wantedBy = [ "multi-user.target" ];
      };
    in
    {
      imports = [ multipartyModule ];

      services.pcscd = {
        enable = true;
        plugins = [ vpcd ];
        readerConfigs = [ (builtins.readFile "${vpcd}/etc/reader.conf.d/vpcd") ];
      };

      systemd.services.jcardsim-A = mkJcardsimUnit "A" 35963;
      systemd.services.jcardsim-B = mkJcardsimUnit "B" 35964;

      security.pam.multiparty = {
        enable = true;
        groups = [
          "A"
          "B"
        ];
        control = "sufficient";
      };

      security.pam.services.login = {
        multipartyAuth = true;
        unixAuth = false;
      };

      users.users.alice = {
        isNormalUser = true;
        uid = 1000;
      };

      environment.systemPackages = with pkgs; [
        opensc
        pcsclite
        pcsc-tools
        pamtester
        yubico-piv-tool
        openssl
        jq
      ];
    };

  testScript = ''
    import time

    INSTALL_PIV_APPLET_APDU = (
        "80 b8 00 00 12 0b "
        "a0 00 00 03 08 00 00 10 00 01 00 "
        "05 00 00 02 0F 0F"
    )

    # PivApplet ships with these PIV factory defaults on a fresh card.
    PIN = "123456"
    WRONG_PIN = "654321"


    class PivCard:
        """A jcardsim-backed virtual PIV card."""

        def __init__(self, label, reader, unit):
            self.label = label    # display label, e.g. "A"
            self.reader = reader  # pcsc reader name, e.g. "Virtual PCD 00 00"
            self.unit = unit      # systemd unit name (no .service suffix)

        def install_applet(self):
            machine.succeed(
                f"opensc-tool -r '{self.reader}' -s '{INSTALL_PIV_APPLET_APDU}' 2>&1"
            )

        def provision_and_enrol(self, user, group):
            """Generate slot-9a on-card, selfsign, import the cert, then
            append the SPKI authfile entry."""
            machine.succeed(f"""set -eo pipefail
                yubico-piv-tool -r '{self.reader}' -a generate -s 9a -A ECCP256 \
                    > /tmp/9a-{group}.pub.pem
                yubico-piv-tool -r '{self.reader}' -P {PIN} \
                    -a verify-pin -a selfsign-certificate \
                    -s 9a -S '/CN={user}/' --valid-days 3650 \
                    < /tmp/9a-{group}.pub.pem > /tmp/9a-{group}.cert.pem
                yubico-piv-tool -r '{self.reader}' -a import-certificate -s 9a \
                    < /tmp/9a-{group}.cert.pem
                spki=$(openssl x509 -in /tmp/9a-{group}.cert.pem -noout -pubkey \
                    | openssl pkey -pubin -outform DER | base64 -w0)
                printf '{{"user":"%s","group":"%s","spki":"%s"}}\n' \
                    "{user}" "{group}" "$spki" \
                    >> /var/lib/piv-multiparty/authfile
            """)

        def unplug(self):
            machine.succeed(f"systemctl stop {self.unit}.service")

        def plug(self):
            machine.succeed(f"systemctl start {self.unit}.service")


    def pam_attempt(service, user, *, pins, password=None):
        """Drive `pamtester <service> <user> authenticate`, feeding the
        configured prompts in order: one PIN per multiparty group, then
        the unix password if the auth stack chains pam_unix after us."""
        parts = list(pins) + ([password] if password is not None else [])
        seq = "\\n".join(parts) + "\\n"
        cmd = (
            f"bash -c \"printf '{seq}' | "
            f"pamtester {service} {user} authenticate\" 2>&1"
        )
        return machine.execute(cmd)


    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("pcscd.socket")
    machine.wait_for_unit("jcardsim-A.service")
    machine.wait_for_unit("jcardsim-B.service")

    card_a = PivCard("A", "Virtual PCD 00 00", "jcardsim-A")
    card_b = PivCard("B", "Virtual PCD 00 01", "jcardsim-B")
    cards  = [card_a, card_b]

    with subtest("two virtual PIV readers enumerate"):
        # jcardsim takes a moment to connect to vpcd's TCP listener
        # after pcscd loads the driver. Poll up to 30s.
        readers = ""
        for _ in range(30):
            rc, out = machine.execute("pcsc_scan -n -r 2>&1 || true")
            machine.log(f"pcsc_scan: {out!r}")
            if out.count("Virtual PCD") >= 2:
                readers = out
                break
            time.sleep(1)
        assert "Virtual PCD" in readers and readers.count("Virtual PCD") >= 2, \
            f"expected 2 Virtual PCD readers, got: {readers!r}"

    with subtest("instantiate PivApplet on both jcardsim cards"):
        for c in cards:
            c.install_applet()

    with subtest("provision and enrol both cards"):
        for c, group in zip(cards, "AB"):
            c.provision_and_enrol("alice", group)

    with subtest("authfile has two distinct SPKIs"):
        import json as _json
        contents = machine.succeed("cat /var/lib/piv-multiparty/authfile")
        machine.log(contents)
        lines = [l for l in contents.splitlines() if l.strip() and not l.startswith("#")]
        assert len(lines) == 2, f"expected 2 entries, got: {contents!r}"
        spkis = {_json.loads(l)["spki"] for l in lines}
        assert len(spkis) == 2, f"SPKIs must differ across distinct cards: {spkis}"

    with subtest("happy path: pamtester succeeds with both PINs"):
        rc, out = pam_attempt("login", "alice", pins=[PIN, PIN])
        machine.log(f"rc={rc} out={out!r}")
        assert rc == 0, f"pamtester should succeed, got rc={rc}: {out}"
        assert "successful" in out.lower(), out

    with subtest("wrong PIN on group A fails"):
        rc, out = pam_attempt("login", "alice", pins=[WRONG_PIN, PIN])
        machine.log(f"rc={rc} out={out!r}")
        assert rc != 0, f"pamtester should FAIL with wrong PIN, got rc={rc}: {out}"

    with subtest("distinct-device contract: same SPKI in two groups is rejected"):
        # Rewrite the authfile so group B references group A's SPKI.
        machine.succeed("cp /var/lib/piv-multiparty/authfile /var/lib/piv-multiparty/authfile.bak")
        # Take group A's line, plus a duplicate of it with group rewritten to B.
        machine.succeed(
            "{ jq -c 'select(.group==\"A\")' /var/lib/piv-multiparty/authfile; "
            "  jq -c 'select(.group==\"A\") | .group=\"B\"' /var/lib/piv-multiparty/authfile; "
            "} > /var/lib/piv-multiparty/authfile.tmp && "
            "mv /var/lib/piv-multiparty/authfile.tmp /var/lib/piv-multiparty/authfile"
        )
        rc, out = pam_attempt("login", "alice", pins=[PIN, PIN])
        machine.log(f"rc={rc} out={out!r}")
        assert rc != 0, f"pamtester must reject same-device authfile: rc={rc} {out}"
        machine.succeed("mv /var/lib/piv-multiparty/authfile.bak /var/lib/piv-multiparty/authfile")

    with subtest("real login: agetty drives pam_piv_multiparty end-to-end"):
        machine.wait_for_unit("getty@tty1.service")
        machine.wait_until_tty_matches("1", "login:")
        machine.send_chars("alice\n")
        machine.wait_until_tty_matches("1", "Present YubiKey for group A")
        machine.wait_until_tty_matches("1", "PIN for YubiKey in group A:")
        machine.send_chars(f"{PIN}\n")
        machine.wait_until_tty_matches("1", "Present YubiKey for group B")
        machine.wait_until_tty_matches("1", "PIN for YubiKey in group B:")
        machine.send_chars(f"{PIN}\n")
        machine.send_chars("id -u > /tmp/login-uid\n")
        machine.wait_until_succeeds("test -f /tmp/login-uid")
        uid = machine.succeed("cat /tmp/login-uid").strip()
        assert uid == "1000", f"expected uid 1000 after login, got {uid!r}"
        # Log out so the tty is ready for any later subtest.
        machine.send_chars("exit\n")
        machine.wait_until_tty_matches("1", "login:")

    with subtest("group B card 'unplugged': auth fails closed"):
        card_b.unplug()
        # Give pcscd a moment to notice slot 1 went dead.
        time.sleep(2)
        rc, out = pam_attempt("login", "alice", pins=[PIN, PIN])
        machine.log(f"rc={rc} out={out!r}")
        assert rc != 0, (
            f"pamtester must FAIL when group B's card is unreachable: rc={rc} {out}"
        )
        card_b.plug()

    with subtest("PIN lockout: card refuses correct PIN after 5 wrong attempts"):
        # PivApplet ships with pinRetries=5
        for i in range(5):
            rc, out = pam_attempt("login", "alice", pins=[WRONG_PIN, PIN])
            machine.log(f"wrong attempt {i + 1}/5: rc={rc} out={out!r}")
            assert rc != 0, f"wrong-PIN attempt {i + 1} should fail"

        # Now the correct PIN must still fail — proving the rejection
        rc, out = pam_attempt("login", "alice", pins=[PIN, PIN])
        machine.log(f"correct PIN after lockout: rc={rc} out={out!r}")
        assert rc != 0, f"locked card must reject even the correct PIN: {out!r}"
  '';
}
