{
  lib,
  rustPlatform,
  pkg-config,
  pcsclite,
  pam,
  clang,
  makeWrapper,
  yubico-piv-tool,
  openssl,
  coreutils,
  src,
}:

rustPlatform.buildRustPackage {
  pname = "piv-multiparty";
  version = "0.1.0";

  inherit src;

  cargoLock.lockFile = "${src}/Cargo.lock";

  nativeBuildInputs = [
    pkg-config
    clang
    makeWrapper
  ];

  buildInputs = [
    pcsclite
    pam
  ];

  env.LIBCLANG_PATH = "${lib.getLib clang.cc}/lib";

  postInstall = ''
    mkdir -p $out/lib/security $out/libexec
    mv $out/lib/libpam_piv_multiparty.so $out/lib/security/pam_piv_multiparty.so

    # Install the enrolment helper. The unwrapped script lives in
    # libexec; the wrapper in bin pulls yubico-piv-tool / openssl /
    # coreutils into PATH so the script Just Works from any shell.
    install -Dm755 ${src}/scripts/enroll.sh $out/libexec/piv-multiparty-enroll
    makeWrapper $out/libexec/piv-multiparty-enroll $out/bin/piv-multiparty-enroll \
      --prefix PATH : ${
        lib.makeBinPath [
          yubico-piv-tool
          openssl
          coreutils
        ]
      }
  '';

  doCheck = true;
}
