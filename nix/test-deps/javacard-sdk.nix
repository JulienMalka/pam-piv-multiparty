{
  stdenvNoCC,
  fetchFromGitHub,
  lib,
}:
stdenvNoCC.mkDerivation {
  pname = "oracle-javacard-sdk";
  version = "3.0.5u3";

  src = fetchFromGitHub {
    owner = "martinpaljak";
    repo = "oracle_javacard_sdks";
    rev = "3751d774dd4e6b60e813c6be61ab017e77f36570";
    sha256 = "1lzax59rdy3wcbkjyq2cira4xbfcyqld8c3vv2rrdw2xmj8ir7kz";
  };

  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp -r jc305u3_kit $out/
    runHook postInstall
  '';

  meta = {
    description = "Oracle JavaCard Classic Development Kit";
    homepage = "https://github.com/martinpaljak/oracle_javacard_sdks";
    license = lib.licenses.unfree;
    platforms = lib.platforms.all;
  };
}
