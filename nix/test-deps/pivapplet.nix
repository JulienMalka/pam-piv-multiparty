{
  lib,
  stdenv,
  fetchFromGitHub,
  ant,
  jdk8,
  jcardsim,
}:

stdenv.mkDerivation {
  pname = "pivapplet";
  version = "0-unstable-2022-08-22";

  src = fetchFromGitHub {
    owner = "arekinath";
    repo = "PivApplet";
    rev = "5cb14a9e8d16e92fbad73dcad86a219a9210554f";
    sha256 = "031hhqlxvyqnkbs8qb5s9v3qiq2jrx3z95i281imc1r0hy5bvqqn";
  };

  nativeBuildInputs = [
    ant
    jdk8
  ];

  buildInputs = [ jcardsim ];

  buildPhase = ''
    runHook preBuild
    # Run only the `preprocess` target — the default `dist` target
    # also tries to build ant-javacard from the missing submodule.
    ant preprocess
    mkdir -p bin
    find src-gen -name '*.java' > sources.lst
    javac -source 1.7 -target 1.7 \
      -cp ${jcardsim}/share/java/jcardsim.jar \
      -d bin @sources.lst
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/java
    (cd bin && jar cf $out/share/java/pivapplet.jar .)
    install -Dm0644 test/jcardsim.cfg $out/share/pivapplet/jcardsim.cfg.example
    runHook postInstall
  '';

  meta = {
    description = "PIV JavaCard applet";
    homepage = "https://github.com/arekinath/PivApplet";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
