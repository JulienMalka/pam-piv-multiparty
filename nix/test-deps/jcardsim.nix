{
  lib,
  fetchFromGitHub,
  maven,
  jdk8,
  javacard-sdk,
}:

maven.buildMavenPackage rec {
  pname = "jcardsim";
  version = "3.0.5-arekinath-2019-03-31";

  src = fetchFromGitHub {
    owner = "arekinath";
    repo = "jcardsim";
    rev = "4c766cfb48c43507f9a30a1443e7214d2073a430";
    sha256 = "08ngmjjn471a86bfv462qvvwagqh6i419hqsp130rs9923q2kafi";
  };

  mvnJdk = jdk8;
  doCheck = false;

  mvnParameters = "-Dmaven.javadoc.skip=true";

  mvnFetchExtraArgs.preBuild = ''
    export JC_CLASSIC_HOME=${javacard-sdk}/jc305u3_kit
    mvn install:install-file \
      -Dfile=$JC_CLASSIC_HOME/lib/api_classic.jar \
      -DgroupId=oracle.javacard \
      -DartifactId=api_classic \
      -Dversion=3.0.5 \
      -Dpackaging=jar \
      -Dmaven.repo.local=$out/.m2
  '';

  preBuild = ''
    export JC_CLASSIC_HOME=${javacard-sdk}/jc305u3_kit
  '';

  mvnHash = "sha256-VnnYkPX+yz84SCn2oDiCXWI8IDMTQf2aE2yXj9V1Jb8=";

  installPhase = ''
    runHook preInstall
    install -Dm0644 target/jcardsim-${builtins.head (builtins.split "-arekinath" version)}-SNAPSHOT.jar \
      $out/share/java/jcardsim.jar
    runHook postInstall
  '';

  meta = {
    description = "JavaCard simulator";
    homepage = "https://github.com/arekinath/jcardsim";
    license = lib.licenses.asl20;
    platforms = lib.platforms.linux;
  };
}
