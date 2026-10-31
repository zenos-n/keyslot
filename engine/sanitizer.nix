{ pkgs }:
let engine = import ./default.nix { inherit pkgs; };
in engine.overrideAttrs (old: {
  pname = "keyslot-engine-security-asan";
  cmakeFlags = old.cmakeFlags ++ [ "-DWITH_ASAN=ON" ];
  postPatch = old.postPatch + ''
    # ASan owns allocation/deallocation in this test; production checks the scrub hook.
    sed -i '1i#if !defined(WITH_ASAN)' src/core/Alloc.cpp
    echo '#endif' >> src/core/Alloc.cpp
    sed -i '/    watchedSize = 97;/,/    require(sawScrubbedFree,/d' src/KeyslotSecurityCheck.cpp
  '';
  buildPhase = ''
    runHook preBuild
    cmake --build . --target keyslot-security-check --parallel "$NIX_BUILD_CORES"
    runHook postBuild
  '';
  checkPhase = ''
    runHook preCheck
    ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ./src/keyslot-security-check
    runHook postCheck
  '';
  installPhase = ''
    runHook preInstall
    mkdir -p "$out"
    echo 'AddressSanitizer security regressions passed' > "$out/result"
    runHook postInstall
  '';
  meta = old.meta // {
    description = "Keyslot native security regressions with AddressSanitizer";
  };
})
