{ pkgs ? import <nixpkgs> {} }:
let
  engine = import ./engine/default.nix { inherit pkgs; };
  proxy = import ./browser-proxy.nix { inherit pkgs engine; };
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "keyslot";
  version = "0.2.0";
  src = pkgs.lib.cleanSource ./.;
  nativeBuildInputs = [ pkgs.meson pkgs.ninja pkgs.wrapGAppsHook4 pkgs.gobject-introspection ];
  nativeCheckInputs = [ pkgs.dbus pkgs.xvfb-run pkgs.gnome-keyring pkgs.libsodium pkgs.openssl pkgs.openssh pkgs.gcr_4 pkgs.nss_wrapper ];
  buildInputs = [ pkgs.gtk4 pkgs.libadwaita pkgs.libsecret (pkgs.python3.withPackages (p: [ p.pygobject3 ])) ];
  postInstall = ''
    mkdir -p "$out/share/icons/hicolor"
    cp -r ${pkgs.keepassxc.src}/share/icons/application/* "$out/share/icons/hicolor/"
  '';
  preFixup = ''
    gappsWrapperArgs+=(--prefix PATH : ${pkgs.lib.makeBinPath [ engine ]})
    gappsWrapperArgs+=(--set KEYSLOT_ENGINE ${engine}/libexec/keyslot-engine)
    gappsWrapperArgs+=(--set KEYSLOT_BROWSER_PROXY ${proxy})
  '';
  # Add Qt console tools after GTK wrapping; browser shells discover the proxy on PATH.
  postFixup = ''
    ln -s ${proxy} "$out/bin/keepassxc-proxy"
    ln -s ${engine}/bin/keepassxc-cli "$out/bin/keepassxc-cli"
  '';
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    export PATH=${engine}/bin:$PATH
    export KEYSLOT_ENGINE=${engine}/libexec/keyslot-engine
    export KEYSLOT_REQUIRE_ENGINE=1
    export KEYSLOT_BROWSER_BRIDGE=${engine}/libexec/keyslot-browser
    export KEYSLOT_BROWSER_PROXY=${proxy}
    export KEYSLOT_BROWSER_PROXY_UPSTREAM=${engine}/libexec/keepassxc-proxy-upstream
    export KEYSLOT_TEST_SODIUM=${pkgs.libsodium}/lib/libsodium.so
    export KEYSLOT_TEST_OPENSSL=${pkgs.openssl}/bin/openssl
    export KEYSLOT_TEST_GCR=${pkgs.gcr_4}/libexec/gcr-ssh-agent
    export KEYSLOT_TEST_NSS_WRAPPER=${pkgs.nss_wrapper}/lib/libnss_wrapper.so
    export KEYSLOT_UPSTREAM_TEST_DATA=${pkgs.keepassxc.src}/tests/data
    export GSETTINGS_BACKEND=memory GTK_A11Y=none GSK_RENDERER=cairo GDK_BACKEND=x11
    xvfb-run -a -s "-screen 0 1440x1000x24" dbus-run-session --config-file=${./tools/test-session.conf} -- meson test --print-errorlogs
    runHook postCheck
  '';
  passthru = { inherit engine; };
  meta = {
    description = "Native GNOME client for KeePassXC databases (early development)";
    license = pkgs.lib.licenses.gpl3Only;
    platforms = pkgs.lib.platforms.linux;
    mainProgram = "keyslot";
  };
}
