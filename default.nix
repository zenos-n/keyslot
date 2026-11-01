{ pkgs ? import <nixpkgs> {}, doCheck ? false }:
let
  engine = import ./engine/default.nix { inherit pkgs doCheck; };
  proxy = import ./browser-proxy.nix { inherit pkgs engine; };
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "keyslot";
  version = "0.2.0";
  src = pkgs.lib.cleanSourceWith {
    src = pkgs.lib.cleanSource ./.;
    filter = path: _type:
      let name = baseNameOf path;
      in name != "__pycache__" && !(pkgs.lib.hasSuffix ".pyc" name) && !(pkgs.lib.hasSuffix ".pyo" name);
  };
  nativeBuildInputs = [ pkgs.meson pkgs.ninja pkgs.wrapGAppsHook4 pkgs.gobject-introspection ];
  nativeCheckInputs = [ pkgs.dbus pkgs.xvfb-run pkgs.gnome-keyring pkgs.libsodium pkgs.openssl pkgs.openssh pkgs.gcr_4 pkgs.nss_wrapper pkgs.zbar ];
  buildInputs = [ pkgs.gtk4 pkgs.libadwaita pkgs.libsecret pkgs.gdk-pixbuf pkgs.librsvg pkgs.adwaita-icon-theme (pkgs.python3.withPackages (p: [ p.pygobject3 ])) ];
  mesonFlags = [ "-Dtests=${if doCheck then "true" else "false"}" ];
  postInstall = ''
    mkdir -p "$out/share/icons/hicolor"
    cp -r ${engine.src}/share/icons/application/* "$out/share/icons/hicolor/"
    install -Dm644 ${engine.src}/COPYING "$out/share/licenses/keyslot/UPSTREAM-COPYING"
    install -Dm644 ${engine.src}/LICENSE.MIT "$out/share/licenses/keyslot/LICENSE.MIT"
    install -Dm644 ${engine.src}/LICENSE.CC0 "$out/share/licenses/keyslot/LICENSE.CC0"
    python3 -m compileall -q "$out/share/keyslot/keyslot"
  '';
  preFixup = ''
    gappsWrapperArgs+=(--set KEYSLOT_ADWAITA_ICONS ${pkgs.adwaita-icon-theme}/share/icons)
    gappsWrapperArgs+=(--prefix PATH : ${pkgs.lib.makeBinPath [ engine ]})
    gappsWrapperArgs+=(--set KEYSLOT_ENGINE ${engine}/libexec/keyslot-engine)
    gappsWrapperArgs+=(--set KEYSLOT_STDIN_READER ${pkgs.coreutils}/bin/head)
    gappsWrapperArgs+=(--set KEYSLOT_BROWSER_PROXY ${proxy})
  '';
  # Publish compatibility commands after GTK wrapping.
  postFixup = ''
    ln -s keyslot "$out/bin/keepassxc"
    ln -s ${proxy} "$out/bin/keyslot-browser-proxy"
    ln -s ${engine}/libexec/keepassxc-proxy "$out/bin/keepassxc-proxy"
    ln -s ${engine}/bin/keepassxc-cli "$out/bin/keepassxc-cli"
  '';
  inherit doCheck;
  checkPhase = ''
    runHook preCheck
    export PATH=${engine}/bin:$PATH
    export KEYSLOT_ENGINE=${engine}/libexec/keyslot-engine
    export KEYSLOT_REQUIRE_ENGINE=1
    export KEYSLOT_BROWSER_BRIDGE=${engine}/libexec/keyslot-browser
    export KEYSLOT_BROWSER_PROXY=${proxy}
    export KEYSLOT_BROWSER_PROXY_UPSTREAM=${engine}/libexec/keepassxc-proxy-upstream
    export KEYSLOT_TEST_SODIUM=${pkgs.libsodium}/lib/libsodium.so
    export KEYSLOT_TEST_ZBAR=${pkgs.zbar}/bin/zbarimg
    export KEYSLOT_TEST_OPENSSL=${pkgs.openssl}/bin/openssl
    export KEYSLOT_TEST_GCR=${pkgs.gcr_4}/libexec/gcr-ssh-agent
    export KEYSLOT_TEST_NSS_WRAPPER=${pkgs.nss_wrapper}/lib/libnss_wrapper.so
    export KEYSLOT_TEST_X11=${pkgs.libX11}/lib/libX11.so.6
    export KEYSLOT_TEST_XTST=${pkgs.libXtst}/lib/libXtst.so.6
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
