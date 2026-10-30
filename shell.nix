{ pkgs ? import <nixpkgs> {} }:
let engine = import ./engine/default.nix { inherit pkgs; };
in
pkgs.mkShell {
  KEYSLOT_ENGINE = "${engine}/libexec/keyslot-engine";
  KEYSLOT_BROWSER_BRIDGE = "${engine}/libexec/keyslot-browser";
  KEYSLOT_BROWSER_PROXY = import ./browser-proxy.nix { inherit pkgs engine; };
  KEYSLOT_BROWSER_PROXY_UPSTREAM = "${engine}/libexec/keepassxc-proxy-upstream";
  KEYSLOT_TEST_SODIUM = "${pkgs.libsodium}/lib/libsodium.so";
  KEYSLOT_TEST_OPENSSL = "${pkgs.openssl}/bin/openssl";
  KEYSLOT_TEST_GCR = "${pkgs.gcr_4}/libexec/gcr-ssh-agent";
  KEYSLOT_TEST_NSS_WRAPPER = "${pkgs.nss_wrapper}/lib/libnss_wrapper.so";
  KEYSLOT_UPSTREAM_TEST_DATA = "${pkgs.keepassxc.src}/tests/data";
  packages = [ engine pkgs.meson pkgs.ninja pkgs.gjs pkgs.dbus pkgs.xvfb-run pkgs.gnome-keyring pkgs.openssh
    pkgs.gtk4 pkgs.libadwaita pkgs.libsecret pkgs.gobject-introspection
    (pkgs.python3.withPackages (p: [ p.pygobject3 ])) ];
}
