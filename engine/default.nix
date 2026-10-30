{ pkgs }:
assert pkgs.keepassxc.version == "2.7.12";
pkgs.keepassxc.overrideAttrs (old: {
  pname = "keyslot-engine";
  # Keep exactly the distro-pinned upstream source and build dependencies.
  postPatch = (old.postPatch or "") + ''
    cp ${./main.cpp} src/keyslot-engine.cpp
    cp ${./CsvImport.h} src/CsvImport.h
    cp ${./CsvImport.cpp} src/CsvImport.cpp
    cp ${./BrowserTransport.cpp} src/keyslot-browser.cpp
    cp ${./BrowserFraming.h} src/BrowserFraming.h
    cp ${./BrowserDeadline.h} src/BrowserDeadline.h
    cp ${./BrowserDatabase.h} src/BrowserDatabase.h
    cp ${./BrowserDatabase.cpp} src/BrowserDatabase.cpp
    cp ${./KeyslotPasskeys.cpp} src/KeyslotPasskeys.cpp
    cp ${./SSHAgentRelay.cpp} src/keyslot-ssh-agent.cpp
    cp ${./KeyslotSSH.h} src/KeyslotSSH.h
    cp ${./KeyslotSSH.cpp} src/KeyslotSSH.cpp
    patch -p1 < ${./PasskeyConsent.patch}
    mkdir src/proxy/upstream
    cp src/proxy/NativeMessagingProxy.cpp src/proxy/NativeMessagingProxy.h src/proxy/keepassxc-proxy.cpp src/proxy/upstream/
    patch -p1 < ${./ProxySocketFraming.patch}
    cat >> src/proxy/CMakeLists.txt <<'CMAKE'
    add_executable(keepassxc-proxy-upstream upstream/keepassxc-proxy.cpp upstream/NativeMessagingProxy.cpp ../browser/BrowserShared.cpp)
    target_link_libraries(keepassxc-proxy-upstream proxy_alloc Qt5::Core Qt5::Network)
    CMAKE
    # Reuse upstream matching/permissions without MainWindow, dialogs or socket activation.
    substituteInPlace src/browser/BrowserService.h \
      --replace-fail 'explicit BrowserService();' 'explicit BrowserService(bool headless = false);' \
      --replace-fail 'friend class TestBrowser;' 'friend class TestBrowser; friend class KeyslotBrowserDatabase;'
    substituteInPlace src/browser/BrowserService.cpp \
      --replace-fail 'BrowserService::BrowserService()' 'BrowserService::BrowserService(bool headless)' \
      --replace-fail 'm_browserHost(new BrowserHost)' 'm_browserHost(headless ? nullptr : new BrowserHost)' \
      --replace-fail '    connect(m_browserHost, &BrowserHost::clientMessageReceived' '    if (headless) return;
    connect(m_browserHost, &BrowserHost::clientMessageReceived'
    cat >> src/CMakeLists.txt <<'CMAKE'
    add_executable(keyslot-engine keyslot-engine.cpp CsvImport.cpp BrowserDatabase.cpp KeyslotPasskeys.cpp KeyslotSSH.cpp)
    target_link_libraries(keyslot-engine keepassx_core)
    add_executable(keyslot-browser keyslot-browser.cpp browser/BrowserMessageBuilder.cpp)
    target_link_libraries(keyslot-browser keepassx_core Qt5::Network)
    add_executable(keyslot-ssh-agent keyslot-ssh-agent.cpp)
    target_link_libraries(keyslot-ssh-agent keepassx_core Qt5::Network)
    CMAKE
  '';
  cmakeFlags = (old.cmakeFlags or []) ++ [ "-DWITH_TESTS=OFF" "-DWITH_GUI_TESTS=OFF" ];
  buildPhase = ''
    runHook preBuild
    cmake --build . --target keyslot-engine keyslot-browser keyslot-ssh-agent keepassxc-cli keepassxc-proxy keepassxc-proxy-upstream translations --parallel "$NIX_BUILD_CORES"
    runHook postBuild
  '';
  installPhase = ''
    runHook preInstall
    install -Dm755 src/keyslot-engine "$out/libexec/keyslot-engine"
    install -Dm755 src/keyslot-browser "$out/libexec/keyslot-browser"
    install -Dm755 src/keyslot-ssh-agent "$out/libexec/keyslot-ssh-agent"
    install -Dm755 src/proxy/keepassxc-proxy "$out/libexec/keepassxc-proxy"
    install -Dm755 src/proxy/keepassxc-proxy-upstream "$out/libexec/keepassxc-proxy-upstream"
    install -Dm755 src/cli/keepassxc-cli "$out/bin/keepassxc-cli"
    mkdir -p "$out/share/keepassxc"
    cp -r ../share/wordlists "$out/share/keepassxc/"
    mkdir -p "$out/share/keepassxc/translations"
    cp share/translations/*.qm "$out/share/keepassxc/translations/"
    cp share/translations/keepassxc_en_US.qm "$out/share/keepassxc/translations/keepassxc_en.qm"
    install -Dm644 ../COPYING "$out/share/doc/keyslot-engine/COPYING"
    install -Dm644 ../LICENSE.GPL-3 "$out/share/licenses/keyslot-engine/LICENSE.GPL-3"
    runHook postInstall
  '';
  doCheck = false;
  doInstallCheck = false;
  dontWrapQtApps = true;
  passthru = {};
  meta = builtins.removeAttrs old.meta [ "mainProgram" ] // {
    description = "Private Keyslot engine linked to KeePassXC 2.7.12 core";
    license = pkgs.lib.licenses.gpl3Only;
    platforms = pkgs.lib.platforms.linux;
  };
})
