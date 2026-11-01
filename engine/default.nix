{ pkgs, doCheck ? false }:
assert pkgs.keepassxc.version == "2.7.12";
pkgs.keepassxc.overrideAttrs (old: {
  pname = "keyslot-engine";
  nativeBuildInputs = (old.nativeBuildInputs or []) ++ [ pkgs.librsvg ];
  # Keep exactly the distro-pinned upstream source and build dependencies.
  postPatch = (old.postPatch or "") + ''
    cp ${./main.cpp} src/keyslot-engine.cpp
    cp ${./KeyslotConfig.h} src/KeyslotConfig.h
    cp ${./KeyslotConfig.cpp} src/KeyslotConfig.cpp
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
    cp ${./OpenSSHKeyGen.h} src/sshagent/OpenSSHKeyGen.h
    cp ${./OpenSSHKeyGen.cpp} src/sshagent/OpenSSHKeyGen.cpp
    cp ${./KeyslotAutoType.h} src/KeyslotAutoType.h
    cp ${./KeyslotAutoType.cpp} src/KeyslotAutoType.cpp
    cp ${./KeyslotKeeShare.h} src/KeyslotKeeShare.h
    cp ${./KeyslotKeeShare.cpp} src/KeyslotKeeShare.cpp
    cp ${./KeyslotSecrets.h} src/KeyslotSecrets.h
    cp ${./KeyslotSecrets.cpp} src/KeyslotSecrets.cpp
    cp ${./KeyslotTransfer.h} src/KeyslotTransfer.h
    cp ${./KeyslotTransfer.cpp} src/KeyslotTransfer.cpp
    cp ${./KeyslotLaunch.h} src/KeyslotLaunch.h
    cp ${./KeyslotLaunch.cpp} src/KeyslotLaunch.cpp
    cp ${./KeyslotHistory.h} src/KeyslotHistory.h
    cp ${./KeyslotHistory.cpp} src/KeyslotHistory.cpp
    cp ${./KeyslotTotp.h} src/KeyslotTotp.h
    cp ${./KeyslotTotp.cpp} src/KeyslotTotp.cpp
    cp ${./KeyslotTrash.h} src/KeyslotTrash.h
    cp ${./KeyslotTrash.cpp} src/KeyslotTrash.cpp
    cp ${./KeyslotEntryActions.h} src/KeyslotEntryActions.h
    cp ${./KeyslotEntryActions.cpp} src/KeyslotEntryActions.cpp
    cp ${./KeyslotReports.h} src/KeyslotReports.h
    cp ${./KeyslotReports.cpp} src/KeyslotReports.cpp
    cp ${./KeyslotIcons.h} src/KeyslotIcons.h
    cp ${./KeyslotIcons.cpp} src/KeyslotIcons.cpp
    cp ${./KeyslotNetwork.h} src/KeyslotNetwork.h
    cp ${./KeyslotNetwork.cpp} src/KeyslotNetwork.cpp
    cp ${./KeyslotBrowserValues.h} src/KeyslotBrowserValues.h
    cp ${./SecurityCheck.cpp} src/KeyslotSecurityCheck.cpp
    patch -p1 < ${./SecurityBackports.patch}
    patch -p1 < ${./SerializationFixes.patch}
    # Reuse upstream text/binary secret conversion independently of Qt widgets.
    substituteInPlace src/fdosecrets/objects/Item.cpp \
      --replace-fail '    static DBusResult setEntrySecret(' '    DBusResult setEntrySecret(' \
      --replace-fail '    static Secret getEntrySecret(' '    Secret getEntrySecret('
    patch -p1 < ${./ProtonPassRecords.patch}
    patch -p1 < ${./TotpBounds.patch}
    patch -p1 < ${./XmlInnerStream.patch}
    patch -p1 < ${./AutoTypeHeadless.patch}
    patch -p1 < ${./KeeShareHeadless.patch}
    patch -p1 < ${./PasskeyConsent.patch}
    mkdir src/proxy/upstream
    cp src/proxy/NativeMessagingProxy.cpp src/proxy/NativeMessagingProxy.h src/proxy/keepassxc-proxy.cpp src/proxy/upstream/
    patch -p1 < ${./ProxySocketFraming.patch}
    cp src/browser/BrowserShared.cpp src/proxy/KeyslotBrowserShared.cpp
    substituteInPlace src/proxy/KeyslotBrowserShared.cpp \
      --replace-fail '#include "BrowserShared.h"' '#include "browser/BrowserShared.h"' \
      --replace-fail '/org.keepassxc.KeePassXC.BrowserServer' '/Keyslot.BrowserServer' \
      --replace-fail '        QFile::remove(origSocketPath);' '        // Dedicated clients do not publish legacy aliases.' \
      --replace-fail '        QFile::link(socketPath, origSocketPath);' '        Q_UNUSED(origSocketPath);'
    cat >> src/proxy/CMakeLists.txt <<'CMAKE'
    add_executable(keyslot-browser-proxy keepassxc-proxy.cpp NativeMessagingProxy.cpp KeyslotBrowserShared.cpp)
    target_link_libraries(keyslot-browser-proxy proxy_alloc Qt5::Core Qt5::Network)
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
    add_executable(keyslot-engine core/Alloc.cpp keyslot-engine.cpp KeyslotConfig.cpp CsvImport.cpp BrowserDatabase.cpp KeyslotPasskeys.cpp KeyslotSSH.cpp KeyslotAutoType.cpp KeyslotKeeShare.cpp KeyslotSecrets.cpp KeyslotTransfer.cpp KeyslotLaunch.cpp KeyslotHistory.cpp KeyslotTotp.cpp KeyslotTrash.cpp KeyslotEntryActions.cpp KeyslotReports.cpp KeyslotIcons.cpp KeyslotNetwork.cpp autotype/xcb/AutoTypeXCB.cpp)
    target_sources(keyslot-engine PRIVATE sshagent/OpenSSHKeyGen.cpp)
    target_link_libraries(keyslot-engine keepassx_core Qt5::X11Extras X11 Xi Xtst)
    add_executable(keyslot-browser core/Alloc.cpp keyslot-browser.cpp browser/BrowserMessageBuilder.cpp)
    target_link_libraries(keyslot-browser keepassx_core Qt5::Network)
    add_executable(keyslot-ssh-agent core/Alloc.cpp keyslot-ssh-agent.cpp)
    target_link_libraries(keyslot-ssh-agent keepassx_core Qt5::Network)
    if(${if doCheck then "TRUE" else "FALSE"})
      add_executable(keyslot-security-check KeyslotSecurityCheck.cpp core/Alloc.cpp)
      target_link_libraries(keyslot-security-check keepassx_core)
      target_link_options(keyslot-security-check PRIVATE "-Wl,--wrap=free")
    endif()
    CMAKE
  '';
  cmakeFlags = (old.cmakeFlags or []) ++ [ "-DWITH_TESTS=OFF" "-DWITH_GUI_TESTS=OFF" ];
  buildPhase = ''
    runHook preBuild
    cmake --build . --target keyslot-engine keyslot-browser keyslot-browser-proxy keyslot-ssh-agent ${pkgs.lib.optionalString doCheck "keyslot-security-check"} keepassxc-cli keepassxc-proxy keepassxc-proxy-upstream translations --parallel "$NIX_BUILD_CORES"
    runHook postBuild
  '';
  installPhase = ''
    runHook preInstall
    install -Dm755 src/keyslot-engine "$out/libexec/keyslot-engine"
    install -Dm755 src/keyslot-browser "$out/libexec/keyslot-browser"
    install -Dm755 src/keyslot-ssh-agent "$out/libexec/keyslot-ssh-agent"
    install -Dm755 src/proxy/keepassxc-proxy "$out/libexec/keepassxc-proxy"
    install -Dm755 src/proxy/keyslot-browser-proxy "$out/libexec/keyslot-browser-proxy"
    install -Dm755 src/proxy/keepassxc-proxy-upstream "$out/libexec/keepassxc-proxy-upstream"
    install -Dm755 src/cli/keepassxc-cli "$out/bin/keepassxc-cli"
    mkdir -p "$out/share/keepassxc"
    cp -r ../share/wordlists "$out/share/keepassxc/"
    mkdir -p "$out/share/keepassxc/database-icons"
    while read -r icon; do
      rsvg-convert --width 128 --height 128 --keep-aspect-ratio "../share/icons/$icon" > "$out/share/keepassxc/database-icons/$(basename "$icon" .svg).png"
    done < <(sed -n 's@.*<file>\(database/[^<]*\.svg\)</file>.*@\1@p' ../share/icons/icons.qrc)
    mkdir -p "$out/share/keepassxc/translations"
    cp share/translations/*.qm "$out/share/keepassxc/translations/"
    cp share/translations/keepassxc_en_US.qm "$out/share/keepassxc/translations/keepassxc_en.qm"
    install -Dm644 ../COPYING "$out/share/doc/keyslot-engine/COPYING"
    install -Dm644 ../LICENSE.GPL-3 "$out/share/licenses/keyslot-engine/LICENSE.GPL-3"
    install -Dm644 ../LICENSE.MIT "$out/share/licenses/keyslot-engine/LICENSE.MIT"
    install -Dm644 ../LICENSE.CC0 "$out/share/licenses/keyslot-engine/LICENSE.CC0"
    runHook postInstall
  '';
  inherit doCheck;
  checkPhase = ''
    runHook preCheck
    ./src/keyslot-security-check
    runHook postCheck
  '';
  doInstallCheck = false;
  dontWrapQtApps = true;
  passthru = {};
  meta = builtins.removeAttrs old.meta [ "mainProgram" ] // {
    description = "Private Keyslot engine linked to KeePassXC 2.7.12 core";
    license = pkgs.lib.licenses.gpl3Only;
    platforms = pkgs.lib.platforms.linux;
  };
})
