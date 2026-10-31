project('keyslot', version: '0.2.0', meson_version: '>= 0.62.0')
python = import('python').find_installation('python3')
dbus = find_program('dbus-run-session')
private_bus = ['--config-file=' + meson.project_source_root() / 'tools/test-session.conf', '--', python.full_path()]
pkgdir = get_option('prefix') / get_option('datadir') / 'keyslot'
bindir = get_option('prefix') / get_option('bindir')
conf = configuration_data()
conf.set('PYTHON', python.full_path())
conf.set('PKGDIR', pkgdir)
conf.set('BINDIR', bindir)
configure_file(input: 'keyslot.in', output: 'keyslot', configuration: conf,
               install: true, install_dir: get_option('bindir'), install_mode: 'rwxr-xr-x')
install_subdir('keyslot', install_dir: pkgdir, exclude_directories: ['__pycache__'])
configure_file(input: 'data/com.neg-zero.keyslot.desktop.in',
    output: 'com.neg-zero.keyslot.desktop', configuration: conf,
    install: true, install_dir: get_option('datadir') / 'applications')
configure_file(input: 'data/com.neg-zero.keyslot.service.in',
    output: 'com.neg-zero.keyslot.service', configuration: conf,
    install: true, install_dir: get_option('datadir') / 'dbus-1/services')
install_data('data/com.neg-zero.keyslot.metainfo.xml', install_dir: get_option('datadir') / 'metainfo')
install_data('LICENSE', install_dir: get_option('datadir') / 'licenses/keyslot')
test('backend', python, args: ['-m', 'unittest', 'discover', '-s', 'tests', '-v'],
     workdir: meson.project_source_root(), timeout: 600)
test('ui', dbus, args: private_bus + files('tools/smoke-ui.py'),
     workdir: meson.project_source_root(), timeout: 90)
test('login', python, args: files('tools/smoke-login.py'),
     workdir: meson.project_source_root(), timeout: 60)
test('signals', python, args: files('tools/smoke-signals.py'),
     workdir: meson.project_source_root(), timeout: 30)
test('browser', dbus, args: private_bus + files('tools/smoke-browser.py'),
     workdir: meson.project_source_root(), timeout: 30)
test('browser-protocol', python, args: files('tools/smoke-browser-protocol.py'),
     workdir: meson.project_source_root(), timeout: 60, is_parallel: false)
test('passkeys', dbus, args: private_bus + files('tools/smoke-passkeys.py'),
     workdir: meson.project_source_root(), timeout: 45)
test('ssh', dbus, args: private_bus + files('tools/smoke-ssh.py'),
     workdir: meson.project_source_root(), timeout: 60)
test('ssh-agents', dbus, args: private_bus + files('tools/smoke-ssh-agents.py') + ['--gcr'],
     workdir: meson.project_source_root(), timeout: 60)
test('ssh-forwarded', python, args: files('tools/smoke-ssh-agents.py') + ['--forwarded'],
     workdir: meson.project_source_root(), timeout: 60)
test('autotype', dbus, args: private_bus + files('tools/smoke-autotype.py'),
     workdir: meson.project_source_root(), timeout: 60)
test('autotype-x11', dbus, args: private_bus + files('tools/smoke-autotype-x11.py'),
     workdir: meson.project_source_root(), timeout: 60, is_parallel: false)
test('secrets', dbus, args: private_bus + files('tools/smoke-secrets.py'),
     workdir: meson.project_source_root(), timeout: 90)
test('appearance', dbus, args: private_bus + files('tools/smoke-appearance.py'),
     workdir: meson.project_source_root(), timeout: 60)
test('transfers', dbus, args: private_bus + files('tools/smoke-transfers.py'),
     workdir: meson.project_source_root(), timeout: 60)
test('bulk-groups', dbus, args: private_bus + files('tools/smoke-bulk-groups.py'),
     workdir: meson.project_source_root(), timeout: 60, is_parallel: false)
test('urls', dbus, args: private_bus + files('tools/smoke-urls.py'),
     workdir: meson.project_source_root(), timeout: 90)
test('history', dbus, args: private_bus + files('tools/smoke-history.py'),
     workdir: meson.project_source_root(), timeout: 90)
test('totp', dbus, args: private_bus + files('tools/smoke-totp.py'),
     workdir: meson.project_source_root(), timeout: 90, is_parallel: false)
