"""The public upstream CLI needs its own installed runtime resources."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest

CLI = shutil.which("keepassxc-cli")
if os.environ.get("KEYSLOT_REQUIRE_ENGINE") == "1" and not CLI:
    raise RuntimeError("The package must supply its upstream CLI")


@unittest.skipUnless(CLI, "Build the upstream CLI")
class CliInstallationTests(unittest.TestCase):
    def test_version_and_localized_help_have_no_missing_translation_warning(self):
        if os.environ.get("KEYSLOT_ENGINE"):
            self.assertEqual(Path(CLI).resolve(), Path(os.environ["KEYSLOT_ENGINE"]).resolve().parents[1] / "bin/keepassxc-cli")
        environment = dict(os.environ, LANG="C", LC_ALL="C")
        version = subprocess.run([CLI, "--version"], env=environment, capture_output=True, text=True, timeout=5)
        self.assertEqual((version.returncode, version.stdout.strip(), version.stderr), (0, "2.7.12", ""))
        english = subprocess.run([CLI, "--help"], env=environment, capture_output=True, text=True, timeout=5)
        environment.update(LANG="pl_PL.UTF-8", LC_ALL="pl_PL.UTF-8")
        polish = subprocess.run([CLI, "--help"], env=environment, capture_output=True, text=True, timeout=5)
        self.assertEqual((english.returncode, polish.returncode, english.stderr, polish.stderr), (0, 0, "", ""))
        self.assertIn("Dostępne polecenia", polish.stdout)
        self.assertNotEqual(english.stdout, polish.stdout)
