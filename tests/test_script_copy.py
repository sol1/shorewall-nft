"""Regression tests for copying compiled firewall scripts."""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shorewall_nft.cli import _copy_script


class ScriptCopyTests(unittest.TestCase):
    def test_copy_preserves_contents_and_mode_without_copying_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            destination = Path(directory) / "destination"

            source.write_bytes(b"#!/bin/sh\nexit 0\n")
            os.chmod(source, 0o750)

            with patch("shutil.copystat",
                       side_effect=PermissionError("SELinux relabel denied")):
                _copy_script(source, destination)

            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertEqual(
                stat.S_IMODE(destination.stat().st_mode),
                0o750,
            )


if __name__ == "__main__":
    unittest.main()
