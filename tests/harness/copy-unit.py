#!/usr/bin/env python3
# _copy_script must copy a firewall script's contents and mode without carrying
# its SELinux context, so a copy on an enforcing system (Rocky 9) does not hit a
# relabel denial (github #36). It uses copyfile plus chmod rather than
# copy2/copystat, which would try to replicate the security xattrs. The mode
# copy matters: the saved and .prev scripts are run directly, so they must stay
# executable.
import os
import shutil
import stat
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft.cli import _copy_script  # noqa: E402

fails = 0


def ok(name):
    print("PASS", name)


def bad(name, msg=""):
    global fails
    print("FAIL", name, ("- " + msg) if msg else "")
    fails += 1


d = tempfile.mkdtemp(prefix="shorewall-nft-copy-")
try:
    src = os.path.join(d, "firewall")
    dst = os.path.join(d, "firewall.prev")
    with open(src, "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(src, 0o750)

    # copystat is what would carry the SELinux context and trip the relabel
    # denial, so prove _copy_script never reaches it.
    called = []
    real = shutil.copystat
    shutil.copystat = lambda *a, **k: called.append(a)
    try:
        _copy_script(src, dst)
    finally:
        shutil.copystat = real

    (ok if open(dst).read() == open(src).read() else bad)(
        "copy: contents are preserved")
    (ok if stat.S_IMODE(os.stat(dst).st_mode) == 0o750 else bad)(
        "copy: executable mode is preserved")
    (ok if not called else bad)(
        "copy: does not copy the SELinux context (no copystat)")
finally:
    shutil.rmtree(d)

sys.exit(1 if fails else 0)
