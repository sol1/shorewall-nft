#!/usr/bin/env python3
# The load-failure hint and the kernel-requirements listing (github, BillK on
# shorewall-users): a missing kernel feature or module must not read as an
# opaque nft error. The hint has to point at the capabilities command, and
# 'show capabilities' has to list the base kernel requirements.
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft.cli import _kernel_hint, _kernel_requirements  # noqa: E402
import io  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    if cond:
        print("PASS", name)
    else:
        print("FAIL", name)
        fails += 1


buf = io.StringIO()
_kernel_hint(out=buf)
hint = buf.getvalue()
check("hint points at 'show capabilities'", "show capabilities" in hint)
check("hint names the base modules",
      "nf_tables" in hint and "nf_conntrack" in hint)

reqs = _kernel_requirements()
names = [name for name, _note, _ok in reqs]
check("requirements list nf_tables and nf_conntrack",
      names == ["nf_tables", "nf_conntrack"])
check("each requirement has a boolean present flag",
      all(isinstance(ok, bool) for _n, _note, ok in reqs))

sys.exit(1 if fails else 0)
