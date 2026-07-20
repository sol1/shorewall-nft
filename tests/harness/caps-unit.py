#!/usr/bin/env python3
# Capability probing: show capabilities and the conntrack ?if gates must
# reflect the kernel, but only when probing is enabled, and never in a way
# that makes corpus compilation depend on the test machine. The gating logic
# is exercised with injected probe results so the test is deterministic; a
# live probe of a bogus helper is also checked to never claim availability.
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft import capabilities  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print("PASS" if cond else "FAIL", name)
    if not cond:
        fails += 1


# With probing off (the default, and how the corpus compiles) a helper reports
# its compile-time default regardless of any cached probe result.
os.environ.pop("SHOREWALL_NFT_STATIC_CAPS", None)
capabilities._probe_cache.clear()
capabilities._probe_cache["ftp"] = False
capabilities.enable_probe(False)
check("probe off: helper uses the static default",
      capabilities.lookup("FTP_HELPER") is True)

# SHOREWALL_NFT_STATIC_CAPS forces probing off even when a command enables it,
# which is what keeps corpus output byte-identical across machines.
os.environ["SHOREWALL_NFT_STATIC_CAPS"] = "1"
capabilities.enable_probe(True)
check("STATIC_CAPS keeps probing off",
      capabilities.lookup("FTP_HELPER") is True)
os.environ.pop("SHOREWALL_NFT_STATIC_CAPS", None)

# With probing on, an unavailable helper is gated out; an available one stays.
capabilities.enable_probe(True)
capabilities._probe_cache["ftp"] = False
check("probe on: unavailable helper is gated out",
      capabilities.lookup("FTP_HELPER") is False)
capabilities._probe_cache["ftp"] = True
check("probe on: available helper stays on",
      capabilities.lookup("FTP_HELPER") is True)

# A probe that cannot tell (None) falls back to the compile-time default.
capabilities._probe_cache["ftp"] = None
check("probe on: unknown result falls back to the default",
      capabilities.lookup("FTP_HELPER") is True)

# Non-helper capabilities are never probed, and an unknown name is false.
check("non-helper capability is static", capabilities.lookup("CT_TARGET") is True)
check("unknown capability is false", capabilities.lookup("NO_SUCH_CAP") is False)

# A live probe of a helper that does not exist must never claim availability.
capabilities._probe_cache.clear()
result = capabilities.probe_helper("definitely_not_a_helper", "tcp")
check("bogus helper is not reported available", result in (False, None))

sys.exit(1 if fails else 0)
