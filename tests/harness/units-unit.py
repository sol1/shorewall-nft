#!/usr/bin/env python3
# The shipped init units must start the firewall AFTER the network is online,
# not before it. An earlier ordering (Before=network-pre.target) started the
# firewall before any interface was up, so provider and routes-file routing
# could not reach its nexthops and the firewall came up unrouted with
# "Device for nexthop is not up" errors (github #16). This guards against a
# regression back to the pre-network ordering. Pure file reads, no systemd.
import os
import sys

REPO = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")
SYSTEMD = os.path.join(REPO, "packaging", "systemd")
FIREWALL_UNITS = ("shorewall.service", "shorewall6.service",
                  "shorewall-lite.service", "shorewall6-lite.service")

fails = 0


def ok(name):
    print("PASS", name)


def bad(name, msg=""):
    global fails
    print("FAIL", name, ("- " + msg) if msg else "")
    fails += 1


for unit in FIREWALL_UNITS:
    text = open(os.path.join(SYSTEMD, unit)).read()
    if "network-pre.target" in text or "Before=network" in text:
        bad(f"{unit} orders before the network",
            "found the pre-network ordering that breaks nexthop routing")
    elif ("After=network-online.target" in text
          and "Wants=network-online.target" in text):
        ok(f"{unit} starts after network-online.target")
    else:
        bad(f"{unit} network ordering",
            "expected Wants= and After=network-online.target")

openrc = open(os.path.join(REPO, "packaging", "openrc", "shorewall.init")).read()
# Check the depend() directives, not the surrounding comments.
directives = [ln.strip() for ln in openrc.splitlines()
              if ln.strip().startswith(("before ", "after ", "need "))]
if any(d.startswith("before ") and "net" in d.split() for d in directives):
    bad("openrc init orders before net", "would break nexthop routing")
elif any(d.startswith("after ") and "net" in d.split() for d in directives):
    ok("openrc init orders after net")
else:
    bad("openrc init network ordering", "expected 'after net' in depend()")

sys.exit(1 if fails else 0)
