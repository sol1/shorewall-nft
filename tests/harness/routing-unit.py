#!/usr/bin/env python3
# _provider_for_route names the provider that an 'ip route get' result landed
# on, so 'shorewall show routing <dest>' can tell an operator which provider a
# flow takes on a multi-ISP box (github: routing query). It reads the table or
# the device out of the route line and maps it to a provider. Pure, so it runs
# without a live kernel.
import os
import sys
from collections import namedtuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft.cli import _provider_for_route  # noqa: E402

fails = 0


def check(name, output, providers, expect):
    global fails
    label = _provider_for_route(output, providers)
    if expect in label:
        print("PASS", name)
    else:
        print("FAIL", name, f"- got {label!r}, wanted {expect!r}")
        fails += 1


P = namedtuple("P", "name number interface")
PROV = [P("exetel", 1, "br0.4001"), P("futurebb", 2, "br1.4002")]

# A provider table named in the result (rt_tables has the name).
check("table by name", "8.8.8.8 via 1.2.3.4 dev br0.4001 table exetel src 9",
      PROV, "provider exetel")
# A provider table named by its number (rt_tables lacks the name).
check("table by number", "8.8.8.8 via 1.2.3.4 dev br1.4002 table 2 src 9",
      PROV, "provider futurebb")
# No table shown, but the device is a provider interface (the balance case).
check("device only", "8.8.8.8 via 1.2.3.4 dev br1.4002 src 9",
      PROV, "provider futurebb")
# The balanced default table.
check("balance table", "8.8.8.8 via 1.2.3.4 dev br0.4001 table balance src 9",
      PROV, "balanced default")
# A local or main route is not a provider.
check("local route", "127.0.0.1 dev lo table local src 127.0.0.1",
      PROV, "no provider")
check("main route", "10.0.0.5 dev eth9 src 10.0.0.1",
      PROV, "no provider")
# No providers configured at all.
check("no providers", "8.8.8.8 via 1.2.3.4 dev eth0 table main src 9",
      [], "no provider")

sys.exit(1 if fails else 0)
