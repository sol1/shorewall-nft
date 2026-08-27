#!/usr/bin/env python3
# Coverage for documented Shorewall configuration forms: each must compile
# and the emitted ruleset must load with nft -c. This exercises the config
# surface the differential corpus does not, where documented forms were
# silently breaking (rejected at compile, or emitting a ruleset nft refuses).
# A form that only shorewall-nft cannot express yet must fail with a located
# ConfigError, never a traceback and never an unloadable ruleset.
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                "..", "..", "src"))
from shorewall_nft import capabilities  # noqa: E402
from shorewall_nft.compile import load  # noqa: E402
from shorewall_nft.emit import render  # noqa: E402
from shorewall_nft.errors import ConfigError  # noqa: E402
from shorewall_nft.reader import resolve_include  # noqa: E402

REPO = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")
BASE = os.path.join(REPO, "tests/corpus/0002-one-interface/config")
fails = 0


def ok(name):
    print("PASS", name)


def bad(name, msg=""):
    global fails
    print("FAIL", name, ("- " + msg) if msg else "")
    fails += 1


def build(overrides):
    d = tempfile.mkdtemp(prefix="shorewall-nft-forms-")
    shutil.copytree(BASE, d, dirs_exist_ok=True)
    for name, text in overrides.items():
        with open(os.path.join(d, name), "w") as f:
            f.write(text)
    return d


def nft_loads(text):
    """True if nft -c accepts the ruleset, run in a throwaway namespace."""
    f = tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False)
    f.write(text)
    f.close()
    try:
        r = subprocess.run(["unshare", "-r", "-n", "/usr/sbin/nft", "-c",
                            "-f", f.name], capture_output=True, text=True)
        return r.returncode == 0, r.stderr.strip()[-200:]
    finally:
        os.unlink(f.name)


def form_rejected(name, overrides, family=4):
    """A documented form we do not implement yet must fail with a located
    ConfigError, never a traceback and never a silently wrong ruleset."""
    d = build(overrides)
    try:
        render(load(d, family))
    except ConfigError:
        ok(name)
        return
    except Exception as e:                       # noqa: BLE001
        bad(name, f"traceback instead of ConfigError: {type(e).__name__}")
        return
    finally:
        shutil.rmtree(d)
    bad(name, "compiled, but is not supported (should be a located error)")


def form_ok(name, overrides, family=4, expect=None):
    """A documented form must compile and its ruleset must load. expect is a
    substring that must appear in the emitted ruleset when given."""
    d = build(overrides)
    try:
        text = render(load(d, family))
    except ConfigError as e:
        bad(name, f"compile rejected it: {str(e)[:120]}")
        return
    except Exception as e:                       # noqa: BLE001
        bad(name, f"traceback: {type(e).__name__}: {str(e)[:120]}")
        return
    finally:
        shutil.rmtree(d)
    loads, msg = nft_loads(text)
    if not loads:
        bad(name, f"nft rejected the ruleset: {msg}")
        return
    if expect and expect not in text:
        bad(name, f"expected {expect!r} in output")
        return
    ok(name)


# --- policy all+/any+ (include intra-zone), a documented catch-all ---
POLICY_ZONES = {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
                "interfaces": "?FORMAT 2\nnet eth0\nloc eth1\n"}
form_ok("policy: all+ all+ catch-all compiles and loads",
        {**POLICY_ZONES, "policy": "all+ all+ DROP\n"})

# --- CONNLIMIT: the documented [d:][!]limit[:mask] grammar ---
for spec in ("10", "!10", "10:24", "d:10"):
    form_ok(f"rules: CONNLIMIT {spec} compiles and loads",
            {"rules": f"?SECTION NEW\nACCEPT net $FW tcp 22 - - - - - {spec}\n"})

# --- TIME: a non-wrapping local window loads (a UTC-wrapping one is a
# located error on an offset box, tested separately) ---
form_ok("rules: TIME evening window compiles and loads",
        {"rules": "?SECTION NEW\nACCEPT net $FW tcp 22 - - - - - - "
         "timestart=19:00&timestop=23:00\n"})

# --- accounting: any/all keywords and a bare address source ---
form_ok("accounting: any/all source and dest compile and load",
        {"accounting": "COUNT - any any\n"})
form_ok("accounting: a bare-address source compiles and loads",
        {"accounting": "ACCOUNT(webtraffic,0.0.0.0/0) - 192.168.1.1 -\n"})

# --- tcpri: a ~MAC address is documented ---
form_ok("tcpri: a ~MAC address compiles and loads",
        {"tcdevices": "eth0 100mbit 100mbit\n",
         "tcclasses": "eth0:1 - 10mbit 100mbit 1\n",
         "tcpri": "1 - - - ~44-55-66-77-88-99 eth0\n"})

# --- USER: a real user (root always exists so nft skuid resolves it) ---
form_ok("rules: USER value compiles and loads",
        {"rules": "?SECTION NEW\nACCEPT $FW net tcp 22 - - - root\n"})

# --- CONNLIMIT with a negated limit must load (nft has no `until`) ---
form_ok("rules: CONNLIMIT !limit loads (no invalid nft keyword)",
        {"rules": "?SECTION NEW\nDROP net $FW tcp 22 - - - - - !10\n"})

# --- rules: the 'all'/'any' meta-zone carrying an address restriction, e.g.
#     DROP net all:192.168.45.0/24 (reported on shorewall-users) ---
form_ok("rules: dest all:<net> compiles, loads, applies the address",
        {"rules": "?SECTION NEW\nDROP net all:192.168.45.0/24\n"},
        expect="192.168.45.0/24")
form_ok("rules: source all:<net> compiles, loads, applies the address",
        {"rules": "?SECTION NEW\nDROP all:10.0.0.0/8 net\n"},
        expect="10.0.0.0/8")

# --- rpfilter: reverse-path anti-spoofing is enforced, not just accepted
#     (shorewall-users). The fib check and its ruleset must load. ---
form_ok("interfaces: rpfilter emits a reverse-path drop that loads",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet eth0 rpfilter\nloc eth1\n"},
        expect="fib saddr . iif oif missing drop")
form_ok("interfaces: rpfilter lets the DHCP client handshake through",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet eth0 rpfilter,dhcp\nloc eth1\n"},
        expect="ip saddr 0.0.0.0 udp dport 67 return")

# --- SOURCE/DEST forms from shorewall-addresses(5) and shorewall-exclusion(5)
# that regressed after 0.1.0 ---

# A REDIRECT/DNAT sourced from $FW (the firewall redirecting its own output,
# the transparent-proxy pattern) is documented and must compile.
form_ok("rules: a $FW-sourced REDIRECT compiles and loads",
        {"rules": "?SECTION NEW\nREDIRECT $FW 3128 tcp 80\n"},
        expect="hook output priority -100")

# A one-to-one NAT with LOCAL=Yes (shorewall-nat(5)) also DNATs the firewall's
# own output, so it hooks output too. That chain must use a numeric priority,
# not the dstnat name, which nft 1.0.2 rejects at the output hook.
form_ok("nat: a LOCAL one-to-one NAT compiles and loads",
        {"nat": "10.0.0.1 NET_IF 10.0.1.2 No Yes\n"},
        expect="hook output priority -110")

# A policy SOURCE/DEST zone exclusion (all!zone) is documented since 4.4.13
# but not implemented in the emitter yet; it must fail with a clear located
# error, not a misleading message or a misapplied policy.
ZONES4 = {"zones": "fw firewall\nnet ipv4\nloc ipv4\ndmz ipv4\n",
          "interfaces": "?FORMAT 2\nnet eth0\nloc eth1\ndmz eth2\n"}
form_rejected("policy: an all!zone exclusion is a clear located error",
              {**ZONES4, "policy": "loc all!dmz REJECT\nall all ACCEPT\n"})

# An accounting SOURCE of interface:address is the documented combined form.
form_ok("accounting: an interface:address source compiles and loads",
        {"accounting": "COUNT accounting eth0:192.168.1.0/24\n"})

# --- rules: zone:interface:address, the three-part SOURCE/DEST form
# (shorewall-rules(5)). Both the interface and the address must match. The base
# zone net is on interface NET_IF (physical eth0). ---
form_ok("rules: zone:interface:address SOURCE matches iif and saddr",
        {"rules": "?SECTION NEW\nACCEPT net:NET_IF:10.0.0.5 $FW tcp 22\n"},
        expect='iifname "eth0" ip saddr 10.0.0.5')
form_ok("rules: zone:interface:address DEST matches oif and daddr",
        {"rules": "?SECTION NEW\nACCEPT $FW net:NET_IF:10.0.0.5 tcp 22\n"},
        expect='oifname "eth0" ip daddr 10.0.0.5')
form_ok("rules: zone:interface:address with an address list",
        {"rules": "?SECTION NEW\nACCEPT net:NET_IF:10.0.0.5,10.0.0.6 $FW tcp 22\n"},
        expect='iifname "eth0" ip saddr { 10.0.0.5, 10.0.0.6 }')
form_ok("rules: zone:!interface:address negates the interface, keeps the addr",
        {"rules": "?SECTION NEW\nACCEPT net:!NET_IF:10.0.0.5 $FW tcp 22\n"},
        expect='iifname != "eth0" ip saddr 10.0.0.5')

# The same form in IPv6: the address has colons too, so the disambiguation
# (left part is an interface only if it is in the interface map) matters.
# A family=6 load reads shorewall6.conf, which the base does not carry, so give
# a plain policy that does not lean on the base $LOG_LEVEL from shorewall.conf.
V6 = {"zones": "fw firewall\nnet ipv6\n",
      "interfaces": "?FORMAT 2\nnet NET_IF physical=eth0\n",
      "policy": "$FW net ACCEPT\nnet all DROP\nall all REJECT\n"}
form_ok("rules: zone:interface:address in IPv6 matches iif and ip6 saddr",
        {**V6, "rules": "?SECTION NEW\nACCEPT net:NET_IF:2001:db8::5 $FW tcp 22\n"},
        family=6, expect='iifname "eth0" ip6 saddr 2001:db8::5')
form_ok("rules: a bare IPv6 address is not mistaken for an interface",
        {**V6, "rules": "?SECTION NEW\nACCEPT net:2001:db8::5 $FW tcp 22\n"},
        family=6, expect="ip6 saddr 2001:db8::5")

# An unknown interface in the three-part form is a located error, not a
# silently wrong ruleset (the token is not in the interface map, so it cannot
# be an address either).
form_rejected("rules: zone:interface:address with an unknown interface",
              {"rules": "?SECTION NEW\nACCEPT net:BADIF:10.0.0.5 $FW tcp 22\n"})

# --- policy: the RATE LIMIT and CONNLIMIT columns (shorewall-policy(5)),
# rejected before. They gate the policy the way a rule's columns do: only
# under-rate and under-limit packets are logged and take the verdict, and the
# excess falls through to the base chain policy (shorewall-users). A colon in
# the LOGLEVEL is rejected, matching upstream, since policy log tags are not a
# thing. ---
form_ok("policy: a RATE LIMIT column rate-limits the policy",
        {"policy": "$FW net ACCEPT\nnet all DROP info 10/sec:20\nall all REJECT\n"},
        expect="limit rate 10/second burst 20 packets")
form_ok("policy: a CONNLIMIT column caps concurrent connections",
        {"policy": "$FW net ACCEPT\nnet all DROP info - 8\nall all REJECT\n"},
        expect="ct count 8")
form_rejected("policy: a level:tag LOGLEVEL is rejected, as upstream does",
              {"policy": "$FW net ACCEPT\nnet all DROP info:blocked\nall all REJECT\n"})

# --- zones: the OPTIONS / IN OPTIONS / OUT OPTIONS columns (shorewall-zones(5))
# are accepted so real configs compile, instead of rejecting the whole file.
# mss and blacklist warn (not applied yet); an unknown option is a located
# error (shorewall-users). ---
form_ok("zones: an OPTIONS column (blacklist) compiles and loads",
        {"zones": "fw firewall\nnet ipv4 - blacklist\n",
         "interfaces": "?FORMAT 2\nnet eth0\n"})
form_rejected("zones: an unknown zone option is a located error",
              {"zones": "fw firewall\nnet ipv4 - bogusopt\n",
               "interfaces": "?FORMAT 2\nnet eth0\n"})

# --- zones: an IPSEC zone (site-to-site, keyed by reqid). Its dispatch is
# scoped to the SA, so cleartext on the tunnel interface is not in the zone.
# Inbound matches ipsec in reqid N, outbound ipsec out reqid N (sol1). ---
_IPSEC = {"zones": "fw firewall\nnet ipv4\ntun ipsec reqid=100\n",
          "interfaces": "?FORMAT 2\nnet eth0\ntun eth1\n",
          "policy": ("$FW net ACCEPT\n$FW tun ACCEPT\nnet all DROP\n"
                     "tun all DROP\nall all REJECT\n")}
form_ok("zones: an ipsec zone scopes inbound to ipsec in reqid",
        {**_IPSEC, "rules": "?SECTION NEW\nACCEPT tun $FW tcp 22\n"},
        expect='iifname "eth1" ipsec in reqid 100 jump')
form_ok("zones: an ipsec zone scopes outbound to ipsec out reqid",
        {**_IPSEC, "rules": "?SECTION NEW\n"},
        expect='oifname "eth1" ipsec out reqid 100 jump')
form_ok("zones: a forward pair through an ipsec zone scopes both directions",
        {**_IPSEC, "rules": "?SECTION NEW\nACCEPT tun net\n"},
        expect='iifname "eth1" ipsec in reqid 100 oifname "eth0"')
# spi= keys the SA by its SPI instead of a reqid.
form_ok("zones: an ipsec zone can key on spi",
        {**{**_IPSEC, "zones": "fw firewall\nnet ipv4\ntun ipsec spi=256\n"},
         "rules": "?SECTION NEW\nACCEPT tun $FW tcp 22\n"},
        expect='iifname "eth1" ipsec in spi 256 jump')
# mode=tunnel with tunnel-src/dst matches the outer addresses at the tunnel SA
# stack level (spnum 0).
form_ok("zones: tunnel-src/dst match the outer addresses via spnum",
        {**{**_IPSEC, "zones": "fw firewall\nnet ipv4\n"
            "tun ipsec mode=tunnel,tunnel-src=203.0.113.1,tunnel-dst=203.0.113.2\n"},
         "rules": "?SECTION NEW\nACCEPT tun $FW tcp 22\n"},
        expect="ipsec in spnum 0 ip saddr 203.0.113.1 ip daddr 203.0.113.2")
# proto= has no nftables ipsec selector, so it is refused rather than dropped.
form_rejected("zones: proto= on an ipsec zone is a located error (no nft match)",
              {**_IPSEC, "zones": "fw firewall\nnet ipv4\n"
               "tun ipsec reqid=100,proto=esp\n",
               "rules": "?SECTION NEW\nACCEPT tun $FW tcp 22\n"})
# A bare (any-SA) ipsec zone cannot be a destination: nft has no outbound
# any-SA match, so using it as a dest is a located error.
form_rejected("zones: a bare ipsec zone as a destination is refused",
              {"zones": "fw firewall\nnet ipv4\ntun ipsec\n",
               "interfaces": "?FORMAT 2\nnet eth0\ntun eth1\n",
               "policy": "$FW net ACCEPT\nall all DROP\n"})
# An ipsec SA selector on a plain (non-ipsec) zone is a located error, as
# upstream requires.
form_rejected("zones: an ipsec option on a plain zone is a located error",
              {"zones": "fw firewall\nnet ipv4 reqid=5\n",
               "interfaces": "?FORMAT 2\nnet eth0\n"})
# On an nft without the ipsec match (0.9.0), an ipsec zone is refused with a
# located error rather than emitted as a rule that cannot load, the same as
# NETMAP and ECN on an nft too old to express them.
capabilities.CAPABILITIES["NFT_IPSEC"] = False
try:
    form_rejected("zones: an ipsec zone is refused where nft lacks the match",
                  {**_IPSEC, "rules": "?SECTION NEW\nACCEPT tun $FW tcp 22\n"})
finally:
    capabilities.CAPABILITIES["NFT_IPSEC"] = True

# --- tunnels file: an ipsec tunnel opens IKE and ESP to the peer gateway in
# the gateway's cleartext zone, so the arriving ESP is accepted and the kernel
# can decrypt it. Without this the ipsec zone never receives traffic. Follows
# upstream Tunnels.pm: proto 50 (ESP), 51 (AH), udp 500 (IKE), and 500,4500
# for ipsecnat. Corpus 0061 proves the decrypted traffic then matches. ---
form_ok("tunnels: an ipsec tunnel opens ESP inbound from the gateway",
        {**_IPSEC, "tunnels": "ipsec net 10.0.9.2\n"},
        expect="ip saddr 10.0.9.2 meta l4proto 50 accept")
form_ok("tunnels: an ipsec tunnel opens IKE inbound from the gateway",
        {**_IPSEC, "tunnels": "ipsec net 10.0.9.2\n"},
        expect="ip saddr 10.0.9.2 udp dport 500 accept")
form_ok("tunnels: an ipsec tunnel opens ESP outbound to the gateway",
        {**_IPSEC, "tunnels": "ipsec net 10.0.9.2\n"},
        expect="ip daddr 10.0.9.2 meta l4proto 50 accept")
form_ok("tunnels: an ipsec tunnel opens AH, upstream proto 51",
        {**_IPSEC, "tunnels": "ipsec net 10.0.9.2\n"},
        expect="ip saddr 10.0.9.2 meta l4proto 51 accept")
form_ok("tunnels: ipsecnat opens IKE and the NAT-T port 4500",
        {**_IPSEC, "tunnels": "ipsecnat net 10.0.9.2\n"},
        expect="udp dport { 500, 4500 } accept")

# --- zones: a cleartext zone sharing an interface with an ipsec zone (the
# --pol none companion). Decrypted traffic carries a secpath and belongs to
# the ipsec zone, so the cleartext inbound dispatch excludes it with
# `meta secpath missing`, and the ipsec rule sorts first. This is what makes
# per-host encryption correct: net is cleartext on eth0, vpn is the ipsec
# peer on the same eth0 by a hosts entry. ---
_SHARED = {"zones": "fw firewall\nnet ipv4\nvpn ipsec reqid=100\n",
           "interfaces": "?FORMAT 2\nnet eth0\n",
           "hosts": "vpn eth0:0.0.0.0/0 ipsec\n",
           "policy": ("$FW net ACCEPT\n$FW vpn ACCEPT\nnet all DROP\n"
                      "vpn all DROP\nall all REJECT\n"),
           "rules": "?SECTION NEW\nACCEPT vpn $FW tcp 22\n"}


def shared_iface_coexistence():
    name = "zones: a cleartext zone shares an ipsec interface safely"
    d = build(_SHARED)
    try:
        text = render(load(d, 4))
    except Exception as e:                           # noqa: BLE001
        bad(name, f"compile failed: {type(e).__name__}: {str(e)[:120]}")
        return
    finally:
        shutil.rmtree(d)
    loads, msg = nft_loads(text)
    if not loads:
        bad(name, f"nft rejected the ruleset: {msg}")
        return
    lines = text.splitlines()
    # Inbound: the cleartext dispatch excludes decrypted traffic.
    net_in = next((i for i, l in enumerate(lines)
                   if 'iifname "eth0" meta secpath missing jump net' in l),
                  None)
    vpn_in = next((i for i, l in enumerate(lines)
                   if 'iifname "eth0"' in l and "ipsec in reqid 100 jump vpn"
                   in l), None)
    if net_in is None:
        bad(name, "cleartext inbound rule lacks meta secpath missing")
        return
    if vpn_in is None or vpn_in > net_in:
        bad(name, "the ipsec inbound rule must sort before the cleartext rule")
        return
    # Outbound: no nft secpath match exists, so the cleartext rule carries no
    # guard, but the ipsec-out rule sorts first to catch to-be-encrypted
    # packets by the positive match.
    vpn_out = next((i for i, l in enumerate(lines)
                    if 'oifname "eth0"' in l and "ipsec out reqid 100" in l),
                   None)
    net_out = next((i for i, l in enumerate(lines)
                    if l.strip() == 'oifname "eth0" jump fw2net'), None)
    if vpn_out is None or net_out is None or vpn_out > net_out:
        bad(name, "the ipsec outbound rule must sort before the cleartext rule")
        return
    ok(name)


shared_iface_coexistence()

# --- rules: address exclusion (shorewall-exclusion(5)). A leading ! is the
# pure-exclusion case; included!excluded matches the include and not the
# exclude. Both lists may be comma-separated. ---
form_ok("rules: a pure !exclusion matches everything but the list",
        {"rules": "?SECTION NEW\nACCEPT net:!10.0.0.0/24 $FW tcp 22\n"},
        expect="ip saddr != 10.0.0.0/24")
form_ok("rules: included!excluded matches the include and not the exclude",
        {"rules": "?SECTION NEW\n"
         "ACCEPT net:155.186.235.0/24!155.186.235.16/28 $FW tcp 22\n"},
        expect="ip saddr 155.186.235.0/24 ip saddr != 155.186.235.16/28")
form_ok("rules: included!excluded with a multi-address exclude list",
        {"rules": "?SECTION NEW\n"
         "ACCEPT net:10.0.0.0/8!10.1.0.0/16,10.2.0.0/16 $FW tcp 22\n"},
        expect="ip saddr 10.0.0.0/8 ip saddr != { 10.1.0.0/16, 10.2.0.0/16 }")
# --- rules: AllowICMPs, a standard action that accepts the needed ICMP types
# (bug #14). On IPv4 it jumps a chain that accepts destination-unreachable
# code frag-needed and time-exceeded, matching upstream --icmp-type 3/4 and
# 11. The old macro.A_AllowICMPs emitted `icmp type fragmentation-needed`,
# which nft rejects; the type-and-code mapping now makes it load. ---
form_ok("rules: AllowICMPs jumps the needed-ICMP chain",
        {"rules": "?SECTION NEW\nAllowICMPs net $FW\n"},
        expect="meta l4proto icmp jump AllowICMPs")
form_ok("rules: the AllowICMPs chain accepts destination-unreachable",
        {"rules": "?SECTION NEW\nAllowICMPs net $FW\n"},
        expect="icmp type destination-unreachable accept")
form_ok("rules: A_AllowICMPs (audit twin) loads, no unparsable icmp type",
        {"rules": "?SECTION NEW\nA_AllowICMPs net $FW\n"},
        expect="icmp type destination-unreachable log level audit accept")
form_rejected("rules: AllowICMPs with a parameter is a located error",
              {"rules": "?SECTION NEW\nAllowICMPs(DROP) net $FW\n"})
# --- rules: the conntrack-state actions. Each matches ct state and applies
# its parameter as the disposition. New and Established default to accept,
# Related, Invalid and Untracked to drop, matching upstream. ---
form_ok("rules: New defaults to accepting the NEW state",
        {"rules": "?SECTION NEW\nNew net $FW\n"},
        expect="ct state new accept")
form_ok("rules: Established defaults to accept",
        {"rules": "?SECTION NEW\nEstablished net $FW\n"},
        expect="ct state established accept")
form_ok("rules: Related defaults to drop",
        {"rules": "?SECTION NEW\nRelated net $FW\n"},
        expect="ct state related drop")
form_ok("rules: Untracked defaults to drop",
        {"rules": "?SECTION NEW\nUntracked net $FW\n"},
        expect="ct state untracked drop")
form_ok("rules: a state action takes a disposition parameter",
        {"rules": "?SECTION NEW\nNew(DROP) net $FW\n"},
        expect="ct state new drop")
form_ok("rules: allowInvalid accepts the INVALID state",
        {"rules": "?SECTION NEW\nallowInvalid net $FW\n"},
        expect="ct state invalid accept")
form_ok("rules: dropInvalid audit twin logs before dropping",
        {"rules": "?SECTION NEW\ndropInvalid(audit) net $FW\n"},
        expect="ct state invalid log level audit drop")
form_ok("rules: an A_ disposition on a state action audits then accepts",
        {"rules": "?SECTION NEW\nNew(A_ACCEPT) net $FW\n"},
        expect="ct state new log level audit accept")
form_rejected("rules: a bad state-wrapper parameter is a located error",
              {"rules": "?SECTION NEW\ndropInvalid(bogus) net $FW\n"})
# --- rules: the Broadcast and Multicast actions. They match the destination
# address type (fib daddr type) and apply the disposition, defaulting to
# drop. Broadcast covers broadcast and anycast, Multicast covers multicast,
# matching upstream -m addrtype --dst-type. ---
form_ok("rules: Broadcast drops the broadcast and anycast dest types",
        {"rules": "?SECTION NEW\ndropBcast net $FW\n"},
        expect="fib daddr type broadcast drop")
form_ok("rules: Broadcast covers the anycast type too",
        {"rules": "?SECTION NEW\ndropBcast net $FW\n"},
        expect="fib daddr type anycast drop")
form_ok("rules: Multicast drops the multicast dest type",
        {"rules": "?SECTION NEW\ndropMcast net $FW\n"},
        expect="fib daddr type multicast drop")
form_ok("rules: allowMcast accepts the multicast dest type",
        {"rules": "?SECTION NEW\nallowMcast net $FW\n"},
        expect="fib daddr type multicast accept")
form_ok("rules: Broadcast takes an explicit disposition",
        {"rules": "?SECTION NEW\nBroadcast(REJECT) net $FW\n"},
        expect="fib daddr type broadcast jump reject_action")
form_ok("rules: a Bcast wrapper audit parameter logs before dropping",
        {"rules": "?SECTION NEW\ndropBcast(audit) net $FW\n"},
        expect="fib daddr type broadcast log level audit drop")
form_rejected("rules: a bad Broadcast disposition is a located error",
              {"rules": "?SECTION NEW\nBroadcast(bogus) net $FW\n"})
# --- rules: the TCP-flag actions. They match a TCP flag combination and apply
# a disposition, matching upstream's --tcp-flags checks. ---
form_ok("rules: RST matches the RST flag and drops by default",
        {"rules": "?SECTION NEW\nRST net $FW\n"},
        expect="meta l4proto tcp tcp flags & rst == rst drop")
form_ok("rules: FIN matches ACK,FIN and accepts by default",
        {"rules": "?SECTION NEW\nFIN net $FW\n"},
        expect="tcp flags & (ack|fin) == ack|fin accept")
form_ok("rules: dropNotSyn drops a non-SYN packet",
        {"rules": "?SECTION NEW\ndropNotSyn net $FW\n"},
        expect="tcp flags & (fin|syn|rst|ack) != syn drop")
form_ok("rules: NotSyn takes a disposition parameter",
        {"rules": "?SECTION NEW\nNotSyn(ACCEPT) net $FW\n"},
        expect="tcp flags & (fin|syn|rst|ack) != syn accept")
form_ok("rules: rejNotSyn rejects a non-SYN packet",
        {"rules": "?SECTION NEW\nrejNotSyn net $FW\n"},
        expect="tcp flags & (fin|syn|rst|ack) != syn jump reject_action")
form_ok("rules: TCPFlags drops the xmas scan combination",
        {"rules": "?SECTION NEW\nTCPFlags net $FW\n"},
        expect="tcp flags & (fin|syn|rst|psh|ack|urg) == fin|psh|urg drop")
form_ok("rules: TCPFlags drops the null scan combination",
        {"rules": "?SECTION NEW\nTCPFlags net $FW\n"},
        expect="tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop")
form_ok("rules: TCPFlags audit twin logs before dropping",
        {"rules": "?SECTION NEW\nTCPFlags(audit) net $FW\n"},
        expect="tcp flags & (syn|rst) == syn|rst log level audit drop")
form_ok("rules: A_REJECT audits then rejects",
        {"rules": "?SECTION NEW\nA_REJECT net $FW\n"},
        expect="log level audit jump reject_action")
form_rejected("rules: a bad TCPFlags parameter is a located error",
              {"rules": "?SECTION NEW\nTCPFlags(bogus) net $FW\n"})
# --- rules: Tier-2 service and drop actions. ---
form_ok("rules: DropDNSrep drops UDP from source port 53",
        {"rules": "?SECTION NEW\nDropDNSrep net $FW\n"},
        expect="udp sport 53 drop")
form_ok("rules: DropSmurfs drops a broadcast source",
        {"rules": "?SECTION NEW\nDropSmurfs net $FW\n"},
        expect="fib saddr type broadcast drop")
form_ok("rules: DropSmurfs drops a multicast source range",
        {"rules": "?SECTION NEW\nDropSmurfs net $FW\n"},
        expect="ip saddr 224.0.0.0/4 drop")
form_ok("rules: GlusterFS opens the base gluster ports",
        {"rules": "?SECTION NEW\nGlusterFS net $FW\n"},
        expect="tcp dport 38465-38467 accept")
form_ok("rules: GlusterFS brick count sizes the high port range",
        {"rules": "?SECTION NEW\nGlusterFS(4) net $FW\n"},
        expect="tcp dport 49151-49154 accept")
form_rejected("rules: a bad GlusterFS brick count is a located error",
              {"rules": "?SECTION NEW\nGlusterFS(9999) net $FW\n"})
# Limit and BLACKLIST are not expressible yet; they must fail with a located
# error naming the action, not the generic 'unsupported action or macro'.
form_rejected("rules: Limit fails loud pointing at the RATE LIMIT column",
              {"rules": "?SECTION NEW\nLimit net $FW\n"})
form_rejected("rules: BLACKLIST fails loud (needs dynamic blacklisting)",
              {"rules": "?SECTION NEW\nBLACKLIST net $FW\n"})
# --- rules: AutoBL auto-blacklists a source that exceeds a rate, with a
# dynamic set and a rate meter (github #21). ---
_AB = "AutoBL(SSH,60,5,2,300,DROP,warn) net $FW tcp 22\n"
form_ok("rules: AutoBL declares the dynamic blacklist set",
        {"rules": "?SECTION NEW\n" + _AB},
        expect="set autobl_SSH {")
form_ok("rules: AutoBL drops an already-blacklisted source",
        {"rules": "?SECTION NEW\n" + _AB},
        expect="ip saddr @autobl_SSH drop")
form_ok("rules: AutoBL adds a rate-exceeding source to the set",
        {"rules": "?SECTION NEW\n" + _AB},
        expect="limit rate over 5/minute } add @autobl_SSH "
               "{ ip saddr timeout 300s }")
form_ok("rules: AutoBL accepts normal under-rate traffic",
        {"rules": "?SECTION NEW\n" + _AB},
        expect="tcp dport 22 accept")
form_ok("rules: an hourly AutoBL interval maps to the hour unit",
        {"rules": "?SECTION NEW\nAutoBL(HTTP,3600,20,2,600,DROP,info) "
         "net $FW tcp 80\n"},
        expect="limit rate over 20/hour")
form_rejected("rules: AutoBL without an event name is a located error",
              {"rules": "?SECTION NEW\nAutoBL(,60,5,2,300,DROP,info) "
               "net $FW tcp 22\n"})
form_rejected("rules: a non-numeric AutoBL count is a located error",
              {"rules": "?SECTION NEW\nAutoBL(SSH,60,x,2,300,DROP,info) "
               "net $FW tcp 22\n"})
# On an nft without dynamic-set and meter support (0.9.0), AutoBL is refused
# with a located error rather than an unloadable ruleset, like NETMAP.
capabilities.CAPABILITIES["NFT_AUTOBL"] = False
try:
    form_rejected("rules: AutoBL is refused where nft lacks the meter support",
                  {"rules": "?SECTION NEW\n" + _AB})
finally:
    capabilities.CAPABILITIES["NFT_AUTOBL"] = True
    # --- rules: native port knocking. Knock packets are handled in an early
    # prerouting chain and the protected service is gated in the zone chain. ---
    form_ok("rules: TCP Knock declares and updates its state set",
        {"rules": "?SECTION NEW\nKNOCK(7000,tcp,timeout=30) net $FW tcp 22\n"},
        expect="set knock_1 {")
    form_ok("rules: UDP Knock uses the knock protocol independently",
        {"rules": "?SECTION NEW\nKNOCK(7000,udp,timeout=30) net $FW tcp 22\n"},
        expect="udp dport 7000")
    form_ok("rules: Knock gates the protected service",
        {"rules": "?SECTION NEW\nKNOCK(7000,tcp,timeout=30) net $FW tcp 22\n"},
        expect="tcp dport 22 ct state new ip saddr @knock_1 accept")
    form_ok("rules: Knock reusable=no consumes authorization",
        {"rules": "?SECTION NEW\nKNOCK(7000,tcp,timeout=30,reusable=no) "
               "net $FW tcp 22\n"},
        expect="delete @knock_1 { ip saddr }")
    form_ok("rules: uniform TCP KnockSequence parses",
        {"rules": "?SECTION NEW\nKNOCKSEQUENCE(7000,8000,9000,tcp,timeout=30) "
               "net $FW tcp 22\n"},
        expect="tcp dport 8000")
    form_ok("rules: mixed TCP and UDP KnockSequence parses",
        {"rules": "?SECTION NEW\nKNOCKSEQUENCE(7000,tcp,8000,udp,9000,tcp,"
               "timeout=30) net $FW tcp 22\n"},
        expect="udp dport 8000")
    form_ok("rules: KnockSequence accepts a prefixed NFLOG",
        {"rules": "?SECTION NEW\nKNOCKSEQUENCE(7000,8000,tcp,timeout=30,"
               "nflog=security-knock:5:128:1) net $FW tcp 22\n"},
        expect='log prefix "security-knock" group 5 snaplen 128 '
               "queue-threshold 1")
    form_ok("rules: Knock accepts an unprefixed NFLOG",
        {"rules": "?SECTION NEW\nKNOCK(7000,tcp,timeout=30,nflog=5:128:1) "
               "net $FW tcp 22\n"},
        expect='log prefix "shorewall:knock" group 5 snaplen 128 '
               "queue-threshold 1")
    form_rejected("rules: incomplete mixed KNOCKSEQUENCE is rejected",
              {"rules": "?SECTION NEW\nKNOCKSEQUENCE(7000,udp,8000,9000,tcp,"
                "timeout=30) net $FW tcp 22\n"})
    form_rejected("rules: KNOCK rejects an invalid protocol",
              {"rules": "?SECTION NEW\nKNOCK(7000,icmp) net $FW tcp 22\n"})
form_rejected("rules: mixed-case knocking action is not native",
              {"rules": "?SECTION NEW\nKnockSequence(7000,8000,tcp) "
                        "net $FW tcp 22\n"})
form_ok("rules: interface then included!excluded together",
        {"rules": "?SECTION NEW\n"
         "ACCEPT net:NET_IF:10.0.0.0/24!10.0.0.5 $FW tcp 22\n"},
        expect='iifname "eth0" ip saddr 10.0.0.0/24 ip saddr != 10.0.0.5')
form_ok("rules: a DEST exclusion negates the destination",
        {"rules": "?SECTION NEW\nACCEPT $FW net:10.0.0.0/8!10.1.0.0/16 tcp 22\n"},
        expect="ip daddr 10.0.0.0/8 ip daddr != 10.1.0.0/16")
# The exclusion ! must not swallow a negated geoip code (^!CC), which carries
# its own ! and is not an address.
form_ok("rules: ^!CC stays a negated geoip, not an exclusion",
        {"rules": "?SECTION NEW\nACCEPT net:^!de $FW tcp 22\n"},
        expect="ip saddr != @geoip_de")
# A trailing ! with no exclude list is malformed and must be a located error.
form_rejected("rules: a trailing ! with no exclusion is a located error",
              {"rules": "?SECTION NEW\nACCEPT net:10.0.0.0/8! $FW tcp 22\n"})

# --- rules: zone:(...) grouping (shorewall-rules(5), 5.1.0+). A grouping
# wrapper for a single source-spec; upstream compiles net:(X) exactly as
# net:X, so we strip the parentheses and reuse the inner handling. ---
form_ok("rules: zone:(interface) is the bare interface form",
        {"rules": "?SECTION NEW\nACCEPT net:(NET_IF) $FW tcp 22\n"},
        expect='iifname "eth0"')
form_ok("rules: zone:(interface:address,address) groups iface and a list",
        {"rules": "?SECTION NEW\nACCEPT net:(NET_IF:10.0.2.5,10.0.2.6) $FW tcp 22\n"},
        expect='iifname "eth0" ip saddr { 10.0.2.5, 10.0.2.6 }')
form_ok("rules: zone:(address,address) groups an address list",
        {"rules": "?SECTION NEW\nACCEPT net:(10.0.2.5,10.0.3.5) $FW tcp 22\n"},
        expect="ip saddr { 10.0.2.5, 10.0.3.5 }")
form_ok("rules: zone:(included!excluded) groups an exclusion",
        {"rules": "?SECTION NEW\nACCEPT net:(10.0.2.0/24!10.0.2.9) $FW tcp 22\n"},
        expect="ip saddr 10.0.2.0/24 ip saddr != 10.0.2.9")


# The wrapper must be an exact no-op: net:(X) and net:X emit the same match.
def _match_of(source):
    d = build({"rules": f"?SECTION NEW\nACCEPT {source} $FW tcp 22\n"})
    try:
        line = [l for l in render(load(d, 4)).splitlines() if "dport 22" in l][0]
    finally:
        shutil.rmtree(d)
    return line.split("dport 22")[0].strip()


if _match_of("net:(NET_IF:10.0.2.5,10.0.2.6)") == _match_of("net:NET_IF:10.0.2.5,10.0.2.6"):
    ok("rules: zone:(X) emits exactly the same match as zone:X")
else:
    bad("rules: zone:(X) not identical to zone:X")

# --- rules: &interface, the interface's primary address (shorewall-rules(5)).
# nft cannot match an interface's current address, so we declare an empty set
# and the lifecycle script fills it at load, the way upstream resolves
# $SW_<IF>_ADDRESS at runtime. The base zone net is on NET_IF (physical eth0). ---
form_ok("rules: &interface SOURCE emits an @set match that loads",
        {"rules": "?SECTION NEW\nACCEPT net:&NET_IF $FW tcp 22\n"},
        expect="ip saddr @_ifaddr_eth0")
form_ok("rules: &interface DEST scopes the destination to that address",
        {"rules": "?SECTION NEW\nACCEPT $FW net:&NET_IF tcp 22\n"},
        expect="ip daddr @_ifaddr_eth0")
form_ok("rules: &interface declares the address set empty",
        {"rules": "?SECTION NEW\nACCEPT net:&NET_IF $FW tcp 22\n"},
        expect="set _ifaddr_eth0 {")
form_rejected("rules: &unknown-interface is a located error",
              {"rules": "?SECTION NEW\nACCEPT net:&BADIF $FW tcp 22\n"})

# &interface in a NAT address column (a DNAT ORIGINAL DEST) resolves to the
# same runtime address set, not a literal &name that nft treats as a hostname
# (github #13). The set is declared so the ruleset loads.
form_ok("rules: &interface in a DNAT origdest resolves to the address set",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet NET_IF physical=enp3s0\nloc eth1\n",
         "rules": "?SECTION NEW\nDNAT net loc:127.0.0.1:1883 tcp 1883 - &NET_IF\n"},
        expect="ip daddr @_ifaddr_enp3s0")
# An excluded &interface in a REDIRECT origdest, !&iface, resolves to the same
# set with a negated match, not a literal &name that nft rejects (github #15).
form_ok("rules: !&interface in a REDIRECT origdest is a negated set match",
        {"zones": "fw firewall\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nloc LOC_IF physical=enp0s31f6\n",
         "policy": "loc $FW ACCEPT\nall all REJECT\n",
         "rules": "?SECTION NEW\nREDIRECT loc 2370 tcp ftp - !&LOC_IF\n"},
        expect="ip daddr != @_ifaddr_enp0s31f6")

# --- params: a params file that uses bash logic (a glob loop over .inc
# includes, declare, BASH_SOURCE, [[ ]]) is sourced through bash the way
# upstream sources it, so the variables it builds are available and expand in
# the config (github #11). ---
form_ok("params: a bash-form params file with .inc includes is sourced",
        {"params": 'NET_IF="enp2s0.10"\n. "${g_confdir}/params.common"\n',
         "params.common": ('set +o posix\ndeclare EXT\n'
                           'for EXT in "${BASH_SOURCE[0]}."*".inc"; do\n'
                           '  [[ -f "$EXT" ]] && . "$EXT"\ndone\n'
                           'unset EXT\nset -o posix\n'),
         "params.common.admin.inc": 'SOL1_ADMIN="10.15.0.0/16"\n',
         "rules": "?SECTION NEW\nACCEPT net:$SOL1_ADMIN $FW tcp 22\n"},
        expect="ip saddr 10.15.0.0/16")
# A params file processed through the shell can use command substitution,
# both $(...) and old-style backticks, the way upstream's /bin/sh does
# (shorewall-users). Backticks must trigger the shell path too.
form_ok("params: command substitution with $(...) is evaluated",
        {"params": "PORTVAR=$(echo 2244)\n",
         "rules": "?SECTION NEW\nACCEPT net $FW tcp $PORTVAR\n"},
        expect="tcp dport 2244")
form_ok("params: command substitution with backticks is evaluated",
        {"params": "PORTVAR=`echo 2255`\n",
         "rules": "?SECTION NEW\nACCEPT net $FW tcp $PORTVAR\n"},
        expect="tcp dport 2255")
# ?INCLUDE is the directive spelling of INCLUDE; upstream accepts either.
form_ok("rules: ?INCLUDE pulls in another file",
        {"rules": "?SECTION NEW\n?INCLUDE rules.extra\n",
         "rules.extra": "ACCEPT net $FW tcp 2222\n"},
        expect="tcp dport 2222")

# The generated lifecycle script must fill the set from the live interface.
_d = build({"rules": "?SECTION NEW\nACCEPT net:&NET_IF $FW tcp 22\n"})
try:
    from shorewall_nft.script import render_script  # noqa: E402
    from shorewall_nft.emit import render_stop  # noqa: E402
    _cfg = load(_d, 4)
    _scr = render_script(_cfg, render(_cfg), render_stop(_cfg))
finally:
    shutil.rmtree(_d)
if 'IFACE_ADDR_SETS="_ifaddr_eth0:eth0"' in _scr and "fill_iface_addrs" in _scr:
    ok("&interface: the wrapper fills the address set from the live interface")
else:
    bad("&interface: wrapper missing the fill logic")

# --- rules: a DNAT whose source-zone list names an empty zone (defined but
# with no interface or host) must not reject the whole config. Upstream accepts
# it and generates nothing for the empty zone; we skip it with a warning and
# still emit the rule for the zones that do have interfaces (shorewall-users). ---
form_ok("rules: DNAT from an empty source zone skips it, keeps the rest",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nloc eth1\n",
         "rules": "?SECTION NEW\nDNAT net,loc loc:192.168.122.11 tcp 80,443\n"},
        expect="dnat ip to 192.168.122.11")

# --- rules: the RATE LIMIT column applies to REDIRECT and DNAT, not just to
# filter rules, so rate limiting an incoming connection works. The limit sits
# before the nat verdict, so only under-rate packets are redirected/DNAT'd
# (shorewall-users). ---
form_ok("rules: REDIRECT honours the RATE LIMIT column",
        {"rules": "?SECTION NEW\nREDIRECT net 3128 tcp 8080 - - 1/min:2\n"},
        expect="limit rate 1/minute burst 2 packets redirect to :3128")
form_ok("rules: DNAT honours the RATE LIMIT column",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet eth0\nloc eth1\n",
         "rules": "?SECTION NEW\nDNAT net loc:10.0.0.9 tcp 80 - - 10/min:5\n"},
        expect="limit rate 10/minute burst 5 packets dnat ip to 10.0.0.9")

# nft's NAT grammar accepts the optional `ip` family qualifier but not an
# `ip6` counterpart.  This surfaced with a Ping/DNAT macro because the parser
# rejected `dnat ip6 to` after successfully parsing the ICMPv6 match.  Keep an
# IPv4 twin here to ensure fixing IPv6 does not remove its supported qualifier.
form_ok("rules: Ping/DNAT uses the valid unqualified IPv6 NAT form",
        {"zones": "fw firewall\nnet ipv6\nlxbr0 ipv6\n",
         "interfaces": "?FORMAT 2\nnet eth0\nlxbr0 lxbr0\n",
         "policy": "$FW net ACCEPT\nnet all DROP\nall all REJECT\n",
         "params": ('acme="[fc42:5009:ba4b:5ab0::202]"\n'
                    'acmednat="[2407:3641:2298:1223::202]"\n'),
         "rules": ("?SECTION NEW\n"
                   "Ping/DNAT net lxbr0:$acme - - - $acmednat\n")},
        family=6,
        expect="icmpv6 type 128 dnat to fc42:5009:ba4b:5ab0::202")
form_ok("rules: Ping/DNAT retains the valid IPv4 NAT family qualifier",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet eth0\nloc eth1\n",
         "params": ('server="10.0.0.202"\n'
                    'public="192.0.2.202"\n'),
         "rules": "?SECTION NEW\nPing/DNAT net loc:$server - - - $public\n"},
        expect="icmp type echo-request dnat ip to 10.0.0.202")

# The IPv6 NAT-family fix is general, not only the ICMP macro that surfaced it.
# Plain IPv6 DNAT and SNAT must use the unqualified form too, and IPv4 keeps
# its `ip` qualifier both ways.
_V6NAT = {"zones": "fw firewall\nnet ipv6\nloc ipv6\n",
          "interfaces": "?FORMAT 2\nnet eth0\nloc eth1\n",
          "policy": ("$FW net ACCEPT\nloc net ACCEPT\nnet all DROP\n"
                     "all all REJECT\n")}
form_ok("rules: a plain IPv6 TCP DNAT uses the unqualified NAT form",
        {**_V6NAT, "rules": "?SECTION NEW\nDNAT net loc:[fc00::202] tcp 80\n"},
        family=6, expect="tcp dport 80 dnat to fc00::202")
form_ok("snat: an IPv6 SNAT uses the unqualified NAT form",
        {**_V6NAT, "snat": "?FORMAT 2\nSNAT([2001:db8::1])\tfc00::/64\teth0\n"},
        family=6, expect="snat to 2001:db8::1")
form_ok("snat: an IPv4 SNAT retains the valid NAT family qualifier",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet eth0\nloc eth1\n",
         "policy": ("$FW net ACCEPT\nloc net ACCEPT\nnet all DROP\n"
                    "all all REJECT\n"),
         "snat": "?FORMAT 2\nSNAT(192.0.2.1)\t10.0.0.0/24\teth0\n"},
        expect="snat ip to 192.0.2.1")

# --- conntrack: the stock /etc/shorewall/conntrack file ships on every
# install. It is ?FORMAT 3 and assigns conntrack helpers, gated on the
# AUTOHELPERS setting and the helper capabilities. Migrating any real system
# reads it, so it must compile and load in both AUTOHELPERS states. ?FORMAT 3
# is conntrack-specific; the reader used to cap every file at ?FORMAT 2. ---
STOCK_CONNTRACK = (
    "?FORMAT 3\n"
    "#ACTION            SOURCE  DEST    PROTO   DPORT   SPORT   USER    SWITCH\n"
    "?if $AUTOHELPERS && __CT_TARGET\n"
    "?if __AMANDA_HELPER\n"
    "CT:helper:amanda:PO     -       -       udp     10080\n"
    "?endif\n"
    "?if __FTP_HELPER\n"
    "CT:helper:ftp:PO        -       -       tcp     21\n"
    "?endif\n"
    "?if __IRC_HELPER\n"
    "CT:helper:irc:PO        -       -       tcp     6667\n"
    "?endif\n"
    "?if __SIP_HELPER\n"
    "CT:helper:sip:PO        -       -       udp     5060\n"
    "?endif\n"
    "?if __TFTP_HELPER\n"
    "CT:helper:tftp:PO       -       -       udp     69\n"
    "?endif\n"
    "?endif\n"
)

# AUTOHELPERS=No (the modern default): the whole file is gated off, so it
# compiles to no helpers. The point is that ?FORMAT 3 is accepted and the file
# is a clean no-op rather than a parse error.
form_ok("conntrack: the stock file with AUTOHELPERS=No compiles and loads",
        {"conntrack": STOCK_CONNTRACK})

# AUTOHELPERS=Yes: the gated helpers activate. Each becomes an nft ct helper
# object plus an assignment rule, and the ruleset must load.
form_ok("conntrack: the stock file with AUTOHELPERS=Yes assigns helpers",
        {"conntrack": STOCK_CONNTRACK, "params": "AUTOHELPERS=Yes\n"},
        expect='ct helper set "helper_ftp_tcp"')

# A bare CT:helper assignment with an explicit hook suffix, independent of
# AUTOHELPERS, exercises the helper emit path directly.
form_ok("conntrack: an explicit CT:helper assignment compiles and loads",
        {"conntrack": "?FORMAT 3\nCT:helper:ftp:PO - - tcp 21\n"},
        expect='type "ftp" protocol tcp')

# --- MSS clamp uses the bitwise flags form, which loads on every nft; the
#     "syn / syn,rst" mask shorthand does not parse on nft 0.9.x ---
form_ok("mss: clamp emits bitwise flags, not the mask shorthand",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet eth0 mss=1400\nloc eth1\n"},
        expect="tcp flags & (syn|rst) == syn")

# --- legacy nft (Debian 10, nft 0.9.0): every fallback forced on at once
#     must still compile to a loadable ruleset. Numeric priorities, bitwise
#     flags, no nat family qualifier, and a de-concatenated dispatch. ---
_LEGACY = ("NFT_NAMED_PRIORITY", "NFT_NAT_FAMILY", "NFT_CONCAT_MAPS")
for _c in _LEGACY:
    capabilities.CAPABILITIES[_c] = False
try:
    d = build({"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
               "interfaces": "?FORMAT 2\nnet eth0 mss=1400\nloc eth1\n",
               "rules": "?SECTION NEW\nDNAT net loc:10.0.0.9 tcp 8080\n"})
    try:
        text = render(load(d, 4))
    finally:
        shutil.rmtree(d)
    loads, msg = nft_loads(text)
    checks = {
        "numeric priorities": bool(re.search(r"priority -?\d+;", text))
        and not re.search(r"priority (filter|mangle|dstnat|srcnat);", text),
        "bitwise flags": "tcp flags & (syn|rst) == syn" in text,
        "nat 'to' without family": "dnat to " in text
        and "dnat ip to" not in text,
        "de-concatenated dispatch": "iifname . oifname vmap" not in text
        and 'oifname "eth1" jump' in text,
    }
    if not loads:
        bad("legacy stack: ruleset did not load", msg)
    else:
        missing = [k for k, v in checks.items() if not v]
        if missing:
            bad("legacy stack", "not applied: " + ", ".join(missing))
        else:
            ok("legacy: all fallbacks together compile to loadable output")
finally:
    for _c in _LEGACY:
        capabilities.CAPABILITIES[_c] = True

# --- COUNTERS=Yes puts readable named counters on the zone-pair chains and
#     the policy denies, still loads, and is absent by default (monitor reads
#     these via nft -j) ---
d = build({})
try:
    cfg = load(d, 4)
    cfg.variables["COUNTERS"] = "Yes"
    text = render(cfg)
finally:
    shutil.rmtree(d)
loads, msg = nft_loads(text)
decl = bool(re.search(r"counter t_\w+ \{ \}", text))
traffic = bool(re.search(r"counter name t_\w+", text))
deny = bool(re.search(r"counter name d_\w+ (drop|reject)", text))
if not loads:
    bad("COUNTERS: ruleset did not load", msg)
elif not (decl and traffic and deny):
    bad("COUNTERS", f"decl={decl} traffic={traffic} deny={deny}")
else:
    ok("COUNTERS=Yes emits loadable named counters for the monitor")

d = build({})
try:
    text = render(load(d, 4))
finally:
    shutil.rmtree(d)
if "counter name t_" in text:
    bad("COUNTERS default", "counters emitted with the setting off")
else:
    ok("COUNTERS off by default: no monitor counters emitted")

# --- a bare interface name in a rule's address column is a located error, so
#     the offending line is findable (reported on shorewall-users) ---
d = build({"rules": "?SECTION NEW\nACCEPT $FW net:cable\n"})
try:
    render(load(d, 4))
    bad("bad address column should be rejected")
except ConfigError as e:
    if "rules:" in str(e) and "cable" in str(e):
        ok("bad address column is a located error naming the line")
    else:
        bad("address-column error not located", str(e))
except Exception as e:                                   # noqa: BLE001
    bad("address-column error", f"traceback: {type(e).__name__}")
finally:
    shutil.rmtree(d)

# --- github #17-#20: config-compatibility fixes a user hit checking iptables
# configs against shorewall-nft. ---
# #18 a REDIRECT DEST may be a service name; nft resolves it at load.
form_ok("rules: REDIRECT DEST accepts a service name",
        {"rules": "?SECTION NEW\nREDIRECT net ssh tcp 28534\n"},
        expect="redirect to :ssh")
# #20 snat interface::address (double colon) gives a clean dest match with no
# stray leading colon on the address.
form_ok("snat: interface::address parses without a stray colon",
        {"zones": "fw firewall\nnet ipv4\nloc ipv4\n",
         "interfaces": "?FORMAT 2\nnet eth0\nloc eth1\n",
         "policy": "loc net ACCEPT\nall all DROP\n",
         "snat": "SNAT(198.51.100.33)\t192.168.1.10\teth0::203.0.113.160\n"},
        expect="ip daddr 203.0.113.160 ip saddr 192.168.1.10 "
               "snat ip to 198.51.100.33")
# #19 a mangle rule with the firewall zone as source goes in the output chain.
d = build({"zones": "fw firewall\nnet ipv4\n",
           "interfaces": "?FORMAT 2\nnet eth0\n",
           "policy": "$FW net ACCEPT\nnet all DROP\nall all REJECT\n",
           "mangle": "MARK(1)\tfw\t0.0.0.0/0\tudp\t-\topenvpn\n"})
try:
    text = render(load(d, 4))
    loads, msg = nft_loads(text)
    lines = text.splitlines()
    out_i = next((i for i, ln in enumerate(lines)
                  if "chain mangle_output" in ln), None)
    mark_i = next((i for i, ln in enumerate(lines)
                   if "meta mark set 1" in ln), None)
    if not loads:
        bad("mangle fw source", f"nft rejected: {msg}")
    elif out_i is None or mark_i is None or mark_i < out_i:
        bad("mangle fw source", "the MARK did not land in mangle_output")
    else:
        ok("mangle: a firewall-source rule goes in the output chain")
except Exception as e:                                   # noqa: BLE001
    bad("mangle fw source", f"{type(e).__name__}: {e}")
finally:
    shutil.rmtree(d)
# #17 a per-interface sysctl for a VLAN interface uses / separators, so the
# dotted VLAN name enp2s0.10 is not split into a .../conf/enp2s0/10/... path.
from shorewall_nft.script import render_script as _rs   # noqa: E402
from shorewall_nft.emit import render_stop as _rstop    # noqa: E402
d = build({"interfaces": "?FORMAT 2\nnet NET_IF physical=enp2s0.10,routefilter\n"})
try:
    cfg = load(d, 4)
    scr = _rs(cfg, render(cfg), _rstop(cfg))
    rp = [ln for ln in scr.splitlines()
          if "rp_filter" in ln and "enp2s0" in ln]
    if rp and "net/ipv4/conf/enp2s0.10/rp_filter" in rp[0]:
        ok("sysctl: a VLAN interface uses the / separator form")
    else:
        bad("sysctl VLAN", f"expected the / form, got {rp}")
except Exception as e:                                   # noqa: BLE001
    bad("sysctl VLAN", f"{type(e).__name__}: {e}")
finally:
    shutil.rmtree(d)

# --- github #23: a per-rule {HELPER=name} assigns a conntrack helper. ---
form_ok("rules: {HELPER=tftp} assigns the tftp conntrack helper",
        {"rules": "?SECTION NEW\nACCEPT net $FW udp 69,4011 {HELPER=tftp}\n"},
        expect='ct helper set "helper_tftp_udp"')
form_ok("rules: {HELPER=tftp} declares the helper object",
        {"rules": "?SECTION NEW\nACCEPT net $FW udp 69,4011 {HELPER=tftp}\n"},
        expect='ct helper helper_tftp_udp {')
form_rejected("rules: an unknown {option} in a rule is a located error",
              {"rules": "?SECTION NEW\nACCEPT net $FW udp 69 {BOGUS=x}\n"})

# --- github #22: blrules SOURCE/DEST accept a comma-separated zone list, the
# same as the rules file, including a trailing zone:address list. ---
MZ = {"zones": "fw firewall\nz1 ipv4\nz2 ipv4\nz3 ipv4\nnet ipv4\n",
      "interfaces": "?FORMAT 2\nz1 eth0\nz2 eth1\nz3 eth2\nnet eth3\n",
      "policy": "all all ACCEPT\n"}
_ln = "REJECT z1,z2 z3,net:192.168.100.1,192.168.0.1 all\n"
d = build({**MZ, "blrules": _ln, "rules": "?SECTION NEW\n"})
try:
    text = render(load(d, 4))
    loads, msg = nft_loads(text)
    # z1 (eth0) and z2 (eth1) sources both appear, going to the net addresses.
    z1 = any('iifname "eth0"' in ln and "192.168.100.1" in ln
             for ln in text.splitlines())
    z2 = any('iifname "eth1"' in ln and "192.168.100.1" in ln
             for ln in text.splitlines())
    if not loads:
        bad("blrules multi-zone", f"nft rejected: {msg}")
    elif not (z1 and z2):
        bad("blrules multi-zone", "the zone list did not fan out")
    else:
        ok("blrules: a comma-separated zone list fans out")
except Exception as e:                                   # noqa: BLE001
    bad("blrules multi-zone", f"{type(e).__name__}: {e}")
finally:
    shutil.rmtree(d)

# --- maclist: an entry with a '-' MAC matches by IP only, the way upstream
#     allows (shorewall-maclist(5)). It must not emit an ether saddr match. ---
d = build({"interfaces": "?FORMAT 2\nnet eth0 maclist\n",
           "maclist": "ACCEPT eth0 - 10.20.30.40,10.20.30.50-10.20.30.60\n"})
try:
    text = render(load(d, 4))
    loads, msg = nft_loads(text)
    entry = [ln for ln in text.splitlines() if "10.20.30.40" in ln]
    if not loads:
        bad("maclist no-MAC entry", f"nft rejected: {msg}")
    elif not entry:
        bad("maclist no-MAC entry", "the IP entry did not reach the chain")
    elif "ether saddr" in entry[0]:
        bad("maclist no-MAC entry", "a MAC-less entry still matched a MAC")
    else:
        ok("maclist: a no-MAC entry matches by IP only")
except Exception as e:                                   # noqa: BLE001
    bad("maclist no-MAC entry", f"traceback: {type(e).__name__}: {e}")
finally:
    shutil.rmtree(d)

# --- a config with no rules file is a valid policy-only firewall; upstream
#     compiles it, so a missing rules file must be empty, not a crash ---
d = build({})
os.remove(os.path.join(d, "rules"))
try:
    render(load(d, 4))
    ok("compile: a missing rules file is accepted (policy-only firewall)")
except Exception as e:                                   # noqa: BLE001
    bad("missing rules file", f"{type(e).__name__}: {str(e)[:80]}")
finally:
    shutil.rmtree(d)

# --- INCLUDE resolves through CONFIG_PATH, not only next to the including
#     file. A bare name like DMZ.rules is found in a rules.d directory listed
#     in CONFIG_PATH, matching upstream find_file. A name with a slash stays
#     literal and is not searched (matdarf CONFIG_PATH report) ---
d = tempfile.mkdtemp(prefix="shorewall-nft-cfgpath-")
try:
    os.makedirs(os.path.join(d, "rules.d"))
    incl = os.path.join(d, "rules.d", "DMZ.rules")
    open(incl, "w").close()
    near = os.path.join(d, "near.rules")
    open(near, "w").close()
    including = os.path.join(d, "rules")
    variables = {"CONFIG_PATH": os.path.join(d, "rules.d")}
    if resolve_include("near.rules", including, {}) != near:
        bad("resolve_include", "a sibling file was not found next to the includer")
    elif resolve_include("DMZ.rules", including, variables) != incl:
        bad("resolve_include", "a bare name was not found through CONFIG_PATH")
    elif resolve_include("DMZ.rules", including, {}) is not None:
        bad("resolve_include", "a bare name resolved with no CONFIG_PATH set")
    elif resolve_include("sub/DMZ.rules", including, variables) is not None:
        bad("resolve_include", "a name with a slash was searched in CONFIG_PATH")
    else:
        ok("resolve_include: sibling first, then CONFIG_PATH, slash stays literal")
finally:
    shutil.rmtree(d)

# --- end to end: a ?INCLUDE of a bare file name pulls a rule from a rules.d
#     directory named in CONFIG_PATH, with ${CONFDIR} expanded to a real path.
#     This is the config the matdarf report used against SW-Iptables ---
d = build({"rules": "?INCLUDE extra.rules\n"})
try:
    base = os.path.basename(os.path.normpath(d))
    with open(os.path.join(d, "shorewall.conf"), "a") as f:
        f.write(f'\nCONFIG_PATH="${{CONFDIR}}/{base}/rules.d"\n')
    os.makedirs(os.path.join(d, "rules.d"))
    with open(os.path.join(d, "rules.d", "extra.rules"), "w") as f:
        f.write("ACCEPT net $FW tcp 22\n")
    text = render(load(d, 4))
    loads, msg = nft_loads(text)
    if not loads:
        bad("INCLUDE via CONFIG_PATH", f"nft rejected: {msg}")
    elif "dport 22" not in text:
        bad("INCLUDE via CONFIG_PATH", "the included rule did not reach the ruleset")
    else:
        ok("INCLUDE: a bare name resolves through a CONFIG_PATH rules.d")
except Exception as e:                                   # noqa: BLE001
    bad("INCLUDE via CONFIG_PATH", f"{type(e).__name__}: {str(e)[:100]}")
finally:
    shutil.rmtree(d)

# --- a site macro.<name> in a CONFIG_PATH directory is found, not only the
#     shipped macros, so a migrated config with custom macros in a directory
#     like /usr/local/share/shorewall compiles (github #30) ---
d = build({"rules": "?SECTION NEW\nFTPS(ACCEPT) net $FW\n"})
try:
    site = os.path.join(d, "sitemacros")
    os.makedirs(site)
    with open(os.path.join(site, "macro.FTPS"), "w") as f:
        f.write("#ACTION\tSOURCE\tDEST\tPROTO\tDPORT\nACCEPT\t-\t-\ttcp\t990\n")
    with open(os.path.join(d, "shorewall.conf"), "a") as f:
        f.write(f'\nCONFIG_PATH="{site}"\n')
    text = render(load(d, 4))
    if "tcp dport 990 accept" in text:
        ok("macros: a site macro in a CONFIG_PATH directory is found")
    else:
        bad("CONFIG_PATH macro", "the site macro was not expanded")
except ConfigError as e:
    bad("CONFIG_PATH macro", f"compile rejected it: {str(e)[:100]}")
except Exception as e:                                   # noqa: BLE001
    bad("CONFIG_PATH macro", f"{type(e).__name__}: {str(e)[:100]}")
finally:
    shutil.rmtree(d)

# A site macro dropped in the config directory is found too, without a
# CONFIG_PATH entry, since the config directory is always searched.
d = build({"rules": "?SECTION NEW\nFTPS(ACCEPT) net $FW\n"})
try:
    with open(os.path.join(d, "macro.FTPS"), "w") as f:
        f.write("ACCEPT\t-\t-\ttcp\t990\n")
    text = render(load(d, 4))
    if "tcp dport 990 accept" in text:
        ok("macros: a site macro in the config directory is found")
    else:
        bad("confdir macro", "the site macro was not expanded")
except Exception as e:                                   # noqa: BLE001
    bad("confdir macro", f"{type(e).__name__}: {str(e)[:100]}")
finally:
    shutil.rmtree(d)

# --- a clean install has no configuration. load must say so with a located
#     ConfigError, not a FileNotFoundError traceback, so `shorewall check` on
#     a fresh box prints a clean message and exits non-zero ---
d = tempfile.mkdtemp(prefix="shorewall-nft-clean-")
shutil.rmtree(d)                                   # a directory that is not there
try:
    load(d, 4)
    bad("clean install", "a missing config directory did not raise")
except ConfigError as e:
    if "shorewall init" in str(e):
        ok("clean install: a missing config directory is a located error")
    else:
        bad("clean install", f"unhelpful message: {str(e)[:80]}")
except Exception as e:                                   # noqa: BLE001
    bad("clean install", f"traceback leaked: {type(e).__name__}: {e}")

# An existing but incomplete directory (no zones) is also a clean error.
d = tempfile.mkdtemp(prefix="shorewall-nft-partial-")
try:
    load(d, 4)
    bad("incomplete config", "a directory with no zones did not raise")
except ConfigError as e:
    if "incomplete" in str(e):
        ok("clean install: an incomplete config directory is a located error")
    else:
        bad("incomplete config", f"unhelpful message: {str(e)[:80]}")
except Exception as e:                                   # noqa: BLE001
    bad("incomplete config", f"traceback leaked: {type(e).__name__}: {e}")
finally:
    shutil.rmtree(d)

sys.exit(1 if fails else 0)
