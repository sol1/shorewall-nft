# Multi-ISP and a pure-Python link monitor

Status: design. This is enhancement territory. It is grounded in the
provider and routing code that exists today, and it says exactly what
that code does before it proposes anything new. Reference:
https://shorewall.org/MultiISP.html.

The short version. We already compile a working static multi-ISP
ruleset: per-provider tables, weighted balance, connection mark tracking,
route rules, and interface-up guards. What we do not have is anything
dynamic. A provider that dies stays in the routing tables until someone
runs a reload. Failover, the reason most people run multi-ISP, needs a
runtime seam the compiler does not provide and a monitor to drive it.
This document audits the gap and designs both.

## 1. Compliance audit

Measured against MultiISP.html. Citations are to
`src/shorewall_nft/`.

### providers file

| Column | Upstream | shorewall-nft | Where |
|---|---|---|---|
| NAME | table name | parsed | parsers.py:737 |
| NUMBER | table 1-252 | parsed | parsers.py:742 |
| MARK | packet mark | parsed, low byte only | parsers.py:743 |
| DUPLICATE | copy a table | **ignored** | parsers.py, cols[3] unread |
| INTERFACE | iface or iface:addr | iface only | parsers.py:738 |
| GATEWAY | ip / detect / - | all three | parsers.py:740, script.py:108 |
| OPTIONS | see below | partial | parsers.py:746 |
| COPY | copy routes | **ignored** | parsers.py, cols[7] unread |

Options:

| Option | shorewall-nft | Note |
|---|---|---|
| `track` | works | connmark save/restore, emit.py:976 |
| `balance`, `balance=N` | works | weighted nexthop, script.py:162 |
| `loose` | works | suppresses the pref 20000 source rules |
| `primary` | **collapsed to balance=1** | loses "preferred default" meaning, parsers.py:755 |
| `fallback`, `fallback=N` | **accepted, does nothing** | no field, no route, parsers.py:759 |
| `optional` | **accepted, does nothing** | parsers.py:759 |
| `persistent` | **accepted, does nothing** | parsers.py:759 |
| `notrack` | **rejected** | not in the option set |
| `load=` | **rejected** | statistical balancing absent |
| `tproxy` | **rejected** | |
| `mtu=`, `src=` | **rejected** | |

Shared interface `eth0:1.2.3.4` is not handled: the interface field is
never split on the colon (parsers.py:738). IPv6 providers are not
handled: every emitted routing command is hardcoded `ip -4`
(script.py:99-251).

### shorewall.conf

Only `MARK_IN_FORWARD_CHAIN` is recognised, and it is rejected when set
to anything but the default (compile.py:39). `USE_DEFAULT_RT`,
`BALANCE_PROVIDERS`, `TRACK_PROVIDERS`, `PROVIDER_OFFSET`,
`PROVIDER_BITS`, `TC_BITS`, `MASK_BITS`, `RESTORE_DEFAULT_ROUTE`,
`KEEP_RT_TABLES`, `HIGH_ROUTE_MARKS` and `NULL_ROUTE_RFC1918` are read
nowhere. Setting them has no effect and raises no error.

This matters because the routing layout is hardwired to one style. When
any provider balances, `_routing` always moves the main table to ip rule
priority 999, puts the balanced default in table 250 at priority 32765,
and strips the main-table default (script.py:199-236). That is the
`USE_DEFAULT_RT=Yes` shape. It is correct and it is what we want, but it
is not selectable, and `fallback` (which lives in table 253 in the
upstream model) has nowhere to attach because we never write table 253.

### rtrules file

SOURCE, DEST, PROVIDER, PRIORITY, MARK are all parsed (parsers.py:780).
PROVIDER is validated against provider names, numbers, `main` and
`default`. `&interface` resolves the interface address at runtime
(script.py:173). The MARK column becomes an `fwmark` match with a default
`/0xff` mask. Priority is taken verbatim, with a trailing `!` meaning
persistent; there is no auto-offset into the reserved priority bands, and
`lo` gets no special treatment (it becomes an `iif lo` match). This is a
close match to upstream for the cases people actually write.

### marking

A provider mark reaches the routing tables through the fwmark ip rule at
priority `10000+i` (script.py:110). Marks are set either by a hand-written
`mangle` MARK rule (emit.py:953) or, for `track` providers, by the
connmark machinery in `_mangle_chains` (emit.py:976-1039), which restores
the mark from conntrack in prerouting and output and saves it per
provider. Masks are fixed at `0xff` / `0xffffff00`; the configurable mark
layout (`PROVIDER_OFFSET` and friends) is not implemented.

### runtime

Nothing. `enable`, `disable` and `reenable` are stubbed as "not
implemented" (cli.py:730). `isusable` is recognised so it does not error
but is never wired into the generated script (compile.py:83). There is no
daemon, no link check, and no way to change routing without a reload. The
only adaptation is the one-shot interface-up guard in `setup_routing`,
which skips a provider whose interface is down at start time so it does
not break the multipath route (script.py:117-140, 199-216).

### verdict

For a static, all-links-up multi-ISP box we are close to upstream. The
real gaps, in priority order for this work:

1. No runtime provider enable/disable. This blocks all of failover.
2. No link monitor to drive it.
3. `fallback` parsed and dropped. It is the simplest failover primitive
   and people expect it.
4. `optional` parsed and dropped. It should mean "do not configure this
   provider if its link is down," which is exactly a startup-time
   failover decision.

The rest (`load=`, shared interfaces, `tproxy`, configurable mark layout,
the conf toggles) are real but secondary. They are catalogued in the gap
list at the end.

## 2. Principle: static ruleset, dynamic routing seam

The compiler is deliberately static. It reads the config once and emits a
ruleset plus a shell wrapper. That is right for the packet-filtering
rules, which do not change while the firewall runs. Routing is different.
Which providers are usable changes minute to minute. We will not make the
compiler dynamic. Instead we add one runtime seam that recomputes the
routing for the currently usable set of providers, and everything else,
the manual `enable`/`disable` verbs, the link monitor, the profiles, sits
on top of that one seam.

The seam already half-exists. `setup_routing` recomputes the balanced
default from whichever provider interfaces are up at that moment
(script.py:199-216). Today it runs once at start. The plan is to make it
runnable at any time, against a usability state that something else
maintains.

## 3. The enable/disable seam

### provider usability state

A directory `${VARDIR}/providers/` with one file per provider,
`<name>.state`, containing `up` or `down`. Absent means up. This is the
single source of truth for "which providers should be routed right now."
It survives across `enable`/`disable` calls but is reset to the config
default on a full `start` (a fresh start trusts the config and the
live interface state, not stale monitor decisions).

### recompute

Refactor `_routing` so the per-provider block and the balanced-default
block are driven by a helper `usable_providers` that intersects three
things: the provider is in the config, its interface is up, and its state
file does not say `down`. The generated wrapper gains one function:

    reroute_providers   # rebuild all provider rules + the balance route
                        # from the current usable set, idempotently

`setup_routing` becomes a call to `reroute_providers` after the one-time
state save. The teardown (`clear_routing`) is unchanged.

Idempotency is the requirement that makes this safe to call repeatedly.
Every rule and route the seam adds is already emitted as
`del ... 2>/dev/null || :` then `add`, or as `replace`
(script.py:110-114, 136-140, 218-228). Extending that discipline to the
whole recompute means `reroute_providers` can run on every link event
with no drift.

### verbs

    shorewall enable  <provider>    # mark up,   then reroute_providers
    shorewall disable <provider>    # mark down, then reroute_providers
    shorewall reenable <provider>   # disable then enable, to reset

These map to the upstream `shorewall enable/disable <interface>`, except
we key on the provider name because that is what our routing is organised
around. An interface-named form can alias to the provider on that
interface. `disable` on the last usable provider is refused with a
warning, so a bad monitor cannot black-hole the box.

The verbs are thin: resolve the provider, write the state file, run the
wrapper's `reroute_providers`, report the new usable set. They do not
touch the packet-filtering ruleset at all, so `disable` cannot open a
hole, it only changes which uplink egress traffic takes.

### connmark interaction

`track` saves a per-provider mark on the connection (emit.py:1002). When
a provider is disabled, existing marked connections still resolve to its
(now empty) table and fall through to the balance table, which no longer
lists it. New connections never get its mark because the source rules and
fwmark rule for it are gone. This is the correct failover behaviour and
it needs no extra work beyond the recompute removing the disabled
provider's rules. It is worth an explicit test (section 7).

## 4. Pure-Python link monitor (shorewall-lsm)

Upstream drives failover with foolsm, a separate C daemon that pings each
gateway and runs an event script calling `firewall enable/disable`. We
reimplement that in Python, in this repository, with no new dependencies,
and wire it to the seam from section 3.

### what it does

A long-running process. For each monitored provider it periodically
probes the gateway. It keeps a small state machine per provider: a run of
successful probes above a threshold means up, a run of failures means
down. On a transition it calls the seam.

### probing without dependencies

Two options, both stdlib:

- Shell out to `ping -c1 -W1 -I <iface> <gateway>` and read the exit
  code. Simple, portable, no privilege beyond what ping already has
  (setuid or cap_net_raw on the ping binary, which is the distro norm).
  This is the default.
- A raw ICMP socket. Needs `CAP_NET_RAW` on the daemon. Faster and gives
  latency and loss directly, but adds a privilege requirement. Offered as
  an opt-in for people who do not want to fork ping.

The probe target is the gateway from the providers file, or an explicit
`checkip` from the monitor config for providers whose gateway does not
answer ICMP. Probing is bound to the provider interface
(`ping -I`, or `SO_BINDTODEVICE` on the raw socket) so the probe goes out
the link under test, not whichever link currently wins the default route.

### configuration, grounded in what exists

The monitor reads the same providers file the compiler reads, so it
already knows every provider's interface and gateway. It needs only the
monitoring parameters, which go in an optional new file
`/etc/shorewall/lsm` (and `/etc/shorewall6/lsm`), one row per provider:

    #PROVIDER   CHECKIP        INTERVAL  RETRIES  LOSS%   METHOD
    ISP1        -              5         3        50      ping
    ISP2        8.8.8.8        5         3        50      ping

`CHECKIP -` means use the provider's gateway. Absent providers are not
monitored. This file is parsed by the same reader stack as the rest of
the config, so variables and `?if` work, and it is reported by
`shorewall check` like any other file.

The monitor does not compile anything. At startup, and on SIGHUP, it
loads the providers file and the lsm file through the existing parser and
builds its watch list. It never emits nftables. Its only output is calls
to the enable/disable seam.

### integration

    /usr/sbin/shorewall-lsm         the daemon (a new cli entry point)
    shorewall-lsm.service           systemd unit, wants shorewall.service
    ${VARDIR}/lsm/<provider>.status latency/loss/state, for `shorewall status`

On a transition the daemon runs, in-process, the same code path as
`shorewall disable <provider>` / `enable <provider>`. It does not fork the
CLI; the verb and the daemon share one function so there is one
implementation of "recompute routing for the usable set." A debounce
(the retries/loss thresholds) keeps a flapping link from thrashing the
routes.

`shorewall status` grows a providers section: each provider, its state,
last probe latency and loss, and when it last changed. This reads the
`${VARDIR}/lsm/*.status` files, so it works whether or not the daemon is
running (stale is labelled stale, exactly as the existing status warning
does for the ruleset).

### coexistence and safety

- The daemon is shipped disabled, like every other unit. It does nothing
  until enabled, and it does nothing to the packet filter ever.
- If the daemon dies, routing freezes in its last good state. The
  firewall keeps filtering. This is fail-static, which is the right
  default for a firewall.
- A single-provider box, or a box with monitoring off, never starts the
  daemon and behaves exactly as today.

## 5. Route profiles (rtrules as profiles)

### three levels of policy

The ask covers three shapes: balance two links, prefer one link for a
network and fall back to another, and swap the whole routing posture on
failure. They sit at three levels, and only the third needs profiles.

1. Balance. Give both providers `balance` (or `balance=N` for a ratio)
   and write no rtrule for that traffic. It falls to the weighted default
   in table 250. `balance=2` with `balance=1` is a 2:1 split.

2. Prefer, then fall back, per network. Write two rtrules for the source
   at adjacent priorities, preferred provider first:

       #SOURCE          DEST  PROVIDER  PRIORITY
       192.168.5.0/24   -     isp1      11000
       192.168.5.0/24   -     isp2      11001

   Policy routing tries rules in priority order and falls through to the
   next when a rule's table has no matching route. While isp1 is up its
   table holds a default and the network egresses isp1; when isp1's table
   is empty the packet falls through to the isp2 rule. This is failover
   with no monitor and no profile. It works only while a dead provider's
   table is actually empty, which today is true just at start, from the
   interface-up guard that skips populating a down provider's table. The
   seam of section 3 makes it true at any time: disabling a provider
   flushes its table, so the fall-through fires at once instead of
   black-holing until a reload. Distinct source networks or reversed
   priorities express any per-network preference.

3. Swap the whole posture. When failover means more than losing a
   nexthop, different weights, a different pinned set, a VPN that runs
   only while the primary is up, that is a profile. The rest of this
   section is the third level.

### model

The request: rtrules as a profile, with failover, load balancing and
route priority selectable. The idea is that a box has more than one
sensible routing posture, and which one is active depends on link state.
Normal posture might balance two links and pin a VPN subnet to one.
Degraded posture might send everything over the survivor.

A profile is a named set of three things:

1. the balance weights per provider (or which single provider is the
   default),
2. the rtrules that apply,
3. optionally which providers are considered usable at all.

Profiles live in a new file, `/etc/shorewall/profiles`, each a named
block that overrides the base providers/rtrules:

    ?PROFILE normal
    balance   ISP1=2 ISP2=1
    rtrules   vpn.rtrules
    ?PROFILE isp1-only
    default   ISP1
    ?PROFILE isp2-only
    default   ISP2

The compiler emits, per profile, a `reroute_providers` variant (a shell
function `profile_<name>`) that applies that profile's weights and
rtrules through the same idempotent seam. Exactly one profile is active
at a time; a state file `${VARDIR}/profile` records it.

### selection

- `shorewall profile <name>` activates a profile by hand.
- The link monitor selects a profile from a policy: the highest-priority
  profile all of whose required providers are up. This turns failover
  into "pick the best profile the current links allow," which is more
  expressive than raw enable/disable and covers load balancing and route
  priority in one mechanism. Priority is the order profiles appear in the
  file.

Profiles are the general form; plain enable/disable (section 3) is the
degenerate case of one provider per profile. We build the seam first,
then enable/disable, then profiles on top, so each layer is testable
before the next exists.

## 6. Filling the parsed-but-dropped gaps

Two of the audit gaps are cheap and belong with this work because they
are failover primitives people expect, and implementing them well needs
the same table-253 plumbing the seam introduces:

- `fallback[=weight]`: add a `Provider.fallback` field, and in the
  recompute write a default route into table 253 (weighted if a weight is
  given, else metric = provider number). Table 253 is consulted after the
  balance table, so a fallback provider catches traffic only when no
  balanced provider is usable. This is failover for untracked traffic
  without any monitor at all, and it is the first thing to ship.
- `optional`: an optional provider whose link is down at start is simply
  left out of the usable set, which the seam already handles. The only
  change is to stop pretending the option does nothing and to document
  that optional providers are monitored by default when the daemon runs.

`primary` should be corrected from "alias for balance=1" to "the default
route when no balancing is in effect," which is a one-line distinction
once table 253 exists.

The remaining gaps (`load=` statistical balancing, shared interfaces,
`tproxy`, configurable mark layout, the untouched conf toggles, IPv6
providers) are out of scope for the failover work and stay on the list.
IPv6 providers in particular are a whole parallel path (`ip -6 rule`) and
deserve their own change.

## 7. Test harness plan

Status: the simulation primitive described in 7.2 and 7.3 is built. The
sandbox now honours `up = false` on a link (start a provider down),
`static_routes` and `forward` (topologies where a destination is
reachable through more than one path), an `[[events]]` phase (toggle a
device, run a wrapper verb such as `restart`, or `exec` a dial hook, then
re-probe), and `route_tables` capture. The runner grades event probes and
diffs route tables, and the ip rule diff now ignores the kernel's own
rules so it is not flaky on the redundant stock main rule. The first
scenario, `0038-failover`, passes: a client that prefers isp1 fails over
to isp2 when isp1's uplink drops and a restart recomputes routing, then
fails back when isp1 returns. The rest of 7.5 builds on this.

### 7.1 What the harness already does

The multi-ISP case `0014-providers` sets `mode = "script"` and
`ip_rules = true`. That combination makes the sandbox run the real
wrapper (`sh firewall start`) inside the fw namespace rather than loading
a static ruleset, and capture `ip -4 rule show` afterwards
(sandbox.py:280-282, 398-401). Grading is by probe verdict and by the
`peer` field, the source address the destination sees, which proves which
provider carried the packet, plus a byte-for-byte parity diff of the
captured `ip rule` output against upstream Shorewall (tests/run:220-225).

So static multi-ISP is already well covered: per-provider egress, every
rtrule shape (dest, source, device, runtime `&interface`, fwmark), source-
over-dest priority ordering, and exact ip rule tables versus upstream.
Three things are missing for failover, all in the harness, none in the
product:

1. The wrapper is invoked once, with `start`. There is no second verb and
   no re-capture (sandbox.py:388-414).
2. Every link is brought up and never down. There is no way to start a
   link down or drop one mid-test (sandbox.py:222-233).
3. Only `ip rule` is captured. Route table contents (the balanced
   nexthops in table 250, a fallback default in table 253) are never
   captured, only inferred through probe `peer`.

### 7.2 The one new primitive: scripted events

Add a phase to `sandbox.py` between the first probe pass and teardown that
runs an optional `[[events]]` list from the case. Each event mutates state
or runs a wrapper verb, then re-probes and re-captures. The case syntax:

    [[events]]
    description = "isp1 uplink fails"
    link  = "eth0"          # fw-side device to toggle
    state = "down"          # down | up
    run   = "disable isp1"  # optional wrapper verb, engine-mapped
    [[events.probes]]       # probes to run after this event
    ...

The sandbox applies `link`/`state` with `ip link set <dev> down|up` in the
fw namespace, runs the verb through the wrapper (`sh firewall disable
isp1`) if given, calls the existing `_settle`, runs the event's probes,
and captures `ip rule` (and route tables, 7.3) again. Results are emitted
per event so the runner can grade each pass. This is the smallest change
that unlocks the whole of failover testing, and it reuses the build,
probe, capture and settle code already there.

A companion `up = false` field on a `[[links]]` entry lets a case start
with a provider link already down, so the product's start-time
skip-if-down branch (script.py:144-151, 199-216) finally gets covered.

### 7.3 Route table capture

Add an optional `route_tables = [250, 253, 1, 2]` capture: for each listed
number, `ip -4 route show table N`, emitted alongside `ip_rules`. Failover
cases assert the balanced multipath in table 250 lost the dead provider's
nexthop, and that a fallback default appeared in table 253, directly
rather than by inference. Diffed against upstream in the parity layer for
differential cases, or against explicit expectations for ours-only cases.

### 7.4 Differential where we can, expectations where we cannot

Static routing stays differential; `0014` already diffs against upstream.
Failover is only partly differential, because the trigger differs between
engines: upstream drives it with foolsm calling `shorewall disable
<interface>`, and we drive it with `shorewall disable <provider>`. So an
event's `run` is engine-mapped (the provider name for us, the interface
for upstream), and we assert outcome parity: after the event, both engines
route the client out the surviving provider (the `peer` shifts) and both
drop the dead provider's ip rules. Where upstream has no equivalent at all
(the profiles of section 5, the daemon of section 4), the case is
`no_upstream` and grades against expectations, exactly as the existing
runtime-state cases do.

### 7.5 Cases and proofs, per phase

Phase 1, the seam plus `fallback` and `optional`:

- `0038-failover` (`mode=script`, `ip_rules`, `route_tables=[250]`): two
  balanced providers. Event one takes `eth0` down and runs
  `disable isp1`; its probes show the client now egresses via isp2 (peer
  is isp2's masquerade address) and isp1's rules and nexthop are gone.
  Event two runs `enable isp1` and restores the balance. Outcome parity
  against upstream via the engine-mapped verb.
- `0039-fallback` (`route_tables=[253]`): a balanced primary and a
  `fallback` secondary. Assert table 253 carries the fallback default;
  take the primary down; assert untracked traffic uses the fallback.
- `0040-optional-down` (`links` with `up=false` on isp2): assert the
  optional down provider is left out of the usable set and the balanced
  default across the survivors is intact.
- `0041-return-path`: the fundamental correctness property, and today a
  blind spot. A remote source (behind an ISP node, not directly connected
  to the fw) connects to a service on the fw via the non-default provider.
  Assert the reply egresses that same provider, not whichever wins the
  balanced default. This exercises the `track` connmark restore that
  `0014` cannot, because `0014`'s ISP sources are directly connected and
  the reply follows the connected route. Add a hop: give the ISP node a
  loopback source address and a route to it via the fw, source the probe
  from there, and check the `peer` matches the ingress provider. Then add
  a preference variant: two ordered rtrules (section 5) for a client
  network, take the preferred provider down with an event, and assert the
  fall-through moves the network to the second provider.
- `seam-proof.sh`, in the `dualstack-proof.sh` style: start two providers,
  `disable` then `enable`, assert the ip rules and balance route recompose
  idempotently, and assert `disable` of the last usable provider is
  refused.

Phase 2, the monitor:

- A pure-Python unit test of the state machine, no namespace. Feed it
  scripted probe outcomes (runs of loss and success) and assert the
  up/down transitions honour the retry and loss thresholds and the
  debounce. Fast and deterministic; it needs no root and no packets.
- `lsm-proof.sh`, in a namespace: run `shorewall-lsm` with a probe method
  the test controls (a checkip target the test can make unreachable),
  take the link down, poll with a bounded timeout until the daemon has
  called `disable` and the client egress has shifted, then restore and
  assert re-enable. This is the one test with real timing; keep its
  intervals short and its timeout generous.

Phase 3, profiles:

- `profile-proof.sh`: activate the `normal` profile and assert the 2:1
  nexthop weights; activate `isp1-only` and assert a single default via
  isp1; assert `shorewall profile` reports the active one.

### 7.6 Test data hygiene

The staged foolsm samples under `tests/harness/.stage` carry a `_disabled`
suffix and are referenced by no case; they are inert upstream copies from
staging. Leave them. New failover fixtures live in `tests/corpus` with
explicit expectations, and the events and route-table capture are additive
to `sandbox.py`, so every existing case runs unchanged.

## 8. Phased plan

1. **Seam.** Refactor `_routing` around a usable set and emit
   `reroute_providers`. Add the `${VARDIR}/providers/*.state` files and
   the `enable`/`disable`/`reenable` verbs. Ship `fallback` and honest
   `optional` in the same phase, since they exercise the same recompute.
   Test with a failover corpus case and a proof script.
2. **Monitor.** The `shorewall-lsm` daemon, ping method, the `lsm` config
   file, the systemd unit, the status files, and the `shorewall status`
   providers section. Test the state machine with faked probes.
3. **Profiles.** The `profiles` file, `profile_<name>` functions, the
   `shorewall profile` verb, and monitor-driven profile selection.
4. **Backlog.** The secondary gaps, prioritised by real configs in the
   fleet: configurable mark layout, `load=`, shared interfaces, IPv6
   providers.

Each phase is independently shippable and independently testable, and
each is grounded in the seam from phase 1. Nothing here changes the
packet filter or the static compile; it all hangs off one runtime
recompute.

## 9. Vendor landscape: what best-in-class means

We looked at OpenWrt mwan3 (the Linux reference, and what Teltonika RUTOS
runs on), pfSense and OPNsense (the dpinger daemon plus gateway groups),
MikroTik RouterOS (recursive routing plus PCC), Cisco Meraki MX
(performance-based SD-WAN failover), and Peplink Balance (outbound policy
modes). Different scales, strikingly convergent design. The shared
vocabulary, and where we stand against it:

Health check.

- Method. ICMP ping is universal. mwan3 and Peplink add DNS, HTTP and
  TCP-connect; Meraki layers DNS, ICMP, HTTP and ARP; Peplink SmartCheck
  is passive, probing only when live traffic is already failing so a
  metered link is spared. Best-in-class is a per-provider choice of
  method, not one global ping.
- Target. Ping the gateway (cheap, tests one hop) or a far host reached
  through the link (tests real end-to-end reachability). MikroTik's
  recursive-route trick and pfSense's monitor IP both exist to test the
  path, not just the first hop. We should allow a per-provider check
  target distinct from the gateway, with probes bound to the interface.
- Hysteresis. Everyone damps flapping. mwan3 uses asymmetric up and down
  consecutive-count thresholds with a reliability quorum (N of M targets
  must answer). pfSense averages latency and loss over a Time Period.
  Peplink separates retries from recovery-retries. The recovery threshold
  is deliberately separate so failback is cautious.
- Performance, not just up or down. The SD-WAN differentiator (Meraki
  performance classes, pfSense trigger levels, mwan3 check_quality): a
  link that still pings but breaches a latency, jitter or loss threshold
  is degraded and steered off. The best tools fail a technically-up link.

Policy and balancing.

- One tier-and-weight model. mwan3 metric, pfSense tier, MikroTik
  distance, Peplink priority: lower is preferred, same tier load
  balances, crossing tiers is failover, and weight sets the ratio within
  a tier. This one construct covers failover, balancing and hybrids. We
  have per-provider `balance=weight`; the tier ordering is what the
  ordered rtrules and profiles add.
- Per connection, sticky. Balancing is per flow, never per packet, and
  source-sticky affinity keeps a client on one WAN. nft's nexthop hash
  gives per-flow; sticky is future.
- Match granularity. src, dst, proto and port everywhere; Peplink and
  Meraki add domain and MAC. Our rtrules do src and dst; proto, port and
  application matching are future.
- last_resort. mwan3 names the all-down behaviour: reject, blackhole, or
  fall through to main. Worth stating explicitly.

Return path. MikroTik's connection-mark to routing-mark recipe, marking
inbound connections by the interface they arrived on, is exactly our
`track` connmark (emit.py:976). Their design independently validates
ours. The only gap is the test, section 7's `0041`.

Failover mechanics. Conntrack flush on a switch (mwan3 `flush_conntrack`,
MikroTik) so live flows re-pin instead of hanging on the dead path.
Deliberate failback: sticky versus snap-back (Peplink "terminate sessions
on recovery", pfSense state killing). Hooks on state change (netwatch
scripts, mwan3 hotplug, RUTOS SMS and email).

Cellular and metered. Treated as expensive everywhere: lowest-priority
standby (Meraki WAN3), on-demand dial (Teltonika Mobile Data on Demand),
passive probe (Peplink SmartCheck), throttled probe rate. This is the
PPP-dial-on-failover request; section 11.

The distilled target for best-in-class on Linux: per-provider
multi-method health checks with a through-the-link target; asymmetric
up/down hysteresis with a reliability quorum; performance-based tripping
on latency, loss and jitter, not just reachability; the tier-and-weight
policy model; conntrack flush and deliberate failback on a switch; and
first-class on-demand cellular or PPP backup. None of it needs anything
nftables and iproute2 cannot express.

## 10. The LSM config file

Grounded in mwan3's interface section and pfSense's dpinger fields. One
block per monitored provider, in `/etc/shorewall/lsm` (and
`/etc/shorewall6/lsm`), parsed by the existing reader so variables and
`?if` work. The provider's interface and gateway come from the providers
file; this file adds only the monitoring policy.

    ?PROVIDER isp1
    method      ping        # ping | dns | http | tcp
    check       -           # target; - is the provider gateway
    interface   -           # - is the provider interface (bind probes here)
    interval    5           # seconds between checks
    timeout     3           # seconds to wait for a reply
    count       1           # probes per check
    reliability 1           # of N targets, how many must answer
    up          3           # consecutive good checks to declare up
    down        3           # consecutive failed checks to declare down
    max_latency 150         # ms; breach means degraded (blank ignores)
    max_loss    5           # percent; breach means degraded (blank ignores)
    max_jitter  -           # ms (blank ignores)
    on_up       -           # command to run on an up transition
    on_down     -           # command to run on a down transition

    ?PROVIDER lte
    method      ping
    check       1.1.1.1     # a far host, reached through the link
    interval    15          # metered: probe gently
    metered     yes         # keep down until needed; dial on demand
    dial        "/etc/shorewall/dial-lte"    # on-demand bring-up hook
    hangup      "/etc/shorewall/hangup-lte"  # idle teardown hook

The defaults match the vendor consensus: interval 5s, timeout 3s, down
after 3 misses (about 15s to failover), up only after 3 good checks (the
anti-flap failback hold). `reliability` is the mwan3 quorum.
`max_latency`, `max_loss` and `max_jitter` add performance-based
tripping: a provider that pings but breaches a threshold is marked
degraded, which the monitor treats like down for steering. The monitor
validates the vendor invariants at load (timeout below interval, sane
thresholds) the way pfSense enforces its dpinger constraints.

Two shorewall.conf knobs govern the switch side effects, matching the
vendor toggles:

    LSM_FLUSH_CONNTRACK   Yes            # flush conntrack on a switch, so
                                         # live flows re-pin, not black-hole
    LSM_FAILBACK          sticky | snap  # ride flows out on the backup
                                         # after recovery, or move them now

## 11. Cellular and PPP backups (on-demand dial)

The request: dial a PPP interface on failover. This is the cellular
backup every vendor has, and it needs care, because a link that is fully
down cannot be probed, and a metered link should not be probed
continuously.

A backup provider is marked `metered` in the lsm file and carries a
`dial` hook. It is not in the usable set while the primaries are up; its
interface may not even exist yet, a `ppp0` that appears only when pppd
connects. The monitor treats "every higher-tier provider is down" as the
demand signal:

1. The primaries fail their checks and are marked down. The seam
   reroutes; with no primary usable, the backup's tier is next.
2. Before enabling the backup, the monitor runs its dial hook (`pppd call
   provider`, or `mmcli`/`qmicli` for a modem). The hook blocks until the
   interface is up with a gateway, or it times out.
3. On success the monitor enables the backup through the seam, which adds
   its routing. The existing point-to-point path (gateway `-`, script.py)
   already routes a ppp interface via the device. Only now does the
   monitor start probing the backup, over its own interface.
4. When a primary recovers, the monitor disables the backup, runs the
   `hangup` hook, and under `LSM_FAILBACK=snap` flushes conntrack so flows
   return to the primary.

This keeps the SIM idle until it is needed, which is the point of a
metered backup, and it reuses the point-to-point routing and the
enable/disable seam. The dial and hangup hooks are ordinary scripts, so
the mechanism is not tied to any modem stack. A lab uses a hook that
brings up a pre-created dummy `ppp0`, which is exactly how the harness
tests it: an event with an `exec` that runs the dial hook, then a probe
that the traffic now leaves over the backup.
