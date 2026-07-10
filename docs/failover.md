# Multi-ISP failover

shorewall-nft does multi-ISP the way Shorewall always did: the
`providers` and `rtrules` files, imported unchanged. On top of that it
adds runtime control and a link monitor, so a provider can be taken out
of service or fail over on its own without a reload. All of it is
opt-in. A box with providers and no monitor behaves exactly as the
configuration it imported.

## Providers

`/etc/shorewall/providers` is read unchanged. The options acted on:

| Option | Effect |
|---|---|
| `balance[=weight]` | Share outbound traffic across providers, per connection, in proportion to the weights. |
| `fallback[=weight]` | A last-resort default, used only when every balanced provider is down. With a weight it is a balanced fallback; without one, a metric route ordered by provider number (lowest first). |
| `track` | Keep a connection's replies on the interface it arrived on. Needed for inbound services on a non-default link. |
| `loose` | Do not add the automatic per-source-address rules; you control routing with `rtrules`. |
| `optional` | The provider may be down. It is skipped when its interface is down, not an error. |
| `persistent` | Keep watching a down provider so it recovers on its own. A persistent provider is monitored by default, even without an `lsm` entry. |

## Route rules and per-network preference

`rtrules` pins traffic to a provider. To prefer one link for a network
and fall back to another, write two rules at adjacent priorities:

    #SOURCE          DEST  PROVIDER  PRIORITY
    192.168.5.0/24   -     isp1      11000
    192.168.5.0/24   -     isp2      11001

Policy routing falls through to the next rule when a rule's table has no
route. While isp1 is up the network uses it; when isp1 is taken down its
table empties and the traffic falls through to isp2. This is failover
with no monitor, driven by the runtime recompute below.

## Runtime control

These change routing without touching the packet filter and without a
reload:

    shorewall disable <provider>    # take it out of service
    shorewall enable  <provider>    # put it back
    shorewall reenable <provider>   # reset to enabled

Disabling empties the provider's table and drops it from the balanced
default; enabling rebuilds it. The last enabled provider cannot be
disabled, so a mistake cannot black-hole the box.

    shorewall show providers

prints the posture: each provider with its interface, gateway, options
and up/enabled state, the monitor line, the route rules that steer to it,
the balanced default, and an on-failure section that states what each
network does when a provider is lost. It shows the configured posture
when the firewall is stopped and live state when it is running.

## The link monitor

`shorewall-lsm` probes each provider and drives the verbs above on a
state change. It is configured in a new file, `/etc/shorewall/lsm` (and
`/etc/shorewall6/lsm`), one block per monitored provider:

    ?PROVIDER isp1
    method      ping        # ping
    check       -           # target; - is the provider gateway
    interface   -           # - is the provider interface (probes bind here)
    interval    5           # seconds between checks
    timeout     3           # seconds to wait for a reply
    count       1           # echoes per check
    reliability 1           # of N targets, how many must answer
    up          3           # consecutive good checks to declare up
    down        3           # consecutive failed checks to declare down
    max_latency 0           # ms; over this a reachable link counts down (0 off)
    max_loss    0           # percent; over this a reachable link counts down

    ?PROVIDER isp2
    check       1.1.1.1     # a host reached through the link, not the gateway

The interface and gateway come from the `providers` file; this file adds
only the monitoring policy. Probes are bound to the provider's interface,
so they test that link, not whichever one currently holds the default
route. A far `check` target (a well-known host) tests reachability
through the link rather than just the local gateway.

A point-to-point provider (ppp, WireGuard) has no gateway, so the default
target does not resolve. Give it an explicit `check` target; without one
it is not monitored, and a warning says so, rather than being reported
down and disabled while its link is up.

The state machine is deliberate: a link goes down only after `down`
consecutive failed checks and comes back only after `up` consecutive
good ones, so a brief blip does not flap the routes. `reliability` is a
quorum over several `check` targets. `max_latency` and `max_loss` fail a
link that still answers but is too slow or too lossy.

Run it in the foreground for a look, or as the service:

    shorewall lsm                    # foreground
    systemctl enable --now shorewall-lsm.service

The service is shipped disabled. It writes each provider's state under
`${STATE}/lsm`, which `shorewall status` and `shorewall show providers`
report.

## A worked example

Two wired ISPs balanced 2:1, with a third link as a fallback, all
monitored.

`/etc/shorewall/providers`:

    #NAME  NUMBER  MARK  DUPLICATE  INTERFACE  GATEWAY      OPTIONS
    isp1   1       1     -          eth0       198.51.100.1 track,balance=2
    isp2   2       2     -          eth1       203.0.113.1  track,balance=1
    backup 3       3     -          eth2       192.0.2.1    track,fallback,optional,persistent

`/etc/shorewall/lsm`:

    ?PROVIDER isp1
    check 1.1.1.1
    ?PROVIDER isp2
    check 1.0.0.1
    ?PROVIDER backup
    check 8.8.8.8

Then:

    shorewall restart
    systemctl enable --now shorewall-lsm.service
    shorewall show providers

Outbound traffic balances 2:1 across isp1 and isp2. If one drops, its
probe fails, the monitor disables it, and the balance continues over the
other. If both drop, traffic falls to `backup` through the fallback
table. When a link recovers, the monitor re-enables it.

## How it fits together

The compiler produces a static ruleset. Nothing above changes it. The
provider state and the balanced default are recomputed at runtime by one
function that reads the set of usable providers; the verbs and the
monitor call it. So `disable` cannot open a hole in the firewall, it only
changes which uplink egress traffic takes. If the monitor stops, routing
holds its last state and the firewall keeps filtering.

See docs/design/multi-isp-lsm.md for the design and the vendor
comparison behind it.
