# providers

`/etc/shorewall/providers` defines the Internet links on a multi-ISP firewall.
Each line is one provider: a routing table, a packet mark, an interface, and a
gateway. The compiler turns these into the route tables, the policy routing
rules, and the balanced default route. Companion files are
[rtrules](#rtrules), which pins traffic to a provider, and the
[lsm](#the-lsm-file) file, which configures the link monitor.

For a worked setup see the [multiple ISPs](../how-to/multi-isp.md) guide.

## The providers file

Columns, in order:

| Column | Meaning |
|---|---|
| NAME | The provider name. Also the routing table name and the status file name. Letters, digits, and underscore. |
| NUMBER | The routing table number, 1 to 252. Each provider needs a distinct one. |
| MARK | The packet mark for this provider, an integer. Used to send a marked packet out this link. |
| DUPLICATE | Accepted as a column but ignored. The routing layout is fixed. |
| INTERFACE | The interface facing this provider. A logical name from [interfaces](interfaces.md) or a physical device. |
| GATEWAY | The next hop. An address, `detect` to read it from the interface, or `-` for a point-to-point link with no gateway. |
| OPTIONS | A comma-separated list. See below. |
| COPY | Accepted as a column but ignored. |

```text
#NAME   NUMBER  MARK    DUPLICATE       INTERFACE       GATEWAY         OPTIONS
isp1    1       1       -               eth0            203.0.113.2     track,balance=1
isp2    2       2       -               eth1            198.51.100.2    track,balance=1
```

## Options

A provider option is a word, sometimes with `=` and a number.

| Option | Effect here |
|---|---|
| `track` | Marks each connection with its provider, so a reply returns on the same link. Needed for any link that accepts incoming connections. |
| `balance`, `balance=N` | Puts the provider in the shared default route. `N` is a weight, default 1. Two providers at `balance=1` share new connections evenly; `balance=2` on one takes twice the share. |
| `loose` | Suppresses the per-source routing rules that would otherwise pin a connection's reply to the interface it arrived on. |
| `primary` | Accepted. Treated as `balance=1`. |
| `fallback`, `fallback=N` | Installs a last-resort default route in table 253, used only when the balanced default has no route. A weight makes a balanced fallback; without one it is a metric route. |
| `optional` | Accepted. It has no extra effect today: a provider whose interface is down at start is already skipped, so a down link never breaks the routing. |
| `persistent` | The link monitor watches a persistent provider with default settings even without an [lsm](#the-lsm-file) block, so it recovers on its own. |

Any other option is an error. Upstream options that are not built yet, such as
`load=`, `tproxy`, `mtu=`, and `src=`, are rejected with a located message
rather than silently ignored.

Balancing and connection tracking are set per provider here, not through
`shorewall.conf`. See [below](#shorewall-conf-and-multi-isp).

## rtrules

`/etc/shorewall/rtrules` sends traffic that matches a source or a destination to
a named provider, overriding the balance. Columns: SOURCE, DEST, PROVIDER,
PRIORITY, and an optional MARK.

```text
#SOURCE         DEST            PROVIDER        PRIORITY
-               198.51.100.0/24 isp2            11000
10.0.1.8        -               isp1            11000
```

- SOURCE and DEST take an address, a CIDR network, or `-` for any. SOURCE also
  takes an interface name, `interface:address` to combine the two, or
  `&interface` to resolve the interface's own address at runtime. Either column
  may be a comma-separated list.
- PROVIDER is a provider name or number, or `main` or `default`.
- PRIORITY is a number. A lower number is consulted first. A trailing `!` makes
  the rule persistent, so a reload does not remove it.
- MARK, if given, matches the packet mark. It becomes an `fwmark` match with a
  default `/0xff` mask.

## The lsm file

`/etc/shorewall/lsm` configures the link monitor. One block per monitored
provider, introduced by `?PROVIDER` and the provider's name. The settings that
follow apply until the next `?PROVIDER`.

```text
?PROVIDER isp1
check -
interval 10
down 3

?PROVIDER isp2
check 1.1.1.1 8.8.8.8
reliability 1
interval 10
down 3
```

| Setting | Default | Meaning |
|---|---|---|
| `method` | `ping` | How to probe. `ping` sends ICMP echoes. |
| `check` | `-` | The targets to probe, space or comma separated. `-` means the provider's gateway from the providers file. |
| `interface` | `-` | The interface to probe from. `-` means the provider's interface. |
| `interval` | `5` | Seconds between checks. At least 1. |
| `timeout` | `3` | Seconds to wait for each probe. At least 1. |
| `count` | `1` | Echoes per probe. At least 1. |
| `reliability` | `1` | How many targets must answer for the link to count as up. At least 1, and no more than the number of targets. |
| `up` | `3` | Consecutive good checks before a down link is declared up again. At least 1. |
| `down` | `3` | Consecutive failed checks before an up link is declared down. At least 1. |
| `max_latency` | `0` | Milliseconds. A probe slower than this counts as a failure. `0` ignores latency. |
| `max_loss` | `0` | Percent. Loss above this counts as a failure. `0` ignores loss. |
| `metered` | `no` | Marks a link as metered, for reporting. |
| `dial`, `hangup` | `-` | Commands to bring a dial-up link up or down. |

A provider with no probe target, a point-to-point link with no gateway and no
`check`, is reported and left unmonitored rather than probed against nothing.

## Runtime commands

These act on a running firewall. They recompute the routing over the usable
providers without reloading the ruleset, so they are fast and do not drop
connections on the links that stay up.

| Command | Effect |
|---|---|
| `shorewall show providers` | The posture of every provider: up or down, enabled or disabled, its options, its monitor, and what happens to each routed network if the provider is lost. |
| `shorewall show routing` | The policy routing rules and every route table. |
| `shorewall show routing <dest> [from SRC] [iif IFACE] [mark N]` | The route one flow would take, and the provider the answer lands on. |
| `shorewall disable <provider>` | Marks the provider down and recomputes the routing. Refuses to disable the last enabled provider. |
| `shorewall enable <provider>` | Returns the provider to service and recomputes the routing. |
| `shorewall reenable <provider>` | Resets the provider to enabled. |
| `shorewall lsm [--once]` | Runs the link monitor. `--once` runs a single check cycle, for cron or scripting. |

The monitor only re-enables a provider it disabled itself, so a link flap never
undoes a `disable` you ran by hand. On a packaged install the monitor runs as
the `shorewall-lsm` service, started after the firewall:

```text
systemctl enable --now shorewall-lsm
```

## shorewall.conf and multi-ISP {#shorewall-conf-and-multi-isp}

The routing layout is fixed. It is the one upstream selects with
`USE_DEFAULT_RT=Yes`: the main table at a high priority, the balanced default in
table 250, and a provider table per link. It is not selectable.

Because of that, the provider-routing settings in `shorewall.conf` are accepted
and ignored: `USE_DEFAULT_RT`, `BALANCE_PROVIDERS`, `TRACK_PROVIDERS`,
`RESTORE_DEFAULT_ROUTE`, `KEEP_RT_TABLES`, `PROVIDER_OFFSET`, `PROVIDER_BITS`,
`TC_BITS`, and `MASK_BITS`. Set balancing and tracking per provider in the
providers file instead. `MARK_IN_FORWARD_CHAIN` is honored only at its default,
`No`, and rejected if set otherwise. See
[shorewall.conf](shorewall-conf.md).

## See also

[multiple ISPs](../how-to/multi-isp.md) for a worked setup.
[interfaces](interfaces.md) for the logical interface names used here.
