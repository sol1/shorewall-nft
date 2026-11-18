# shorewall.conf

`/etc/shorewall/shorewall.conf` holds the firewall's global settings. Each
setting is `NAME=value`, one per line. A value with spaces is quoted.

```text
IP_FORWARDING=On
LOG_LEVEL="info"
```

A setting that changes how packets are handled is either honored or, if
shorewall-nft does not yet implement its non-default behavior, rejected with a
clear error. A setting left at its shipped default always compiles. Nothing that
would change the firewall is silently ignored.

A setting can be read elsewhere as a variable. `LOG_LEVEL="info"` lets a policy
or rule use `$LOG_LEVEL`.

## Honored

These are read and acted on.

`IP_FORWARDING`
: `On` turns packet forwarding on, `Off` turns it off, `Keep` (the default)
  leaves the kernel as it is. A router needs `On`. A host that must not forward
  stays safe with `Off` or `Keep`.

`ROUTE_FILTER`
: Sets reverse-path filtering.

`LOG_MARTIANS`
: Logs packets with impossible source addresses.

`CLAMPMSS`
: Clamps the SYN MSS to the path MTU, or to a fixed value.

`DROP_DEFAULT`, `REJECT_DEFAULT`, `ACCEPT_DEFAULT`
: The default action run before a `DROP`, `REJECT` or `ACCEPT` policy. `none`
  disables it.

`BLACKLIST_DISPOSITION`
: How a blacklist rule disposes of a packet.

`INVALID_DISPOSITION`
: How an invalid packet that matched no rule in the `INVALID` section is
  disposed of: `A_DROP`, `A_REJECT`, `DROP`, `REJECT` or `CONTINUE` (the
  default).

`MACLIST_DISPOSITION`
: How an unmatched MAC on a maclist interface is disposed of.

`TC_ENABLED`
: `Internal` or `Simple` selects the traffic-shaping model. `No` disables it.

`DOCKER`, `DOCKER_BRIDGE`
: Coexistence with Docker's own table.

`REQUIRE_IPSETS`
: `Yes` (the default) makes an unsupported ipset a compile error. `No` warns and
  skips it, so one odd set does not fail the whole ruleset.

`REQUIRE_SECURE_CONFIG`
: `No` (the default) warns if the configuration directory is group- or
  world-writable, or not owned by root when run as root. `Yes` makes it an
  error. A user who can edit the configuration can have their input run as root
  at start. This is a shorewall-nft addition.

`VERBOSITY`
: Progress detail for `start`, `restart`, `reload` and `stop`. `0` and below are
  quiet, `1` (the default) shows the main steps, `2` adds detail. The `-v`, `-q`
  and `-vN` options override it.

## Rejected if set to a non-default value

These change packet handling, and the non-default behavior is not implemented
yet. The default matches what shorewall-nft does, so a configuration at the
default compiles. A non-default value is an error that names the setting, never
a silent divergence.

`INVALID_LOG_LEVEL`, `RELATED_DISPOSITION`, `UNTRACKED_DISPOSITION`,
`SMURF_DISPOSITION`, `TCP_FLAGS_DISPOSITION`, `SFILTER_DISPOSITION`,
`RPFILTER_DISPOSITION`, `MACLIST_TABLE`, `ACCOUNTING_TABLE`, `MANGLE_ENABLED`,
`IMPLICIT_CONTINUE`, `MULTICAST`, `MARK_IN_FORWARD_CHAIN`, `BASIC_FILTERS`,
`REJECT_ACTION`, `TC_PRIOMAP`.

`FASTACCEPT` is accepted at any value and ignored. It only moves where
established and related traffic is accepted, for speed. The verdict is the same.

## Safe no-ops

Many settings do not change the generated ruleset. They name paths and tools,
set the log format, control compile-time optimization, or are informational.
They are accepted and have no effect. Examples are `PATH`, `IP`, `IPTABLES`,
`LOGFILE`, `LOGFORMAT`, `OPTIMIZE`, `AUTOMAKE`, `STARTUP_ENABLED` and the
per-feature `*_LOG_LEVEL` settings. Where one of these has a real effect not yet
covered, honoring it is future work; none of them weakens the firewall.

## CONFIG_PATH

`CONFIG_PATH` is the search path for `?INCLUDE`. A bare file name is looked for
next to the including file first, then in each `CONFIG_PATH` directory in order.
A name with a slash is taken as written. `${CONFDIR}` and `${SHAREDIR}` in the
value expand. `CONFIG_PATH` is not used to find the main configuration files;
those are read from the directory given on the command line.

## See also

[Configuration files](configuration-files.md) for the format shared by every
file.
