<!-- docs-proof: base=getting-started/two-interface.md -->
# Logging

Shorewall logs a packet by handing it to the kernel log. The message lands in the
system log, usually the journal or `/var/log/messages`, with a prefix that names
the chain and the disposition, such as `shorewall:net2fw:DROP:`. You log to see
what the firewall is dropping, and to confirm a rule matches.

This guide adds to the [two-interface firewall](../getting-started/two-interface.md).

## Logging a policy

The [policy](../reference/policy.md) file logs through its `LOGLEVEL` column. The
two-interface policy already logs dropped traffic from the Internet:

```text
#SOURCE   DEST   POLICY   LOGLEVEL
net       all    DROP     info
```

Every connection the Internet tries to open, and that no rule allowed, is logged
at level `info` and then dropped.

## Logging a rule

Append `:level` to a rule's action to log the traffic the rule matches. The level
is a syslog level such as `info`, `notice` or `warning`.

```text
#ACTION         SOURCE   DEST   PROTO   DPORT
ACCEPT:info     net      $FW    tcp     443
REJECT:info     net      $FW    tcp     23
```

The first line logs and accepts web traffic to the firewall. The second logs and
rejects attempts to reach telnet.

## A complete rules file

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION         SOURCE   DEST   PROTO   DPORT
Invalid(DROP)   net      all    tcp
DNS(ACCEPT)     $FW      net
SSH(ACCEPT)     loc      $FW
ACCEPT:info     net      $FW    tcp     443
REJECT:info     net      $FW    tcp     23
```

## Reading the log

The messages go to the system log. With journald:

```sh
journalctl -k | grep shorewall
```

Each line carries the prefix, so `shorewall:net2fw:DROP:` is a packet from `net`
to the firewall that the `net` to firewall policy dropped.

## Log only what you need

A busy Internet link drops a lot. Logging every drop fills the log. The policy
already rate-limits its own logging. Log specific rules when you are chasing one
problem, and turn the logging off again once you have the answer.

## See also

[policy](../reference/policy.md) and [rules](../reference/rules.md) for the columns
that carry a log level.
