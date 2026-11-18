<!-- docs-proof: base=getting-started/two-interface.md -->
# Rate limiting

A rate limit caps how fast new connections are accepted. Use it to slow a
brute-force attempt against a service, or to keep one source from flooding the
firewall. Shorewall sets the limit in the `RATE` column of a
[rule](../reference/rules.md) or a [policy](../reference/policy.md).

This guide adds to the [two-interface firewall](../getting-started/two-interface.md).

## The rate syntax

A rate is written `count/unit:burst`.

- `count/unit` is the sustained rate, such as `3/min` or `10/sec`.
- `burst` is how many connections may arrive in a clump before the limit applies.

So `3/min:5` allows a burst of 5, then settles to 3 per minute.

## Rate-limiting a rule

The `RATE` column is the eighth column, after `ORIGDEST`. Leave the columns
between at `-`. This accepts new SSH from the Internet, but no faster than 3 a
minute:

```text
#ACTION   SOURCE   DEST   PROTO   DPORT   SPORT   ORIGDEST   RATE
ACCEPT    net      $FW    tcp     22      -       -          3/min:5
```

A connection over the limit is dropped. A legitimate admin gets in; a script
trying thousands of passwords is throttled.

## A complete rules file

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION         SOURCE   DEST   PROTO   DPORT   SPORT   ORIGDEST   RATE
Invalid(DROP)   net      all    tcp
DNS(ACCEPT)     $FW      net
SSH(ACCEPT)     loc      $FW
ACCEPT          net      $FW    tcp     22      -       -          3/min:5
```

## Rate-limiting a policy

A policy takes a rate in its own `RATE` column. This limits new connections the
policy accepts, rather than one service:

```text
#SOURCE   DEST   POLICY   LOGLEVEL   RATE
net       all    DROP     info       10/sec:20
```

## See also

[rules](../reference/rules.md) and [policy](../reference/policy.md) for the
`RATE` column.
