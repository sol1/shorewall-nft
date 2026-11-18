# policy

`/etc/shorewall/policy` sets the default for traffic between each pair of zones.
[rules](rules.md) make the exceptions. The policy is the firewall's stance:
rules open the few things you allow against it.

```text
#SOURCE   DEST   POLICY   LOGLEVEL   RATE   CONNLIMIT
```

## Columns

`SOURCE`
: The zone the traffic comes from, or `all` for every zone.

`DEST`
: The zone the traffic goes to, or `all`.

`POLICY`
: What to do with traffic this line matches. See below.

`LOGLEVEL`
: Log matched traffic at this level, such as `info`. Leave it as `-` for no log.

`RATE`
: Rate-limit new connections this policy matches.

`CONNLIMIT`
: Limit the number of simultaneous connections per source.

## Policies

`ACCEPT`
: Allow the traffic.

`DROP`
: Discard it with no reply. The sender sees a timeout.

`REJECT`
: Discard it and send an error back.

`CONTINUE`
: Leave the traffic for a later rule or policy to decide. Used with nested zones.

`QUEUE`, `NFQUEUE`
: Hand the traffic to a userspace program.

`NONE`
: There is never any traffic between these zones. Generate no rules.

## Order matters

The policy file is read top to bottom. The first line that matches a pair of
zones wins, so write specific lines before general ones. The last line is almost
always the catch-all:

```text
all   all   REJECT   info
```

Traffic between a zone and itself is accepted by default. A `DROP` or `REJECT`
policy runs the default action first (`DROP_DEFAULT`, `REJECT_DEFAULT` in
[shorewall.conf](shorewall-conf.md)), which drops broadcasts and multicasts
quietly so the log is not flooded.

## Example

Let the local network out, keep the Internet out, and reject anything else.

```text
#SOURCE   DEST   POLICY   LOGLEVEL
loc       net    ACCEPT
net       all    DROP     info
all       all    REJECT   info
```

## See also

[rules](rules.md) for the exceptions to these defaults.
