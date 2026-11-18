<!-- docs-proof: base=getting-started/two-interface.md -->
# rules

`/etc/shorewall/rules` holds the exceptions to the [policy](policy.md). A rule
opens or closes one kind of traffic between two zones, or between a zone and the
firewall.

```text
#ACTION   SOURCE   DEST   PROTO   DPORT   SPORT   ORIGDEST   RATE   USER   MARK   CONNLIMIT   TIME   HEADERS   SWITCH   HELPER
```

Only the first few columns are used in most rules. Leave the rest at `-`.

## Columns

`ACTION`
: What to do. See below.

`SOURCE`
: Where the traffic comes from: a zone, or a zone narrowed to an interface or
  address. See the forms below.

`DEST`
: Where it goes, in the same forms as `SOURCE`. For `DNAT` and `REDIRECT` this is
  the internal host and, after a colon, the address or port to send it to.

`PROTO`
: The protocol: `tcp`, `udp`, `icmp`, a number, or `-`.

`DPORT`
: The destination port or ports. A list is comma-separated.

`SPORT`
: The source port or ports.

`ORIGDEST`
: The original destination, for matching DNATed traffic.

`RATE`
: Rate-limit new connections this rule matches.

`USER`
: Match by the local user or group that owns the socket.

`MARK`
: Match on a packet mark.

The remaining columns (`CONNLIMIT`, `TIME`, `HEADERS`, `SWITCH`, `HELPER`) are
less common and are described in the configuration comments.

## Actions

`ACCEPT`, `DROP`, `REJECT`, `CONTINUE`
: Allow, discard silently, discard with an error, or leave for a later decision.

`DNAT`
: Rewrite the destination and forward the connection to an internal host. This is
  port forwarding.

`REDIRECT`
: Send the connection to a port on the firewall itself.

A macro
: A named bundle of rules for a service, such as `SSH`, `DNS`, `Web` or `Ping`.
  Write the verdict in parentheses: `SSH(ACCEPT)`.

A user action
: An action you define, from [actions](configuration-files.md).

`LOG`, `NFLOG`, `QUEUE`, `NFQUEUE`
: Log the traffic, or hand it to a userspace program.

## Sections

Rules are grouped by connection state. A `?SECTION` line starts a group. Order
is fixed.

```text
?SECTION ALL
?SECTION ESTABLISHED
?SECTION RELATED
?SECTION INVALID
?SECTION UNTRACKED
?SECTION NEW
```

Most rules go in `NEW`, which matches new connections. Established and related
traffic is handled for you, so a reply always gets back. A file with no
`?SECTION` line treats every rule as `NEW`.

## Source and destination forms

Both `SOURCE` and `DEST` accept more than a bare zone name.

`zone:interface`
: Narrow to one interface, such as `loc:eth1`.

`zone:interface:address`
: Narrow further to an address.

`zone:address`
: An address or a comma-separated list of addresses or networks.

`zone:range`
: An address range.

`zone:+setname`
: Members of an ipset.

`zone:~MAC`
: A source MAC address.

`zone:^CC`
: Hosts in a country, by two-letter code, using geoip.

`zone:included!excluded`
: Everything in the first part except the second.

`&interface`
: The primary address of an interface, resolved when the firewall loads.

## Example

Administer the firewall over SSH from the local network, let the firewall resolve
names, and forward web traffic from the Internet to an internal server.

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION        SOURCE   DEST                PROTO   DPORT
SSH(ACCEPT)    loc      $FW
DNS(ACCEPT)    $FW      net
DNAT           net      loc:10.0.1.20       tcp     443
```

The `DNAT` rule sends connections arriving from the Internet on TCP 443 to the
host `10.0.1.20` inside the local network.

## See also

[policy](policy.md) for the defaults these rules override.
[snat](snat.md) for rewriting the source address of outbound traffic.
