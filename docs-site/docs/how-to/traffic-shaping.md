<!-- docs-proof: base=getting-started/two-interface.md -->
# Traffic shaping

Traffic shaping decides which packets go first when a link is full. Without it,
a large download or an upload can starve an interactive session, and SSH or a
voice call turns to treacle. Shaping gives latency-sensitive traffic priority, so
the link stays responsive under load.

Shorewall has two modes. Simple shaping sorts traffic into three priority bands
with almost no configuration. Full shaping builds a classful tree with
guaranteed and capped rates per class. This guide covers simple shaping, which is
enough for most firewalls. The [traffic shaping reference](../reference/tc.md)
covers the full model.

This guide adds to the [two-interface firewall](../getting-started/two-interface.md).

## Turn on simple shaping

Set the mode in `shorewall.conf`.

```text title="/etc/shorewall/shorewall.conf"
TC_ENABLED=Simple
```

## Declare the link speed

Shaping only works if Shorewall knows how fast the link really is. It holds the
queue on the firewall, just under the true rate, so the firewall decides the
order instead of the modem. List the interface, its type, and its speeds in
`tcinterfaces`.

```text title="/etc/shorewall/tcinterfaces"
#INTERFACE   TYPE       IN_BANDWIDTH   OUT_BANDWIDTH
eth0         external   20mbit         10mbit
```

`external` marks the interface that faces the Internet. Set `OUT_BANDWIDTH` a
little below your real upload speed and `IN_BANDWIDTH` a little below your real
download speed, so the queue forms on the firewall where it can be managed.

## Sort traffic into bands

Simple shaping has three priority bands. Band 1 goes first, then band 2, then
band 3. Assign traffic to a band in `tcpri` by protocol and port.

```text title="/etc/shorewall/tcpri"
#BAND   PROTO   DPORT
1       tcp     22
2       tcp     80
```

SSH goes in band 1, so it stays quick even while the link is busy. Web traffic
goes in band 2. Everything not listed falls to band 3. With this in place a bulk
transfer in band 3 yields to an SSH session in band 1, and the session keeps its
latency.

The `tcpri` columns after the band are the same match fields as a rule: protocol,
destination port, source port, address, and interface. Match on what you want to
prioritize.

## Full shaping

When you need more than three bands, or a guaranteed rate for a class, use the
full model. Set `TC_ENABLED=Internal`, define each interface and its total
bandwidth in `tcdevices`, and define the classes, each with a rate, a ceiling,
and a priority, in `tcclasses`. The [traffic shaping reference](../reference/tc.md)
describes both files.

## See also

[traffic shaping files](../reference/tc.md) for `tcinterfaces`, `tcpri`,
`tcdevices`, and `tcclasses`.
