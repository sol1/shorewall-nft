# traffic shaping files

Traffic shaping is controlled by `TC_ENABLED` in
[shorewall.conf](shorewall-conf.md) and a set of files. Simple shaping uses
`tcinterfaces` and `tcpri`. Full shaping uses `tcdevices` and `tcclasses`.

For a worked setup see the [traffic shaping](../how-to/traffic-shaping.md) guide.

## TC_ENABLED

| Value | Meaning |
|---|---|
| `Internal` | Full shaping from `tcdevices` and `tcclasses`. The default. |
| `Simple` | Simple three-band shaping from `tcinterfaces` and `tcpri`. |
| `No` | No shaping. |

## Simple shaping

### tcinterfaces

One line per shaped interface. Simple shaping builds an egress token-bucket
limiter, a three-band priority queue with fair-queued leaves, and ingress
policing.

| Column | Meaning |
|---|---|
| INTERFACE | The interface to shape. |
| TYPE | `external` for an Internet-facing interface, `internal` for a local one. |
| IN_BANDWIDTH | The download rate to hold to, for ingress policing. |
| OUT_BANDWIDTH | The upload rate to hold to, for the egress queue. |

```text
#INTERFACE   TYPE       IN_BANDWIDTH   OUT_BANDWIDTH
eth0         external   20mbit         10mbit
```

Set the bandwidths a little below the true link speed, so the queue forms on the
firewall where it can be ordered rather than in the modem.

### tcpri

Assigns traffic to one of the three priority bands. Band 1 is served first.
Traffic that matches no line falls to band 3.

| Column | Meaning |
|---|---|
| BAND | 1, 2, or 3. |
| PROTO | The protocol, or `-`. |
| DPORT | The destination port, or `-`. |
| SPORT | The source port, or `-`. |
| ADDRESS | A source network, or a `~MAC` address, or `-`. |
| INTERFACE | The interface, or `-`. |

```text
#BAND   PROTO   DPORT
1       tcp     22
2       tcp     80
```

## Full shaping

### tcdevices

One line per shaped interface, with its total bandwidth. An optional number
before the interface sets the device number; otherwise they are numbered in
order.

| Column | Meaning |
|---|---|
| INTERFACE | The interface, optionally `number:interface`. |
| IN_BANDWIDTH | The ingress bandwidth, or `-`. |
| OUT_BANDWIDTH | The egress bandwidth, or `-`. |

```text
#INTERFACE   IN_BANDWIDTH   OUT_BANDWIDTH
eth0         20mbit         10mbit
```

An OPTIONS column is not supported yet and is rejected.

### tcclasses

The classes under a device. Each has a guaranteed rate, a ceiling it may borrow
up to, and a priority.

| Column | Meaning |
|---|---|
| INTERFACE | The device, as `interface:class` to set the class number. |
| MARK | The packet mark that selects this class, or `-`. A class needs a class number or a mark. |
| RATE | The guaranteed rate. |
| CEIL | The most the class may use when the link is otherwise idle. |
| PRIO | The priority. A lower number is served first. |
| OPTIONS | `default` marks the class that takes unclassified traffic. |

```text
#INTERFACE   MARK   RATE     CEIL     PRIO   OPTIONS
eth0:1       1      5mbit    10mbit   1
eth0:2       2      2mbit    10mbit   2      default
```

## See also

[traffic shaping](../how-to/traffic-shaping.md) for a worked setup.
[shorewall.conf](shorewall-conf.md) for `TC_ENABLED`.
