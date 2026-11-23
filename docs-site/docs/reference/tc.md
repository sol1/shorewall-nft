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
policing. Each interface gets its own queues. An interface that is down when
the firewall starts is skipped with a warning.

| Column | Meaning |
|---|---|
| INTERFACE | The interface to shape. Each interface may be listed once. |
| TYPE | `external` for an Internet-facing interface, `internal` for a local one, or `-`. This sets how the hosts behind the interface share a band: `external` gives each source host a fair share, `internal` each destination host, and `-` shares nothing out. |
| IN_BANDWIDTH | The download rate to hold to, for ingress policing. See [IN_BANDWIDTH](#in_bandwidth). |
| OUT_BANDWIDTH | The upload rate to hold to, for the egress queue, or `-` for no limit. See [OUT_BANDWIDTH](#out_bandwidth). |

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
| IN_BANDWIDTH | The ingress bandwidth, or `-`. See [IN_BANDWIDTH](#in_bandwidth). |
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

## IN_BANDWIDTH

The IN_BANDWIDTH column of tcinterfaces and tcdevices polices incoming
traffic. It takes one of three forms.

| Form | Meaning |
|---|---|
| `-` or `0` | No ingress policing. |
| `rate[:burst]` | Drop traffic above *rate*. *burst* is how much may arrive at once, 10kb by default. |
| `~rate[:interval:decay]` | Drop traffic once its estimated average rate passes *rate*. The estimator samples every *interval* (250ms, 500ms, 1sec, 2sec, 4sec or 8sec) and averages over *decay* (500ms, or 1sec to 64sec in powers of two), which must be longer than the interval. The default is 250ms:4sec. |

A rate takes kbit, mbit, gbit, kbps, mbps or gbps. A bare number is bytes per
second.

```text
#INTERFACE   TYPE       IN_BANDWIDTH        OUT_BANDWIDTH
eth0         external   900mbit:256kb       45mbit
eth1         external   ~20mbit:500ms:8sec  10mbit
```

The 10kb default burst is too small for a fast link. A network card merges
incoming packets into chunks of up to 64KB before the policer sees them, and the
policer drops any chunk bigger than the burst. At gigabit speeds that can cut a
download from 100MB/s to a few MB/s. Give a fast link a larger burst. 256kb
holds a gigabit link.

The `~` form needs the tc basic classifier. RHEL, Rocky and AlmaLinux 9 kernels
do not have it, so there the `~` form is an error and the `rate[:burst]` form
polices with u32 filters instead.

## OUT_BANDWIDTH

The OUT_BANDWIDTH column of tcinterfaces limits outgoing traffic with a token
bucket. It takes `-` for no limit, or `rate[:burst[:latency[:peak[:minburst]]]]`.

| Field | Meaning |
|---|---|
| rate | The rate to hold to. Set it a little below the true upload speed. |
| burst | How much may be sent at once, 10kb by default. |
| latency | How long a packet may wait for its turn before it is dropped, 200ms by default. |
| peak | A higher rate the bucket may send at briefly after it has been idle. |
| minburst | The packet size the peak rate is measured over, usually the interface MTU. Give it whenever you give a peak. |

A rate takes the units IN_BANDWIDTH takes. Leave a field empty to keep its
default.

```text
#INTERFACE   TYPE       IN_BANDWIDTH   OUT_BANDWIDTH
eth0         external   20mbit         10mbit
eth1         internal   -              10mbit::100ms:12mbit:1500
```

An interface with no OUT_BANDWIDTH still gets the three-band priority queue, so
tcpri sorts its traffic, but nothing holds its rate down.

## See also

[traffic shaping](../how-to/traffic-shaping.md) for a worked setup.
[shorewall.conf](shorewall-conf.md) for `TC_ENABLED`.
