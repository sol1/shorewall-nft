# tcfilters

The tcfilters file classifies traffic into the HTB classes that tcdevices and
tcclasses build, by matching on addresses, protocol, ports, TOS and length,
rather than by a firewall mark. It is the last classful traffic-shaping file we
do not support. This note specifies how we implement it.

## What it is

With tcdevices and tcclasses a config builds an HTB tree and gives each class a
mark. Traffic reaches a class by carrying that mark, set in the mangle file.
tcfilters is the alternative: it binds traffic to a class directly, with a tc
u32 filter, so a class can be selected without spending a mark. The two
coexist; a class can be reached by mark, by filter, or both.

Shaping lives in the tc layer whether the firewall is iptables or nftables, so
tcfilters compiles to the same tc u32 filters upstream emits. It is not an
nftables construct. Classifying with a native `meta priority` rule instead
would leave no tc filter to compare, so the differential tc-state test could
not check it against upstream. We emit the tc filters upstream emits.

## File format

One rule per line. Columns, from shorewall-tcfilters(5):

    CLASS  SOURCE  DEST  PROTO  DPORT  SPORT  TOS  LENGTH  PRIORITY

- **CLASS** (required) is `device:minor`: the device, by name or number, and
  the classid minor of a class on it. The minor is the tcclasses class number,
  which is `10 + the class or mark number` in the generated tree (class mark 1
  is classid `1:11`). It must name a defined leaf class; a non-leaf or unknown
  class is a located error.
- **SOURCE**, **DEST** are an address or CIDR, or `-`.
- **PROTO** is a protocol name or number, or `-`. Required if a port is given.
- **DPORT**, **SPORT** are a port or port list, or `-`. Only tcp, udp and sctp
  take a port; a dport may also be an icmp type for icmp.
- **TOS** is a TOS name or `value` or `value/mask`, or `-`.
- **LENGTH** is a power-of-two packet-length bucket, or `-`.
- **PRIORITY** is the tc filter priority, or `-` to auto-number per device.

## Emission

Family picks the match keywords: `ip`/`ip` for IPv4, `ipv6`/`ip6` for IPv6.
The device number is the tcdevices number; filters attach at `parent num:0`.

A rule with no port is one u32 filter:

    tc filter add dev DEV protocol ip parent NUM:0 prio P u32 \
       match ip src S/mask \
       match ip dst D/mask \
       match ip tos TOS mask \
       match u16 0x0000 LENMASK at 2 \
       match ip protocol PROTO 0xff \
       flowid NUM:minor

The length offset is 2 for IPv4 and 4 for IPv6. A rule with no match at all
(only a CLASS) is a degenerate filter and is warned and skipped, as upstream
does.

A rule with a port needs the transport header, which sits at a variable offset
after the IP header. Upstream reaches it with a u32 hash table, and we do the
same so the tc state matches:

    # once per (device, base match) that carries a port
    tc filter add dev DEV parent NUM:0 protocol ip prio P handle T: u32 divisor 1
    tc filter add dev DEV protocol ip parent NUM:0 prio P u32 \
       match ip src S/mask \
       match ip protocol 6 0xff \
       link T:0 offset at 0 mask 0x0F00 shift 6 plus 0 eat
    # one per port in the list
    tc filter add dev DEV protocol ip parent NUM:0 prio P u32 ht T:0 \
       match tcp dport 80 0xffff \
       flowid NUM:minor

The IPv6 link form is `link T:0 offset plus 40 eat`, since the IPv6 header is a
fixed 40 bytes. Ports use `match tcp|udp dport|src PORT 0xffff`; sctp uses a u32
match at `nexthdr+0`. The hash table is reused when consecutive port rules share
the same base match, as upstream reuses it.

Priority auto-numbers per device from 1 when PRIORITY is `-`, tracking the
highest explicit priority seen so an explicit value does not collide with a
later auto one.

## Out of scope for the first cut

- **BASIC_FILTERS**. Upstream has a second code path that emits the tc `basic`
  classifier when BASIC_FILTERS=Yes. RHEL, Rocky and AlmaLinux 9 ship kernels
  without cls_basic (see #32), so we keep the u32 path and do not implement the
  basic variant. BASIC_FILTERS=Yes is a located error.
- **icmp type/code dports** and multi-port ranges land in a second pass once the
  single-port tcp/udp path is proven against upstream.

## Integration

- `model.py`: a `TcFilter` record (class ref, source, dest, proto, dports,
  sports, tos, length, priority, origin).
- `parsers.py`: `parse_tcfilters`, validating the columns and that a port
  carries a proto.
- `compile.py`: load tcfilters into `cfg.tcfilters`; drop tcfilters from the
  fail-loud list.
- `script.py`: `_tc` emits the filters after the classes of each device,
  resolving each CLASS to a defined leaf class and raising a located error
  otherwise.

## Testing

- A corpus case under tests/corpus with tcdevices, tcclasses and tcfilters,
  `mode = "script"`, comparing the tc state (qdiscs, classes and filters)
  against upstream, plus probes that confirm a classified flow still forwards.
- A unit test rendering `_tc` with tcfilters and asserting the generated u32
  lines, including the port hash-table form and the class-resolution errors.

## status

`shorewall status` gains a traffic-shaping section when tcdevices are
configured: per device, the qdisc and each class with its rate, ceiling and
live byte and packet counters (`tc -s class show`), so an operator can see
which classes are carrying traffic. It is omitted when no device is shaped.
