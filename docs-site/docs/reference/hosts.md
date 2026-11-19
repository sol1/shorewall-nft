# hosts

`/etc/shorewall/hosts` scopes a zone to a set of addresses on an interface,
instead of a whole interface. Use it to split one interface into several zones, or
to put a few addresses on an interface into their own zone. The rest of the
interface stays in whatever zone the [interfaces](interfaces.md) file gives it.

For a worked setup see the
[multiple zones on one interface](../how-to/multiple-zones.md) guide.

## Columns

| Column | Meaning |
|---|---|
| ZONE | The zone these hosts belong to. It must be a declared [zone](zones.md). |
| HOSTS | The interface and the addresses, written `interface:addresses`. The addresses are a network or a comma-separated list. |
| OPTIONS | Optional. |

```text
#ZONE   HOSTS
admin   LOC:10.0.1.0/28
mgmt    eth1:10.0.1.128/25,10.0.2.0/24
```

The interface may be a logical name from the interfaces file or a physical device.
The addresses after the colon are the part of that interface that belongs to the
zone.

## Order and nesting

Where two zones could claim the same host, the first matching entry wins, so
declare the more specific zone first. A zone meant to sit inside another is
declared in [zones](zones.md) with the `child:parent` form, and a `CONTINUE`
policy lets a host in the child zone fall through to the parent's rules. See
[multiple zones on one interface](../how-to/multiple-zones.md).

An exclusion in the HOSTS column is not supported yet and is rejected.

## See also

[multiple zones on one interface](../how-to/multiple-zones.md) for a worked setup.
[zones](zones.md) for zone types and nesting.
[interfaces](interfaces.md) for assigning a whole interface to a zone.
