# interfaces

`/etc/shorewall/interfaces` says which network interface faces which zone, and
sets options on each interface.

```text
?FORMAT 2
#ZONE   INTERFACE   OPTIONS
```

## Columns

`ZONE`
: The zone this interface faces, from [zones](zones.md). A `-` means the
  interface belongs to no single zone; use it when [hosts](configuration-files.md)
  assigns the zones instead.

`INTERFACE`
: The interface. This can be the device name, such as `eth0`, or a logical name
  bound to a device with the `physical=` option. A logical name lets the rest of
  the configuration stay the same when a device is renamed. A trailing `+` is a
  wildcard: `eth0+` matches `eth0`, `eth0.1` and so on.

`OPTIONS`
: A comma-separated list of options. An unknown option is a compile error.

## Options

`physical=name`
: The real device for a logical interface name.

`dhcp`
: Allow the DHCP exchange on this interface. Use it when the address is leased.

`tcpflags`
: Drop packets with illegal TCP flag combinations.

`nosmurfs`
: Drop packets whose source is a broadcast or multicast address.

`routefilter`, `rpfilter`
: Reverse-path filtering. A packet is dropped if the reply would leave by a
  different interface. `rpfilter` is the strict fib check; established traffic is
  exempt.

`logmartians`
: Log packets with an impossible source address.

`sourceroute`
: Allow source-routed packets. `sourceroute=0` refuses them.

`routeback`
: Allow a packet to be sent back out the interface it arrived on.

`forward`
: Set the per-interface forwarding flag.

`proxyarp`, `arp`
: Proxy ARP controls for the interface.

`mss=number`
: Clamp the SYN MSS on this interface.

`sfilter`, `norfc1918`
: Accepted but not enforced yet, and warn.

## Example

The Internet interface leases its address and has the full set of sanity checks.
The local interface does not use DHCP.

```text
?FORMAT 2
#ZONE   INTERFACE   OPTIONS
net     NET_IF      dhcp,tcpflags,nosmurfs,routefilter,logmartians,physical=eth0
loc     LOC_IF      tcpflags,nosmurfs,routefilter,logmartians,physical=eth1
```

## See also

[zones](zones.md) declares the zones named here.
