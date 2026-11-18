# params

`/etc/shorewall/params` holds variables you define. Set an address, a network or
an interface name once here, then use it by name in the other files. A change to
the value changes every file that uses it.

```text
NET_IF=eth0
ADMIN=192.168.1.0/24
```

Use a variable elsewhere with a leading `$`:

```text
#ACTION        SOURCE   DEST
SSH(ACCEPT)    $ADMIN   $FW
```

## Format

Each line is `NAME=value`, the way a shell assigns a variable. A value with
spaces is quoted. The file is read before the others, so a variable is set before
anything uses it.

`$FW` is always defined as the firewall zone, even if params is empty. You do not
set it.

## Shell logic

A params file may use shell features: a loop, a test, a command in `$(...)` or
backticks, or sourcing another file. When shorewall-nft sees shell logic, it runs
the file through the shell to get the values, the way Shorewall does. A plain file
of `NAME=value` lines does not need the shell.

## Example

Name the two interfaces and the admin network, then use them.

```text
NET_IF=eth0
LOC_IF=eth1
ADMIN=10.0.1.0/24
```

## See also

[shorewall.conf](shorewall-conf.md) holds the firewall's global settings, which
can also be read as variables.
