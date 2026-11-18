# Configuration files

shorewall-nft reads a directory of plain-text configuration files. On most
systems that directory is `/etc/shorewall` for IPv4 and `/etc/shorewall6` for
IPv6. Each file controls one part of the firewall. The reference pages that
follow describe one file each.

This page covers the rules common to all of them.

## Format

The files are column-based. Columns are separated by one or more spaces or tabs.
A column reads left to right in the order the file defines.

- A `#` starts a comment. The rest of the line is ignored.
- A blank line is ignored.
- A column you want to leave at its default takes a single `-`.
- A long line can be split. End a line with a backslash (`\`) and the next line
  continues it.

```text
#ACTION   SOURCE   DEST   PROTO   DPORT
ACCEPT    loc      net    tcp     22
```

## FORMAT

Some files have had columns added over the years. A `?FORMAT` directive at the
top of a file says which column layout the file uses, so an old file keeps
working after new columns are added.

```text
?FORMAT 2
```

The reference page for each file gives its current format. Shipped sample files
carry the right `?FORMAT` line already.

## Variables

Two files define variables you can use elsewhere:

- [params](params.md) holds variables you set, such as an address or an
  interface name. You write `$NAME` to use one.
- [shorewall.conf](shorewall-conf.md) holds the firewall's global settings. A
  setting such as `LOG_LEVEL` can also be used as `$LOG_LEVEL`.

One variable is always defined: `$FW` is the name of the firewall zone. Use it
wherever a rule refers to the firewall itself.

## Including other files

`?INCLUDE` reads another file in place, so you can split a large configuration
into pieces.

```text
?INCLUDE custom.rules
```

`?INCLUDE` takes one exact file name. To read every file in a directory, use
`?INCLUDE_GLOB`, a shorewall-nft extension. Matches are read in path order.

```text
?INCLUDE_GLOB rules.d/*.rules
```

A bare file name is looked for next to the including file first, then in the
directories listed in `CONFIG_PATH` in shorewall.conf. A name with a slash in it
is taken as written.

## Which directory

`shorewall start`, `check`, `compile` and the rest read `/etc/shorewall` by
default. Give a directory on the command line to read a different one, which is
how you test a configuration before installing it.

```sh
shorewall check /etc/shorewall.new
```

## The reference pages

- [shorewall](shorewall.md), the command.
- [shorewall.conf](shorewall-conf.md), the global settings.
- [zones](zones.md), the network zones.
- [interfaces](interfaces.md), the network interfaces.
- [policy](policy.md), the default policy between zones.
- [rules](rules.md), the exceptions to the policy.
- [snat](snat.md), source NAT and masquerading.
- [params](params.md), your own variables.
