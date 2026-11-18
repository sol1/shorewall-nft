<!-- docs-proof: base=getting-started/two-interface.md -->
# Blacklisting

Blacklisting blocks traffic from a source before the normal rules run. Use it to
shut out an address that is attacking you, a network you never deal with, or a
whole country. Shorewall keeps blacklist rules in the
[blrules](../reference/configuration-files.md) file, checked ahead of the regular
[rules](../reference/rules.md) on every new connection.

This guide adds to the [two-interface firewall](../getting-started/two-interface.md).

## Blocking an address or network

A `blrules` line names an action and a source. `DROP` discards the traffic
silently, `REJECT` sends an error back, and `WHITELIST` exempts a source so a
later blacklist line does not catch it. List the whitelist entries first.

```text title="/etc/shorewall/blrules"
#ACTION      SOURCE                DEST
WHITELIST    net:203.0.113.9       all
DROP         net:198.51.100.0/24   all
```

A trusted host is let through, and a hostile network is dropped, before any rule in
the rules file is considered.

## Blocking a country

A source can be a country, written as `^` and the two-letter code. This needs the
geoip country data, which `shorewall geoip-update` downloads and loads into named
sets. The rule matches the set.

```text
#ACTION   SOURCE      DEST   PROTO   DPORT
DROP      net:^CN     all
ACCEPT    net:^US     $FW    tcp     22
```

Run `shorewall geoip-update` on a schedule to keep the country sets current. A
country set that has not been filled yet matches nothing, so the rule is safe
before the first update.

## Dynamic blacklisting with an ipset

To block addresses that change over time, point a rule at an ipset and let another
tool fill it. A `+name` is a native nft set. A set referenced but not defined in
the configuration is declared empty and kept across reloads, so a ban daemon such
as fail2ban can add to it directly.

```text
#ACTION   SOURCE       DEST
DROP      net:+banned  all
```

The daemon adds an address with `nft add element ip shorewall banned { 1.2.3.4 }`.
Run `shorewall savesets` to snapshot the set so it survives a reload or reboot.

## See also

[rules](../reference/rules.md) for the source forms, including `+ipset` and `^geoip`.
