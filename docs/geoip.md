# GeoIP

Match traffic by country, the drop-in way. A `^CC` in an address
column, exactly as Shorewall writes it, matches a country. The
difference from upstream is under the hood: instead of the xt_geoip
kernel module, shorewall-nft matches against a native nftables set of
that country's address ranges, filled and refreshed out of band.

## Using it

Write the country code with a caret in any source or destination
address, as before:

    # accept ssh to the firewall only from the US
    ACCEPT  net:^US  $FW  tcp  22

    # drop everything from CN
    DROP    net:^CN  all

    # everything except GB
    ACCEPT  net:^!GB  $FW  tcp  443

A leading `!` on the column or a `!` after the caret negates the match.
One country code per column.

## How it compiles

Each `^CC` becomes a reference to an nftables set named `geoip_<cc>`:

    ip saddr @geoip_us tcp dport 22 accept

The compiler declares an empty interval set for each country a
configuration mentions:

    set geoip_us { type ipv4_addr; flags interval; }

The set starts empty. An empty geoip set matches nothing, so until it
is filled a `^CC` rule matches no traffic. Filling it is a separate
step, so the large and changing country data is not baked into the
compiled ruleset and can be refreshed without recompiling.

## Filling and refreshing the sets

    shorewall geoip-update

This finds every geoip set in the running firewall, fetches each
country's address ranges, and loads them. By default it downloads the
ipdeny aggregated zone files, the same public data the community uses.
A local directory serves offline hosts, an admin's own data, or a
mirror:

    shorewall geoip-update --from /usr/share/xt_geoip/zones

Extra arguments limit it to named countries:

    shorewall geoip-update us gb

Every range is validated as a real CIDR of the set's family before it
is loaded, so a bad line in the source cannot corrupt the firewall.
The loaded ranges are also written to /var/lib/shorewall-nft/geoip so a
restart repopulates the sets from disk without the network.

## Scheduling

Country allocations drift, so the sets need periodic refresh. The
package ships a systemd timer:

    systemctl enable --now shorewall-geoip-update.timer

It runs `shorewall geoip-update` weekly, with a randomized delay so
many hosts do not fetch at the same moment, and catches up a refresh
missed during downtime. Adjust the schedule by overriding the timer.

## Notes

- The sets are per country and shared across the ruleset, so a country
  referenced in several rules is fetched once.
- IPv4 and IPv6 both work; the set type follows the configuration
  family and geoip-update loads the matching-family ranges.
- If geoip-update has never run, `^CC` rules match nothing rather than
  everything, which fails safe.
