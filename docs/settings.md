# shorewall.conf settings

How shorewall-nft treats each shorewall.conf setting. There are 125.
The rule: a setting that changes how packets are handled is either
honored or, if we do not implement its non-default behavior, rejected
loud. A setting at its shipped default is always accepted. Nothing that
would change the firewall is silently ignored.

## Honored

These are read and acted on.

| Setting | Effect |
|---|---|
| IP_FORWARDING | On sets ip_forward, Off clears it, Keep leaves it. |
| ROUTE_FILTER | Sets rp_filter. |
| LOG_MARTIANS | Sets log_martians. |
| CLAMPMSS | Clamps SYN MSS to the path MTU or a fixed value. |
| DROP_DEFAULT | Default action before a DROP policy. none disables it. |
| REJECT_DEFAULT | Default action before a REJECT policy. none disables it. |
| ACCEPT_DEFAULT | Default action before an ACCEPT policy. |
| BLACKLIST_DISPOSITION | Disposition for a BLACKLIST rule. |
| MACLIST_DISPOSITION | Disposition for an unmatched MAC on a maclist interface. |
| TC_ENABLED | Internal or Simple selects the shaping model; No disables it. |
| DOCKER, DOCKER_BRIDGE | Docker coexistence. |
| TCP_FLAGS_LOG_LEVEL | Log level for the tcp-flags check. |
| ADMINISABSENTMINDED | Affects the stopped-state policy. |
| REQUIRE_IPSETS | Yes (default): an unsupported ipset is a compile error. No: warn and skip it, so one odd set does not fail the whole ruleset. |
| REQUIRE_SECURE_CONFIG | No (default): warn if /etc/shorewall is group- or world-writable, or (when run as root) not owned by root. Yes: make it a compile error. A less-privileged user who can edit the config can have their input run as root at start. This is a shorewall-nft addition; upstream did not check. |

## Rejected loud if set to a non-default value

These change packet handling and we do not implement their non-default
behavior yet. The default matches what we do, so a config at the
default compiles. A non-default value is an error, naming the setting,
not a silent divergence. Listed with the default we accept.

INVALID_DISPOSITION (continue), RELATED_DISPOSITION (accept),
UNTRACKED_DISPOSITION (continue), SMURF_DISPOSITION (drop),
TCP_FLAGS_DISPOSITION (drop), SFILTER_DISPOSITION (drop),
RPFILTER_DISPOSITION (drop), MACLIST_TABLE (filter),
ACCOUNTING_TABLE (filter), MANGLE_ENABLED (yes),
IMPLICIT_CONTINUE (no), MULTICAST (no),
MARK_IN_FORWARD_CHAIN (no), BASIC_FILTERS (no), REJECT_ACTION (empty),
TC_PRIOMAP (the default priomap).

FASTACCEPT is accepted at any value and ignored. It only moves where
established and related traffic is accepted, for speed; the verdict is
the same, so it changes nothing we need to reject.

Several of these are candidates to honor properly later, TC_PRIOMAP and
the disposition settings especially. For now they are gated, not
guessed.

## Safe no-ops

These do not change the generated ruleset. They are paths, tooling,
logging format, compile-time optimization, or informational, and are
ignored without harm.

Paths and tooling: PATH, CONFIG_PATH, PERL, IP, IPTABLES, IPSET, TC,
NFACCT, PAGER, MODULESDIR, LOCKFILE, SUBSYSLOCK, SHOREWALL_SHELL,
RESTOREFILE, RESTART, RCP_COMMAND, RSH_COMMAND, FIREWALL, GEOIPDIR,
LOGFILE, STARTUP_LOG, MUTEX_TIMEOUT, PERL_HASH_SEED, PROVIDER_BITS,
PROVIDER_OFFSET, TC_BITS, ZONE_BITS, MASK_BITS, DONT_LOAD.

Logging format and verbosity: LOG_LEVEL, LOGFORMAT, LOGLIMIT, LOG_ZONE,
LOGTAGONLY, LOGALLNEW, LOG_BACKEND, LOG_VERBOSITY, USE_NFLOG_SIZE,
VERBOSITY, VERBOSE_MESSAGES, and the per-feature *_LOG_LEVEL settings
(BLACKLIST_LOG_LEVEL, INVALID_LOG_LEVEL, RELATED_LOG_LEVEL,
UNTRACKED_LOG_LEVEL, MACLIST_LOG_LEVEL, RPFILTER_LOG_LEVEL,
SFILTER_LOG_LEVEL, SMURF_LOG_LEVEL, TCP_FLAGS_LOG_LEVEL as a level).

Compile-time and cosmetic: OPTIMIZE, OPTIMIZE_ACCOUNTING, AUTOMAKE,
AUTOCOMMENT, EXPAND_POLICIES, RENAME_COMBINED, TRACK_RULES, COMPLETE,
DELETE_THEN_ADD, IGNOREUNKNOWNVARIABLES, WARNOLDCAPVERSION,
IPSET_WARNINGS, EXPORTMODULES, WORKAROUNDS, DEFER_DNS_RESOLUTION,
RETAIN_ALIASES, KEEP_RT_TABLES, USE_RT_NAMES, USE_PHYSICAL_NAMES,
TC_EXPERT, TRACK_PROVIDERS, RESTORE_ROUTEMARKS, RESTORE_DEFAULT_ROUTE,
USE_DEFAULT_RT, SAVE_IPSETS, SAVE_ARPTABLES, ZERO_MARKS,
FORWARD_CLEAR_MARK, HELPERS, AUTOHELPERS, MINIUPNPD, STARTUP_ENABLED,
REQUIRE_INTERFACE, ADD_IP_ALIASES, ADD_SNAT_ALIASES,
DETECT_DNAT_IPADDRS, BALANCE_PROVIDERS, DYNAMIC_BLACKLIST, ACCOUNTING,
BLACKLIST, BLACKLIST_DEFAULT, QUEUE_DEFAULT, NFQUEUE_DEFAULT, ARPTABLES,
PATH-like and other tooling flags.

Where one of these has a real effect we do not yet cover (for example
ACCOUNTING=No to skip the accounting file, or a custom BLACKLIST_DEFAULT
action), honoring it is future work; today it is a documented no-op, not
a silent security change, because none of them weakens the firewall.

## The IP_FORWARDING check

The setting most likely to matter. On forces forwarding on, Off forces
it off, and Keep, the shipped default, leaves the kernel as it is. We
honor all three. A box that must not forward stays that way; a router
gets forwarding on.
