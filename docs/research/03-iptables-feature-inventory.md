# iptables feature inventory

Research date: 2026-07-03. Every iptables and netfilter feature the upstream
compiler can emit, with the source location that emits it. Paths relative to
upstream/shorewall/Shorewall/Perl/. This is the checklist for nftables mapping.

The authoritative artifact is the capability probe table in Config.pm. Every
probe records the exact iptables syntax Shorewall relies on.

## Capability matrix

Declared in %capdesc (Config.pm:422-541), detected at Config.pm:4609-5310.

| Capability | Probe (iptables syntax) | Line |
|---|---|---|
| NAT_ENABLED | -t nat -L | 4609 |
| NAT_INPUT_CHAIN | -t nat -L INPUT | 4613 |
| PERSISTENT_SNAT | -j SNAT --to-source X --persistent | 4619 |
| MASQUERADE_TGT | -t nat -j MASQUERADE | 4635 |
| NETMAP_TARGET | -t nat -j NETMAP --to X | 4651 |
| UDPLITEREDIRECT | -p udplite ... -j REDIRECT | 4667 |
| MANGLE_ENABLED | -t mangle -L | 4683 |
| CONNTRACK_MATCH | -m conntrack --ctorigdst X | 4689 |
| NEW_CONNTRACK_MATCH | -m conntrack -p tcp --ctorigdstport 22 | 4697 |
| OLD_CONNTRACK_MATCH | pre-inversion negation syntax | 4701 |
| state (required) | -m conntrack --ctstate or -m state | 5354 |
| MULTIPORT | -m multiport --dports 21,22 | 4709 |
| XMULTIPORT | multiport with ranges | 4733 |
| EMULTIPORT | multiport with sctp | 4737 |
| KLUDGEFREE | repeated match modules in one rule | 4713 |
| POLICY_MATCH | -m policy --pol ipsec | 4741 |
| PHYSDEV_MATCH | -m physdev --physdev-in | 4745 |
| PHYSDEV_BRIDGE | --physdev-is-bridged | 4749 |
| IPRANGE_MATCH | -m iprange --src-range | 4753 |
| RECENT_MATCH | -m recent --update | 4761 |
| REAP_OPTION | -m recent --reap | 4765 |
| OWNER_MATCH | -m owner --uid-owner | 4770 |
| CONNMARK_MATCH / XCONNMARK | -m connmark --mark N[/mask] | 4781 |
| IPP2P_MATCH | -m ipp2p (xtables-addons) | 4789 |
| LENGTH_MATCH | -m length | 4797 |
| ENHANCED_REJECT | -j REJECT --reject-with | 4801 |
| COMMENTS | -m comment | 4809 |
| HASHLIMIT_MATCH | -m hashlimit | 4813 |
| MARK / XMARK / EXMARK | -j MARK --set/and/or-mark [/mask] | 4825 |
| CONNMARK / XCONNMARK targets | -j CONNMARK --save/restore [--mask] | 4837 |
| NEW_TOS_MATCH | -m tos --tos V/mask | 4845 |
| CLASSIFY_TARGET | -j CLASSIFY --set-class | 4849 |
| IPMARK_TARGET | -j IPMARK (xtables-addons) | 4853 |
| TPROXY_TARGET | -j TPROXY | 4857 |
| MANGLE_FORWARD | mangle FORWARD chain exists | 4861 |
| RAW_TABLE | -t raw -L | 4865 |
| IPSET_MATCH | -m set --match-set | 4891 |
| IPSET_MATCH_NOMATCH | --return-nomatch | 4905 |
| IPSET_MATCH_COUNTERS | --packets-lt etc. | 4906 |
| ADDRTYPE | -m addrtype --src-type | 4946 |
| TARPIT_TARGET | -j TARPIT (xtables-addons) | 4950 |
| TCPMSS_MATCH | -m tcpmss --mss | 4954 |
| NFQUEUE_TARGET | -j NFQUEUE --queue-num | 4958 |
| CPU_FANOUT | --queue-cpu-fanout | 5200 |
| REALM_MATCH | -m realm | 4962 |
| HELPER_MATCH | -m helper | 4966 |
| CT_TARGET | -t raw -j CT --notrack | 5129 |
| helper probes | -j CT --helper amanda/ftp/h323/irc/netbios-ns/pptp/sane/sip/snmp/tftp | 4970-5046 |
| CONNLIMIT_MATCH | -m connlimit | 5049 |
| TIME_MATCH | -m time | 5053 |
| GOTO_TARGET | -g chain | 5057 |
| LOG_TARGET / NFLOG / ULOG / LOGMARK | -j LOG / NFLOG / ULOG / LOGMARK | 5061-5077 |
| FLOW_FILTER / BASIC_FILTER | tc filter types | 5081-5093 |
| CONNMARK_ACTION | tc action connmark | 5089 |
| FWMARK_RT_MASK | ip rule fwmark with mask | 5097 |
| MARK_ANYWHERE | MARK outside mangle | 5101 |
| HEADER_MATCH | -m ipv6header | 5105 |
| ACCOUNT_TARGET | -j ACCOUNT (xtables-addons) | 5109 |
| CONDITION_MATCH | -m condition (xtables-addons) | 5117 |
| AUDIT_TARGET | -j AUDIT | 5121 |
| STATISTIC_MATCH | -m statistic | 5140 |
| IMQ_TARGET | -j IMQ (out of tree) | 5145 |
| DSCP_MATCH / DSCP_TARGET | -m dscp / -j DSCP | 5149 |
| RPFILTER_MATCH | -m rpfilter | 5157 |
| NFACCT_MATCH | -m nfacct | 5161 |
| GEOIP_MATCH | -m geoip (xtables-addons) | 5173 |
| CHECKSUM_TARGET | -j CHECKSUM | 5177 |
| ARPTABLESJF | arptables variant detection | 5181 |
| IFACE_MATCH | -m iface (xtables-addons) | 5192 |
| TCPMSS_TARGET | -j TCPMSS --clamp-mss-to-pmtu | 5196 |
| WAIT_OPTION / RESTORE_WAIT_OPTION | iptables -w, iptables-restore --wait | 5344, 5204 |

## Matches emitted

Builder subs, mostly in Chains.pm.

| Match | Builder | Triggered by |
|---|---|---|
| proto, multiport, port sets | do_proto Chains.pm:4981 | PROTO, DPORT, SPORT columns |
| conntrack state | state_imatch Chains.pm:4960 | policies, rule sections |
| conntrack orig dest | match_orig_dest Chains.pm:6714 | ORIGINAL DEST, DNAT |
| ipset | get_set_flags Chains.pm:6166 | +setname in address columns |
| physdev | match_source_dev Chains.pm:6035 | bridge port zones |
| iprange | Chains.pm:6373, 6549 | address ranges |
| mac | do_mac Chains.pm:5183 | ~xx-xx-... , maclist |
| mark, connmark | do_test Chains.pm:5458 | MARK column, mangle tests |
| limit, hashlimit | do_ratelimit Chains.pm:5490 | RATE column, LOGLIMIT |
| connlimit | do_connlimit Chains.pm:5591 | CONNLIMIT column |
| time | do_time Chains.pm:5615 | TIME column |
| owner | do_user Chains.pm:5676 | USER/GROUP column |
| tos | do_tos Chains.pm:5763 | TOS column |
| connbytes | do_connbytes Chains.pm:5778 | CONNBYTES column |
| helper | do_helper Chains.pm:5853 | HELPER column |
| length | do_length Chains.pm:5869 | LENGTH column |
| ipv6header | do_headers Chains.pm:5927 | HEADER column (v6) |
| statistic | do_probability Chains.pm:5955 | PROBABILITY column |
| condition | do_condition Chains.pm:5972 | SWITCH column |
| dscp | do_dscp Chains.pm:6008 | DSCP column |
| nfacct | do_nfacct Chains.pm:6028 | NFACCT column |
| policy (ipsec) | do_ipsec Chains.pm:6794 | IPSEC column, ipsec zones |
| addrtype | Misc.pm:681, 745 | smurf filtering, DOCKER |
| recent | Misc.pm:1522, Providers.pm:2466 | blacklisting, provider fallback |
| rpfilter | Misc.pm:941, 1149 | rpfilter option, SFILTER |
| realm | Nat.pm:178, Rules.pm:5714 | provider realms |
| socket | Rules.pm:4481 | DIVERT (TPROXY) |
| tcpmss | Rules.pm:4757 | TCPMSS action |
| geoip, ipp2p, iface | capability-gated columns | GEOIP, mangle |

Negation is a literal `!` prefix per match. Interface wildcard `+` is honored.
Goto vs jump is a per-rule field.

## Targets emitted

%builtin_target lists legal targets per table (Chains.pm:615-668).

| Target | Emitter | Triggered by |
|---|---|---|
| ACCEPT, DROP, REJECT, RETURN | Misc.pm:766, Rules.pm | policies, rules |
| REJECT --reject-with variants | Misc.pm:1370 | reject action |
| LOG | log_rule_limit Chains.pm:6905 | log levels |
| NFLOG, ULOG, LOGMARK | Chains.pm:6892-6945 | NFLOG(...), ULOG(...) levels |
| NFQUEUE | Rules.pm | NFQUEUE action |
| AUDIT | Rules.pm:1089 | A_* actions |
| MARK | Rules.pm:4670, Tc.pm:1666, Providers.pm:174 | MARK, tcrules, providers |
| CONNMARK | Rules.pm:4692 | SAVE, RESTORE, CONNMARK |
| CLASSIFY | Rules.pm:4400 | CLASSIFY (tc) |
| DSCP, TOS, TTL, HL | Rules.pm:4516-4853 | mangle actions |
| TCPMSS | Rules.pm:4744, Misc.pm:2657 | TCPMSS, CLAMPMSS |
| CHECKSUM | Rules.pm:4390 | CHECKSUM action |
| IPMARK, IMQ | Rules.pm:4628, 4583 | IPMARK, IMQ actions |
| TPROXY | Rules.pm:4800 | TPROXY action |
| ECN | Rules.pm:4530 | ecn file |
| SECMARK, CONNSECMARK | Tc.pm:2143 | secmarks file |
| SET (add/del) | Rules.pm:2940, Misc.pm:819 | ADD, DEL, dynamic blacklist |
| CT (notrack, helper) | Raw.pm:110-208 | conntrack file |
| DNAT, SNAT, MASQUERADE, REDIRECT, NETMAP | Nat.pm | nat, snat, netmap files |
| ACCOUNT | Accounting.pm | accounting with ranges |
| TARPIT | Rules.pm:3297 | TARPIT action |
| RAWDNAT, RAWSNAT | rawnat file | xtables-addons |
| DOCKER chain jumps | Misc.pm:681, Chains.pm:9322 | DOCKER=Yes |

Recognized only for passthrough via IPTABLES()/INLINE actions: CHAOS,
CLUSTERIP, COUNT, DELUDE, DHCPMAC, DNETMAP, ECHO, IDLETIMER, MIRROR, QUEUE,
RATEEST, STEAL, SYSRQ, TCPOPTSTRIP, TEE, TRACE.

No SNPT, DNPT, LED or IFWLOG anywhere in the tree.

## Tables and hooks

valid_tables (Chains.pm:4668): raw, nat, mangle, filter. No security or
rawpost table. Chains registered: raw OUTPUT/PREROUTING; filter
INPUT/OUTPUT/FORWARD (policy DROP); nat PREROUTING/POSTROUTING/OUTPUT plus
INPUT when available; mangle PREROUTING/INPUT/OUTPUT/FORWARD/POSTROUTING.

## External tools driven by the compiled script

| Tool | Usage | Where |
|---|---|---|
| iptables-restore | ruleset load | Chains.pm:9243-9300 |
| arptables | ARP filtering | ARP.pm:106-283 |
| ipset | create, add, swap, save, restore | Chains.pm:8925-9167 |
| tc | qdisc, class, filter: htb, hfsc, prio, sfq, red, fq_codel, tbf, ingress; filters u32, fw, flow, basic | Tc.pm |
| ip | rule add, route add, link | Providers.pm:253-922, lib.runtime |
| conntrack | flush, list | lib.runtime:419 |
| /proc/sys writes | rp_filter, proxy_arp, forwarding, arp_* | Proc.pm:27-326 |
| nfacct | accounting objects | Config.pm:5161 |

## iptables-restore specifics

Emits *table / :CHAIN policy / rules / COMMIT into
${VARDIR}/.iptables-restore-input and pipes it in (Chains.pm:9284). Uses
--wait when detected, --counters on reload. Negation is the modern `!` prefix
except two legacy fallbacks. Builtin chain ordering is preserved deliberately.

## Gap flags for nftables mapping

ULOG is dead upstream. IMQ, IPMARK, ACCOUNT, TARPIT, RAWDNAT, RAWSNAT and the
passthrough xtables-addons targets have no nft equivalent. ipp2p, geoip,
condition, iface, realm-set and Arptables-JF need individual decisions. See
docs/research/04-nftables-capability-map.md.
