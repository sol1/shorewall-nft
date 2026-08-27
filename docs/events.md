# Events

shorewall-nft provides native `SetEvent`, `ResetEvent` and `IfEvent`
actions, matching [Shorewall's Events](https://shorewall.org/Events.html)
interface. Upstream builds these on the `xt_recent` kernel module; nftables
has no equivalent module, so these are backed by nftables dynamic timed
sets and, for a rate test, a meter. The dialect is the same three
parameterized actions; some behavior is an honest approximation, documented
below.

Upstream spells the actions mixed-case. The uppercase form (`SETEVENT`,
`RESETEVENT`, `IFEVENT`) is also accepted.

## Basic usage

    SetEvent(event,[action],[src-dst],[disposition])
    ResetEvent(event,[action],[src-dst],[disposition])
    IfEvent(event,[action],[duration],[hitcount],[src-dst],[command[:option]],[disposition])

- `event` is a name: starts with a letter, holds only letters, digits, `_`
  or `-`, at most 29 characters (upstream's own rule).
- `action` is the disposition to apply: `ACCEPT`, `DROP`, `REJECT`, an
  `A_` audit variant, `COUNT`, or `LOG` (`LOG` and `COUNT` are both a
  no-op: the packet falls through to the next rule, optionally logged).
  It may carry `:loglevel[:tag]`, e.g. `REJECT:warn:knock`.
  `SetEvent`'s action defaults to `COUNT`; `ResetEvent`'s and `IfEvent`'s
  default to `ACCEPT`.
- `src-dst` is `src` or `dst`, defaulting to `src`.
- The trailing `disposition` parameter overrides the word shown in the log
  prefix in place of the action name, e.g. `Added` or `Removed`.
- A nested action or macro name as `action` (e.g. passing another
  user-defined action's name to `IfEvent`) is not supported yet and is a
  located error. Give a plain disposition (optionally with `:loglevel`)
  instead.

`IfEvent` additionally takes:

- `duration`: seconds the test covers. Omitted means "not time-constrained"
  (the entry never expires on its own).
- `hitcount`: minimum number of hits required, default 1 (a plain
  membership test).
- `command`: `check` (default), `reset` or `update`.
  - `reset`: if the test succeeds, the event is reset before the action
    runs. Exact: the mutation only happens when nftables has already
    matched the same condition.
  - `update`: an entry is (re)recorded when the test succeeds.
    **Divergence from upstream**: upstream unconditionally records a new
    hit regardless of whether the test succeeded; shorewall-nft can only
    mutate state reached by the same match, so a source that fails the
    test is not recorded. Document this if you rely on `update` for a
    source that is expected to fail the test.
  - `reset`/`update` are only valid with `hitcount` 1. A rate test
    (`hitcount` > 1) is itself an nftables meter, which samples the
    current packet on every evaluation; there is no side-effect-free way
    to test it without also counting the packet, so `check` is the only
    valid command there.
- `option` after the command: `reap` is accepted as a no-op (nftables set
  timeouts already expire entries on their own); `ttl` is not supported
  yet (it would need the original packet's TTL remembered per entry) and
  is a located error rather than silently ignored.

## Membership vs. rate tests

- `hitcount` 1 (the default): an exact test — "is this source currently in
  the event". Backed by plain nftables dynamic-set membership.
- `hitcount` > 1: "have there been at least this many hits in this many
  seconds" is approximated with an nftables meter (a token bucket), the
  same technique `AutoBL` uses. This needs an explicit `duration`; an
  unconstrained hitcount-only rate test (`duration` omitted) is not
  supported yet and is a located error.

An event's underlying nftables set gets a timeout only if some
membership-only `IfEvent` gives it a `duration`; that duration is reused by
`SetEvent`/`ResetEvent`/`IfEvent update` for the same event. If multiple
membership tests on the same event give different durations, the longest
is used for the set (a documented approximation for that specific case). A
rate test's own duration is independent — it only sizes that test's meter,
never the set's timeout.

## Where they can be used

Directly in `rules`, or inside a user-defined action's body
(`action.<name>`, declared in `actions`), the same as any other action.
Only allowed in the `NEW` section.

## Example: automatic blacklisting

    # actions
    SSHLIMIT                    #Automatically blacklist hosts who exceed SSH connection limits

    # action.SSHLIMIT
    IfEvent(SSH_COUNTER,REJECT,300,1)             -  -  tcp  22
    IfEvent(SSH,DROP:warn,60,5,src,check)         -  -  tcp  22
    IfEvent(SSH,REJECT:warn:,2,1,-,update)        -  -  tcp  22
    ResetEvent(SSH_COUNTER,LOG:warn,-,Removed)    -  -  tcp  22
    SetEvent(SSH,ACCEPT,src)                      -  -  tcp  22

    # rules
    SSHLIMIT  net  $FW  tcp  22

Two events are in play: `SSH_COUNTER` tracks the *previously blacklisted*
state of a source, and `SSH` tracks the *rate* of connection attempts.
Every new SSH connection runs through all five lines in order, top to
bottom, before the next rule's implicit accept:

1. `IfEvent(SSH_COUNTER,REJECT,300,1)`: is this source currently marked
   in `SSH_COUNTER` (a plain membership test, `hitcount` defaults to 1,
   `duration` 300 means the mark lasts 5 minutes)? If so, `REJECT` the
   connection immediately — this is the actual blacklist enforcement, a
   silent (no `:loglevel`) reject for a source that already tripped the
   rate check below within the last 5 minutes.
2. `IfEvent(SSH,DROP:warn,60,5,src,check)`: has this source hit this
   line 5 or more times (`hitcount` 5) in the last 60 seconds
   (`duration` 60)? This is the rate test — the nftables meter that
   approximates it also records the current hit as it tests, so `check`
   here behaves the same as it would with `update`. If the rate is
   exceeded, log at `warn` and `DROP` this connection.
3. `IfEvent(SSH,REJECT:warn:,2,1,-,update)`: separately, has this exact
   source hit this line within the last 2 seconds (`hitcount` 1,
   `duration` 2, `src-dst` omitted so it defaults to `src`)? `update`
   means the hit is (re)recorded regardless, refreshing the 2-second
   window. If the test succeeds — two connection attempts within 2
   seconds of each other — log at `warn` (with an empty tag, `warn:`)
   and `REJECT`. This catches a rapid double-attempt distinct from the
   slower 5-in-60-seconds rate test above.
4. `ResetEvent(SSH_COUNTER,LOG:warn,-,Removed)`: if none of the above
   rejected the connection, clear this source's `SSH_COUNTER` mark (so a
   client that behaves for a while stops being treated as blacklisted).
   `LOG:warn` is the no-op disposition — it only logs, at `warn`, using
   `Removed` (the trailing `disposition` parameter) in place of the
   verdict word in the log prefix, and falls through to the next line
   rather than accepting or dropping.
5. `SetEvent(SSH,ACCEPT,src)`: the connection reached this far without
   being rejected or dropped, so record this attempt against the `SSH`
   rate-tracking event (feeding steps 2 and 3 for future connections)
   and `ACCEPT` it.

So a source is only ever blacklisted (step 1) after it has already
tripped the rate test in step 2 on a *previous* connection — nothing in
this action ever runs `SetEvent(SSH_COUNTER,...)`, since that would need
`SSH_BLACKLIST` as a separate nested action (upstream's original example
invokes it from `IfEvent`'s own action parameter, the one restriction
noted above). To keep this a single, self-contained action while still
demonstrating every native event action, step 2 here directly drops with
a log instead of handing off to a separate blacklisting action; a real
deployment that wants a persistent `SSH_COUNTER`-driven blacklist needs
`SetEvent(SSH_COUNTER,...)` inlined at that point instead of `DROP:warn`.

## Example: reset a knock on a port scan

Watching a range around the real knock port lets an out-of-order scan
(1599 then 1600 then 1601) reset the state instead of authorizing:

    # actions
    Knock                                          #Port Knocking

    # action.Knock
    IfEvent(SSH,ACCEPT:info,60,1,src,reset)  -  -  tcp  22
    SetEvent(SSH,ACCEPT)                     -  -  tcp  1600
    ResetEvent(SSH,DROP:info)                -  -  tcp  1599,1601

    # rules
    Knock  net  $FW  tcp  22,1599-1601

A knock on 1600 sets the event; a follow-up SSH connection within 60
seconds is accepted and the event is reset (single use); a hit on 1599 or
1601 instead resets the event outright, defeating a simple port scan.

For a fixed-sequence, protocol-mixed native alternative to hand-built
event actions, see [Port knocking](knocking.md) (`KNOCK`/`KNOCKSEQUENCE`).

## Not implemented yet

- `shorewall show events` / `show event`: upstream reads
  `/proc/net/xt_recent/*`; our events live in nftables sets instead, with
  no equivalent proc table. Inspect them directly instead:

      nft list set <family> shorewall event_<name>

- A nested action or macro name as an event's `action` parameter.
- An unconstrained (`duration` omitted) rate test (`hitcount` > 1).
- The `ttl` `IfEvent` option.
