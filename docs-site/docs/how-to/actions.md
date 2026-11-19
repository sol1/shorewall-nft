<!-- docs-proof: base=getting-started/two-interface.md -->
# Custom actions and macros

The rules you have already written use macros. `SSH(ACCEPT)`, `DNS(ACCEPT)`, and
`Ping(ACCEPT)` are macros that Shorewall ships. A macro is a named bundle of
rules, so you write `SSH(ACCEPT)` instead of remembering that SSH is TCP 22. You
can write your own, both as macros and as actions, to name the service bundles
and patterns you use often.

This guide adds to the [two-interface firewall](../getting-started/two-interface.md).

## A macro

A macro is the simpler of the two. It is a small file of rule lines that is
expanded in place wherever you invoke it. Write it as `macro.NAME` in the
configuration directory. Use `PARAM` where the disposition of the invocation
goes.

```text title="/etc/shorewall/macro.WebServer"
#ACTION   SOURCE   DEST   PROTO   DPORT
PARAM     -        -      tcp     80
PARAM     -        -      tcp     443
```

Invoke it like any shipped macro. The disposition in the parentheses replaces
`PARAM`, and the source and destination come from the rule.

```text
WebServer(ACCEPT)   net   $FW
```

That one line opens TCP 80 and 443. A `-` in the macro's SOURCE or DEST column
inherits the side from the invocation; a literal keyword or address in the macro
restricts it.

## An action

An action does the same job but compiles to its own chain, so it is defined once
and jumped to wherever it is used. Use one when the bundle is large or reused a
lot, or when it carries state. Declare the name in the
[actions](../reference/actions.md) file.

```text title="/etc/shorewall/actions"
MyServices
```

Define its body in `action.NAME`, as rule lines. Here `-` in SOURCE and DEST
means the action applies to whatever zones invoked it.

```text title="/etc/shorewall/action.MyServices"
#ACTION   SOURCE   DEST   PROTO   DPORT
ACCEPT    -        -      tcp     8080
ACCEPT    -        -      tcp     8443
```

Invoke it from the rules file the same way.

```text
MyServices(ACCEPT)   net   $FW
```

## Putting it together

```text title="/etc/shorewall/rules"
?SECTION NEW
#ACTION               SOURCE   DEST   PROTO   DPORT
Invalid(DROP)         net      all    tcp
SSH(ACCEPT)           loc      $FW
WebServer(ACCEPT)     net      $FW
MyServices(ACCEPT)    net      $FW
```

The Internet reaches the firewall's web ports through the `WebServer` macro and
its application ports through the `MyServices` action. Both read as one line in
the rules.

## Macro or action

- A macro is expanded inline. It is lightest for a short bundle of ports used in
  a few places.
- An action compiles to a chain and is jumped to. Prefer it for a larger bundle,
  for something reused widely, or for a pattern that keeps state.

To see the macros Shorewall ships, run `shorewall show macros`.

## See also

[actions](../reference/actions.md) for the actions file and the action body.
[rules](../reference/rules.md) for the ACTION column grammar.
