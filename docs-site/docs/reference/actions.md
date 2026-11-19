# actions

A custom action is a reusable bundle of rules, compiled to its own chain and
jumped to wherever it is invoked. Declare its name in `/etc/shorewall/actions`,
and define its body in `action.NAME`. An action is the heavier cousin of a
[macro](../how-to/actions.md), which is expanded inline instead.

For a worked setup see the [custom actions and macros](../how-to/actions.md)
guide.

## The actions file

One action name per line. The name must start with a letter.

```text
MyServices
Mail
```

Shorewall ships many standard actions. Declare only the ones you define yourself.

## The action body

`action.NAME` holds rule lines, the same columns as the [rules](rules.md) file:
ACTION, SOURCE, DEST, PROTO, DPORT, and the rest.

```text
#ACTION   SOURCE   DEST   PROTO   DPORT
ACCEPT    -        -      tcp     8080
ACCEPT    -        -      tcp     8443
```

- A `-` in SOURCE or DEST inherits that side from the invocation, so the action
  works wherever it is used.
- Use the invocation's disposition by writing `PARAM` in the ACTION column, the
  way a macro does, when the action should accept, drop, or reject according to
  how it was called.

## Invoking an action

Invoke it from the [rules](rules.md) file, or from inside another action, with the
disposition in parentheses.

```text
MyServices(ACCEPT)   net   $FW
```

The source and destination of the rule become the action's inherited sides.

## Actions and macros

Both name a bundle of rules. The difference is how they compile.

- A [macro](../how-to/actions.md) (`macro.NAME`) is expanded inline at each use.
  It is lightest for a short bundle used in a few places.
- An action (`action.NAME`) compiles to a chain that is jumped to. Prefer it for
  a larger bundle, something reused widely, or a pattern that keeps state.

To list the macros and actions Shorewall ships, run `shorewall show macros`.

## See also

[custom actions and macros](../how-to/actions.md) for a worked setup.
[rules](rules.md) for the ACTION column grammar used in an action body.
