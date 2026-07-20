# Automating shorewall-nft

shorewall-nft is meant to be driven by a configuration management tool, not
just by hand. `shorewall automate <verb>` is the interface for that. It speaks
JSON, reports whether it changed anything, and never asks a question.

The short version: every verb prints one JSON object to stdout, sets a small
stable exit code, and puts a `changed` field in the output so Ansible can act
on it. Mutating verbs take `--check` to say what they would do without doing
it. The full contract, with the envelope and every result shape, is in
[docs/design/automate.md](design/automate.md); this page is how to use it.

## The shape of a reply

    $ shorewall automate check
    {"schema":1,"command":"check","ok":true,"changed":false,"family":"ipv4",
     "result":{"confdir":"/etc/shorewall","compiles":true,"nft_accepts":true},
     "warnings":[],"errors":[]}

stdout is only ever that one object, so `shorewall automate <verb> | jq` always
works. Human progress and warnings go to stderr. Exit codes are few: 0 success,
1 configuration error, 2 usage error, 3 the firewall is not running or not
ready. `changed` lives in the JSON, not the exit code.

## The verbs

Read-only, safe to run any time:

- `check` reports whether the configuration compiles and the kernel accepts it.
  Errors carry `file` and `line`.
- `status` reports whether the firewall is running, the version and the rule
  counts. Exit 3 when it is stopped.
- `versioncheck` compares the installed version against the latest GitHub
  release. Offline is a warning, not a failure.
- `capabilities` reports which conntrack helpers and targets this kernel
  provides, probed for real.
- `doctor` is a preflight: nft present, the config compiles, no leftover
  iptables Shorewall, and so on. `result.ready` is the summary.
- `diff` shows what a reload would change against the running ruleset.

Mutating, and each takes `--check`:

- `apply` reloads the firewall only if the compiled ruleset actually changed.
  This is the idempotent primitive.
- `safe-apply` applies, then reverts after `--timeout` seconds unless a second
  call commits it. The anti-lockout path for a remote box.
- `rollback` reverts to the previous ruleset now.
- `migrate` hands the box over from the old iptables Shorewall. Idempotent:
  already migrated is `changed:false`.

## Idempotent apply

`apply` compiles the configuration, compares its hash to the last applied one,
and reloads only if they differ. Run it every time; it does nothing when
nothing changed.

    - name: Apply the shorewall-nft firewall
      command: shorewall automate apply
      register: sw_apply
      changed_when: (sw_apply.stdout | from_json).changed | bool

`apply` exits 0 whether or not it changed anything, so read `changed` from the
JSON rather than the return code. To preview without applying, add `--check`;
the reply carries the same `changed` and a `diff`-style summary.

## Not locking yourself out

Applying a bad rule over SSH can cut the session that is applying it.
`safe-apply` guards against that. It applies the ruleset, keeps the previous
one, and arms a revert that fires after `--timeout` seconds. A second call
commits the change and cancels the revert. If the box becomes unreachable
before the commit, it reverts on its own and comes back on the old rules.

    - name: Apply with a safety net
      command: shorewall automate safe-apply --timeout 60
      register: sw_safe
      changed_when: (sw_safe.stdout | from_json).changed | bool

    - name: Prove the box is still reachable
      wait_for_connection:
        timeout: 30

    - name: Commit the firewall
      command: shorewall automate safe-apply --commit

If the `wait_for_connection` step fails, the play stops before the commit, the
timer fires, and the previous firewall is restored without anyone logging in.

## Migrating under automation

    - name: Move this box to shorewall-nft
      command: shorewall automate migrate
      register: sw_migrate
      changed_when: (sw_migrate.stdout | from_json).changed | bool
      failed_when: (sw_migrate.stdout | from_json).ok | bool == false

`migrate --check` reports whether it would hand over without doing it. A
configuration with an unsupported file, or one that does not compile, is a
located refusal with exit 1, so the play stops with the reason rather than
half-migrating.

## Preflight and drift

    - name: Firewall preflight
      command: shorewall automate doctor
      register: sw_doctor
      changed_when: false
      failed_when: not (sw_doctor.stdout | from_json).result.ready

    - name: Report pending firewall changes
      command: shorewall automate apply --check
      register: sw_plan
      changed_when: (sw_plan.stdout | from_json).changed | bool

`doctor` asserts the box is ready before a run touches it. `apply --check` is a
read-only drift report: it tells you whether the running firewall matches the
configuration, which is what you want in an Ansible check-mode run.

## Background: the Ansible role

sol1 maintains an Ansible role for Shorewall,
[sol1-ansible/sol1-shorewall](https://github.com/sol1-ansible/sol1-shorewall).
It is being updated to drive shorewall-nft through this interface: `doctor` for
preflight, `check` to validate, `safe-apply` for the change, and `migrate` for
the handover. Support for shorewall-nft is in progress; the link is the role as
it stands today.

A dedicated Ansible module may follow, wrapping this contract so a task reports
`changed`, check mode and diff natively. Until then the `command` plus
`from_json` pattern above is the supported way in.
