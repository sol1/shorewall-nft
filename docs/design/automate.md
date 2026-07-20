# shorewall automate: a machine interface

`shorewall automate <verb>` is a stable, machine-readable interface for
configuration management tools, Ansible in particular. It wraps the same
logic as the human verbs but with a contract a program can rely on.

## Contract

- One JSON object is written to stdout and nothing else. Human progress,
  warnings and errors go to stderr. `shorewall automate <verb> | jq` always
  parses.
- Every object uses the same envelope:

      {
        "schema": 1,
        "command": "apply",
        "ok": true,
        "changed": true,
        "family": "ipv4",
        "result": { ... verb specific ... },
        "warnings": [ { "file": "rules", "line": 12, "message": "..." } ],
        "errors":   [ { "file": "rules", "line": 3,  "message": "..." } ]
      }

- `changed` is a first-class field, because that is what Ansible reports. It
  is not encoded in the exit code.
- Exit codes are few and stable: 0 success, 1 configuration error (nothing
  applied), 2 usage error, 3 system or runtime error. `status` and `doctor`
  return 3 when the firewall is not running or not ready.
- Mutating verbs accept `--check` (a synonym for `--dry-run`): compute
  `changed` and what would happen, change nothing.
- Automate verbs never prompt. They imply `--yes`.
- `schema` is bumped only on an incompatible change to the envelope or a
  result shape.

## Verbs

Read-only:

| Verb | result | Exit |
|------|--------|------|
| `check` | `confdir`, `compiles`, `nft_accepts` | 0 ok, 1 error |
| `status` | `running`, `state`, `stack`, `version`, `loaded`, `rules{total,filter,nat}` | 0 running, 3 stopped |
| `capabilities` | `capabilities{NAME: bool}` probed from the kernel | 0 |
| `versioncheck` | `installed`, `latest`, `source`, `update_available`, `up_to_date`, `migration_needed` | 0 |
| `doctor` | `ready`, `checks[{name, ok, critical, detail}]` | 0 ready, 3 not |
| `diff` | `changed`, `has_current`, `summary{added,removed}`, `diff` | 0 |

Mutating (accept `--check`):

| Verb | result | Notes |
|------|--------|-------|
| `apply` | `changed`, `applied`, `ruleset_sha256`, `previous_sha256` | reload only if the compiled ruleset changed |
| `safe-apply` | `changed`, `applied`, `rollback{armed, deadline, timeout}` | applies, then reverts after `--timeout` unless committed |
| `safe-apply --commit` | `committed` | cancels a pending revert |
| `rollback` | `reverted` | revert to the previous ruleset now |
| `migrate` | `already_migrated`, `from`, `to`, `unsupported[]`, `compat[]`, `handed_over` | idempotent: already on nft is `changed:false` |

### Idempotency

`apply` decides `changed` by hashing the freshly compiled ruleset and comparing
it to the last applied one. Compilation is deterministic, so identical config
produces an identical hash and no reload. It does not diff the live nft state,
whose handles and ordering are noisy; `diff` does the fuller comparison for a
human.

### safe-apply, the anti-lockout path

Applying a bad rule over SSH can cut the session. `safe-apply --timeout N`
applies the new ruleset, keeps the previous one, and arms a detached revert
after N seconds. A second call, `safe-apply --commit`, cancels the revert once
the playbook has confirmed connectivity. If the box goes unreachable, the
revert restores the previous firewall on its own.

### versioncheck

`latest` comes from the GitHub releases API
(`https://api.github.com/repos/sol1/shorewall-nft/releases/latest`),
overridable with `SWNFT_GITHUB_LATEST_URL`. packages.sol1.net is an unofficial
repository for now and is not consulted. When GitHub is unreachable `latest` is
null and the reason is in `warnings`; the verb still succeeds.

## Not in the contract

The JSON is the interface a program depends on. The human verbs keep their
free-form text output, which may change. A thin Ansible module can wrap this
contract to give native `changed`, check mode and diff.
