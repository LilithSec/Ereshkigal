# dummy — an underworld of pure imagination

Remembers what it was told and does nothing else. No commands are
run, no rules are created; bans live in the kur process's memory (and
its clay tablet) and nowhere else. For testing Ereshkigal itself,
protocol glue, and integrations without touching a firewall.

```toml
[kur.pretend]
backend = "dummy"
```

## Requirements

None. No binaries, no privileges, no firewall. This is the one
backend that works as an unprivileged user, provided `run_base_dir`
and `cache_base_dir` point somewhere that user can write.

## Settings

- `ports` / `protocols` — accepted and validated (ports must be
  1–65535 or `getservbyname`-resolvable names, protocols must resolve
  via `getprotobyname`), then ignored. This keeps it a drop-in
  stand-in for a real backend: a config that validates against dummy
  will validate against iptables or pf.
- `prefix` — accepted, unused.
- `options` — takes none; anything passed is ignored.

## What each operation does

| operation  | effect                                                        |
|------------|----------------------------------------------------------------|
| `init`     | marks the backend inited; nothing else                        |
| `ban`      | adds the IP to the in-memory ban hash                         |
| `unban`    | removes the IP from the hash                                  |
| `list`     | returns the hash keys                                         |
| `check`    | always reports healthy — it cannot fail                       |
| `flush`    | clears the hash                                               |
| `re_init`  | clears and re-marks inited                                    |
| `teardown` | clears the inited flag                                        |

IPv6 addresses are lowercased on the way in, matching every other
backend, so `2001:DB8::1` and `2001:db8::1` are one ban.

## Behavior worth knowing

- Because `check` always passes, `self_heal` never triggers here —
  there is nothing to heal.
- The kur-level machinery all still works for real: sentences expire
  via the sweeper, the tablet is written and reloaded across
  restarts, `banned`/`status`/`flush`/`re_init` behave exactly as
  they would over a real firewall. That is what makes it useful — you
  can exercise the whole manager/kur/client stack, timed bans
  included, with zero risk.
- It is also handy as a gate member while wiring up an integration:
  point the integration at a gate whose members are dummies, watch
  `banned` to confirm the right IPs arrive, then swap the members'
  backends for real ones.

## Errors

Only the shared validation errors apply (bad port, bad protocol, bad
prefix/name, options not a hash); the operations themselves cannot
fail. See `perldoc Net::Firewall::BlockerHelper::backends::dummy` for
the flag list.
