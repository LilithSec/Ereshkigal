# shell — commands you specify

The escape hatch. Runs your commands for init/ban/unban/teardown —
anything without a dedicated backend (an appliance CLI, a REST call
via curl, an exotic filter) can be a kur this way.

```toml
[kur.custom]
backend = "shell"

[kur.custom.options]
init     = "mkdir -p /tmp/banned"
teardown = "rm -rf /tmp/banned"
ban      = "touch /tmp/banned/%%%BAN%%%"
unban    = "rm -f /tmp/banned/%%%BAN%%%"
check    = "test -d /tmp/banned"
```

## How it works

Every operation runs the corresponding command you supplied, via the
shell, with `2>&1` appended (so stderr lands in the error string on
failure). In the `ban` and `unban` templates, every occurrence of
`%%%BAN%%%` is replaced with the IP being acted on. A non-zero exit
is a failure and surfaces as the kur command's error, output
included.

The IP is validated against strict IPv4/IPv6 regexes before it goes
anywhere near your template, so the substitution cannot smuggle shell
metacharacters — but the templates themselves run verbatim as root
(usually), so treat the config file accordingly (it already is code
execution as root — see [security.md](../security.md)).

## Requirements

Whatever your commands need. The backend itself needs nothing but a
shell.

## Settings

- `ports` / `protocols` — ignored entirely; encode any scoping into
  your commands.
- `prefix` — unused.
- `name` — required by the frontend as always, available to you only
  in the sense that you know it when writing the config.

## Options

| option     | required | what                                                                    |
|------------|----------|--------------------------------------------------------------------------|
| `init`     | yes      | run once at kur start (and during re_init) to set the blocking up      |
| `teardown` | yes      | run at stop/re_init to tear the blocking down                          |
| `ban`      | yes      | run per ban; `%%%BAN%%%` → the IP                                      |
| `unban`    | yes      | run per unban; `%%%BAN%%%` → the IP                                    |
| `check`    | no       | health probe; exit 0 = healthy. Unset ⇒ always healthy                 |
| `flush`    | no       | remove all bans at once. Unset ⇒ falls back to unbanning each IP       |

The four required commands must be defined and non-empty — the kur
fails to start otherwise. `check` and `flush` run with no
substitution (`flush` gets no `%%%BAN%%%`; it is expected to clear
everything your commands created).

## What each operation runs

| operation  | commands                                                              |
|------------|--------------------------------------------------------------------------|
| `init`     | your `init` command                                                   |
| `ban`      | your `ban` command with `%%%BAN%%%` substituted                       |
| `unban`    | your `unban` command with `%%%BAN%%%` substituted                     |
| `list`     | no command — the kur's own ban book                                   |
| `check`    | your `check` command, or nothing (healthy) if unset                   |
| `flush`    | your `flush` command, or your `unban` per banned IP if unset          |
| `re_init`  | `teardown` (best effort), `init`, then `ban` per banned IP            |
| `teardown` | your `teardown` command                                               |

## Writing good commands

- **Make `ban` idempotent.** During a kur restart the saved tablet is
  replayed through your `ban` command; after re_init, likewise. A ban
  command that errors when the IP is already blocked will spray
  errors into the log at every restart. (`touch`, `ipset add -exist`,
  `-o pipefile` style commands are naturally idempotent; `add`
  commands often are not.)
- **Make `unban` tolerate absence** for the mirrored reason —
  sentences that expired while the kur was down are unbanned at
  startup just in case.
- **Give it a real `check`** if there is anything to probe. Without
  one, `self_heal` has nothing to work with and externally destroyed
  setups go unnoticed until bans start failing.
- **Give it a real `flush`** if a bulk clear exists — the fallback
  unbans one IP at a time, which is slow for large ban books.
- Handle both families in your templates if you expect both — the
  substitution is the same for IPv4 and IPv6 (IPv6 arrives
  lowercased).

## Gotchas

- Quoting inside the templates is on you; the backend appends `2>&1`
  and changes nothing else.
- The kur's ban book (and tablet) is the only state — the backend
  never queries your system for what is currently blocked.
- Errors carry Error::Helper flags (`initInvalid`, `banInvalid`, …) —
  `perldoc Net::Firewall::BlockerHelper::backends::shell` has the
  full table.
