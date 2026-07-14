# opnsense — an OPNsense firewall alias

Blocks on an OPNsense firewall by adding IPs to a firewall alias via
the `alias_util` REST API, driven with `curl(1)`. One alias holds
both IPv4 and IPv6 — OPNsense host aliases are family agnostic. The
alias and the rule that blocks on it are yours to create; the kur
manages membership only.

```toml
[kur.sshd]
backend = "opnsense"

[kur.sshd.options]
host   = "fw.example.org"
key    = "someAPIkey"
secret = "someAPIsecret"
```

## OPNsense-side setup — required first

- Create the alias: *Firewall → Aliases*, type Host(s), name matching
  the `alias` option (default `<prefix>_<name>`, e.g. `kur_sshd`).
- Create a firewall rule blocking traffic whose source is that
  alias, on the interfaces that matter.
- Create an API key pair: *System → Access → Users*, the key/secret
  pair lands in a download. A dedicated user whose privileges cover
  just the firewall API is better than root's keys.

## Requirements

- `curl` in the `PATH` of the kur process.

## Settings

- `ports` / `protocols` — accepted for parity but **ignored**;
  scoping lives on the referencing rule.
- `prefix` — builds the default alias name.

## Options

| option     | default           | what                                                  |
|------------|-------------------|--------------------------------------------------------|
| `host`     | *(required)*      | OPNsense host, optionally `host:port`                 |
| `key`      | *(required)*      | API key (basic auth user)                             |
| `secret`   | *(required)*      | API secret (basic auth password)                      |
| `alias`    | `<prefix>_<name>` | the pre-existing alias the IPs are added to           |
| `scheme`   | `https`           | `https` or `http`                                     |
| `insecure` | `0`               | adds `-k` to curl, accepting self-signed certificates |
| `curl_cmd` | `curl -s`         | the curl binary plus base arguments                   |

## What each operation runs

All calls are
`curl -s [-k] -u '<key>:<secret>' -H 'Content-Type: application/json' ...`:

| operation  | call                                                                  |
|------------|---------------------------------------------------------------------------|
| `init`     | `GET .../api/firewall/alias_util/list/<alias>` — verifies reachability, auth, and the alias |
| `ban`      | `POST .../api/firewall/alias_util/add/<alias>` with `{"address":"<ip>"}` |
| `unban`    | `POST .../api/firewall/alias_util/delete/<alias>` with `{"address":"<ip>"}` |
| `list`     | no API call — the kur's own ban book                                  |
| `check`    | same list call as init                                                |
| `flush`    | `POST .../api/firewall/alias_util/flush/<alias>` with `{}`            |
| `re_init`  | teardown (best effort), init, re-add every banned IP                  |
| `teardown` | the same alias flush (ban book kept for re_init)                      |

Deleting an address already gone from the alias succeeds quietly —
hand-removals on the firewall don't error later unbans.

## self_heal

`check` verifies the API answers and the alias exists — not that any
rule consumes the alias, nor the alias's contents. Contents removed
by hand stay removed until `re_init`.

## Gotchas

- **teardown and flush empty the whole alias.** If anything besides
  this kur feeds the same alias (another kur, hand-curated entries),
  those entries are flushed too — give each kur its own alias.
- `insecure = 1` is `curl -k`: encrypted, unauthenticated. Give the
  firewall a real certificate if the path matters.
- The key and secret appear on curl's command line, which is visible
  to local `ps` — on a multi-user box, weigh that; the kur host is
  usually single-purpose enough not to care.
- Errors carry Error::Helper flags (`hostNotDefined`,
  `apiKeyNotDefined`, `apiSecretNotDefined`, …) — [`Net::Firewall::BlockerHelper::backends::opnsense`](https://metacpan.org/pod/Net::Firewall::BlockerHelper::backends::opnsense) has the full
  table.
