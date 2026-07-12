# Configuration

The config file is TOML, by default `/usr/local/etc/ereshkigal.toml`
(overridable with `ereshkigal start --config <path>`). Top level keys
are manager settings; each hash under `kur` defines one underworld,
named for the hash — the hash at `kur.sshd` is the kur instance
`sshd`. Names must match `/^[a-zA-Z0-9-]+$/`.

## Manager settings

| key             | default                       | what                                                        |
|-----------------|-------------------------------|-------------------------------------------------------------|
| `socket_group`  | root's default group          | group ownership of the manager socket                       |
| `socket_mode`   | `"0660"`                      | perms on the manager socket, as a string, processed via oct |
| `run_base_dir`  | `/var/run/ereshkigal`         | sockets and PID files live under here                       |
| `cache_base_dir`| `/var/cache/ereshkigal`       | the clay tablets (ban state CSVs) live here                 |
| `kur_bin`       | `kur`                         | the kur bin the manager spawns                              |
| `timeout`       | `30`                          | seconds the manager waits on a kur socket                   |
| `ban_time`      | `600`                         | seconds a ban lasts; `0` = eternal residence                |
| `checkpoint`    | `60`                          | seconds between tablet recopies; `0` = mutations/stop only  |
| `enable_auth`   | `false`                       | Neti at the gate — see [security.md](security.md)           |
| `authed_users`  | `[]`                          | users with global access (with enable_auth)                 |
| `authed_groups` | `[]`                          | groups with global access (with enable_auth)                |
| `auth_temp_dir` | system tmpdir                 | where the auth challenge cookie files go                    |

Kur sockets are always mode 0600 — that is not configurable, and
[security.md](security.md) explains why it must stay that way.

## Kur settings

Inside a `[kur.<name>]` hash...

| key             | what                                                                     |
|-----------------|--------------------------------------------------------------------------|
| `backend`       | required; the Net::Firewall::BlockerHelper backend (`pf`, `ipfw`, `iptables`, `shell`, `dummy`) |
| `ports`         | array of ports to block for; all if unset                                |
| `protocols`     | array of protocols to block for; all if unset                            |
| `prefix`        | rule/table/chain name prefix, default `kur`                              |
| `self_heal`     | verify and re-init the firewall setup before each ban/unban, default 1   |
| `ban_time`      | this underworld's default sentence, overriding the top level one         |
| `checkpoint`    | this underworld's tablet recopy interval, overriding the top level one   |
| `options`       | a table of backend specific options, passed through                      |
| `authed_users`  | users granted access to this kur, expanding the global list              |
| `authed_groups` | groups granted access to this kur, expanding the global list             |

## How ban_time layers

The most specific setting wins:

    per request --ban-time  >  kur ban_time  >  top level ban_time  >  600

`0` at any layer means the ban never expires. `checkpoint` layers the
same way, minus the per-request level.

## Backend options

The `[kur.<name>.options]` table is handed to the backend unchecked.
What each accepts (see the `Net::Firewall::BlockerHelper::backends::*`
POD for the full story)...

- **pf** — `kill` (kill existing states for a banned IP; see
  [security.md](security.md), you almost certainly want this on).
- **ipfw** — `rule` (rule number), `type` (`deny`/`unreach`/
  `unreachable6`), `unreach` (the unreach code), `kill` (tcpdrop
  existing TCP connections).
- **iptables** — `type` (`drop`/`reject`), `kill` (drop existing
  conntrack state).
- **shell** — runs commands you specify; see its POD.
- **dummy** — takes none; an underworld of pure imagination that just
  remembers what it was told, for testing.

## A complete example

```toml
# the world above
socket_group = "wheel"      # who may speak to the manager...
socket_mode  = "0660"       # ...via group membership on the socket
ban_time     = 600          # ten minute sentences unless told otherwise
checkpoint   = 60           # recopy the tablets every minute

# Neti at the gate... identity checks on top of the socket perms
enable_auth   = false
#authed_users  = [ "zane" ]
#authed_groups = [ "wheel" ]

# the sshd underworld... hour long sentences, and sever the states of
# anyone sent below
[kur.sshd]
backend   = "pf"
ports     = [ "22" ]
protocols = [ "tcp" ]
ban_time  = 3600

[kur.sshd.options]
kill = 1

# the mail underworld, on the defaults
[kur.smtp]
backend   = "pf"
ports     = [ "25", "465", "587" ]
protocols = [ "tcp" ]

[kur.smtp.options]
kill = 1

# eternal residence for the manually curated
[kur.blocklist]
backend  = "pf"
ban_time = 0

[kur.blocklist.options]
kill = 1
```

Config changes take effect on restart. Kurs added at runtime with
`ereshkigal add` are not written back to this file — to make one
permanent, add its hash here.
