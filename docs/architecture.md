# Architecture

## Why these names

Ereshkigal is the Sumerian goddess of Kur, the underworld. In this
software the `ereshkigal` manager rules; each `kur` process is an
underworld of its own, holding the IPs consigned to it; and the
manager is the only one who speaks to the underworlds directly.
Throughout the docs a *ban* is a descent into Kur, an *unban* is a
release back to the world above, a timed ban is a *sentence*, and the
persisted ban state is the *clay tablets*. Every one of those is just
flavor on a concrete mechanism, described below.

## The shape of it

```
                 /usr/local/etc/ereshkigal.toml
                              |
                              v
  ereshkigal(1) ---- the manager daemon
   App::Cmd CLI       |  socket: /var/run/ereshkigal/socket
                      |  pid:    /var/run/ereshkigal/pid
                      |
                      |  spawns + supervises (POE::Wheel::Run)
          +-----------+-----------+
          v                       v
     kur --name sshd         kur --name smtp
          |                       |
     socket: .../kur/sshd.sock    .../kur/smtp.sock
     pid:    .../kur/sshd.pid     .../kur/smtp.pid
     tablets: /var/cache/ereshkigal/kur.sshd.csv   kur.smtp.csv
          |                       |
          v                       v
     Net::Firewall::         Net::Firewall::
     BlockerHelper           BlockerHelper
     (pf/ipfw/iptables/      (one per kur)
      shell/dummy)
```

The manager reads the config, spawns one `kur` process per hash under
`kur` in the config, and supervises them. Each kur owns exactly one
`Net::Firewall::BlockerHelper` instance — the thing that actually
talks to the firewall — and serves it over its own unix socket. The
CLI (and anything else in the world above) talks only to the manager
socket; the manager proxies per-underworld work to the kur sockets and
aggregates the answers.

## What lives where

| path                                      | what                                            |
|-------------------------------------------|-------------------------------------------------|
| `/usr/local/etc/ereshkigal.toml`          | the config                                      |
| `/var/run/ereshkigal/socket`              | the manager socket (mode 0660, configured group)|
| `/var/run/ereshkigal/pid`                 | the manager PID                                 |
| `/var/run/ereshkigal/kur/<name>.sock`     | a kur's socket (always 0600)                    |
| `/var/run/ereshkigal/kur/<name>.pid`      | a kur's PID                                     |
| `/var/cache/ereshkigal/kur.<name>.csv`    | a kur's clay tablets — the persisted ban state  |

The run and cache base dirs are configurable; the layout under them is
not.

## Supervision

Kurs are spawned via `POE::Wheel::Run` in foreground mode so the
manager can watch them. An underworld that collapses is raised again —
a kur that dies is restarted with a doubling backoff (1s, 2s, 4s...
capped at 60s, reset after a minute of healthy uptime), and on the way
back up it restores its residents from the tablets (see below). The
`status` command shows the restart count per kur.

## The protocol

Both the manager socket and the kur sockets speak the
newline-delimited JSON of
[POE::Component::Server::JSONUnix](https://metacpan.org/pod/POE::Component::Server::JSONUnix):
one JSON object per line in each direction.

```
-> {"command":"ban","args":{"ips":["1.2.3.4"],"kur":"sshd","ban_time":3600}}
<- {"status":"ok","result":{"kurs":{"sshd":{"ips":{"1.2.3.4":{"status":"ok"}}}}}}

-> {"command":"status_kur","args":{"name":"nope"}}
<- {"status":"error","error":"No such kur instance, \"nope\""}
```

The manager commands are `status`, `status_all`, `status_kur`,
`banned`, `ban`, `unban`, `add_kur`, `remove_kur`, `checkpoint`, and
`stop`. The kur commands are `ban`, `unban`, `banned`, `status`,
`flush`, `re_init`, `checkpoint`, and `stop` — but the kur sockets are
0600 and only the manager is expected to speak to them. See
[usage.md](usage.md) for driving the manager socket from your own
integrations.

## Sentences and the sweeper

Every ban carries a term — the resolved `ban_time`, with `0` meaning
eternal residence. Each kur runs a sweeper, a once-a-second check
that releases any soul whose sentence has been served: the IP is
unbanned from the backend, dropped from the books, and counted in the
`expired` stat. Re-banning an IP that is already below just refreshes
its sentence.

## The clay tablets

Each kur checkpoints its ban book to
`/var/cache/ereshkigal/kur.<name>.csv`, a CSV of
`ip,time,ban_time_left` — who is below, when the row was written, and
how many seconds of their sentence remained at that moment (`0` for
eternal). The tablets are recopied

- on every arrival and departure (ban/unban/flush/expiry),
- every `checkpoint` seconds (default 60) even without changes, so
  the time-left figures never go stale,
- at `stop`, right before the firewall teardown, and
- on demand via the `checkpoint` command.

Writes go to a temp file then `rename`, so the tablets are never half
written. At startup a kur reads them back and compares each row's time
against the present: whoever's sentence lapsed while the underworld
was dark is released (the firewall may still carry the rule, so the
unban is attempted), and everyone else is re-banned into the freshly
initialized backend with their original release date intact. An
updated tablet is written back out immediately, so the file always
reflects who is actually below.
