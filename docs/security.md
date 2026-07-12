# Security considerations

## Socket permissions are the first gate

The manager socket is created with the configured `socket_mode`
(default 0660) and chowned to `socket_group` (default: the root
user's default group — `wheel` on the BSDs, `root` on Linux). Group
membership on that socket is the base access control: whoever can
write to it can ban and unban. Pick the group accordingly.

The kur sockets are always mode 0600, owned by the user ereshkigal
runs as, and that is deliberately not configurable — read on.

## Neti at the gate: the enable_auth trust model

With `enable_auth = true`, the manager demands that every connection
prove its identity before any command is honored — Neti, the
gatekeeper of the underworld, at the door. Mechanically this is the
POE::Component::Server::JSONUnix ownership challenge: the server
hands the client a random cookie and a directory; the client writes
the cookie to a new file there; the server stats the file. Since the
kernel assigns file ownership from the writing process's UID, a
correctly-written cookie file proves which unix user is on the other
end. `Ereshkigal::Client` (and therefore the CLI) completes this
transparently.

What it proves: the unix UID of the connecting process. What it does
not prove: anything about the process beyond that — any process of
that user passes.

Authorization then works from two pairs of lists:

- The top level `authed_users`/`authed_groups` grant **global**
  access — every command, every kur.
- Each kur's own `authed_users`/`authed_groups` **expand** the global
  lists for that kur only. They never replace them.
- A command must be authorized for **every underworld it touches**.
  `ban --kur sshd` touches one; a bare `ban`, `unban`, `banned`, or
  `checkpoint` touches all of them. Commands about the manager
  itself — `stop`, `add`, `remove`, and the whole-manager views
  `status`/`status --all` — require the global lists.
- UID 0 is always authorized.

Group membership is resolved at request time (the user's primary
group plus each listed group's member list), so user database changes
apply without a restart. Unknown group names simply never match.

**The boundary, stated plainly:** the kur backends do no checking at
all. Enforcement lives entirely in the manager, and that is only
sound because the kur sockets are 0600 — anything that CAN write to a
kur socket walks past Neti entirely. Protecting the kur sockets IS
the enforcement, which is why their mode is hardwired and why you
should never relax the run dir's permissions.

## The dead still speaking: established connections survive plain bans

The big one. Consigning an IP to Kur adds a firewall rule, and on
every real firewall that only bars NEW connections — sessions
established before the ban keep right on talking from the underworld.
An attacker whose brute-force succeeded before the ban landed keeps
their shell.

Every backend has a `kill` option that severs those remaining ties to
the world above, and for ban-on-abuse use you almost certainly want
it on:

```toml
[kur.sshd.options]
kill = 1
```

- **pf** — `kill = 1` runs `pfctl -k` to kill the existing states for
  the banned IP.
- **ipfw** — `kill = 1` uses tcpdrop(8) to tear down its established
  TCP connections.
- **iptables** — `kill = 1` uses conntrack(8) to delete its
  connection-tracking state.

All of them default to off, matching the underlying tools — so this
is an explicit choice you have to make per kur.

## Running as root

The pf/ipfw/iptables backends need root, so in practice the manager
and its kurs run as root. Consequences:

- `ereshkigal.toml` must be owned by root and not group- or
  world-writable. It names `kur_bin` — the program the manager execs —
  so write access to the config is code execution as root.
- The same goes for the `kur_bin` itself and the directories on its
  path.
- The manager socket's group (`socket_group`) is effectively "may
  manipulate the firewall"; with `enable_auth` off it is the whole
  story. Treat membership in that group accordingly.

## auth_temp_dir

The gate challenge writes cookie files into a shared directory
(default: the system tmpdir). A sticky-bit `/tmp` is fine — the
challenge only ever creates fresh files and checks their ownership —
but a dedicated root-owned, world-writable-with-sticky-bit directory
(or per-deployment `auth_temp_dir`) avoids pathological tmp setups
and tmp-cleaner races on long-idle connections.

## The tablets name names

The ban state CSVs under `/var/cache/ereshkigal/` list every banned
IP and when each sentence ends. If revealing who you have banned (or
when a ban lapses) matters in your environment, keep the cache dir
readable only by root.

## Ban-time footguns

- `ban_time = 0` is eternal residence — the IP stays banished until
  someone explicitly releases it, across restarts, forever. Make sure
  automation feeding a `ban_time = 0` kur is something you trust.
- `self_heal` (default on) re-establishes the firewall scaffolding
  (the anchor/table/chain/etc) if something outside removed it, before
  each ban or unban. It does not resurrect individual rules removed
  by hand behind the kur's back — the kur's book and the tablets are
  the source of truth, and `re_init` (or a kur restart) will re-ban
  from them.
- The one-second sweeper means a sentence can run up to a second
  long. If that matters, your threat model is more interesting than
  this software.
