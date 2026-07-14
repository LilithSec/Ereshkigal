# Kurs — every kind of underworld

Each `[kur.<name>]` hash in the config defines one kur. A kur is
either a *real* kur — a process wrapping one
`Net::Firewall::BlockerHelper` backend, with its own socket, PID
file, and clay tablet — or a *gate*, a `fan_out` list that opens onto
several real kurs.

This page covers the settings every kur shares and points at the
detail page for each kind. Each detail page goes deep: what the
backend creates, the exact commands or API calls behind every
operation, every option, host prerequisites, how `self_heal`
interacts with it, and its particular footguns.

## Every kind of kur

- [gate.md](kurs/gate.md) — the `fan_out` gate: one name opening onto
  several underworlds; validation, command fan out, response shapes,
  and the authorization model that is its reason to exist
- [dummy.md](kurs/dummy.md) — an underworld of pure imagination, for
  testing
- [pf.md](kurs/pf.md) — pf on FreeBSD/OpenBSD; table in an anchor,
  and the `anchor "kur/*"` line pf.conf must carry
- [ipfw.md](kurs/ipfw.md) — ipfw on FreeBSD; table plus a rule
  number, and why that number must be unique per kur
- [iptables.md](kurs/iptables.md) — Linux iptables/ip6tables plus
  ipset
- [nftables.md](kurs/nftables.md) — Linux nft; everything in one
  dedicated table
- [firewalld.md](kurs/firewalld.md) — Linux hosts firewalld manages;
  ipsets plus direct interface rules, and what a firewalld reload
  does to them
- [ufw.md](kurs/ufw.md) — Ubuntu's uncomplicated firewall; per-IP
  prepended rules
- [npf.md](kurs/npf.md) — npf on NetBSD; the table and rule npf.conf
  must declare
- [route.md](kurs/route.md) — null routes via iproute2; no firewall
  needed at all
- [shell.md](kurs/shell.md) — commands you specify; the escape hatch
- [cloudflare.md](kurs/cloudflare.md) — IP access rules at the
  Cloudflare edge
- [netscaler.md](kurs/netscaler.md) — policy dataset bindings on a
  Citrix NetScaler/ADC
- [nsupdate.md](kurs/nsupdate.md) — an RBL-style DNS blocklist in a
  BIND zone

The authoritative reference for any backend remains its POD —
`perldoc Net::Firewall::BlockerHelper::backends::<backend>`.

## Settings every kur shares

| key             | default          | what                                                              |
|-----------------|------------------|-------------------------------------------------------------------|
| `backend`       | *(required)*     | one of the backends above; mutually exclusive with `fan_out`      |
| `fan_out`       | *(unset)*        | array of other kur names; makes this a [gate](kurs/gate.md)       |
| `ports`         | `[]`             | ports to block for; all if unset                                  |
| `protocols`     | `[]`             | protocols to block for; backend-dependent default if unset        |
| `prefix`        | `"kur"`          | rule/table/chain/set name prefix; must match `/^[a-zA-Z0-9]+$/`   |
| `self_heal`     | `1`              | check the firewall setup before each ban/unban, re-init if gone   |
| `ban_time`      | top level / 600  | this kur's default sentence in seconds; `0` = eternal residence   |
| `checkpoint`    | top level / 60   | seconds between tablet recopies; `0` = mutations/stop only        |
| `options`       | `{}`             | backend specific options table — see each backend's page          |
| `authed_users`  | `[]`             | users granted access to this kur (with `enable_auth`)             |
| `authed_groups` | `[]`             | groups granted access to this kur (with `enable_auth`)            |

Notes that apply across the board...

- Kur names must match `/^[a-zA-Z0-9-]+$/`. The name and prefix also
  become firewall object names (`<prefix>_<name>` tables, chains, and
  sets), so the packet filter backends impose combined length limits
  — pf 31, ipfw 63, iptables 28, firewalld 29 characters; each page
  has the why.
- `ports` entries may be ints (1–65535) or service names resolvable
  via `getservbyname`; `protocols` entries are checked against
  `/etc/protocols`. Duplicates are dropped.
- `self_heal` is the fail2ban actioncheck-before-action behavior:
  each ban/unban first asks the backend to `check` its setup and
  re-inits it if something external (a firewall reload, a flushed
  table) swept it away. It costs one probe per ban/unban; leave it on
  unless that matters to you. What `check` actually probes — and
  where it can probe nothing — varies per backend; see each page.
- Several backends take no `ports`/`protocols` at all — they block
  the whole IP or operate somewhere ports have no meaning (`npf`,
  `route`, `cloudflare`, `netscaler`, `nsupdate`). Specifying either
  there is an error and the kur will fail to start.
- IPv6 addresses are lowercased everywhere, so case variants of one
  IP cannot become two bans.

## Picking one

| backend      | platform / where           | granularity        | kill support        |
|--------------|----------------------------|--------------------|----------------------|
| `pf`         | FreeBSD, OpenBSD, etc      | ports/protocols    | yes (states)        |
| `ipfw`       | FreeBSD                    | ports/protocols    | TCP only (tcpdrop)  |
| `iptables`   | Linux                      | ports/protocols    | yes (conntrack)     |
| `nftables`   | Linux                      | ports/protocols    | yes (conntrack)     |
| `firewalld`  | Linux with firewalld       | ports/protocols    | yes (conntrack)     |
| `ufw`        | Linux with ufw             | ports/protocols    | yes (ss/conntrack)  |
| `npf`        | NetBSD                     | whole IP (rule in npf.conf) | no          |
| `route`      | Linux (iproute2)           | whole IP           | no                  |
| `shell`      | anywhere                   | whatever you script | whatever you script |
| `cloudflare` | Cloudflare edge            | whole IP           | n/a (remote)        |
| `netscaler`  | Citrix NetScaler/ADC       | via responder policies | n/a (remote)    |
| `nsupdate`   | BIND zone (DNS RBL)        | whole IP, IPv4 only | n/a (remote)       |
| `dummy`      | the imagination            | none               | n/a                 |

On "kill support": a firewall rule only stops **new** connections;
`kill` severs the established ones too. For ban-on-abuse you almost
certainly want it on where it exists — [security.md](security.md)
explains.
