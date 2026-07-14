# iptables — Linux (iptables/ip6tables + ipset)

Blocks via ipset in combination with iptables and ip6tables. Banning
an IP is one ipset add. If the host runs firewalld, use the
[firewalld](firewalld.md) backend instead — driving iptables directly
fights the daemon and loses on reload.

```toml
[kur.web]
backend   = "iptables"
ports     = [ "80", "443" ]
protocols = [ "tcp" ]

[kur.web.options]
kill = 1
```

## What it creates

- Two ipsets: `<prefix>_<name>_4` (`hash:ip family inet`) and
  `<prefix>_<name>_6` (`hash:ip family inet6`).
- A dedicated chain `<prefix>_<name>` in the `filter` table of both
  iptables and ip6tables, populated with the block rules and jumped
  to from `INPUT`:

```
iptables -N kur_web
iptables -A kur_web -m set --match-set kur_web_4 src -p tcp -m multiport --dports 80,443 -j DROP
iptables -A INPUT -j kur_web
```

The jump is appended (`-A INPUT`), so it lands after existing INPUT
rules — an earlier ACCEPT wins. If your INPUT chain accepts by
protocol/port before falling through, consider whether the block
needs to come earlier; the [nftables](nftables.md) backend's priority
option gives finer control.

## Requirements

- `ipset`, `iptables`, and `ip6tables` in the `PATH` of the kur
  process, with privileges to use them — in practice, root (or
  `CAP_NET_ADMIN`).
- The `ip_set` kernel module (loaded on demand by ipset on any normal
  kernel). `kill = 1` additionally needs `conntrack` (the
  conntrack-tools package) and connection tracking enabled.
- Works with both iptables-legacy and iptables-nft, as it only ever
  talks through the `iptables`/`ip6tables` frontends.

## Ports, protocols, and names

- Default `protocols`: all traffic sourced from the sets — or `tcp`,
  `udp` when `ports` are given. Ports attach only to port-capable
  protocols (tcp/udp/sctp), via `-m multiport --dports` with a comma
  list.
- Family-inappropriate protocols are skipped per family: `icmp` gets
  no ip6tables rule; `ipv6-icmp`/`icmp6`/`icmpv6` get no iptables
  rule.
- `<prefix>_<name>` must be ≤ 28 characters — the iptables chain name
  limit (the ipsets add `_4`/`_6` within ipset's 31-char limit).

## Options

| option | default | what                                                        |
|--------|---------|--------------------------------------------------------------|
| `type` | `drop`  | `drop` silently drops; `reject` sends ICMP port-unreachable |
| `kill` | `0`     | drop existing conntrack entries for a banned IP             |

### `type`

`reject` uses `-j REJECT --reject-with icmp-port-unreachable` on
IPv4 and `--reject-with icmp6-port-unreachable` on IPv6; `drop` is a
plain `-j DROP`.

### `kill`

A firewall rule only stops **new** connections — established flows
keep talking through their conntrack entries (see
[security.md](../security.md)). With `kill = 1`, each ban also runs
`conntrack -D -s <ip>` (with `-f ipv6` for IPv6 IPs), scoped to the
configured protocols via `-p`:

- No protocols configured — everything is blocked, so every entry for
  the IP is dropped.
- Ports but no protocols — scoped to tcp and udp.
- Protocols configured — one `conntrack -D -p <proto> -s <ip>` per
  blocked protocol conntrack can filter by (`tcp`, `udp`, `udplite`,
  `sctp`, `dccp`, `gre`, `icmp`, `icmpv6` — the icmp of the wrong
  family is skipped). Blocking only udp never drops tcp entries.

Exit codes are ignored — no matching entries is not an error.

## What each operation runs

With `C = <prefix>_<name>`, `S4/S6` the sets:

| operation  | commands                                                                            |
|------------|----------------------------------------------------------------------------------------|
| `init`     | cleanup (failures ok): `-D INPUT -j C`, `-F C`, `-X C` on both frontends, `ipset destroy S4/S6`; then (fatal): `ipset create S4 hash:ip family inet`, `ipset create S6 hash:ip family inet6`, `-N C` both frontends, the block rules, `-A INPUT -j C` both frontends |
| `ban`      | `ipset add <S4\|S6> <ip>` per the IP's family, then the conntrack kills if enabled  |
| `unban`    | `ipset del <S4\|S6> <ip>`                                                           |
| `list`     | no command — the kur's own ban book                                                 |
| `check`    | `ipset list S4`, `ipset list S6`, `iptables -C INPUT -j C`, `ip6tables -C INPUT -j C`, plus every block rule re-tested with `-C` |
| `flush`    | `ipset flush S4`, `ipset flush S6` (rules stay in place)                            |
| `re_init`  | teardown (best effort), init, re-add every banned IP                                |
| `teardown` | `-D INPUT -j C`, `-F C`, `-X C` on both frontends, then `ipset destroy S4`, `ipset destroy S6` |

## self_heal and reloads

`check` is thorough here: both sets, both INPUT jumps, and every
individual block rule are verified. Anything a
`iptables-restore`/distro firewall restart swept away is noticed by
the next ban/unban with `self_heal` on, which re-inits and re-bans
from the kur's book. Note that ipsets survive an iptables flush (they
are a separate subsystem), so partial damage — rules gone, sets still
populated — is the common post-reload state, and re_init handles it.

## Gotchas

- Rules are runtime only. Nothing is written to
  `/etc/iptables/rules.v4` or the like — after a reboot the kur
  recreates everything at startup, which is the intended model.
  Conversely, if you use `iptables-save` for persistence, the kur's
  chain and jump will be captured; harmless, but re-initialized over
  at next start.
- IPv6 addresses are lowercased on ban so case variants can't
  duplicate.
- Errors carry Error::Helper flags (`typeInvalid`, `nameTooLong`, …)
  — `perldoc Net::Firewall::BlockerHelper::backends::iptables` has
  the full table.
