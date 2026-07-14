# dns_rpz — a DNS Response Policy Zone

Blocks at the resolver by maintaining RPZ triggers in a BIND
Response Policy Zone via `nsupdate(1)` and a TSIG key. Both IPv4 and
IPv6, unlike its RBL cousin [nsupdate](nsupdate.md). What "blocked"
means depends on the trigger:

- **`client-ip`** (the default) — banned IPs can't use the resolver:
  queries *from* them get the policy action.
- **`ip`** — answers *containing* banned IPs get rewritten: clients
  can't resolve their way to them.

Records are `CNAME .`, the RPZ idiom for NXDOMAIN.

```toml
[kur.resolver]
backend = "dns_rpz"

[kur.resolver.options]
zone    = "rpz.example.org"
keyfile = "/usr/local/etc/namedb/rpz.key"
trigger = "client-ip"
```

## BIND-side setup — required first

```shell
tsig-keygen -a hmac-sha256 kur-rpz > /usr/local/etc/namedb/rpz.key
chmod 400 /usr/local/etc/namedb/rpz.key
```

```
include "/usr/local/etc/namedb/rpz.key";

zone "rpz.example.org" {
    type master;
    file "dynamic/rpz.example.org.zone";
    allow-update { key kur-rpz; };
    allow-transfer { none; };
};

options {
    response-policy { zone "rpz.example.org"; };
};
```

The `response-policy` clause is what makes the zone *do* anything —
a dynamic zone nothing consults is the RPZ version of the
[npf](npf.md) rule-less table.

## Requirements

- `nsupdate` in the `PATH` of the kur process (or the `nsupdate`
  option), the keyfile readable, and DNS-update reach to the zone's
  master.

## Settings

- `ports` / `protocols` — **not supported**; specifying either is a
  fatal error at kur startup.
- `prefix` — unused; the zone is the container.

## Options

| option     | default      | what                                                 |
|------------|--------------|-------------------------------------------------------|
| `zone`     | *(required)* | the RPZ zone; `/^[a-zA-Z0-9.\-]+$/`                  |
| `keyfile`  | *(required)* | TSIG key file path; no whitespace or single quotes   |
| `trigger`  | `client-ip`  | `client-ip` or `ip` — see above                      |
| `server`   | *(unset)*    | adds a `server <server>` statement for nsupdate      |
| `ttl`      | `60`         | TTL of the created records                           |
| `nsupdate` | `nsupdate`   | the nsupdate command                                 |

## What each operation runs

Everything is `printf '<statements>' | nsupdate -k '<keyfile>'`. The
owner name encodes prefix length plus the reversed address — IPv4
`1.2.3.4` becomes `32.4.3.2.1.rpz-client-ip.<zone>`; IPv6 reverses
the groups with the longest zero run collapsed to `zz`, so
`2001:db8::1` becomes `128.1.zz.db8.2001.rpz-client-ip.<zone>`:

| operation  | statements                                                        |
|------------|-----------------------------------------------------------------------|
| `init`     | none — verifies the keyfile exists                                |
| `ban`      | `zone <zone>` ⏎ `update add <owner> <ttl> IN CNAME .` ⏎ `send`    |
| `unban`    | `zone <zone>` ⏎ `update delete <owner> IN CNAME .` ⏎ `send`       |
| `list`     | no command — the kur's own ban book                               |
| `check`    | keyfile still exists — nothing else is probed                     |
| `flush`    | the delete per banned IP                                          |
| `re_init`  | teardown (best effort), init, re-add every banned IP              |
| `teardown` | the delete per banned IP (ban book kept)                          |

A `server` option prepends a `server <server>` statement when the
zone's master is not where resolution would find it.

## self_heal

`check` only confirms the keyfile exists — DNS reachability, TSIG
validity, and zone contents are all invisible to it, so `self_heal`
is effectively a no-op here (as with [nsupdate](nsupdate.md)).
Records removed server-side stay gone until `re_init`.

## Gotchas

- `client-ip` blocking stops the banned IP from *resolving*, not
  from connecting — pair it with a packet filter kur in a gate if
  you want both, and remember every client of that resolver is
  affected.
- RPZ acts on the resolver evaluating the policy; secondaries
  serving the zone lag by transfer time.
- Keep `ttl` low; it bounds how long lifted bans linger in caches.
- Errors carry Error::Helper flags (`zoneInvalid`,
  `keyfileInvalid`, `triggerInvalid`, …) — `perldoc
  Net::Firewall::BlockerHelper::backends::dns_rpz` has the full
  table.
