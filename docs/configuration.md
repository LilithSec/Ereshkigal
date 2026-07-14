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
| `backend`       | required unless `fan_out` is set; the Net::Firewall::BlockerHelper backend — `pf`, `ipfw`, `iptables`, `nftables`, `firewalld`, `ufw`, `shorewall`, `npf`, `route`, `xdp`, `hosts_deny`, `routeros`, `routeros_api`, `opnsense`, `pfsense`, `vyos`, `panos`, `fortigate`, `cisco_fmc`, `checkpoint`, `juniper_srx`, `f5_bigip`, `netscaler`, `bgp_rtbh`, `cloudflare`, `fastly`, `akamai`, `aws_wafv2`, `cloud_armor`, `azure`, `nsupdate`, `dns_rpz`, `abuseipdb`, `file_reload`, `shell`, or `dummy` — see [kurs.md](kurs.md) |
| `fan_out`       | array of other kur names, in place of `backend`; makes this a gate (see below) |
| `ports`         | array of ports to block for; all if unset                                |
| `protocols`     | array of protocols to block for; all if unset                            |
| `prefix`        | rule/table/chain name prefix, default `kur`                              |
| `self_heal`     | verify and re-init the firewall setup before each ban/unban, default 1   |
| `ban_time`      | this underworld's default sentence, overriding the top level one         |
| `checkpoint`    | this underworld's tablet recopy interval, overriding the top level one   |
| `options`       | a table of backend specific options, passed through                      |
| `authed_users`  | users granted access to this kur, expanding the global list              |
| `authed_groups` | groups granted access to this kur, expanding the global list             |

## Gates — fan_out kurs

A kur hash may carry `fan_out`, an array of other kur names, in place
of `backend`:

```toml
[kur.baphomet]
fan_out      = [ "sshd", "smtp" ]
authed_users = [ "baphomet" ]
```

Such a kur is a gate — one name that opens onto several underworlds.
It has no process and no socket of its own; commands targeted at it
(`ban --kur`, `checkpoint <name>`, `status <name>`) fan out to its
members instead, with results reported per member. With `enable_auth`
on, authorization for a command aimed at a gate is checked against the
gate's own lists, not its members' — which is the point: an outside
integration (a log watcher, IDS glue) can be granted just the gate and
drive a whole set of kurs through a single point of contact, without
being listed on — or knowing about — any member.

Members must be real kurs (gates may not nest), and untargeted
commands (`ban` with no `--kur`, `unban`, `banned`, bare `checkpoint`)
never touch gates, only real kurs. In `status`, a gate shows its
member list and counts as running when every member is.

## How ban_time layers

The most specific setting wins:

    per request --ban-time  >  kur ban_time  >  top level ban_time  >  600

`0` at any layer means the ban never expires. `checkpoint` layers the
same way, minus the per-request level.

## Backend options

The `[kur.<name>.options]` table is handed to the backend unchecked.
[kurs.md](kurs.md) links a detail page per backend covering every
option and the host setup each needs; the short version...

- **pf** — `kill` (kill existing states for a banned IP; see
  [security.md](security.md), you almost certainly want this on).
- **ipfw** — `rule` (rule number, unique per kur), `type`
  (`deny`/`unreach`/`unreach6`), `unreach`/`unreach6` (the reject
  codes), `kill` (tcpdrop existing TCP connections).
- **iptables** — `type` (`drop`/`reject`/`tarpit`/`delude`),
  `tarpit_mode`, `kill` (drop existing conntrack state).
- **nftables** — `type` (`drop`/`reject`), `priority` (base chain
  priority), `kill` (conntrack).
- **firewalld** — `type` (`drop`/`reject`), `chain` (direct interface
  chain), `kill` (conntrack).
- **ufw** — `type` (`deny`/`reject`), `kill` (`''`/`ss`/`conntrack`).
- **shorewall** — `type` (`drop`/`reject`), `shorewall_cmd`,
  `shorewall6_cmd`.
- **npf** — `table` (the npf table, pre-declared in npf.conf).
- **route** — `blocktype` (`blackhole`/`unreachable`/`prohibit`).
- **xdp** — `interfaces` (required), `mode` (`src`/`dst`),
  `xdp_mode`, `xdp_filter_cmd`.
- **hosts_deny** — `file`, `daemon`.
- **routeros** — `host` (required), `user`, `ssh_cmd`, `ssh_port`,
  `identity`, `list4`/`list6`, `action`.
- **routeros_api** — `host`+`user`+`password` (required), `scheme`,
  `insecure`, `list4`/`list6`, `timeout`.
- **opnsense** — `host`+`key`+`secret` (required), `alias`,
  `scheme`, `insecure`, `curl_cmd`.
- **pfsense** — `host`+`key` (required), `alias`, `timeout`,
  `insecure`.
- **vyos** — `host`+`key` (required), `group`, `timeout`,
  `insecure`.
- **panos** — `host`+`key` (required), `tag`, `vsys`, `scheme`,
  `insecure`, `timeout`.
- **fortigate** — `host`+`token` (required), `group4`/`group6`,
  `vdom`, `scheme`, `insecure`, `timeout`.
- **cisco_fmc** — `host`+`user`+`password`+`group_id` (required),
  `group_name`, `domain`, `timeout`, `insecure`; changes need an FMC
  deployment to enforce.
- **checkpoint** — `host`+`user`+`password` (required), `group`,
  `timeout`, `insecure`; publishes but does not install-policy.
- **juniper_srx** — `host`+`user`+`password` (required),
  `address_set`, `timeout`, `insecure`; commits per change.
- **f5_bigip** — `host`+`user`+`password` (required), `name`,
  `partition`, `timeout`, `insecure`.
- **netscaler** — `host`, `user`+`pass` or `auth`, `dataset`,
  `scheme`, `ssl_verify`, `timeout`.
- **bgp_rtbh** — `driver` (`exabgp`/`gobgp`/`frr`), `announce_type`
  (`rtbh`/`flowspec`), `community`, `next_hop`/`next_hop6`,
  `mask4`/`mask6`, `extra`, `vtysh_cmd`.
- **cloudflare** — `token` or `email`+`key`, `zone`, `mode`, `notes`,
  `timeout`.
- **fastly** — `token`+`service`+`acl` (required), `timeout`,
  `insecure`.
- **akamai** — `host`+`client_token`+`client_secret`+`access_token`+
  `network_list_id` (required), `timeout`, `insecure`; does not
  activate the list.
- **aws_wafv2** — `name4`+`id4` and/or `name6`+`id6`, `scope`,
  `region`, `aws_cmd`.
- **cloud_armor** — `policy` (required), `priority`, `project`,
  `gcloud_cmd`; max 10 banned IPs per rule.
- **azure** — `resource_group`+`nsg`+`rule` (required),
  `subscription`, `az_cmd`.
- **nsupdate** — `domain`, `keyfile`, `ttl`, `rdata`, `nsupdate`.
- **dns_rpz** — `zone`+`keyfile` (required), `trigger`
  (`client-ip`/`ip`), `server`, `ttl`, `nsupdate`.
- **abuseipdb** — `key` (required), `categories`, `comment`,
  `timeout`; reporting only, blocks nothing itself.
- **file_reload** — `file` (required), `format`, `header`, `footer`,
  `reload`, `check`, `remove_on_teardown`.
- **shell** — `init`, `teardown`, `ban`, `unban` (required commands),
  `check`, `flush` (optional).
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
