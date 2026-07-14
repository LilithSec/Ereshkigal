# bgp_rtbh — BGP Remote Triggered Black Hole

Blocks by announcing each banned IP to the network as a host route
(`/32` IPv4, `/128` IPv6) carrying the RFC 7999 BLACKHOLE community.
Routers that honor the community drop the traffic — at your edge, or
with a transit provider that accepts blackhole announcements, before
it ever reaches your link. The [route](route.md) backend scaled from
one host to the whole network.

```toml
[kur.ddos]
backend  = "bgp_rtbh"
ban_time = 3600

[kur.ddos.options]
driver = "exabgp"
```

## How the network side works — required first

This kur only announces and withdraws; everything else is BGP
engineering that must already exist:

- A running **ExaBGP** or **GoBGP** daemon on the kur host holding
  BGP session(s) to your routers. The kur talks to the daemon
  (`exabgpcli` / `gobgp`), never to the routers.
- Routers configured to act on the community — typically a route-map
  matching `65535:666` that sets the next hop to a discard route.
  The stock next hops here (`192.0.2.1`, `100::1`) are the
  conventional discard targets; match them or override the options.
- **Source-based vs destination-based**: plain RTBH drops traffic
  *toward* the announced prefix; since this tool bans attacker
  *sources*, the usual pairing is source-based RTBH — loose uRPF
  (`ip verify unicast source reachable-via any`) on the edge plus
  the blackhole route, which drops traffic *from* the prefix.
  Destination-based RTBH with attacker sources does something quite
  different (it blackholes your replies); know which one your edge
  implements.
- **Guardrails are not optional.** A bug here announces routes.
  Configure max-prefix limits on the peers, filter what the routers
  will accept to host routes carrying the community, and never let
  these announcements escape to peers that shouldn't see them.

## Requirements

- `exabgpcli` (driver `exabgp`, the default) or `gobgp` (driver
  `gobgp`) in the `PATH` of the kur process, and its daemon running.

## Settings

- `ports` / `protocols` — accepted for parity but **ignored**; a
  route has no ports.
- `prefix` / `name` — unused beyond the usual bookkeeping.

## Options

| option          | default      | what                                                  |
|-----------------|--------------|--------------------------------------------------------|
| `driver`        | `exabgp`     | `exabgp` or `gobgp`                                   |
| `community`     | `65535:666`  | community on every announcement (RFC 7999 BLACKHOLE)  |
| `next_hop`      | `192.0.2.1`  | next hop for IPv4 announcements                       |
| `next_hop6`     | `100::1`     | next hop for IPv6 announcements                       |
| `mask4`         | `32`         | IPv4 prefix length                                    |
| `mask6`         | `128`        | IPv6 prefix length                                    |
| `extra`         | *(unset)*    | extra attributes appended verbatim, driver syntax     |
| `exabgpcli_cmd` | `exabgpcli`  | exabgpcli binary (driver exabgp)                      |
| `gobgp_cmd`     | `gobgp`      | gobgp binary (driver gobgp)                           |

`extra` is driver-specific syntax passed through untouched — exabgp
`local-preference 50` vs gobgp `local-pref 50`; switching drivers
means rewriting it. Widening `mask4`/`mask6` announces more than the
banned IP — deliberate collateral only.

## What each operation runs

| operation  | exabgp driver                                                     | gobgp driver                                             |
|------------|-------------------------------------------------------------------|-----------------------------------------------------------|
| `init`     | nothing                                                           | nothing                                                   |
| `ban`      | `exabgpcli 'announce route <ip>/<mask> next-hop <nh> community [<community>]'` | `gobgp global rib add <ip>/<mask> nexthop <nh> community <community> -a ipv4\|ipv6` |
| `unban`    | `exabgpcli 'withdraw route <ip>/<mask> next-hop <nh> community [<community>]'` | `gobgp global rib del <ip>/<mask> -a ipv4\|ipv6`         |
| `check`    | `exabgpcli 'show neighbor summary'` exits 0                       | `gobgp neighbor` exits 0                                  |
| `flush`    | the withdraw per banned IP                                        | same                                                      |
| `re_init`  | teardown (best effort), init, re-announce every banned IP         | same                                                      |
| `teardown` | the withdraw per banned IP (ban book kept)                        | same                                                      |

`list` is the kur's own ban book; there is no init-time setup.

## self_heal

`check` confirms the daemon answers — not that sessions are
Established, not that any specific route is still announced, and
certainly not that routers are dropping. An ExaBGP restart loses its
announcements while `check` recovers as soon as the daemon is back:
pair daemon restarts with a `re_init` (which re-announces the whole
book), and watch session state with your normal BGP monitoring, not
this kur.

## Gotchas

- The blast radius is the network, not the host. Test with a lab
  peer and `ban_time` short before trusting automation with it.
- Sentences ending means withdraws; a mass expiry is a burst of
  `exabgpcli` invocations. BGP handles it; your logging might blink.
- Errors carry Error::Helper flags (`driverInvalid`, …) — `perldoc
  Net::Firewall::BlockerHelper::backends::bgp_rtbh` has the full
  table.
