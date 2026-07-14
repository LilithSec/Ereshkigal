# bgp_rtbh — BGP Remote Triggered Black Hole

Blocks by announcing each banned IP to the network as a host route
(`/32` IPv4, `/128` IPv6) carrying the RFC 7999 BLACKHOLE community —
or, with `announce_type = "flowspec"`, as a BGP FlowSpec rule
discarding traffic from the source. Routers that honor the
announcement drop the traffic — at your edge, or with a transit
provider that accepts them, before it ever reaches your link. The
[route](route) backend scaled from one host to the whole network.

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

- A running **ExaBGP**, **GoBGP**, or **FRR** daemon on the kur host
  holding BGP session(s) to your routers. The kur talks to the
  daemon (`exabgpcli` / `gobgp` / `vtysh`), never to the routers.
- Routers configured to act on the community — typically a route-map
  matching `65535:666` that sets the next hop to a discard route.
  The stock next hops here (`192.0.2.1`, `100::1`) are the
  conventional discard targets; match them or override the options.
- The **frr driver works differently**: it injects a blackhole
  static route via `vtysh` and relies on a `redistribute static`
  route-map in your FRR BGP config to tag it with the blackhole
  community — `next_hop`/`community` here are not used by it.
- **FlowSpec** (`announce_type = "flowspec"`, exabgp and gobgp only)
  announces a discard rule matching the *source* prefix instead of a
  blackhole route. Where your edge supports RFC 8955, this drops
  traffic *from* the attacker directly — no loose-uRPF pairing
  needed, and no risk of blackholing your replies. Your peers must
  accept the flowspec address families for it to do anything.
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
| `driver`        | `exabgp`     | `exabgp`, `gobgp`, or `frr`                           |
| `announce_type` | `rtbh`       | `rtbh` or `flowspec` (flowspec: exabgp/gobgp only)    |
| `community`     | `65535:666`  | community on every announcement (RFC 7999 BLACKHOLE)  |
| `next_hop`      | `192.0.2.1`  | next hop for IPv4 announcements                       |
| `next_hop6`     | `100::1`     | next hop for IPv6 announcements                       |
| `mask4`         | `32`         | IPv4 prefix length                                    |
| `mask6`         | `128`        | IPv6 prefix length                                    |
| `extra`         | *(unset)*    | extra attributes appended verbatim, driver syntax     |
| `exabgpcli_cmd` | `exabgpcli`  | exabgpcli binary (driver exabgp)                      |
| `gobgp_cmd`     | `gobgp`      | gobgp binary (driver gobgp)                           |
| `vtysh_cmd`     | `vtysh`      | vtysh binary (driver frr)                             |

`community`, `next_hop`/`next_hop6`, and `extra` apply to the
exabgp/gobgp rtbh announcements; the frr driver's blackhole static
route carries none of them (your redistribute route-map adds the
community), and flowspec rules encode match-and-discard instead.

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

With `announce_type = "flowspec"` the ban/unban commands become
FlowSpec discard rules instead:

- exabgp: `exabgpcli 'announce|withdraw flow route { match { source
  <ip>/<mask>; } then { discard; } }'`
- gobgp: `gobgp global rib add|del -a ipv4-flowspec|ipv6-flowspec
  match source <ip>/<mask> then discard`

The frr driver injects and removes blackhole statics via
`vtysh -c 'configure terminal' -c '[no] ip[v6] route <ip>/<mask>
blackhole'`, and its `check` is `vtysh -c 'show ip bgp summary'`.

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
- Errors carry Error::Helper flags (`driverInvalid`, …) — [`Net::Firewall::BlockerHelper::backends::bgp_rtbh`](https://metacpan.org/pod/Net::Firewall::BlockerHelper::backends::bgp_rtbh) has the full
  table.
