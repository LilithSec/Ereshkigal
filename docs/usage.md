# Usage

Everything goes through the `ereshkigal` CLI, which talks to the
manager socket. The global `-s <path>` option points it at a
non-default socket and works with every subcommand...

```shell
ereshkigal -s /var/run/ereshkigal/socket status
```

Data commands print their result as pretty JSON and exit 0; errors
print the server's error text and exit nonzero, so the CLI scripts
cleanly.

## Raising and quieting the underworlds

```shell
ereshkigal start                      # read the config, daemonize, raise every kur
ereshkigal start --foreground        # same, staying attached (for supervisors/testing)
ereshkigal start --config /etc/e.toml
ereshkigal stop                       # stop every kur (tearing down their firewall
                                      # state) and then the manager
```

## A census of who dwells below

```shell
ereshkigal status           # manager uptime, each kur's up/down state and restarts
ereshkigal status --all     # the above plus every kur's full status block
ereshkigal status sshd      # one underworld in detail... uptime, stats, ban counts,
                            # sentence defaults, when the tablets were last copied
ereshkigal banned           # the rolls... every banned IP per kur, with the epoch
                            # each sentence ends (0 = eternal)
```

## Sending IPs below and calling them back

```shell
ereshkigal ban 1.2.3.4 5.6.7.8        # consign to EVERY kur
ereshkigal ban --kur sshd 1.2.3.4     # just the sshd underworld
ereshkigal ban --kur gate 1.2.3.4     # a gate (fan_out kur) sends it to
                                      # every member underworld
ereshkigal ban --ban-time 3600 1.2.3.4  # a one hour sentence
ereshkigal ban --ban-time 0 1.2.3.4     # eternal residence

ereshkigal unban 1.2.3.4    # each kur is checked and the IP released wherever it
                            # is actually held... the response reports was_banned
                            # per kur
ereshkigal unban --all      # empty every underworld (flush)
```

Sentences default per the config layering (request > kur > global >
600 seconds). Banning an IP already below just refreshes its sentence.
When a sentence is served, the kur's sweeper releases the IP on its
own — no cron jobs needed.

## Managing underworlds at runtime

```shell
ereshkigal add dns --backend pf --ports 53 --protocols tcp,udp \
    --option kill=1 --ban-time 300     # raise a new kur, now
ereshkigal add gate --fan-out sshd,smtp  # raise a gate onto existing kurs
                                         # (see configuration.md)
ereshkigal remove dns                  # stop it, tear down its firewall state,
                                       # and deregister it
```

Neither touches the config file — a kur added at runtime vanishes on
the next restart unless you also add it to ereshkigal.toml, and a
removed one returns unless you delete it from there.

## The tablets

```shell
ereshkigal checkpoint          # every kur recopies its ban state CSV now
ereshkigal checkpoint sshd     # just the one
```

Normally you never need this — the tablets are rewritten on every
ban/unban, every `checkpoint` seconds, and at stop — but it is there
for taking a consistent snapshot before backups and the like.

## Driving the socket directly

Integrations (log watchers, IDS glue) do not need the CLI. The
manager socket speaks newline-delimited JSON: send one object, read
one back.

```
{"command":"ban","args":{"ips":["1.2.3.4"],"kur":"sshd","ban_time":3600}}
```

If `kur` names a gate (a `fan_out` kur), the ban fans out to its
members — handy for pointing an integration at one stable name and
managing which underworlds it reaches from the config side.

A shell one-liner...

```shell
printf '%s\n' '{"command":"ban","args":{"ips":["1.2.3.4"]}}' \
    | nc -U /var/run/ereshkigal/socket
```

From perl, `Ereshkigal::Client` handles the framing, timeouts, and —
when `enable_auth` is on — the gate challenge, transparently...

```perl
use Ereshkigal::Client;

my $client = Ereshkigal::Client->new(
    socket => '/var/run/ereshkigal/socket',
);

# dies on error responses, returns the result
my $result = $client->call_ok( 'ban',
    { ips => ['1.2.3.4'], kur => 'sshd', ban_time => 3600 } );

# or handle the envelope yourself
my $response = $client->call('status');
if ( $response->{status} eq 'ok' ) { ... }
```

The commands and their args mirror the CLI exactly: `status`,
`status_all`, `status_kur` (`{"name":...}`), `banned`, `ban`
(`{"ips":[...], "kur":..., "ban_time":...}` with kur/ban_time
optional), `unban` (`{"ip":...}` or `{"all":true}`), `add_kur`
(`{"name":..., "opts":{...}}`), `remove_kur` (`{"name":...}`),
`checkpoint` (`{"kur":...}` optional), and `stop`. Responses are
`{"status":"ok","result":...}` or `{"status":"error","error":"..."}`.

Note that with `enable_auth` on, a raw `nc` integration must complete
the auth challenge itself (see [security.md](security.md)) — using
Ereshkigal::Client is much less bother.
