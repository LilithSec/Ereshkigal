# Examples

Worked scenarios to copy from. Paths assume the defaults; adjust to
taste.

## An sshd underworld on pf, hour-long sentences

`/usr/local/etc/ereshkigal.toml`...

```toml
socket_group = "wheel"

[kur.sshd]
backend   = "pf"
ports     = [ "22" ]
protocols = [ "tcp" ]
ban_time  = 3600

[kur.sshd.options]
kill = 1        # sever established sessions too... see security.md
```

```shell
ereshkigal start
ereshkigal ban --kur sshd 203.0.113.7
ereshkigal status sshd
```

The ban adds 203.0.113.7 to the kur's pf table and kills its existing
states. An hour later the sweeper releases it on its own.

## One underworld per service

```toml
ban_time = 600                  # the default sentence

[kur.sshd]
backend   = "pf"
ports     = [ "22" ]
protocols = [ "tcp" ]
ban_time  = 3600                # ssh abusers sit longer

[kur.sshd.options]
kill = 1

[kur.smtp]
backend   = "pf"
ports     = [ "25", "465", "587" ]
protocols = [ "tcp" ]

[kur.smtp.options]
kill = 1

[kur.web]
backend   = "pf"
ports     = [ "80", "443" ]
protocols = [ "tcp" ]
ban_time  = 300                 # web scanners come and go
```

`ereshkigal ban 198.51.100.9` consigns an IP to all three at once;
`--kur web` picks one.

## An eternal-residence blocklist

```toml
[kur.blocklist]
backend  = "pf"
ban_time = 0                    # no one comes back on their own

[kur.blocklist.options]
kill = 1
```

Feeding it from a file...

```shell
xargs ereshkigal ban --kur blocklist < /usr/local/etc/blocklist.txt
```

Those IPs stay below across restarts (the tablets see to that) until
an explicit `ereshkigal unban`.

## Raising and tearing down an underworld at runtime

```shell
# raise a dns kur right now
ereshkigal add dns --backend pf --ports 53 --protocols tcp,udp \
    --option kill=1 --ban-time 300

ereshkigal ban --kur dns 192.0.2.4

# tear it down... firewall state and all
ereshkigal remove dns
```

Neither command edits ereshkigal.toml — to keep the dns kur across
restarts, add its `[kur.dns]` hash to the config.

## A minimal log watcher

The simplest possible integration, banning via the CLI...

```sh
#!/bin/sh
# consign repeat offenders in auth.log to the sshd underworld
tail -F /var/log/auth.log | while read line; do
    ip=$(printf '%s\n' "$line" \
        | sed -n 's/.*Failed password.*from \([0-9.]*\).*/\1/p')
    [ -n "$ip" ] && ereshkigal ban --kur sshd "$ip"
done
```

Or skipping the CLI and speaking JSON straight at the manager
socket...

```shell
printf '%s\n' \
  '{"command":"ban","args":{"ips":["203.0.113.7"],"kur":"sshd","ban_time":3600}}' \
  | nc -U /var/run/ereshkigal/socket
```

From perl, use `Ereshkigal::Client` — it also handles the
`enable_auth` gate transparently (see [usage](usage)).

## A monitoring user Neti admits to only one kur

```toml
enable_auth   = true
authed_groups = [ "wheel" ]     # admins may do anything

[kur.sshd]
backend      = "pf"
ports        = [ "22" ]
protocols    = [ "tcp" ]
authed_users = [ "sshd-mon" ]   # expands the global lists, for sshd only

[kur.sshd.options]
kill = 1
```

The `sshd-mon` user can `ereshkigal status sshd` and
`ereshkigal ban --kur sshd ...`, but `status`, a bare `ban`, `stop`,
and anything touching other kurs is refused at the gate. See
[security](security) for the full trust model.

## An underworld of pure imagination

The `dummy` backend remembers what it was told and touches no
firewall, so everything can be tried unprivileged...

```toml
run_base_dir   = "/tmp/ereshkigal-play/run"
cache_base_dir = "/tmp/ereshkigal-play/cache"
socket_group   = "wheel"        # any group you are in

[kur.testing]
backend = "dummy"
```

```shell
ereshkigal start --config ./play.toml
ereshkigal -s /tmp/ereshkigal-play/run/socket ban --ban-time 5 192.0.2.1
ereshkigal -s /tmp/ereshkigal-play/run/socket banned
sleep 6
ereshkigal -s /tmp/ereshkigal-play/run/socket banned   # released by the sweeper
ereshkigal -s /tmp/ereshkigal-play/run/socket stop
```
