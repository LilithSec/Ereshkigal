# Ereshkigal

Ereshkigal is the Sumerian goddess of Kur, the underworld. She decides
who is sent below, how long they stay, and who is permitted to return
to the world above.

In the world above, Ereshkigal is a ban manager for firewalls, in the
same family as fail2ban. An `ereshkigal` manager daemon rules over one
`kur` worker per firewall concern — each kur an underworld of its own,
holding the IPs consigned to it. Each kur wraps a single
[Net::Firewall::BlockerHelper](https://metacpan.org/pod/Net::Firewall::BlockerHelper)
instance for talking to the actual firewall (pf, ipfw, iptables, a
shell command, or a dummy for testing), and everything speaks
newline-delimited JSON over unix sockets.

Sending an IP below and calling it back looks like this...

```shell
# raise the underworlds
ereshkigal start

# consign an IP to the sshd underworld for an hour
ereshkigal ban --kur sshd --ban-time 3600 1.2.3.4

# read the rolls of who dwells below
ereshkigal banned

# call one back to the world above
ereshkigal unban 1.2.3.4
```

Bans may be timed — sentences, served and then automatically released
by the sweeper — or eternal (`--ban-time 0`). Every kur records its
residents to a CSV ledger, its clay tablets, so the underworld
survives a restart intact.

## Install

### From source

Dependencies are declared in Makefile.PL, so with
[cpanminus](https://metacpan.org/pod/App::cpanminus)...

```shell
cpanm --installdeps .
perl Makefile.PL
make
make test
make install
```

The dependencies, if fetching them by hand: App::Cmd, Error::Helper,
JSON::MaybeXS, Net::Firewall::BlockerHelper, Net::Server (for
Net::Server::Daemonize), POE, POE::Component::Server::JSONUnix, and
TOML::Tiny. Tests additionally want Test::Exception.

### FreeBSD

Most of the dependencies are ported...

```shell
pkg install p5-App-Cmd p5-Error-Helper p5-JSON-MaybeXS p5-Net-Server \
    p5-POE p5-App-cpanminus
cpanm TOML::Tiny Net::Firewall::BlockerHelper \
    POE::Component::Server::JSONUnix
```

...then the from-source install above.

### Debian

```shell
apt-get install libapp-cmd-perl libjson-maybexs-perl libnet-server-perl \
    libpoe-perl libtoml-tiny-perl cpanminus
cpanm Error::Helper Net::Firewall::BlockerHelper \
    POE::Component::Server::JSONUnix
```

...then the from-source install above. Package names are current as of
writing; anything your release lacks, cpanm will happily fetch.

Startup scripts for running at boot — a FreeBSD rc.d script and a
systemd unit — ship in the [`rc/`](rc/) directory; see
[docs/install.md](docs/install.md) for putting them in place.

## Documentation

The docs index lives at [docs/index.md](docs/index.md).

| doc                                              | covers                                                          |
|--------------------------------------------------|-----------------------------------------------------------------|
| [docs/architecture.md](docs/architecture.md)     | how the manager and the kur underworlds fit together             |
| [docs/install.md](docs/install.md)               | dependencies in detail and running at boot                       |
| [docs/configuration.md](docs/configuration.md)   | the ereshkigal.toml reference                                    |
| [docs/usage.md](docs/usage.md)                   | the CLI, and driving the socket directly from integrations       |
| [docs/security.md](docs/security.md)             | the trust model, and why you probably want `kill = 1`            |
| [docs/examples.md](docs/examples.md)             | worked scenarios to copy from                                    |

The module POD (`perldoc Ereshkigal`, `perldoc Ereshkigal::Kur`, and
so on) is the API reference; [DESIGN.md](DESIGN.md) is the development
design doc.
