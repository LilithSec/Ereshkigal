# Ereshkigal

Ereshkigal is the Sumerian goddess of Kur, the underworld. She decides
who is sent below, how long they stay, and who is permitted to return
to the world above.

In the world above, Ereshkigal is a ban manager for firewalls, in the
same family as fail2ban. An `ereshkigal` manager daemon rules over all
`kur`. Each kur an underworld of its own, holding the IPs consigned to it. Each kur wraps
a single
[Net::Firewall::BlockerHelper](https://metacpan.org/pod/Net::Firewall::BlockerHelper)
instance for talking to the actual firewall (pf, ipfw, iptables, shell commands, or a
dummy for testing).

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

Banishments may be timed sentences, served, and then automatically released
by the sweeper or eternal (`--ban-time 0`). Every kur records its
residents to a CSV clay tablets, so the underworld survives a restart intact.

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

### FreeBSD

```shell
pkg install p5-App-Cmd p5-Error-Helper p5-JSON-MaybeXS p5-Net-Server \
    p5-POE p5-App-cpanminus
cpanm TOML::Tiny Net::Firewall::BlockerHelper \
    POE::Component::Server::JSONUnix Ereshkigal
```

Startup scripts for running at boot [rc/freebsd/ereshkigal](rc/freebsd/ereshkigal).

### Debian

```shell
apt-get install libapp-cmd-perl libjson-maybexs-perl libnet-server-perl \
    libpoe-perl libtoml-tiny-perl cpanminus
cpanm Error::Helper Net::Firewall::BlockerHelper \
    POE::Component::Server::JSONUnix Ereshkigal
```

Startup scripts for running at boot
[rc/systemd/ereshkigal.service](rc/systemd/ereshkigal.service).

## Documentation

To continue your journey go to [docs/index.md](docs/index.md).

Also...

- `perldoc Ereshkigal`
- `perldoc Ereshkigal::Kur`
- `perldoc Ereshkigal::Client`
