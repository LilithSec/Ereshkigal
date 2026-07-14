# Ereshkigal documentation

Ereshkigal is the Sumerian goddess of Kur, the underworld. She decides
who is sent below, how long they stay, and who is permitted to return
to the world above.

- [architecture](architecture) :: how the manager and the kur underworlds fit
  together — processes, sockets, the protocol, sentences, the sweeper, and the clay
  tablets

- [install](install) :: dependencies in detail, per-OS install, and running at boot

- [configuration](configuration) :: the ereshkigal.toml reference and a complete
  example

- [kurs](kurs) :: every kind of underworld — shared settings and a page per kur
  under [kurs/](kurs/) detailing each backend, its options, and what the host must
  provide


- [usage](usage) :: communing with Ereshkigal via CLI or socket

- [security](security) :: the trust model, Neti at the gate, and why you probably
  want `kill = 1`

- [examples](examples) :: More examples!

Also...

- [`Ereshkigal`](https://metacpan.org/pod/Ereshkigal)
- [`Ereshkigal::Kur`](https://metacpan.org/pod/Ereshkigal::Kur)
- [`Ereshkigal::Client`](https://metacpan.org/pod/Ereshkigal::Client)
