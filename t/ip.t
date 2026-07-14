#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use Ereshkigal::IP qw( normalize_ip );

#
# IPv4
#

is( normalize_ip('1.2.3.4'),         '1.2.3.4',         'valid IPv4 returned as is' );
is( normalize_ip('255.255.255.255'), '255.255.255.255', 'broadcast IPv4 returned as is' );

# leading zero octets are ambiguous, octal vs decimal wise, so they are
# refused rather than guessed at
is( normalize_ip('001.002.003.004'), undef, 'IPv4 with leading zero octets refused' );
is( normalize_ip('010.0.0.1'),       undef, 'IPv4 with a leading zero octet refused' );

is( normalize_ip('1.2.3'),     undef, 'short IPv4 refused' );
is( normalize_ip('1.2.3.4.5'), undef, 'long IPv4 refused' );
is( normalize_ip('1.2.3.256'), undef, 'out of range octet refused' );

#
# IPv6... long form, short form, and case variants all reduce to the same
# canonical form
#

is( normalize_ip('2001:0db8:0000:0000:0000:0000:0000:0001'), '2001:db8::1', 'long form IPv6 canonicalized' );
is( normalize_ip('2001:0DB8:0000:0000:0000:0000:0000:0001'), '2001:db8::1', 'uppercase long form canonicalized' );
is( normalize_ip('2001:db8:0:0::1'),                         '2001:db8::1', 'partially compressed canonicalized' );
is( normalize_ip('2001:db8::1'),                             '2001:db8::1', 'already canonical returned as is' );
is( normalize_ip('2001:DB8::1'),                             '2001:db8::1', 'uppercase short form lowercased' );

is( normalize_ip('::1'), '::1', 'loopback IPv6 ok' );

is( normalize_ip('2001:db8::1::2'), undef, 'double compression refused' );
is( normalize_ip('2001:db8:::1'),   undef, 'triple colon refused' );
is( normalize_ip('12345::1'),       undef, 'oversized group refused' );

#
# non-IP stuff
#

is( normalize_ip('not-an-ip'),    undef, 'random string refused' );
is( normalize_ip(''),             undef, 'empty string refused' );
is( normalize_ip(undef),          undef, 'undef refused' );
is( normalize_ip( ['1.2.3.4'] ),  undef, 'ref refused' );
is( normalize_ip('1.2.3.4/32'),   undef, 'CIDR refused' );
is( normalize_ip(' 1.2.3.4'),     undef, 'leading whitespace refused' );
is( normalize_ip("1.2.3.4\n"),    undef, 'trailing newline refused' );
is( normalize_ip('fe80::1%eth0'), undef, 'scope id refused' );

done_testing;
