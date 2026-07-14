package Ereshkigal::IP;

use 5.006;
use strict;
use warnings;
use Exporter     qw( import );
use Regexp::IPv4 qw( $IPv4_re );
use Regexp::IPv6 qw( $IPv6_re );
use Socket       qw( AF_INET6 inet_ntop inet_pton );

=pod

=head1 NAME

Ereshkigal::IP - Exportable IP validation and normalization helper shared by the Ereshkigal modules.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

our @EXPORT_OK = qw( normalize_ip );

=head1 SYNOPSIS

    use Ereshkigal::IP qw( normalize_ip );

    my $ip = normalize_ip('2001:0DB8:0000:0000:0000:0000:0000:0001');
    # $ip is now '2001:db8::1'

    if ( !defined( normalize_ip($raw_ip) ) ) {
        die( '"' . $raw_ip . '" does not appear to be a IPv4 or IPv6 IP' );
    }

=head1 DESCRIPTION

This holds the C<normalize_ip> sub used for validating IPs and reducing them
to a single canonical string form so variant spellings of the same IP, most
notably IPv6 long form vs short form as well as case, can not be mistaken
for differing IPs. Anything unparseable comes back as undef, letting garbage
be bounced at the point of entry instead of being passed along for something
further down to bounce.

=head1 EXPORTS

Nothing is exported by default. L</normalize_ip> is available via C<@EXPORT_OK>.

=head1 FUNCTIONS

=head2 normalize_ip

Returns the canonical string form of the passed IP. If it does not validate
as either a IPv4 or IPv6 IP, undef is returned. undef and refs also return
undef.

    my $ip = normalize_ip($raw_ip);

Validation is done via L<Regexp::IPv4> and L<Regexp::IPv6>, the same as
L<Net::Firewall::BlockerHelper> uses, so anything accepted here is also
acceptable to the backends. On top of that IPv4 with leading zero octets,
such as 010.0.0.1, which the regex permits, is explicitly refused rather
than the octal vs decimal ambiguity being guessed at.

Only IPv6 IPs the regex has already validated are handed to inet_pton and
inet_ntop, which are used purely for reducing them to the canonical form.
IPv4 IPs that validate are already in canonical form and are returned as is.

=cut

sub normalize_ip {
	my ($ip) = @_;

	if ( !defined($ip) || ref($ip) ne '' ) {
		return undef;
	}

	if ( $ip =~ /\A$IPv4_re\z/ ) {
		# the regex permits leading zero octets, but whether those are octal
		# or decimal depends on what is reading them, so they are refused
		# rather than guessed at
		foreach my $octet ( split( /\./, $ip ) ) {
			if ( $octet =~ /\A0[0-9]/ ) {
				return undef;
			}
		}
		# a valid dotted quad with out leading zero octets is already
		# canonical
		return $ip;
	} ## end if ( $ip =~ /\A$IPv4_re\z/ )

	if ( $ip =~ /\A$IPv6_re\z/ ) {
		my $packed = inet_pton( AF_INET6, $ip );
		if ( defined($packed) ) {
			my $canonical = inet_ntop( AF_INET6, $packed );
			if ( defined($canonical) ) {
				return $canonical;
			}
		}
		# valid per the regex, but the inet functions could not round trip
		# it... refusing it beats passing along a form that could not be
		# canonicalized
		return undef;
	} ## end if ( $ip =~ /\A$IPv6_re\z/ )

	return undef;
} ## end sub normalize_ip

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
