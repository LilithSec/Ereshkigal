package Ereshkigal::LogDrek;

use 5.006;
use strict;
use warnings;
use Exporter    qw( import );
use Sys::Syslog qw( closelog openlog syslog );

=pod

=head1 NAME

Ereshkigal::LogDrek - Exportable syslog helper shared by the Ereshkigal bins and modules.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

our @EXPORT_OK = qw( log_drek );

=head1 SYNOPSIS

    use Ereshkigal::LogDrek qw( log_drek );

    log_drek( 'info', 'started' );
    log_drek( 'err',  'something broke', $tracking_int );
    log_drek( 'info', 'banned 1.2.3.4', undef, 'kur-sshd' );

=head1 DESCRIPTION

This holds the C<log_drek> sub used by both C<ereshkigal> and C<kur> as well
as the various Ereshkigal modules for logging everything they do. It is a
plain function usable with out new or the like being called, exported on
request, so everything can share one implementation instead of each carrying
their own copy.

=head1 EXPORTS

Nothing is exported by default. L</log_drek> is available via C<@EXPORT_OK>.

=head1 FUNCTIONS

=head2 log_drek

Writes a message to syslog.

    log_drek( $level, $message, $tracking_int, $ident );

C<$level> defaults to 'info' when undef. When C<$tracking_int> is defined it is
prepended to the message as C<< $tracking_int . ' : ' . $message >>. C<$ident>
is the syslog ident to log under and defaults to 'ereshkigal' when undef. Kur
instances should pass C<'kur-' . $name> so log lines are attributable per
instance.

=cut

sub log_drek {
	my ( $level, $message, $tracking_int, $ident ) = @_;

	if ( !defined($level) ) {
		$level = 'info';
	}

	if ( !defined($message) ) {
		$message = '';
	}
	chomp($message);

	if ( defined($tracking_int) ) {
		$message = $tracking_int . ' : ' . $message;
	}

	if ( !defined($ident) ) {
		$ident = 'ereshkigal';
	}

	openlog( $ident, 'cons,pid', 'daemon' );
	syslog( $level, '%s', $message );
	closelog();

	return;
} ## end sub log_drek

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
