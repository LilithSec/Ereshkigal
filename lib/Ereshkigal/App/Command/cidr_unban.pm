package Ereshkigal::App::Command::cidr_unban;

use 5.006;
use strict;
use warnings;
use Ereshkigal::App -command;
use Ereshkigal::Client ();
use JSON::MaybeXS      ();

=head1 NAME

Ereshkigal::App::Command::cidr_unban - Unban a CIDR range.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    # check every kur for the CIDR and unban it where present
    ereshkigal cidr-unban 1.2.3.0/24

There is no --all form... C<ereshkigal unban --all> already flushes CIDR bans
alongside single IP bans.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

# accept both the dashed and underscored spellings
sub command_names { return ( 'cidr-unban', 'cidr_unban' ); }

sub abstract { return 'unban a CIDR range' }

sub description {
	return 'Each kur is checked for the CIDR and it is unbanned from each kur it is present on. '
		. 'To remove everything, including CIDR bans, use unban --all.';
}

sub usage_desc { return '%c cidr-unban %o <CIDR>'; }

sub opt_spec {
	return ();
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} != 1 ) {
		$self->usage_error('a single CIDR must be specified');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $client = Ereshkigal::Client->new( 'socket' => $self->app->global_options->{socket} );
	my $result = $client->call_ok( 'cidr_unban', { 'cidr' => $args->[0] } );

	print JSON::MaybeXS->new( 'pretty' => 1, 'canonical' => 1 )->encode($result);

	return;
} ## end sub execute

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
