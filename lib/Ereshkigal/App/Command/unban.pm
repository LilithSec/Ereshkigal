package Ereshkigal::App::Command::unban;

use 5.006;
use strict;
use warnings;
use Ereshkigal::App -command;
use Ereshkigal::Client ();
use JSON::MaybeXS      ();

=head1 NAME

Ereshkigal::App::Command::unban - Unban a IP or everything.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    # check every kur for the IP and unban it where present
    ereshkigal unban 1.2.3.4

    # remove all bans everywhere
    ereshkigal unban --all

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'unban a IP or everything' }

sub description {
	return 'With a IP, each kur is checked for it and it is unbanned from each kur it is present on. '
		. 'With --all, every kur is flushed, removing all bans everywhere.';
}

sub usage_desc { return '%c unban %o [<IP>]'; }

sub opt_spec {
	return ( [ 'all', 'remove all bans from every kur' ], );
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( $opt->all && @{$args} ) {
		$self->usage_error('--all and a IP may not be used together');
	}
	if ( !$opt->all && @{$args} != 1 ) {
		$self->usage_error('either --all or a single IP must be specified');
	}

	return;
} ## end sub validate_args

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $unban_args;
	if ( $opt->all ) {
		$unban_args = { 'all' => 1 };
	} else {
		$unban_args = { 'ip' => $args->[0] };
	}

	my $client = Ereshkigal::Client->new( 'socket' => $self->app->global_options->{socket} );
	my $result = $client->call_ok( 'unban', $unban_args );

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
