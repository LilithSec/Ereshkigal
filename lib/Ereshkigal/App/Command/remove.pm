package Ereshkigal::App::Command::remove;

use 5.006;
use strict;
use warnings;
use Ereshkigal::App -command;
use Ereshkigal::Client ();
use JSON::MaybeXS      ();

=head1 NAME

Ereshkigal::App::Command::remove - Stop a kur instance and deregister it.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    ereshkigal remove sshd

=head1 DESCRIPTION

Stops the kur instance, tearing it's firewall setup down and removing it's
socket and PID files, and deregisters it from the running manager. Does not
rewrite the config file... to make it permanent, remove it from the config.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, validate_args, and execute.

=cut

sub abstract { return 'stop a kur instance and deregister it' }

sub description {
	return 'Stop the kur instance, tearing it\'s firewall setup down, and deregister it from the '
		. 'running manager. Does not rewrite the config file.';
}

sub usage_desc { return '%c remove <kur>'; }

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} != 1 ) {
		$self->usage_error('a single kur instance name must be specified');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $client = Ereshkigal::Client->new( 'socket' => $self->app->global_options->{socket} );
	my $result = $client->call_ok( 'remove_kur', { 'name' => $args->[0] } );

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
