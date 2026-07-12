package Ereshkigal::App::Command::checkpoint;

use 5.006;
use strict;
use warnings;
use Ereshkigal::App -command;
use Ereshkigal::Client ();
use JSON::MaybeXS      ();

=head1 NAME

Ereshkigal::App::Command::checkpoint - Force kur instances to write their ban state CSV out now.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    # every kur checkpoints
    ereshkigal checkpoint

    # just sshd
    ereshkigal checkpoint sshd

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, validate_args, and execute.

=cut

sub abstract { return 'force kur instances to write their ban state CSV out now' }

sub description {
	return 'Force all kur instances, or just the named one, to write their ban state CSV out now.';
}

sub usage_desc { return '%c checkpoint [kur]'; }

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} > 1 ) {
		$self->usage_error('checkpoint takes at most one arg, a kur instance name');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $client = Ereshkigal::Client->new( 'socket' => $self->app->global_options->{socket} );
	my $result = $client->call_ok( 'checkpoint', @{$args} ? { 'kur' => $args->[0] } : undef );

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
