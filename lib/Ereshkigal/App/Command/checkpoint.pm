package Ereshkigal::App::Command::checkpoint;

use 5.006;
use strict;
use warnings;
use Ereshkigal::App -command;

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
	return <<'DESCRIPTION';
Force kurs to write their tablets out now.

Each kur persists what it is holding to CSVs under the cache dir, so
timed bans survive a restart with the right time left on them. Those
writes already happen on every ban and unban, every checkpoint seconds,
and at stop, so you rarely need this... it is here for taking a
consistent snapshot before a backup or a manual poke at the files.

With no args every kur checkpoints; with a kur name only that one, and
naming a fan_out gate reaches every kur behind it.

Writes are atomic, so a checkpoint racing a backup cannot hand you half
a file.
DESCRIPTION
} ## end sub description

sub usage_desc { return '%c checkpoint %o [kur]'; }

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} > 1 ) {
		$self->usage_error('checkpoint takes at most one arg, a kur instance name');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	$self->run_command( 'checkpoint', @{$args} ? { 'kur' => $args->[0] } : undef );

	return;
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
