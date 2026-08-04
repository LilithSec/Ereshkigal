package Ereshkigal::App::Command::status;

use 5.006;
use strict;
use warnings;
use Ereshkigal::App -command;

=head1 NAME

Ereshkigal::App::Command::status - Show status of the manager and kur instances.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    ereshkigal status
    ereshkigal status --all
    ereshkigal status sshd

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'show status of the manager and kur instances' }

sub description {
	return
		  'With no args, shows manager status and the up/down state of each kur instance. '
		. 'With --all, includes each kur\'s full status block. '
		. 'With a kur name, shows the full status of that one instance.';
}

sub usage_desc { return '%c status %o [kur]'; }

sub opt_spec {
	return ( [ 'all', 'include the full status of every kur instance' ], );
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} > 1 ) {
		$self->usage_error('status takes at most one arg, a kur instance name');
	}
	if ( @{$args} && $opt->all ) {
		$self->usage_error('--all and a kur instance name may not be used together');
	}

	return;
} ## end sub validate_args

sub execute {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} ) {
		$self->run_command( 'status_kur', { 'name' => $args->[0] } );
	} elsif ( $opt->all ) {
		$self->run_command('status_all');
	} else {
		$self->run_command('status');
	}

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
