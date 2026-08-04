package Ereshkigal::App::Command::banned;

use 5.006;
use strict;
use warnings;
use Ereshkigal::App -command;

=head1 NAME

Ereshkigal::App::Command::banned - List banned IPs, grouped per kur.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    ereshkigal banned

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, validate_args, and execute.

=cut

sub abstract { return 'list banned IPs, grouped per kur' }

sub description { return 'List the banned IPs of every kur instance.'; }

sub usage_desc { return '%c banned'; }

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} ) {
		$self->usage_error('banned does not take any args');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	$self->run_command('banned');

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
