package Ereshkigal::App::Command::unban;

use 5.006;
use strict;
use warnings;
use Ereshkigal::App -command;

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
	return <<'DESCRIPTION';
Release a IP from the underworld, or empty it entirely.

With a IP, every kur is asked whether it is holding that address and it is
released from each one that is. A kur that never had it says so rather
than erroring, so it is safe to fire at all of them.

With --all, every kur is flushed instead. That means BOTH single IP and
range bans on every kur, released in one go, with no confirmation and no
undo... the ban books are emptied and the firewall rules removed. The
tablets are rewritten straight after, so a restart will not bring any of
them back. If you meant one address, name it.

  ereshkigal unban 1.2.3.4        # release the one
  ereshkigal unban --all          # empty every underworld, everywhere

Ranges banned with cidr-ban are matched by "cidr-unban", not by naming a
IP inside them... but --all takes those too.
DESCRIPTION
} ## end sub description

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

	$self->run_command( 'unban', $unban_args );

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
