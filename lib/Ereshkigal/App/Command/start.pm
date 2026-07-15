package Ereshkigal::App::Command::start;

use 5.006;
use strict;
use warnings;
use Ereshkigal::App -command;
use Ereshkigal             ();
use Net::Server::Daemonize qw( daemonize );

=head1 NAME

Ereshkigal::App::Command::start - Start the manager and all the configured kur instances.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    ereshkigal start
    ereshkigal start --foreground
    ereshkigal start --config /usr/local/etc/ereshkigal.toml

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'start the manager and all the configured kur instances' }

sub description { return 'Start the manager, daemonizing unless told otherwise.'; }

sub usage_desc { return '%c start %o'; }

sub opt_spec {
	return (
		[ 'config=s',     'path of the config file', { default => '/usr/local/etc/ereshkigal.toml' } ],
		[ 'foreground|f', 'do not daemonize' ],
	);
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} ) {
		$self->usage_error('start does not take any args');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $ereshkigal = Ereshkigal->new( 'config' => $opt->config );

	# A previous manager may still be tearing down. `ereshkigal stop`, and thus
	# `service ereshkigal restart`, returns as soon as the shutdown is requested,
	# so the following start can race the old process. The manager unlinks its
	# PID file only once it has fully exited, so wait briefly for a live PID to
	# clear rather than letting daemonize() abort with
	# "Pid_file already exists for running process".
	$self->_wait_for_pid_clear( $ereshkigal->pid_path );

	if ( $opt->foreground ) {
		open( my $pid_fh, '>', $ereshkigal->pid_path )
			|| die( 'Failed to open the PID file "' . $ereshkigal->pid_path . '"... ' . $! );
		print $pid_fh $$;
		close($pid_fh);
	} else {
		daemonize( $>, ( split( /\s+/, $) ) )[0], $ereshkigal->pid_path );
	}

	$ereshkigal->start_server;

	unlink( $ereshkigal->pid_path ) if -e $ereshkigal->pid_path;

	return;
} ## end sub execute

# Poll for up to ~10s, waiting for the named PID file to belong to a process
# that is no longer running. Returns as soon as the file is gone, holds no
# readable PID, or names a dead process, so a stale PID file (which daemonize()
# happily reclaims) and a still-exiting manager both resolve cleanly. If a live
# manager is still running after the timeout, we return anyway and let
# daemonize() refuse to start a duplicate.
sub _wait_for_pid_clear {
	my ( $self, $pid_path ) = @_;

	for ( 1 .. 40 ) {
		last if !-e $pid_path;

		open( my $pid_fh, '<', $pid_path ) or last;
		my $pid = <$pid_fh>;
		close($pid_fh);

		last if !defined($pid) || $pid !~ /([0-9]+)/;
		$pid = $1;

		# kill 0 is true while the process exists (or exists but is ours to
		# signal); once it goes false the old manager is gone.
		last if !kill( 0, $pid );

		# 0.25s nap without pulling in Time::HiRes.
		select( undef, undef, undef, 0.25 );
	}

	return;
} ## end sub _wait_for_pid_clear

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
