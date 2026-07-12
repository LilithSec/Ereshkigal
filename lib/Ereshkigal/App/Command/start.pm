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

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
