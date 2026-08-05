package Ereshkigal::App::Command;

use 5.006;
use strict;
use warnings;
use parent 'App::Cmd::Command';
use Ereshkigal::Client ();
use JSON::MaybeXS      ();

=head1 NAME

Ereshkigal::App::Command - Base class for the ereshkigal subcommands.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

Base class for the Ereshkigal::App::Command modules, providing the shared
talk-to-the-manager plumbing.

Commands going through run_command exit with...

    0 - clean success
    1 - transport or server error, printed to STDERR
    2 - the command completed, but the result carries per-kur,
        per-IP, or per-CIDR failures

=head1 METHODS

=head2 client

Returns a new L<Ereshkigal::Client> for the socket named by the global
--socket option.

    my $client = $self->client;

=cut

sub client {
	my ($self) = @_;

	return Ereshkigal::Client->new( 'socket' => $self->app->global_options->{socket} );
}

=head2 run_command

Sends the command to the manager and prints the result to STDOUT as pretty
JSON, exiting per the codes above.

    $self->run_command( $command, $command_args );

=cut

sub run_command {
	my ( $self, $command, $command_args ) = @_;

	my $result;
	eval { $result = $self->client->call_ok( $command, defined($command_args) ? $command_args : () ); };
	if ($@) {
		my $error = $@;
		$error =~ s/\n*$//;
		print STDERR $error . "\n";
		exit 1;
	}

	print JSON::MaybeXS->new( 'pretty' => 1, 'canonical' => 1 )->encode($result);

	if ( _result_has_failures($result) ) {
		exit 2;
	}

	return;
} ## end sub run_command

# returns true if the result carries any partial failures... a rejected
# hash with entries, a kur that errored, or any per IP or per CIDR entry
# with a status of error, checking both the fanned out shape under kurs
# and the single kur shape with ips/cidrs at the top level
sub _result_has_failures {
	my ($result) = @_;

	return 0 if ref($result) ne 'HASH';

	if ( ref( $result->{rejected} ) eq 'HASH' && %{ $result->{rejected} } ) {
		return 1;
	}

	my @to_scan = ($result);
	if ( ref( $result->{kurs} ) eq 'HASH' ) {
		foreach my $kur_result ( values( %{ $result->{kurs} } ) ) {
			next     if ref($kur_result) ne 'HASH';
			return 1 if defined( $kur_result->{error} );
			push( @to_scan, $kur_result );
		}
	}

	foreach my $to_scan (@to_scan) {
		foreach my $entries_key ( 'ips', 'cidrs' ) {
			next if ref( $to_scan->{$entries_key} ) ne 'HASH';
			foreach my $entry ( values( %{ $to_scan->{$entries_key} } ) ) {
				if ( ref($entry) eq 'HASH' && defined( $entry->{status} ) && $entry->{status} eq 'error' ) {
					return 1;
				}
			}
		}
	} ## end foreach my $to_scan (@to_scan)

	return 0;
} ## end sub _result_has_failures

# App::Cmd wires up a help command but no --help flag, so every subcommand
# would answer "Unknown option: help" to the first thing most people reach
# for. This adds it once here rather than in each subcommand's opt_spec.
sub _option_processing_params {
	my ( $class, @args ) = @_;

	return ( $class->usage_desc(@args), $class->opt_spec(@args), [ 'help|h', 'show this help and exit' ] );
}

# handled here rather than in each validate_args so --help answers before
# any of them get to complain about missing args... "ban --help" should
# explain ban, not refuse for want of a IP
sub prepare {
	my ( $class, $app, @args ) = @_;

	my ( $self, $opt, @rest ) = $class->SUPER::prepare( $app, @args );

	if ( $opt->{help} ) {
		print $self->_help_text;
		exit 0;
	}

	return ( $self, $opt, @rest );
} ## end sub prepare

# the same shape the built in help command renders, so "ereshkigal help foo"
# and "ereshkigal foo --help" agree
sub _help_text {
	my ($self) = @_;

	my $description = $self->description;
	$description = "\n" . $description if ( length($description) );

	return join( "\n", $self->usage->leader_text, $description, $self->usage->option_text ) . "\n";
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
