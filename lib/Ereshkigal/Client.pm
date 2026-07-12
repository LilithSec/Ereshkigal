package Ereshkigal::Client;

use 5.006;
use strict;
use warnings;
use IO::Socket::UNIX ();
use JSON::MaybeXS    qw( encode_json decode_json );

=head1 NAME

Ereshkigal::Client - Small blocking JSON over unix socket client for Ereshkigal.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Ereshkigal::Client;

    my $client = Ereshkigal::Client->new( socket => '/var/run/ereshkigal/socket' );

    # returns the raw response hash, {status=>..., ...}
    my $response = $client->call( 'status' );

    # dies unless status is ok, returning the result
    my $result = $client->call_ok( 'ban', { ips => ['1.2.3.4'] } );

=head1 DESCRIPTION

Connects to a unix socket speaking the newline delimited JSON protocol of
L<POE::Component::Server::JSONUnix>, sends a single request, and reads back
the response. Used by the C<ereshkigal> CLI for talking to the manager and by
the manager for talking to kur instances.

=head1 METHODS

=head2 new

Initiates the object. Will die on errors.

    - socket :: Path of the unix socket to connect to. Must be specified.
        Default :: undef

    - timeout :: Timeout in seconds for a call.
        Default :: 30

=cut

sub new {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{socket} ) ) {
		die('No socket specified');
	}

	my $self = {
		socket  => $opts{socket},
		timeout => defined( $opts{timeout} ) ? $opts{timeout} : 30,
	};
	bless $self;

	return $self;
} ## end sub new

=head2 call

Sends a single request and returns the decoded response hash. Will die on
connect failure, timeout, or a undecodable response.

    my $response = $client->call( $command, $args );

C<$args>, if defined, is sent as the args value of the request.

=cut

sub call {
	my ( $self, $command, $args ) = @_;

	if ( !defined($command) ) {
		die('No command specified');
	}

	my $response;
	eval {
		local $SIG{ALRM} = sub { die( 'timed out after ' . $self->{timeout} . " seconds\n" ); };
		alarm( $self->{timeout} );

		my $sock = IO::Socket::UNIX->new(
			'Type' => IO::Socket::UNIX::SOCK_STREAM(),
			'Peer' => $self->{socket},
		) || die( 'Failed to connect to "' . $self->{socket} . '"... ' . $! );

		my $request = { 'command' => $command };
		if ( defined($args) ) {
			$request->{args} = $args;
		}

		print $sock encode_json($request) . "\n";

		my $line = <$sock>;
		close($sock);
		alarm(0);

		if ( !defined($line) ) {
			die( 'No response read from "' . $self->{socket} . '"' );
		}

		$response = decode_json($line);
	};
	my $call_error = $@;
	alarm(0);
	if ($call_error) {
		die($call_error);
	}

	if ( ref($response) ne 'HASH' ) {
		die('Response is not a JSON object');
	}

	return $response;
} ## end sub call

=head2 call_ok

Like L</call>, but dies if the response status is not ok, and returns the
result value of the response instead of the whole response.

    my $result = $client->call_ok( $command, $args );

=cut

sub call_ok {
	my ( $self, $command, $args ) = @_;

	my $response = $self->call( $command, $args );

	if ( !defined( $response->{status} ) || $response->{status} ne 'ok' ) {
		my $error = defined( $response->{error} ) ? $response->{error} : 'unknown error';
		$error .= "\n" if $error !~ /\n$/;
		die($error);
	}

	return $response->{result};
} ## end sub call_ok

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
