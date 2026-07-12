package Ereshkigal::Client;

use 5.006;
use strict;
use warnings;
use IO::Socket::UNIX ();
use File::Temp       ();
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

If the server answers with the L<POE::Component::Server::JSONUnix>
authentication required error, the unix ownership challenge is completed
transparently on the same connection and the request is resent, so no
special handling is needed for talking to a manager with enable_auth on.
The timeout wraps the whole exchange.

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

		$response = $self->_send_request( $sock, $request );

		# auth state is per connection, so complete the ownership challenge
		# on this same connection and resend
		if (   defined( $response->{status} )
			&& $response->{status} eq 'error'
			&& defined( $response->{error} )
			&& $response->{error} =~ /^authentication required/ )
		{
			$self->_authenticate($sock);
			$response = $self->_send_request( $sock, $request );
		}

		close($sock);
		alarm(0);
	};
	my $call_error = $@;
	alarm(0);
	if ($call_error) {
		die($call_error);
	}

	return $response;
} ## end sub call

# sends a single request on the socket and returns the decoded response
sub _send_request {
	my ( $self, $sock, $request ) = @_;

	print $sock encode_json($request) . "\n";

	my $line = <$sock>;
	if ( !defined($line) ) {
		die( 'No response read from "' . $self->{socket} . '"' );
	}

	my $response = decode_json($line);
	if ( ref($response) ne 'HASH' ) {
		die('Response is not a JSON object');
	}

	return $response;
} ## end sub _send_request

# completes the POE::Component::Server::JSONUnix unix ownership challenge on
# the passed connection... auth_start hands back a cookie and a temp dir, the
# cookie gets written to a file there owned by us, which is what proves the
# identity, and auth_verify is pointed at it
sub _authenticate {
	my ( $self, $sock ) = @_;

	my $start = $self->_send_request( $sock, { 'command' => 'auth_start' } );
	if ( !defined( $start->{status} ) || $start->{status} ne 'ok' ) {
		die( 'auth_start failed... ' . ( defined( $start->{error} ) ? $start->{error} : 'unknown error' ) );
	}
	my $cookie   = $start->{result}{cookie};
	my $temp_dir = $start->{result}{temp_dir};
	if ( !defined($cookie) || !defined($temp_dir) ) {
		die('auth_start did not return a cookie and temp_dir');
	}

	my ( $cookie_fh, $cookie_file )
		= File::Temp::tempfile( 'ereshkigal-auth-XXXXXXXX', 'DIR' => $temp_dir, 'UNLINK' => 0 );
	print $cookie_fh $cookie;
	close($cookie_fh);

	my $verify;
	eval {
		$verify
			= $self->_send_request( $sock, { 'command' => 'auth_verify', 'args' => { 'path' => $cookie_file } } );
	};
	my $verify_error = $@;
	# the server removes it on success, but make sure it is gone either way
	unlink($cookie_file) if -e $cookie_file;
	if ($verify_error) {
		die($verify_error);
	}
	if ( !defined( $verify->{status} ) || $verify->{status} ne 'ok' ) {
		die( 'auth_verify failed... ' . ( defined( $verify->{error} ) ? $verify->{error} : 'unknown error' ) );
	}

	return;
} ## end sub _authenticate

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
