#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use Test::Exception;
use lib 't/lib';
use EreshkigalTest qw( test_dir socket_path_ok mock_server );

use Ereshkigal::Client;

my $dir = test_dir();
if ( !socket_path_ok($dir) ) {
	plan skip_all => 'temp dir path too long for a unix socket... set TMPDIR to something shorter';
}

my $socket = $dir . '/mock.sock';
mock_server(
	$socket,
	{
		'ping' => { 'status' => 'ok', 'result' => { 'pong' => 1 } },
		'echo' => sub {
			my ($request) = @_;
			return { 'status' => 'ok', 'result' => { 'args' => $request->{args} } };
		},
		'bad'      => { 'status' => 'error', 'error' => 'nope' },
		'garbage'  => 'this is not json',
		'arrayish' => sub { return [ 1, 2, 3 ]; },
		'sleepy'   => { '__no_reply__' => 1 },
	}
);

#
# new
#

throws_ok { Ereshkigal::Client->new } qr/No socket specified/, 'new dies with out a socket';

my $client = Ereshkigal::Client->new( 'socket' => $socket );
is( $client->{timeout}, 30, 'timeout defaults to 30' );
is( Ereshkigal::Client->new( 'socket' => $socket, 'timeout' => 5 )->{timeout}, 5, 'timeout override honored' );

#
# call / call_ok
#

my $response = $client->call('ping');
is( $response->{status},       'ok', 'call returns the response hash' );
is( $response->{result}{pong}, 1,    'call result decoded' );

$response = $client->call( 'echo', { 'foo' => 'bar' } );
is_deeply( $response->{result}{args}, { 'foo' => 'bar' }, 'args sent through verbatim' );

is_deeply( $client->call_ok('ping'), { 'pong' => 1 }, 'call_ok returns just the result' );

eval { $client->call_ok('bad'); };
is( $@, "nope\n", 'call_ok dies with the error text and a trailing newline' );

$response = $client->call('nosuchcommand');
is( $response->{status}, 'error', 'a error response comes back as a plain hash from call' );

#
# failure modes
#

throws_ok { Ereshkigal::Client->new( 'socket' => $dir . '/nothere.sock' )->call('ping') }
qr/Failed to connect/, 'connect to a nonexistent socket dies';

throws_ok { $client->call('garbage') } qr/./, 'undecodable response dies';

throws_ok { $client->call('arrayish') } qr/not a JSON object/, 'non-object JSON response dies';

throws_ok { $client->call(undef) } qr/No command specified/, 'undef command dies';

#
# the transparent auth challenge retry
#

my $auth_socket = $dir . '/auth.sock';
my $cookie_dir  = $dir . '/cookies';
mkdir($cookie_dir) || die($!);
my $cookie = 'deadbeefcafe1234';
mock_server(
	$auth_socket,
	{
		'auth_start' => sub {
			return { 'status' => 'ok', 'result' => { 'cookie' => $cookie, 'temp_dir' => $cookie_dir } };
		},
		'auth_verify' => sub {
			my ( $request, $state ) = @_;
			my $path = $request->{args}{path};
			if ( !defined($path) || !-f $path ) {
				return { 'status' => 'error', 'error' => 'no such cookie file' };
			}
			open( my $fh, '<', $path ) || die($!);
			my $got = <$fh>;
			close($fh);
			if ( $got ne $cookie ) {
				return { 'status' => 'error', 'error' => 'cookie mismatch' };
			}
			$state->{authed} = 1;
			return { 'status' => 'ok', 'result' => { 'uid' => $>, 'username' => 'testuser' } };
		},
		'secured' => sub {
			my ( $request, $state ) = @_;
			if ( !$state->{authed} ) {
				return {
					'status' => 'error',
					'error'  => 'authentication required: call auth_start then auth_verify first'
				};
			}
			return { 'status' => 'ok', 'result' => { 'secret' => 42 } };
		},
	}
);

my $auth_client = Ereshkigal::Client->new( 'socket' => $auth_socket );
is_deeply( $auth_client->call_ok('secured'), { 'secret' => 42 },
	'the challenge is completed transparently and the command resent' );
opendir( my $cookie_dh, $cookie_dir ) || die($!);
my @leftover = grep { $_ ne '.' && $_ ne '..' } readdir($cookie_dh);
closedir($cookie_dh);
is_deeply( \@leftover, [], 'the cookie file was cleaned up' );

# a server rejecting the challenge surfaces as a die rather than a retry loop
my $bad_socket = $dir . '/bad-auth.sock';
mock_server(
	$bad_socket,
	{
		'auth_start' => sub {
			return { 'status' => 'ok', 'result' => { 'cookie' => 'right', 'temp_dir' => $cookie_dir } };
		},
		'auth_verify' => sub {
			return { 'status' => 'error', 'error' => 'cookie mismatch' };
		},
		'secured' => sub {
			return {
				'status' => 'error',
				'error'  => 'authentication required: call auth_start then auth_verify first'
			};
		},
	}
);
throws_ok { Ereshkigal::Client->new( 'socket' => $bad_socket )->call('secured') }
qr/auth_verify failed.*cookie mismatch/, 'a rejected challenge dies';
opendir( $cookie_dh, $cookie_dir ) || die($!);
@leftover = grep { $_ ne '.' && $_ ne '..' } readdir($cookie_dh);
closedir($cookie_dh);
is_deeply( \@leftover, [], 'the cookie file was cleaned up after the rejection too' );

# this one last as the mock will be stuck sleeping afterwards
throws_ok { Ereshkigal::Client->new( 'socket' => $socket, 'timeout' => 1 )->call('sleepy') }
qr/timed out/, 'times out when the server never replies';

done_testing;
