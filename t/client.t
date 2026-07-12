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

# this one last as the mock will be stuck sleeping afterwards
throws_ok { Ereshkigal::Client->new( 'socket' => $socket, 'timeout' => 1 )->call('sleepy') }
qr/timed out/, 'times out when the server never replies';

done_testing;
