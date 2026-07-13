#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use App::Cmd::Tester;
use JSON::MaybeXS qw( decode_json );
use lib 't/lib';
use EreshkigalTest qw( test_dir socket_path_ok mock_server );

use Ereshkigal::App;

my $dir = test_dir();

# checks a invocation fails with a message matching the regex
sub usage_error_ok {
	my ( $argv, $regex, $test_name ) = @_;

	my $result = test_app( 'Ereshkigal::App' => $argv );
	isnt( $result->exit_code, 0, $test_name . '... nonzero exit' );
	my $combined = join( '', defined( $result->error ) ? $result->error : '', $result->stderr, $result->stdout );
	like( $combined, $regex, $test_name . '... message' );

	return;
} ## end sub usage_error_ok

#
# usage errors, no server needed
#

usage_error_ok( [ 'start',  'extra' ], qr/does not take any args/, 'start with stray args' );
usage_error_ok( [ 'stop',   'extra' ], qr/does not take any args/, 'stop with stray args' );
usage_error_ok( [ 'banned', 'extra' ], qr/does not take any args/, 'banned with stray args' );

usage_error_ok( [ 'status', 'a',     'b' ],    qr/at most one/,              'status with two args' );
usage_error_ok( [ 'status', '--all', 'sshd' ], qr/may not be used together/, 'status --all with a kur name' );

usage_error_ok( ['ban'], qr/at least one IP/, 'ban with no IPs' );

usage_error_ok( ['unban'], qr/either --all or a single IP/, 'unban with no args' );
usage_error_ok( [ 'unban', '--all',   '1.2.3.4' ], qr/may not be used together/,    'unban --all with a IP' );
usage_error_ok( [ 'unban', '1.2.3.4', '5.6.7.8' ], qr/either --all or a single IP/, 'unban with two IPs' );

usage_error_ok( ['add'],             qr/single kur instance name/, 'add with no name' );
usage_error_ok( [ 'add', 'a', 'b' ], qr/single kur instance name/, 'add with two names' );
usage_error_ok(
	[ 'add', 'sshd' ],
	qr/either --backend or --fan-out must be specified/,
	'add with out --backend or --fan-out'
);
usage_error_ok(
	[ 'add', 'gate', '--backend', 'dummy', '--fan-out', 'sshd' ],
	qr/may not be used together/,
	'add with both --backend and --fan-out'
);
usage_error_ok(
	[ 'add', 'sshd', '--backend', 'dummy', '--option', 'bad-format' ],
	qr/not in the form key=value/,
	'add with a malformed --option'
);

usage_error_ok( ['remove'], qr/single kur instance name/, 'remove with no name' );

usage_error_ok( [ 'checkpoint', 'a', 'b' ], qr/at most one/, 'checkpoint with two args' );

usage_error_ok( ['bogus'], qr/bogus/i, 'unknown subcommand' );

# -s reaches the client for every client command
foreach my $command ( 'stop', 'status', 'banned' ) {
	usage_error_ok( [ '-s', $dir . '/nothere.sock', $command ], qr/Failed to connect/, $command . ' honors -s' );
}
usage_error_ok( [ '-s', $dir . '/nothere.sock', 'ban',    '1.2.3.4' ], qr/Failed to connect/, 'ban honors -s' );
usage_error_ok( [ '-s', $dir . '/nothere.sock', 'unban',  '--all' ],   qr/Failed to connect/, 'unban honors -s' );
usage_error_ok( [ '-s', $dir . '/nothere.sock', 'remove', 'sshd' ],    qr/Failed to connect/, 'remove honors -s' );
usage_error_ok( [ '-s', $dir . '/nothere.sock', 'checkpoint' ], qr/Failed to connect/, 'checkpoint honors -s' );
usage_error_ok(
	[ '-s', $dir . '/nothere.sock', 'add', 'sshd', '--backend', 'dummy' ],
	qr/Failed to connect/,
	'add honors -s'
);

#
# happy paths against a mock manager
#

SKIP: {
	skip 'temp dir path too long for a unix socket', 29 if !socket_path_ok($dir);
	skip 'unix sockets and fork required',           29 if $^O eq 'MSWin32';

	my $socket = $dir . '/mock.sock';
	my $echo   = sub {
		my ($request) = @_;
		return { 'status' => 'ok', 'result' => { 'command' => $request->{command}, 'args' => $request->{args} } };
	};
	mock_server(
		$socket,
		{
			'status'     => { 'status' => 'ok', 'result' => { 'pid' => 42, 'uptime' => 1, 'kurs' => {} } },
			'status_all' => { 'status' => 'ok', 'result' => { 'all' => 1 } },
			'status_kur' => $echo,
			'banned'     => { 'status' => 'ok', 'result' => { 'kurs' => { 'sshd' => { 'banned' => [] } } } },
			'ban'        => $echo,
			'unban'      => $echo,
			'add_kur'    => $echo,
			'remove_kur' => { 'status' => 'error', 'error' => 'No such kur instance, "sshd"' },
			'checkpoint' => $echo,
			'stop'       => { 'status' => 'ok', 'result' => { 'stopping' => 1 } },
		}
	);

	my @s = ( '-s', $socket );

	my $result = test_app( 'Ereshkigal::App' => [ @s, 'status' ] );
	is( $result->exit_code, 0, 'status exit 0' );
	is_deeply(
		decode_json( $result->stdout ),
		{ 'pid' => 42, 'uptime' => 1, 'kurs' => {} },
		'status prints the result as JSON'
	);

	$result = test_app( 'Ereshkigal::App' => [ @s, 'status', '--all' ] );
	is_deeply( decode_json( $result->stdout ), { 'all' => 1 }, 'status --all calls status_all' );

	$result = test_app( 'Ereshkigal::App' => [ @s, 'status', 'sshd' ] );
	my $decoded = decode_json( $result->stdout );
	is( $decoded->{command},    'status_kur', 'status with a name calls status_kur' );
	is( $decoded->{args}{name}, 'sshd',       'status passes the name' );

	$result = test_app( 'Ereshkigal::App' => [ @s, 'banned' ] );
	is( $result->exit_code, 0, 'banned exit 0' );
	is_deeply(
		decode_json( $result->stdout ),
		{ 'kurs' => { 'sshd' => { 'banned' => [] } } },
		'banned prints the result'
	);

	$result  = test_app( 'Ereshkigal::App' => [ @s, 'ban', '1.2.3.4', '5.6.7.8' ] );
	$decoded = decode_json( $result->stdout );
	is( $decoded->{command}, 'ban', 'ban calls ban' );
	is_deeply( $decoded->{args}{ips}, [ '1.2.3.4', '5.6.7.8' ], 'ban passes the IPs' );
	ok( !defined( $decoded->{args}{kur} ), 'ban with out --kur sends no kur' );

	$result  = test_app( 'Ereshkigal::App' => [ @s, 'ban', '--kur', 'sshd', '1.2.3.4' ] );
	$decoded = decode_json( $result->stdout );
	is( $decoded->{args}{kur}, 'sshd', 'ban passes --kur' );

	$result  = test_app( 'Ereshkigal::App' => [ @s, 'ban', '--ban-time', '30', '1.2.3.4' ] );
	$decoded = decode_json( $result->stdout );
	is( $decoded->{args}{ban_time}, 30, 'ban passes --ban-time' );

	$result  = test_app( 'Ereshkigal::App' => [ @s, 'ban', '1.2.3.4' ] );
	$decoded = decode_json( $result->stdout );
	ok( !defined( $decoded->{args}{ban_time} ), 'ban with out --ban-time sends no ban_time' );

	$result  = test_app( 'Ereshkigal::App' => [ @s, 'unban', '1.2.3.4' ] );
	$decoded = decode_json( $result->stdout );
	is( $decoded->{args}{ip}, '1.2.3.4', 'unban passes the IP' );
	ok( !$decoded->{args}{all}, 'unban with a IP does not send all' );

	$result  = test_app( 'Ereshkigal::App' => [ @s, 'unban', '--all' ] );
	$decoded = decode_json( $result->stdout );
	is( $decoded->{args}{all}, 1, 'unban --all sends all' );

	$result = test_app(
		'Ereshkigal::App' => [
			@s,        'add',          'dns', '--backend', 'dummy', '--ports',
			'53,5353', '--protocols',  'udp', '--option',  'a=1',   '--option',
			'b=2',     '--self-heal',  '0',   '--prefix',  'foo',   '--ban-time',
			'300',     '--checkpoint', '30',
		]
	);
	$decoded = decode_json( $result->stdout );
	is( $decoded->{command},    'add_kur', 'add calls add_kur' );
	is( $decoded->{args}{name}, 'dns',     'add passes the name' );
	is_deeply(
		$decoded->{args}{opts},
		{
			'backend'    => 'dummy',
			'ports'      => [ '53', '5353' ],
			'protocols'  => ['udp'],
			'options'    => { 'a' => '1', 'b' => '2' },
			'self_heal'  => 0,
			'prefix'     => 'foo',
			'ban_time'   => 300,
			'checkpoint' => 30,
		},
		'add passes the full def through'
	);

	$result  = test_app( 'Ereshkigal::App' => [ @s, 'add', 'gate', '--fan-out', 'sshd,smtp' ] );
	$decoded = decode_json( $result->stdout );
	is( $decoded->{args}{name}, 'gate', 'add --fan-out passes the name' );
	is_deeply( $decoded->{args}{opts}, { 'fan_out' => [ 'sshd', 'smtp' ] }, 'add --fan-out passes the member list' );

	$result = test_app( 'Ereshkigal::App' => [ @s, 'remove', 'sshd' ] );
	isnt( $result->exit_code, 0, 'a error response exits nonzero' );
	my $combined = join( '', defined( $result->error ) ? $result->error : '', $result->stderr );
	like( $combined, qr/No such kur instance/, 'the error message is shown' );

	$result  = test_app( 'Ereshkigal::App' => [ @s, 'checkpoint' ] );
	$decoded = decode_json( $result->stdout );
	is( $decoded->{command}, 'checkpoint', 'checkpoint calls checkpoint' );
	ok( !defined( $decoded->{args} ), 'checkpoint with out a name sends no args' );

	$result  = test_app( 'Ereshkigal::App' => [ @s, 'checkpoint', 'sshd' ] );
	$decoded = decode_json( $result->stdout );
	is( $decoded->{args}{kur}, 'sshd', 'checkpoint passes the kur name' );

	$result = test_app( 'Ereshkigal::App' => [ @s, 'stop' ] );
	is( $result->exit_code, 0, 'stop exit 0' );
	is_deeply( decode_json( $result->stdout ), { 'stopping' => 1 }, 'stop prints the result' );
} ## end SKIP:

done_testing;
