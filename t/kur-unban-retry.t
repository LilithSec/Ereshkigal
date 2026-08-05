#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use lib 't/lib';
use EreshkigalTest qw( test_dir );

use Ereshkigal::Kur;

my $dir = test_dir();

my %common = (
	'backend'        => 'dummy',
	'ports'          => ['22'],
	'protocols'      => ['tcp'],
	'run_base_dir'   => $dir . '/run',
	'cache_base_dir' => $dir . '/cache',
);

# hide the Error::Helper warn noise
local *STDERR;
open( STDERR, '>', \my $stderr_capture );

# wrap _backend_do so unban failures can be forced and the methods that
# actually reach the backend recorded
my $fail_unban = 0;
my @backend_calls;
my $orig_backend_do = \&Ereshkigal::Kur::_backend_do;
{
	no warnings 'redefine';
	*Ereshkigal::Kur::_backend_do = sub {
		my ( $self, $method, @args ) = @_;
		push( @backend_calls, $method );
		if ( $fail_unban && ( $method eq 'unban' || $method eq 'unban_cidr' ) ) {
			die("unban forced to fail\n");
		}
		return $orig_backend_do->( $self, $method, @args );
	};
}

my $kur = Ereshkigal::Kur->new( %common, 'name' => 'testy', 'enable_cidr' => 1 );
$kur->{started} = time;

#
# a failed unban at expiry lands in the retry HoH and the ban still expires
#

$kur->_cmd_ban( { 'args' => { 'ips' => ['1.2.3.4'] } } );
$kur->{bans}{'1.2.3.4'}{expires} = time - 5;

$fail_unban = 1;
my $before = time;
$kur->_sweep_bans;

ok( !defined( $kur->{bans}{'1.2.3.4'} ), 'expired ban dropped from the book despite the unban failing' );
my $retry = $kur->{unban_retries}{'1.2.3.4'};
ok( defined($retry), 'failed unban tracked for retry' );
is( $retry->{times_tried}, 1, 'first try counted' );
ok( $retry->{first_tried} >= $before && $retry->{first_tried} <= time, 'first_tried recorded' );
is( $retry->{last_tried}, $retry->{first_tried}, 'last_tried matches first_tried on the first failure' );
ok( $retry->{next_try} > $retry->{last_tried}, 'next_try scheduled in the future' );
is( $retry->{delay}, 2, 'backoff doubled for the next failure' );

#
# a due retry that fails again backs off further
#

$retry->{next_try} = time - 1;
$before = time;
$kur->_sweep_bans;

is( $retry->{times_tried}, 2, 'second try counted' );
ok( $retry->{last_tried} >= $before && $retry->{last_tried} <= time, 'last_tried updated' );
ok( $retry->{next_try} >= $before + 2,                               'next_try honors the previous delay' );
is( $retry->{delay}, 4, 'backoff doubled again' );

#
# the backoff caps at 60
#

$retry->{next_try} = time - 1;
$retry->{delay}    = 40;
$kur->_sweep_bans;
is( $retry->{delay}, 60, 'backoff capped at 60' );
$retry->{next_try} = time - 1;
$kur->_sweep_bans;
is( $retry->{delay}, 60, 'backoff stays at the cap' );

#
# a due retry that succeeds clears the entry
#

$retry->{next_try} = time - 1;
$fail_unban = 0;
$kur->_sweep_bans;
ok( !defined( $kur->{unban_retries}{'1.2.3.4'} ), 'successful retry cleared' );

#
# re-banning something pending a retry cancels the retry with out asking the
# backend to re-add what it already carries
#

$kur->_cmd_ban( { 'args' => { 'ips' => ['5.6.7.8'] } } );
$kur->{bans}{'5.6.7.8'}{expires} = time - 5;
$fail_unban = 1;
$kur->_sweep_bans;
ok( defined( $kur->{unban_retries}{'5.6.7.8'} ), 'retry pending for the re-ban check' );

@backend_calls = ();
my $result = $kur->_cmd_ban( { 'args' => { 'ips' => ['5.6.7.8'] } } );
is( $result->{ips}{'5.6.7.8'}{status}, 'ok', 're-ban of a pending retry is ok' );
ok( !defined( $kur->{unban_retries}{'5.6.7.8'} ), 're-ban cancelled the pending retry' );
ok( defined( $kur->{bans}{'5.6.7.8'} ),           're-ban booked' );
ok( !grep { $_ eq 'ban' } @backend_calls,         'backend not asked to re-add what it already carries' );

#
# a hand unban while the backend is still refusing leaves the retry pending,
# as it fails against that same backend... it only clears once the backend
# takes it, which is what the retry loop is for
#

$kur->_cmd_ban( { 'args' => { 'ips' => ['4.4.4.4'] } } );
$kur->{bans}{'4.4.4.4'}{expires} = time - 5;
$fail_unban = 1;
$kur->_sweep_bans;
my $pending = $kur->{unban_retries}{'4.4.4.4'};
ok( defined($pending), 'retry pending for the hand unban check' );

my $tries_before = $pending->{times_tried};
eval { $kur->_cmd_unban( { 'args' => { 'ip' => '4.4.4.4' } } ) };
ok( $@, 'a hand unban fails while the backend is refusing' );
is( $kur->{unban_retries}{'4.4.4.4'}, $pending,      'the failed hand unban left the retry pending' );
is( $pending->{times_tried},          $tries_before, 'a failed hand unban does not disturb the retry book keeping' );

$fail_unban = 0;
$kur->_cmd_unban( { 'args' => { 'ip' => '4.4.4.4' } } );
ok( !defined( $kur->{unban_retries}{'4.4.4.4'} ), 'a hand unban clears the retry once the backend takes it' );

#
# the CIDR family retries the same way
#

$kur->_cmd_cidr_ban( { 'args' => { 'cidrs' => ['10.0.0.0/24'] } } );
$kur->{cidr_bans}{'10.0.0.0/24'}{expires} = time - 5;
$fail_unban = 1;
$kur->_sweep_bans;
ok( defined( $kur->{cidr_unban_retries}{'10.0.0.0/24'} ), 'failed CIDR unban tracked for retry' );
$kur->{cidr_unban_retries}{'10.0.0.0/24'}{next_try} = time - 1;
$fail_unban = 0;
$kur->_sweep_bans;
ok( !defined( $kur->{cidr_unban_retries}{'10.0.0.0/24'} ), 'successful CIDR retry cleared' );

#
# flush drops pending retries
#

$kur->_cmd_ban( { 'args' => { 'ips' => ['9.9.9.9'] } } );
$kur->{bans}{'9.9.9.9'}{expires} = time - 5;
$fail_unban = 1;
$kur->_sweep_bans;
ok( defined( $kur->{unban_retries}{'9.9.9.9'} ), 'retry pending for the flush check' );
$fail_unban = 0;
$kur->_cmd_flush;
ok( !defined( $kur->{unban_retries}{'9.9.9.9'} ), 'flush cleared the pending retry' );

done_testing;
