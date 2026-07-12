#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use Test::Exception;
use lib 't/lib';
use EreshkigalTest qw( test_dir );

use Ereshkigal;

my $dir = test_dir();

my $config_count = 0;

sub write_cfg {
	my ($content) = @_;
	$config_count++;
	my $path = $dir . '/cfg' . $config_count . '.toml';
	open( my $fh, '>', $path ) || die($!);
	print $fh $content;
	close($fh);
	return $path;
}

# hide the Error::Helper warn noise
local *STDERR;
open( STDERR, '>', \my $stderr_capture );

#
# config error paths
#

throws_ok { Ereshkigal->new( 'config' => $dir . '/nothere.toml' ) } qr/Failed to open the config/,
	'dies on a missing config file';

throws_ok { Ereshkigal->new( 'config' => write_cfg('kur = [broken') ) } qr/Failed to parse the config/,
	'dies on invalid TOML';

throws_ok { Ereshkigal->new( 'config' => write_cfg('kur = "a string"') ) } qr/defined but not a hash/,
	'dies when kur is not a hash';

throws_ok {
	Ereshkigal->new( 'config' => write_cfg(qq([kur.sshd]\nports = [ "22" ]\n)) )
}
qr/lacks a backend/, 'dies when a kur def lacks a backend';

throws_ok {
	Ereshkigal->new( 'config' => write_cfg(qq([kur."bad.name"]\nbackend = "dummy"\n)) )
}
qr/does not match/, 'dies on a invalid kur name';

throws_ok {
	Ereshkigal->new( 'config' => write_cfg(qq(socket_group = "nosuchgroupzzz"\n)) )
}
qr/Failed to resolve the socket group/, 'dies on a unknown socket_group';

throws_ok {
	Ereshkigal->new( 'config' => write_cfg(qq(ban_time = "abc"\n)) )
}
qr/ban_time/, 'dies on a non-int top level ban_time';

throws_ok {
	Ereshkigal->new( 'config' => write_cfg(qq([kur.sshd]\nbackend  = "dummy"\nban_time = "abc"\n)) )
}
qr/ban_time for the kur/, 'dies on a non-int kur ban_time';

throws_ok {
	Ereshkigal->new( 'config' => write_cfg(qq(checkpoint = "abc"\n)) )
}
qr/checkpoint/, 'dies on a non-int top level checkpoint';

throws_ok {
	Ereshkigal->new( 'config' => write_cfg(qq([kur.sshd]\nbackend    = "dummy"\ncheckpoint = "abc"\n)) )
}
qr/checkpoint for the kur/, 'dies on a non-int kur checkpoint';

#
# defaults
#

# run_base_dir has to be set as new creates the run dirs, which will not
# work for the default of /var/run/ereshkigal when unprivileged
my $minimal
	= write_cfg( 'run_base_dir = "' . $dir . '/defrun"' . "\n" . qq([kur.sshd]\nbackend = "dummy"\n) );
my $ereshkigal;
lives_ok { $ereshkigal = Ereshkigal->new( 'config' => $minimal ) } 'new lives on a minimal config';
is( $ereshkigal->{socket_mode}, 0660,  'socket_mode defaults to 0660' );
is( $ereshkigal->{timeout},     30,    'timeout defaults to 30' );
is( $ereshkigal->{kur_bin},     'kur', 'kur_bin defaults to kur' );
is( $ereshkigal->{ban_time},    600,   'ban_time defaults to 600' );
is( $ereshkigal->{checkpoint},  60,    'checkpoint defaults to 60' );
is( $ereshkigal->{socket_gid}, ( getpwnam('root') )[3], 'socket_gid defaults to the default group of root' );
ok( -d $dir . '/defrun/kur', 'new created the run dirs' );

#
# settings merge and kur parsing
#

my $group = getgrgid( ( split( /\s+/, $( ) )[0] );

my $full = write_cfg( 'run_base_dir   = "' . $dir . '/run"' . "\n"
		. 'cache_base_dir = "' . $dir . '/cache"' . "\n"
		. 'socket_group   = "' . $group . '"' . "\n"
		. 'socket_mode    = "0640"' . "\n"
		. 'kur_bin        = "/somewhere/kur"' . "\n"
		. 'timeout        = 5' . "\n"
		. 'ban_time       = 120' . "\n"
		. 'checkpoint     = 90' . "\n\n"
		. '[kur.sshd]' . "\n"
		. 'backend   = "dummy"' . "\n"
		. 'ports     = [ "22", "80" ]' . "\n"
		. 'protocols = [ "tcp" ]' . "\n"
		. 'prefix    = "foo"' . "\n"
		. 'self_heal = 1' . "\n\n"
		. '[kur.sshd.options]' . "\n"
		. 'b = "2"' . "\n"
		. 'a = "1"' . "\n\n"
		. '[kur.smtp]' . "\n"
		. 'backend    = "dummy"' . "\n"
		. 'ban_time   = 30' . "\n"
		. 'checkpoint = 15' . "\n"
		. 'ports      = [ "25" ]' . "\n" );

lives_ok { $ereshkigal = Ereshkigal->new( 'config' => $full ) } 'new lives on a full config';
is( $ereshkigal->{run_base_dir},   $dir . '/run',    'run_base_dir merged' );
is( $ereshkigal->{cache_base_dir}, $dir . '/cache',  'cache_base_dir merged' );
is( $ereshkigal->{kur_bin},        '/somewhere/kur', 'kur_bin merged' );
is( $ereshkigal->{timeout},        5,                'timeout merged' );
is( $ereshkigal->{ban_time},       120,              'ban_time merged' );
is( $ereshkigal->{checkpoint},     90,               'checkpoint merged' );
is( $ereshkigal->{socket_mode},    0640,             'socket_mode processed via oct' );
is( $ereshkigal->{socket_gid}, ( split( /\s+/, $( ) )[0], 'socket_group resolved to our GID' );

is( scalar( keys( %{ $ereshkigal->{kurs} } ) ), 2, 'both kur instances parsed' );
foreach my $name ( 'sshd', 'smtp' ) {
	my $entry = $ereshkigal->{kurs}{$name};
	ok( defined($entry), 'kur "' . $name . '" registered' );
	is( $entry->{enabled},  1, $name . ' enabled' );
	is( $entry->{restarts}, 0, $name . ' restarts 0' );
	is( $entry->{delay},    1, $name . ' delay 1' );
}

is( $ereshkigal->socket_path, $dir . '/run/socket', 'socket_path' );
is( $ereshkigal->pid_path,    $dir . '/run/pid',    'pid_path' );
is( $ereshkigal->kur_socket_path('sshd'), $dir . '/run/kur/sshd.sock', 'kur_socket_path' );

#
# _build_kur_cmd
#

my @cmd     = $ereshkigal->_build_kur_cmd('sshd');
my $cmd_str = join( ' ', @cmd );
is( $cmd[0], '/somewhere/kur', 'cmd starts with kur_bin' );
like( $cmd_str, qr/--foreground/,                       'cmd has --foreground' );
like( $cmd_str, qr/--name sshd/,                        'cmd has --name' );
like( $cmd_str, qr/--backend dummy/,                    'cmd has --backend' );
like( $cmd_str, qr/--ports 22,80/,                      'cmd joins ports' );
like( $cmd_str, qr/--protocols tcp/,                    'cmd has protocols' );
like( $cmd_str, qr/--prefix foo/,                       'cmd has prefix' );
like( $cmd_str, qr/--self-heal 1/,                      'cmd has self-heal' );
like( $cmd_str, qr/--option a=1 --option b=2/,          'cmd has sorted options' );
like( $cmd_str, qr/--ban-time 120/,                     'cmd has the manager wide ban_time' );
like( $cmd_str, qr/--checkpoint 90/,                    'cmd has the manager wide checkpoint' );
like( $cmd_str, qr/--run \Q$dir\E\/run/,                'cmd has the run dir' );
like( $cmd_str, qr/--cache \Q$dir\E\/cache/,            'cmd has the cache dir' );

@cmd     = $ereshkigal->_build_kur_cmd('smtp');
$cmd_str = join( ' ', @cmd );
unlike( $cmd_str, qr/--prefix|--self-heal|--option|--protocols/, 'unset options not passed for smtp' );
like( $cmd_str, qr/--ban-time 30/,   'the kur ban_time overrides the manager wide one' );
like( $cmd_str, qr/--checkpoint 15/, 'the kur checkpoint overrides the manager wide one' );

done_testing;
