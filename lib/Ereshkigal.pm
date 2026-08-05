package Ereshkigal;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use FindBin                          ();
use POE                              qw( Wheel::Run );
use POE::Component::Server::JSONUnix ();
use TOML::Tiny                       qw( from_toml );
use Ereshkigal::Client               ();
use Ereshkigal::IP                   qw( normalize_ip normalize_cidr );
use Ereshkigal::LogDrek              qw( log_drek );

=head1 NAME

Ereshkigal - Handle firewall or similar bans.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Ereshkigal;

    my $ereshkigal = Ereshkigal->new( config => '/usr/local/etc/ereshkigal.toml' );

    $ereshkigal->start_server;

Ereshkigal is a ban manager for firewalls. It wrangles various
L<Ereshkigal::Kur> instances, spawned via the C<kur> bin, each of which runs
as it's own process and uses L<Net::Firewall::BlockerHelper> for talking to
the firewall.

The manager listens on a unix socket, by default
C</var/run/ereshkigal/socket>, speaking the newline delimited JSON protocol
of L<POE::Component::Server::JSONUnix>, and proxies per instance work to the
kur sockets under C</var/run/ereshkigal/kur/>.

=head1 CONFIG FILE

The config file is TOML. Hashes under C<kur> define instances. The instance
name is the hash name, so the hash at C<kur.sshd> is the kur instance
C<sshd>. Keys inside are what kur/L<Net::Firewall::BlockerHelper> take...
C<backend>, C<ports>, C<protocols>, C<prefix>, C<self_heal>, and the backend
specific C<options> table.

Top level keys are manager settings.

    - socket_group :: Group ownership of the manager socket.
        Default :: the default group of the root user

    - socket_mode :: Perms for the manager socket. Processed via oct, so
          should be specified as a string such as "0660". Kur sockets are
          always 0600 and not configurable.
        Default :: 0660

    - run_base_dir :: Base dir for run files.
        Default :: /var/run/ereshkigal

    - cache_base_dir :: Base dir for cache files, passed to kur.
        Default :: /var/cache/ereshkigal

    - kur_bin :: The kur bin to spawn instances with.
        Default :: kur

    - timeout :: Timeout in seconds used when talking to kur sockets. For
          commands touching multiple kurs this bounds the whole fan out
          rather than each kur individually.
        Default :: 30

    - ban_time :: How long bans should last in seconds. 0 means bans never
          time out. May be overridden per kur via ban_time in it's hash and
          per ban request.
        Default :: 600

    - checkpoint :: Seconds between periodic rewrites of each kur's ban
          state CSV. 0 disables the periodic rewrite... ban/unban, stop,
          and on demand checkpoints still happen. May be overridden per kur
          via checkpoint in it's hash.
        Default :: 60

    - enable_cidr :: Whether CIDR banning is enabled. May be overridden per
          kur via enable_cidr in it's hash. Even when set, the cidr_ban and
          cidr_unban commands only work on a kur whose backend supports CIDR
          bans.
        Default :: false

    - cidr_silent_drop :: How a kur handles a CIDR command when CIDR banning
          is not available for it, either because enable_cidr is off or the
          backend can not do CIDR. When set such a kur silently drops the
          command rather than erroring, which keeps a fan out across a mix of
          CIDR capable and incapable kurs from being spoiled by the incapable
          ones. May be overridden per kur via cidr_silent_drop in it's hash.
        Default :: false

    - enable_auth :: Enables the L<POE::Component::Server::JSONUnix>
          auth_required cookie file ownership challenge on the manager
          socket, along with authorization via authed_users/authed_groups.
        Default :: 0

    - authed_users :: A array of users with global access.
        Default :: []

    - authed_groups :: A array of groups with global access.
        Default :: []

    - auth_temp_dir :: Dir used for the ownership challenge cookie files,
          passed through to L<POE::Component::Server::JSONUnix>.
        Default :: undef

A kur hash may instead carry C<fan_out>, a array of other kur names, in
place of C<backend>. Such a kur is manager side only... no process and no
socket of it's own. Commands targeted at it (C<ban> with args.kur,
C<checkpoint> with args.kur, C<status_kur>) fan out to it's members
instead, making it usable as a single point of contact for driving a whole
set of kurs. With enable_auth on, authorization for a command targeted at
a fan_out kur is checked against the fan_out kur's own lists rather than
it's members', so a integration may be granted just the gateway with out
being listed on any member. Members must be defined non fan_out kurs...
fan_out kurs may not nest. Untargeted commands (C<ban> with out args.kur,
C<unban>, C<banned>, C<checkpoint> with out args.kur) touch only real
kurs, never fan_out ones.

    [kur.baphomet]
    fan_out      = [ "sshd", "smtp" ]
    authed_users = [ "baphomet" ]

Each kur hash may also carry it's own C<authed_users>/C<authed_groups>,
which expand upon the global ones for that kur... the effective lists for
a kur are the global ones plus it's own. A command must be authorized for
every kur it touches, with untargeted fan-out commands touching every kur,
while commands about the manager it's self (stop, add_kur, remove_kur, and
the whole manager views status/status_all) require the global lists. UID 0
is always authorized. The kur backends do no checking at all... their
sockets are 0600 and only ereshkigal is expected to be able to write to
them, so enforcement is entirely the manager's responsibility.

A refused command comes back as a normal JSONUnix error response carrying
a machine-readable C<code>, C<permission_denied> for a authorization
refusal, matching the C<code> field convention of
L<POE::Component::Server::JSONUnix>'s own permission and auth errors, so a
consumer may branch on the code rather than matching the message text.

Example...

    socket_group = "wheel"
    socket_mode  = "0660"

    [kur.sshd]
    backend   = "ipfw"
    ports     = [ "22" ]
    protocols = [ "tcp" ]

=head1 METHODS

=head2 new

Initiates the object. All errors are considered fatal, meaning if new fails
it will die.

    - config :: Path to the TOML config file.
        Default :: /usr/local/etc/ereshkigal.toml

=cut

sub new {
	my ( $blank, %opts ) = @_;

	my $self = {
		perror        => undef,
		error         => undef,
		errorLine     => undef,
		errorFilename => undef,
		errorString   => "",
		errorExtra    => {
			all_errors_fatal => 1,
			all_fatal        => 1,
			flags            => {
				1 => 'configReadFailed',
				2 => 'configParseFailed',
				3 => 'invalidKurDef',
				4 => 'runBaseDirError',
				5 => 'badSocketGroup',
				6 => 'invalidBanTime',
				7 => 'invalidCheckpoint',
				8 => 'invalidAuthedList',
			},
			fatal_flags      => {},
			perror_not_fatal => 0,
		},
		config           => '/usr/local/etc/ereshkigal.toml',
		run_base_dir     => '/var/run/ereshkigal',
		cache_base_dir   => '/var/cache/ereshkigal',
		kur_bin          => 'kur',
		timeout          => 30,
		ban_time         => 600,
		checkpoint       => 60,
		enable_cidr      => 0,
		cidr_silent_drop => 0,
		enable_auth      => 0,
		authed_users     => [],
		authed_groups    => [],
		auth_temp_dir    => undef,
		socket_group     => undef,
		socket_mode      => oct('0660'),
		kurs             => {},
		wheel_to_kur     => {},
		pid_to_kur       => {},
		shutting_down    => 0,
		started          => undef,
		server           => undef,
	};
	bless $self;

	if ( defined( $opts{config} ) ) {
		$self->{config} = $opts{config};
	}

	my $raw_config;
	{
		local $/ = undef;
		my $fh;
		if ( !open( $fh, '<', $self->{config} ) ) {
			$self->{perror}      = 1;
			$self->{error}       = 1;
			$self->{errorString} = 'Failed to open the config, "' . $self->{config} . '"... ' . $!;
			$self->warn;
		}
		$raw_config = <$fh>;
		close($fh);
	}

	my ( $config, $parse_error ) = from_toml($raw_config);
	if ( !defined($config) || ref($config) ne 'HASH' ) {
		$self->{perror} = 1;
		$self->{error}  = 2;
		$self->{errorString}
			= 'Failed to parse the config, "'
			. $self->{config} . '"... '
			. ( defined($parse_error) ? $parse_error : 'parsing did not return a hash' );
		$self->warn;
	}

	my @settings_to_merge = (
		'run_base_dir', 'cache_base_dir', 'kur_bin',     'timeout',
		'ban_time',     'checkpoint',     'enable_cidr', 'cidr_silent_drop',
		'enable_auth',  'auth_temp_dir',  'socket_group'
	);
	foreach my $item (@settings_to_merge) {
		if ( defined( $config->{$item} ) ) {
			$self->{$item} = $config->{$item};
		}
	}
	if ( defined( $config->{socket_mode} ) ) {
		# vetted before oct is trusted with it, as oct hands back 0 for
		# anything unparseable, which would leave the socket unusable by
		# everyone rather than erroring
		if ( '' . $config->{socket_mode} !~ /^0[0-7]{1,4}$/ ) {
			$self->{perror} = 1;
			$self->{error}  = 2;
			$self->{errorString}
				= 'socket_mode, "' . $config->{socket_mode} . '", is not a octal mode string such as "0660"';
			$self->warn;
		}
		$self->{socket_mode} = oct( '' . $config->{socket_mode} );
	} ## end if ( defined( $config->{socket_mode} ) )

	# A bare kur_bin (no path separator) is resolved against the directory
	# ereshkigal was invoked from, since kur is installed alongside it. This
	# avoids relying on $PATH, which is stripped down under service managers
	# such as FreeBSD's rc.subr (no /usr/local/bin) and would otherwise make
	# exec of the kur bin fail with "No such file or directory".
	if ( $self->{kur_bin} !~ m{/} ) {
		my $sibling = $FindBin::RealBin . '/' . $self->{kur_bin};
		if ( -x $sibling ) {
			$self->{kur_bin} = $sibling;
		}
	}

	if ( $self->{ban_time} !~ /^[0-9]+$/ ) {
		$self->{perror}      = 1;
		$self->{error}       = 6;
		$self->{errorString} = 'ban_time, "' . $self->{ban_time} . '", is not a non-negative int of seconds';
		$self->warn;
	}

	if ( $self->{checkpoint} !~ /^[0-9]+$/ ) {
		$self->{perror}      = 1;
		$self->{error}       = 7;
		$self->{errorString} = 'checkpoint, "' . $self->{checkpoint} . '", is not a non-negative int of seconds';
		$self->warn;
	}

	foreach my $item ( 'authed_users', 'authed_groups' ) {
		if ( defined( $config->{$item} ) ) {
			my $list_error = _authed_list_error( $config->{$item} );
			if ( defined($list_error) ) {
				$self->{perror}      = 1;
				$self->{error}       = 8;
				$self->{errorString} = $item . ' is ' . $list_error;
				$self->warn;
			}
			$self->{$item} = $config->{$item};
		} ## end if ( defined( $config->{$item} ) )
	} ## end foreach my $item ( 'authed_users', 'authed_groups')

	# default to the default group of the root user... wheel on the BSDs, root on Linux
	if ( !defined( $self->{socket_group} ) ) {
		$self->{socket_gid} = ( getpwnam('root') )[3];
	} else {
		$self->{socket_gid} = getgrnam( $self->{socket_group} );
	}
	if ( !defined( $self->{socket_gid} ) ) {
		$self->{perror} = 1;
		$self->{error}  = 5;
		$self->{errorString}
			= 'Failed to resolve the socket group'
			. ( defined( $self->{socket_group} ) ? ', "' . $self->{socket_group} . '",' : ' for the root user' )
			. ' to a GID';
		$self->warn;
	}

	if ( defined( $config->{kur} ) && ref( $config->{kur} ) ne 'HASH' ) {
		$self->{perror}      = 1;
		$self->{error}       = 3;
		$self->{errorString} = 'kur in the config is defined but not a hash';
		$self->warn;
	}
	if ( defined( $config->{kur} ) ) {
		foreach my $name ( keys( %{ $config->{kur} } ) ) {
			my $def = $config->{kur}{$name};
			$self->_check_kur_def( $name, $def, 1 );
			$self->{kurs}{$name} = {
				'opts'     => $def,
				'wheel'    => undef,
				'pid'      => undef,
				'restarts' => 0,
				'delay'    => 1,
				'enabled'  => 1,
				'spawned'  => undef,
			};
		} ## end foreach my $name ( keys( %{ $config->{kur} } ) )
		# member validation has to wait till every kur is registered
		foreach my $name ( keys( %{ $config->{kur} } ) ) {
			if ( defined( $config->{kur}{$name}{fan_out} ) ) {
				$self->_check_fan_out_members( $name, $config->{kur}{$name}, 1 );
			}
		}
	} ## end if ( defined( $config->{kur} ) )

	# create these here rather than in start_server as the PID file gets
	# written prior to start_server being called
	foreach my $dir ( $self->{run_base_dir}, $self->{run_base_dir} . '/kur' ) {
		if ( !-e $dir ) {
			# don't need to check if this worked failed or not here as the next if statement will handle that
			eval { mkdir($dir); };
		}
		if ( !-d $dir || !-r $dir || !-w $dir ) {
			$self->{perror}      = 1;
			$self->{error}       = 4;
			$self->{errorString} = 'The dir "' . $dir . '" is not a directory or is not read/writable';
			$self->warn;
		}
	} ## end foreach my $dir ( $self->{run_base_dir}, $self->...)

	return $self;
} ## end sub new

=head2 socket_path

Returns the path of the manager unix socket.

    my $socket_path = $ereshkigal->socket_path;

=cut

sub socket_path {
	my ($self) = @_;

	return $self->{run_base_dir} . '/socket';
}

=head2 pid_path

Returns the path of the manager PID file.

    my $pid_path = $ereshkigal->pid_path;

=cut

sub pid_path {
	my ($self) = @_;

	return $self->{run_base_dir} . '/pid';
}

=head2 kur_socket_path

Returns the path of the unix socket for the specified kur instance.

    my $kur_socket_path = $ereshkigal->kur_socket_path($name);

=cut

sub kur_socket_path {
	my ( $self, $name ) = @_;

	return $self->{run_base_dir} . '/kur/' . $name . '.sock';
}

=head2 start_server

Starts the manager. Spawns all configured kur instances, each supervised and
restarted with a backoff should it die, and brings up the
L<POE::Component::Server::JSONUnix> server on the manager socket, then calls
$poe_kernel->run.

This should not be expected to return till the manager is told to stop.

After binding, the manager socket is chowned to the configured group and
chmoded to the configured mode.

The JSON commands handled are as below.

    - status :: Manager status... uptime and kur list with up/down state.

    - status_all :: The above plus each kur's full status block.

    - status_kur :: Full status of the kur instance args.name. For a
          fan_out kur this is it's member list plus each member's status.

    - banned :: Banned IPs, grouped per kur, along with when each expires.

    - ban :: Ban the IPs args.ips on the kur args.kur, or on all kurs if
          args.kur is not specified. If args.kur is a fan_out kur it expands
          to it's members. args.ban_time, if defined, is forwarded
          to the kurs, overriding their default for how long the bans should
          last in seconds, with 0 meaning never time out. IPs are validated
          and normalized to their canonical form before being fanned out,
          with anything failing to validate reported back per IP under
          rejected rather than being sent to the kurs. If nothing validates
          the request as a whole errors.

    - unban :: If args.all is true, flush every kur. Otherwise validate and
          normalize args.ip, erroring if it fails to validate, then check
          each kur for it and unban it from each kur it is present on.

    - cidr_ban :: Ban the CIDR ranges args.cidrs, otherwise behaving like
          ban including the args.kur targeting and args.ban_time forwarding.
          CIDRs are validated and reduced to their canonical network form
          before being fanned out. A targeted kur, or a untargeted fan out,
          for which CIDR is not available answers per kur with either a drop
          or a error depending on it's cidr_silent_drop.

    - cidr_unban :: Validate and normalize args.cidr, erroring if it fails to
          validate, then check each kur for it and unban it from each kur it
          is present on. There is no all form... unban with args.all already
          flushes CIDR bans alongside single IP bans.

    - add_kur :: Define and start a new kur instance, args.name and
          args.opts. Does not rewrite the config file.

    - remove_kur :: Stop the kur instance args.name and deregister it. Does
          not rewrite the config file.

    - checkpoint :: Force the kur args.kur, or all kurs if args.kur is not
          specified, to write their ban state CSVs out now. If args.kur is a
          fan_out kur it expands to it's members.

    - re_init :: Have the kur args.kur, or all kurs if args.kur is not
          specified, tear their firewall setup down and rebuild it, re-banning
          everything their ban book carries. Expands a fan_out kur the same
          way checkpoint does. Bans are briefly not enforced while the setup
          is being rebuilt.

    - clear_retries :: Have the kur args.kur, or all kurs if args.kur is not
          specified, forget unbans still owed to the firewall. args.ip or
          args.cidr, at most one of them, names a single owed unban to
          forget rather than the lot. Expands a fan_out kur the same way
          checkpoint does. Nothing is asked of the firewall, so anything
          genuinely still banished there stays that way.

    - stop :: Stop all kur instances and then the manager.

=cut

sub start_server {
	my ($self) = @_;

	$self->errorblank;

	POE::Session->create(
		object_states => [
			$self => {
				'_start'      => '_poe_start',
				'spawn_kur'   => '_poe_spawn_kur',
				'restart_kur' => '_poe_restart_kur',
				'kur_stdout'  => '_poe_kur_stdout',
				'kur_stderr'  => '_poe_kur_stderr',
				'kur_reaped'  => '_poe_kur_reaped',
				'remove_kur'  => '_poe_remove_kur',
				'stop_all'    => '_poe_stop_all',
			},
		],
	);

	my $server = POE::Component::Server::JSONUnix->spawn(
		'socket_path'   => $self->socket_path,
		'socket_mode'   => $self->{socket_mode},
		'alias'         => 'ereshkigal_server',
		'auth_required' => $self->{enable_auth} ? 1 : 0,
		defined( $self->{auth_temp_dir} ) ? ( 'auth_temp_dir' => $self->{auth_temp_dir} ) : (),
		'on_error' => sub {
			my ( $operation, $errnum, $errstr ) = @_;
			log_drek( 'err', 'socket error during ' . $operation . '... ' . $errstr . ' (' . $errnum . ')' );
		},
		'commands' => {
			'status' => sub {
				my ( undef, undef, $ctx ) = @_;
				$self->_authorize($ctx);
				return $self->_cmd_status;
			},
			'status_all' => sub {
				my ( undef, undef, $ctx ) = @_;
				$self->_authorize($ctx);
				return $self->_cmd_status_all;
			},
			'status_kur' => sub {
				my ( undef, $request, $ctx ) = @_;
				return $self->_cmd_status_kur( $request, $ctx );
			},
			'banned' => sub {
				my ( undef, undef, $ctx ) = @_;
				$self->_authorize( $ctx, $self->_real_kur_names );
				return $self->_cmd_banned;
			},
			'ban' => sub {
				my ( undef, $request, $ctx ) = @_;
				return $self->_cmd_ban( $request, $ctx );
			},
			'unban' => sub {
				my ( undef, $request, $ctx ) = @_;
				$self->_authorize( $ctx, $self->_real_kur_names );
				return $self->_cmd_unban($request);
			},
			'cidr_ban' => sub {
				my ( undef, $request, $ctx ) = @_;
				return $self->_cmd_cidr_ban( $request, $ctx );
			},
			'cidr_unban' => sub {
				my ( undef, $request, $ctx ) = @_;
				$self->_authorize( $ctx, $self->_real_kur_names );
				return $self->_cmd_cidr_unban($request);
			},
			'add_kur' => sub {
				my ( undef, $request, $ctx ) = @_;
				$self->_authorize($ctx);
				return $self->_cmd_add_kur($request);
			},
			'remove_kur' => sub {
				my ( undef, $request, $ctx ) = @_;
				$self->_authorize($ctx);
				return $self->_cmd_remove_kur($request);
			},
			'checkpoint' => sub {
				my ( undef, $request, $ctx ) = @_;
				return $self->_cmd_checkpoint( $request, $ctx );
			},
			'clear_retries' => sub {
				my ( undef, $request, $ctx ) = @_;
				return $self->_cmd_clear_retries( $request, $ctx );
			},
			're_init' => sub {
				my ( undef, $request, $ctx ) = @_;
				return $self->_cmd_re_init( $request, $ctx );
			},
			'stop' => sub {
				my ( undef, undef, $ctx ) = @_;
				$self->_authorize($ctx);
				log_drek( 'info', 'stop requested' );
				$poe_kernel->post( 'ereshkigal_manager', 'stop_all' );
				# the current session is the JSONUnix server session, so this
				# fires its shutdown state after the response has had time to flush
				$poe_kernel->delay( 'shutdown', 1 );
				return { 'stopping' => 1 };
			},
		},
	);
	$self->{server} = $server;

	# group ownership gates who may drive the manager
	if ( !chown( $>, $self->{socket_gid}, $self->socket_path ) ) {
		log_drek( 'err', 'chown of "' . $self->socket_path . '" to GID ' . $self->{socket_gid} . ' failed... ' . $! );
	}

	$self->{started} = time;

	log_drek( 'info',
		'started... socket=' . $self->socket_path . ' kurs=' . join( ',', sort( keys( %{ $self->{kurs} } ) ) ) );

	$poe_kernel->run;

	log_drek( 'info', 'stopped' );

	return;
} ## end sub start_server

sub _check_kur_def {
	my ( $self, $name, $def, $perror ) = @_;

	my $error;
	if ( !defined($name) || $name !~ /^[a-zA-Z0-9\-]+$/ ) {
		$error = 'The kur name, "' . ( defined($name) ? $name : 'undef' ) . '", does not match /^[a-zA-Z0-9\-]+$/';
	} elsif ( ref($def) ne 'HASH' ) {
		$error = 'The def for the kur "' . $name . '" is not a hash';
	} elsif ( defined( $def->{backend} ) && defined( $def->{fan_out} ) ) {
		$error = 'The def for the kur "' . $name . '" has both a backend and a fan_out';
	} elsif ( !defined( $def->{backend} ) && !defined( $def->{fan_out} ) ) {
		$error = 'The def for the kur "' . $name . '" lacks a backend or a fan_out';
	} elsif ( defined( $def->{fan_out} ) && ( ref( $def->{fan_out} ) ne 'ARRAY' || !@{ $def->{fan_out} } ) ) {
		$error = 'The fan_out for the kur "' . $name . '" is not a array of one or more kur names';
	} elsif ( defined( $def->{fan_out} )
		&& grep { !defined($_) || ref($_) ne '' || $_ !~ /^[a-zA-Z0-9\-]+$/ } @{ $def->{fan_out} } )
	{
		$error = 'The fan_out for the kur "' . $name . '" contains a invalid kur name';
	} elsif ( defined( $def->{ban_time} ) && $def->{ban_time} !~ /^[0-9]+$/ ) {
		$error
			= 'The ban_time for the kur "'
			. $name . '", "'
			. $def->{ban_time}
			. '", is not a non-negative int of seconds';
	} elsif ( defined( $def->{checkpoint} ) && $def->{checkpoint} !~ /^[0-9]+$/ ) {
		$error
			= 'The checkpoint for the kur "'
			. $name . '", "'
			. $def->{checkpoint}
			. '", is not a non-negative int of seconds';
	} elsif ( defined( $def->{authed_users} ) && defined( _authed_list_error( $def->{authed_users} ) ) ) {
		$error = 'The authed_users for the kur "' . $name . '" is ' . _authed_list_error( $def->{authed_users} );
	} elsif ( defined( $def->{authed_groups} ) && defined( _authed_list_error( $def->{authed_groups} ) ) ) {
		$error = 'The authed_groups for the kur "' . $name . '" is ' . _authed_list_error( $def->{authed_groups} );
	} elsif ( defined( $def->{options} ) && defined( _options_error( $def->{options} ) ) ) {
		$error = 'The options for the kur "' . $name . '" is ' . _options_error( $def->{options} );
	}

	if ( defined($error) ) {
		if ($perror) {
			$self->{perror}      = 1;
			$self->{error}       = 3;
			$self->{errorString} = $error;
			$self->warn;
		}
		die($error);
	}

	return;
} ## end sub _check_kur_def

# validates every member of a fan_out kur is a defined non fan_out kur...
# separate from _check_kur_def as it needs the kur registry, meaning at
# config load it can only happen once every kur is registered
sub _check_fan_out_members {
	my ( $self, $name, $def, $perror ) = @_;

	my $error;
	foreach my $member ( @{ $def->{fan_out} } ) {
		if ( !defined( $self->{kurs}{$member} ) ) {
			$error = 'The fan_out for the kur "' . $name . '" contains a unknown kur, "' . $member . '"';
			last;
		}
		if ( defined( $self->{kurs}{$member}{opts}{fan_out} ) ) {
			$error
				= 'The fan_out for the kur "'
				. $name
				. '" contains the fan_out kur "'
				. $member
				. '"... fan_out kurs may not nest';
			last;
		}
	} ## end foreach my $member ( @{ $def->{fan_out} } )

	if ( defined($error) ) {
		if ($perror) {
			$self->{perror}      = 1;
			$self->{error}       = 3;
			$self->{errorString} = $error;
			$self->warn;
		}
		die($error);
	}

	return;
} ## end sub _check_fan_out_members

# returns a error string if the passed value is not a array of strings,
# undef otherwise
sub _authed_list_error {
	my ($list) = @_;

	if ( ref($list) ne 'ARRAY' ) {
		return 'not a array';
	}
	foreach my $item ( @{$list} ) {
		if ( !defined($item) || ref($item) ne '' ) {
			return 'not a array of just strings';
		}
	}

	return undef;
} ## end sub _authed_list_error

# returns a error string if the passed backend options hash carries anything
# _build_kur_cmd can not hand to the kur bin, undef otherwise... values must
# be plain scalars, except interfaces, which may also be a array of them
sub _options_error {
	my ($options) = @_;

	if ( ref($options) ne 'HASH' ) {
		return 'not a hash';
	}
	foreach my $key ( keys( %{$options} ) ) {
		my $value = $options->{$key};
		next if ( ref($value) eq '' );
		if ( $key eq 'interfaces' && ref($value) eq 'ARRAY' && !grep { ref($_) ne '' } @{$value} ) {
			next;
		}
		return 'carrying a non-scalar value for the option "' . $key
			. '"... only interfaces may be a array, and only of plain scalars';
	}

	return undef;
} ## end sub _options_error

# checks if the user is in the passed users list or a member of one of the
# passed groups... group membership (primary and secondary) comes from the
# JSONUnix context, which resolves it through NSS and caches it per
# connection, so user/group database changes apply with out a restart
sub _user_in_lists {
	my ( $self, $ctx, $username, $users, $groups ) = @_;

	foreach my $user ( @{$users} ) {
		if ( $user eq $username ) {
			return 1;
		}
	}

	foreach my $group ( @{$groups} ) {
		# unknown groups just never match rather than erroring
		if ( $ctx->in_group($group) ) {
			return 1;
		}
	}

	return 0;
} ## end sub _user_in_lists

# authorizes the authenticated user behind the context for the specified
# kurs, or for manager level commands when no kurs are specified, dieing if
# they are not allowed... a no-op when enable_auth is off
sub _authorize {
	my ( $self, $ctx, @kurs ) = @_;

	if ( !$self->{enable_auth} ) {
		return;
	}

	my $uid      = $ctx->uid;
	my $username = $ctx->username;
	if ( !defined($uid) ) {
		# should be unreachable as JSONUnix gates unauthed commands first...
		# a hash ref die carries a machine-readable code through to the
		# JSONUnix error response, matching it's own auth_required code
		die( { 'error' => 'authentication required', 'code' => 'auth_required' } );
	}
	if ( $uid == 0 ) {
		return;
	}
	$username = '' if !defined($username);

	# no kurs named means a manager level command... untargeted commands on a
	# manager with zero real kurs also land here, deliberately, as with no
	# per-kur lists to expand the global lists are all there is to check
	if ( !@kurs ) {
		if ( $self->_user_in_lists( $ctx, $username, $self->{authed_users}, $self->{authed_groups} ) ) {
			return;
		}
		die(
			{
				'error' => 'The user "' . $username . '" is not authorized for manager level commands',
				'code'  => 'permission_denied',
			}
		);
	} ## end if ( !@kurs )

	foreach my $name (@kurs) {
		# the effective lists for a kur are the global ones plus it's own
		my $def = defined( $self->{kurs}{$name} ) ? $self->{kurs}{$name}{opts} : {};
		my @users
			= ( @{ $self->{authed_users} }, ref( $def->{authed_users} ) eq 'ARRAY' ? @{ $def->{authed_users} } : () );
		my @groups = ( @{ $self->{authed_groups} },
			ref( $def->{authed_groups} ) eq 'ARRAY' ? @{ $def->{authed_groups} } : () );
		if ( !$self->_user_in_lists( $ctx, $username, \@users, \@groups ) ) {
			die(
				{
					'error' => 'The user "' . $username . '" is not authorized for the kur "' . $name . '"',
					'code'  => 'permission_denied',
				}
			);
		}
	} ## end foreach my $name (@kurs)

	return;
} ## end sub _authorize

sub _kur_client {
	my ( $self, $name ) = @_;

	return Ereshkigal::Client->new(
		'socket'  => $self->kur_socket_path($name),
		'timeout' => $self->{timeout},
	);
}

# the names of the kurs that are actual processes, sorted... fan_out kurs
# are manager side only and get excluded everywhere a untargeted command
# resolves it's targets
sub _real_kur_names {
	my ($self) = @_;

	return grep { !defined( $self->{kurs}{$_}{opts}{fan_out} ) } sort( keys( %{ $self->{kurs} } ) );
}

# expands a targeted kur name into fan out targets... a fan_out kur becomes
# it's members while a plain kur is just it's self
sub _expand_kur_targets {
	my ( $self, $name ) = @_;

	my $entry = $self->{kurs}{$name};
	if ( defined($entry) && defined( $entry->{opts}{fan_out} ) ) {
		return @{ $entry->{opts}{fan_out} };
	}

	return ($name);
} ## end sub _expand_kur_targets

# fans one command out to the passed kur instances concurrently via
# Ereshkigal::Client->call_many, returning the hash the handlers use as the
# kurs value of their responses... each name maps to the result hash on
# success or { error => ... } otherwise, with kurs that are not running
# answered with a not running error with out a connect ever being attempted
sub _fan_out {
	my ( $self, $targets, $command, $args ) = @_;

	my $kurs    = {};
	my $sockets = {};
	foreach my $name ( @{$targets} ) {
		my $entry = $self->{kurs}{$name};
		if ( !defined($entry) || !defined( $entry->{pid} ) ) {
			$kurs->{$name} = { 'error' => 'not running' };
			next;
		}
		$sockets->{$name} = $self->kur_socket_path($name);
	}

	if ( %{$sockets} ) {
		my $answers = Ereshkigal::Client->call_many(
			'sockets' => $sockets,
			'command' => $command,
			defined($args) ? ( 'args' => $args ) : (),
			'timeout' => $self->{timeout},
		);
		foreach my $name ( keys( %{$answers} ) ) {
			if ( defined( $answers->{$name}{error} ) ) {
				$kurs->{$name} = { 'error' => $answers->{$name}{error} };
			} else {
				$kurs->{$name} = $answers->{$name}{result};
			}
		}
	} ## end if ( %{$sockets} )

	return $kurs;
} ## end sub _fan_out

sub _build_kur_cmd {
	my ( $self, $name ) = @_;

	my $def = $self->{kurs}{$name}{opts};

	my @cmd = (
		$self->{kur_bin}, '--foreground',  '--name', $name,
		'--backend',      $def->{backend}, '--run',  $self->{run_base_dir},
		'--cache',        $self->{cache_base_dir},
	);

	foreach my $listy ( 'ports', 'protocols' ) {
		if ( defined( $def->{$listy} ) ) {
			my @items = ref( $def->{$listy} ) eq 'ARRAY' ? @{ $def->{$listy} } : ( $def->{$listy} );
			if (@items) {
				push( @cmd, '--' . $listy, join( ',', @items ) );
			}
		}
	}

	if ( defined( $def->{prefix} ) ) {
		push( @cmd, '--prefix', $def->{prefix} );
	}

	if ( defined( $def->{self_heal} ) ) {
		push( @cmd, '--self-heal', $def->{self_heal} ? 1 : 0 );
	}

	# the kur ban_time and checkpoint, defaulting to the manager wide ones
	push( @cmd, '--ban-time',   defined( $def->{ban_time} )   ? $def->{ban_time}   : $self->{ban_time} );
	push( @cmd, '--checkpoint', defined( $def->{checkpoint} ) ? $def->{checkpoint} : $self->{checkpoint} );

	# the CIDR toggles, per kur overriding the manager wide ones, collapsed to
	# 1/0 here so the kur is handed a clean boolean
	my $enable_cidr      = defined( $def->{enable_cidr} )      ? $def->{enable_cidr}      : $self->{enable_cidr};
	my $cidr_silent_drop = defined( $def->{cidr_silent_drop} ) ? $def->{cidr_silent_drop} : $self->{cidr_silent_drop};
	push( @cmd, '--enable-cidr',      $enable_cidr      ? 1 : 0 );
	push( @cmd, '--cidr-silent-drop', $cidr_silent_drop ? 1 : 0 );

	if ( ref( $def->{options} ) eq 'HASH' ) {
		foreach my $key ( sort( keys( %{ $def->{options} } ) ) ) {
			my $value = $def->{options}{$key};
			# interfaces is the one array valued option, riding its own flag
			# so the kur bin can rebuild the array
			if ( $key eq 'interfaces' ) {
				push( @cmd, '--interfaces', ref($value) eq 'ARRAY' ? join( ',', @{$value} ) : $value );
			} else {
				push( @cmd, '--option', $key . '=' . $value );
			}
		} ## end foreach my $key ( sort( keys( %{ $def->{options...}})))
	} ## end if ( ref( $def->{options} ) eq 'HASH' )

	return @cmd;
} ## end sub _build_kur_cmd

#
# POE states for the manager session
#

sub _poe_start {
	my ( $self, $kernel ) = @_[ OBJECT, KERNEL ];

	$kernel->alias_set('ereshkigal_manager');

	foreach my $name ( sort( keys( %{ $self->{kurs} } ) ) ) {
		$kernel->yield( 'spawn_kur', $name );
	}

	return;
} ## end sub _poe_start

sub _poe_spawn_kur {
	my ( $self, $kernel, $name ) = @_[ OBJECT, KERNEL, ARG0 ];

	my $entry = $self->{kurs}{$name};
	if ( !defined($entry) || !$entry->{enabled} || defined( $entry->{wheel} ) || $self->{shutting_down} ) {
		return;
	}

	# fan_out kurs are manager side only... nothing to spawn
	if ( defined( $entry->{opts}{fan_out} ) ) {
		return;
	}

	my @cmd = $self->_build_kur_cmd($name);

	my $wheel = POE::Wheel::Run->new(
		'Program'     => \@cmd,
		'StdoutEvent' => 'kur_stdout',
		'StderrEvent' => 'kur_stderr',
	);

	$kernel->sig_child( $wheel->PID, 'kur_reaped' );

	$entry->{wheel}   = $wheel;
	$entry->{pid}     = $wheel->PID;
	$entry->{spawned} = time;

	$self->{wheel_to_kur}{ $wheel->ID } = $name;
	$self->{pid_to_kur}{ $wheel->PID }  = $name;

	log_drek( 'info', 'spawned kur "' . $name . '" as PID ' . $wheel->PID . '... ' . join( ' ', @cmd ) );

	return;
} ## end sub _poe_spawn_kur

sub _poe_restart_kur {
	my ( $self, $kernel, $name ) = @_[ OBJECT, KERNEL, ARG0 ];

	$kernel->yield( 'spawn_kur', $name );

	return;
}

sub _poe_kur_stdout {
	my ( $self, $line, $wheel_id ) = @_[ OBJECT, ARG0, ARG1 ];

	my $name = $self->{wheel_to_kur}{$wheel_id};
	$name = 'unknown' if !defined($name);
	chomp($line);
	log_drek( 'info', 'kur "' . $name . '" stdout... ' . $line );

	return;
} ## end sub _poe_kur_stdout

sub _poe_kur_stderr {
	my ( $self, $line, $wheel_id ) = @_[ OBJECT, ARG0, ARG1 ];

	my $name = $self->{wheel_to_kur}{$wheel_id};
	$name = 'unknown' if !defined($name);
	chomp($line);
	log_drek( 'err', 'kur "' . $name . '" stderr... ' . $line );

	return;
} ## end sub _poe_kur_stderr

sub _poe_kur_reaped {
	my ( $self, $kernel, $pid, $exit ) = @_[ OBJECT, KERNEL, ARG1, ARG2 ];

	my $name = delete( $self->{pid_to_kur}{$pid} );
	if ( !defined($name) ) {
		return;
	}

	my $entry = $self->{kurs}{$name};
	if ( defined($entry) && defined( $entry->{wheel} ) ) {
		delete( $self->{wheel_to_kur}{ $entry->{wheel}->ID } );
		$entry->{wheel} = undef;
		$entry->{pid}   = undef;
	}

	log_drek( 'info', 'kur "' . $name . '" PID ' . $pid . ' exited with ' . ( $exit >> 8 ) );

	if ( $self->{shutting_down} || !defined($entry) || !$entry->{enabled} ) {
		return;
	}

	# it ran long enough to be considered to have started fine, so reset the backoff
	if ( defined( $entry->{spawned} ) && ( time - $entry->{spawned} ) > 60 ) {
		$entry->{delay} = 1;
	}

	my $delay = $entry->{delay};
	$entry->{delay} = $delay * 2 > 60 ? 60 : $delay * 2;
	$entry->{restarts}++;

	log_drek( 'err', 'kur "' . $name . '" died, restarting in ' . $delay . ' seconds' );

	$kernel->delay_set( 'restart_kur', $delay, $name );

	return;
} ## end sub _poe_kur_reaped

# the actual removal has to happen in the manager session as destroying a
# POE::Wheel::Run from within another session leaves it's watchers behind,
# keeping the manager session alive forever
sub _poe_remove_kur {
	my ( $self, $name ) = @_[ OBJECT, ARG0 ];

	my $entry = $self->{kurs}{$name};
	if ( !defined($entry) ) {
		return;
	}

	if ( defined( $entry->{pid} ) ) {
		eval { $self->_kur_client($name)->call_ok('stop'); };
		if ($@) {
			log_drek( 'err', 'stopping kur "' . $name . '" via it\'s socket failed, sending TERM... ' . $@ );
			if ( defined( $entry->{wheel} ) ) {
				$entry->{wheel}->kill('TERM');
			}
		}
	}

	# the reaped handler only cleans these up while the registry entry is
	# still around, which it is about to not be, so they are cleaned here...
	# otherwise every add/remove cycle leaks a wheel_to_kur entry
	if ( defined( $entry->{wheel} ) ) {
		delete( $self->{wheel_to_kur}{ $entry->{wheel}->ID } );
	}
	if ( defined( $entry->{pid} ) ) {
		delete( $self->{pid_to_kur}{ $entry->{pid} } );
	}

	delete( $self->{kurs}{$name} );

	log_drek( 'info', 'removed kur "' . $name . '"' );

	return;
} ## end sub _poe_remove_kur

sub _poe_stop_all {
	my ( $self, $kernel ) = @_[ OBJECT, KERNEL ];

	$self->{shutting_down} = 1;

	foreach my $name ( sort( keys( %{ $self->{kurs} } ) ) ) {
		my $entry = $self->{kurs}{$name};
		if ( !defined( $entry->{pid} ) ) {
			next;
		}
		eval { $self->_kur_client($name)->call_ok('stop'); };
		if ($@) {
			log_drek( 'err', 'stopping kur "' . $name . '" via it\'s socket failed, sending TERM... ' . $@ );
			if ( defined( $entry->{wheel} ) ) {
				$entry->{wheel}->kill('TERM');
			}
		}
	} ## end foreach my $name ( sort( keys( %{ $self->{kurs}...})))

	$kernel->alarm_remove_all;
	$kernel->alias_remove('ereshkigal_manager');

	return;
} ## end sub _poe_stop_all

#
# JSONUnix command handlers
#

sub _kur_summary {
	my ($self) = @_;

	my $kurs = {};
	foreach my $name ( keys( %{ $self->{kurs} } ) ) {
		my $entry = $self->{kurs}{$name};
		# a fan_out kur has no process of it's own... it counts as running
		# when every member is
		if ( defined( $entry->{opts}{fan_out} ) ) {
			my $running = 1;
			foreach my $member ( @{ $entry->{opts}{fan_out} } ) {
				if ( !defined( $self->{kurs}{$member} ) || !defined( $self->{kurs}{$member}{pid} ) ) {
					$running = 0;
					last;
				}
			}
			$kurs->{$name} = {
				'fan_out' => $entry->{opts}{fan_out},
				'running' => $running,
				'enabled' => $entry->{enabled} ? 1 : 0,
			};
			next;
		} ## end if ( defined( $entry->{opts}{fan_out} ) )
		$kurs->{$name} = {
			'running'  => defined( $entry->{pid} ) ? 1 : 0,
			'pid'      => $entry->{pid},
			'restarts' => $entry->{restarts},
			'enabled'  => $entry->{enabled} ? 1 : 0,
		};
	} ## end foreach my $name ( keys( %{ $self->{kurs} } ) )

	return $kurs;
} ## end sub _kur_summary

# handles the status command... the manager's own info plus the bare
# summary row for each kur, without asking any kur process anything
sub _cmd_status {
	my ($self) = @_;

	return {
		'pid'         => $$,
		'uptime'      => time - $self->{started},
		'config'      => $self->{config},
		'enable_auth' => $self->{enable_auth} ? 1 : 0,
		'kurs'        => $self->_kur_summary,
	};
} ## end sub _cmd_status

# handles the status_all command... _cmd_status with each running real kur
# additionally asked for its own status
sub _cmd_status_all {
	my ($self) = @_;

	my $status = $self->_cmd_status;

	# only the running real ones... a not running kur stays a bare summary
	# row and a fan_out kur has no socket to ask
	my @running = grep { $status->{kurs}{$_}{running} && !defined( $status->{kurs}{$_}{fan_out} ) }
		sort( keys( %{ $status->{kurs} } ) );
	my $answers = $self->_fan_out( \@running, 'status' );
	foreach my $name (@running) {
		if ( defined( $answers->{$name}{error} ) ) {
			$status->{kurs}{$name}{error} = $answers->{$name}{error};
		} else {
			$status->{kurs}{$name}{status} = $answers->{$name};
		}
	}

	return $status;
} ## end sub _cmd_status_all

# handles the status_kur command... the summary row for the kur named by
# args.name plus its own status when running, or the member list plus each
# member's status when it is a fan_out kur
sub _cmd_status_kur {
	my ( $self, $request, $ctx ) = @_;

	my $args = $request->{args};
	if ( !defined($args) || !defined( $args->{name} ) ) {
		die('args.name must be the name of a kur instance');
	}
	my $name = $args->{name};

	# authorized before existence is checked, so an unauthorized caller can
	# not use the difference in errors to enumerate kur names
	$self->_authorize( $ctx, $name );

	my $entry = $self->{kurs}{$name};
	if ( !defined($entry) ) {
		die( 'No such kur instance, "' . $name . '"' );
	}

	# a fan_out kur has no process of it's own, so it's status is it's
	# member list plus each member's status
	if ( defined( $entry->{opts}{fan_out} ) ) {
		return {
			'name'    => $name,
			'fan_out' => $entry->{opts}{fan_out},
			'enabled' => $entry->{enabled} ? 1 : 0,
			'kurs'    => $self->_fan_out( $entry->{opts}{fan_out}, 'status' ),
		};
	}

	my $status = {
		'name'     => $name,
		'running'  => defined( $entry->{pid} ) ? 1 : 0,
		'pid'      => $entry->{pid},
		'restarts' => $entry->{restarts},
		'enabled'  => $entry->{enabled} ? 1 : 0,
	};

	if ( $status->{running} ) {
		# via _fan_out rather than a bare call_ok so a live process with a
		# wedged socket degrades to a error entry, reported under the same
		# error key status_all uses rather than nested inside status
		my $answer = $self->_fan_out( [$name], 'status' )->{$name};
		if ( defined( $answer->{error} ) ) {
			$status->{error} = $answer->{error};
		} else {
			$status->{status} = $answer;
		}
	} ## end if ( $status->{running} )

	return $status;
} ## end sub _cmd_status_kur

# handles the banned command... fans banned out to every real kur, trimming
# each successful answer down to just the ban and expiry fields
sub _cmd_banned {
	my ($self) = @_;

	my $kurs = $self->_fan_out( [ $self->_real_kur_names ], 'banned' );
	foreach my $name ( keys( %{$kurs} ) ) {
		if ( !defined( $kurs->{$name}{error} ) ) {
			$kurs->{$name} = {
				'banned'       => $kurs->{$name}{banned},
				'expires'      => $kurs->{$name}{expires},
				'banned_cidr'  => $kurs->{$name}{banned_cidr},
				'cidr_expires' => $kurs->{$name}{cidr_expires},
			};
		}
	} ## end foreach my $name ( keys( %{$kurs} ) )

	return { 'kurs' => $kurs };
} ## end sub _cmd_banned

# handles the ban command... fans args.ips out to the targeted kurs, all of
# the shared validate/authorize/fan_out work living in _cmd_ban_common
sub _cmd_ban {
	my ( $self, $request, $ctx ) = @_;

	return $self->_cmd_ban_common(
		$request, $ctx,
		{
			'arg_key'    => 'ips',
			'noun'       => 'IP',
			'noun_long'  => 'IPv4 or IPv6 IP',
			'normalizer' => \&normalize_ip,
			'command'    => 'ban',
		}
	);
} ## end sub _cmd_ban

# handles the unban command... args.all set fans flush out to every real
# kur, otherwise args.ip is normalized and unban fanned out instead
sub _cmd_unban {
	my ( $self, $request ) = @_;

	my $args = $request->{args};
	if ( !defined($args) || ( !$args->{all} && !defined( $args->{ip} ) ) ) {
		die('Either args.all must be true or args.ip must be a IP');
	}

	my @all = $self->_real_kur_names;
	my $kurs;
	if ( $args->{all} ) {
		$kurs = $self->_fan_out( \@all, 'flush' );
	} else {
		# bounce garbage here instead of fanning it out just for every kur
		# to report it absent, and fan out the canonical form so variant
		# spellings of the same IP all find the ban
		my $ip = normalize_ip( $args->{ip} );
		if ( !defined($ip) ) {
			die( '"' . $args->{ip} . '" does not appear to be a IPv4 or IPv6 IP' );
		}
		# the kur checks if the IP is present and only unbans it if it is,
		# reporting back via was_banned
		$kurs = $self->_fan_out( \@all, 'unban', { 'ip' => $ip } );
	} ## end else [ if ( $args->{all} ) ]

	return { 'kurs' => $kurs };
} ## end sub _cmd_unban

# the CIDR twin of _cmd_ban... fans args.cidrs out to the targeted kurs,
# all of the shared validate/authorize/fan_out work living in
# _cmd_ban_common
sub _cmd_cidr_ban {
	my ( $self, $request, $ctx ) = @_;

	return $self->_cmd_ban_common(
		$request, $ctx,
		{
			'arg_key'    => 'cidrs',
			'noun'       => 'CIDR',
			'noun_long'  => 'IPv4 or IPv6 CIDR',
			'normalizer' => \&normalize_cidr,
			'command'    => 'cidr_ban',
		}
	);
} ## end sub _cmd_cidr_ban

# the shared body of _cmd_ban and _cmd_cidr_ban, which differ only in the
# args key, the normalizer, the kur command, and the noun used in errors
sub _cmd_ban_common {
	my ( $self, $request, $ctx, $spec ) = @_;

	my $args    = $request->{args};
	my $arg_key = $spec->{arg_key};
	if ( !defined($args) || ref( $args->{$arg_key} ) ne 'ARRAY' || !@{ $args->{$arg_key} } ) {
		die( 'args.' . $arg_key . ' must be a array of one or more ' . $spec->{noun} . 's' );
	}

	# targets are resolved and authorization checked before anything is done
	# with the payload, so an unauthorized caller can neither enumerate kur
	# names nor burn cycles on validation
	my @targets;
	if ( defined( $args->{kur} ) ) {
		# authorization is checked against the requested name... for a
		# fan_out kur being authorized for the gateway is the grant, which
		# is what makes one usable as a single point of contact
		$self->_authorize( $ctx, $args->{kur} );
		if ( !defined( $self->{kurs}{ $args->{kur} } ) ) {
			die( 'No such kur instance, "' . $args->{kur} . '"' );
		}
		@targets = $self->_expand_kur_targets( $args->{kur} );
	} else {
		@targets = $self->_real_kur_names;
		# authorized before the empty check, matching every other untargeted
		# command... with zero real kurs this is the manager level check, so
		# an unauthorized caller is refused rather than being told what the
		# manager is carrying
		$self->_authorize( $ctx, @targets );
		if ( !@targets ) {
			die('No kur instances');
		}
	} ## end else [ if ( defined( $args->{kur} ) ) ]

	# pre-flight the entries so garbage is bounced here instead of being
	# fanned out just for every kur to bounce it, and so what is fanned out
	# is the canonical form... variant spellings also dedupe here
	my @entries;
	my %seen;
	my $rejected = {};
	foreach my $raw_entry ( @{ $args->{$arg_key} } ) {
		my $entry = $spec->{normalizer}->($raw_entry);
		if ( !defined($entry) ) {
			my $key = defined($raw_entry) ? $raw_entry : '';
			$rejected->{$key}
				= { 'status' => 'error', 'error' => '"' . $key . '" does not appear to be a ' . $spec->{noun_long} };
			next;
		}
		if ( !$seen{$entry} ) {
			$seen{$entry} = 1;
			push( @entries, $entry );
		}
	} ## end foreach my $raw_entry ( @{ $args->{$arg_key} } )
	if ( !@entries ) {
		die( 'None of the ' . $spec->{noun} . 's in args.' . $arg_key . ' appear to be a ' . $spec->{noun_long} );
	}

	my $kur_args = { $arg_key => \@entries };
	if ( defined( $args->{ban_time} ) ) {
		$kur_args->{ban_time} = $args->{ban_time};
	}

	my $response = { 'kurs' => $self->_fan_out( \@targets, $spec->{command}, $kur_args ) };
	if ( %{$rejected} ) {
		$response->{rejected} = $rejected;
	}

	return $response;
} ## end sub _cmd_ban_common

# the CIDR twin of _cmd_unban, minus the all form... args.cidr is
# normalized and cidr_unban fanned out to every real kur
sub _cmd_cidr_unban {
	my ( $self, $request ) = @_;

	my $args = $request->{args};
	if ( !defined($args) || !defined( $args->{cidr} ) ) {
		die('args.cidr must be a CIDR');
	}

	# bounce garbage here instead of fanning it out just for every kur to
	# report it absent, and fan out the canonical network form so variant
	# spellings of the same range all find the ban
	my $cidr = normalize_cidr( $args->{cidr} );
	if ( !defined($cidr) ) {
		die( '"' . $args->{cidr} . '" does not appear to be a IPv4 or IPv6 CIDR' );
	}

	# the kur checks if the CIDR is present and only unbans it if it is,
	# reporting back via was_banned
	my $kurs = $self->_fan_out( [ $self->_real_kur_names ], 'cidr_unban', { 'cidr' => $cidr } );

	return { 'kurs' => $kurs };
} ## end sub _cmd_cidr_unban

# handles the checkpoint command... fans checkpoint out to the kurs behind
# args.kur when given, or every real kur otherwise
sub _cmd_checkpoint {
	my ( $self, $request, $ctx ) = @_;

	my $args = $request->{args};

	my @targets;
	if ( defined($args) && defined( $args->{kur} ) ) {
		# like ban, authorization is against the requested name, so a
		# fan_out kur grant covers the fanned command... and it comes before
		# the existence check so kur names can not be enumerated
		$self->_authorize( $ctx, $args->{kur} );
		if ( !defined( $self->{kurs}{ $args->{kur} } ) ) {
			die( 'No such kur instance, "' . $args->{kur} . '"' );
		}
		@targets = $self->_expand_kur_targets( $args->{kur} );
	} else {
		@targets = $self->_real_kur_names;
		$self->_authorize( $ctx, @targets );
	}

	return { 'kurs' => $self->_fan_out( \@targets, 'checkpoint' ) };
} ## end sub _cmd_checkpoint

# handles the re_init command... fans re_init out the same way checkpoint
# does, having the kurs tear their firewall setup down and rebuild it from
# what their ban books carry
sub _cmd_re_init {
	my ( $self, $request, $ctx ) = @_;

	my $args = $request->{args};

	my @targets;
	if ( defined($args) && defined( $args->{kur} ) ) {
		# as with checkpoint, authorization is against the requested name so
		# a fan_out grant covers the fanned command, and it comes before the
		# existence check so kur names can not be enumerated
		$self->_authorize( $ctx, $args->{kur} );
		if ( !defined( $self->{kurs}{ $args->{kur} } ) ) {
			die( 'No such kur instance, "' . $args->{kur} . '"' );
		}
		@targets = $self->_expand_kur_targets( $args->{kur} );
	} else {
		@targets = $self->_real_kur_names;
		$self->_authorize( $ctx, @targets );
	}

	return { 'kurs' => $self->_fan_out( \@targets, 're_init' ) };
} ## end sub _cmd_re_init

# handles the clear_retries command... fans it out the same way checkpoint
# does, passing along the optional args.ip or args.cidr naming a single owed
# unban to forget rather than the lot
sub _cmd_clear_retries {
	my ( $self, $request, $ctx ) = @_;

	my $args = defined( $request->{args} ) ? $request->{args} : {};

	if ( defined( $args->{ip} ) && defined( $args->{cidr} ) ) {
		die('only one of args.ip and args.cidr may be given');
	}

	# validated and canonicalized here as well as kur side, so garbage is
	# bounced once rather than by each kur it would have been fanned out to,
	# and what is fanned out is the form the retry tablets are keyed by
	my $fan_args = {};
	if ( defined( $args->{ip} ) ) {
		my $ip = normalize_ip( $args->{ip} );
		if ( !defined($ip) ) {
			die( '"' . $args->{ip} . '" does not appear to be a IPv4 or IPv6 IP' );
		}
		$fan_args->{ip} = $ip;
	}
	if ( defined( $args->{cidr} ) ) {
		my $cidr = normalize_cidr( $args->{cidr} );
		if ( !defined($cidr) ) {
			die( '"' . $args->{cidr} . '" does not appear to be a IPv4 or IPv6 CIDR' );
		}
		$fan_args->{cidr} = $cidr;
	}

	my @targets;
	if ( defined( $args->{kur} ) ) {
		# as with checkpoint, authorization is against the requested name so
		# a fan_out grant covers the fanned command, and it comes before the
		# existence check so kur names can not be enumerated
		$self->_authorize( $ctx, $args->{kur} );
		if ( !defined( $self->{kurs}{ $args->{kur} } ) ) {
			die( 'No such kur instance, "' . $args->{kur} . '"' );
		}
		@targets = $self->_expand_kur_targets( $args->{kur} );
	} else {
		@targets = $self->_real_kur_names;
		$self->_authorize( $ctx, @targets );
	}

	return { 'kurs' => $self->_fan_out( \@targets, 'clear_retries', %{$fan_args} ? $fan_args : undef ) };
} ## end sub _cmd_clear_retries

# handles the add_kur command... validates the definition in args.opts the
# same way config load would, registers it under args.name, and has the
# manager session spawn it
sub _cmd_add_kur {
	my ( $self, $request ) = @_;

	my $args = $request->{args};
	if ( !defined($args) || !defined( $args->{name} ) ) {
		die('args.name must be the name for the new kur instance');
	}
	my $name = $args->{name};

	if ( defined( $self->{kurs}{$name} ) ) {
		die( 'The kur instance "' . $name . '" already exists' );
	}

	$self->_check_kur_def( $name, $args->{opts}, 0 );
	if ( defined( $args->{opts}{fan_out} ) ) {
		$self->_check_fan_out_members( $name, $args->{opts}, 0 );
	}

	$self->{kurs}{$name} = {
		'opts'     => $args->{opts},
		'wheel'    => undef,
		'pid'      => undef,
		'restarts' => 0,
		'delay'    => 1,
		'enabled'  => 1,
		'spawned'  => undef,
	};

	$poe_kernel->post( 'ereshkigal_manager', 'spawn_kur', $name );

	log_drek( 'info', 'added kur "' . $name . '"' );

	return { 'added' => $name };
} ## end sub _cmd_add_kur

# handles the remove_kur command... refuses while args.name is still a
# fan_out member, otherwise disables it and has the manager session stop
# and drop it
sub _cmd_remove_kur {
	my ( $self, $request ) = @_;

	my $args = $request->{args};
	if ( !defined($args) || !defined( $args->{name} ) ) {
		die('args.name must be the name of a kur instance');
	}
	my $name = $args->{name};

	my $entry = $self->{kurs}{$name};
	if ( !defined($entry) ) {
		die( 'No such kur instance, "' . $name . '"' );
	}

	# config load refuses a fan_out naming a unknown kur, so removal can not
	# be allowed to create that same dangling state at runtime... remove the
	# gate first, or the member stays
	my @gates_using;
	foreach my $other_name ( sort( keys( %{ $self->{kurs} } ) ) ) {
		my $fan_out = $self->{kurs}{$other_name}{opts}{fan_out};
		if ( defined($fan_out) && grep { $_ eq $name } @{$fan_out} ) {
			push( @gates_using, $other_name );
		}
	}
	if (@gates_using) {
		die(      'The kur "'
				. $name
				. '" is a fan_out member of "'
				. join( '", "', @gates_using )
				. '"... remove the fan_out kur first' );
	}

	$entry->{enabled} = 0;

	# the actual stop and removal happens in the manager session given the
	# wheel has to be destroyed there
	$poe_kernel->post( 'ereshkigal_manager', 'remove_kur', $name );

	return { 'removed' => $name };
} ## end sub _cmd_remove_kur

=head1 ERRORS CODES / ERROR FLAGS

Error handling is provided by L<Error::Helper>. All errors
are considered fatal.

=head2 1, configReadFailed

Failed to read the config file.

=head2 2, configParseFailed

Failed to parse the config file as TOML.

=head2 3, invalidKurDef

A kur def in the config is invalid... bad name, not a hash, lacking a
backend or a fan_out, having both, or a invalid fan_out (not a array of
kur names, a unknown member, or a nested fan_out kur).

=head2 4, runBaseDirError

The run base dir or the kur dir under it could not be created or is not
read/writable.

=head2 5, badSocketGroup

Failed to resolve the socket group to a GID.

=head2 6, invalidBanTime

ban_time is not a non-negative int of seconds.

=head2 7, invalidCheckpoint

checkpoint is not a non-negative int of seconds.

=head2 8, invalidAuthedList

authed_users or authed_groups is not a array of strings.

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-ereshkigal at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Ereshkigal>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Ereshkigal

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Ereshkigal>

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/Ereshkigal>

=item * Search CPAN

L<https://metacpan.org/release/Ereshkigal>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2023 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)


=cut

1;    # End of Ereshkigal
