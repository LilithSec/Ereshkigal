package Ereshkigal::Kur;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use POE;
use POE::Component::Server::JSONUnix ();
use Net::Firewall::BlockerHelper     ();
use Ereshkigal::LogDrek              qw( log_drek );

=head1 NAME

Ereshkigal::Kur - FW handler for Ereshkigal.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Ereshkigal::Kur;

    my $kur = Ereshkigal::Kur->new(
                  'name'      => 'sshd',
                  'backend'   => 'ipfw',
                  'ports'     => ['22'],
                  'protocols' => ['tcp'],
              );

    $kur->start_server;

Each Kur instance wraps a single L<Net::Firewall::BlockerHelper> instance and
serves it up via a L<POE::Component::Server::JSONUnix> server listening on a
unix socket under C<$run_base_dir/kur/>.

=head1 METHODS

=head2 new

Initiates the object. All errors are considered fatal, meaning if new fails
it will die.

    - name :: Name of this specific instance. Must match /^[a-zA-Z0-9\-]+$/.
        Default :: undef

    - backend :: The backend to use for Net::Firewall::BlockerHelper.
        Default :: undef

    - ports :: A array of ports to block, passed to Net::Firewall::BlockerHelper.
        Default :: []

    - protocols :: A array of protocols to block, passed to Net::Firewall::BlockerHelper.
        Default :: []

    - prefix :: Prefix to use, passed to Net::Firewall::BlockerHelper.
        Default :: kur

    - options :: Backend specific options hash, passed to Net::Firewall::BlockerHelper.
        Default :: {}

    - self_heal :: Self heal setting, passed to Net::Firewall::BlockerHelper.
        Default :: 1

    - ban_time :: How long bans should last in seconds. 0 means bans never
          time out. May be overridden per ban request.
        Default :: 600

    - checkpoint :: Seconds between periodic rewrites of the ban state CSV.
          0 disables the periodic rewrite... ban/unban, stop, and on demand
          checkpoints still happen.
        Default :: 60

    - run_base_dir :: Base dir for run files. The socket and PID for this
          instance live under C<$run_base_dir/kur/> named for this instance.
        Default :: /var/run/ereshkigal

    - cache_base_dir :: Base dir for cache files. The ban state for this
          instance is persisted as a CSV at
          C<$cache_base_dir/kur.$name.csv>, so timed bans survive a restart.
        Default :: /var/cache/ereshkigal

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
			flags            => {
				1 => 'NErunBaseDir',
				2 => 'invalidName',
				3 => 'backendInitFailed',
				4 => 'nonRWrunBaseDir',
				5 => 'NEcacheBaseDir',
				6 => 'nonRWcacheBaseDir',
				7 => 'invalidBanTime',
				8 => 'invalidCheckpoint',
			},
			fatal_flags      => {},
			perror_not_fatal => 0,
		},
		name            => undef,
		backend         => undef,
		ports           => [],
		protocols       => [],
		prefix          => undef,
		options         => undef,
		self_heal       => undef,
		ban_time        => 600,
		checkpoint      => 60,
		run_base_dir    => '/var/run/ereshkigal',
		cache_base_dir  => '/var/cache/ereshkigal',
		backend_obj     => undef,
		server          => undef,
		started         => undef,
		stopping        => 0,
		bans            => {},
		last_checkpoint => 0,
		stats           => {
			bans    => 0,
			unbans  => 0,
			errors  => 0,
			expired => 0,
		},
	};
	bless $self;

	my @to_merge = (
		'name',      'backend',  'ports',      'protocols',    'prefix', 'options',
		'self_heal', 'ban_time', 'checkpoint', 'run_base_dir', 'cache_base_dir'
	);
	foreach my $item (@to_merge) {
		if ( defined( $opts{$item} ) ) {
			$self->{$item} = $opts{$item};
		}
	}

	if ( $self->{ban_time} !~ /^[0-9]+$/ ) {
		$self->{perror}      = 1;
		$self->{error}       = 7;
		$self->{errorString} = 'ban_time, "' . $self->{ban_time} . '", is not a non-negative int of seconds';
		$self->warn;
	}

	if ( $self->{checkpoint} !~ /^[0-9]+$/ ) {
		$self->{perror}      = 1;
		$self->{error}       = 8;
		$self->{errorString} = 'checkpoint, "' . $self->{checkpoint} . '", is not a non-negative int of seconds';
		$self->warn;
	}

	if ( !defined( $self->{name} ) ) {
		$self->{perror}      = 1;
		$self->{error}       = 2;
		$self->{errorString} = 'name is undef';
		$self->warn;
	} elsif ( $self->{name} !~ /^[a-zA-Z0-9\-]+$/ ) {
		$self->{perror}      = 1;
		$self->{error}       = 2;
		$self->{errorString} = 'The specified name, "' . $self->{name} . '", does not match /^[a-zA-Z0-9\-]+$/';
		$self->warn;
	}

	foreach my $dir ( $self->{run_base_dir}, $self->{run_base_dir} . '/kur' ) {
		if ( !-e $dir ) {
			# don't need to check if this worked failed or not here as the next if statement will handle that
			eval { mkdir($dir); };
		}
		if ( !-d $dir ) {
			$self->{perror}      = 1;
			$self->{error}       = 1;
			$self->{errorString} = 'run dir,"' . $dir . '", does not exist or is not a directory';
			$self->warn;
		}
		if ( !-r $dir || !-w $dir ) {
			$self->{perror}      = 1;
			$self->{error}       = 4;
			$self->{errorString} = 'run dir,"' . $dir . '", is either not writable or readable by the current user';
			$self->warn;
		}
	} ## end foreach my $dir ( $self->{run_base_dir}, $self->...)

	if ( !-e $self->{cache_base_dir} ) {
		# don't need to check if this worked failed or not here as the next if statement will handle that
		eval { mkdir( $self->{cache_base_dir} ); };
	}
	if ( !-d $self->{cache_base_dir} ) {
		$self->{perror}      = 1;
		$self->{error}       = 5;
		$self->{errorString} = 'cache_base_dir,"' . $self->{cache_base_dir} . '", does not exist or is not a directory';
		$self->warn;
	}
	if ( !-r $self->{cache_base_dir} || !-w $self->{cache_base_dir} ) {
		$self->{perror} = 1;
		$self->{error}  = 6;
		$self->{errorString}
			= 'cache_base_dir,"'
			. $self->{cache_base_dir}
			. '", is either not writable or readable by the current user';
		$self->warn;
	}

	eval {
		$self->{backend_obj} = Net::Firewall::BlockerHelper->new(
			backend   => $self->{backend},
			ports     => $self->{ports},
			protocols => $self->{protocols},
			name      => $self->{name},
			defined( $self->{prefix} )    ? ( prefix    => $self->{prefix} )    : (),
			defined( $self->{options} )   ? ( options   => $self->{options} )   : (),
			defined( $self->{self_heal} ) ? ( self_heal => $self->{self_heal} ) : (),
		);
		$self->{backend_obj}->init_backend;
	};
	if ($@) {
		$self->{perror}      = 1;
		$self->{error}       = 3;
		$self->{errorString} = 'Failed to init the backend... ' . $@;
		$self->warn;
	}

	# bring any persisted ban state back, dropping and unbanning whatever
	# expired while not running
	$self->_load_bans;

	return $self;
} ## end sub new

=head2 socket_path

Returns the path of the unix socket for this instance.

    my $socket_path = $kur->socket_path;

=cut

sub socket_path {
	my ($self) = @_;

	return $self->{run_base_dir} . '/kur/' . $self->{name} . '.sock';
}

=head2 pid_path

Returns the path of the PID file for this instance.

    my $pid_path = $kur->pid_path;

=cut

sub pid_path {
	my ($self) = @_;

	return $self->{run_base_dir} . '/kur/' . $self->{name} . '.pid';
}

=head2 state_path

Returns the path of the ban state CSV for this instance.

    my $state_path = $kur->state_path;

=cut

sub state_path {
	my ($self) = @_;

	return $self->{cache_base_dir} . '/kur.' . $self->{name} . '.csv';
}

=head2 start_server

Starts up the L<POE::Component::Server::JSONUnix> server for this instance,
calling $poe_kernel->run.

This should not be expected to return till the server is told to stop.

The socket is chmoded to 0600 given only the manager, running as the same
user, talks to it.

A ban sweeper is also started, which checks once a second for timed bans
that have expired and unbans them, and handles the periodic checkpointing
of the ban state CSV.

The JSON commands handled are as below.

    - ban :: Ban the IPs specified via the array args.ips. args.ban_time,
          if defined, overrides the instance default for how long the bans
          should last in seconds, with 0 meaning never time out. Banning a
          already banned IP just refreshes it's timer.

    - unban :: Check if the IP, args.ip, is banned and if so unban it.

    - banned :: Return a list of banned IPs along with a expires map of
          when each times out, 0 meaning never.

    - status :: Return instance status info and stats, including ban_time,
          counts of timed and permanent bans, and the next expiry.

    - flush :: Unban all currently banned IPs.

    - re_init :: Re-init the backend, re-banning everything.

    - checkpoint :: Write the ban state CSV out now.

    - stop :: Checkpoint, teardown the backend, and exit.

=cut

sub start_server {
	my ($self) = @_;

	$self->errorblank;

	my $ident = 'kur-' . $self->{name};

	my $server = POE::Component::Server::JSONUnix->spawn(
		'socket_path' => $self->socket_path,
		'socket_mode' => 0600,
		'alias'       => $ident,
		'on_error'    => sub {
			my ( $operation, $errnum, $errstr ) = @_;
			log_drek( 'err', 'socket error during ' . $operation . '... ' . $errstr . ' (' . $errnum . ')',
				undef, $ident );
		},
		'commands' => {
			'ban' => sub {
				my ( undef, $request ) = @_;
				return $self->_cmd_ban($request);
			},
			'unban' => sub {
				my ( undef, $request ) = @_;
				return $self->_cmd_unban($request);
			},
			'banned' => sub {
				return $self->_cmd_banned;
			},
			'status' => sub {
				return $self->_cmd_status;
			},
			'flush' => sub {
				return $self->_cmd_flush;
			},
			're_init' => sub {
				return $self->_cmd_re_init;
			},
			'checkpoint' => sub {
				return $self->_cmd_checkpoint;
			},
			'stop' => sub {
				my ( undef, undef, $ctx ) = @_;
				return $self->_cmd_stop($ctx);
			},
		},
	);

	$self->{server}  = $server;
	$self->{started} = time;

	# the ban sweeper... a self-rescheduling one second alarm that expires
	# timed bans and handles the periodic checkpoint... it stops
	# rescheduling once stop has been requested so the session ends and the
	# kernel can exit
	POE::Session->create(
		'inline_states' => {
			'_start' => sub {
				$_[KERNEL]->delay( 'sweep', 1 );
			},
			'sweep' => sub {
				if ( $self->{stopping} ) {
					return;
				}
				$self->_tick;
				$_[KERNEL]->delay( 'sweep', 1 );
			},
		},
	);

	log_drek( 'info', 'started... socket=' . $self->socket_path . ' backend=' . $self->{backend}, undef, $ident );

	$poe_kernel->run;

	log_drek( 'info', 'stopped', undef, $ident );

	return;
} ## end sub start_server

# calls the specified method on the backend object, dieing if it either dies
# or is left with the error set, as depending on the fatality settings in play
# Error::Helper may just warn instead of dieing
sub _backend_do {
	my ( $self, $method, %args ) = @_;

	my @results;
	eval { @results = $self->{backend_obj}->$method(%args); };
	if ($@) {
		die($@);
	}
	if ( $self->{backend_obj}->error ) {
		die( $self->{backend_obj}->errorString );
	}

	return @results;
} ## end sub _backend_do

sub _cmd_ban {
	my ( $self, $request ) = @_;

	my $args = $request->{args};
	if ( !defined($args) || ref( $args->{ips} ) ne 'ARRAY' || !@{ $args->{ips} } ) {
		die('args.ips must be a array of one or more IPs');
	}

	my $ban_time = $self->{ban_time};
	if ( defined( $args->{ban_time} ) ) {
		if ( ref( $args->{ban_time} ) ne '' || $args->{ban_time} !~ /^[0-9]+$/ ) {
			die('args.ban_time must be a non-negative int of seconds');
		}
		$ban_time = $args->{ban_time};
	}

	my $ident = 'kur-' . $self->{name};

	my $results = {};
	foreach my $ip ( @{ $args->{ips} } ) {
		my $expires = $ban_time ? time + $ban_time : 0;

		# already banned, so just refresh it's timer
		if ( defined( $self->{bans}{$ip} ) ) {
			$self->{bans}{$ip}{expires} = $expires;
			$results->{$ip} = { 'status' => 'ok', 'refreshed' => 1 };
			log_drek( 'info', 'refreshed ban of ' . $ip . ' expires=' . $expires, undef, $ident );
			next;
		}

		eval { $self->_backend_do( 'ban', ban => $ip ); };
		if ($@) {
			$self->{stats}{errors}++;
			$results->{$ip} = { 'status' => 'error', 'error' => $@ };
			log_drek( 'err', 'ban of "' . $ip . '" failed... ' . $@, undef, $ident );
		} else {
			$self->{stats}{bans}++;
			$self->{bans}{$ip} = { 'banned_at' => time, 'expires' => $expires };
			$results->{$ip} = { 'status' => 'ok' };
			log_drek( 'info', 'banned ' . $ip . ' expires=' . $expires, undef, $ident );
		}
	} ## end foreach my $ip ( @{ $args->{ips} } )

	$self->_checkpoint;

	return { 'ips' => $results };
} ## end sub _cmd_ban

sub _cmd_unban {
	my ( $self, $request ) = @_;

	my $args = $request->{args};
	if ( !defined($args) || !defined( $args->{ip} ) || ref( $args->{ip} ) ne '' ) {
		die('args.ip must be a IP');
	}
	my $ip = $args->{ip};

	# check if it is actually present before trying to unban it
	my @banned  = $self->_backend_do('list');
	my $present = grep { $_ eq $ip } @banned;
	if ( !$present ) {
		# make sure no stale timer is left behind either way
		if ( defined( delete( $self->{bans}{$ip} ) ) ) {
			$self->_checkpoint;
		}
		return { 'ip' => $ip, 'was_banned' => 0 };
	}

	$self->_backend_do( 'unban', ban => $ip );
	$self->{stats}{unbans}++;
	delete( $self->{bans}{$ip} );
	$self->_checkpoint;
	log_drek( 'info', 'unbanned ' . $ip, undef, 'kur-' . $self->{name} );

	return { 'ip' => $ip, 'was_banned' => 1 };
} ## end sub _cmd_unban

sub _cmd_banned {
	my ($self) = @_;

	my @banned = $self->_backend_do('list');

	my $expires = {};
	foreach my $ip ( keys( %{ $self->{bans} } ) ) {
		$expires->{$ip} = $self->{bans}{$ip}{expires};
	}

	return { 'banned' => \@banned, 'expires' => $expires };
} ## end sub _cmd_banned

sub _cmd_status {
	my ($self) = @_;

	my @banned = $self->_backend_do('list');

	my $timed       = 0;
	my $permanent   = 0;
	my $next_expiry = 0;
	foreach my $ip ( keys( %{ $self->{bans} } ) ) {
		if ( $self->{bans}{$ip}{expires} ) {
			$timed++;
			if ( !$next_expiry || $self->{bans}{$ip}{expires} < $next_expiry ) {
				$next_expiry = $self->{bans}{$ip}{expires};
			}
		} else {
			$permanent++;
		}
	} ## end foreach my $ip ( keys( %{ $self->{bans} } ) )

	return {
		'name'            => $self->{name},
		'backend'         => $self->{backend},
		'ports'           => $self->{ports},
		'protocols'       => $self->{protocols},
		'prefix'          => $self->{prefix},
		'ban_time'        => $self->{ban_time},
		'checkpoint'      => $self->{checkpoint},
		'last_checkpoint' => $self->{last_checkpoint},
		'pid'             => $$,
		'uptime'          => time - $self->{started},
		'stats'           => $self->{stats},
		'banned_count'    => scalar(@banned),
		'bans_timed'      => $timed,
		'bans_permanent'  => $permanent,
		'next_expiry'     => $next_expiry,
	};
} ## end sub _cmd_status

sub _cmd_flush {
	my ($self) = @_;

	$self->_backend_do('flush');
	$self->{bans} = {};
	$self->_checkpoint;
	log_drek( 'info', 'flushed all bans', undef, 'kur-' . $self->{name} );

	return { 'flushed' => 1 };
} ## end sub _cmd_flush

sub _cmd_re_init {
	my ($self) = @_;

	$self->_backend_do('re_init');
	log_drek( 'info', 're_init done', undef, 'kur-' . $self->{name} );

	return { 're_init' => 1 };
}

sub _cmd_checkpoint {
	my ($self) = @_;

	$self->_checkpoint;
	log_drek( 'info', 'checkpointed', undef, 'kur-' . $self->{name} );

	return { 'checkpointed' => 1, 'bans' => scalar( keys( %{ $self->{bans} } ) ) };
}

sub _cmd_stop {
	my ( $self, $ctx ) = @_;

	my $ident = 'kur-' . $self->{name};

	log_drek( 'info', 'stop requested, tearing the backend down', undef, $ident );

	# keeps the ban sweeper from rescheduling so it's session can end
	$self->{stopping} = 1;

	# leave a fresh state CSV behind
	$self->_checkpoint;

	eval { $self->_backend_do('teardown'); };
	my $teardown_error = $@;
	if ($teardown_error) {
		log_drek( 'err', 'teardown failed... ' . $teardown_error, undef, $ident );
	}

	$ctx->respond_result( { 'stopping' => 1, $teardown_error ? ( 'teardown_error' => $teardown_error ) : () } );
	$ctx->close;

	# the current session is the JSONUnix server session, so this fires its
	# shutdown state after the response has had time to flush
	$poe_kernel->delay( 'shutdown', 1 );

	return undef;
} ## end sub _cmd_stop

# ran once a second by the sweeper session... expires timed bans and
# handles the periodic checkpoint
sub _tick {
	my ($self) = @_;

	$self->_sweep_bans;

	if ( $self->{checkpoint} && ( time - $self->{last_checkpoint} ) >= $self->{checkpoint} ) {
		$self->_checkpoint;
	}

	return;
} ## end sub _tick

# unbans timed bans that have expired... ran once a second via the sweeper
# session started by start_server
sub _sweep_bans {
	my ($self) = @_;

	my $ident   = 'kur-' . $self->{name};
	my $now     = time;
	my $changed = 0;

	foreach my $ip ( keys( %{ $self->{bans} } ) ) {
		my $entry = $self->{bans}{$ip};
		if ( !$entry->{expires} || $entry->{expires} > $now ) {
			next;
		}

		eval { $self->_backend_do( 'unban', ban => $ip ); };
		if ($@) {
			$self->{stats}{errors}++;
			log_drek( 'err', 'unbanning expired ban of "' . $ip . '" failed... ' . $@, undef, $ident );
		}
		delete( $self->{bans}{$ip} );
		$self->{stats}{expired}++;
		$changed = 1;
		log_drek( 'info', 'ban of ' . $ip . ' expired', undef, $ident );
	} ## end foreach my $ip ( keys( %{ $self->{bans} } ) )

	if ($changed) {
		$self->_checkpoint;
	}

	return;
} ## end sub _sweep_bans

# checkpoints the ban state as a CSV of ip,time,ban_time_left to the state
# file under the cache dir, atomically via a temp file and rename
sub _checkpoint {
	my ($self) = @_;

	my $state_file = $self->state_path;
	my $now        = time;
	eval {
		my $tmp = $state_file . '.tmp';
		open( my $fh, '>', $tmp ) || die( 'open failed... ' . $! );
		print $fh "ip,time,ban_time_left\n";
		foreach my $ip ( sort( keys( %{ $self->{bans} } ) ) ) {
			my $left = 0;
			if ( $self->{bans}{$ip}{expires} ) {
				$left = $self->{bans}{$ip}{expires} - $now;
				# clamped so a nearly expired ban can't collide with 0 meaning
				# permanent... anything actually expired is the sweeper's job
				if ( $left < 1 ) {
					$left = 1;
				}
			}
			print $fh $ip . ',' . $now . ',' . $left . "\n";
		} ## end foreach my $ip ( sort( keys( %{ $self->{bans} }...)))
		close($fh);
		rename( $tmp, $state_file ) || die( 'rename failed... ' . $! );
	};
	if ($@) {
		log_drek( 'err', 'checkpointing ban state to "' . $state_file . '" failed... ' . $@,
			undef, 'kur-' . $self->{name} );
		return;
	}

	$self->{last_checkpoint} = $now;

	return;
} ## end sub _checkpoint

# loads the persisted ban state CSV... the time in each row is compared to
# the current time for figuring out if the ban should be restored or not...
# entries that expired while not running are unbanned in case the backend
# still carries the rule, the rest are re-banned so the freshly inited
# backend carries them again
sub _load_bans {
	my ($self) = @_;

	my $state_file = $self->state_path;
	if ( !-f $state_file ) {
		return;
	}

	my $ident = 'kur-' . $self->{name};

	my @lines;
	eval {
		open( my $fh, '<', $state_file ) || die( 'open failed... ' . $! );
		@lines = <$fh>;
		close($fh);
	};
	if ($@) {
		log_drek( 'err', 'loading ban state from "' . $state_file . '" failed... ' . $@, undef, $ident );
		return;
	}

	my $now         = time;
	my $line_number = 0;
	foreach my $line (@lines) {
		$line_number++;
		chomp($line);
		if ( $line eq '' ) {
			next;
		}
		if ( $line_number == 1 && $line =~ /^ip,/ ) {
			# the header
			next;
		}

		my @row = split( /,/, $line );
		if ( @row != 3 || $row[0] eq '' || $row[1] !~ /^[0-9]+$/ || $row[2] !~ /^[0-9]+$/ ) {
			log_drek( 'err', 'skipping malformed line ' . $line_number . ' in "' . $state_file . '"... "' . $line . '"',
				undef, $ident );
			next;
		}
		my ( $ip, $written, $left ) = @row;

		my $expires = $left ? $written + $left : 0;

		if ( $expires && $expires <= $now ) {
			# expired while not running... the backend may still carry the rule
			eval { $self->{backend_obj}->unban( ban => $ip ); };
			$self->{stats}{expired}++;
			log_drek( 'info', 'ban of ' . $ip . ' expired while not running', undef, $ident );
			next;
		}

		eval { $self->_backend_do( 'ban', ban => $ip ); };
		if ($@) {
			log_drek( 'err', 're-banning "' . $ip . '" from saved state failed... ' . $@, undef, $ident );
		}
		# banned_at is not persisted, so the row's time stands in for it
		$self->{bans}{$ip} = { 'banned_at' => $written, 'expires' => $expires };
	} ## end foreach my $line (@lines)

	# write a updated one back out so the file reflects what got restored
	$self->_checkpoint;

	return;
} ## end sub _load_bans

=head1 ERRORS CODES / ERROR FLAGS

Error handling is provided by L<Error::Helper>. All errors
are considered fatal.

=head2 1, NErunBaseDir

The run base dir or the kur dir under it does not exist or is not a directory.

=head2 2, invalidName

Name not defined or does not match /^[a-zA-Z0-9\-]+$/.

=head2 3, backendInitFailed

Failed to initialize the backend.

=head2 4, nonRWrunBaseDir

The run base dir or the kur dir under it is not readable or writable by the
current user.

=head2 5, NEcacheBaseDir

The cache base dir does not exist or is not a directory.

=head2 6, nonRWcacheBaseDir

The cache base dir or the kur dir under it is not readable or writable by
the current user.

=head2 7, invalidBanTime

ban_time is not a non-negative int of seconds.

=head2 8, invalidCheckpoint

checkpoint is not a non-negative int of seconds.

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
