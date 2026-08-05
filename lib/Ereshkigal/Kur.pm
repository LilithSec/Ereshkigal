package Ereshkigal::Kur;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use POE;
use POE::Component::Server::JSONUnix ();
use Net::Firewall::BlockerHelper     ();
use Ereshkigal::LogDrek              qw( log_drek );
use Ereshkigal::IP                   qw( normalize_ip normalize_cidr );

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

    - enable_cidr :: Boolean for whether CIDR banning is enabled for this
          instance. Even when set, CIDR commands only work if the backend
          supports CIDR bans. The strings true/false/yes/no/on/off are
          accepted alongside 1/0.
        Default :: 0

    - cidr_silent_drop :: Boolean for how a CIDR command is handled when CIDR
          banning is not available for this instance, either because
          enable_cidr is off or the backend does not support it. When set the
          command is silently dropped, returning dropped => 1, rather than
          erroring, which is the point of contact when fanning out to a mix of
          CIDR capable and incapable instances.
        Default :: 0

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
			all_fatal        => 1,
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
		name               => undef,
		backend            => undef,
		ports              => [],
		protocols          => [],
		prefix             => undef,
		options            => undef,
		self_heal          => undef,
		ban_time           => 600,
		checkpoint         => 60,
		enable_cidr        => 0,
		cidr_silent_drop   => 0,
		run_base_dir       => '/var/run/ereshkigal',
		cache_base_dir     => '/var/cache/ereshkigal',
		backend_obj        => undef,
		cidr_supported     => 0,
		server             => undef,
		started            => undef,
		stopping           => 0,
		bans               => {},
		cidr_bans          => {},
		unban_retries      => {},
		cidr_unban_retries => {},
		last_checkpoint    => 0,
		stats              => {
			bans         => 0,
			unbans       => 0,
			cidr_bans    => 0,
			cidr_unbans  => 0,
			errors       => 0,
			expired      => 0,
			cidr_expired => 0,
		},
	};
	bless $self;

	my @to_merge = (
		'name',       'backend',     'ports',            'protocols',
		'prefix',     'options',     'self_heal',        'ban_time',
		'checkpoint', 'enable_cidr', 'cidr_silent_drop', 'run_base_dir',
		'cache_base_dir'
	);
	foreach my $item (@to_merge) {
		if ( defined( $opts{$item} ) ) {
			$self->{$item} = $opts{$item};
		}
	}

	# the two CIDR toggles are booleans... a config may hand them over as the
	# literal strings true/false, which are both truthy in Perl, so those are
	# folded down before the truthiness of the value is trusted
	foreach my $toggle ( 'enable_cidr', 'cidr_silent_drop' ) {
		if ( !defined( $self->{$toggle} ) || $self->{$toggle} =~ /\A(?:|0|false|no|off)\z/i ) {
			$self->{$toggle} = 0;
		} else {
			$self->{$toggle} = 1;
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

	# note whether the backend can carry CIDR bans... enable_cidr is the
	# operator opting in, but a backend that can not do CIDR still can not, so
	# the two together are what gate the CIDR commands
	$self->{cidr_supported} = $self->_backend_cidr_supported;
	if ( $self->{enable_cidr} && !$self->{cidr_supported} ) {
		log_drek(
			'warning',
			'enable_cidr is set but the "'
				. $self->{backend}
				. '" backend does not support CIDR bans... CIDR commands will be refused',
			undef,
			'kur-' . ( defined( $self->{name} ) ? $self->{name} : '' )
		);
	} ## end if ( $self->{enable_cidr} && !$self->{cidr_supported...})

	# bring any persisted ban state back, dropping and unbanning whatever
	# expired while not running
	$self->_load_bans;
	$self->_load_cidr_bans;
	$self->_load_retries;

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

=head2 cidr_state_path

Returns the path of the CIDR ban state CSV for this instance. This is kept
separate from L</state_path> so the single IP state format stays untouched.

    my $cidr_state_path = $kur->cidr_state_path;

=cut

sub cidr_state_path {
	my ($self) = @_;

	return $self->{cache_base_dir} . '/kur.' . $self->{name} . '.cidr.csv';
}

=head2 retry_state_path

Returns the path of the unban retry state CSV for this instance, the tablet
carrying entries whose unban at expiry failed and is still owed to the
firewall.

    my $retry_state_path = $kur->retry_state_path;

=cut

sub retry_state_path {
	my ($self) = @_;

	return $self->{cache_base_dir} . '/kur.' . $self->{name} . '.retry.csv';
}

=head2 cidr_retry_state_path

Returns the path of the CIDR unban retry state CSV for this instance, the
CIDR counterpart of L</retry_state_path>.

    my $cidr_retry_state_path = $kur->cidr_retry_state_path;

=cut

sub cidr_retry_state_path {
	my ($self) = @_;

	return $self->{cache_base_dir} . '/kur.' . $self->{name} . '.cidr.retry.csv';
}

=head2 start_server

Starts up the L<POE::Component::Server::JSONUnix> server for this instance,
calling $poe_kernel->run.

This should not be expected to return till the server is told to stop.

The socket is chmoded to 0600 given only the manager, running as the same
user, talks to it.

A ban sweeper is also started, which checks once a second for timed bans
that have expired and unbans them, and handles the periodic checkpointing
of the ban state CSVs. SIGTERM and SIGINT are handled, checkpointing and
tearing the backend down the same as the stop command before exiting.

IPs passed to ban and unban are validated and normalized to their canonical
string form, so variant spellings of the same IP, most notably IPv6 long
form vs short form as well as case, are all treated as the same IP. For ban
anything failing to validate errors per IP with out disturbing the rest of
the request, while for unban it is fatal to the request.

The JSON commands handled are as below.

    - ban :: Ban the IPs specified via the array args.ips. args.ban_time,
          if defined, overrides the instance default for how long the bans
          should last in seconds, with 0 meaning never time out. Banning a
          already banned IP just refreshes it's timer.

    - unban :: Check if the IP, args.ip, is banned and if so unban it.

    - cidr_ban :: Ban the CIDR ranges specified via the array args.cidrs,
          otherwise behaving like ban. Only handled when enable_cidr is set
          and the backend supports CIDR bans, otherwise it is either dropped
          or refused per cidr_silent_drop.

    - cidr_unban :: Check if the CIDR, args.cidr, is banned and if so unban
          it. Gated the same as cidr_ban.

    - banned :: Return a list of banned IPs along with a expires map of
          when each times out, 0 meaning never. banned_cidr and cidr_expires
          carry the same for CIDR bans. unban_retries and cidr_unban_retries
          carry the per entry book keeping for unbans still owed to the
          firewall.

    - status :: Return instance status info and stats, including ban_time,
          counts of timed and permanent bans, the next expiry, and how many
          unbans are still owed to the firewall along with how long the
          longest owed has been outstanding.

    - flush :: Unban all currently banned IPs.

    - re_init :: Re-init the backend, re-banning everything.

    - checkpoint :: Write the ban state CSVs out now.

    - clear_retries :: Forget unbans still owed to the firewall, either the
          single one named by args.ip or args.cidr, or all of them when
          neither is given. Only the book keeping is forgotten, nothing is
          asked of the firewall, so anything genuinely still banished there
          stays that way.

    - stop :: Checkpoint, teardown the backend, and exit.

=cut

sub start_server {
	my ($self) = @_;

	$self->errorblank;

	my $ident = 'kur-' . $self->{name};

	my $server = POE::Component::Server::JSONUnix->spawn(
		'socket_path' => $self->socket_path,
		'socket_mode' => oct('0600'),
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
			'cidr_ban' => sub {
				my ( undef, $request ) = @_;
				return $self->_cmd_cidr_ban($request);
			},
			'cidr_unban' => sub {
				my ( undef, $request ) = @_;
				return $self->_cmd_cidr_unban($request);
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
			'clear_retries' => sub {
				my ( undef, $request ) = @_;
				return $self->_cmd_clear_retries($request);
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
	# kernel can exit... it also watches for TERM/INT so a signaled kur
	# still checkpoints and tears the backend down rather than dying with
	# the firewall state dangling
	POE::Session->create(
		'inline_states' => {
			'_start' => sub {
				$_[KERNEL]->sig( 'TERM', 'sig_shutdown' );
				$_[KERNEL]->sig( 'INT',  'sig_shutdown' );
				$_[KERNEL]->delay( 'sweep', 1 );
			},
			'sweep' => sub {
				if ( $self->{stopping} ) {
					return;
				}
				$self->_tick;
				$_[KERNEL]->delay( 'sweep', 1 );
			},
			'sig_shutdown' => sub {
				my $signal = $_[ARG0];
				$_[KERNEL]->sig_handled;
				if ( $self->{stopping} ) {
					return;
				}
				log_drek( 'info', 'SIG' . $signal . ' received, tearing the backend down', undef, $ident );
				$self->_stop_guts;
				# _stop_guts set stopping, so the pending sweep alarm is the
				# only thing keeping this session alive... clear it and fire
				# the server session's shutdown so the kernel can exit
				$_[KERNEL]->delay('sweep');
				$_[KERNEL]->post( $ident, 'shutdown' );
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

# the per family knobs the shared ban/unban/sweep/load helpers use... the
# single IP and CIDR paths are identical beyond these
my %family_spec = (
	'ip' => {
		'noun'             => 'IP',
		'label'            => 'ip',
		'log_label'        => 'ban',
		'infix'            => '',
		'normalizer'       => \&normalize_ip,
		'ban_method'       => 'ban',
		'unban_method'     => 'unban',
		'list_method'      => 'list',
		'hash'             => 'bans',
		'retry_hash'       => 'unban_retries',
		'ban_stat'         => 'bans',
		'unban_stat'       => 'unbans',
		'expired_stat'     => 'expired',
		'checkpoint'       => '_checkpoint',
		'retry_checkpoint' => '_checkpoint_retries',
		'retry_path'       => 'retry_state_path',
		'retry_arg'        => 'ip',
	},
	'cidr' => {
		'noun'             => 'CIDR',
		'label'            => 'cidr',
		'log_label'        => 'cidr ban',
		'infix'            => 'cidr ',
		'normalizer'       => \&normalize_cidr,
		'ban_method'       => 'ban_cidr',
		'unban_method'     => 'unban_cidr',
		'list_method'      => 'list_cidr',
		'hash'             => 'cidr_bans',
		'retry_hash'       => 'cidr_unban_retries',
		'ban_stat'         => 'cidr_bans',
		'unban_stat'       => 'cidr_unbans',
		'expired_stat'     => 'cidr_expired',
		'checkpoint'       => '_checkpoint_cidr',
		'retry_checkpoint' => '_checkpoint_cidr_retries',
		'retry_path'       => 'cidr_retry_state_path',
		'retry_arg'        => 'cidr',
	},
);

# refuses backend-mutating commands once stop has been requested... the
# backend is torn down at that point, and anything landing in the window
# before the server session shuts down would both fail against it and
# overwrite the fresh final tablet stop just left behind
sub _refuse_when_stopping {
	my ($self) = @_;

	if ( $self->{stopping} ) {
		die('this kur is stopping');
	}

	return;
}

# resolves the effective ban_time for a ban request, the instance default
# unless the request carries its own, dieing if the carried one is invalid
sub _resolve_ban_time {
	my ( $self, $args ) = @_;

	if ( !defined( $args->{ban_time} ) ) {
		return $self->{ban_time};
	}
	if ( ref( $args->{ban_time} ) ne '' || $args->{ban_time} !~ /^[0-9]+$/ ) {
		die('args.ban_time must be a non-negative int of seconds');
	}

	return $args->{ban_time};
} ## end sub _resolve_ban_time

# gives self_heal its chance on the refresh path... a refresh does not go
# through the backend's ban, which is where self_heal normally hooks in, and
# refresh heavy traffic is the common case for ban sources, so the
# check-and-re_init half is ran here so a swept away setup still gets
# noticed and rebuilt... best effort, a failure here is the next real ban's
# problem
sub _refresh_heal {
	my ($self) = @_;

	my $self_heal = defined( $self->{self_heal} ) ? ( $self->{self_heal} ? 1 : 0 ) : 1;
	if ( !$self_heal ) {
		return;
	}

	my $healthy;
	eval { ($healthy) = $self->_backend_do('check'); };
	if ( !$@ && !$healthy ) {
		eval { $self->_backend_do('re_init'); };
		if ($@) {
			log_drek( 'err', 're_init during refresh self heal failed... ' . $@, undef, 'kur-' . $self->{name} );
		} else {
			# re_init re-bans only what the book carries, so anything pending
			# a unban retry is no longer in the firewall
			$self->{unban_retries}      = {};
			$self->{cidr_unban_retries} = {};
			$self->_checkpoint_retries;
			$self->_checkpoint_cidr_retries;
		}
	} ## end if ( !$@ && !$healthy )

	return;
} ## end sub _refresh_heal

# the shared loop body of _cmd_ban and _cmd_cidr_ban... validates and
# normalizes each entry, refreshes the timer of anything already banned, and
# bans the rest via the backend, returning the per entry results hash
#
# $entries is the raw args.ips or args.cidrs arrayref straight from the
# request, $ban_time the effective seconds from _resolve_ban_time, and $spec
# the matching %family_spec entry, ip or cidr, supplying the normalizer
# along with the backend ban method, ban hash, and stats keys
sub _ban_many {
	my ( $self, $entries, $ban_time, $spec ) = @_;

	my $ident = 'kur-' . $self->{name};

	my $results = {};
	foreach my $raw_entry ( @{$entries} ) {
		# bounced here rather than left for the backend to judge, given the
		# backend accepts ambiguous stuff like leading zero octet IPv4, and
		# reduced to the canonical form so variant spellings dedupe
		my $entry = $spec->{normalizer}->($raw_entry);
		if ( !defined($entry) ) {
			my $key = defined($raw_entry) ? $raw_entry : '';
			$self->{stats}{errors}++;
			$results->{$key} = {
				'status' => 'error',
				'error'  => '"' . $key . '" does not appear to be a IPv4 or IPv6 ' . $spec->{noun}
			};
			log_drek(
				'err',
				$spec->{log_label} . ' of "'
					. $key
					. '" failed... does not appear to be a IPv4 or IPv6 '
					. $spec->{noun},
				undef,
				$ident
			);
			next;
		} ## end if ( !defined($entry) )
		my $expires = $ban_time ? time + $ban_time : 0;

		# already banned, so just refresh it's timer... the backend ban is
		# not re-ran, as not every backend takes re-adding an existing entry
		# gracefully, but self_heal still gets its chance via _refresh_heal
		if ( defined( $self->{ $spec->{hash} }{$entry} ) ) {
			$self->_refresh_heal;
			$self->{ $spec->{hash} }{$entry}{expires} = $expires;
			$results->{$entry} = { 'status' => 'ok', 'refreshed' => 1 };
			log_drek( 'info', 'refreshed ' . $spec->{log_label} . ' of ' . $entry . ' expires=' . $expires,
				undef, $ident );
			next;
		}

		# a pending unban retry means the firewall still carries it, so the
		# backend is not asked to re-add what it already has... the retry is
		# cancelled and the entry booked fresh
		if ( defined( $self->{ $spec->{retry_hash} }{$entry} ) ) {
			delete( $self->{ $spec->{retry_hash} }{$entry} );
			my $retry_checkpoint_method = $spec->{retry_checkpoint};
			$self->$retry_checkpoint_method;
			$self->{stats}{ $spec->{ban_stat} }++;
			$self->{ $spec->{hash} }{$entry} = { 'banned_at' => time, 'expires' => $expires };
			$results->{$entry} = { 'status' => 'ok' };
			log_drek( 'info',
				'banned ' . $spec->{infix} . $entry . ' expires=' . $expires . ', cancelling pending unban retry',
				undef, $ident );
			next;
		} ## end if ( defined( $self->{ $spec->{retry_hash}...}))

		my $ban_method = $spec->{ban_method};
		eval { $self->_backend_do( $ban_method, ban => $entry ); };
		if ($@) {
			$self->{stats}{errors}++;
			$results->{$entry} = { 'status' => 'error', 'error' => $@ };
			log_drek( 'err', $spec->{log_label} . ' of "' . $entry . '" failed... ' . $@, undef, $ident );
		} else {
			$self->{stats}{ $spec->{ban_stat} }++;
			$self->{ $spec->{hash} }{$entry} = { 'banned_at' => time, 'expires' => $expires };
			$results->{$entry} = { 'status' => 'ok' };
			log_drek( 'info', 'banned ' . $spec->{infix} . $entry . ' expires=' . $expires, undef, $ident );
		}
	} ## end foreach my $raw_entry ( @{$entries} )

	return $results;
} ## end sub _ban_many

# the shared body of _cmd_unban and _cmd_cidr_unban... checks presence via
# the backend, unbans when present, and keeps the book and tablet straight
# either way, returning whether it was actually banned
#
# $entry is a single IP or CIDR, already normalized by the caller having ran
# the request arg through the family normalizer, and $spec is the matching
# %family_spec entry, ip or cidr, supplying the normalizer along with the
# backend list/unban methods, ban hash, stats keys, and checkpoint method
sub _unban_one {
	my ( $self, $entry, $spec ) = @_;

	my $checkpoint_method = $spec->{checkpoint};

	# check if it is actually present before trying to unban it... what the
	# backend lists back is compared in normalized form, as a firewall may
	# well render an entry differently to how it was handed over, IPv6
	# especially, and that spelling is what it wants back to remove it
	my @banned = $self->_backend_do( $spec->{list_method} );
	my $present;
	foreach my $banned_entry (@banned) {
		my $normalized = $spec->{normalizer}->($banned_entry);
		if ( ( defined($normalized) ? $normalized : $banned_entry ) eq $entry ) {
			$present = $banned_entry;
			last;
		}
	}
	if ( !defined($present) ) {
		# make sure no stale timer is left behind either way
		if ( defined( delete( $self->{ $spec->{hash} }{$entry} ) ) ) {
			$self->$checkpoint_method;
		}
		return 0;
	}

	# unbanned via the spelling the backend book actually carries, which for
	# anything banned by this process is the canonical form anyway
	eval { $self->_backend_do( $spec->{unban_method}, ban => $present ); };
	if ($@) {
		$self->{stats}{errors}++;
		die($@);
	}
	$self->{stats}{ $spec->{unban_stat} }++;
	# the book and the retry list are both keyed by the canonical form, that
	# being the only form either ever carries, so the backend's spelling is
	# not a key to worry about here... a pending unban retry is now moot
	delete( $self->{ $spec->{hash} }{$entry} );
	if ( defined( delete( $self->{ $spec->{retry_hash} }{$entry} ) ) ) {
		my $retry_checkpoint_method = $spec->{retry_checkpoint};
		$self->$retry_checkpoint_method;
	}
	$self->$checkpoint_method;
	log_drek( 'info', 'unbanned ' . $spec->{infix} . $entry, undef, 'kur-' . $self->{name} );

	return 1;
} ## end sub _unban_one

# handles the ban command... bans or refreshes each of args.ips via
# _ban_many, with args.ban_time optionally overriding the instance default,
# then checkpoints the lot to the tablet in one go
sub _cmd_ban {
	my ( $self, $request ) = @_;

	$self->_refuse_when_stopping;

	my $args = $request->{args};
	if ( !defined($args) || ref( $args->{ips} ) ne 'ARRAY' || !@{ $args->{ips} } ) {
		die('args.ips must be a array of one or more IPs');
	}

	my $results = $self->_ban_many( $args->{ips}, $self->_resolve_ban_time($args), $family_spec{ip} );

	$self->_checkpoint;

	return { 'ips' => $results };
} ## end sub _cmd_ban

# handles the unban command... normalizes args.ip and hands it to
# _unban_one, returning the canonical IP and whether it was actually banned
sub _cmd_unban {
	my ( $self, $request ) = @_;

	$self->_refuse_when_stopping;

	my $args = $request->{args};
	if ( !defined($args) || !defined( $args->{ip} ) || ref( $args->{ip} ) ne '' ) {
		die('args.ip must be a IP');
	}
	my $ip = normalize_ip( $args->{ip} );
	if ( !defined($ip) ) {
		die( 'args.ip, "' . $args->{ip} . '", does not appear to be a IPv4 or IPv6 IP' );
	}

	return { 'ip' => $ip, 'was_banned' => $self->_unban_one( $ip, $family_spec{ip} ) };
} ## end sub _cmd_unban

# reaches through the frontend to the actual backend object to see if it
# claims CIDR support, mirroring how the frontend its self gates ban_cidr...
# anything missing is treated as no support rather than dieing
sub _backend_cidr_supported {
	my ($self) = @_;

	my $frontend = $self->{backend_obj};
	if ( !defined($frontend) || ref($frontend) eq '' ) {
		return 0;
	}
	my $backend = $frontend->{backend_obj};
	if ( !defined($backend) || ref($backend) eq '' ) {
		return 0;
	}

	return $backend->{cidr_supported} ? 1 : 0;
} ## end sub _backend_cidr_supported

# whether this instance will actually act on CIDR commands... the operator has
# to have opted in via enable_cidr and the backend has to be able to do it
sub _cidr_available {
	my ($self) = @_;

	return ( $self->{enable_cidr} && $self->{cidr_supported} ) ? 1 : 0;
}

# decides what to do with a CIDR command when CIDR is not available... returns
# undef to say carry on, a dropped response hashref when cidr_silent_drop is
# set, or dies otherwise so the refusal is reported
sub _cidr_guard {
	my ($self) = @_;

	if ( $self->_cidr_available ) {
		return undef;
	}

	my $reason;
	if ( !$self->{enable_cidr} ) {
		$reason = 'CIDR bans are not enabled for this kur';
	} else {
		$reason = 'the "' . $self->{backend} . '" backend does not support CIDR bans';
	}

	if ( $self->{cidr_silent_drop} ) {
		log_drek( 'info', 'dropping CIDR command... ' . $reason, undef, 'kur-' . $self->{name} );
		return { 'dropped' => 1, 'reason' => $reason };
	}

	die($reason);
} ## end sub _cidr_guard

# the CIDR twin of _cmd_ban... _cidr_guard gets first say, then each of
# args.cidrs is banned or refreshed via _ban_many and the CIDR tablet
# checkpointed in one go
sub _cmd_cidr_ban {
	my ( $self, $request ) = @_;

	$self->_refuse_when_stopping;

	my $args = $request->{args};
	if ( !defined($args) ) {
		$args = {};
	}

	# the guard comes first so a dropping or incapable instance short circuits
	# regardless of the payload... a capable one falls through and validates
	my $drop = $self->_cidr_guard;
	if ( defined($drop) ) {
		return $drop;
	}

	if ( ref( $args->{cidrs} ) ne 'ARRAY' || !@{ $args->{cidrs} } ) {
		die('args.cidrs must be a array of one or more CIDRs');
	}

	my $results = $self->_ban_many( $args->{cidrs}, $self->_resolve_ban_time($args), $family_spec{cidr} );

	$self->_checkpoint_cidr;

	return { 'cidrs' => $results };
} ## end sub _cmd_cidr_ban

# the CIDR twin of _cmd_unban... _cidr_guard gets first say, then args.cidr
# is normalized and handed to _unban_one
sub _cmd_cidr_unban {
	my ( $self, $request ) = @_;

	$self->_refuse_when_stopping;

	my $args = $request->{args};
	if ( !defined($args) ) {
		$args = {};
	}

	my $drop = $self->_cidr_guard;
	if ( defined($drop) ) {
		return $drop;
	}

	if ( !defined( $args->{cidr} ) || ref( $args->{cidr} ) ne '' ) {
		die('args.cidr must be a CIDR');
	}
	my $cidr = normalize_cidr( $args->{cidr} );
	if ( !defined($cidr) ) {
		die( 'args.cidr, "' . $args->{cidr} . '", does not appear to be a IPv4 or IPv6 CIDR' );
	}

	return { 'cidr' => $cidr, 'was_banned' => $self->_unban_one( $cidr, $family_spec{cidr} ) };
} ## end sub _cmd_cidr_unban

# handles the banned command... returns what the backend book actually
# carries for both single IPs and CIDRs, plus the expiry times the ban
# hashes are tracking for them
sub _cmd_banned {
	my ($self) = @_;

	my @banned = $self->_backend_do('list');

	my $expires = {};
	foreach my $ip ( keys( %{ $self->{bans} } ) ) {
		$expires->{$ip} = $self->{bans}{$ip}{expires};
	}

	# list_cidr is safe on every backend, returning empty on the ones that do
	# not do CIDR, so there is no need to gate this on _cidr_available
	my @banned_cidr = $self->_backend_do('list_cidr');

	my $cidr_expires = {};
	foreach my $cidr ( keys( %{ $self->{cidr_bans} } ) ) {
		$cidr_expires->{$cidr} = $self->{cidr_bans}{$cidr}{expires};
	}

	return {
		'banned'             => \@banned,
		'expires'            => $expires,
		'banned_cidr'        => \@banned_cidr,
		'cidr_expires'       => $cidr_expires,
		'unban_retries'      => $self->_retry_details( $family_spec{ip} ),
		'cidr_unban_retries' => $self->_retry_details( $family_spec{cidr} ),
	};
} ## end sub _cmd_banned

# the per entry retry book keeping for that family, as a plain hash of entry
# to it's counts and times... these are unbans still owed to the firewall, so
# they are deliberately not folded into the banned lists, which are what the
# firewall is currently carrying on this kur's behalf
sub _retry_details {
	my ( $self, $spec ) = @_;

	my $details = {};
	foreach my $entry ( keys( %{ $self->{ $spec->{retry_hash} } } ) ) {
		my $retry = $self->{ $spec->{retry_hash} }{$entry};
		$details->{$entry} = {
			'first_tried' => $retry->{first_tried},
			'last_tried'  => $retry->{last_tried},
			'times_tried' => $retry->{times_tried},
			'next_try'    => $retry->{next_try},
		};
	}

	return $details;
} ## end sub _retry_details

# the first_tried of the longest owed retry for that family, 0 when none are
# owed... the age of that is what says whether the backend is briefly
# unhappy or has been refusing since last week
sub _retries_oldest {
	my ( $self, $spec ) = @_;

	my $oldest = 0;
	foreach my $entry ( keys( %{ $self->{ $spec->{retry_hash} } } ) ) {
		my $first_tried = $self->{ $spec->{retry_hash} }{$entry}{first_tried};
		if ( !$oldest || $first_tried < $oldest ) {
			$oldest = $first_tried;
		}
	}

	return $oldest;
} ## end sub _retries_oldest

# handles the status command... the instance settings and stats plus ban
# counts from the backend and ban hashes, split timed versus permanent, with
# the soonest expiry across both families
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

	my @banned_cidr    = $self->_backend_do('list_cidr');
	my $cidr_timed     = 0;
	my $cidr_permanent = 0;
	foreach my $cidr ( keys( %{ $self->{cidr_bans} } ) ) {
		if ( $self->{cidr_bans}{$cidr}{expires} ) {
			$cidr_timed++;
			if ( !$next_expiry || $self->{cidr_bans}{$cidr}{expires} < $next_expiry ) {
				$next_expiry = $self->{cidr_bans}{$cidr}{expires};
			}
		} else {
			$cidr_permanent++;
		}
	} ## end foreach my $cidr ( keys( %{ $self->{cidr_bans} ...}))

	return {
		'name'                => $self->{name},
		'backend'             => $self->{backend},
		'ports'               => $self->{ports},
		'protocols'           => $self->{protocols},
		'prefix'              => $self->{prefix},
		'ban_time'            => $self->{ban_time},
		'checkpoint'          => $self->{checkpoint},
		'last_checkpoint'     => $self->{last_checkpoint},
		'pid'                 => $$,
		'uptime'              => time - $self->{started},
		'stats'               => $self->{stats},
		'banned_count'        => scalar(@banned),
		'bans_timed'          => $timed,
		'bans_permanent'      => $permanent,
		'next_expiry'         => $next_expiry,
		'cidr_enabled'        => $self->{enable_cidr},
		'cidr_supported'      => $self->{cidr_supported},
		'cidr_banned_count'   => scalar(@banned_cidr),
		'cidr_bans_timed'     => $cidr_timed,
		'cidr_bans_permanent' => $cidr_permanent,
		# unbans that failed at expiry and are still owed to the firewall...
		# oldest is the first_tried of the longest owed, so a operator can
		# tell a blip from something wedged with out asking for banned
		'unban_retries'             => scalar( keys( %{ $self->{unban_retries} } ) ),
		'unban_retries_oldest'      => $self->_retries_oldest( $family_spec{ip} ),
		'cidr_unban_retries'        => scalar( keys( %{ $self->{cidr_unban_retries} } ) ),
		'cidr_unban_retries_oldest' => $self->_retries_oldest( $family_spec{cidr} ),
	};
} ## end sub _cmd_status

# handles the flush command... clears everything via the backend, empties
# both ban hashes, and checkpoints both tablets
sub _cmd_flush {
	my ($self) = @_;

	$self->_refuse_when_stopping;

	# the backend flush clears both single IP and CIDR rules, so the CIDR
	# tracking is cleared and checkpointed alongside the single IP tracking,
	# and pending unban retries are moot
	$self->_backend_do('flush');
	$self->{bans}               = {};
	$self->{cidr_bans}          = {};
	$self->{unban_retries}      = {};
	$self->{cidr_unban_retries} = {};
	$self->_checkpoint;
	$self->_checkpoint_cidr;
	$self->_checkpoint_retries;
	$self->_checkpoint_cidr_retries;
	log_drek( 'info', 'flushed all bans', undef, 'kur-' . $self->{name} );

	return { 'flushed' => 1 };
} ## end sub _cmd_flush

# handles the re_init command... has the backend tear its setup down and
# rebuild it from scratch
sub _cmd_re_init {
	my ($self) = @_;

	$self->_refuse_when_stopping;

	# re_init tears down and re-bans only what the book carries, so anything
	# pending a unban retry is no longer in the firewall
	$self->_backend_do('re_init');
	$self->{unban_retries}      = {};
	$self->{cidr_unban_retries} = {};
	$self->_checkpoint_retries;
	$self->_checkpoint_cidr_retries;
	log_drek( 'info', 're_init done', undef, 'kur-' . $self->{name} );

	return { 're_init' => 1 };
} ## end sub _cmd_re_init

# handles the clear_retries command... forgets unbans still owed to the
# firewall, either a single named one via args.ip or args.cidr or the lot
# when neither is given
#
# this is the escape hatch for a retry that will never succeed, the rule
# having been removed by hand or the entry having never existed as far as
# the backend is concerned. forgetting one does not touch the firewall, so
# anything genuinely still banished there stays banished
sub _cmd_clear_retries {
	my ( $self, $request ) = @_;

	my $args = defined( $request->{args} ) ? $request->{args} : {};

	if ( defined( $args->{ip} ) && defined( $args->{cidr} ) ) {
		die('only one of args.ip and args.cidr may be given');
	}

	my $ident   = 'kur-' . $self->{name};
	my $cleared = { 'ip' => 0, 'cidr' => 0 };

	foreach my $family ( 'ip', 'cidr' ) {
		my $spec               = $family_spec{$family};
		my $named              = $args->{ $spec->{retry_arg} };
		my $other_family_named = defined( $args->{ $family_spec{ $family eq 'ip' ? 'cidr' : 'ip' }->{retry_arg} } );

		# a named entry only clears from it's own family, and naming one
		# family means the other is left alone entirely
		if ( defined($named) ) {
			if ( ref($named) ne '' ) {
				die( 'args.' . $spec->{retry_arg} . ' must be a single ' . $spec->{noun} );
			}
			my $entry = $spec->{normalizer}->($named);
			if ( !defined($entry) ) {
				die(      'args.'
						. $spec->{retry_arg} . ', "'
						. $named
						. '", does not appear to be a IPv4 or IPv6 '
						. $spec->{noun} );
			}
			if ( defined( delete( $self->{ $spec->{retry_hash} }{$entry} ) ) ) {
				$cleared->{$family} = 1;
				my $retry_checkpoint_method = $spec->{retry_checkpoint};
				$self->$retry_checkpoint_method;
				log_drek( 'info', 'forgot the owed unban of ' . $spec->{infix} . $entry, undef, $ident );
			}
			next;
		} ## end if ( defined($named) )

		next if ($other_family_named);

		my $count = scalar( keys( %{ $self->{ $spec->{retry_hash} } } ) );
		if ($count) {
			$self->{ $spec->{retry_hash} } = {};
			$cleared->{$family} = $count;
			my $retry_checkpoint_method = $spec->{retry_checkpoint};
			$self->$retry_checkpoint_method;
			log_drek( 'info', 'forgot ' . $count . ' owed ' . $spec->{infix} . 'unbans', undef, $ident );
		}
	} ## end foreach my $family ( 'ip', 'cidr' )

	return {
		'cleared'      => $cleared->{ip} + $cleared->{cidr},
		'cleared_ip'   => $cleared->{ip},
		'cleared_cidr' => $cleared->{cidr},
	};
} ## end sub _cmd_clear_retries

# handles the checkpoint command... force writes both tablets now,
# returning how many entries each is carrying
sub _cmd_checkpoint {
	my ($self) = @_;

	$self->_checkpoint;
	$self->_checkpoint_cidr;
	$self->_checkpoint_retries;
	$self->_checkpoint_cidr_retries;
	log_drek( 'info', 'checkpointed', undef, 'kur-' . $self->{name} );

	return {
		'checkpointed'       => 1,
		'bans'               => scalar( keys( %{ $self->{bans} } ) ),
		'cidr_bans'          => scalar( keys( %{ $self->{cidr_bans} } ) ),
		'unban_retries'      => scalar( keys( %{ $self->{unban_retries} } ) ),
		'cidr_unban_retries' => scalar( keys( %{ $self->{cidr_unban_retries} } ) ),
	};
} ## end sub _cmd_checkpoint

# handles the stop command... unlike the other handlers this one responds
# via $ctx its self and returns undef, as the response has to be flushed
# before the delayed shutdown takes the server session down with it
sub _cmd_stop {
	my ( $self, $ctx ) = @_;

	log_drek( 'info', 'stop requested, tearing the backend down', undef, 'kur-' . $self->{name} );

	my $teardown_error = $self->_stop_guts;

	$ctx->respond_result( { 'stopping' => 1, $teardown_error ? ( 'teardown_error' => $teardown_error ) : () } );
	$ctx->close;

	# the current session is the JSONUnix server session, so this fires its
	# shutdown state after the response has had time to flush
	$poe_kernel->delay( 'shutdown', 1 );

	return undef;
} ## end sub _cmd_stop

# the common guts of stopping... checkpoints both tablets, tears the backend
# down, and returns any teardown error... shared by the stop command and the
# signal handler
sub _stop_guts {
	my ($self) = @_;

	# keeps the ban sweeper from rescheduling so it's session can end
	$self->{stopping} = 1;

	# leave a fresh state CSV behind
	$self->_checkpoint;
	$self->_checkpoint_cidr;
	$self->_checkpoint_retries;
	$self->_checkpoint_cidr_retries;

	eval { $self->_backend_do('teardown'); };
	my $teardown_error = $@;
	if ($teardown_error) {
		log_drek( 'err', 'teardown failed... ' . $teardown_error, undef, 'kur-' . $self->{name} );
	} else {
		# teardown takes the whole firewall setup with it, orphaned rules
		# included, so anything that was owed has just been paid... left in
		# place the tablets would have the next run retrying unbans for
		# rules that no longer exist. a failed teardown may well have left
		# them there, so those debts are kept
		$self->{unban_retries}      = {};
		$self->{cidr_unban_retries} = {};
		$self->_checkpoint_retries;
		$self->_checkpoint_cidr_retries;
	} ## end else [ if ($teardown_error) ]

	return $teardown_error;
} ## end sub _stop_guts

# ran once a second by the sweeper session... expires timed bans and
# handles the periodic checkpoint of both tablets
sub _tick {
	my ($self) = @_;

	$self->_sweep_bans;

	if ( $self->{checkpoint} && ( time - $self->{last_checkpoint} ) >= $self->{checkpoint} ) {
		$self->_checkpoint;
		$self->_checkpoint_cidr;
		$self->_checkpoint_retries;
		$self->_checkpoint_cidr_retries;
	}

	return;
} ## end sub _tick

# unbans timed bans that have expired, both families... ran once a second
# via the sweeper session started by start_server
sub _sweep_bans {
	my ($self) = @_;

	foreach my $family ( 'ip', 'cidr' ) {
		$self->_sweep_family( $family_spec{$family} );
	}

	return;
}

# the shared per family sweep... unbans anything whose sentence has been
# served and checkpoints that family's tablet when anything changed
sub _sweep_family {
	my ( $self, $spec ) = @_;

	my $ident         = 'kur-' . $self->{name};
	my $now           = time;
	my $changed       = 0;
	my $retry_changed = 0;

	foreach my $banned_entry ( keys( %{ $self->{ $spec->{hash} } } ) ) {
		my $entry = $self->{ $spec->{hash} }{$banned_entry};
		if ( !$entry->{expires} || $entry->{expires} > $now ) {
			next;
		}

		eval { $self->_backend_do( $spec->{unban_method}, ban => $banned_entry ); };
		if ($@) {
			$self->{stats}{errors}++;
			# the sentence is still considered served... the firewall side is
			# left to the retry loop below rather than staying orphaned there
			$self->{ $spec->{retry_hash} }{$banned_entry} = {
				'first_tried' => $now,
				'last_tried'  => $now,
				'times_tried' => 1,
				'next_try'    => $now + 1,
				'delay'       => 2,
			};
			$retry_changed = 1;
			log_drek(
				'err',
				'unbanning expired '
					. $spec->{log_label} . ' of "'
					. $banned_entry
					. '" failed, will retry... '
					. $@,
				undef,
				$ident
			);
		} ## end if ($@)
		delete( $self->{ $spec->{hash} }{$banned_entry} );
		$self->{stats}{ $spec->{expired_stat} }++;
		$changed = 1;
		log_drek( 'info', $spec->{log_label} . ' of ' . $banned_entry . ' expired', undef, $ident );
	} ## end foreach my $banned_entry ( keys( %{ $self->{ $spec...}}))

	# retries unbans that failed at expiry, backing off with the same
	# doubling to a cap of 60 seconds the manager uses for respawns... a
	# re-ban via _ban_many cancels the entry instead
	foreach my $retry_entry ( keys( %{ $self->{ $spec->{retry_hash} } } ) ) {
		my $retry = $self->{ $spec->{retry_hash} }{$retry_entry};
		if ( $retry->{next_try} > $now ) {
			next;
		}

		eval { $self->_backend_do( $spec->{unban_method}, ban => $retry_entry ); };
		if ($@) {
			$self->{stats}{errors}++;
			$retry->{last_tried} = $now;
			$retry->{times_tried}++;
			$retry->{next_try} = $now + $retry->{delay};
			$retry->{delay}    = $retry->{delay} * 2 > 60 ? 60 : $retry->{delay} * 2;
			$retry_changed     = 1;
			log_drek(
				'err',
				'unban retry '
					. $retry->{times_tried} . ' for '
					. $spec->{log_label} . ' of "'
					. $retry_entry
					. '" failed... '
					. $@,
				undef,
				$ident
			);
		} else {
			delete( $self->{ $spec->{retry_hash} }{$retry_entry} );
			$retry_changed = 1;
			log_drek( 'info', 'unban retry for ' . $spec->{log_label} . ' of ' . $retry_entry . ' succeeded',
				undef, $ident );
		}
	} ## end foreach my $retry_entry ( keys( %{ $self->{ $spec...}}))

	if ($changed) {
		my $checkpoint_method = $spec->{checkpoint};
		$self->$checkpoint_method;
	}
	if ($retry_changed) {
		my $retry_checkpoint_method = $spec->{retry_checkpoint};
		$self->$retry_checkpoint_method;
	}

	return;
} ## end sub _sweep_family

# checkpoints the single IP ban state, tracking the time of the last
# successful checkpoint so the periodic timer has something to measure against
sub _checkpoint {
	my ($self) = @_;

	my $now = time;
	if ( $self->_write_state( $self->state_path, $self->{bans}, $now, 'ip' ) ) {
		$self->{last_checkpoint} = $now;
	}

	return;
} ## end sub _checkpoint

# checkpoints the CIDR ban state to its own sibling CSV, kept separate so
# the single IP tablet format stays as it was before CIDR support existed
sub _checkpoint_cidr {
	my ($self) = @_;

	$self->_write_state( $self->cidr_state_path, $self->{cidr_bans}, time, 'cidr' );

	return;
}

# checkpoints the single IP unban retry state to its own tablet, so a unban
# still owed to the firewall is not forgotten by a restart
sub _checkpoint_retries {
	my ($self) = @_;

	$self->_write_retry_state( $family_spec{ip} );

	return;
}

# checkpoints the CIDR unban retry state, mirroring _checkpoint_retries
sub _checkpoint_cidr_retries {
	my ($self) = @_;

	$self->_write_retry_state( $family_spec{cidr} );

	return;
}

# writes a retry hash out as a CSV to that family's retry tablet, atomically
# via a temp file and rename the same way _write_state does... the times are
# absolute rather than relative as a retry has no sentence to re-anchor, and
# a next_try left in the past just means the retry is due at once
#
# an empty retry hash unlinks the tablet rather than leaving a header only
# file behind, so nothing owed means nothing on disk
sub _write_retry_state {
	my ( $self, $spec ) = @_;

	my $path_method = $spec->{retry_path};
	my $state_file  = $self->$path_method;
	my $retries     = $self->{ $spec->{retry_hash} };

	if ( !%{$retries} ) {
		if ( -e $state_file && !unlink($state_file) ) {
			$self->{stats}{errors}++;
			log_drek( 'err',
				'removing the empty ' . $spec->{infix} . 'retry tablet "' . $state_file . '" failed... ' . $!,
				undef, 'kur-' . $self->{name} );
		}
		return 1;
	}

	my $tmp_file = $state_file . '.tmp';
	eval {
		open( my $fh, '>', $tmp_file ) || die( 'open failed... ' . $! );
		print $fh $spec->{label} . ",first_tried,last_tried,times_tried,next_try,delay\n";
		foreach my $key ( sort( keys( %{$retries} ) ) ) {
			my $retry = $retries->{$key};
			print $fh join( ',',
				$key,                  $retry->{first_tried}, $retry->{last_tried},
				$retry->{times_tried}, $retry->{next_try},    $retry->{delay} ) . "\n";
		}
		# as with the ban tablets, buffered print failures only surface at
		# close, and skipping the rename keeps the last good file in place
		close($fh)                       || die( 'close failed... ' . $! );
		rename( $tmp_file, $state_file ) || die( 'rename failed... ' . $! );
	};
	if ($@) {
		unlink($tmp_file);
		$self->{stats}{errors}++;
		log_drek( 'err',
			'checkpointing ' . $spec->{infix} . 'unban retry state to "' . $state_file . '" failed... ' . $@,
			undef, 'kur-' . $self->{name} );
		return 0;
	}

	return 1;
} ## end sub _write_retry_state

# writes a ban state hash out as a CSV of <label>,time,ban_time_left to the
# given file, atomically via a temp file and rename... returns 1 on success
# and 0 on failure, having logged the failure. shared by the single IP and
# CIDR checkpoints, the only difference being the file, the hash, and the
# label used for the first column
sub _write_state {
	my ( $self, $state_file, $bans, $now, $label ) = @_;

	my $tmp_file = $state_file . '.tmp';
	eval {
		open( my $fh, '>', $tmp_file ) || die( 'open failed... ' . $! );
		print $fh $label . ",time,ban_time_left\n";
		foreach my $key ( sort( keys( %{$bans} ) ) ) {
			my $left = 0;
			if ( $bans->{$key}{expires} ) {
				$left = $bans->{$key}{expires} - $now;
				# clamped so a nearly expired ban can't collide with 0 meaning
				# permanent... anything actually expired is the sweeper's job
				if ( $left < 1 ) {
					$left = 1;
				}
			}
			print $fh $key . ',' . $now . ',' . $left . "\n";
		} ## end foreach my $key ( sort( keys( %{$bans} ) ) )
		# checked as buffered print failures, a full filesystem for example,
		# only surface here... skipping the rename keeps the previous good
		# state file in place rather than replacing it with a truncated one
		close($fh)                       || die( 'close failed... ' . $! );
		rename( $tmp_file, $state_file ) || die( 'rename failed... ' . $! );
	};
	if ($@) {
		unlink($tmp_file);
		$self->{stats}{errors}++;
		log_drek( 'err', 'checkpointing ' . $label . ' ban state to "' . $state_file . '" failed... ' . $@,
			undef, 'kur-' . $self->{name} );
		return 0;
	}

	return 1;
} ## end sub _write_state

# loads the persisted ban state CSV... the time in each row is compared to
# the current time for figuring out if the ban should be restored or not...
# entries that expired while not running are unbanned in case the backend
# still carries the rule, the rest are re-banned so the freshly inited
# backend carries them again
sub _load_bans {
	my ($self) = @_;

	$self->_load_state( $self->state_path, $family_spec{ip} );

	return;
}

# loads the persisted CIDR ban state, mirroring _load_bans but for CIDR... it
# is skipped entirely when CIDR is not available for this instance so the
# persisted file is left intact for a later run that re-enables it, rather than
# being handed to a backend that can not carry it
sub _load_cidr_bans {
	my ($self) = @_;

	if ( !$self->_cidr_available ) {
		return;
	}

	$self->_load_state( $self->cidr_state_path, $family_spec{cidr} );

	return;
} ## end sub _load_cidr_bans

# loads both retry tablets... a unban that was still owed when the kur went
# down is owed just as much now, so the entries come back with their counts
# and backoff intact rather than starting over. the CIDR side is loaded
# regardless of whether CIDR is currently available, as the debt is to the
# firewall and does not care whether the operator has since turned the
# feature off
sub _load_retries {
	my ($self) = @_;

	foreach my $family ( 'ip', 'cidr' ) {
		$self->_load_retry_state( $family_spec{$family} );
	}

	return;
}

# the shared per family retry tablet loader... rows that will not parse or
# will not normalize are skipped, keeping the same canonical only invariant
# the ban books have
sub _load_retry_state {
	my ( $self, $spec ) = @_;

	my $path_method = $spec->{retry_path};
	my $state_file  = $self->$path_method;

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
		log_drek( 'err', 'loading ' . $spec->{infix} . 'unban retry state from "' . $state_file . '" failed... ' . $@,
			undef, $ident );
		return;
	}

	my $line_number = 0;
	foreach my $line (@lines) {
		$line_number++;
		chomp($line);
		if ( $line eq '' ) {
			next;
		}
		if ( $line_number == 1 && $line =~ /^$spec->{label},/ ) {
			# the header
			next;
		}

		my @row = split( /,/, $line );
		if ( @row != 6 || $row[0] eq '' || grep { $row[$_] !~ /^[0-9]+$/ } ( 1 .. 5 ) ) {
			log_drek( 'err', 'skipping malformed line ' . $line_number . ' in "' . $state_file . '"... "' . $line . '"',
				undef, $ident );
			next;
		}
		my ( $entry, $first_tried, $last_tried, $times_tried, $next_try, $delay ) = @row;

		my $normalized = $spec->{normalizer}->($entry);
		if ( !defined($normalized) ) {
			log_drek(
				'err',
				'skipping line '
					. $line_number . ' in "'
					. $state_file
					. '"... "'
					. $entry
					. '" is not a valid '
					. $spec->{noun},
				undef,
				$ident
			);
			next;
		} ## end if ( !defined($normalized) )

		$self->{ $spec->{retry_hash} }{$normalized} = {
			'first_tried' => $first_tried,
			'last_tried'  => $last_tried,
			'times_tried' => $times_tried,
			'next_try'    => $next_try,
			# a tablet written by hand could carry a 0, which would peg the
			# backoff at 0 forever, so it is floored at where a first failure
			# would have left it
			'delay' => $delay ? $delay : 2,
		};
		log_drek(
			'info',
			'unban of '
				. $spec->{infix}
				. $normalized
				. ' still owed from a previous run, tried '
				. $times_tried
				. ' times',
			undef,
			$ident
		);
	} ## end foreach my $line (@lines)

	# rewrite so the tablet reflects what actually got restored
	my $checkpoint_method = $spec->{retry_checkpoint};
	$self->$checkpoint_method;

	return;
} ## end sub _load_retry_state

# the shared per family loader behind _load_bans and _load_cidr_bans...
# parameterized the same way as the rest of the shared family helpers
sub _load_state {
	my ( $self, $state_file, $spec ) = @_;

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
		log_drek( 'err', 'loading ' . $spec->{infix} . 'ban state from "' . $state_file . '" failed... ' . $@,
			undef, $ident );
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
		if ( $line_number == 1 && $line =~ /^$spec->{label},/ ) {
			# the header
			next;
		}

		my @row = split( /,/, $line );
		if ( @row != 3 || $row[0] eq '' || $row[1] !~ /^[0-9]+$/ || $row[2] !~ /^[0-9]+$/ ) {
			log_drek( 'err', 'skipping malformed line ' . $line_number . ' in "' . $state_file . '"... "' . $line . '"',
				undef, $ident );
			next;
		}
		my ( $banned_entry, $written, $left ) = @row;
		# everything is normalized before being booked, so a row that will
		# not normalize is a hand edit or a corrupt tablet... it is skipped
		# rather than booked raw, which would leave a entry the unban path
		# can never name, as it normalizes what it is asked to remove
		my $normalized = $spec->{normalizer}->($banned_entry);
		if ( !defined($normalized) ) {
			log_drek(
				'err',
				'skipping line '
					. $line_number . ' in "'
					. $state_file
					. '"... "'
					. $banned_entry
					. '" is not a valid '
					. $spec->{noun},
				undef,
				$ident
			);
			next;
		} ## end if ( !defined($normalized) )
		$banned_entry = $normalized;

		my $expires = $left ? $written + $left : 0;

		if ( $expires && $expires <= $now ) {
			# expired while not running... the backend may still carry the rule
			eval { $self->_backend_do( $spec->{unban_method}, ban => $banned_entry ); };
			if ($@) {
				log_drek( 'err',
					'unbanning expired ' . $spec->{log_label} . ' of "' . $banned_entry . '" failed... ' . $@,
					undef, $ident );
			}
			$self->{stats}{ $spec->{expired_stat} }++;
			log_drek( 'info', $spec->{log_label} . ' of ' . $banned_entry . ' expired while not running',
				undef, $ident );
			next;
		} ## end if ( $expires && $expires <= $now )

		eval { $self->_backend_do( $spec->{ban_method}, ban => $banned_entry ); };
		if ($@) {
			# not recorded in the book on failure, matching how a live ban
			# behaves... a book claiming a ban the firewall does not carry
			# would just feed the sweeper a doomed unban later
			log_drek( 'err',
				're-banning ' . $spec->{infix} . '"' . $banned_entry . '" from saved state failed... ' . $@,
				undef, $ident );
			next;
		}
		# banned_at is not persisted, so the row's time stands in for it
		$self->{ $spec->{hash} }{$banned_entry} = { 'banned_at' => $written, 'expires' => $expires };
	} ## end foreach my $line (@lines)

	# write a updated one back out so the file reflects what got restored
	my $checkpoint_method = $spec->{checkpoint};
	$self->$checkpoint_method;

	return;
} ## end sub _load_state

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
