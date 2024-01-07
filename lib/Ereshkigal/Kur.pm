package Ereshkigal::Kur;

use 5.006;
use strict;
use warnings;
use base 'Error::Helper';
use JSON;
use POE;
use POE::Wheel::SocketFactory;
use POE::Wheel::Run;
use POE::Wheel::ReadWrite;
use Socket;
use Sys::Syslog;
use Net::Firewall::BlockerHelper;

=head1 NAME

Ereshkigal::Kur - FW handler for Ereshkigal.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Ereshkigal::Kur;

    my $kur = Ereshkigal::Kur->new(
                backend => 'ipfw',
                ports => ['22'],
                protocols => ['tcp'],
                name => 'ssh',
              );

=head1 METHODS

=head2 new

    - run_base_dir :: The default directory to use for the base for PID
            files and sockets.
        - Default :: /var/run/ereshkigal

    - cache_base_dir :: The directory to use for storing caches.
        - Default :: /var/cache/ereshkigal

    - backend :: The Net::Firewall::BlockerHelper backend to use.
        - Default :: undef

    - ports :: The ports array to pass to Net::Firewall::BlockerHelper.
        - Default :: []

    - protocols :: The protocols array to pass to Net::Firewall::BlockerHelper.
        - Default :: []

    - name :: The name value to pass to Net::Firewall::BlockerHelper.

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
			},
			fatal_flags      => {},
			perror_not_fatal => 0,
		},
		run_base_dir   => '/var/run/ereshkigal',
		cache_base_dir => '/var/cache/ereshkigal',
		backend        => undef,
		backend_obj    => undef,
		config         => undef,
		ports          => undef,
		protocols      => undef,
		options        => undef,
		name           => undef,
	};
	bless $self;

	my @to_merge = ( 'run_base_dir', 'ports', 'protocols', 'backend', 'name', 'options', 'cache_base_dir' );
	foreach my $item (@to_merge) {
		if ( defined( $opts{$item} ) ) {
			$self->{$item} = $opts{$item};
		}
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

	if ( !-e $self->{run_base_dir} ) {
		# don't need to check if this worked failed or not here as the next if statement will handle that
		eval { mkdir( $self->{run_base_dir} ); };
	}
	if ( !-d $self->{run_base_dir} ) {
		$self->{perror}      = 1;
		$self->{error}       = 1;
		$self->{errorString} = 'run_base_dir,"' . $self->{run_base_dir} . '", does not exist or is not a directory';
		$self->warn;
	}
	if ( !-r $self->{run_base_dir} || !-w $self->{run_base_dir} ) {
		$self->{perror} = 1;
		$self->{error}  = 4;
		$self->{errorString}
			= 'run_base_dir,"' . $self->{run_base_dir} . '", is either not writable or readable by the current user';
		$self->warn;
	}

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
		$self->{error}  = 7;
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
		);
		$self->{backend_obj}->init_backend;
	};
	if ($@) {
		$self->{perror}      = 1;
		$self->{error}       = 3;
		$self->{errorString} = 'Failed to init the backend... ' . $@;
		$self->warn;
	}

	return $self;
} ## end sub new

=head2 start_server

Starts up server, calling $poe_kernel->run.

This should not be expected to return.

    - instance :: The instance to start. This must be specified.
        Default :: undef

=cut

sub start_server {
	my ( $self, %opts ) = @_;

	$self->errorblank;

	if ( defined( $opts{instance} ) ) {
		$self->{error}       = 2;
		$self->{errorString} = 'No value for instance specified';
		$self->warn;
		return;
	}

	POE::Session->create(
		inline_states => {
			_start     => \&server_started,
			got_client => \&server_accepted,
			got_error  => \&server_error,
		},
		heap => { socket => $self->{socket}, self => $self, instance => $opts{instance}, },
	);

	$poe_kernel->run();
} ## end sub start_server

sub server_started {
	my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
	unlink $heap->{socket} if -e $heap->{socket};
	$heap->{server} = POE::Wheel::SocketFactory->new(
		SocketDomain => PF_UNIX,
		BindAddress  => $heap->{socket},
		SuccessEvent => 'got_client',
		FailureEvent => 'got_error',
	);
} ## end sub server_started

sub server_error {
	my ( $heap, $syscall, $errno, $error ) = @_[ HEAP, ARG0 .. ARG2 ];
	$error = "Normal disconnection." unless $errno;
	warn "Server socket encountered $syscall error $errno: $error\n";
	delete $heap->{server};
}

sub server_accepted {
	my ( $heap, $client_socket ) = @_[ HEAP, ARG0 ];
	session_spawn( $client_socket, $heap->{self} );
}

##
##
## for when we get a connection
##
##

# spawns the session
sub session_spawn {
	my $socket = shift;
	my $self   = shift;
	POE::Session->create(
		inline_states => {
			_start           => \&server_session_start,
			got_client_input => \&server_session_input,
			got_client_error => \&server_session_error,
		},
		args => [$socket],
		heap => { self => $self, processing => 0 },
	);
} ## end sub session_spawn

# starts the session and setup handlers referenced in session_spawn
sub server_session_start {
	my ( $heap, $socket ) = @_[ HEAP, ARG0 ];
	$heap->{client} = POE::Wheel::ReadWrite->new(
		Handle     => $socket,
		InputEvent => 'got_client_input',
		ErrorEvent => 'got_client_error',
	);
}

# handle line inputs
sub server_session_input {
	my ( $heap, $input ) = @_[ HEAP, ARG0 ];

	if ( $input eq 'exit' ) {
		delete $heap->{client};
		return;
	}

	if ( $heap->{processing} ) {
		my $error = { status => 1, error => 'already processing a request' };
		$heap->{client}->put( encode_json($error) );
		return;
	}

	my $json;
	eval { $json = decode_json($input); };
	if ($@) {
		my $error = { status => 1, error => $@ };
		$heap->{client}->put( encode_json($error) );
		return;
	} elsif ( !defined($json) ) {
		my $error = { status => 1, error => 'parsing JSON returned undef' };
		$heap->{client}->put( encode_json($error) );
		return;
	}

	if ( !defined( $json->{command} ) ) {
		my $error = { status => 1, error => '$json->{command} is undef' };
		$heap->{client}->put( encode_json($error) );
		return;
	}

	my $do_action = 0;
	if ( !defined( $json->{action} ) ) {
		my $error = { status => 1, error => '$json->{action} is undef' };
		$heap->{client}->put( encode_json($error) );
		return;
	} elsif ( $json->{action} eq 'ban'
		|| $json->{action} eq 'unban' )
	{
		$do_action = 1;
	} elsif ( $json->{action} eq 'stats' ) {
		my $stats = { status => 0, stats => $heap->{self}->{stats} };
		$heap->{client}->put( encode_json($stats) );
		return;
	}

} ## end sub server_session_input

sub server_session_error {
	my ( $heap, $syscall, $errno, $error ) = @_[ HEAP, ARG0 .. ARG2 ];
	$error = "Normal disconnection." unless $errno;
	warn "Server session encountered $syscall error $errno: $error\n";
	delete $heap->{client};
}

=head2 verbose


    - string :: String to use for verbose. If undef or '', it just returns.
        Default :: undef

    - level :: Syslog level to use.
        Default :: info

    - print :: The string to stdout.
        Default :: undef

    - warn :: Use warn to print the message. If print is also true, this
              takes prescence.
        Default :: undef

=cut

sub verbose {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{string} ) || $opts{string} eq '' ) {
		return;
	}

	if ( !defined( $opts{level} ) ) {
		$opts{level} = 'info';
	}

	openlog( 'ereshkigal', undef, 'daemon' );
	syslog( $opts{level}, $opts{string} );
	closelog();

	if ( !defined( $opts{string} ) || $opts{string} eq '' ) {
		return;
	}

	if ( $opts{warn} ) {
		warn( $opts{string} );
		return;
	}

	if ( $opts{print} ) {
		print( $opts{string} );
	}

	return;
} ## end sub verbose

=head1 ERRORS CODES / ERROR FLAGS

Error handling is provided by L<Error::Helper>. All errors
are considered fatal.

=head2 1, NErunBaseDir

The run base dir does not exist or is not a directory.

=head2 2, invalidName

Name not defined or does not match /^[a-zA-Z0-9\-]+$/.

=head2 3, backendInitFailed

Failed to initialize the backend.

=head 4, nonRWrunBaseDir

The run base dir is not readable or writable by the current user.

=head2 5, NEcacheBaseDir

The cache base dir does not exist or is not a directory.

=head 6, nonRWrunBaseDir

The cache base dir is not readable or writable by the current user.

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
