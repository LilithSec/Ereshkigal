package Ereshkigal;

use 5.006;
use strict;
use warnings;
use JSON;
use POE;
use POE::Wheel::SocketFactory;
use POE::Wheel::Run;
use POE::Wheel::ReadWrite;
use Socket;
use Sys::Syslog;

=head1 NAME

Ereshkigal - Handle firewall or similar bans.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Ereshkigal;

    my $foo = Ereshkigal->new();
    ...


=head1 METHODS

=head2 new

    - socket :: Socket location.
        Default :: /var/run/ereshkigal/socket

    - config :: Location of the config file that will be passed to kur.


=cut

sub new {
	my ( $blank, %opts ) = @_;

	my $self = {
		socket => '/var/run/ereshkigal/socket',
		stats  => {
			buckets       => {},
			total         => 0,
			bucket_totals => {},
		},
	};
	bless $self;

	my @to_merge = ( 'pid', 'socket' );
	foreach my $item (@to_merge) {
		if ( defined( $opts{$item} ) ) {
			$self->{$item} = $opts{item};
		}
	}

	return $self;

} ## end sub new

=head2 start_server

Starts up server, calling $poe_kernel->run.

This should not be expected to return.

=cut

sub start_server {
	my ($self) = @_;

	POE::Session->create(
		inline_states => {
			_start     => \&server_started,
			got_client => \&server_accepted,
			got_error  => \&server_error,
		},
		heap => { socket => $self->{socket}, self => $self },
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
	$heap->{client}->put( "Connected to Net::LDAP::KeyCache v. " . $Net::LDAP::KeyCache::VERSION );
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
