package Ereshkigal::App::Command::add;

use 5.006;
use strict;
use warnings;
use Ereshkigal::App -command;
use Ereshkigal::Client ();
use JSON::MaybeXS      ();

=head1 NAME

Ereshkigal::App::Command::add - Define and start a new kur instance at runtime.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    ereshkigal add sshd --backend ipfw --ports 22 --protocols tcp
    ereshkigal add baphomet --fan-out sshd,smtp

=head1 DESCRIPTION

Defines and starts a new kur instance in the running manager. Does not
rewrite the config file... to make it permanent, add it to the config.

With C<--fan-out> in place of C<--backend> the new kur is a manager side
fan out kur... no process of it's own, with commands targeted at it
fanning out to the listed member kurs.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

sub abstract { return 'define and start a new kur instance at runtime' }

sub description {
	return 'Define and start a new kur instance in the running manager. Takes the same additional '
		. 'args as the kur bin, which are passed through. Does not rewrite the config file.';
}

sub usage_desc { return '%c add %o <kur>'; }

sub opt_spec {
	return (
		[ 'backend=s',    'the Net::Firewall::BlockerHelper backend to use' ],
		[ 'fan-out=s',    'comma seperated list of kurs to fan out to, in place of --backend' ],
		[ 'ports=s',      'comma seperated list of ports to block' ],
		[ 'protocols=s',  'comma seperated list of protocols to block' ],
		[ 'prefix=s',     'the prefix to use' ],
		[ 'option=s@',    'a backend specific option, key=value, may be given multiple times' ],
		[ 'self-heal=i',  'if the firewall setup should be checked and re-inited before each ban/unban' ],
		[ 'ban-time=i',   'seconds bans should last for this kur, 0 meaning never time out' ],
		[ 'checkpoint=i', 'seconds between ban state CSV rewrites for this kur' ],
	);
} ## end sub opt_spec

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} != 1 ) {
		$self->usage_error('a single kur instance name must be specified');
	}
	if ( !defined( $opt->backend ) && !defined( $opt->fan_out ) ) {
		$self->usage_error('either --backend or --fan-out must be specified');
	}
	if ( defined( $opt->backend ) && defined( $opt->fan_out ) ) {
		$self->usage_error('--backend and --fan-out may not be used together');
	}

	return;
} ## end sub validate_args

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $opts = {};

	if ( defined( $opt->backend ) ) {
		$opts->{backend} = $opt->backend;
	}
	if ( defined( $opt->fan_out ) ) {
		$opts->{fan_out} = [ split( /\s*,\s*/, $opt->fan_out ) ];
	}
	if ( defined( $opt->ports ) ) {
		$opts->{ports} = [ split( /\s*,\s*/, $opt->ports ) ];
	}
	if ( defined( $opt->protocols ) ) {
		$opts->{protocols} = [ split( /\s*,\s*/, $opt->protocols ) ];
	}
	if ( defined( $opt->prefix ) ) {
		$opts->{prefix} = $opt->prefix;
	}
	if ( defined( $opt->self_heal ) ) {
		$opts->{self_heal} = $opt->self_heal;
	}
	if ( defined( $opt->ban_time ) ) {
		$opts->{ban_time} = $opt->ban_time;
	}
	if ( defined( $opt->checkpoint ) ) {
		$opts->{checkpoint} = $opt->checkpoint;
	}
	if ( defined( $opt->option ) ) {
		my %backend_options;
		foreach my $key_value ( @{ $opt->option } ) {
			my ( $key, $value ) = split( /=/, $key_value, 2 );
			if ( !defined($value) ) {
				$self->usage_error( '--option "' . $key_value . '" is not in the form key=value' );
			}
			$backend_options{$key} = $value;
		}
		$opts->{options} = \%backend_options;
	} ## end if ( defined( $opt->option ) )

	my $client = Ereshkigal::Client->new( 'socket' => $self->app->global_options->{socket} );
	my $result = $client->call_ok( 'add_kur', { 'name' => $args->[0], 'opts' => $opts } );

	print JSON::MaybeXS->new( 'pretty' => 1, 'canonical' => 1 )->encode($result);

	return;
} ## end sub execute

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

=cut

1;
