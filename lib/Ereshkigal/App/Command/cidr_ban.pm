package Ereshkigal::App::Command::cidr_ban;

use 5.006;
use strict;
use warnings;
use Ereshkigal::App -command;
use Ereshkigal::Client ();
use JSON::MaybeXS      ();

=head1 NAME

Ereshkigal::App::Command::cidr_ban - Ban one or more CIDR ranges.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    # ban on all kur instances
    ereshkigal cidr-ban 1.2.3.0/24 10.0.0.0/8

    # ban on just the kur instance sshd
    ereshkigal cidr-ban --kur sshd 1.2.3.0/24

    # a hour long ban
    ereshkigal cidr-ban --ban-time 3600 1.2.3.0/24

    # a permanent ban
    ereshkigal cidr-ban --ban-time 0 1.2.3.0/24

Only works on a kur whose backend supports CIDR bans and which has CIDR
banning enabled. A kur that can not or will not do CIDR either drops the
command or reports a error per its cidr_silent_drop setting.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

# accept both the dashed and underscored spellings
sub command_names { return ( 'cidr-ban', 'cidr_ban' ); }

sub abstract { return 'ban one or more CIDR ranges' }

sub description {
	return 'Ban one or more CIDR ranges. Sent to the named kur if --kur is given, otherwise to all kurs.';
}

sub usage_desc { return '%c cidr-ban %o <CIDR> [<CIDR> ...]'; }

sub opt_spec {
	return (
		[ 'kur=s',      'kur instance to send the ban to, defaulting to all of them' ],
		[ 'ban-time=i', 'seconds the bans should last, 0 meaning never time out, defaulting to the kur default' ],
	);
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( !@{$args} ) {
		$self->usage_error('at least one CIDR must be specified');
	}

	return;
}

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $ban_args = { 'cidrs' => $args };
	if ( defined( $opt->kur ) ) {
		$ban_args->{kur} = $opt->kur;
	}
	if ( defined( $opt->ban_time ) ) {
		$ban_args->{ban_time} = $opt->ban_time;
	}

	my $client = Ereshkigal::Client->new( 'socket' => $self->app->global_options->{socket} );
	my $result = $client->call_ok( 'cidr_ban', $ban_args );

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
