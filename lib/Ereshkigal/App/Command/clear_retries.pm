package Ereshkigal::App::Command::clear_retries;

use 5.006;
use strict;
use warnings;
use Ereshkigal::App -command;

=head1 NAME

Ereshkigal::App::Command::clear_retries - Forget unbans still owed to the firewall.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    # forget every owed unban, on every kur
    ereshkigal clear-retries

    # just the ones sshd is carrying
    ereshkigal clear-retries sshd

    # just this one IP, everywhere
    ereshkigal clear-retries --ip 1.2.3.4

    # and a range, on the one kur
    ereshkigal clear-retries blocklist --cidr 1.2.3.0/24

=head1 DESCRIPTION

When a ban's sentence runs out but the backend refuses the unban, the kur
still drops it from the ban book and hands the firewall side to a retry that
backs off until it lands. Those owed unbans show up under C<unban_retries> in
the output of L<banned|Ereshkigal::App::Command::banned> and are counted by
L<status|Ereshkigal::App::Command::status>.

This forgets them. It is the escape hatch for one that will never land, the
rule having been removed by hand or the backend having never had it to begin
with. Nothing is asked of the firewall, so anything genuinely still banished
there stays banished... this only stops the kur from asking.

=head1 METHODS

Standard L<App::Cmd::Command> methods... abstract, opt_spec, validate_args,
and execute.

=cut

# accept both the dashed and underscored spellings
sub command_names { return ( 'clear-retries', 'clear_retries' ); }

sub abstract { return 'forget unbans still owed to the firewall' }

sub description {
	return
		  'Forget unbans that failed at expiry and are still being retried, either all of them '
		. 'or the single one named by --ip or --cidr. Only the book keeping is forgotten... nothing '
		. 'is asked of the firewall.';
}

sub usage_desc { return '%c clear-retries %o [kur]'; }

sub opt_spec {
	return (
		[ 'ip=s',   'forget the owed unban of just this IP' ],
		[ 'cidr=s', 'forget the owed unban of just this CIDR range' ],
	);
}

sub validate_args {
	my ( $self, $opt, $args ) = @_;

	if ( @{$args} > 1 ) {
		$self->usage_error('clear-retries takes at most one arg, a kur instance name');
	}
	if ( defined( $opt->ip ) && defined( $opt->cidr ) ) {
		$self->usage_error('--ip and --cidr may not be used together');
	}

	return;
} ## end sub validate_args

sub execute {
	my ( $self, $opt, $args ) = @_;

	my $command_args = {};
	if ( @{$args} ) {
		$command_args->{kur} = $args->[0];
	}
	if ( defined( $opt->ip ) ) {
		$command_args->{ip} = $opt->ip;
	}
	if ( defined( $opt->cidr ) ) {
		$command_args->{cidr} = $opt->cidr;
	}

	$self->run_command( 'clear_retries', %{$command_args} ? $command_args : undef );

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
