package SAuth::Provider;
use Moose;

use SAuth::Util;
use SAuth::Provider::Key;
use SAuth::Provider::KeyStore;

use List::AllUtils qw[ first ];

has 'secret' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has 'capabilities' => (
    traits   => [ 'Array' ],
    is       => 'ro',
    isa      => 'ArrayRef[ Str ]',
    required => 1,
    handles  => {
        '_find_capability' => 'first'
    }
);

has 'key_store' => (
    is       => 'ro',
    does     => 'SAuth::Provider::KeyStore',
    required => 1,
    handles  => [qw[
        get_key_for
        has_key_for
    ]]
);

sub create_key {
    my ($self, %args) = @_;

    foreach my $capability ( @{ $args{ capabilities } } ) {
        ( $self->has_capability( $capability ) )
            || confess "The capability ($capability) is not offered by this provider";
    }

    confess "There is already a key for $args{uid}"
        if $self->has_key_for( $args{uid} );

    my $key = SAuth::Provider::Key->new(
        %args,
        shared_secret => $self->generate_shared_secret( \%args )
    );

    $self->key_store->add_key_for( $key->uid, $key );

    $key;
}

sub has_capability {
    my ($self, $capability) = @_;
    $self->_find_capability( sub { $_ eq $capability } ) ? 1 : 0;
}

sub generate_shared_secret {
    my ($self, $args) = @_;
    digest(
        $args->{uid},
        @{ $args->{capabilities} },
        $args->{allow_refresh},
        format_datetime( $args->{expires} ),
        $args->{token_max_lifespan},
        $self->secret
    );
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider;

=head1 DESCRIPTION

