package SAuth::Core::Key;
use Moose;
use MooseX::StrictConstructor;

use SAuth::Util;

has 'uid' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1
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

has 'allow_refresh' => (
    is       => 'ro',
    isa      => 'Bool',
    required => 1
);

has 'expires' => (
    is       => 'ro',
    isa      => 'DateTime',
    required => 1
);

has 'token_max_lifespan' => (
    is       => 'ro',
    isa      => 'Int',
    required => 1
);

has 'shared_secret' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1
);

sub has_capability {
    my ($self, $capability) = @_;
    $self->_find_capability( sub { $_ eq $capability } ) ? 1 : 0;
}

sub is_valid {
    my $self = shift;
    ( DateTime->compare( DateTime->now, $self->expires ) <= 0 ) ? 1 : 0
}

sub to_json {
    my $self = shift;
    encode_json({
        uid                => $self->uid,
        capabilities       => $self->capabilities,
        allow_refresh      => $self->allow_refresh ? JSON::XS::true() : JSON::XS::false(),
        expires            => format_datetime( $self->expires ),
        token_max_lifespan => $self->token_max_lifespan,
        shared_secret      => encode_base64( $self->shared_secret ),
    });
}

sub from_json {
    my ($class, $json) = @_;

    my $data = decode_json( $json );

    $data->{allow_refresh} = $data->{allow_refresh} == JSON::XS::true ? 1 : 0;
    $data->{expires}       = parse_datetime( $data->{expires} );
    $data->{shared_secret} = decode_base64( $data->{shared_secret} );

    $class->new( $data );
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Core::Key;

=head1 DESCRIPTIOn

=attr uid

The unique identifier for this key.

=attr capabilities

A array of strings which represent a subset of the capabilities
provided by the service itself.

=attr allow_refresh

Boolean telling if this key allows tokens to be refreshed? Or is
this a one time access only.

=attr expires

The date at which this key expires.

=attr token_max_lifespan

The max length in seconds that a token is valid for.

=attr shared_secret

This is the shared secret between the key provider and the key
owner.

=method to_json

Converts this key into JSON.

=method from_json( $json )

Converts a JSON key into a key object.




