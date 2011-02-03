package SAuth::Provider::Key;
use Moose;

use SAuth::Util;

has 'uid' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1
);

has 'capabilities' => (
    is       => 'ro',
    isa      => 'ArrayRef[ Str ]',
    required => 1
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

sub to_JSON {
    my $self = shift;
    encode_json({
        uid                => $self->uid,
        capabilities       => $self->capabilities,
        allow_refresh      => $self->allow_refresh ? JSON::XS::true() : JSON::XS::false(),
        expires            => format_datetime( $self->expires ),
        token_max_lifespan => $self->token_max_lifespan,
        shared_secret      => $self->shared_secret,
    });
}

sub from_JSON {
    my ($class, $json) = @_;

    my $data = decode_json( $json );

    $data->{allow_refresh} = $data->{allow_refresh} == JSON::XS::true ? 1 : 0;
    $data->{expires}       = parse_datetime( $data->{expires} );

    $class->new( $data );
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::Key;

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

=method to_JSON

Converts this key into JSON.

=method from_JSON( $json )

Converts a JSON key into a key object.




