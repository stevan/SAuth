package SAuth::Core::AccessGrant;
use Moose;

use SAuth::Util;

has 'uid' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1
);

has 'token' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has 'access_to' => (
    is       => 'ro',
    isa      => 'ArrayRef[Str]',
    required => 1
);

has 'timeout' => (
    is       => 'rw',
    isa      => 'DateTime',
    required => 1
);

has 'can_refresh' => (
    is       => 'ro',
    isa      => 'Bool',
    required => 1
);

has 'nonce' => (
    is       => 'rw',
    isa      => 'Str',
    required => 1
);

sub to_json {
    my $self = shift;
    encode_json({
        uid           => $self->uid,
        token         => $self->token,
        access_to     => $self->access_to,
        timeout       => format_datetime( $self->timeout ),
        can_refresh   => $self->can_refresh ? JSON::XS::true() : JSON::XS::false(),
        nonce         => encode_base64( $self->nonce ),
    });
}

sub from_json {
    my ($class, $json) = @_;
    my $data = decode_json( $json );

    $data->{timeout}     = parse_datetime( $data->{timeout} );
    $data->{can_refresh} = $data->{can_refresh} == JSON::XS::true ? 1 : 0;
    $data->{nonce}       = decode_base64( $data->{nonce} );

    $class->new( $data );
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Core::AccessGrant;

=head1 DESCRIPTION

