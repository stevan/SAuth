package SAuth::Core::AccessRequest;
use Moose;
use MooseX::StrictConstructor;

use SAuth::Util;

has 'uid' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1
);

has 'access_for' => (
    is       => 'ro',
    isa      => 'ArrayRef[ Str ]',
    required => 1
);

has 'token_lifespan' => (
    is       => 'ro',
    isa      => 'Int',
    required => 1
);

sub to_json {
    my $self = shift;
    encode_json({
        uid            => $self->uid,
        access_for     => $self->access_for,
        token_lifespan => $self->token_lifespan
    });
}

sub from_json {
    my ($class, $json) = @_;
    $class->new( decode_json( $json ) );
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Core::AccessRequest;

=head1 DESCRIPTION

