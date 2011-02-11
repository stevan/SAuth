package SAuth::Core::AccessRefresh;
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

has 'token_lifespan' => (
    is       => 'ro',
    isa      => 'Int',
    required => 1
);

sub to_json {
    my $self = shift;
    encode_json({
        uid            => $self->uid,
        token          => $self->token,
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

  use SAuth::Core::AccessRefresh;

=head1 DESCRIPTION

