package SAuth::Consumer::RequestWrapper;
use Moose;
use Moose::Util::TypeConstraints;

use SAuth::Util;
use SAuth::Core::Key;

has 'key' => (
    is       => 'ro',
    isa      => 'SAuth::Core::Key',
    required => 1,
);

has 'body' => (
    is       => 'ro',
    isa      => duck_type([qw[ to_json ]]),
    required => 1,
);

has 'timestamp' => (
    is      => 'ro',
    isa     => 'Int',
    lazy    => 1,
    default => sub { mint_timestamp },
);

has 'hmac' => (
    is      => 'ro',
    isa     => 'Str',
    lazy    => 1,
    builder => 'build_hmac'
);

sub build_hmac {
    my $self = shift;
    hmac_digest(
        $self->key->shared_secret,
        $self->timestamp,
        $self->body->to_json
    );
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Consumer::AccessRequest;

=head1 DESCRIPTION

