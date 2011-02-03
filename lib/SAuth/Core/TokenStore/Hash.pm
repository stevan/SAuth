package SAuth::Core::TokenStore::Hash;
use Moose;

with 'SAuth::Core::TokenStore';

has 'access_grants' => (
    traits  => [ 'Hash' ],
    is      => 'ro',
    isa     => 'HashRef[ SAuth::Core::AccessGrant ]',
    lazy    => 1,
    default => sub { +{} },
);

sub has_token {
    my ($self, $token) = @_;
    $self->access_grants->{ $token } ? 1 : 0;
}

sub get_token {
    my ($self, $token) = @_;
    $self->access_grants->{ $token };
}

sub add_token {
    my ($self, $access_grant) = @_;
    $self->access_grants->{ $access_grant->token } = $access_grant;
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Core::TokenStore::Hash;

=head1 DESCRIPTION

