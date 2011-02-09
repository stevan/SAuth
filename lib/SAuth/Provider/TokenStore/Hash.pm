package SAuth::Provider::TokenStore::Hash;
use Moose;

with 'SAuth::Provider::TokenStore';

has 'access_grants' => (
    traits  => [ 'Hash' ],
    is      => 'ro',
    isa     => 'HashRef[ HashRef[ SAuth::Core::AccessGrant ] ]',
    lazy    => 1,
    default => sub { +{} },
);

sub has_access_grant_for_token {
    my ($self, $token) = @_;
    $self->access_grants->{ $token } ? 1 : 0;
}

sub get_access_grant_for_token {
    my ($self, $token) = @_;
    $self->access_grants->{ $token };
}

sub add_access_grant_for_token {
    my ($self, $access_grant) = @_;
    $self->access_grants->{ $access_grant->token } = $access_grant;
}

sub update_nonce_for_token {
    my ($self, $token, $nonce) = @_;
    $self->get_access_grant_for_token( $token )->nonce( $nonce );
}

sub get_current_nonce_for_token {
    my ($self, $token) = @_;
    $self->get_access_grant_for_token( $token )->nonce;
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::TokenStore::Hash;

=head1 DESCRIPTION

