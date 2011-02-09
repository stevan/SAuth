package SAuth::Provider::TokenStore;
use Moose::Role;

requires 'has_token';
requires 'add_token';
requires 'get_token';

sub update_nonce_for_token {
    my ($self, $token, $nonce) = @_;
    $self->get_token( $token )->nonce( $nonce );
}

sub get_current_nonce_for_token {
    my ($self, $token) = @_;
    $self->get_token( $token )->nonce;
}

no Moose::Role; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::TokenStore;

=head1 DESCRIPTION

