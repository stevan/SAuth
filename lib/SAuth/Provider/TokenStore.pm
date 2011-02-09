package SAuth::Provider::TokenStore;
use Moose::Role;

requires 'has_access_grant_for_token';
requires 'add_access_grant_for_token';
requires 'get_access_grant_for_token';

requires 'update_nonce_for_token';
requires 'get_nonce_for_token';

no Moose::Role; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::TokenStore;

=head1 DESCRIPTION

