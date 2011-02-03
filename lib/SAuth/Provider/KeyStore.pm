package SAuth::Provider::KeyStore;
use Moose::Role;

requires 'has_key_for';
requires 'add_key_for';
requires 'get_key_for';

no Moose::Role; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::KeyStore;

=head1 DESCRIPTION

