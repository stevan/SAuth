package SAuth::Provider::TokenStore;
use Moose::Role;

use SAuth::Util;

requires 'has_token';
requires 'add_token';
requires 'get_token';

no Moose::Role; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::TokenStore;

=head1 DESCRIPTION

