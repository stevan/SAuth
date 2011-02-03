package SAuth::Core::TokenStore;
use Moose::Role;

use SAuth::Util;

requires 'has_token';
requires 'add_token';
requires 'get_token';

no Moose::Role; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Core::TokenStore;

=head1 DESCRIPTION

