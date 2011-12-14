package SAuth::Core::Role::WithMongoDBCollection;
use Moose::Role;

use MongoDB;
use boolean;

has 'collection' => (
    is       => 'ro',
    isa      => 'MongoDB::Collection',
    required => 1
);

no Moose::Role; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Core::Role::WithMongoDBCollection;

=head1 DESCRIPTION
