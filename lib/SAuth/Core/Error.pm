package SAuth::Core::Error;
use Moose;

extends 'Throwable::Error';

__PACKAGE__->meta->make_immutable( inline_constructor => 0 );

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Core::Error;

=head1 DESCRIPTION

