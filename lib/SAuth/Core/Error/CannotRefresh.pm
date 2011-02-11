package SAuth::Core::Error::CannotRefresh;
use Moose;

extends 'SAuth::Core::Error';

__PACKAGE__->meta->make_immutable( inline_constructor => 0 );

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Core::Error::InvalidKey;

=head1 DESCRIPTION

