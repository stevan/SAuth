package SAuth::Provider::KeyStore::Hash;
use Moose;

has 'keys' => (
    traits  => [ 'Hash' ],
    is      => 'ro',
    isa     => 'HashRef[ SAuth::Provider::Key ]',
    lazy    => 1,
    default => sub { +{} },
    handles => {
        'has_key_for' => 'exists',
        'add_key_for' => 'set',
        'get_key_for' => 'get',
    }
);

# Moose :(
with 'SAuth::Provider::KeyStore';

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::KeyStore::Hash;

=head1 DESCRIPTION

