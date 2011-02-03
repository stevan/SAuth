package SAuth::Provider::KeyStore::Dir;
use Moose;
use MooseX::Types::Path::Class;

use SAuth::Util;
use SAuth::Core::Key;

has 'dir' => (
    is       => 'ro',
    isa      => 'Path::Class::Dir',
    coerce   => 1,
    required => 1
);

with 'SAuth::Provider::KeyStore';

sub has_key_for {
    my ($self, $uid) = @_;
    -e $self->dir->file( digest( $uid ) . '.json' ) ? 1 : 0
}

sub get_key_for {
    my ($self, $uid) = @_;
    SAuth::Core::Key->from_json( $self->dir->file( digest( $uid ) . '.json' )->slurp );
}

sub add_key_for {
    my ($self, $uid, $key) = @_;
    my $fh = $self->dir->file( digest( $uid ) . '.json' )->openw;
    $fh->print( $key->to_json );
    $fh->close;
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::KeyStore::Hash;

=head1 DESCRIPTION

