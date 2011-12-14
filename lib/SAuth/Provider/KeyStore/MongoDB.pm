package SAuth::Provider::KeyStore::MongoDB;
use Moose;

use SAuth::Util;
use SAuth::Core::Key;

with 'SAuth::Provider::KeyStore',
     'SAuth::Core::Role::WithMongoDBCollection';

sub has_key_for {
    my ($self, $uid) = @_;
    my $count = $self->collection->count( { _id => digest( $uid ) } );
    $count ? 1 : 0;
}

sub get_key_for {
    my ($self, $uid) = @_;
    my $doc = $self->collection->find_one( { _id => digest( $uid ) } );
    $self->unpack_key( $doc->{'key'} );
}

sub add_key_for {
    my ($self, $uid, $key) = @_;
    $self->collection->insert(
        {
            _id => digest( $uid ),
            key => $self->pack_key( $key )
        },
        { safe => 1 }
    );
}

sub pack_key {
    my ($self, $key) = @_;
    $key->expires->set_time_zone( 'America/New_York' )
        if $key->expires->time_zone->isa('DateTime::TimeZone::Floating');
    return +{
        uid                => $key->uid,
        capabilities       => $key->capabilities,
        allow_refresh      => $key->allow_refresh ? boolean::true() : boolean::false(),
        expires            => $key->expires,
        token_max_lifespan => $key->token_max_lifespan,
        shared_secret      => encode_base64( $key->shared_secret ),
    }
}

sub unpack_key {
    my ($class, $data) = @_;
    $data->{allow_refresh} = $data->{allow_refresh} == boolean::true() ? 1 : 0;
    $data->{shared_secret} = decode_base64( $data->{shared_secret} );
    SAuth::Core::Key->new( $data );
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::KeyStore::MongoDB;

=head1 DESCRIPTION

