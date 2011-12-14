package SAuth::Provider::TokenStore::MongoDB;
use Moose;

use SAuth::Util;
use SAuth::Core::AccessGrant;

with 'SAuth::Provider::TokenStore',
     'SAuth::Core::Role::WithMongoDBCollection';

sub has_access_grant_for_token {
    my ($self, $token) = @_;
    my $count = $self->collection->count( { token => $token } );
    $count ? 1 : 0;
}

sub get_access_grant_for_token {
    my ($self, $token) = @_;
    my $doc = $self->collection->find_one( { token => $token } );
    $self->unpack_access_grant( $doc->{'access_grant'} );
}

sub update_access_grant_for_token {
    my ($self, $access_grant) = @_;
    $self->collection->update(
        { token        => $access_grant->token },
        { access_grant => $self->pack_access_grant( $access_grant ) },
        { safe         => 1 }
    );
}

sub add_access_grant_for_token {
    my ($self, $access_grant) = @_;
    $self->collection->insert(
        {
            token        => $access_grant->token,
            access_grant => $self->pack_access_grant( $access_grant )
        },
        { safe => 1 }
    );
}

sub pack_access_grant {
    my ($self, $access_grant) = @_;
    $access_grant->timeout->set_time_zone( 'America/New_York' )
        if $access_grant->timeout->time_zone->isa('DateTime::TimeZone::Floating');
    return +{
        uid         => $access_grant->uid,
        token       => $access_grant->token,
        access_to   => $access_grant->access_to,
        timeout     => $access_grant->timeout,
        can_refresh => $access_grant->can_refresh ? boolean::true() : boolean::false()
    }
}

sub unpack_access_grant {
    my ($self, $data) = @_;
    $data->{can_refresh} = $data->{can_refresh} == boolean::true() ? 1 : 0;
    SAuth::Core::AccessGrant->new( $data );
}


__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::TokenStore::MongoDB;

=head1 DESCRIPTION

