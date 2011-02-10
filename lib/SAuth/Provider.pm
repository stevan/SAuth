package SAuth::Provider;
use Moose;
use MooseX::Params::Validate;

use SAuth::Util;

use SAuth::Core::Key;
use SAuth::Core::AccessRequest;
use SAuth::Core::AccessGrant;

use SAuth::Provider::KeyStore;
use SAuth::Provider::TokenStore;

use DateTime;
use DateTime::Duration;
use List::AllUtils qw[ first min ];

has 'capabilities' => (
    traits   => [ 'Array' ],
    is       => 'ro',
    isa      => 'ArrayRef[ Str ]',
    required => 1,
    handles  => {
        '_find_capability' => 'first'
    }
);

has 'access_request_timestamp_tolerance' => (
    is      => 'ro',
    isa     => 'DateTime::Duration',
    lazy    => 1,
    default => sub { DateTime::Duration->new( seconds => 30 ) },
);

has 'key_store' => (
    is       => 'ro',
    does     => 'SAuth::Provider::KeyStore',
    required => 1,
    handles  => [qw[
        get_key_for
        has_key_for
    ]]
);

has 'token_store' => (
    is       => 'ro',
    does     => 'SAuth::Provider::TokenStore',
    required => 1,
    handles  => [qw[
        get_access_grant_for_token
        has_access_grant_for_token
    ]]
);

## Key creation and management

sub create_key {
    my ($self, $uid, $capabilities, $allow_refresh, $expires, $token_max_lifespan) = validated_list(\@_,
        uid                => { isa => 'Str' },
        capabilities       => { isa => 'ArrayRef[Str]' },
        allow_refresh      => { isa => 'Bool' },
        expires            => { isa => 'DateTime' },
        token_max_lifespan => { isa => 'Int' },
    );

    foreach my $capability ( @$capabilities ) {
        ( $self->has_capability( $capability ) )
            || confess "The capability ($capability) is not offered by this provider";
    }

    confess "There is already a key for $uid"
        if $self->has_key_for( $uid );

    my $key = SAuth::Core::Key->new(
        uid                => $uid,
        capabilities       => $capabilities,
        allow_refresh      => $allow_refresh,
        expires            => $expires,
        token_max_lifespan => $token_max_lifespan,
        shared_secret      => generate_random_data()
    );

    $self->key_store->add_key_for( $key->uid, $key );

    $key;
}

## Access request

sub process_access_request {
    my ($self, $uid, $timestamp, $body, $hmac) = validated_list(\@_,
        uid       => { isa => 'Str' },
        timestamp => { isa => 'Int' },
        body      => { isa => 'Str' },
        hmac      => { isa => 'Str' },
    );

    ($self->has_key_for( $uid ))
        || confess "There is no key for the UID ($uid)";

    my $key = $self->get_key_for( $uid );

    ($key->is_valid)
        || confess "The key for UID ($uid) is not valid";

    my $digest = hmac_digest( $key->shared_secret, $timestamp, $body );

    if ( $hmac eq $digest ) {

        my $now   = DateTime->now;
        my $stamp = DateTime->from_epoch( epoch => $timestamp );
        my $diff  = $now - $stamp;

        unless ( DateTime::Duration->compare( $diff, $self->access_request_timestamp_tolerance ) <= 0 ) {
            confess "Invalid Access Request - Request Expired"
        }

        return $self->_grant_access(
            $key,
            SAuth::Core::AccessRequest->from_json( $body )
        );
    }
    else {
        confess "Invalid Access Request - HMAC Verification Fail";
    }
}

sub _grant_access {
    my ($self, $key, $request) = @_;

    my @access_to;
    foreach my $capability ( @{ $request->access_for }) {
        push @access_to => $capability
            if $key->has_capability( $capability );
    }

    my $token_lifespan = min( $key->token_max_lifespan, $request->token_lifespan );
    my $allow_refresh  = $key->allow_refresh;
    my $timeout        = (DateTime->now + DateTime::Duration->new( seconds => $token_lifespan ));

    my $access_grant = SAuth::Core::AccessGrant->new(
        uid         => $key->uid,
        token       => generate_uuid(),
        access_to   => \@access_to,
        timeout     => $timeout,
        can_refresh => $allow_refresh,
    );

    $self->token_store->add_access_grant_for_token( $access_grant );

    $access_grant;
}

## Nonce service

sub generate_nonce { generate_random_data() }

## Authentication

sub authenticate {
    my ($self, $token, $hmac, $nonce) = validated_list(\@_,
        token => { isa => 'Str' },
        hmac  => { isa => 'Str' },
        nonce => { isa => 'Str' },
    );

    ($self->has_access_grant_for_token( $token ))
        || confess "There is no access grant for token ($token)";

    my $access_grant = $self->get_access_grant_for_token( $token );

    ($access_grant->is_valid)
        || confess "The access grant for token ($token) is not valid";

    ($self->has_key_for( $access_grant->uid ))
        || confess "There is no key for the UID (" . $access_grant->uid . ")";

    my $key = $self->get_key_for( $access_grant->uid );

    ($key->is_valid)
        || confess "The key for UID (" . $access_grant->uid . ") is not valid";

    my $digest = hmac_digest( $key->shared_secret, $token, $nonce );

    ( $digest eq $hmac )
        || confess "Authentication Fail - HMAC Verification Fail";

    return $self->generate_nonce;
}

## Util methods

sub has_capability {
    my ($self, $capability) = @_;
    $self->_find_capability( sub { $_ eq $capability } ) ? 1 : 0;
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider;

=head1 DESCRIPTION

