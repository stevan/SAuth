package SAuth::Provider;
use Moose;
use MooseX::StrictConstructor;
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
            || SAuth::Core::Error->throw("The capability ($capability) is not offered by this provider");
    }

    SAuth::Core::Error->throw("There is already a key for $uid")
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
    my $self = shift;

    my ($key, $body) = $self->_process_and_verify_request( @_ );

    return $self->_grant_access(
        $key,
        SAuth::Core::AccessRequest->from_json( $body )
    );
}

sub process_access_refresh {
    my $self = shift;

    my ($key, $body) = $self->_process_and_verify_request( @_ );

    return $self->_refresh_access(
        $key,
        SAuth::Core::AccessRefresh->from_json( $body )
    );
}

sub _process_and_verify_request {
    my ($self, $uid, $timestamp, $body, $hmac) = validated_list(\@_,
        uid       => { isa => 'Str'    },
        timestamp => { isa => 'Int'    },
        body      => { isa => 'Str'    },
        hmac      => { isa => 'Str'    },
    );

    ($self->has_key_for( $uid ))
        || SAuth::Core::Error->throw("There is no key for the UID ($uid)");

    my $key = $self->get_key_for( $uid );

    ($key->is_valid)
        || SAuth::Core::Error::InvalidKey->throw("The key for UID ($uid) is not valid");

    my $digest = hmac_digest( $key->shared_secret, $timestamp, $body );

    if ( $hmac eq $digest ) {

        my $now   = DateTime->now;
        my $stamp = DateTime->from_epoch( epoch => $timestamp );
        my $diff  = $now - $stamp;

        unless ( DateTime::Duration->compare( $diff, $self->access_request_timestamp_tolerance ) <= 0 ) {
            SAuth::Core::Error->throw("Invalid Access Request - Request Expired")
        }

        return ( $key, $body );
    }
    else {
        SAuth::Core::Error::HMACVerificationFail->throw("Invalid Access Request - HMAC Verification Fail");
    }
}

sub _grant_access {
    my ($self, $key, $request) = @_;

    foreach my $capability ( @{ $request->access_for } ) {
        ($key->has_capability( $capability ))
            || SAuth::Core::Error->throw("Cannot grant access for capability ($capability) because it is not allowed by this key");
    }

    my $token_lifespan = min( $key->token_max_lifespan, $request->token_lifespan );
    my $allow_refresh  = $key->allow_refresh;
    my $timeout        = (DateTime->now + DateTime::Duration->new( seconds => $token_lifespan ));

    my $access_grant = SAuth::Core::AccessGrant->new(
        uid         => $key->uid,
        token       => generate_uuid(),
        access_to   => $request->access_for,
        timeout     => $timeout,
        can_refresh => $allow_refresh,
    );

    $self->token_store->add_access_grant_for_token( $access_grant );

    $access_grant;
}

sub _refresh_access {
    my ($self, $key, $request) = @_;

    ($self->has_access_grant_for_token( $request->token ))
        || SAuth::Core::Error->throw("There is no access grant for token (" . $request->token . ")");

    my $access_grant   = $self->token_store->get_access_grant_for_token( $request->token );
    my $token_lifespan = min( $key->token_max_lifespan, $request->token_lifespan );
    my $timeout        = (DateTime->now + DateTime::Duration->new( seconds => $token_lifespan ));

    $self->token_store->update_access_grant_for_token( $access_grant->refresh( $timeout ) );

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
        || SAuth::Core::Error->throw("There is no access grant for token ($token)");

    my $access_grant = $self->get_access_grant_for_token( $token );

    ($access_grant->is_valid)
        || SAuth::Core::Error->throw("The access grant for token ($token) is not valid");

    ($self->has_key_for( $access_grant->uid ))
        || SAuth::Core::Error->throw("There is no key for the UID (" . $access_grant->uid . ")");

    my $key = $self->get_key_for( $access_grant->uid );

    ($key->is_valid)
        || SAuth::Core::Error::InvalidKey->throw("The key for UID (" . $access_grant->uid . ") is not valid");

    my $digest = hmac_digest( $key->shared_secret, $token, $nonce );

    ( $digest eq $hmac )
        || SAuth::Core::Error::HMACVerificationFail->throw("Authentication Fail - HMAC Verification Fail");

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

