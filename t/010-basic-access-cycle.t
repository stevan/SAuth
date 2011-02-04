#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Fatal;
use Test::Moose;

use FindBin;
use DateTime;
use Path::Class;

BEGIN {
    use_ok('SAuth::Provider');
    use_ok('SAuth::Provider::KeyStore::Dir');
    use_ok('SAuth::Provider::TokenStore::Hash');
    use_ok('SAuth::Consumer');
}

map { -f $_ ? unlink( $_ ) : () } dir("$FindBin::Bin/key-store")->children;

## .....................................................
## Initialize a provider object, tell it where to find
## and store the tokens and keys
## .....................................................

my $provider = SAuth::Provider->new(
    secret       => 'shhh its a secret, dont tell anyone',
    token_store  => SAuth::Provider::TokenStore::Hash->new,
    key_store    => SAuth::Provider::KeyStore::Dir->new( dir => [ $FindBin::Bin, 'key-store' ]),
    capabilities => [qw[
        create
        read
        update
        delete
    ]]
);
isa_ok($provider, 'SAuth::Provider');

## .....................................................
## Create a key for a consumer
## .....................................................

{
    my $key = $provider->create_key(
        uid                => 'http://www.example.org',
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->new( day => 20, month => 12, year => 2012 ),
        token_max_lifespan => (24 * 60 * 60)
    );
    isa_ok($key, 'SAuth::Core::Key');
}

## .....................................................
## Initialize the consumer object with the key
## .....................................................

my $consumer = SAuth::Consumer->new(
    key => $provider->get_key_for('http://www.example.org'),
);
isa_ok($consumer, 'SAuth::Consumer');

## .....................................................
## The consumer prepares an access request to be sent
## to the provider
## .....................................................

my $access_request = $consumer->create_access_request(
    access_for     => [qw[ read ]],
    token_lifespan => (20 * 60 * 60)
);
isa_ok($access_request, 'SAuth::Consumer::RequestWrapper');

like($access_request->hmac, qr/^[a-f0-9]+$/, '... go the hmac digest');
isa_ok($access_request->body, 'SAuth::Core::AccessRequest');

## .....................................................
## the access request is sent to the provider, if
## it is accepted the provider returns an access
## grant to the consumer
## .....................................................

my $access_grant = $provider->process_access_request(
    uid       => 'http://www.example.org',
    hmac      => $access_request->hmac,
    timestamp => $access_request->timestamp,
    body      => $access_request->body->to_json
);
isa_ok($access_grant, 'SAuth::Core::AccessGrant');

isa_ok($access_grant->timeout, 'DateTime');
ok($access_grant->can_refresh, '... we are allowed to refresh this token');
is_deeply($access_grant->access_to, [qw[ read ]], '... got the right access');
like($access_grant->token, qr/^[A-Z0-9-]+$/, '... got the token');
like(SAuth::Util::encode_base64($access_grant->nonce), qr/^[a-zA-Z0-9\/\+]+==$/, '... got the nonce');

## .....................................................
## The consumer recieves the access grant and can then
## start using the service protected by the provider
## .....................................................

$consumer->process_access_grant( $access_grant->to_json );

foreach ( 0 .. 10 ) {

    # Check the nonce
    is(
        $consumer->access_grant->nonce,
        $provider->get_current_nonce_for_token( $consumer->access_grant->token ),
        '... our current nonces match'
    );

    my ($next_nonce, $new_timeout);

    ## .....................................................
    ## every time the consumer wants to access the service
    ## they must first authenticate with the provider
    ## by sending the token and an hmac
    ##
    ## If the auth is successful, then they provider sends
    ## back the next nonce, and if allow-refresh was true,
    ## and the token timed out, a new timeout.
    ## .....................................................
    is(exception {
        ($next_nonce, $new_timeout) = $provider->authenticate(
            token => $consumer->access_grant->token,
            hmac  => $consumer->generate_token_hmac
        );
    }, undef, '... no exception has been thrown during authenticate');

    $consumer->access_grant->nonce( $next_nonce );
    if ( $new_timeout ) {
        $consumer->access_grant->timeout( $new_timeout );
    }
}


done_testing;

