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
    use_ok('SAuth::Provider::KeyStore::SQLite');
    use_ok('SAuth::Provider::TokenStore::SQLite');
    use_ok('SAuth::Consumer');
}

my $DB_FILE = file("$FindBin::Bin/data/db");

unlink $DB_FILE;

## .....................................................
## Initialize a provider object, tell it where to find
## and store the tokens and keys
## .....................................................

my $provider = SAuth::Provider->new(
    key_store    => SAuth::Provider::KeyStore::SQLite->new( db_file => $DB_FILE ),
    token_store  => SAuth::Provider::TokenStore::SQLite->new( db_file => $DB_FILE ),
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

my $uid = 'http://www.example.org';

{
    my $key = $provider->create_key(
        uid                => $uid,
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
    key => $provider->get_key_for($uid),
);
isa_ok($consumer, 'SAuth::Consumer');

## .....................................................
## The consumer prepares an access request to be sent
## to the provider
## .....................................................

my $access_request = $consumer->create_access_request(
    access_for     => [qw[ read ]],
    token_lifespan => 1
);
isa_ok($access_request, 'SAuth::Consumer::RequestWrapper');

## .....................................................
## the access request is sent to the provider, if
## it is accepted the provider returns an access
## grant to the consumer
## .....................................................

my $access_grant = $provider->process_access_request(
    uid       => $uid,
    hmac      => $access_request->hmac,
    timestamp => $access_request->timestamp,
    body      => $access_request->body->to_json
);
isa_ok($access_grant, 'SAuth::Core::AccessGrant');

## .....................................................
## The consumer recieves the access grant and can then
## start using the service protected by the provider
## .....................................................

$consumer->process_access_grant( $access_grant->to_json );

## .....................................................
## ... allow the validity of the access grant to lapse
## .....................................................

ok($access_grant->is_valid, '... the access grant it still valid');
ok($consumer->has_valid_access_grant, '... the consumer has a valid access grant');

diag("wait a second ...");
sleep(2);

ok(!$access_grant->is_valid, '... the access grant it no longer valid');
ok(!$consumer->has_valid_access_grant, '... the consumer no longer has a valid access grant');
ok($access_grant->can_refresh, '... we can refresh this access grant');

## .....................................................
## Now ask for an access refresh
## .....................................................

my $refresh_request = $consumer->create_refresh_request(
    token_lifespan => 100
);
isa_ok($refresh_request, 'SAuth::Consumer::RequestWrapper');
isa_ok($refresh_request->body, 'SAuth::Core::AccessRefresh');

## .....................................................
## the access refresh is sent to the provider, if
## it is accepted the provider returns an access
## grant to the consumer
## .....................................................

my $refreshed_access_grant = $provider->process_access_refresh(
    uid       => $uid,
    hmac      => $refresh_request->hmac,
    timestamp => $refresh_request->timestamp,
    body      => $refresh_request->body->to_json
);
isa_ok($refreshed_access_grant, 'SAuth::Core::AccessGrant');

ok($refreshed_access_grant->is_valid, '... the refreshed access grant it still valid');
ok(!$access_grant->is_valid, '... the old access grant it still not valid');

is($refreshed_access_grant->token, $access_grant->token, '... they have the same token');
isnt(
    SAuth::Util::format_datetime($refreshed_access_grant->timeout),
    SAuth::Util::format_datetime($access_grant->timeout),
    '... but they do not have the same timeout'
);

$consumer->process_access_grant( $refreshed_access_grant->to_json );

ok($consumer->has_valid_access_grant, '... the consumer has a valid access grant again');

## .....................................................
## The provider needs to provide the initial nonce
## .....................................................

my $current_nonce = $provider->generate_nonce;
like(SAuth::Util::encode_base64($current_nonce), qr/^[a-zA-Z0-9-_]+$/, '... got the nonce');

foreach ( 0 .. 10 ) {

    ## .....................................................
    ## every time the consumer wants to access the service
    ## they must first authenticate with the provider
    ## by sending the token and an hmac
    ##
    ## If the auth is successful, then they provider sends
    ## back the next nonce
    ## .....................................................
    is(exception {
        $current_nonce = $provider->authenticate(
            token => $consumer->access_grant->token,
            hmac  => $consumer->generate_token_hmac( $current_nonce ),
            nonce => $current_nonce,
        );
    }, undef, '... no exception has been thrown during authenticate');
}


done_testing;

