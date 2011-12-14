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
$DB_FILE->parent->mkpath;

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
## Create invalid key and assign it to the consumer
## .....................................................

{
    my $uid = 'http://www.example.org';
    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->new( year => 2001 ),
        token_max_lifespan => 60 # one minute
    );
    isa_ok($key, 'SAuth::Core::Key');
    ok(!$key->is_valid, '... the key is not valid');

    like(exception {
        SAuth::Consumer->new( key => $key )
    }, qr/The key is invalid/,
    '... cannot create a consumer with an invalid key');

    like(exception {
        SAuth::Consumer->new(
            key => $provider->get_key_for( $uid ),
        )
    }, qr/The key is invalid/,
    '... cannot create a consumer with an invalid key');
}

## .....................................................
## Create a valid key, but let it expire then try
## and use it
## .....................................................

{
    my $uid = 'http://www.example.com';
    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->now,
        token_max_lifespan => 60
    );
    isa_ok($key, 'SAuth::Core::Key');

    my $consumer;
    is(exception {
        $consumer = SAuth::Consumer->new( key => $key );
    }, undef, '... able to create a key');
    isa_ok($consumer, 'SAuth::Consumer');

    diag("wait a second ...");
    sleep(1);

    ok(!$consumer->key->is_valid, '... the key is no longer valid');

    like(exception {
        $consumer->create_access_request(
            access_for     => [qw[ read ]],
            token_lifespan => (20 * 60 * 60)
        )
    }, qr/The key is invalid/, '... got an exception now');

    like(exception{
        $consumer->generate_token_hmac
    }, qr/Cannot generate token hmac without a nonce/, '... got the expection we expected');

    like(exception{
        $consumer->generate_token_hmac( 'nonce' )
    }, qr/Cannot generate token hmac without a valid access grant/, '... got the expection we expected');
}

## .....................................................
## Create a valid key, and get an access grant, but let
## the key expire then try and use it
## .....................................................

{
    my $uid = 'http://www.example.info';
    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->now,
        token_max_lifespan => 60
    );
    isa_ok($key, 'SAuth::Core::Key');

    my $consumer;
    is(exception {
        $consumer = SAuth::Consumer->new( key => $key );
    }, undef, '... able to consume a key');
    isa_ok($consumer, 'SAuth::Consumer');

    my $access_request;
    is(exception {
        $access_request = $consumer->create_access_request(
            access_for     => [qw[ read ]],
            token_lifespan => 30
        )
    }, undef, '... able to create an access request');
    isa_ok($access_request, 'SAuth::Consumer::RequestWrapper');

    my $access_grant = $provider->process_access_request(
        uid       => $uid,
        hmac      => $access_request->hmac,
        timestamp => $access_request->timestamp,
        body      => $access_request->body->to_json
    );
    isa_ok($access_grant, 'SAuth::Core::AccessGrant');

    $consumer->process_access_grant( $access_grant->to_json );

    ok($consumer->has_access_grant, '... we have an access grant');

    diag("wait a second ...");
    sleep(1);

    ok(!$consumer->key->is_valid, '... the key is no longer valid');

    like(exception{
        $consumer->generate_token_hmac( 'nonce' );
    }, qr/Cannot generate token hmac with an invalid key/, '... got the expection we expected');
}

## .....................................................
## Create a valid key and then get an access grant
## and let that expire, and try to use it
## .....................................................

{
    my $uid = 'http://www.example.net';
    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->new( year => 2012 ),
        token_max_lifespan => 60
    );
    isa_ok($key, 'SAuth::Core::Key');

    my $consumer;
    is(exception {
        $consumer = SAuth::Consumer->new( key => $key );
    }, undef, '... able to consume a key');
    isa_ok($consumer, 'SAuth::Consumer');

    my $access_request;
    is(exception {
        $access_request = $consumer->create_access_request(
            access_for     => [qw[ read ]],
            token_lifespan => 1
        )
    }, undef, '... able to create an access request');
    isa_ok($access_request, 'SAuth::Consumer::RequestWrapper');

    my $access_grant = $provider->process_access_request(
        uid       => $uid,
        hmac      => $access_request->hmac,
        timestamp => $access_request->timestamp,
        body      => $access_request->body->to_json
    );
    isa_ok($access_grant, 'SAuth::Core::AccessGrant');

    $consumer->process_access_grant( $access_grant->to_json );

    ok($consumer->has_access_grant, '... we have an access grant');
    ok($consumer->has_valid_access_grant, '... we have a valid access grant');

    diag("wait 2 seconds ...");
    sleep(2);

    ok($consumer->key->is_valid, '... the key is still longer valid');
    ok(!$consumer->has_valid_access_grant, '... the access grant is no longer valid');

    like(exception{
        $consumer->generate_token_hmac( 'nonce' );
    }, qr/Cannot generate token hmac without a valid access grant/, '... got the expection we expected');
}



done_testing;
