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
## Check the error handler on the access request
## .....................................................

{
    my $uid = 'http://www.example.tv';
    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->new( year => 2012 ),
        token_max_lifespan => 60
    );
    isa_ok($key, 'SAuth::Core::Key');

    my $consumer = SAuth::Consumer->new( key => $key );
    isa_ok($consumer, 'SAuth::Consumer');

    my $access_request = $consumer->create_access_request(
        access_for     => [qw[ read ]],
        token_lifespan => 30
    );
    isa_ok($access_request, 'SAuth::Consumer::RequestWrapper');

    like(exception{
        $provider->process_access_request(
            uid       => 'http://www.examples.tv',
            hmac      => $access_request->hmac,
            timestamp => $access_request->timestamp,
            body      => $access_request->body->to_json
        );
    }, qr/There is no key for the UID \(http\:\/\/www\.examples\.tv\)/, '... got the expection we expected');

    like(exception{
        $provider->process_access_request(
            uid       => $uid,
            hmac      => $access_request->hmac . 'junk',
            timestamp => $access_request->timestamp,
            body      => $access_request->body->to_json
        );
    }, qr/Invalid Access Request \- HMAC Verification Fail/, '... got the expection we expected');

    {
        my $bad_access_request = SAuth::Consumer::RequestWrapper->new(
            key       => $key,
            body      => $access_request->body,
            timestamp => 100, # one hundred seconds after the epoch
        );

        like(exception{
            $provider->process_access_request(
                uid       => $uid,
                hmac      => $bad_access_request->hmac,
                timestamp => $bad_access_request->timestamp,
                body      => $bad_access_request->body->to_json
            );
        }, qr/Invalid Access Request \- Request Expired/, '... got the expection we expected');
    }
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

    diag("wait a second ...");
    sleep(1);

    ok(!$key->is_valid, '... the key is no longer valid');

    like(exception{
        $provider->process_access_request(
            uid       => $uid,
            hmac      => $access_request->hmac,
            timestamp => $access_request->timestamp,
            body      => $access_request->body->to_json
        );
    }, qr/The key for UID \(http\:\/\/www\.example\.info\) is not valid/, '... got the expection we expected');
}

## .....................................................
## Create a valid key, and ask for an access grant with
## capabilties that are not allowed
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

    my $consumer = SAuth::Consumer->new( key => $key );
    isa_ok($consumer, 'SAuth::Consumer');

    my $access_request = $consumer->create_access_request(
        access_for     => [qw[ read create ]],
        token_lifespan => 30
    );
    isa_ok($access_request, 'SAuth::Consumer::RequestWrapper');

    like(exception {
        $provider->process_access_request(
            uid       => $uid,
            hmac      => $access_request->hmac,
            timestamp => $access_request->timestamp,
            body      => $access_request->body->to_json
        );
    }, qr/Cannot grant access for capability \(create\) because it is not allowed by this key/,
    '... unable to process an access request');

}

done_testing;
