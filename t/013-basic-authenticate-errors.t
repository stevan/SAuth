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

# cannot find the token ...
{
    my $uid = 'http://www.example.org';
    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->new( day => 20, month => 12, year => 2025 ),
        token_max_lifespan => (24 * 60 * 60)
    );
    isa_ok($key, 'SAuth::Core::Key');

    my $consumer = SAuth::Consumer->new( key => $key );
    isa_ok($consumer, 'SAuth::Consumer');

    my $access_request = $consumer->create_access_request(
        access_for     => [qw[ read ]],
        token_lifespan => (20 * 60 * 60)
    );
    isa_ok($access_request, 'SAuth::Consumer::RequestWrapper');

    my $access_grant = $provider->process_access_request(
        uid       => $uid,
        hmac      => $access_request->hmac,
        timestamp => $access_request->timestamp,
        body      => $access_request->body->to_json
    );
    isa_ok($access_grant, 'SAuth::Core::AccessGrant');

    $consumer->process_access_grant( $access_grant->to_json );

    my $current_nonce = $provider->generate_nonce;

    like(exception {
        $current_nonce = $provider->authenticate(
            token => 'foo',
            hmac  => $consumer->generate_token_hmac( $current_nonce ),
            nonce => $current_nonce,
        );
    }, qr/There is no access grant for token \(foo\)/, '... got exception in authenticate');
}

# invalid access grant ...
{
    my $uid = 'http://www.example.com';
    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->new( day => 20, month => 12, year => 2025 ),
        token_max_lifespan => (24 * 60 * 60)
    );
    isa_ok($key, 'SAuth::Core::Key');

    my $consumer = SAuth::Consumer->new( key => $key );
    isa_ok($consumer, 'SAuth::Consumer');

    my $access_request = $consumer->create_access_request(
        access_for     => [qw[ read ]],
        token_lifespan => 1
    );
    isa_ok($access_request, 'SAuth::Consumer::RequestWrapper');

    my $access_grant = $provider->process_access_request(
        uid       => $uid,
        hmac      => $access_request->hmac,
        timestamp => $access_request->timestamp,
        body      => $access_request->body->to_json
    );
    isa_ok($access_grant, 'SAuth::Core::AccessGrant');

    $consumer->process_access_grant( $access_grant->to_json );

    ok($consumer->has_valid_access_grant, '... we have a valid access grant');

    my $current_nonce = $provider->generate_nonce;
    my $hmac          = $consumer->generate_token_hmac( $current_nonce );

    diag("wait 2 seconds ...");
    sleep(2);

    ok(!$consumer->has_valid_access_grant, '... the access grant is no longer valid');

    like(exception {
        $current_nonce = $provider->authenticate(
            token => $access_grant->token,
            hmac  => $hmac,
            nonce => $current_nonce,
        );
    }, qr/The access grant for token \(.*\) is not valid/, '... got exception in authenticate');
}

# invalid key ...
{
    my $uid = 'http://www.example.net';
    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->now,
        token_max_lifespan => (24 * 60 * 60)
    );
    isa_ok($key, 'SAuth::Core::Key');

    my $consumer = SAuth::Consumer->new( key => $key );
    isa_ok($consumer, 'SAuth::Consumer');

    my $access_request = $consumer->create_access_request(
        access_for     => [qw[ read ]],
        token_lifespan => 1
    );
    isa_ok($access_request, 'SAuth::Consumer::RequestWrapper');

    my $access_grant = $provider->process_access_request(
        uid       => $uid,
        hmac      => $access_request->hmac,
        timestamp => $access_request->timestamp,
        body      => $access_request->body->to_json
    );
    isa_ok($access_grant, 'SAuth::Core::AccessGrant');

    $consumer->process_access_grant( $access_grant->to_json );

    ok($key->is_valid, '... key is valid');
    ok($consumer->has_valid_access_grant, '... we have a valid access grant');

    my $current_nonce = $provider->generate_nonce;
    my $hmac          = $consumer->generate_token_hmac( $current_nonce );

    diag("wait a second ...");
    sleep(1);

    ok(!$key->is_valid, '... key is no longer valid');
    ok($consumer->has_valid_access_grant, '... the access grant is no longer valid');

    like(exception {
        $current_nonce = $provider->authenticate(
            token => $access_grant->token,
            hmac  => $hmac,
            nonce => $current_nonce,
        );
    }, qr/The key for UID \(http\:\/\/www\.example\.net\) is not valid/, '... got exception in authenticate');
}

# bad hmac
{
    my $uid = 'http://www.example.info';
    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->new( day => 20, month => 12, year => 2025 ),
        token_max_lifespan => (24 * 60 * 60)
    );
    isa_ok($key, 'SAuth::Core::Key');

    my $consumer = SAuth::Consumer->new( key => $key );
    isa_ok($consumer, 'SAuth::Consumer');

    my $access_request = $consumer->create_access_request(
        access_for     => [qw[ read ]],
        token_lifespan => (20 * 60 * 60)
    );
    isa_ok($access_request, 'SAuth::Consumer::RequestWrapper');

    my $access_grant = $provider->process_access_request(
        uid       => $uid,
        hmac      => $access_request->hmac,
        timestamp => $access_request->timestamp,
        body      => $access_request->body->to_json
    );
    isa_ok($access_grant, 'SAuth::Core::AccessGrant');

    $consumer->process_access_grant( $access_grant->to_json );

    my $current_nonce = $provider->generate_nonce;

    like(exception {
        $current_nonce = $provider->authenticate(
            token => $access_grant->token,
            hmac  => $consumer->generate_token_hmac( $current_nonce ) . 'foo',
            nonce => $current_nonce,
        );
    }, qr/Authentication Fail \- HMAC Verification Fail/, '... got exception in authenticate');
}


done_testing;

