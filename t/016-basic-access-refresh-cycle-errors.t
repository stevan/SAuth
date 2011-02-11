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

{
    my $uid = 'http://www.example.org';

    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->new( day => 20, month => 12, year => 2012 ),
        token_max_lifespan => (24 * 60 * 60)
    );
    isa_ok($key, 'SAuth::Core::Key');

    my $consumer = SAuth::Consumer->new( key => $key );
    isa_ok($consumer, 'SAuth::Consumer');

    ## check some errors ...

    like(exception {
        $consumer->create_refresh_request( token_lifespan => 100 )
    }, qr/No current access grant to refresh/, '... got the expection expected');

    # make a unrefreshable access grant ...

    my $access_grant = SAuth::Core::AccessGrant->new(
        uid         => $uid,
        token       => 'skasdjkldfsajklsadflk',
        access_to   => [qw[ read ]],
        timeout     => DateTime->new( year => 2035 ),
        can_refresh => 0,
    );

    like(exception {
        $access_grant->refresh( DateTime->new( year => 2035 ) )
    }, qr/Cannot refresh this access grant/, '... got the expection expected');

    $consumer->access_grant( $access_grant );

    like(exception {
        $consumer->create_refresh_request( token_lifespan => 100 )
    }, qr/The current access grant does not allow refreshing/, '... got the expection expected');

}

{
    my $uid = 'http://www.example.com';

    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 0,
        expires            => DateTime->new( day => 20, month => 12, year => 2012 ),
        token_max_lifespan => (24 * 60 * 60)
    );
    isa_ok($key, 'SAuth::Core::Key');

    my $consumer = SAuth::Consumer->new( key => $key );
    isa_ok($consumer, 'SAuth::Consumer');

    ## check some errors ...

    $consumer->access_grant(
        SAuth::Core::AccessGrant->new(
            uid         => $uid,
            token       => 'skasdjkldfsajklsadflk',
            access_to   => [qw[ read ]],
            timeout     => DateTime->new( year => 2035 ),
            can_refresh => 1,
        )
    );

    like(exception {
        $consumer->create_refresh_request( token_lifespan => 100 )
    }, qr/The key does not allow refreshing/, '... got the expection expected');

}

{
    my $uid = 'http://www.example.net';

    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 0,
        expires            => DateTime->now,
        token_max_lifespan => (24 * 60 * 60)
    );
    isa_ok($key, 'SAuth::Core::Key');

    my $consumer = SAuth::Consumer->new( key => $key );
    isa_ok($consumer, 'SAuth::Consumer');

    ## check some errors ...

    $consumer->access_grant(
        SAuth::Core::AccessGrant->new(
            uid         => $uid,
            token       => 'skasdjkldfsajklsadflk',
            access_to   => [qw[ read ]],
            timeout     => DateTime->new( year => 2035 ),
            can_refresh => 1,
        )
    );

    diag("wait a second ...");
    sleep(1);

    like(exception {
        $consumer->create_refresh_request( token_lifespan => 100 )
    }, qr/The key is invalid/, '... got the expection expected');

}

{
    my $uid = 'http://www.example.edu';
    my $key = $provider->create_key(
        uid                => $uid,
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->new( year => 2012 ),
        token_max_lifespan => 60
    );
    isa_ok($key, 'SAuth::Core::Key');

    my $refresh_request = SAuth::Consumer::RequestWrapper->new(
        key  => $key,
        body => SAuth::Core::AccessRefresh->new(
            uid            => $uid,
            token          => 'abcdefghijklm',
            token_lifespan => 10
        )
    );

    like(exception {
        $provider->process_access_refresh(
            uid       => $uid,
            hmac      => $refresh_request->hmac,
            timestamp => $refresh_request->timestamp,
            body      => $refresh_request->body->to_json
        );
    }, qr/There is no access grant for token \(abcdefghijklm\)/, '... got the expection expected');

}

done_testing;


