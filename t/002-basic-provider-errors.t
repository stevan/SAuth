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
    my $key = $provider->create_key(
        uid                => 'http://www.example.org',
        capabilities       => [qw[ read update ]],
        allow_refresh      => 1,
        expires            => DateTime->new( year => 2001 ),
        token_max_lifespan => 60
    );
    isa_ok($key, 'SAuth::Core::Key');
    ok(!$key->is_valid, '... this key is not valid');
}

{
    like(exception {
        $provider->create_key(
            uid                => 'http://www.example.org',
            capabilities       => [qw[ read transmogrify ]],
            allow_refresh      => 1,
            expires            => DateTime->new( year => 2012 ),
            token_max_lifespan => 60
        )
    }, qr/The capability \(transmogrify\) is not offered by this provider/,
    '... cannot create key with invalid capabilities');

    like(exception {
        $provider->create_key(
            uid                => 'http://www.example.org',
            capabilities       => [qw[ read ]],
            allow_refresh      => 1,
            expires            => DateTime->new( year => 2012 ),
            token_max_lifespan => 60
        )
    }, qr/There is already a key for http\:\/\/www\.example\.org/,
    '... cannot create key with with duplicate uid');
}



done_testing;