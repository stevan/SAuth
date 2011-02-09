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
}

my $DB_FILE = file("$FindBin::Bin/key-store/db");

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

my $json;

{
    my $key = $provider->create_key(
        uid                => 'http://www.example.org',
        capabilities       => [qw[
            read
            update
        ]],
        allow_refresh      => 1,
        expires            => DateTime->new( day => 20, month => 12, year => 2012 ),
        token_max_lifespan => 24 * 60 * 60
    );
    isa_ok($key, 'SAuth::Core::Key');

    check_key( $key );

    $json = $key->to_json;
}

{
    my $key = SAuth::Core::Key->from_json( $json );
    check_key( $key );
}

{
    check_key( $provider->get_key_for( 'http://www.example.org' ) );
}


done_testing;

sub check_key {
    my $key = shift;
    is($key->uid, 'http://www.example.org', '... got the right uid');
    is_deeply($key->capabilities, [qw[ read update ]], '... got the right capabilities');
    ok($key->allow_refresh, '... got the right allow_refresh');
    is($key->expires->day, 20, '... got the right expires day');
    is($key->expires->month, 12, '... got the right expires month');
    is($key->expires->year, 2012, '... got the right expires year');
    is($key->token_max_lifespan, 24 * 60 * 60, '... got the right token max lifespan in hours');
    like(SAuth::Util::encode_base64($key->shared_secret), qr/^[a-zA-Z0-9-_]+$/, '... got the expected shared secret format');
}