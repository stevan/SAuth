#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Fatal;
use Test::Moose;
use DateTime;

BEGIN {
    use_ok('SAuth');
    use_ok('SAuth::Provider::KeyStore::Hash')
}

my $_24_HOURS = 24 * 60 * 60;
my $JSON_KEY = '{"allow_refresh":true,"capabilities":["read","update"],"expires":"2012-12-20T00:00:00Z","shared_secret":"ca2625eed11a8f22a16e83a9eb78e23816d68e2eb6443ce0dfb89659154263d1","token_max_lifespan":"86400","uid":"http://www.example.org"}';

my $provider = SAuth::Provider->new(
    secret       => 'shhh its a secret, dont tell anyone',
    key_store    => SAuth::Provider::KeyStore::Hash->new,
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
        capabilities       => [qw[
            read
            update
        ]],
        allow_refresh      => 1,
        expires            => DateTime->new( day => 20, month => 12, year => 2012 ),
        token_max_lifespan => $_24_HOURS
    );
    isa_ok($key, 'SAuth::Provider::Key');

    check_key( $key );
}

{
    my $key = SAuth::Provider::Key->from_JSON( $JSON_KEY );
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
    is($key->token_max_lifespan, $_24_HOURS, '... got the right token max lifespan in hours');
    like($key->shared_secret, qr/^[a-z0-9]+$/, '... got the expected shared secret format');
    is($key->to_JSON, $JSON_KEY, '... got the JSON we expected');
}