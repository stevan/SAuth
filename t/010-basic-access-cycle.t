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
    use_ok('SAuth::Core::TokenStore::Hash');
    use_ok('SAuth::Consumer');
}

map { -f $_ ? unlink( $_ ) : () } dir("$FindBin::Bin/key-store")->children;

my $provider = SAuth::Provider->new(
    secret       => 'shhh its a secret, dont tell anyone',
    token_store  => SAuth::Core::TokenStore::Hash->new,
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

my $consumer = SAuth::Consumer->new(
    key         => $provider->get_key_for('http://www.example.org'),
    token_store => SAuth::Core::TokenStore::Hash->new,
);
isa_ok($consumer, 'SAuth::Consumer');

## .....................................................

my $access_request = $consumer->create_access_request(
    access_for     => [qw[ read ]],
    token_lifespan => (20 * 60 * 60)
);
isa_ok($access_request, 'SAuth::Consumer::RequestWrapper');

like($access_request->hmac, qr/^[a-f0-9]+$/, '... go the hmac digest');
isa_ok($access_request->body, 'SAuth::Core::AccessRequest');

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
like($access_grant->token, qr/^[A-Z0-9-]+$/, '... go the token');

## .....................................................

$consumer->process_access_grant(
    current_nonce => undef,
    access_grant  => $access_grant->to_json
);


done_testing;

