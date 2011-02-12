#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Fatal;
use Test::Moose;

use FindBin;
use DateTime;
use Path::Class;
use Plack::Client;
use Plack::Builder;
use HTTP::Request::Common qw[ GET POST DELETE ];

BEGIN {
    use_ok('SAuth::Provider');
    use_ok('SAuth::Provider::KeyStore::SQLite');
    use_ok('SAuth::Provider::TokenStore::SQLite');
    use_ok('SAuth::Consumer');

    use_ok('SAuth::Web::Provider');
    use_ok('SAuth::Web::Provider::AuthMiddleware');
    use_ok('SAuth::Web::Consumer::Client');
}

my $DB_FILE = file("$FindBin::Bin/data/db");

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

my $key = $provider->create_key(
    uid                => 'http://www.example.org',
    capabilities       => [qw[ read update ]],
    allow_refresh      => 1,
    expires            => DateTime->new( day => 20, month => 12, year => 2012 ),
    token_max_lifespan => (24 * 60 * 60)
);

# .........

{
    my $app = builder {
        mount '/sauth/' => sub { [ 500, [], [] ] };
        mount '/-/'     => SAuth::Web::Provider::AuthMiddleware->new(
            provider => $provider,
            realm    => 'protected-service',
            app      => sub {
                my $r = Plack::Request->new( shift );
                return [
                    200, [], [
                        'METHOD: ' . $r->method . ';' .
                        'PATH: ' . $r->path
                    ]
                ];
            }
        );
    };

    my $client = SAuth::Web::Consumer::Client->new(
        provider_uri => 'psgi-local://test_app/sauth/',
        service_uri  => 'psgi-local://test_app/-/',
        consumer     => SAuth::Consumer->new( key => $key ),
        plack_client => Plack::Client->new(
            'psgi-local' => {
                apps => {
                    test_app => $app
                }
            }
        )
    );

    ok(!$client->consumer->access_grant, '... no access grant yet');
    ok(!$client->nonce, '... we dont have a nonce');
    ok(!$client->is_ready, '... we are not ready');

    like(exception {
        $client->request_access(
            access_for     => [qw[ read ]],
            token_lifespan => (20 * 60 * 60)
        );
    }, qr/Access Request failed/, '... access request failed (as expected)');
}

{
    my $app = builder {
        mount '/sauth/' => builder {
            mount '/request_access/' => sub {
                return [
                    200, [], [
                        SAuth::Core::AccessGrant->new(
                            uid         => 'test',
                            token       => 'token',
                            access_to   => [qw[ read ]],
                            timeout     => DateTime->now,
                            can_refresh => 1
                        )->to_json
                    ]
                ]
            };
            mount '/generate_nonce/' => sub { [ 500, [], [] ] };
        };
        mount '/-/'     => SAuth::Web::Provider::AuthMiddleware->new(
            provider => $provider,
            realm    => 'protected-service',
            app      => sub {
                my $r = Plack::Request->new( shift );
                return [
                    200, [], [
                        'METHOD: ' . $r->method . ';' .
                        'PATH: ' . $r->path
                    ]
                ];
            }
        );
    };

    my $client = SAuth::Web::Consumer::Client->new(
        provider_uri => 'psgi-local://test_app/sauth/',
        service_uri  => 'psgi-local://test_app/-/',
        consumer     => SAuth::Consumer->new( key => $key ),
        plack_client => Plack::Client->new(
            'psgi-local' => {
                apps => {
                    test_app => $app
                }
            }
        )
    );

    ok(!$client->consumer->access_grant, '... no access grant yet');
    ok(!$client->nonce, '... we dont have a nonce');
    ok(!$client->is_ready, '... we are not ready');

    like(exception {
        $client->aquire_nonce(
            access_for     => [qw[ read ]],
            token_lifespan => (20 * 60 * 60)
        );
    }, qr/Nonce fetch failed/, '... access request failed (as expected)');
}

{
    my $app = builder {
        mount '/sauth/' => SAuth::Web::Provider->new( provider => $provider )->to_app;
        mount '/-/'     => sub {
            my $r = Plack::Request->new( shift );
            return [
                200, [], [
                    'METHOD: ' . $r->method . ';' .
                    'PATH: ' . $r->path
                ]
            ];
        };
    };

    my $client = SAuth::Web::Consumer::Client->new(
        provider_uri => 'psgi-local://test_app/sauth/',
        service_uri  => 'psgi-local://test_app/-/',
        consumer     => SAuth::Consumer->new( key => $key ),
        plack_client => Plack::Client->new(
            'psgi-local' => {
                apps => {
                    test_app => $app
                }
            }
        )
    );

    ok(!$client->consumer->access_grant, '... no access grant yet');
    ok(!$client->nonce, '... we dont have a nonce');
    ok(!$client->is_ready, '... we are not ready');

    is(exception {
        $client->request_access(
            access_for     => [qw[ read ]],
            token_lifespan => (20 * 60 * 60)
        );
    }, undef, '... access request sent successfully');

    is(exception {
        $client->aquire_nonce;
    }, undef, '... nonce aquired successfully');

    isa_ok($client->consumer->access_grant, 'SAuth::Core::AccessGrant');
    ok($client->nonce, '... we have a nonce');
    ok($client->is_ready, '... we are ready now');

    my $res = $client->call_service( GET "/foo" );
    is($res->code, 500, '... got the right status');
    like($res->body->[0], qr/500 Internal Server Error No Authentication\-Info header found/, '... got the expected content');
}

{
    my $app = builder {
        mount '/sauth/' => SAuth::Web::Provider->new( provider => $provider )->to_app;
        mount '/-/'     => sub {
            my $r = Plack::Request->new( shift );
            return [ 401, [ 'WWW-Authenticate' => 'SAuth realm="foo";nonce="bar"'], [] ];
        };
    };

    my $client = SAuth::Web::Consumer::Client->new(
        provider_uri => 'psgi-local://test_app/sauth/',
        service_uri  => 'psgi-local://test_app/-/',
        consumer     => SAuth::Consumer->new( key => $key ),
        plack_client => Plack::Client->new(
            'psgi-local' => {
                apps => {
                    test_app => $app
                }
            }
        )
    );

    ok(!$client->consumer->access_grant, '... no access grant yet');
    ok(!$client->nonce, '... we dont have a nonce');
    ok(!$client->is_ready, '... we are not ready');

    is(exception {
        $client->request_access(
            access_for     => [qw[ read ]],
            token_lifespan => (20 * 60 * 60)
        );
        $client->aquire_nonce;
    }, undef, '... acces_request and nonce aquired successfully');

    isa_ok($client->consumer->access_grant, 'SAuth::Core::AccessGrant');
    ok($client->nonce, '... we have a nonce');
    ok($client->is_ready, '... we are ready now');

    my $res = $client->call_service( GET "/foo" );
    is($res->code, 401, '... got the right status');
    like($res->body->[0], qr/401 Unauthorized/, '... got the expected content');
}

{
    my $app = builder {
        mount '/sauth/' => SAuth::Web::Provider->new( provider => $provider )->to_app;
        mount '/-/'     => SAuth::Web::Provider::AuthMiddleware->new(
            provider => $provider,
            realm    => 'protected-service',
            app      => sub {
                my $r = Plack::Request->new( shift );
                return [
                    200, [], [
                        'METHOD: ' . $r->method . ';' .
                        'PATH: ' . $r->path
                    ]
                ];
            }
        );
    };

    my $client = SAuth::Web::Consumer::Client->new(
        provider_uri => 'psgi-local://test_app/sauth/',
        service_uri  => 'psgi-local://test_app/-/',
        consumer     => SAuth::Consumer->new( key => $key ),
        plack_client => Plack::Client->new(
            'psgi-local' => {
                apps => {
                    test_app => $app
                }
            }
        )
    );

    ok(!$client->consumer->access_grant, '... no access grant yet');
    ok(!$client->nonce, '... we dont have a nonce');
    ok(!$client->is_ready, '... we are not ready');

    like(exception {
        $client->call_service( GET "/foo" );
    }, qr/Cannot make a service call until client is ready/, '... cannot call service if client is not ready');
}

done_testing;




