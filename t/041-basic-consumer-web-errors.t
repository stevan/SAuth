#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::Fatal;
use Test::Moose;

use FindBin;
use DateTime;
use Path::Class;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common qw[ GET POST DELETE ];

BEGIN {
    use_ok('SAuth::Provider');
    use_ok('SAuth::Provider::KeyStore::SQLite');
    use_ok('SAuth::Provider::TokenStore::SQLite');
    use_ok('SAuth::Consumer');

    use_ok('SAuth::Web::Provider');
    use_ok('SAuth::Web::Provider::AuthMiddleware');
    use_ok('SAuth::Web::Consumer');
    use_ok('SAuth::Web::Consumer::Client');
}

my $DB_FILE = file("$FindBin::Bin/data/db");

unlink $DB_FILE;

## ----------------------------------------------------
## This should have been done once, when the app was
## first registered with the service
## ----------------------------------------------------

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

## ----------------------------------------------------
## This is our actual service wrapper, so this is
## what is being protected
## ----------------------------------------------------

my $provider_app = builder {
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

## ----------------------------------------------------
## Now this is on the app side, we tell the client
## where to find the providers, and initialize a
## consumer object for it;
## ----------------------------------------------------

my $client = SAuth::Web::Consumer::Client->new(
    consumer     => SAuth::Consumer->new( key => $key ),
    provider_uri => 'psgi-local://test_app/sauth/',
    service_uri  => 'psgi-local://test_app/-/',
    plack_client => Plack::Client->new(
        'psgi-local' => {
            apps => {
                test_app => $provider_app
            }
        }
    )
);

## ----------------------------------------------------
## aquire the access token ...
## ----------------------------------------------------

like(exception {
    SAuth::Web::Consumer->new( client => $client, service_uri => '/service' )->to_app
}, qr/You must first acquire an access token before intiailizing this application/,
'... cant start this unless we have an access token');

done_testing;








