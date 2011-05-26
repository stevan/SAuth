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
use HTTP::Request::Common qw[ GET PUT POST DELETE ];

BEGIN {
    use_ok('SAuth::Provider');
    use_ok('SAuth::Provider::KeyStore::SQLite');
    use_ok('SAuth::Provider::TokenStore::SQLite');
    use_ok('SAuth::Consumer');

    use_ok('SAuth::Web::Provider');
    use_ok('SAuth::Web::Provider::AuthMiddleware::FromQueryString');
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

my $consumer = SAuth::Consumer->new( key => $key );

my $access_request = $consumer->create_access_request(
    access_for     => [qw[ read ]],
    token_lifespan => (20 * 60 * 60)
);

my $app = builder {
    mount '/sauth/' => SAuth::Web::Provider->new( provider => $provider )->to_app;
    mount '/-/' => SAuth::Web::Provider::AuthMiddleware::FromQueryString->new(
        provider => $provider,
        realm    => 'protected-service',
        app      => sub {
            my $env = shift;
            return [ 200, [], [ join ", " => @{ $env->{'sauth.capabilities'} } ]];
        }
    );
};

test_psgi(
    app    => $app,
    client => sub {
        my $cb = shift;

        my ($access_grant, $nonce);
        {
            my $req = POST(
                "http://localhost/sauth/request_access",
                [
                    uid       => 'http://www.example.org',
                    hmac      => $access_request->hmac,
                    timestamp => $access_request->timestamp,
                    body      => $access_request->body->to_json
                ]
            );
            my $res = $cb->($req);
            is($res->code, 200, '... got the right status for request_access');

            $access_grant = SAuth::Core::AccessGrant->from_json( $res->content );
            isa_ok($access_grant, 'SAuth::Core::AccessGrant');

            isa_ok($access_grant->timeout, 'DateTime');
            ok($access_grant->can_refresh, '... we are allowed to refresh this token');
            is_deeply($access_grant->access_to, [qw[ read ]], '... got the right access');
            like($access_grant->token, qr/^[A-Z0-9-]+$/, '... got the token');
        }

        $consumer->process_access_grant( $access_grant->to_json );

        {
            my $req = GET( "http://localhost/sauth/generate_nonce" );
            my $res = $cb->($req);
            is($res->code, 200, '... got the right status for generating a nonce');
            $nonce = SAuth::Util::decode_base64( $res->content );
            like(SAuth::Util::encode_base64($nonce), qr/^[a-zA-Z0-9-_]+$/, '... got the nonce');
        }

        {
            my $req = GET(
                "http://localhost/-/?" .
                    'sauth_token=' . SAuth::Util::encode_base64( $consumer->access_grant->token ) . '&' .
                    'sauth_hmac='  . SAuth::Util::encode_base64( $consumer->generate_token_hmac( $nonce ) ) . '&' .
                    'sauth_nonce=' . SAuth::Util::encode_base64( $nonce ) . '&' .
                    'sauth_redirect_to=/some/endpoint'
            );

            my $res = $cb->($req);
            is($res->code, 302, '... got the right status for calling wrapped service w querystring');
            my $location_header = $res->header('Location');
            like($location_header, qr/^\/some\/endpoint\?/, '... got the right location');
            like($location_header, qr/sauth_nextnonce\=/, '... got the next-nonce in the query string');
            like($location_header, qr/sauth_response\=read/, '... got the response in the query string');
        }


    }
);

done_testing;




