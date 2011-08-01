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
    use_ok('SAuth::Web::Provider::AuthMiddleware');
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
    mount '/-/' => SAuth::Web::Provider::AuthMiddleware->new(
        provider => $provider,
        realm    => 'protected-service',
        app      => sub {
            return [ 200, [], ["HORRAY!"]];
        }
    );
};

test_psgi(
    app    => $app,
    client => sub {
        my $cb = shift;

        {
            my $req = POST(
                "http://localhost/sauth/request_access",
                [
                    uid       => 'http://www.example.com',
                    hmac      => $access_request->hmac,
                    timestamp => $access_request->timestamp,
                    body      => $access_request->body->to_json
                ]
            );
            my $res = $cb->($req);
            is($res->code, 500, '... got the right status for request_access');
        }

        {
            my $req = POST(
                "http://localhost/sauth/request_access",
                [
                    uid       => 'http://www.example.org',
                    hmac      => $access_request->hmac . "foo",
                    timestamp => $access_request->timestamp,
                    body      => $access_request->body->to_json
                ]
            );
            my $res = $cb->($req);
            is($res->code, 500, '... got the right status for request_access');
        }

        {
            my $req = GET(
                "http://localhost/sauth/request_access?" .
                    "uid=http://www.example.com;" .
                    "hmac=" . $access_request->hmac . ";" .
                    "timestamp=" . $access_request->timestamp . ";" .
                    "body=" . $access_request->body->to_json . ";"
            );
            my $res = $cb->($req);
            is($res->code, 405, '... got the right status for request_access');
            is($res->header('Allow'), "POST", '... got the right allow header');
        }

        # now let them pass, and check authenticate ...

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
        }

        $consumer->process_access_grant( $access_grant->to_json );

        {
            my $req = GET( "http://localhost/sauth/generate_nonce" );
            my $res = $cb->($req);
            is($res->code, 200, '... got the right status for generating a nonce');
            $nonce = SAuth::Util::decode_base64( $res->content );
        }

        # auth errors ...


        {
            # do not pass the auth info
            my $req = GET( "http://localhost/-/" );
            my $res = $cb->($req);
            is($res->code, 401, '... got the right status for calling wrapped service without auth header');
            my $www_auth_header = $res->header('WWW-Authenticate');
            like($www_auth_header, qr/^SAuth realm\=\"protected-service\",nonce\=\"[a-zA-Z0-9-_]+\"$/, '... got the right nonce in the header');
        }

        {
            # mess up the response
            my $req = GET(
                "http://localhost/-/" => (
                    'Authorization' => 'SAuth ' .
                    'response="' . SAuth::Util::encode_base64(
                        'foo' . (join ':' => $consumer->access_grant->token, $consumer->generate_token_hmac( $nonce ))
                    ) . '",nonce="' . SAuth::Util::encode_base64( $nonce ) . '"'
                )
            );
            my $res = $cb->($req);
            is($res->code, 401, '... got the right status for calling wrapped service with bad response');
            my $www_auth_header = $res->header('WWW-Authenticate');
            like($www_auth_header, qr/^SAuth realm\=\"protected-service\",nonce\=\"[a-zA-Z0-9-_]+\"$/, '... got the right nonce in the header');
            like($res->content, qr/There is no access grant for token \(.*\)/, '... got the right content');
        }

        {
            # mess up the nonce
            my $req = GET(
                "http://localhost/-/" => (
                    'Authorization' => 'SAuth ' .
                    'response="' . SAuth::Util::encode_base64(
                        join ':' => $consumer->access_grant->token, $consumer->generate_token_hmac( $nonce )
                    ) . '",nonce="foo' . SAuth::Util::encode_base64( $nonce ) . '"'
                )
            );
            my $res = $cb->($req);
            is($res->code, 401, '... got the right status for calling wrapped service with bad nonce');
            my $www_auth_header = $res->header('WWW-Authenticate');
            like($www_auth_header, qr/^SAuth realm\=\"protected-service\",nonce\=\"[a-zA-Z0-9-_]+\"$/, '... got the right nonce in the header');
            like($res->content, qr/Authentication Fail \- HMAC Verification Fail/, '... got the right content');
        }

    }
);

done_testing;




