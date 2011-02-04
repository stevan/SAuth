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
    use_ok('SAuth::Provider::KeyStore::Dir');
    use_ok('SAuth::Provider::TokenStore::Hash');
    use_ok('SAuth::Consumer');

    use_ok('SAuth::Web::Provider');
    use_ok('SAuth::Web::Provider::AuthMiddleware');
}

map { -f $_ && $_ =~ /\.json$/ ? unlink( $_ ) : () } dir("$FindBin::Bin/key-store")->children;

my $provider = SAuth::Provider->new(
    token_store  => SAuth::Provider::TokenStore::Hash->new,
    key_store    => SAuth::Provider::KeyStore::Dir->new( dir => [ $FindBin::Bin, 'key-store' ]),
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
        app      => sub {
            return [ 200, [], ["HORRAY!"]];
        }
    );
};

test_psgi(
    app    => $app,
    client => sub {
        my $cb = shift;

        my $access_grant;
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
            is($res->code, 200, '... got the right status for query-ing open slots');

            $access_grant = SAuth::Core::AccessGrant->from_json( $res->content );
            isa_ok($access_grant, 'SAuth::Core::AccessGrant');

            isa_ok($access_grant->timeout, 'DateTime');
            ok($access_grant->can_refresh, '... we are allowed to refresh this token');
            is_deeply($access_grant->access_to, [qw[ read ]], '... got the right access');
            like($access_grant->token, qr/^[A-Z0-9-]+$/, '... got the token');
            like(SAuth::Util::encode_base64($access_grant->nonce), qr/^[a-zA-Z0-9-]+$/, '... got the nonce');
        }

        $consumer->process_access_grant( $access_grant->to_json );

        {
            my $req = GET(
                "http://localhost/-/" => (
                    'Authorization' => 'SAuth ' . SAuth::Util::encode_base64(
                        join ':' => $consumer->access_grant->token, $consumer->generate_token_hmac
                    )
                )
            );
            my $res = $cb->($req);
            is($res->code, 200, '... got the right status for query-ing open slots');
            is($res->content, 'HORRAY!', '... got the expected content');
        }


    }
);

done_testing;




