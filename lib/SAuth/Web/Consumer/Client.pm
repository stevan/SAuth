package SAuth::Web::Consumer::Client;
use Moose;
use MooseX::StrictConstructor;
use MooseX::Params::Validate;

use SAuth::Util;
use SAuth::Consumer;

use Try::Tiny;
use Devel::PartialDump    qw[ dump ];

use Plack::Client;
use HTTP::Request;
use HTTP::Request::Common qw[ GET POST ];

use HTTP::Throwable::Factory qw[ http_exception ];

has 'plack_client' => (
    is       => 'ro',
    isa      => 'Plack::Client',
    required => 1,
);

has 'consumer' => (
    is       => 'ro',
    isa      => 'SAuth::Consumer',
    required => 1,
);

has 'nonce' => (
    is      => 'ro',
    isa     => 'Str',
    writer  => '_set_nonce',
    clearer => '_clear_nonce'
);

has [ 'provider_uri', 'service_uri' ] => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

sub request_access {
    my ($self, $token_lifespan, $access_for) = validated_list(\@_,
        token_lifespan => { isa => 'Int' },
        access_for     => { isa => 'ArrayRef[Str]' },
    );
    $self->_process_access_operation(
        "/request_access" => $self->consumer->create_access_request(
            token_lifespan => $token_lifespan,
            access_for     => $access_for
        )
    );
}

sub refresh_access {
    my ($self, $token_lifespan) = validated_list(\@_,
        token_lifespan => { isa => 'Int' },
    );
    $self->_process_access_operation(
        "/refresh_access" => $self->consumer->create_refresh_request(
            token_lifespan => $token_lifespan
        )
    );
}

sub _process_access_operation {
    my ($self, $uri, $request) = @_;

    # NOTE:
    # We might want to put the same
    # 502 prevention code here, but
    # these don't seem to be a problem
    # for me right now, so I am going
    # to punt on this.
    # - SL

    my $res = $self->plack_client->request(
        POST(
            $self->_construct_uri( $self->provider_uri, $uri ),
            [
                uid       => $self->consumer->key->uid,
                hmac      => $request->hmac,
                timestamp => $request->timestamp,
                body      => $request->body->to_json
            ]
        )
    );

    SAuth::Core::Error->throw("Access Request failed : " . dump($res))
        if $res->status != 200;

    $self->consumer->process_access_grant( @{ $res->body } );
}

sub aquire_nonce {
    my $self = shift;

    my $res = $self->plack_client->request(
        POST( $self->_construct_uri( $self->provider_uri, "/generate_nonce" ) )
    );

    SAuth::Core::Error->throw("Nonce fetch failed : "  . dump($res))
        if $res->status != 200;

    $self->_set_nonce( $res->body->[0] );
}

sub is_ready {
    my $self = shift;
    $self->nonce
        &&
    $self->consumer->has_valid_access_grant
        &&
    $self->consumer->has_valid_key
        ? 1 : 0
}

sub check_status {
    my $self = shift;
    return +{
        nonce        => $self->nonce ? 1 : 0,
        access_grant => $self->consumer->has_valid_access_grant,
        key          => $self->consumer->has_valid_key
    }
}

sub call_service {
    my ($self, $req) = @_;

    ($self->is_ready)
        || confess "Cannot make a service call until client is ready";

    if ( $req->isa('HTTP::Request') ) {
        $req->uri( $self->_construct_uri( $self->service_uri, $req->uri->path_query ) );
    }
    elsif ( $req->isa('Plack::Request') ) {
        my $headers = $req->headers;
        # NOTE:
        # We need to remove this because
        # it will be the host for this
        # side and req_to_psgi will use
        # the value of this to set the
        # uri's host-port and then things
        # will just not work right.
        # I suspect too that we might want
        # to not send on most of the other
        # headers as well, but we can punt
        # on that for now.
        # - SL
        $headers->remove_header('Host');

        my $base_uri = $req->base;
        my $uri      = $req->uri;
        $uri =~ s/^$base_uri//;

        $req = HTTP::Request->new(
            $req->method,
            $self->_construct_uri( $self->service_uri, $uri ),
            $headers,
            $req->content
        );
    }

    $req->header('Authorization' => $self->_generate_auth_header);

    my $max_retries = 10;
    my $num_retries = 0;
    my $res;
    do {
        # NOTE:
        # This is just plain stupid, but it
        # seems that AnyEvent::HTTP (which is
        # used by Plack::App::Proxy, which is
        # used by the Plack::Client HTTP backend)
        # just likes to get "stuck" every once
        # in a while, however it seems that if
        # you just ignore it and try again it
        # seems to just work. The real solution
        # here actually is to write a different
        # HTTP backend for Plack::Client that
        # is less flakey.
        # - SL
        warn ".............. Retrying after a 502\n" if $res;
        $res = $self->plack_client->request( $req );
        $num_retries++;
    } while $res->code == 502 && $num_retries < $max_retries;

    my $auth_info_header = $res->header('Authentication-Info');

    unless ( $auth_info_header ) {

        my $error;
        if ( $res->code == 401 ) {

            # TODO:
            # Ponder if I should try an extract a nonce
            # from the WWW-Authenticate header, I am not
            # sure it would be the right thing to do, or
            # that it would matter, unless I were to put
            # an experiation value on the nonce
            # - SL

            $error = http_exception(
                'Unauthorized' => {
                    # NOTE:
                    # wrap the header call in a try block
                    # just to be sure, this call croaks if
                    # there is no headers.
                    # - SL
                    www_authenticate => try { $res->header( 'WWW-Authenticate' ) }
                }
            )->as_psgi;
        }
        else {
            $error = http_exception(
                'InternalServerError' => {
                    message => "No Authentication-Info header found for response "  . dump( $res->finalize )
                }
            )->as_psgi;
        }

        # NOTE:
        # I think perhaps I might want to clear
        # the nonce value here, but I am not 100%
        # sure if it makes sense or not.
        # - SL

        return Plack::Response->new( @$error );
    }

    my ($nonce) = ($auth_info_header =~ /^nextnonce=\"([a-zA-Z0-9-_]+)\"/);

    $self->_set_nonce( $nonce );

    return $res;
}

# ...

sub _construct_uri {
    my ($self, $base, $uri) = @_;
    if ( $base =~ /\/$/ && $uri =~ /^\// ) {
        $uri =~ s/^\///;
    }
    return $base . $uri;
}

sub _generate_auth_header {
    my $self     = shift;
    my $response = join ':' => (
        $self->consumer->access_grant->token,
        $self->consumer->generate_token_hmac( $self->nonce )
    );
    'SAuth response="' . encode_base64( $response ) . '",nonce="' . encode_base64( $self->nonce ) . '"';
}


__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Web::Consumer;

=head1 DESCRIPTION

