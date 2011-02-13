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

use HTTP::Throwable::InternalServerError;
use HTTP::Throwable::Unauthorized;

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

    my $access_request = $self->consumer->create_access_request(
        token_lifespan => $token_lifespan,
        access_for     => $access_for
    );

    my $res = $self->plack_client->request(
        POST(
            $self->_construct_uri( $self->provider_uri, "/request_access" ),
            [
                uid       => $self->consumer->key->uid,
                hmac      => $access_request->hmac,
                timestamp => $access_request->timestamp,
                body      => $access_request->body->to_json
            ]
        )
    );

    SAuth::Core::Error->throw("Access Request failed : " . dump($res))
        if $res->status != 200;

    $self->consumer->process_access_grant( @{ $res->body } );
}

sub refresh_access {
    my ($self, $token_lifespan) = validated_list(\@_,
        token_lifespan => { isa => 'Int' },
    );

    my $refresh_request = $self->consumer->create_refresh_request(
        token_lifespan => $token_lifespan
    );

    my $res = $self->plack_client->request(
        POST(
            $self->_construct_uri( $self->provider_uri, "/refresh_access" ),
            [
                uid       => $self->consumer->key->uid,
                hmac      => $refresh_request->hmac,
                timestamp => $refresh_request->timestamp,
                body      => $refresh_request->body->to_json
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
        $req->uri( $self->_construct_uri( $self->service_uri, $req->uri ) );
    }
    elsif ( $req->isa('Plack::Request') ) {
        $req = HTTP::Request->new(
            $req->method,
            $self->_construct_uri( $self->service_uri, $req->path ),
            $req->headers,
            $req->content
        );
    }

    $req->header('Authorization' => $self->_generate_auth_header);

    my $res = $self->plack_client->request( $req );

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

            $error = HTTP::Throwable::Unauthorized->new(
                # NOTE:
                # wrap the header call in a try block
                # just to be sure, this call croaks if
                # there is no headers.
                # - SL
                www_authenticate => try { $res->header( 'WWW-Authenticate' ) }
            )->as_psgi;
        }
        else {
            $error = HTTP::Throwable::InternalServerError->new(
                message => "No Authentication-Info header found for response "  . dump( $res->finalize )
            )->as_psgi;
        }

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

