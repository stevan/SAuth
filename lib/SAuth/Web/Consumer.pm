package SAuth::Web::Consumer;
use Moose;

use SAuth::Util;
use Plack::Client;
use HTTP::Request::Common qw[ GET POST ];

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
    is     => 'ro',
    writer => '_set_nonce',
    isa    => 'Str'
);

has [ 'provider_url', 'service_url' ] => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

sub send_access_request {
    my $self = shift;

    my $access_request = $self->consumer->create_access_request( @_ );

    my $res = $self->plack_client->request(
        POST(
            ($self->provider_url . "/request_access"),
            [
                uid       => $self->consumer->key->uid,
                hmac      => $access_request->hmac,
                timestamp => $access_request->timestamp,
                body      => $access_request->body->to_json
            ]
        )
    );

    confess "Access Request failed : " . $res->content
        if $res->status != 200;

    $self->consumer->process_access_grant( @{ $res->body } );

    $self->_get_nonce;
}

sub _get_nonce {
    my $self = shift;

    my $res = $self->plack_client->request(
        GET( $self->provider_url . "/generate_nonce" )
    );

    confess "Access Request failed : "  . $res->content
        if $res->status != 200;

    $self->_set_nonce( $res->body->[0] );
}

sub send_service_call {
    my ($self, $req) = @_;

    $req->uri( $self->service_url . $req->uri );
    $req->header( 'Authorization' => $self->_generate_auth_header );

    my $res = $self->plack_client->request( $req );

    confess "Service Call failed : "  . $res->content
        if $res->status == 500;

    my $auth_info_header = $res->header('Authentication-Info');
    my ($nonce) = ($auth_info_header =~ /^nextnonce=\"([a-zA-Z0-9-_]+)\"/);

    $self->_set_nonce( $nonce );

    return $res;
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

