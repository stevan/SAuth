package SAuth::Web::Provider::AuthMiddleware::FromQueryString;
use Moose;
use MooseX::StrictConstructor;

use SAuth::Util;

use Try::Tiny;
use Plack::Request;
use HTTP::Throwable::Factory qw[ http_exception ];

extends 'SAuth::Web::Provider::AuthMiddleware';

sub extract_challange_from_env {
    my $self = shift;
    my $r    = Plack::Request->new( shift );

    my $token = $r->param('sauth_token');
    my $hmac  = $r->param('sauth_hmac');
    my $nonce = $r->param('sauth_nonce');

    return unless $token && $hmac && $nonce;

    return +{
        nonce => decode_base64( $nonce ),
        token => decode_base64( $token ),
        hmac  => decode_base64( $hmac ),
    };
}

sub call_app {
    my $self        = shift;
    my $r           = Plack::Request->new( shift );
    my $next_nonce  = shift;
    my $redirect_to = $r->param('sauth_redirect_to');

    # TODO:
    # Add some serious error handling
    # - check for no sauth_redirect_to
    # - check for exceptions from the app
    # - handle packaging that all up for
    #   sending int he redirect below
    # - check for different kinds of plack bodies
    # - check for non 200 responses
    # ... etc

    my $result = $self->app->( $r->env );

    my $response = $r->new_response( 302 );
    $response->header(
        'Location' =>  $redirect_to
                    . '?sauth_nextnonce=' . encode_base64( $next_nonce )
                    . '&sauth_response=' . (join "" => @{ $result->[2] })
    );
    $response->finalize;
}


__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Web::Provider::AuthMiddleware::FromQueryString;

=head1 DESCRIPTION

