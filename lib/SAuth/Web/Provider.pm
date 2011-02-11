package SAuth::Web::Provider;
use Moose;
use MooseX::StrictConstructor;

use SAuth::Util;

use Try::Tiny;
use Path::Router;
use Plack::Request;
use HTTP::Throwable::InternalServerError;
use HTTP::Throwable::MethodNotAllowed;

extends 'Plack::App::Path::Router::PSGI';

has 'provider' => (
    is       => 'ro',
    isa      => 'SAuth::Provider',
    required => 1,
);

has '+router' => ( builder => 'build_router' );

sub build_router {
    my $self   = shift;
    my $router = Path::Router->new;

    $router->add_route(
        '/request_access',
        target => sub {
            return $self->process_request(
                'process_access_request' => Plack::Request->new( shift )
            );
        }
    );

    $router->add_route(
        '/refresh_access',
        target => sub {
            return $self->process_request(
                'process_access_refresh' => Plack::Request->new( shift )
            );
        }
    );

    $router->add_route(
        '/generate_nonce',
        target => sub {
            my $nonce = encode_base64( $self->provider->generate_nonce );
            return [
                200,
                [ 'Content-Type'   => 'text/plain',
                  'Content-Length' => length $nonce ],
                [ $nonce ]
            ];
        }
    );

    $router;
}

sub process_request {
    my ($self, $provider_method, $r) = @_;

    return HTTP::Throwable::MethodNotAllowed->new(
        allow   => [ 'POST' ],
        message => 'Only POST is supported'
    )->as_psgi
        if $r->method ne 'POST';

    # TODO:
    # Support sending as JSON, as well as
    # application/x-www-form-urlencoded,
    # either way should be fine.
    # - SL

    my ($access_grant, $error);
    try {
        $access_grant = $self->provider->$provider_method(
            uid       => $r->param('uid'),
            hmac      => $r->param('hmac'),
            timestamp => int($r->param('timestamp')),
            body      => $r->param('body')
        );
    } catch {
        $error = $_;
    };

    if ($error) {
        return HTTP::Throwable::InternalServerError->new(
            message          => $error,
            show_stack_trace => 0
        )->as_psgi;
    }
    else {
        my $json = $access_grant->to_json;
        return [
            200,
            [ 'Content-Type'   => 'application/json',
              'Content-Length' => length $json ],
            [ $json ]
        ];
    }
}



__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Web::Provider;

=head1 DESCRIPTION

