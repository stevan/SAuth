package SAuth::Web::Provider;
use Moose;

use Try::Tiny;
use Path::Router;
use Plack::Request;

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
            my $r = Plack::Request->new( shift );

            my ($access_grant, $error);
            try {
                $access_grant = $self->provider->process_access_request(
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
    );

    $router;
}


__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Web::Provider;

=head1 DESCRIPTION

