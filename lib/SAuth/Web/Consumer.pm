package SAuth::Web::Consumer;
use Moose;
use MooseX::NonMoose;

use Try::Tiny;
use Plack::App::URLMap;
use SAuth::Web::Consumer::Client;

extends 'Plack::Component';

has 'consumer_client' => (
    is       => 'ro',
    isa      => 'SAuth::Web::Consumer::Client',
    required => 1,
);

has [ 'init_url', 'service_url' ] => (
    is       => 'ro',
    isa      => 'Str',
    required => 1
);

has '_app' => ( is => 'rw' );

sub prepare_app {
    my $self = shift;
    my $url_map = Plack::App::URLMap->new;
    $url_map->map(
        $self->init_url => sub {
            my $r = Plack::Request->new( shift );

            my $error;
            try {
                $self->consumer_client->send_access_request(
                    token_lifespan => $r->param('token_lifespan'),
                    access_for     => [ $r->parameters->get_all('access_for') ]
                );
            } catch {
                $error = $_;
            };

            return HTTP::Throwable::InternalServerError->new(
                show_stack_trace => 0,
                message          => $error
            )->as_psgi
                if $error;

            return [ 200, [], [] ];
        }
    );
    $url_map->map(
        $self->service_url => sub {
            my $r = Plack::Request->new( shift );

            my ($resp, $error);
            try {
                $resp = $self->consumer_client->send_service_call( $r );
            } catch {
                $error = $_;
            };

            return HTTP::Throwable::InternalServerError->new(
                show_stack_trace => 0,
                message          => $error
            )->as_psgi
                if $error;

            return $resp->finalize;
        }
    );

    $self->_app( $url_map );
}

sub to_app {
    my $self = shift;
    $self->prepare_app;
    return $self->_app->to_app;
}


__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Web::Consumer;

=head1 DESCRIPTION

