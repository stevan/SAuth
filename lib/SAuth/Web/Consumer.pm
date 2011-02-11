package SAuth::Web::Consumer;
use Moose;
use MooseX::NonMoose;

use Try::Tiny;
use Plack::App::URLMap;
use SAuth::Web::Consumer::Client;

extends 'Plack::Component';

has 'client' => (
    is       => 'ro',
    isa      => 'SAuth::Web::Consumer::Client',
    required => 1,
);

has 'service_uri' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1
);

has '_app' => ( is => 'rw' );

sub prepare_app {
    my $self = shift;

    confess "You must first acquire an access token before intiailizing this application"
        unless $self->client->is_ready;

    my $url_map = Plack::App::URLMap->new;
    $url_map->map(
        $self->service_uri => sub {
            my $env = shift;
            $self->client->send_service_call(
                Plack::Request->new(
                    $env
                )
            )->finalize;
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

