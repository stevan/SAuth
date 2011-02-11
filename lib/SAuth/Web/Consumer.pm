package SAuth::Web::Consumer;
use Moose;
use MooseX::StrictConstructor;
use MooseX::NonMoose;

use SAuth::Web::Consumer::Client;

extends 'Plack::Component';

has 'client' => (
    is       => 'ro',
    isa      => 'SAuth::Web::Consumer::Client',
    required => 1,
);

sub prepare_app {
    my $self = shift;
    confess "The consumer client is not ready"
        unless $self->client->is_ready;
}

sub to_app {
    my $self = shift;
    $self->prepare_app;
    return sub {
        my $env = shift;
        $self->client->send_service_call(
            Plack::Request->new(
                $env
            )
        )->finalize;
    };
}


__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Web::Consumer;

=head1 DESCRIPTION

