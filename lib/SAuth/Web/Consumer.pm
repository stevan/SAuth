package SAuth::Web::Consumer;
use Moose;
use MooseX::StrictConstructor;
use MooseX::NonMoose;

use SAuth::Util;
use SAuth::Web::Consumer::Client;

extends 'Plack::Component';

has 'client' => (
    is       => 'ro',
    isa      => 'SAuth::Web::Consumer::Client',
    required => 1,
);

has 'automate_access' => ( is => 'ro', isa => 'Bool', default => 0 );
has 'token_lifespan'  => ( is => 'ro', isa => 'Int' );
has 'access_for'      => ( is => 'ro', isa => 'ArrayRef[Str]' );

sub BUILD {
    my $self = shift;
    ($self->token_lifespan && $self->access_for)
        || SAuth::Core::Error->throw("You must specify a token_lifespan and access_for in order for the automate access")
            if $self->automate_access;
}

sub check_client_status {
    my $self = shift;
    unless ( $self->client->is_ready ) {

        SAuth::Core::Error->throw("Consumer client is not ready")
            unless $self->automate_access;

        my $status = $self->client->check_status;

        ($status->{key})
            || SAuth::Core::Error::InvalidKey->throw("Consumer client key is not valid");

        unless ( $status->{access_grant} ) {
            if ( $self->client->consumer->has_access_grant ) {
                $self->client->request_refresh(
                    token_lifespan => $self->token_lifespan
                );
            }
            else {
                $self->client->request_access(
                    access_for     => $self->access_for,
                    token_lifespan => $self->token_lifespan
                );
            }
        }

        unless ( $status->{nonce} ) {
            $self->client->aquire_nonce;
        }
    }
}

sub prepare_app { (shift)->check_client_status }

sub call {
    my $self = shift;
    my $r    = Plack::Request->new( shift );
    $self->check_client_status;
    $self->client->call_service( $r )->finalize;
}


__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Web::Consumer;

=head1 DESCRIPTION

