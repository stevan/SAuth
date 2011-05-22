package SAuth::Web::Provider::AuthMiddleware;
use Moose;
use MooseX::StrictConstructor;
use MooseX::NonMoose;

use SAuth::Util;
use SAuth::Provider;

use Try::Tiny;
use HTTP::Throwable::Factory qw[ http_exception ];

extends 'Plack::Middleware';

has 'app' => ( is => 'ro' ); # to make MX::StrictConstructor happy

has 'provider' => (
    is       => 'ro',
    isa      => 'SAuth::Provider',
    required => 1
);

has 'realm' => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

sub call {
    my ($self, $env) = @_;

    my $challange = $self->extract_challange_from_env( $env );

    return $self->unauthorized unless $challange;

    my ($next_nonce, $error);
    try {
        $next_nonce = $self->provider->authenticate( %$challange );
    } catch {
        $error = $_;
    };

    if ($error) {

        if (blessed $error) {
            # NOTE:
            # We need to deal with these possible errors
            # - SAuth::Core::Error::AccessGrantNotFound
            # - SAuth::Core::Error::InvalidAccessGrant
            # - SAuth::Core::Error::KeyNotFound
            # - SAuth::Core::Error::InvalidKey
            # - SAuth::Core::Error::HMACVerificationFail
            # All of which represent some kind of auth
            # failure, so we just return unauthorized
            # - SL
            return $self->unauthorized( $error->message );
        }
        else {
            return http_exception(
                'InternalServerError' => {
                    message          => $error,
                    show_stack_trace => 0
                }
            )->as_psgi;
        }
    }
    else {

        my $access_grant = $self->provider->get_access_grant_for_token( $challange->{'token'} );

        $env->{'sauth.capabilities'} = [ @{ $access_grant->access_to } ];

        my $res = $self->app->($env);
        push @{ $res->[1] } => (
            'Authentication-Info' => 'nextnonce="' . encode_base64( $next_nonce ) . '"'
        );
        return $res;
    }

}

sub unauthorized {
    my $self = shift;
    return http_exception(
        'Unauthorized' => {
            www_authenticate =>
                'SAuth realm="' . $self->realm
                  . '",nonce="' . encode_base64( $self->provider->generate_nonce ) . '"',
            # provide an optional message
            (scalar @_ ? (message => shift) : ())
        }
    )->as_psgi;
}

# utils ...

sub extract_challange_from_env {
    my ($self, $env) = @_;

    my $auth = $env->{'HTTP_AUTHORIZATION'};

    return unless $auth;

    my ($header) = ($auth =~ /^SAuth (.*)$/);
    return unless $header;

    my $extracted = $self->parse_challenge_from_header( $header );
    my ($token, $hmac) = split /:/, $extracted->{'response'};

    return +{
        nonce => $extracted->{'nonce'},
        token => $token,
        hmac  => $hmac
    };
}


# NOTE:
# These were stolen pretty much verbatim
# from Plack::Middleware::Digest, except
# that I do the base64 decode on the values
# - SL
sub parse_challenge_from_header {
    my ( $self, $header ) = @_;
    my $auth;
    while ( $header =~ /(\w+)\=("[^\"]+"|[^,]+)/g ) {
        $auth->{ $1 } = decode_base64( dequote( $2 ) );
    }
    return $auth;
}

sub dequote {
    my $s = shift;
    $s =~ s/^"(.*)"$/$1/;
    $s =~ s/\\(.)/$1/g;
    $s;
}


__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Web::Provider::AuthMiddleware;

=head1 DESCRIPTION

