package SAuth::Web::Provider::AuthMiddleware;
use Moose;
use MooseX::NonMoose;

use Try::Tiny;
use SAuth::Util;

extends 'Plack::Middleware';

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

    my $auth = $env->{HTTP_AUTHORIZATION};

    return $self->unauthorized unless $auth;

    if ($auth =~ /^SAuth (.*)$/) {
        my $challange = $self->parse_challenge( $1 );

        my($token, $hmac) = split /:/, $challange->{response};

        my ($next_nonce, $error);
        try {
            $next_nonce = $self->provider->authenticate(
                token => $token,
                hmac  => $hmac,
                nonce => $challange->{nonce}
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
            my $res = $self->app->($env);
            push @{ $res->[1] } => (
                'Authentication-Info' => 'nextnonce="' . encode_base64( $next_nonce ) . '"'
            );
            return $res;
        }

    }

    return $self->unauthorized;
}

sub unauthorized {
    my $self = shift;
    return HTTP::Throwable::Unauthorized->new(
        www_authenticate =>
            'SAuth realm="' . $self->realm
              . '",nonce="' . encode_base64( $self->provider->generate_nonce ) . '"'
    )->as_psgi;
}

# utils ...

# NOTE:
# These were stolen pretty much verbatim
# from Plack::Middleware::Digest, except
# that I do the base64 decode on the values
# - SL
sub parse_challenge {
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

