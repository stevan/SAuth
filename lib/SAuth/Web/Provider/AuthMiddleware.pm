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

sub call {
    my ($self, $env) = @_;

    my $auth = $env->{HTTP_AUTHORIZATION};

    return $self->unauthorized unless $auth;

    if ($auth =~ /^SAuth (.*)$/) {
        my($token, $hmac) = split /:/, (decode_base64($1) || ":");

        my ($next_nonce, $new_timeout, $error);
        try {
            ($next_nonce, $new_timeout) = $self->provider->authenticate(
                token => $token,
                hmac  => $hmac
            );
        } catch {
            $error = $_;
        };

        if ($error) {
            return [
                500,
                [ 'Content-Type'   => 'text/plain',
                  'Content-Length' => length $error ],
                [ $error ]
            ];
        }
        else {
            my $info = 'nextnonce=' . $next_nonce;
            $info .= ';nexttimeout=' . $new_timeout
                if $new_timeout;

            my $res = $self->app->($env);
            push @{ $res->[2] } => ( 'Authentication-Info' => $info );
            return $res;
        }

    }

    return $self->unauthorized;
}

sub unauthorized {
    my $self = shift;
    my $body = shift || 'Authorization required';
    return [
        401,
        [ 'Content-Type'     => 'text/plain',
          'Content-Length'   => length $body,
          'WWW-Authenticate' => 'SAuth "restricted area"' ],
        [ $body ],
    ];
}


__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Web::Provider::AuthMiddleware;

=head1 DESCRIPTION

