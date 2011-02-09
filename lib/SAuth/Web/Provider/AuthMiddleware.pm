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
            return HTTP::Throwable::InternalServerError->new(
                message          => $error,
                show_stack_trace => 0
            )->as_psgi;
        }
        else {
            my $info = 'nextnonce=' . SAuth::Util::encode_base64( $next_nonce );
            $info .= ';nexttimeout=' . $new_timeout
                if $new_timeout;

            my $res = $self->app->($env);
            push @{ $res->[1] } => ( 'Authentication-Info' => $info );
            return $res;
        }

    }

    return $self->unauthorized;
}

sub unauthorized {
    return HTTP::Throwable::Unauthorized->new(
        www_authenticate => 'SAuth "restricted area"'
    )->as_psgi;
}


__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Web::Provider::AuthMiddleware;

=head1 DESCRIPTION

