package SAuth::Util;

use strict;
use warnings;

use SAuth::Core::Error;
use SAuth::Core::Error::InvalidKey;
use SAuth::Core::Error::HMACVerificationFail;

use Digest       ();
use JSON::XS     ();
use MIME::Base64 ();

use Digest::HMAC;
use Digest::SHA1;

use Data::UUID;
use Crypt::Random::Source qw[ get_strong ];

use DateTime;
use DateTime::Format::RFC3339;

use Sub::Exporter;

my @exports = qw/
    digest
    hmac_digest

    encode_json
    decode_json

    format_datetime
    parse_datetime

    mint_timestamp

    generate_uuid
    generate_random_data

    encode_base64
    decode_base64
/;

Sub::Exporter::setup_exporter({
    exports => \@exports,
    groups  => { default => \@exports }
});

my $JSON = JSON::XS->new->canonical(1);

sub encode_json { $JSON->encode( shift ) }
sub decode_json { $JSON->decode( shift ) }

sub format_datetime { DateTime::Format::RFC3339->format_datetime( shift ) }
sub parse_datetime  { DateTime::Format::RFC3339->parse_datetime( shift )  }

sub mint_timestamp { DateTime->now->epoch }

sub digest      { Digest->new("SHA-256")->add( @_ )->hexdigest }
sub hmac_digest {
    my ($self, $key, $timestamp, $data) = @_;
    my $d = Digest::HMAC->new( $key, "Digest::SHA1" );
    $d->add( $timestamp );
    $d->add( ' ' );
    $d->add( $data );
    $d->hexdigest;
}

sub generate_uuid { Data::UUID->new->create_str }

sub generate_random_data { get_strong( shift || 16 ) }

sub encode_base64 { MIME::Base64::encode_base64url( shift ) }
sub decode_base64 { MIME::Base64::decode_base64url( shift ) }

1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Util;

=head1 DESCRIPTION

