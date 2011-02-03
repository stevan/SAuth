package SAuth::Util;

use strict;
use warnings;

use Digest   ();
use JSON::XS ();

use DateTime;
use DateTime::Duration;
use DateTime::Format::RFC3339;

use Sub::Exporter;

my @exports = qw/
    digest

    encode_json
    decode_json

    format_datetime
    parse_datetime
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

sub digest { Digest->new("SHA-256")->add( @_ )->hexdigest }

1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Util;

=head1 DESCRIPTION

