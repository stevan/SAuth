package SAuth::Core::Error::HMACVerificationFail;
use Moose;

extends 'SAuth::Core::Error';

has '+message' => ( default => "HMAC Verification Fail" );

__PACKAGE__->meta->make_immutable( inline_constructor => 0 );

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Core::Error::InvalidKey;

=head1 DESCRIPTION

