package SAuth;
use Moose;

use SAuth::Util; # loads most of the Error stuff too

# load the core stuff
use SAuth::Core::Key;
use SAuth::Core::AccessGrant;
use SAuth::Core::AccessRefresh;
use SAuth::Core::AccessRequest;

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A simple, OAuth style, auth framework

=head1 SYNOPSIS

=head1 DESCRIPTION

