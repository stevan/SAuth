package SAuth::Consumer;
use Moose;
use MooseX::Params::Validate;

use SAuth::Util;
use SAuth::Core::Key;
use SAuth::Core::AccessRequest;

use SAuth::Consumer::RequestWrapper;

has 'key' => (
    is       => 'ro',
    isa      => 'SAuth::Core::Key',
    required => 1,
);

has 'token_store' => (
    is       => 'ro',
    does     => 'SAuth::Core::TokenStore',
    required => 1,
    handles  => [qw[
        get_token
        has_token
    ]]
);

sub create_access_request {
    my ($self, $token_lifespan, $access_for) = validated_list(\@_,
        token_lifespan => { isa => 'Int' },
        access_for     => { isa => 'ArrayRef[Str]' },
    );

    SAuth::Consumer::RequestWrapper->new(
        key  => $self->key,
        body => SAuth::Core::AccessRequest->new(
            uid            => $self->key->uid,
            access_for     => $access_for,
            token_lifespan => $token_lifespan
        )
    );
}

sub process_access_grant {
    my ($self, $nonce, $_access_grant) = validated_list(\@_,
        nonce        => { isa => 'Any' },
        access_grant => { isa => 'Str' },
    );

    my $access_grant = SAuth::Core::AccessGrant->from_json( $_access_grant );

}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Consumer;

=head1 DESCRIPTION

