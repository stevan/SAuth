package SAuth::Consumer;
use Moose;
use MooseX::StrictConstructor;
use MooseX::Params::Validate;

use SAuth::Util;
use SAuth::Core::Key;
use SAuth::Core::AccessRequest;
use SAuth::Core::AccessRefresh;

use SAuth::Consumer::RequestWrapper;

has 'key' => (
    is       => 'ro',
    isa      => 'SAuth::Core::Key',
    required => 1,
    trigger  => sub {
        ((shift)->has_valid_key)
            || SAuth::Core::Error::InvalidKey->throw;
    }
);

has 'access_grant' => (
    is        => 'rw',
    isa       => 'SAuth::Core::AccessGrant',
    predicate => 'has_access_grant'
);

sub create_access_request {
    my ($self, $token_lifespan, $access_for) = validated_list(\@_,
        token_lifespan => { isa => 'Int' },
        access_for     => { isa => 'ArrayRef[Str]' },
    );

    ($self->has_valid_key)
        || SAuth::Core::Error::InvalidKey->throw;

    SAuth::Consumer::RequestWrapper->new(
        key  => $self->key,
        body => SAuth::Core::AccessRequest->new(
            uid            => $self->key->uid,
            access_for     => $access_for,
            token_lifespan => $token_lifespan
        )
    );
}

sub create_refresh_request {
    my ($self, $token_lifespan) = validated_list(\@_,
        token_lifespan => { isa => 'Int' },
    );

    ($self->has_access_grant)
        || SAuth::Core::Error::AccessGrantNotFound->throw("No current access grant to refresh");

    ($self->access_grant->can_refresh)
        || SAuth::Core::Error::CannotRefresh->throw("The current access grant does not allow refreshing");

    ($self->has_valid_key)
        || SAuth::Core::Error::InvalidKey->throw;

    ($self->key->allow_refresh)
        || SAuth::Core::Error::CannotRefresh->throw("The key does not allow refreshing");

    SAuth::Consumer::RequestWrapper->new(
        key  => $self->key,
        body => SAuth::Core::AccessRefresh->new(
            uid            => $self->key->uid,
            token          => $self->access_grant->token,
            token_lifespan => $token_lifespan
        )
    );
}

sub process_access_grant {
    my ($self, $access_grant) = @_;
    $self->access_grant( SAuth::Core::AccessGrant->from_json( $access_grant ) );
}

sub has_valid_access_grant {
    my $self = shift;
    $self->has_access_grant && $self->access_grant->is_valid ? 1 : 0
}

sub has_valid_key {
    my $self = shift;
    $self->key->is_valid ? 1 : 0
}

sub generate_token_hmac {
    my ($self, $nonce) = @_;

    (defined $nonce)
        || SAuth::Core::Error->throw("Cannot generate token hmac without a nonce");

    ($self->has_valid_access_grant)
        || SAuth::Core::Error::InvalidAccessGrant->throw("Cannot generate token hmac without a valid access grant");

    ($self->has_valid_key)
        || SAuth::Core::Error::InvalidKey->throw("Cannot generate token hmac with an invalid key");

    hmac_digest(
        $self->key->shared_secret,
        $self->access_grant->token,
        $nonce
    );
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Consumer;

=head1 DESCRIPTION

