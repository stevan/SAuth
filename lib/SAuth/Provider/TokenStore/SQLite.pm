package SAuth::Provider::TokenStore::SQLite;
use Moose;

use SAuth::Util;

with 'SAuth::Provider::TokenStore',
     'SAuth::Core::Role::WithSQLiteHandle';

sub BUILD {
    my $self = shift;
    $self->dbh->do(q[
        CREATE TABLE IF NOT EXISTS access_grants (
            token        VARCHAR( 36 ),
            access_grant TEXT,
            nonce        VARCHAR( 36 ),
            PRIMARY KEY ( token )
        )
    ]);
}

sub has_access_grant_for_token {
    my ($self, $token) = @_;
    my $sth = $self->dbh->prepare( 'SELECT COUNT(*) FROM access_grants WHERE token = ?' );
    $sth->execute( $token );
    my ($count) = $sth->fetchrow_array;
    $count ? 1 : 0;
}

sub get_access_grant_for_token {
    my ($self, $token) = @_;
    my $sth = $self->dbh->prepare( 'SELECT access_grant FROM access_grants WHERE token = ?' );
    $sth->execute( $token );
    my ($access_grant_json) = $sth->fetchrow_array;
    SAuth::Core::AccessGrant->from_json( $access_grant_json );
}

sub add_access_grant_for_token {
    my ($self, $access_grant, $nonce) = @_;
    $self->dbh->do(
        'INSERT INTO access_grants (token, access_grant, nonce) VALUES(?, ?, ?)',
        {},
        $access_grant->token,
        $access_grant->to_json,
        SAuth::Util::encode_base64( $nonce )
    );
}

sub get_nonce_for_token {
    my ($self, $token) = @_;
    my $sth = $self->dbh->prepare( 'SELECT nonce FROM access_grants WHERE token = ?' );
    $sth->execute( $token );
    my ($nonce) = $sth->fetchrow_array;
    SAuth::Util::decode_base64( $nonce );
}

sub update_nonce_for_token {
    my ($self, $token, $nonce) = @_;
    $self->dbh->do(
        'UPDATE access_grants SET nonce = ? WHERE token = ?',
        {},
        SAuth::Util::encode_base64( $nonce ),
        $token,
    );
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::TokenStore::SQLite;

=head1 DESCRIPTION

