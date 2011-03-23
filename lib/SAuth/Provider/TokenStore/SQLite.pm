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

sub update_access_grant_for_token {
    my ($self, $access_grant) = @_;
    $self->dbh->do(
        'UPDATE access_grants SET access_grant = ? WHERE token = ?',
        {},
        $access_grant->to_json,
        $access_grant->token
    );
}

sub add_access_grant_for_token {
    my ($self, $access_grant) = @_;
    $self->dbh->do(
        'INSERT INTO access_grants (token, access_grant) VALUES(?, ?)',
        {},
        $access_grant->token,
        $access_grant->to_json
    );
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::TokenStore::SQLite;

=head1 DESCRIPTION

