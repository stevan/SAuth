package SAuth::Provider::KeyStore::SQLite;
use Moose;
use MooseX::Types::Path::Class;

use SAuth::Util;
use SAuth::Core::Key;

use DBI;

with 'SAuth::Provider::KeyStore';

has 'db_file' => (
    is       => 'ro',
    isa      => 'Path::Class::File',
    coerce   => 1,
    required => 1,
);

has 'dbh' => (
    init_arg => undef,
    is       => 'ro',
    isa      => 'DBI::db',
    lazy     => 1,
    default  => sub {
        my $self = shift;
        DBI->connect(
            'dbi:SQLite:dbname=' . $self->db_file, '', '',
            { RaiseError => 1, PrintError => 0 }
        ) || confess $DBI::errstr;
    },
);

sub BUILD {
    my $self = shift;
    $self->dbh->do(q[
        CREATE TABLE IF NOT EXISTS keys (
            id  VARCHAR( 64 ),
            key TEXT,
            PRIMARY KEY ( id )
        );
    ]);
}

sub has_key_for {
    my ($self, $uid) = @_;
    my $sth = $self->dbh->prepare( 'SELECT COUNT(*) FROM keys WHERE id = ?' );
    $sth->execute( digest( $uid ) );
    my ($count) = $sth->fetchrow_array;
    $count ? 1 : 0;
}

sub get_key_for {
    my ($self, $uid) = @_;
    my $sth = $self->dbh->prepare( 'SELECT key FROM keys WHERE id = ?' );
    $sth->execute( digest( $uid ) );
    my ($key) = $sth->fetchrow_array;
    SAuth::Core::Key->from_json( $key );
}

sub add_key_for {
    my ($self, $uid, $key) = @_;
    $self->dbh->do(
        'INSERT INTO keys (id, key) VALUES(?, ?)',
        {},
        digest( $uid ),
        $key->to_json
    );
}

__PACKAGE__->meta->make_immutable;

no Moose; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Provider::KeyStore::SQLite;

=head1 DESCRIPTION

