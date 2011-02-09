package SAuth::Core::Role::WithSQLiteHandle;
use Moose::Role;
use MooseX::Types::Path::Class;

use DBI;

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

no Moose::Role; 1;

__END__

# ABSTRACT: A Moosey solution to this problem

=head1 SYNOPSIS

  use SAuth::Core::Role::WithSQLiteHandle;

=head1 DESCRIPTION

