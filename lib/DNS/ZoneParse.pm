# DNS::ZoneParse
# Parse and Manipulate DNS Zonefiles
# Version 0.95
# CVS: $Id: ZoneParse.pm,v 1.4 2008-11-14 16:59:51 mikeschilli Exp $
package DNS::ZoneParse;

use 5.005;
use Storable 'dclone';
use POSIX 'strftime';
use vars qw($VERSION);
use strict;
use Carp;

$VERSION = '0.96';
my (%dns_id, %dns_soa, %dns_ns, %dns_a, %dns_cname, %dns_mx,
    %dns_txt, %dns_ptr, %dns_a4, %dns_srv, %dns_last_name);

sub new {
    my $class = shift;
    my $self = bless [], $class;

    $self->_initialize();
    $self->_load_file(@_) if @_;
    return $self;
}

sub DESTROY {
    my $self = shift;
    delete $dns_soa   {$self};    delete $dns_ns    {$self};
    delete $dns_a     {$self};    delete $dns_cname {$self};
    delete $dns_mx    {$self};    delete $dns_txt   {$self};
    delete $dns_ptr   {$self};    delete $dns_a4    {$self};
    delete $dns_srv   {$self};
    delete $dns_id    {$self};    delete $dns_last_name {$self};
}

sub AUTOLOAD {
    my $self = shift;
    (my $method = $DNS::ZoneParse::AUTOLOAD) =~ s/.*:://;

    my $rv = $method eq 'soa'      ? $dns_soa   {$self}
           : $method eq 'ns'       ? $dns_ns    {$self}
           : $method eq 'a'        ? $dns_a     {$self}
           : $method eq 'cname'    ? $dns_cname {$self}
           : $method eq 'mx'       ? $dns_mx    {$self}
           : $method eq 'txt'      ? $dns_txt   {$self}
           : $method eq 'ptr'      ? $dns_ptr   {$self}
           : $method eq 'aaaa'     ? $dns_a4    {$self}
           : $method eq 'srv'      ? $dns_srv   {$self}
           : $method eq 'zonefile' ? $dns_id    {$self}->{ZoneFile}
           : $method eq 'origin'   ? $dns_id    {$self}->{Origin}
           : undef;

    croak "Invalid method called: $method" unless defined $rv;
    return $rv;
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Public OO Methods
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

sub dump {
    # returns a HOH for use with XML modules, etc
    my $self = shift;
    return dclone({
                   SOA   => $dns_soa   {$self}, AAAA  => $dns_a4  {$self},
                   A     => $dns_a     {$self}, NS    => $dns_ns  {$self},
                   CNAME => $dns_cname {$self}, MX    => $dns_mx  {$self},
                   PTR   => $dns_ptr   {$self}, TXT   => $dns_txt {$self},
                   SRV   => $dns_srv   {$self},
                  });
}

sub new_serial {
    my $self = shift;
    my $incriment = shift || 0;
    my $soa = $dns_soa{$self};
    if ($incriment > 0) { 
        $soa->{serial} += $incriment;
    } else {
        my $newserial = strftime("%Y%m%d%H", localtime(time));
        $soa->{serial} = ($newserial > $soa->{serial}) ? $newserial
            : $soa->{serial} + 1;
    }
    return $soa->{serial};
}

sub output {
    my $self = shift;
    my @quick_classes = qw(A AAAA CNAME PTR SRV);
    my $zone_ttl = $dns_soa{$self}{ttl} ? "\$TTL $dns_soa{$self}{ttl}" : '';
    my $output = "";
    $output .= <<ZONEHEADER;
;
;  Database file $dns_id{$self}->{ZoneFile} for $dns_id{$self}->{Origin} zone.
;	Zone version: $dns_soa{$self}->{serial}
;

$zone_ttl
$dns_soa{$self}->{origin}		$dns_soa{$self}->{ttl}	IN  SOA  $dns_soa{$self}->{primary} $dns_soa{$self}->{email} (
				$dns_soa{$self}->{serial}	; serial number
				$dns_soa{$self}->{refresh}	; refresh
				$dns_soa{$self}->{retry}	; retry
				$dns_soa{$self}->{expire}	; expire
				$dns_soa{$self}->{minimumTTL}	; minimum TTL
				)
;
; Zone NS Records
;

ZONEHEADER

    foreach (@{$dns_ns{$self}}) {
        next unless defined;
        $output .= "$_->{name}	$_->{ttl}	$_->{class}	NS	$_->{host}\n";
    }

    $output .= "\n\;\n\; Zone MX Records\n\;\n\n";
    foreach (@{$dns_mx{$self}}) {
        next unless defined;
        $output .= "$_->{name}	$_->{ttl}	$_->{class}	MX	$_->{priority} "
                ." $_->{host}\n";
    }

    $output .= "\n\;\n\; Zone Records\n\;\n\n";
    foreach (@{$dns_a{$self}}) {
        next unless defined;
        $output .= "$_->{name}	$_->{ttl}	$_->{class}	A	$_->{host}\n";
    }
    foreach (@{$dns_cname{$self}}) {
        next unless defined;
        $output .= "$_->{name}	$_->{ttl}	$_->{class}	CNAME	$_->{host}\n";
    }
    foreach (@{$dns_a4{$self}}) {
        next unless defined;
        $output .= "$_->{name}	$_->{ttl}	$_->{class}	AAAA	$_->{host}\n";
    }
    foreach (@{$dns_txt{$self}}) {
        next unless defined;
        $output .= qq[$_->{name}	$_->{ttl} $_->{class} TXT	"$_->{text}"\n]
    }
    foreach (@{$dns_ptr{$self}}) {
        next unless defined;
        $output .= "$_->{name}	$_->{ttl}	$_->{class}	PTR		$_->{host}\n";
    }
    foreach (@{$dns_srv{$self}}) {
        next unless defined;
        $output .= "$_->{name}	$_->{ttl}	$_->{class}	SRV	$_->{priority}	" .
		    "$_->{weight}	$_->{port}	$_->{host}\n";
    }
    return $output;
}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Private Methods
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

sub _initialize {
    my $self = shift;
    $dns_id    {$self} = {};    $dns_soa   {$self} = {};
    $dns_ns    {$self} = [];    $dns_a     {$self} = [];
    $dns_cname {$self} = [];    $dns_mx    {$self} = [];
    $dns_txt   {$self} = [];    $dns_ptr   {$self} = [];
    $dns_a4    {$self} = [];    $dns_srv   {$self} = [];
    $dns_last_name{$self} = '@';
    return 1;
}


sub _load_file {
    my ($self, $zonefile, $origin) = @_;
    my $zone_contents;
    if(ref($zonefile) eq "SCALAR") {
        $zone_contents = $$zonefile;
    } else {
        local *inZONE;
        if (open(inZONE, "$zonefile")) {
            $zone_contents = do {local $/; <inZONE>};
            close(inZONE);
        } else {
            croak qq[DNS::ZoneParse Could not open input file: "$zonefile":$!]
        }
    }
    if ($self->_parse( $zonefile, $zone_contents, $origin )) { return 1; }
}


sub _parse {
    my ($self, $zonefile, $contents, $origin) = @_;
    $self->_initialize();

    my $chars = qr/[a-z\-\.0-9]+/i;
    $contents =~ /Database file ($chars)( dns)? for ($chars) zone/si;
    $dns_id{$self} = $self -> _massage({
        ZoneFile => $1 || $zonefile,
        Origin   => $3 || $origin,
    });

    my $records    = $self->_clean_records($contents);
    my $valid_name = qr/[\@a-z_\-\.0-9\*]+/i;
    my $valid_ip6  = qr/[\@a-z_\-\.0-9\*:]+/i;
    my $rr_class   = qr/\b(?:IN|HS|CH)\b/i;
    my $rr_type    = qr/\b(?:NS|A|CNAME)\b/i;
    my $rr_ttl     = qr/(?:\d+[wdhms]?)+/i;
    my $ttl_cls    = qr/(?:($rr_ttl)\s)?(?:($rr_class)\s)?/;
    my $last_name  = $dns_id {$self} -> {Origin} || '@';

    foreach (@$records) {
        TRACE ("parsing line <$_>");
        if (/^($valid_name)? \s*      # host
              $ttl_cls                   # ttl & class
              ($rr_type) \s              # record type
              ($valid_name)              # record data
             /ix) {
             my ($name, $ttl, $class, $type, $host) = ($1, $2, $3, $4, $5);
             my $dns_thing = uc $type eq 'NS' ? $dns_ns{$self}
                 : uc $type eq 'A' ? $dns_a{$self} : $dns_cname{$self};
             push @$dns_thing,
                 $self -> _massage({name => $name, class=> $class,
                                    host => $host, ttl => $ttl});
        }
        elsif (/^($valid_name)? \s*
                $ttl_cls
                AAAA \s
                ($valid_ip6)
                /x)
        {
            my ($name, $ttl, $class, $host) = ($1, $2, $3, $4);
             push @{$dns_a4{$self}},
                 $self -> _massage({name => $name, class=> $class,
                                    host => $host, ttl => $ttl})
        }
        elsif (/^($valid_name)? \s*
                 $ttl_cls
                 MX \s
                 (\d+) \s
                 ($valid_name)
               /ix)
        {
              # host ttl class mx pri dest
             my ($name, $ttl, $class, $pri, $host) = ($1, $2, $3, $4, $5);
             push @{$dns_mx{$self}},
                  $self -> _massage({ name => $name, priority => $pri,
                                      host => $host, ttl => $ttl,
                                      class => $class})
        }
        elsif (/^($valid_name)? \s*
                 $ttl_cls
                 SRV \s
                 (\d+) \s
                 (\d+) \s
                 (\d+) \s
                 ($valid_name)
               /ix)
        {
              # host ttl class mx priority weight port dest
             my ($name, $ttl, $class, $pri, $weight, $port, $host) = 
			     ($1, $2, $3, $4, $5, $6, $7);
             push @{$dns_srv{$self}},
                  $self -> _massage({ name => $name, priority => $pri,
                                      weight => $weight, port => $port,
                                      host => $host, ttl => $ttl,
                                      class => $class})
        }
        elsif (/^($valid_name) \s+
                 $ttl_cls
                 SOA \s+
                 ($valid_name) \s+
                 ($valid_name) \s*
                 \(?\s*
                     ($rr_ttl) \s+
                     ($rr_ttl) \s+
                     ($rr_ttl) \s+
                     ($rr_ttl) \s+
                     ($rr_ttl) \s*
                 \)?
               /ix)
        {
            # SOA record
            my $ttl = $dns_soa{$self}->{ttl} || $2 || '';
            $dns_soa{$self} =
                $self -> _massage({ origin => $1, ttl => $ttl, primary => $4,
                                    email => $5, serial => $6, refresh => $7,
                                    retry => $8, expire => $9,
                                    minimumTTL => $10 });
        }
        elsif (/^($valid_name)? \s*
                $ttl_cls
                PTR \s+
                ($valid_name)
               /ix)
        {
            # PTR
            push @{$dns_ptr{$self}},
                $self -> _massage({ name => $1, class => $3, ttl => $2,
                                    host => $4 });
        }
        elsif (/($valid_name)? \s $ttl_cls TXT \s \"([^\"]*)\"/ix)
        {
            push @{$dns_txt{$self}},
                $self -> _massage({ name => $1,  ttl => $2, class => $3,
                                    text=> $4});
        }
        elsif (/\$TTL\s+($rr_ttl)/i) {
            $dns_soa{$self}->{ttl} = $1;
        }
        else {
            carp "Unparseable line\n  $_\n";
        }
    }
    return 1;
}

sub _clean_records {
    my $self = shift;
    my ($zone) = shift;

    $zone =~ s<\;.*$> <>mg;  # Remove comments
    $zone =~ s<^\s*$> <>mg;  # Remove empty lines
    $zone =~ s<$/+>   <$/>g; # Remove multiple carriage returns
    $zone =~ s<[ \t]+>< >g;  # Collapse whitespace, turn TABs to spaces

    # Concatenate everything split over multiple lines i.e. elements surrounded
    # by parentheses can be split over multiple lines. See RFC 1035 section 5.1
    $zone =~ s{(\([^\)]*?\))}{_concatenate($1)}egs;

    # Split into multiple records, and kick out empty lines
    my @records = grep !/^$/, split (m|$/|, $zone);
    return \@records;
}

sub _concatenate {
    my $text_in_parenth= shift;
    $text_in_parenth=~ s{\s*$/\s*}{ }g;
    return $text_in_parenth;
}

sub _massage {
    my $self = shift;
    my $record = shift;
    my $last_name = \$dns_last_name {$self};

    foreach (keys %$record) {
        $record->{$_} = "" unless defined $record->{$_};
        $record->{$_} = uc $record->{$_} if $_ eq 'class';
    }

    return $record unless exists $record->{name};
    if (length $record->{name}) {
        $$last_name = $record->{name};
    } else {
        TRACE("Record has no name, using last name");
        $record->{name} = $$last_name;
    }
    DUMP("Record parsed", $record);
    return $record;
}

sub TRACE {0 && print @_, $/}
sub DUMP  {0 && require Data::Dumper && TRACE(shift, Data::Dumper::Dumper(@_))}

1;
__END__

=head1 NAME

DNS::ZoneParse - Parse and manipulate DNS Zone Files.

=head1 SYNOPSIS

    use DNS::ZoneParse;
    
    my $zonefile = DNS::ZoneParse->new("/path/to/dns/zonefile.db", $origin);
    
    # Get a reference to the MX records
    my $mx = $zonefile->mx;
    
    # Change the first mailserver on the list
    $mx->[0] = { host => 'mail.localhost.com',
                 priority => 10,
                 name => '@' };
    
    # update the serial number
    $zonefile->new_serial();
    
    # write the new zone file to disk 
    open NEWZONE, ">/path/to/dns/zonefile.db" or die "error";
    print NEWZONE $zonefile->output();
    close NEWZONE;

=head1 INSTALLATION

   perl Makefile.PL
   make
   make test
   make install

Win32 users substitute "make" with "nmake" or equivalent. 
nmake is available at http://download.microsoft.com/download/vc15/Patch/1.52/W95/EN-US/Nmake15.exe

=head1 DESCRIPTION

This module will parse a Zone File and put all the Resource Records (RRs)
into an anonymous hash structure. At the moment, the following types of 
RRs are supported: SOA, NS, MX, A, CNAME, TXT, PTR. It could be useful for
maintaining DNS zones, or for transferring DNS zones to other servers. If
you want to generate an XML-friendly version of your zone files, it is
easy to use XML::Simple with this module once you have parsed the zonefile.

DNS::ZoneParse scans the DNS zonefile - removes comments and seperates
the file into its constituent records. It then parses each record and
stores the records internally. See below for information on the accessor
methods.


=head2 METHODS

=over 4

=item new

This creates the DNS::ZoneParse Object and loads the zonefile

Example:
    my $zonefile = DNS::ZoneParse->new("/path/to/zonefile.db");

You can also initialise the object with the contents of a file:
    my $zonefile = DNS::ZoneParse->new( \$zone_contents );

You can pass a second, optional parameter to the constructor to supply an
C<$origin> if none can be found in the zone file.

    my $zonefile = DNS::ZoneParse->new( \$zone_contents, $origin );

=item a(), cname(), srv(), mx(), ns(), ptr()

These methods return references to the resource records. For example:

    my $mx = $zonefile->mx;

Returns the mx records in an array reference.

A, CNAME, NS, MX, PTR, and SRV records have the following properties:
'ttl', 'class', 'host', 'name'

MX records also have a 'priority' property.

SRV records also have 'priority', 'weight' and 'port' properties

=item soa()

Returns a hash reference with the following properties:
'serial', 'origin', 'primary', 'refresh', 'retry', 'ttl', 'minimumTTL',
'email', 'expire'

=item dump

Returns a copy of the datastructute that stores all the resource records. This
might be useful if you want to quickly transform the data into another format,
such as XML.

=item new_serial

C<new_serial()> incriments the Zone serial number. It will generate a
date-based serial number. Or you can pass a positive number to add to the
current serial number.

Examples:

    $zonefile->new_serial(); 
            # generates a new serial number based on date:
            # YYYYmmddHH format, incriments current serial
            # by 1 if the new serial is still smaller

    $zonefile->new_serial(50);  
            # adds 50 to the original serial number

=item output

C<output()> returns the new zonefile output as a string. If you wish your
output formatted differently, you can pass the output of C<dump()> to your
favourite templating module.

=back

=head2 EXAMPLES

This script will print the A records in a zone file, add a new A record for the
name "new" and then return the zone file.

    use strict;
    use DNS::ZoneParse;
    
    my $zonefile = DNS::ZoneParse->new("/path/to/zonefile.db");
    
    print "Current A Records\n";
    my $a_records = $zonefile->a();
    
    foreach my $record (@$a_records) {
        print "$record->{name} resolves at $record->{host}\n";
    }
    
    push (@$a_records, { name => 'new', class => 'IN',
                         host => '127.0.0.1', ttl => '' });
    
    $zonefile->new_serial();
    my $newfile = $zonefile->output();




This script will convert a DNS Zonefile to an XML file using XML::Simple.


    use strict;
    use DNS::ZoneParse;
    use XML::Simple;

    my $zonefile = DNS::ZoneParse->new("/path/to/zonefile.db");

    my $new_xml = XMLout($zonefile->dump,
                         noattr => 1,
                         suppressempty => 1,
                         rootname => $zonefile->origin);

=head1 CHANGES

see F<Changes>

=head1 API

The DNS::ZoneParse API may change in future versions. At present, the parsing
is not as strict as it should be and support for C<$ORIGIN> and C<$TTL> is
quite basic. It would also be nice to support the C<INCLUDE>
statement. Furthermore, parsing large zonefiles with thousands of records can
use lots of memory - some people have requested a callback interface.

=head1 BUGS

I can squash more bugs with your help. Please let me know if you spot something
that doesn't work as expected.

You can report bugs via the CPAN RT:
L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=DNS-ZoneParse>

If possible, please provide a diff against F<t/dns-zoneparse.t> and
F<t/test-zone.db> that demonstrates the bug(s).

=head1 SEE ALSO

Other modules with similar functionality:

Net::DNS::ZoneParser, Net::DNS::ZoneFile, DNS::ZoneFile

=head1 AUTHOR

Simon Flack

=head1 MAINTENANCE

Maintainer: Mike Schilli, m@perlmeister.com,
Bug queue: http://rt.cpan.org/Public/Dist/Display.html?Name=DNS-ZoneParse

=head1 LICENSE

DNS::ZoneParse is free software which you can redistribute and/or modify under
the same terms as Perl itself.

=cut
