use strict;
BEGIN { $^W++ }
use Test::More tests => 19;
use File::Spec::Functions ':ALL';
use lib '../lib';

# See if the module compiles - it should...
require_ok( 'DNS::ZoneParse' );

my $filename = catfile( ( splitpath( rel2abs( $0 ) ) )[0, 1], 'include-test-zone.db' );
my $FH;
open( $FH, '<', $filename ) or die "error loading test file $filename: $!";
my $zone_data = do { local $/; <$FH> };
close $FH;

sub on_parse_fail {
    my ( $dns, $line, $reason ) = @_;
    if ( $line !~ /this should fail/ ) {
        ok( 0, "Parse failure ($reason) on line: $line\n" );
    }
}

#create a DNS::ZoneParse object;

# Additional errors are created by the repeat inclusion of 
# the deliberately bad RRs.

my $str_zonefile = DNS::ZoneParse->new( \$zone_data, undef, \&on_parse_fail );
ok( $str_zonefile,                                'new obj from string' );
test_zone( $str_zonefile );

$str_zonefile = DNS::ZoneParse->new( $filename, undef, \&on_parse_fail );
ok( $str_zonefile,                                'new obj from filename' );
test_zone( $str_zonefile );

# We don't test a parse zone's output being parsed again as the included records
# will be returned in an format disimilar to direct parsing due to
# grouping of records by ORIGIN when records are output(). 

sub test_zone {
    my $zf = shift;

    # See if the new_serial method works.
    my $serial = $zf->soa->{serial};
    ok( defined $serial, 'serial is defined' );
    $zf->new_serial( 1 );
    my $newserial = $zf->soa->{serial};
    ok( $newserial = $serial + 1, 'new_serial( int )' );
    $serial = $zf->new_serial();
    ok( $serial > $newserial, 'new_serial()' );

    # Test some basic records to ensure inclusion is working as expected
    # regarding behavior of record names, TTLs and origins.

    is_deeply(
        $zf->soa,
        {
            'minimumTTL' => '86400',
            'serial'     => $serial,
            'ttl'        => '1H',
            'primary'    => 'ns0.dns-zoneparse-test.net.',
            'origin'     => '@',
            'email'      => 'support\\.contact.dns-zoneparse-test.net.',
            'retry'      => '3600',
            'refresh'    => '10801',
            'expire'     => '691200',
            'ORIGIN'     => 'dns-zoneparse-test.net.',
            'class'      => 'IN',
        },
        'SOA parsed ok',
    );

    is_deeply(
        $zf->a,
        [
            {
                'ttl'   => '1H',
                'name'  => '@',
                'class' => 'IN',
                'host'  => '127.0.0.1',
                'ORIGIN' => 'dns-zoneparse-test.net.'
            },
            {
                'ttl'   => '1H',
                'name'  => 'next-rr-will-have-this-name',
                'class' => 'IN',
                'host'  => '127.0.0.1',
                'ORIGIN' => 'dns-zoneparse-test.net.'
            },
            {
                'ttl'   => '1H',
                'name'  => '@',
                'class' => 'IN',
                'host'  => '127.0.0.2',
                'ORIGIN' => 'dns-zoneparse-test.net.'
            },
            {
                'ttl'   => '1H',
                'name'  => 'next-rr-will-have-this-name2',
                'class' => 'IN',
                'host'  => '127.0.0.2',
                'ORIGIN' => 'dns-zoneparse-test.net.'
            },
            {
                'ttl'   => '1H',
                'name'  => '@',
                'class' => 'IN',
                'host'  => '127.0.0.2',
                'ORIGIN' => 'dns-zoneparse-test-include.net.'
            },
            {
                'ttl'   => '1H',
                'name'  => 'next-rr-will-have-this-name2',
                'class' => 'IN',
                'host'  => '127.0.0.2',
                'ORIGIN' => 'dns-zoneparse-test-include.net.'
            },
            {
                'ttl'   => '1H',
                'name'  => '@',
                'class' => 'IN',
                'host'  => '127.0.0.2',
                'ORIGIN' => 'dns-zoneparse-test-include2.net.'
            },
            {
                'ttl'   => '1H',
                'name'  => 'next-rr-will-have-this-name2',
                'class' => 'IN',
                'host'  => '127.0.0.2',
                'ORIGIN' => 'dns-zoneparse-test-include2.net.'
            },
        ],
        'A records parsed OK',
    );

    is_deeply(
        $zf->ns,
        [
            {
                'ttl'    => '43200',
                'name'   => '@',
                'class'  => 'IN',
                'host'   => 'ns0.dns-zoneparse-test.net.',
                'ORIGIN' => 'dns-zoneparse-test.net.',
            },
            {
                'ttl'    => '1H',
                'name'   => '@',
                'class'  => 'IN',
                'host'   => 'ns1.dns-zoneparse-test.net.',
                'ORIGIN' => 'dns-zoneparse-test.net.',
            },
            {
                'ttl'    => '43200',
                'name'   => 'next-rr-will-have-this-name',
                'class'  => 'IN',
                'host'   => 'ns2.dns-zoneparse-test.net.',
                'ORIGIN' => 'dns-zoneparse-test.net.',
            },
            {
                'ttl'    => '1H',
                'name'   => '@',
                'class'  => 'IN',
                'host'   => 'ns3.dns-zoneparse-test.net.',
                'ORIGIN' => 'dns-zoneparse-test.net.'
            },
            {
                'ttl'    => '43200',
                'name'   => 'next-rr-will-have-this-name2',
                'class'  => 'IN',
                'host'   => 'ns2.dns-zoneparse-test.net.',
                'ORIGIN' => 'dns-zoneparse-test-include.net.'
            },
            {
                'ttl'    => '1H',
                'name'   => '@',
                'class'  => 'IN',
                'host'   => 'ns3.dns-zoneparse-test.net.',
                'ORIGIN' => 'dns-zoneparse-test-include.net.'
            },
            {
                'ttl'    => '43200',
                'name'   => 'next-rr-will-have-this-name2',
                'class'  => 'IN',
                'host'   => 'ns2.dns-zoneparse-test.net.',
                'ORIGIN' => 'dns-zoneparse-test-include2.net.'
            },
            {
                'ttl'    => '1H',
                'name'   => '@',
                'class'  => 'IN',
                'host'   => 'ns3.dns-zoneparse-test.net.',
                'ORIGIN' => 'dns-zoneparse-test-include2.net.'
            }
            
        ],
        'NS records parsed OK',
    );

    is_deeply(
        $zf->mx,
        [
            {
                'priority' => '10',
                'ttl'      => '1H',
                'name'     => '@',
                'class'    => 'IN',
                'host'     => 'mail',
                'ORIGIN'   => 'dns-zoneparse-test.net.',
            },
            {
                'priority' => '10',
                'ttl'      => '1H',
                'name'     => '@',
                'class'    => 'IN',
                'host'     => 'mail2',
                'ORIGIN'   => 'dns-zoneparse-test.net.',
            },
            {
                'priority' => '10',
                'ttl'      => '1H',
                'name'     => '@',
                'class'    => 'IN',
                'host'     => 'mail2',
                'ORIGIN'   => 'dns-zoneparse-test-include.net.',
            },
            {
                'priority' => '10',
                'ttl'      => '1H',
                'name'     => '@',
                'class'    => 'IN',
                'host'     => 'mail2',
                'ORIGIN'   => 'dns-zoneparse-test-include2.net.',
            },
        ],
        'MX records parsed OK',
    );

    is_deeply(
        $zf->cname,
        [
            {
                'ttl'    => '1H',
                'name'   => 'ftp',
                'class'  => 'IN',
                'host'   => 'www',
                'ORIGIN' => 'dns-zoneparse-test.net.',
            },
            {
                'ttl'    => '1H',
                'name'   => 'ftp',
                'class'  => 'IN',
                'host'   => 'www1',
                'ORIGIN' => 'dns-zoneparse-test.net.',
            },
            {
                'ttl'    => '1H',
                'name'   => 'ftp',
                'class'  => 'IN',
                'host'   => 'www1',
                'ORIGIN' => 'dns-zoneparse-test-include.net.',
            },
            {
                'ttl'    => '1H',
                'name'   => 'ftp',
                'class'  => 'IN',
                'host'   => 'www1',
                'ORIGIN' => 'dns-zoneparse-test-include2.net.',
            },
        ],
        'CNAME records parsed OK',
    );
}
