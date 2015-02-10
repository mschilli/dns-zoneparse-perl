use strict;
BEGIN { $^W++ }
use Test::More tests => 13;
use lib '../lib/';

# See if the module compiles - it should...
require_ok( 'DNS::ZoneParse' );

my $zone_data = do { local $/; <DATA> };
close DATA;

sub on_parse_fail {
    my ( $dns, $line, $reason ) = @_;
    if ( $line !~ /this should fail/ ) {
        ok( 0, "Parse failure ($reason) on line: $line\n" );
    }
}

# Specify alternate TTL parsing (using RFC2308 perscribed method of parsing
# $TTL directives).
my $alt_ttl_mode = 1;

my $str_zonefile = DNS::ZoneParse->new( \$zone_data, undef, \&on_parse_fail, $alt_ttl_mode );
ok( $str_zonefile,                                'new obj from string' );
ok( $str_zonefile->last_parse_error_count() == 0, "caught all errors (none!)" );
test_zone( $str_zonefile );

my $serialized = $str_zonefile->output();
$str_zonefile = DNS::ZoneParse->new( \$serialized, undef, \&on_parse_fail, $alt_ttl_mode );
ok( $str_zonefile,                                'new obj from output' );
ok( $str_zonefile->last_parse_error_count() == 0, "caught all errors (none!)" );
test_zone( $str_zonefile );

sub test_zone {
    my $zf = shift;
    
    # Ensure $TTL and absence of $TTL is working as per RFC 2308
    is_deeply(
        $zf->soa,
        {
            'ORIGIN'     => 'dns-zoneparse-test.net.',
            'minimumTTL' => '86400',
            'serial'     => '2000100502',
            'refresh'    => '10801',
            'retry'      => '3600',
            'expire'     => '691200',
            'ttl'        => '3600',
            'primary'    => 'ns0.dns-zoneparse-test.net.',
            'origin'     => '@',
            'email'      => 'support\\.contact.dns-zoneparse-test.net.',
            'class'      => 'IN',
        },
        'SOA parsed ok'
    );

    is_deeply(
        $zf->ns,
        [
            {
                'ORIGIN' => 'dns-zoneparse-test.net.',
                'class'  => 'IN',
                'ttl'    => '10',
                'host'   => 'ns1.dns-zoneparse-test.net.',
                'name'   => 'ns1',
            },
        ],
        'NS parsed ok'
    );

    is_deeply(
        $zf->a,
        [
            {
                'ORIGIN'  => 'dns-zoneparse-test.net.',
                'class'   => 'IN',
                'ttl'     => '3600',
                'name'    => '@',
                'host'    => '127.0.0.1'
            },
            {
                'ORIGIN'  => 'dns-zoneparse-test.net.',
                'class'   => 'IN',
                'ttl'     => '3600',
                'name'    => 'ns1',
                'host'    => '127.0.0.2'
            },
            {
                'ORIGIN'  => 'dns-zoneparse-test.net.',
                'class'   => 'IN',
                'ttl'     => '3600',
                'name'    => 'www',
                'host'    => '127.0.0.3'
            },
        ],
        'A parsed ok'
    );

    is_deeply(
        $zf->cname,
        [
            {
                'ORIGIN' => 'dns-zoneparse-test.net.',
                'class'  => 'IN',
                'ttl'    => '3600',
                'name'   => 'ftp',
                'host'   => 'www'
            },
        ],
        'CNAME parsed ok'
    );

}

__DATA__
$ORIGIN dns-zoneparse-test.net.
$TTL 3600
@                           IN	SOA	ns0.dns-zoneparse-test.net.	support\.contact.dns-zoneparse-test.net.	(
                        2000100502   ; serial number
                        10801       ; refresh
                        3600        ; retry
                        691200      ; expire
                        86400     ) ; minimum TTL

; This zone demonstrates that without the $TTL directive
; TTLs are inherited from the last TTL specified.
    
    IN  A   127.0.0.1
ns1 IN  A   127.0.0.2
    IN  10  NS  ns1.dns-zoneparse-test.net.

www IN  A   127.0.0.3
ftp IN  CNAME   www
