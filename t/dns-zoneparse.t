use strict;
BEGIN { $^W++ }
use Test::More tests => 49;
use File::Spec::Functions ':ALL';

# See if the module compiles - it should...
require_ok( 'DNS::ZoneParse' );

my $filename = catfile( ( splitpath( rel2abs( $0 ) ) )[0, 1], 'test-zone.db' );
my $FH;
open( $FH, '<', $filename ) or die "error loading test file $filename: $!";
my $zone_data = do { local $/; <$FH> };
close $FH;

sub on_parse_fail {
    my ( $dns, $line ) = @_;
    if ( $line !~ /this should fail/ ) {
        warn "Parse failure on line: $line\n";
    }
}

#create a DNS::ZoneParse object;

my $str_zonefile = DNS::ZoneParse->new( \$zone_data, undef, \&on_parse_fail );
ok( $str_zonefile, 'new obj from string' );
ok( $str_zonefile->last_parse_error_count() == 2, "caught all errors" );
test_zone( $str_zonefile );

$str_zonefile = DNS::ZoneParse->new( $filename, undef, \&on_parse_fail );
ok( $str_zonefile, 'new obj from filename' );
ok( $str_zonefile->last_parse_error_count() == 2, "caught all errors" );
test_zone( $str_zonefile );

my $serialized = $str_zonefile->output();
$str_zonefile = DNS::ZoneParse->new( \$serialized, undef, \&on_parse_fail );
ok( $str_zonefile, 'new obj from output' );
ok( $str_zonefile->last_parse_error_count() == 0, "caught all errors (none!)" );
test_zone( $str_zonefile );

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

    is_deeply(
        $zf->soa,
        {
            'minimumTTL' => '86400',
            'serial'     => $serial,
            'ttl'        => '1H',
            'primary'    => 'ns0.dns-zoneparse-test.net.',
            'origin'     => '@',
            'email'      => 'support.dns-zoneparse-test.net.',
            'retry'      => '3600',
            'refresh'    => '10800',
            'expire'     => '691200'
        },
        'SOA parsed ok'
    );

    is_deeply(
        $zf->a,
        [{
                'ttl'   => '',
                'name'  => '@',
                'class' => 'IN',
                'host'  => '127.0.0.1'
            },
            {
                'ttl'   => '',
                'name'  => 'localhost',
                'class' => 'IN',
                'host'  => '127.0.0.1'
            },
            {
                'ttl'   => '',
                'name'  => 'mail',
                'class' => 'IN',
                'host'  => '127.0.0.1'
            },
            {
                'ttl'   => '',
                'name'  => 'www',
                'class' => 'IN',
                'host'  => '127.0.0.1'
            },
            {
                'ttl'   => '',
                'name'  => 'www',
                'class' => 'IN',
                'host'  => '10.0.0.2'
            },
            {
                'ttl'   => '43200',
                'name'  => 'www',
                'class' => 'IN',
                'host'  => '10.0.0.3'
            },
            {
                'ttl'   => '',
                'name'  => 'www',
                'class' => '',
                'host'  => '10.0.0.5'
            },
            {
                'ttl'   => '',
                'name'  => 'foo',
                'class' => 'IN',
                'host'  => '10.0.0.6'
            },
            {
                'ttl'   => '',
                'name'  => 'mini',
                'class' => '',
                'host'  => '10.0.0.7'
            },
        ],
        'A records parsed OK'
    );

    is_deeply(
        $zf->ns,
        [{
                'ttl'   => '43200',
                'name'  => '@',
                'class' => 'IN',
                'host'  => 'ns0.dns-zoneparse-test.net.'
            },
            {
                'ttl'   => '',
                'name'  => '@',
                'class' => 'IN',
                'host'  => 'ns1.dns-zoneparse-test.net.'
            }
        ],
        'NS records parsed OK'
    );

    is_deeply(
        $zf->mx,
        [{
                'priority' => '10',
                'ttl'      => '',
                'name'     => '@',
                'class'    => 'IN',
                'host'     => 'mail'
            },
            {
                'priority' => '10',
                'ttl'      => '',
                'name'     => 'www',
                'class'    => 'IN',
                'host'     => '10.0.0.4'
            },
        ],
        'MX records parsed OK'
    );

    is_deeply(
        $zf->cname,
        [{
                'ttl'   => '',
                'name'  => 'ftp',
                'class' => 'IN',
                'host'  => 'www'
            },
            {
                'ttl'   => '',
                'name'  => '-=+!@#$%^&*`~://+-,[]{}|\\?~`\'";',
                'class' => '',
                'host'  => 'ns0.dns-zoneparse-test.net.'
            },
        ],
        'CNAME records parsed OK'
    );

    is_deeply(
        $zf->txt,
        [{
                'text'  => 'web server',
                'ttl'   => '',
                'name'  => 'www',
                'class' => ''
            },
            {
                'text'  => 'This is a text message',
                'ttl'   => '',
                'name'  => 'soup',
                'class' => 'IN'
            },
            {
                'text'  => 'This is another text message',
                'ttl'   => '',
                'name'  => 'txta',
                'class' => ''
            },
            {
                'text'  => 'I\'ve"got\\back\\"slashes;!',
                'ttl'   => '',
                'name'  => 'txttest1',
                'class' => ''
            },
            {
                'text'  => 'embedded"quote',
                'ttl'   => '',
                'name'  => 'txttest2',
                'class' => ''
            },
            {
                'text'  => 'noquotes',
                'ttl'   => '',
                'name'  => 'txttest3',
                'class' => ''
            },
            {
                'text'  => 'MORE (complicated) stuff -h343-',
                'ttl'   => '',
                'name'  => 'txttest4',
                'class' => ''
            },
        ],
        'TXT records parsed OK'
    );

    is_deeply(
        $zf->aaaa,
        [{
                'host'  => 'fe80::0260:83ff:fe7c:3a2a',
                'ttl'   => '',
                'name'  => 'icarus',
                'class' => 'IN'
            }
        ],
        'AAAA records parsed OK'
    );

    is_deeply(
        $zf->rp,
        [{
                'name'  => 'txta',
                'class' => '',
                'ttl'   => '',
                'mbox'  => 'mbox',
                'text'  => 'sometext',
            },
        ],
        'RP records parsed OK'
    );

    is_deeply(
        $zf->srv,
        [{
                'name'  => 'srvtest.a',
                'class' => 'IN',
                'ttl'   => '',
                'priority' => 11,
                'weight'   => 22,
                'port'     => 33,
                'host'     => 'avalidname',
            },
        ],
        'SRV records parsed OK'
    );

    is_deeply(
        $zf->loc,
        [{
              'name' => 'borrowed.from.rfc.1876.com.',
              'ttl' => '',
              'class' => '',
              'd1' => '42',
              'm1' => '21',
              's1' => '54',
              'NorS' => 'N',
              'd2' => '71',
              'm2' => '06',
              's2' => '18',
              'EorW' => 'W',
              'alt' => '-24m',
              'siz' => '30m',
              'hp' => '',
              'vp' => '',
            },
            {
              'name' => 'borrowed2.from.rfc.1876.com.',
              'ttl' => '',
              'class' => '',
              'd1' => '42',
              'm1' => '21',
              's1' => '43.952',
              'NorS' => 'N',
              'd2' => '71',
              'm2' => '5',
              's2' => '6.344',
              'EorW' => 'W',
              'alt' => '-24m',
              'siz' => '1m',
              'hp' => '200m',
              'vp' => '',
            },
            {
              'name' => 'borrowed3.from.rfc.1876.com.',
              'ttl' => '',
              'class' => '',
              'd1' => '52',
              'm1' => '14',
              's1' => '05',
              'NorS' => 'N',
              'd2' => '00',
              'm2' => '08',
              's2' => '50',
              'EorW' => 'E',
              'alt' => '10m',
              'siz' => '',
              'hp' => '',
              'vp' => '',
            },
            {
              'name' => 'borrowed4.from.rfc.1876.com.',
              'ttl' => '',
              'class' => '',
              'd1' => '32',
              'm1' => '7',
              's1' => '19',
              'NorS' => 'S',
              'd2' => '116',
              'm2' => '2',
              's2' => '25',
              'EorW' => 'E',
              'alt' => '10m',
              'siz' => '',
              'hp' => '',
              'vp' => '',
            },
            {
              'name' => 'borrowed5.from.rfc.1876.com.',
              'ttl' => '',
              'class' => '',
              'd1' => '42',
              'm1' => '21',
              's1' => '28.764',
              'NorS' => 'N',
              'd2' => '71',
              'm2' => '00',
              's2' => '51.617',
              'EorW' => 'W',
              'alt' => '-44m',
              'siz' => '2000m',
              'hp' => '',
              'vp' => '',
            },
            {
              'name' => 'notborrowed.from.rfc.1876.com.',
              'ttl' => '',
              'class' => '',
              'd1' => '32',
              'm1' => '7',
              's1' => '',
              'NorS' => 'S',
              'd2' => '116',
              'm2' => '',
              's2' => '',
              'EorW' => 'E',
              'alt' => '-15m',
              'siz' => '16m',
              'hp' => '17m',
              'vp' => '18m',
            },
        ],
        'LOC records parsed OK'
    );

    is_deeply(
        $zf->hinfo,
        [{
                'name'  => 'icarus',
                'class' => '',
                'ttl'   => '',
                'cpu'   => 'server',
                'os'    => 'freebsd',
            },
            {
                'name'  => 'soup',
                'class' => '',
                'ttl'   => '86401',
                'cpu'   => 'server',
                'os'    => 'freebsd',
            },

            {
                name  => 'commenttest0',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest1',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest2',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest3',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest4',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest5',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest6',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest7',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest8',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest9',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest10',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest11',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest12',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest13',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest14',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest15',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'test2',
            },
            {
                name  => 'commenttest16',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'tes;t2',
            },
            {
                name  => 'commenttest17',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'tes;t2',
            },
            {
                name  => 'commenttest18',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'tes;t2',
            },
            {
                name  => 'commenttest19',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'tes;t2',
            },
            {
                name  => 'commenttest20',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'tes;t2',
            },
            {
                name  => 'commenttest21',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'tes;t2',
            },
            {
                name  => 'commenttest22',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'tes;t2',
            },
            {
                name  => 'commenttest23',
                class => '',
                ttl   => '',
                cpu   => 'test',
                os    => 'tes;t2',
            },
            {
                name  => 'commenttest24',
                class => '',
                ttl   => '',
                cpu   => 'te;st',
                os    => 'test2',
            },
            {
                name  => 'commenttest25',
                class => '',
                ttl   => '',
                cpu   => 'te;st',
                os    => 'test2',
            },
            {
                name  => 'commenttest26',
                class => '',
                ttl   => '',
                cpu   => 'te;st',
                os    => 'test2',
            },
            {
                name  => 'commenttest27',
                class => '',
                ttl   => '',
                cpu   => 'te;st',
                os    => 'test2',
            },
            {
                name  => 'commenttest28',
                class => '',
                ttl   => '',
                cpu   => 'te;st',
                os    => 'test2',
            },
            {
                name  => 'commenttest29',
                class => '',
                ttl   => '',
                cpu   => 'te;st',
                os    => 'test2',
            },
            {
                name  => 'commenttest30',
                class => '',
                ttl   => '',
                cpu   => 'te;st',
                os    => 'test2',
            },
            {
                name  => 'commenttest31',
                class => '',
                ttl   => '',
                cpu   => 'te;st',
                os    => 'test2',
            },
            {
                name  => 'commenttest32',
                class => '',
                ttl   => '',
                cpu   => 'te;st',
                os    => 'te;st2',
            },
            {
                name  => 'commenttest33',
                class => '',
                ttl   => '',
                cpu   => 'te;st',
                os    => 'te;st2',
            },
            {
                name  => 'commenttest34',
                class => '',
                ttl   => '',
                cpu   => 'te;st',
                os    => 'te;st2',
            },
            {
                name  => 'commenttest35',
                class => '',
                ttl   => '',
                cpu   => 'te;st',
                os    => 'te;st2',
            },

        ],
        'HINFO records parsed OK'
    );

}
