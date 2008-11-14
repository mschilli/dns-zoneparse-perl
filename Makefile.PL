use 5.005;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'DNS::ZoneParse',
    'VERSION_FROM'	=> 'lib/DNS/ZoneParse.pm', # finds $VERSION
    'PREREQ_PM'		=> {
                         Storable     => 0.407,
                         'Test::More' => 0.31,
                        },
    'ABSTRACT_FROM' => 'lib/DNS/ZoneParse.pm',
    'AUTHOR' => 'Simon Flack (perl@simonflack.com)',
);
