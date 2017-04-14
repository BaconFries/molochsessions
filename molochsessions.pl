#!/usr/bin/perl
use strict;
use warnings;
use POSIX 'strftime';
use LWP::UserAgent;
use JSON;
use Data::Dumper;
use Getopt::Long;
use Date::Manip;
use URI::Escape;

my ( $expression, $verbose, $help, $start, $end, $j ) = "";
my $FORMAT   = "%Y-%m-%d %H:%M:%S";
my $count    = 100;
my $hours    = 1;
my $hostname = 'moloch.hostname:8005';
my $realm    = 'Moloch';
my $apiuser  = 'apiuser';
my $apipass  = 'apipass';
my $maxcount = 2000;

sub usage {
    my $message = $_[0];
    if ( defined $message && length $message ) {
        $message .= "\n"
          unless $message =~ /\n$/;
    }

    my $command = $0;
    $command =~ s#^.*/##;

    print STDERR (
        $message,
        "usage: $command\n"
          . "  -h ,--help\n"
          . "  -e <moloch search expresion> Examples: ip, ip.dst, ip.src\n"
          . "     All fields detailed here $hostname/help#fields\n"
          . "  -c <number of matched flows to display. max 2000>\n"
          . "  -v (verbose output)\n"
          . "  -start <start date or expression>\n"
          . "  -end <end date or expression>\n"
          . "  -hours <hours>\n"
          . "  -j (raw json output)\n" . "  \n"
    );
    die("\n");
}

GetOptions(
    "e=s"     => \$expression,
    "c=s"     => \$count,
    "v"       => \$verbose,
    "start=s" => \$start,
    "end=s"   => \$end,
    "hours=s" => \$hours,
    "j"       => \$j,
    "help"    => \$help,
    "h"       => \$help,
) or usage("Error in command line arguments\n");

usage("help") if $help;

if ($expression) {

    $expression = "&expression=" . uri_escape($expression);
}

my $time = "date=$hours&";
if ( $start && $end ) {
    my $s = UnixDate( $start, "%s" );
    my $e = UnixDate( $end,   "%s" );
    $time = "&startTime=$s&stopTime=$e&";
}
elsif ( $start && !$end ) {
    my $s = UnixDate( $start, "%s" );
    my $e = localtime(time);
    $time = "&startTime=$s&stopTime=$e&";
}

if ( $count > $maxcount ) {
    print "Count too high. setting to $maxcount\n";
    $count = $maxcount;
}

my $ua = LWP::UserAgent->new;
$ua->credentials( $hostname, $realm, $apiuser, $apipass);
my $response =
  $ua->get( 'http://'
      . $hostname
      . '/sessions.json?'
      . $time
      . 'bounding=first&iDisplayLength='
      . $count
      . '&fields=fp,lp,sl,ss,ipSrc,tipv61-term,p1,as1,ipDst,tipv62-term,p2,as2,prot-term,by,by1,by2,ta,tcpflags.syn,tcpflags.syn-ack,tcpflags.ack,tcpflags.psh,tcpflags.fin,tcpflags.urg,tcpflags.rst,vlan,fb1,fb2,user'
      . $expression );
$response->is_success or die $response->status_line;
my $output = $response->decoded_content;

if ($j) {
    print $output;
    exit;
}
my $json = decode_json($output);

foreach my $session ( @{ $json->{data} } ) {
    printf "Start: %s End: %s %-15s %-5d => %-15s %-5d %s\n",
      strftime( $FORMAT, localtime $session->{fp} ),
      strftime( $FORMAT, localtime $session->{lp} ), $session->{ipSrc},
      $session->{p1}, $session->{ipDst}, $session->{p2},
      join( ',', @{ $session->{'prot-term'} } );
    if ($verbose) {
        printf "\tASN: %s => %s\n", $session->{as1} || "n/a",
          $session->{as2} || "none"
          if ( $session->{as1} || $session->{as2} );
        print "\tTags: " . join( ',', @{ $session->{ta} } ) . "\n";
        print "\tTCP Flags: "
          . join( ',',
            map { "$_=$session->{tcpflags}->{$_}" }
              keys %{ $session->{tcpflags} } )
          . "\n"
          if ( $session->{tcpflags} );
    }
}