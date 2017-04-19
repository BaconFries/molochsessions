#!/usr/bin/perl
use strict;
use warnings;
use LWP::UserAgent;
use JSON;
use Data::Dumper;
use Getopt::Long;
use URI::Escape;

my ( $expression, $verbose, $help, $start, $end, $j ) = "";
my $maxsec   = 86400;
my $sec      = 3600;
my $minudpc  = 5;
my $hostname = 'localhost:9200';
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
          . "  -s <seconds 86400max>\n"
          . "  -m <minimum unique dest port count>\n"
          . "  -v (verbose output)\n"
          . "  -j (raw json output)\n" . "  \n"
    );
    die("\n");
}

GetOptions(
    "v"    => \$verbose,
    "s=s"  => \$sec,
    "m=s"  => \$minudpc,
    "j"    => \$j,
    "help" => \$help,
    "h"    => \$help,
) or usage("Error in command line arguments\n");

usage("help") if $help;

if ( $sec > $maxsec ) {
    print "Seconds too high. setting to $maxsec\n";
    $sec = $maxsec;
}

my $query = '{"size":0,"query":{"bool":{"must":[{"match":{"tcpflags.fin":0}},{"range":{"tcpflags.syn":{"gte":"1"}}},{"range":{"firstPacket":{"gte":"now-'.$sec.'s"}}}]}},"aggs":{"ipSrc":{"terms":{"field":"ipSrc"},"aggs":{"ipDst":{"terms":{"field":"ipDst","order":{"unique_port_count":"desc"}},"aggs":{"unique_port_count":{"cardinality":{"field":"p2"}}}}}}}}';


my $ua = LWP::UserAgent->new;
my $req = HTTP::Request->new(GET => 'http://' . $hostname. '/sessions*/_aliases');
my $response = $ua->request($req);
$response->is_success or die $response->status_line;
my $indices = decode_json($response->decoded_content);
my $index = (reverse sort keys %{$indices})[0];

$req = HTTP::Request->new(GET => 'http://' . $hostname. '/' . $index . '/_search');
$req->header( 'Content-Type' => 'application/json' );
$req->content( $query );
$response = $ua->request($req);

$response->is_success or die $response->status_line;
my $output = $response->decoded_content;

if ($j) {
    print $output;
    exit;
}
my $json = decode_json($output);

#print Dumper $json;

my $buckets = $json->{'aggregations'}->{'ipSrc'}->{'buckets'};
foreach my $obj (@{$buckets}) {
  my $ipSrc = $obj->{'key'};
  my $buckets = $obj->{'ipDst'}->{'buckets'};
  foreach my $obj (@{$buckets}) {
    if ( $obj->{'unique_port_count'}->{'value'} > $minudpc ) {
printf "ip.src == %15s && ip.dst == %15s %15d\n", $ipSrc, $obj->{'key'}, $obj->{'unique_port_count'}->{'value'};
    }
  }
}