#!/usr/bin/perl

# Copyright (c) 2012 Return Path, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

#
# A log parser for the Exim mail server logs
#

use strict;
use warnings;
use POSIX;
use Fcntl;

my $me    = "maillog-parser";
my $debug = "0";

## No need for editing pass this line ##
my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst );

sub get_timestamp {
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);
    $mon++;
    if ( $mon < 10 )  { $mon  = "0$mon"; }
    if ( $mday < 10 ) { $mday = "0$mday"; }
    if ( $hour < 10 ) { $hour = "0$hour"; }
    if ( $min < 10 )  { $min  = "0$min"; }
    if ( $sec < 10 )  { $sec  = "0$sec"; }
    $year = $year + 1900;

    return ' ' . $year . '-' . $mon . '-' . $mday . ' ' . $hour . ':' . $min . ':' . $sec;
}

sub print_log {
    print get_timestamp() . " ($$) [$me] " . $_[0] . "\n";
}

##### Unbuffer all the outputs
select STDERR;
$| = 1;
select STDOUT;
$| = 1;
local $| = 1;

print_log("Debug mode is enabled.") if ($debug);
print_log("Starting...");

$SIG{INT} = $SIG{TERM} = $SIG{USR1} = $SIG{USR2} = $SIG{HUP} = \&signal_handler;
$SIG{__WARN__} = sub {
    &print_log( "WARN - NOTE! " . join( " ", @_ ) );
};
$SIG{__DIE__} = sub {
    my $err = join( " ", @_ );
    if ( $err eq "alarm\n" ) {
        die @_;
    }
    else {
        &print_log( "DIE - FATAL! " . join( " ", @_ ) );
        print_log("Cleaning up before shutting down...");
        close STDIN;
        close STDERR;
        print_log("Shutting down due to die...");
        close STDOUT;
        exit(255);
    }
};

sub signal_handler {
    print_log("Caught signal. Shut down scheduled...");
    exit(1);
}

my %clients = ();

while (<>) {

    # ********************* Start of regex to do stats *********************
    ### MAIL FROM Phase ###

    #2009-05-29 00:19:26 H=[10.0.0.2]:3932 I=[10.0.0.1]:25 rejected MAIL <nationgem1@example.net>: NO HELO OR EHLO
    if (/^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*rejected MAIL \<.*@(\S+)\>.*NO HELO OR EHLO/) {
        print_log("$1:$2:$3 -- NO HELO OR EHLO") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "1", "0", "0" );
    }

    ### RCPT Phase ####

    #2009-05-29 10:03:28 H=mx1.example.net [10.0.0.2]:13432 I=[10.0.0.1]:25 F=<> rejected RCPT <brett@example.net>: Only one
    # receipient accepted for NULL sender
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<\>.*rejected RCPT(.+).*Only one receipient accepted for NULL sender/
      ) {
        print_log("$1:$2::$3 -- Only one receipient accepted for NULL sender") if ( $debug > 1 );
        &Track( "$1", "", "$2", "1", "0", "1", "0", "0" );
    }

    #2009-05-29 01:28:56 H=fallbackmx08.example.net [10.0.0.2]:37604 I=[10.0.0.1]:25 F=<sammuelagent@example.net> rejected
    # RCPT <richard@example.net>: SPAM BLOCK: RBL-ANTISPAM - bl.example.net
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\>.*rejected RCPT(.+).*SPAM BLOCK: RBL-ANTISPAM - .*/
      ) {
        print_log("$1:$2:$3:$4 -- SPAM BLOCK: RBL-ANTISPAM") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "1", "0", "0" );
    }

    #2009-05-29 00:01:12 H=(XL249865560643) [10.0.0.2]:8325 I=[10.0.0.1]:25 F=<alababelden@example.net> rejected
    # RCPT <praneeta@example.net>: "Invalid domain or IP given in HELO/EHLO"
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\>.*rejected RCPT(.+).*Invalid domain or IP given in HELO\/EHLO/
      ) {
        print_log("$1:$2:$3:$4 -- Invalid domain or IP given in HELO") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "1", "0", "0" );
    }

    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F=<>.*rejected RCPT(.+).*Invalid domain or IP given in HELO\/EHLO/
      ) {
        print_log("$1:$2:$3 -- Invalid domain or IP given in HELO") if ( $debug > 1 );
        &Track( "$1", "", "$2", "1", "0", "1", "0", "0" );
    }

    #2009-05-29 00:02:28 H=(10.0.0.3) [10.0.0.2]:3992 I=[10.0.0.1]:25 F=<fkidqbrmmg@k3912jdhyf34j.example.net> rejected RCPT <ey@sn.example.net>: HELO of bare IP: 10.0.0.2
    #2009-05-29 00:03:08 H=(10.0.0.3) [10.0.0.3]:2760 I=[10.0.0.1]:25 F=<qemlkru@example.net> rejected RCPT <qemllkhwlrz@example.net>: HELO of bare IP: 10.0.0.3
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\>.*rejected RCPT(.+).*HELO of bare IP.*/
      ) {
        print_log("$1:$2:$3:$4 -- HELO of bare IP") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "1", "0", "0" );
    }

    #2009-05-29 01:32:22 H=10-0-0-2-snnd-esr-1.dynamic.example.net (sn.notvalid.net) [10.0.0.2]:2199 I=[10.0.0.1]:25
    # F=<noreply@sn.notvalid.net> rejected RCPT <napwadir@sn.notvalid.net>: HELO of systems hostname: sn.notvalid.net
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\>.*rejected RCPT(.+).*HELO of systems hostname.*/
      ) {
        print_log("$1:$2:$3:$4 -- HELO of systems hostname") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "1", "0", "0" );
    }

    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<\>.*rejected RCPT(.+).*HELO of systems hostname.*/
      ) {
        print_log("$1:$2:$3 -- HELO of systems hostname") if ( $debug > 1 );
        &Track( "$1", "", "$2", "1", "0", "1", "0", "0" );
    }

    #2009-05-29 08:50:42 1M9vvN-000Jzs-L7 virusstats 10.0.0.2::20090529065042Z:noreply@example.net
    # :autumnstar@example.net:Phishing.Heuristics.Email.SpoofedDomain
    elsif (/^(\S+ \S+).*virusstats (\d+\.\d+.\d+.\d+):.+:.*@(\S+):(\S+):/) {
        print_log("$1:$2:$3:$4 -- Virus Stats") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "0", "1", "0" );
    }

    elsif (/^(\S+ \S+).*virusstats (\d+\.\d+.\d+.\d+):.+::(\S+):/) {
        print_log("$1:$2:$3 -- Virus Stats") if ( $debug > 1 );
        &Track( "$1", "", "$2", "1", "0", "0", "1", "0" );
    }

    #2009-05-29 18:29:11 H=adsl-10-0-0-2.dsl.lsan03.example.net [10.0.0.2]:1905
    #  I=[10.0.0.1]:25 F=<diordyh@example.net> rejected RCPT <pcmorris@example.net>: rejected
    #  (sender: diordyh@example.net) because 10.0.0.2 is in a black list at bl.example.net
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<(\S+)\>.*rejected RCPT(.+): rejected.*is in a black list at.*/
      ) {
        print_log("$1:$2:$3:$4 -- Black listed") if ( $debug > 1 );
        my ( $local_part, $domain ) = split( "@", $3, 2 );
        &Track( "$1", "$domain", "$2", "1", "0", "1", "0", "0" );
    }

    #2009-05-29 18:29:12 H=10-0-0-2.dial-up.example.net [10.0.0.2]:4336 I=[10.0.0.1]:25
    #  F=<AlbertaKincaid@example.net> rejected RCPT <daryl@example.net>: Sender verify failed
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\>.*rejected RCPT(.+).*Sender verify failed/
      ) {
        print_log("$1:$2:$3:$4 -- Sender verify failed") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "1", "0", "0" );
    }

    # Unroutable address
    #2009-05-29 18:25:33 H=smtp03.example.net [10.0.0.2]:55714 I=[10.0.0.1]:25 F=<> rejected RCPT
    # <vgkc@example.net>: Unrouteable address
    #2009-05-29 18:26:47 H=10-0-0-2.ip.example.net [10.0.0.2]:54901 I=[10.0.0.1]:25
    # F=<collection@example.net> rejected RCPT <collection@example.net>: Unrouteable address
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<(\S+)\>.*rejected RCPT(.+).*Unrouteable address/)
    {
        print_log("$1:$2:$3:$4 -- Unroutable address") if ( $debug > 1 );
        my ( $local_part, $domain ) = split( "@", $3, 2 );
        &Track( "$1", "$domain", "$2", "1", "0", "0", "0", "1" );
    }

    elsif (/^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<\>.*rejected RCPT(.+).*Unrouteable address/) {
        print_log("$1:$2:$3 -- Bounce - Unroutable address") if ( $debug > 1 );
        &Track( "$1", "", "$2", "1", "0", "0", "0", "1" );
    }

    ### Data Phase ###

    #2009-05-29 01:03:14 1M9od0-000Jm6-EX H=mailgate01.example.net [10.0.0.2]:34934 I=[10.0.0.1]:25
    # F=<root@server19.example.net> rejected during MIME ACL checks: MIME ERROR: LONG BOUNDARY
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\> rejected during MIME ACL checks: MIME ERROR: LONG BOUNDARY/
      ) {
        print_log("$1:$2:$3 -- MIME ERROR: LONG BOUNDARY") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "0", "1", "0" );
    }

    #2009-05-29 07:49:36 1M9uyG-0009TU-5N H=relay01.example.net [10.0.0.2]:51863 I=[10.0.0.1]:25
    # F=<rgm_admin@example.net> rejected during MIME ACL checks: MIME ERROR: EMPTY BOUNDARY
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\> rejected during MIME ACL checks: MIME ERROR: EMPTY BOUNDARY/
      ) {
        print "$1:$2:$3 -- MIME ERROR: EMPTY BOUNDARY\n" if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "0", "1", "0" );
    }

    #2009-05-29 18:26:42 1MA4uo-000IcK-OY H=mailgate07.example.net [10.0.0.2]:1199 I=[10.0.0.1]:25
    # F=<karen@example.net> rejected during MIME ACL checks: MIME_ERROR : Proposed filename too long
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\> rejected during MIME ACL checks: MIME_ERROR : Proposed filename too long/
      ) {
        print_log("$1:$2:$3 -- MIME ERROR: Proposed filename too long") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "0", "1", "0" );
    }

    #2009-05-29 01:50:15 1M9pMV-000OOf-J5 H=dedi184.example.net [10.0.0.2]:38007 I=[10.0.0.1]:25
    # F=<info@example.net> rejected during MIME ACL checks: MIME_ERROR : Maximum line length exceeded
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\> rejected during MIME ACL checks: MIME_ERROR : Maximum line length exceeded/
      ) {
        print_log("$1:$2:$3 -- MIME ERROR: Maximum line length exceeded") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "0", "1", "0" );
    }

    #2009-05-29 05:28:51 1M9sm2-000JkN-Tw H=mail05.example.net [10.0.0.2]:3765 I=[10.0.0.1]:25
    # F=<jjanneker@example.net> rejected during MIME ACL checks: MIME ERROR: MESSAGE/PARTIAL MIME ENTITY
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\> rejected during MIME ACL checks: MIME ERROR: MESSAGE\/PARTIAL MIME ENTITY/
      ) {
        print "$1:$2:$3 -- MIME ERROR: MESSAGE/PARTIAL MIME ENTITY\n" if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "0", "1", "0" );
    }

    #2009-12-16 04:38:20 1NKjmL-000P6e-LY H=mail05.example.net [10.0.0.2]:62853 I=[10.0.0.1]:25
    # F=<jlerm@example.net> rejected during MIME ACL checks: MIME ERROR: TOO MANY PARTS
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\> rejected during MIME ACL checks: MIME ERROR: TOO MANY PARTS/
      ) {
        print "$1:$2:$3 -- MIME ERROR: TOO MANY PARTS\n" if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "0", "1", "0" );
    }

    #2009-05-29 09:19:52 1M9wNM-000PcR-B6 H=(psdn.example.net) [10.0.0.2]:4038 I=[10.0.0.1]:25
    # F=<mendoza@example.net> rejected after DATA: This message contains an unwanted file extension (blah).
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\> rejected after DATA: This message contains an unwanted file extension.*/
      ) {
        print_log("$1:$2:$3 -- This message contains an unwanted file extension") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "0", "1", "0" );
    }

    #2009-05-29 02:05:17 1M9pb3-000Pwj-29 H=10-0-0-2-blah-not.example.net (webmail.example.net) [10.0.0.2]:10255
    # I=[10.0.0.1]:25 F=<notice@example.net> rejected after DATA: This message contains malware (Email.Phishing.Bank-33)
    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\> rejected after DATA: This message contains malware.*/
      ) {
        print_log("$1:$2:$3 -- This message contains malware") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "0", "1", "0" );
    }

    elsif (
        /^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F=<> rejected after DATA: This message contains malware.*/
      ) {
        print_log("$1:$2 -- This message contains malware") if ( $debug > 1 );
        &Track( "$1", "", "$2", "1", "0", "0", "1", "0" );
    }

    # Accepted mails :)
    #2009-05-29 00:01:34 1M9nfJ-000DWQ-Rw <= smtp@example.net H=(example.net) [10.0.0.2]:36851
    # I=[10.0.0.1]:25 P=esmtp S=5273 T="Example Subject" from <smtp@example.net> for cargo@example.net
    #2009-05-29 00:01:07 1M9net-000DDS-DA <= <> H=mailgate04.example.net [10.0.0.2]:49623 I=[10.0.0.1]:25
    # P=esmtp S=2122 id=E1M9nee-0009lw-8e@smtp01.example.net T="Example Subject" from <> for ahsblah@example.net
    #if (/^(\S+ \S+).*<= (\S+) H\=.*\[(\d+\.\d+.\d+.\d+)\].*I\=.*from <(.+)> for/)
    elsif (/^(\S+ \S+).*<= (.+) H\=.*?\[(\d+\.\d+.\d+.\d+)\].*from <.*@(\S+)> for/) {
        print_log("$1:$2:$3:$4 -- Accepted") if ( $debug > 1 );
        my ( $local_part, $domain ) = split( '@', "$2", 2 );
        if ( !defined($domain) ) {
            my $domain = "";
        }
        &Track( "$1", "$4", "$3", "1", "1", "0", "0", "0" );
    }

    # Bounce mails
    elsif (/^(\S+ \S+).*<= <>.*?\[(\d+\.\d+.\d+.\d+)\].*from <> for/) {
        print_log("$1:$2 -- Bounce Accepted") if ( $debug > 1 );
        &Track( "$1", "", "$2", "1", "1", "0", "0", "0" );
    }

    ### Catch all for RCPT phase ###

    #2009-05-29 00:32:41 H=(13145509119.user.example.net) [10.0.0.2]:50433 I=[10.0.0.1]:25 F=<blah@example.net> rejected RCPT <|catchthismail@example.net>
    elsif (/^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F\=\<.*@(\S+)\> rejected RCPT \<(.+)\>/) {
        print_log("$1:$2:$3 -- rejected RCPT") if ( $debug > 1 );
        &Track( "$1", "$3", "$2", "1", "0", "1", "0", "0" );
    }

    elsif (/^(\S+ \S+).*?\[(\d+\.\d+.\d+.\d+)\].*F=<> rejected RCPT \<(.+)\>/) {
        print_log("$1:$2 -- rejected RCPT - Blank Sender") if ( $debug > 1 );
        &Track( "$1", "", "$2", "1", "0", "1", "0", "0" );
    }

    # Things we are ignorning
    elsif (/.*temporarily rejected.*/
        || /.*sender verify defer.*/
        || /.*no IP address found for host.*/
        || /.*Warning.*/
        || /.*Completed.*/
        || /.*incomplete transaction.*/
        || /.*no host name found for IP address.*/
        || /.*SMTP command timeout on connection from.*/
        || /.*unexpected disconnection while reading SMTP command from.*/
        || /.*SMTP protocol error in.*/
        || /^\S+ \S+.*=>.*F=<.*>.*R.*T.*/
        || /.*too many nonmail commands.*/
        || /.*retry timeout exceeded$/
        || /.*error ignored$/
        || /.*MTA-imposed quota exceeded while writing to.*/
        || /.*sender verify fail for.*/
        || /.*Operation timed out$/
        || /.*returning message to sender.*/
        || /.*message abandoned.*/
        || /.*SMTP error from remote mail server after.*/
        || /.*uuencoded line length.*/
        || /.*Unable to authenticate at present.*/
        || /.*lost while reading message data.*/
        || /.*Connection refused$/
        || /.*retry time not reached for any host$/
        || /.*retry time not reached$/
        || /.*Retry time not yet reached$/
        || /^\S+ \S+.*==.*/
        || /.*Start queue run.*/
        || /.*Frozen.*/
        || /^\S+ \S+.*\*\*.*/
        || /.*removed by root$/
        || /.*End queue run.*/
        || /.*SMTP protocol synchronization error.*/
        || /.*demime acl condition.*/
        || /.*syntactically invalid argument.*/
        || /.*Message is frozen$/
        || /.*closed connection in response to initial connection$/
        || /.*too many connections from that IP address$/
        || /.*No route to host$/
        || /.*SMTP syntax error in.*/
        || /.*Spool file is locked.*/
        || /.*Software caused connection abort$/
        || /.*closed connection in response to.*/
        || /.*message too big.*/
        || /.*SMTP connection lost after final dot.*/
        || /.*unqualified sender rejected.*/
        || /.*suspected mail loop.*/
        || /^\S+ \S+.*->.*/
        || /.*SMTP connection from.*/
        || /.*Connection reset by peer$/
        || /.*host name alias list truncated for.*/
        || /.*DNS list lookup defer.*/
        || /.*too many unrecognized commands.*/
        || /.*Broken pipe$/
        || /.*ignoring AUTH.*/
        || /.*unqualified recipient rejected.*/
        || /.*no immediate delivery: load average.*/
        || /.*unable to read from socket.*/
        || /.*authenticator failed for.*/
        || /.*temporarily refused connection from.*/ ) {
        print_log("IGNORED ENTRY --> $_") if ( $debug > 2 );
    }
    ## Did not get a match from a regex so we can print it out
    else {
        print_log("NO MATCH --> $_") if ( $debug > -1 );
    }
}

if ($debug) {

    #Insert test data if we in debug mode
    &Track( "1970-01-01 01:00:00", "dummy-debug.example.net", "10.0.0.1", "1", "1", "0", "0", "0" );
    &Track( "1970-01-01 00:00:00", "dummy-debug.example.net", "10.0.0.1", "1", "0", "1", "0", "0" );
    &Track( "1970-01-01 03:00:00", "dummy-debug.example.net", "10.0.0.1", "1", "0", "0", "1", "0" );
    &Track( "1970-01-01 02:00:00", "dummy-debug.example.net", "10.0.0.1", "1", "0", "0", "0", "1" );
}

&DumpStats;
print_log("Finished...");
exit(0);

sub Track {
    my ( $time, $domain, $ip, $total_attempted, $delivered_250, $rejected_before_data,
        $filtered_after_data, $unknow_users )
      = @_;
    my $err = 0;

    ### Add checks to make sure we get all the right values otherwise we should skip ###
    if ( $time !~ m/^(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)/ && $time !~ m/^(\d+)$/ ) {
        print_log("Time field invalid, bad datetime: line: $. '$time'");
        $err = 1;
    }

    if ( $domain !~ m/^[\w\d\.\-_]*\s*$/ ) {
        if ( $domain =~ m/^\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]$/ ) {
            print_log(
                "SKIPPING --> Domain field has got ip literal in it so skipping reporting this -> $. '$domain'"
            );
            return;
        }
        else {
            print_log("Domain field invalid, bad domain: line: $. '$domain'");
            $err = 1;
        }
    }

    if ( $ip !~ m/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ ) {
        print_log("IP field invalid, bad IP: line: $. '$ip'");
        $err = 1;
    }

    if ( $total_attempted !~ m/^\d*$/ ) {
        print_log("Total attempted field invalid, bad attempted: line: $. '$total_attempted'");
        $err = 1;
    }

    my $sum = ( $delivered_250 + $rejected_before_data + $filtered_after_data + $unknow_users );
    if ( $total_attempted != $sum ) {
        print_log(
            "Total attempted field invalid, bad attempted - isn't the sum of other fields: line: $. $total_attempted != $sum"
        );
        $err = 1;
    }

    if ( $delivered_250 !~ m/^\d*$/ ) {
        print_log("Delivered - 250 field invalid, bad delivered: line: $. '$delivered_250'");
        $err = 1;
    }

    if ( $rejected_before_data !~ m/^\d*$/ ) {
        print_log(
            "Rejected before data field invalid, bad rejected: line: $. '$rejected_before_data'\n");
        $err = 1;
    }

    if ( $filtered_after_data !~ m/^\d*$/ ) {
        print_log(
            "Filtered after data field invalid, bad filterd: line: $. '$filtered_after_data'");
        $err = 1;
    }

    if ( $unknow_users !~ m/^\d*$/ ) {
        print_log("Unknown User field invalid, bad unknown users: line: $. '$unknow_users'");
        $err = 1;
    }

    if ( $err == 1 ) {
        print_log(
            "We got given some bad data so to be safe we exitting. Most probably a bad regex or typo."
        );
        exit(2);
    }

    my $domip = lc("$domain:$ip");

    if ( !defined( $clients{$domip} ) ) {
        print_log("No log entry found for $domip pair, adding default values") if ($debug);
        $clients{$domip}->{'time'}                 = $time;
        $clients{$domip}->{'domain'}               = lc($domain);
        $clients{$domip}->{'ip'}                   = $ip;
        $clients{$domip}->{'total_attempted'}      = $total_attempted;
        $clients{$domip}->{'delivered_250'}        = $delivered_250;
        $clients{$domip}->{'rejected_before_data'} = $rejected_before_data;
        $clients{$domip}->{'filtered_after_data'}  = $filtered_after_data;
        $clients{$domip}->{'unknow_users'}         = $unknow_users;
    }
    else {
        $clients{$domip}->{'total_attempted'} =
          $clients{$domip}->{'total_attempted'} + $total_attempted;
        $clients{$domip}->{'delivered_250'} = $clients{$domip}->{'delivered_250'} + $delivered_250;
        $clients{$domip}->{'rejected_before_data'} =
          $clients{$domip}->{'rejected_before_data'} + $rejected_before_data;
        $clients{$domip}->{'filtered_after_data'} =
          $clients{$domip}->{'filtered_after_data'} + $filtered_after_data;
        $clients{$domip}->{'unknow_users'} = $clients{$domip}->{'unknow_users'} + $unknow_users;
    }
}

sub DumpStats {

    #Lets try dump the stats
    print_log("Dumping stats:");
    while ( my ( $cip, $ckeysh ) = each %clients ) {
        print $ckeysh->{'time'} . ","
          . $ckeysh->{'domain'} . ","
          . $ckeysh->{'ip'} . ","
          . $ckeysh->{'total_attempted'} . ","
          . $ckeysh->{'delivered_250'} . ","
          . $ckeysh->{'rejected_before_data'} . ","
          . $ckeysh->{'filtered_after_data'} . ","
          . $ckeysh->{'unknow_users'} . "\n";
    }
    print_log("End of dumping stats");
}
