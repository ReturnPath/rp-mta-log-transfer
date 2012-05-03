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

##  This is a simple mailsystems reject.ec log file parser
##  This file is fairly generic however it will require tuning specific to your implimentation
##  Takes one argument that is the name of your specific reject.ec log
##  This will output two files  YYYYMMDDHHMMSS_reject.log (parsed file output to push to Return Path
##  and YYYYMMDDHHSS_exceptions.log
##  This will capture any exceptions or lines not parsed from the reject.ec log file
##  Each line within the source file is represented in one or both of the files above.
##  Aggregation of the parsed content is completed on the Return Path side


use strict;
use warnings;
use DateTime;


my $filedate = DateTime->now;

##Get time now for output file format
$filedate = $filedate->ymd('') . $filedate->hms('');

##create output fle name for parsed output
my $outfile = $filedate . "_reject.log";


## create output file name for excptions log
my $exception = $filedate . "_excptions.log";

##variables
my ( $date, $domain, $ip, $attempted, $delivered, $rejected, $filtered, $unknown, $action );

##open a file handle for the parsed reject output to go to
open( REJECT, ">$outfile" ) || die "can't open outfile";

##open exception file handle
open( EXCEPTION, ">$exception" ) || die "can't open exception log";


##begin looping through source file line by line
while (<>) {
    $attempted = 0;
    $delivered = 0;
    $rejected  = 0;
    $filtered  = 0;
    $unknown   = 0;
    my $line = $_;

    #pull the date string and properly format for RP
    if ( $line =~ /^(\d+)\:\s/ ) {
        $date = $1;
        my $datetime = DateTime->from_epoch( epoch => $date );
        $date = $datetime->ymd . ' ' . $datetime->hms;
    }
    else {
        ##IF date is not present in the source file, log exception and skip to the next line
        print EXCEPTION "no date available \n$line\n";
        next;
    }

    ## Parse from domain where available or set domain value to null
    if ( $line =~ /mailfrom_domain=([\w.]+),/i ) {
        $domain = $1;
    }
    else {
        $domain = 'null';
    }
    ## Parse sending domain from source or log exception and skip
    if ( $line =~ /R=\"(\d+.\d+.\d+.\d+):\d+\"/ ) {
        $ip = $1;
    }
    else {
        print EXCEPTION "no ip match\n$line\n";
        next;
    }

# we want date, domain,ip,attempted,delivered,rejected,filtered,unknown
# this section is written to be very verboxe but will require proper tuning for your specific platform

##First check for the sieve_final_action info and determine proper category for message
## either Rejected, unknown or filtered.
## not every source line contains this data
    if ( $line =~ /sieve_final_action=\"([\w+\s+:]+)"+/ ) {
        $action = $1;
        if ( $action =~ /DNS:Internal Error/i ) {
            $attempted = 1;
            $unknown   = 1;
        }
        elsif ( $action =~ /Drop Msg: Bad attachment/i ) {
            $attempted = 1;
            $rejected  = 1;
        }
        elsif ( $action =~ /Drop Msg: mailfrom Spoof/i ) {
            $attempted = 1;
            $filtered  = 1;
        }
        elsif ( $action =~ /Prefs::/ ) {
            $attempted = 1;
            $filtered  = 1;
        }
        elsif ( $action =~ /Rate Limit/i ) {
            $attempted = 1;
            $rejected  = 1;
        }
        elsif ( $action =~ /Discarded spam/i ) {
            $attempted = 1;
            $filtered  = 1;
        }
        else {

## by default, if the sieve_final_action tag is present but not categorized above
## we mark the record as attempted 1 and rejected 1
## comment out the followin print if you do not want to see this data printed to the exception file
            print EXCEPTION "final action categorized as rejected: $1\n";
            $attempted = 1;
            $rejected  = 1;
        }
## Generic rejection categorizations follow:

    }
    elsif ( $line =~ m/sieve_final_action=RBL:SBL-XBL/ ) {
        $action    = "SBL-XBL";
        $attempted = 1;
        $filtered  = 1;
    }
    elsif ( $line =~ m/syntax error/ ) {
        $action    = "syntax error";
        $attempted = 1;
        $rejected  = 1;
    }
    elsif ( $line =~ /RBL Restriction:/ ) {
        $action    = "RBL Restriction:";
        $attempted = 1;
        $filtered  = 1;
    }
    elsif ( $line =~ /]\s\d{3}.+PTR\sInvalid/ ) {
        $action    = "invalid ptr";
        $attempted = 1;
        $filtered  = 1;
    }
    elsif ( $line =~ /]\s\d{3}.+IP\sreputation\serror/ ) {
        $action    = "bad reputation";
        $attempted = 1;
        $filtered  = 1;
    }
    elsif ( $line =~ /]\s\d{3}\sSMTP\serror/i ) {
        $action    = "smtp error";
        $attempted = 1;
        $rejected  = 1;
    }
    elsif ( $line =~ /]\s\d{3}.+unrecognized\scommand/i ) {
        $action    = "unrecognized command";
        $attempted = 1;
        $rejected  = 1;
    }
    elsif ( $line =~ /]\srelaying\sdenied/i ) {
        $action    = "relaying_denied";
        $attempted = 1;
        $rejected  = 1;
    }
    elsif ( $line =~ /]\s\d{3}.+Lone\sCR\sor\sLF\sin\sheaders/i ) {
        $action    = "bad header";
        $attempted = 1;
        $rejected  = 1;
    }
    elsif ( $line =~ /]\s\d{3}.+Invalid\sheader\sfound/i ) {
        $action    = "bad_header";
        $attempted = 1;
        $rejected  = 1;

    }
    elsif ( $line =~ /]\s\d{3}.+discarded\sby\spolicy/ ) {
        $action    = "policy discard";
        $attempted = 1;
        $filtered  = 1;
    }
    else {
##  Default categorization based on nature of the reject log itself... by default call it rejected
##  Comment the print stmt below if you do not want this data printed to the exception file
        print EXCEPTION "Default action, setting as rejected\n$line\n";
        $attempted = 1;
        $rejected  = 1;
    }
    print REJECT "$date,$domain,$ip,$attempted,$delivered,$rejected,$filtered,$unknown\n";
}
close REJECT;

#time is time from epoch first field split
#domain is CTXMESS=[mailfrom_domain=" "
#ip is R="10.79.25.142:42601" strip off port
# attempted will be aggregated by IP at the end.
#rejected +1 for E=550
#error message is the last field
# we want date, domain,ip,attempted,delivered,rejected,filtered,unknown
## we want 2009-03-22 00:30:33,creiu.com,110.37.11.11,5,0,5,0,0
