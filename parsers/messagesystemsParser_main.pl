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

##  This is a simple mailsystems mainlog.ec log file parser it is meant to be light weight and portible
##  This file is fairly generic however it will require tuning specific to your implimentation
##  Takes one argument that is the name of your specific mainlog.ec log file
##  This will output two files  YYYYMMDDHHMMSS_main.log (parsed file output to push to Return Path
##  and YYYYMMDDHHSS_mainexceptions.log
##  This will capture any exceptions or lines not parsed from the mainlog.ec log file
##  Each line within the source file is represented in one or both of the files above.
##  Aggregation of the parsed content is completed on the Return Path side


use strict;
use DateTime;
use Data::Dumper;


my $filedate = DateTime->now;

##Get time now for output file format
$filedate = $filedate->ymd('') . $filedate->hms('');

##create output fle name for parsed output
my $outfile = $filedate . "_main.log";


## create output file name for excptions log
my $exception = $filedate . "_mainexcptions.log";

##variables
my ( $date, $delid, $msg, $mid );
my %msg;
##open a file handle for the parsed reject output to go to
open( MAIN, ">$outfile" ) || die "can't open outfile";

##open exception file handle

open( EXCEPTION, ">$exception" ) || die "can't open exception log";


##begin looping through source file line by line
## @ delimited file.  0 is date, Field 3 D=Delivered T=Transcient error P=Perm Fail
## if field 3=R than field 6 is domain field 7 is ip address
## if field 3=D than message was delivered, if 3=T transcient failure, if 3=P than perm failure
## and field 11 indicates reason
while (<>) {
    my @line = split( '\@', $_ );

    #pulls the received line and corresponding Message ID, domain, IP
    if ( $line[2] eq 'R' ) {
        $mid = $line[1];
        $msg{$mid}{ip} = $line[7];
        if ( defined $line[6] ) {
            $msg{$mid}{domain} = $line[6];
        }
        else {
            ## domain isn't necessary for us to count the record.  If it dosn't exist in the record
            ## we define as ''
            $msg{$mid}{domain} = '';
        }
        ## D is successful delivery
    }
    elsif ( $line[2] eq 'D' ) {
        $delid = $line[1];
        if ( defined $msg{$delid} && defined $msg{$delid}{ip} ) {
            $date = $line[0];
            my $datetime = DateTime->from_epoch( epoch => $date );
            $date = $datetime->ymd . ' ' . $datetime->hms;
            ## print line indicating successful delivery
            print MAIN "$date,$msg{$delid}{domain},$msg{$delid}{ip},1,1,0,0,0\n";
            delete $msg{$delid};
        }
    }
    elsif ( $line[2] eq 'T' ) {
        $delid = $line[1];
        if ( defined $msg{$delid} && defined $msg{$delid}{ip} ) {
            $date = $line[0];
            my $datetime = DateTime->from_epoch( epoch => $date );
            $date = $datetime->ymd . ' ' . $datetime->hms;
            ## print line indicating transcient error
            print MAIN "$date,$msg{$delid}{domain},$msg{$delid}{ip},1,0,1,0,0\n";
            delete $msg{$delid};
        }
    }
    elsif ( $line[2] eq 'P' ) {
        $delid = $line[1];
        if ( defined $msg{$delid} && defined $msg{$delid}{ip} ) {
            $date = $line[0];
            my $datetime = DateTime->from_epoch( epoch => $date );
            $date = $datetime->ymd . ' ' . $datetime->hms;
            ## print line indicating permenent error, categorize as unknown user
            print MAIN "$date,$msg{$delid}{domain},$msg{$delid}{'ip'},1,0,0,0,1\n";
        }
    }
    else {
        ## Print out lines that indicate an exception (no R, P, D, or T)
        ## These lines would indicate heartbeat or messages or other code
        ## comment out this line if you would rather not have this data printed to Exceptions
        print EXCEPTION $_;
    }

}
## This prints left over data to the exeption files.  These records would include a Recept code
## but not a cooresponding delivery / failure notification.
## comment out to not print this file
print EXCEPTION "The following records did not contain a delivery or failure indication:\n";
for my $key ( keys %msg ) {
    print EXCEPTION "$key,$msg{$key}{domain},$msg{key}{ip}\n";
}
close EXCEPTION;
close MAIN;

