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
##  
##  Takes two parameters:
##    1. The name of your specific mainlog.ec log file
##    2. The hostname (preferably FQDN) of the server that generated the log
##
##  This will output two files  
##    1. hostname.YYYYMMDDHHMMSS.csv.gz (send this to Return Path)
##    2. hostname.YYYYMMDDHHSS.mainexceptions.csv.gz
##  The second will capture any exceptions or lines not parsed from the 
##  mainlog.ec log file
##  Each line within the source file is represented in one or both of the 
##  files above.
##  Aggregation of the parsed content is completed on the Return Path side


use strict;
use warnings;
## You'll have to install the following modules if you don't already 
## have them.
use DateTime;
use IO::Compress::Gzip qw(gzip $GzipError);

##variables
my ($date,
    $domain,
    $ip,
    $attempted,
    $delivered,
    $rejected,
    $filtered,
    $unknown,
    $action,
    $line,
    $logfile,
    $hostname);

my $filedate=DateTime->now;

if ((exists $ARGV[0]) && (exists $ARGV[1])) {
  $logfile = $ARGV[0];
  $hostname = $ARGV[1];
}
else {
  die "usage: $0 <name of log file> <hostname of server>\n";
}

##Get time now for output file format
$filedate = $filedate->ymd('') . $filedate->hms('');

##create output fle name for parsed output
my $outfile = "$hostname.${filedate}_reject.csv";

## create output file name for exceptions log
my $exception = "$hostname.${filedate}_rejectexceptions.csv";

##open a file handle for the parsed reject output to go to
open (REJECT, ">$outfile") || die "can't open outfile for writing\n";

##open exception file handle
open (EXCEPTION,">$exception") || die "can't open exception log for writing\n";

open (FH, "<$logfile") || die "Can't open $logfile for reading\n";

##begin looping through source file line by line
while ($line = <FH>){
  chomp($line);
  $attempted=1;
  $delivered=0;
  $rejected=0;
  $filtered=0;
  $unknown=0;
  $domain="null";
  
  #pull the date string and properly format for RP
  if ($line =~ /^(\d+)\:\s/) {
    $date=$1;
    my $datetime=DateTime->from_epoch( epoch => $date );
              $date = $datetime->ymd . ' ' . $datetime->hms;
  } 
  else {
  ##IF date is not present in the source file, log exception and skip 
  ## to the next line
    print EXCEPTION "no date available \n$line\n";
    next;
  }

  ## Parse from domain where available
  if ($line =~ /mailfrom_domain=(\w[\w\.-]+)?,/i) {
    # If it's not defined, either it was rejected prior to MAIL FROM, or
    # the MAIL FROM was the NULL sender, <>
    if (defined($1)) {
      $domain = $1;
    }
  }

  ## Parse sending IP from source or log exception and skip
  if ($line =~ /R=\"(\d+.\d+.\d+.\d+):\d+\"/) {
    $ip = $1;
  }
  else {
    print EXCEPTION "no ip match\n$line\n";
    next;
  }  

  # we want date, domain,ip,attempted,delivered,rejected,filtered,unknown
  #
  # By definition, everything in this file is rejected, but the reason for
  # the rejection determines whether we count it as rejected or unknown.
  #
  # The reason is captured in an E=XXX field in the line; it seems that if
  # the field is "E=550" it's user unknown; otherwise, it's just rejected
  (($line =~ /E=550/) ? $unknown = 1 : $rejected = 1);
  
  print REJECT "$date,$domain,$ip,$attempted,$delivered,$rejected,$filtered,$unknown\n";    
}  
close REJECT;    
close EXCEPTION;
close FH;

gzip $outfile => "$outfile.gz"
  or die "gzip failed: $GzipError\n";

gzip $exception => "$exception.gz"
  or die "gzip failed: $GzipError\n";

# Since this gzip keeps the original file around...
unlink $outfile or warn "Could not unlink $outfile: $!\n";
unlink $exception or warn "Could not unlink $exception: $!\n";
