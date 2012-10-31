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

##  This is a simple eCelerity mainlog.ec log file parser.
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

use warnings;
use strict;
## You'll have to install the following modules if you don't already 
## have them.
use DateTime;
use Data::Dumper;
use IO::Compress::Gzip qw(gzip $GzipError);

##variables
my ($date,$mid,$msg);
my %msg;
my ($logfile, $hostname);

if ((exists $ARGV[0]) && (exists $ARGV[1])) {
  $logfile = $ARGV[0];
  $hostname = $ARGV[1];
}
else {
  die "usage: $0 <name of log file> <hostname of server>\n";
}
  
my $filedate=DateTime->now;

##Get time now for output file format
$filedate = $filedate->ymd('') . $filedate->hms('');

##create output fle name for parsed output
my $outfile = "$hostname.$filedate.csv";

## create output file name for exceptions log
my $exception = "$hostname.$filedate.mainexceptions.csv";

##open a file handle for the parsed reject output to go to
open (MAIN, ">$outfile") || die "can't open outfile for writing\n";

##open exception file handle

open (EXCEPTION,">$exception") || die "can't open exception log for writing\n";

open (FH, "<$logfile") || die "Can't open $logfile for reading\n";

##begin looping through source file line by line
## @ delimited file.  0 is date, Field 3 D=Delivered T=Transient error P=Perm Fail
## if field 3=R than field 6 is domain field 7 is ip address
## if field 3=D than message was delivered, if 3=T transient failure, if 3=P than perm failure 
## and field 11 indicates reason
while (<FH>) {
  chomp;
  my @line=split('\@',$_);  
  #pulls the received line and corresponding Message ID, domain, IP
  if ($line[2] eq 'R') {
    $mid=$line[1];
    $msg{$mid}{ip}=$line[7];
    if (defined $line[6]) {
      $msg{$mid}{domain}=$line[6];
    } 
    else {
    ## domain isn't necessary for us to count the record.  If it dosn't exist in the record
    ## we define as ''
      $msg{$mid}{domain}='';
    }
  } 
  ## D is successful delivery
  elsif($line[2] eq 'D') {
    $mid=$line[1];
    if (defined $msg{$mid} && defined $msg{$mid}{ip}) {
      $date=$line[0];
      my $datetime=DateTime->from_epoch( epoch => $date );
                $date = $datetime->ymd . ' ' . $datetime->hms;
    ## print line indicating successful delivery
      print MAIN "$date,$msg{$mid}{domain},$msg{$mid}{ip},1,1,0,0,0\n";
      delete $msg{$mid};
    }
  } 
  elsif ($line[2] eq 'T') {
    $mid=$line[1];
    if (defined $msg{$mid} && defined $msg{$mid}{ip}) {
      $date=$line[0];
      my $datetime=DateTime->from_epoch( epoch => $date );
      $date = $datetime->ymd . ' ' . $datetime->hms;
    ## print line indicating transient error    
      print MAIN "$date,$msg{$mid}{domain},$msg{$mid}{ip},1,0,1,0,0\n";
      delete $msg{$mid};
    }
  } 
  elsif ($line[2] eq 'P') {
    $mid=$line[1];
    if (defined $msg{$mid} && defined $msg{$mid}{ip}) {
      $date=$line[0];
      my $datetime=DateTime->from_epoch( epoch => $date );
      $date = $datetime->ymd . ' ' . $datetime->hms;
    ## print line indicating permenent error, categorize as unknown user
      print MAIN "$date,$msg{$mid}{domain},$msg{$mid}{'ip'},1,0,0,0,1\n";
    }
  } 
  elsif ($line[2] =~ 'M') {
    ## It's a heartbeat line, and can be ignored
    ;;
  }
  else {
    ## Print out lines that indicate an exception (no R, P, D, or T)
    ## comment out this line if you would rather not have this data printed to 
    ## Exceptions
    print EXCEPTION $_;
  }
}  
    
## This prints left over data to the exeption files.  These records would 
## include a Recept code but not a cooresponding delivery / failure 
## notification.  
## comment out to not print this file
print EXCEPTION "The following records did not contain a delivery or failure indication:\n";
for my $key (keys %msg) {
  print EXCEPTION "$key,$msg{$key}{domain},$msg{$key}{ip}\n";
}
close EXCEPTION;
close MAIN;    
close FH;

gzip $outfile => "$outfile.gz"
  or die "gzip failed: $GzipError\n";

gzip $exception => "$exception.gz"
  or die "gzip failed: $GzipError\n";

# Since this gzip keeps the original file around...
unlink $outfile or warn "Could not unlink $outfile: $!\n";
unlink $exception or warn "Could not unlink $exception: $!\n";


