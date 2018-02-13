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
# Parser for Postfix logs that will output two data files for 
# consumption by Return Path.  Requires perl version 5.8.8 or later, plus the 
# Date::Manip::DM5, IO::Compress::Gzip, and Net::CIDR::Lite modules.
#
# Usage:
# ./postfixParser.pl [-r] [-x exclude_file] -l logfile -h hostname 
#
# Command-line parameters:
#   -r - an optional parameter to indicate that the log file contains 
#        timestamps that were generated by rsyslog.  If not present, 
#        parser defauls to a date format generated by syslog.
#
#   -x exclude_file - an optional parameter to indicate a filename that
#                     contains a list of CIDR ranges (one per line) of 
#                     connecting IPs that should be ignored during processing.
#                     The ranges 10/8, 172.16/12, and 192.168/16 will always
#                     be excluded.
#
#   -l logfile - REQUIRED - the name of the logfile to be parsed
#
#   -h hostname - REQUIRED - the hostname of a server that generated the
#                            logfile.  If more than one server contributed
#                            to the log, you can use any value here; this
#                            parameter will be part of the output filename.
#
#
# Resulting output will be two files.
#
# File 1, a volume data file, will be named ${hostname}.${fileDate}.csv
# where hostname is the name of the Ironport server (ideally, the second
# parameter passed to this program) and fileDate is derived from the time 
# the parser is run.  This file will be a CSV file, and will meet the 
# following specifications:
#
# A CSV file with the following columns, in the following order, of aggregated
# results from incoming SMTP connections
# 
# Date/Time
# 	
#   YYYY-­‐MM-­‐DDTHH:MM:SSZ (UTC timestamp)
# 
#   The date/time field is a UTC-­‐formatted timestamp from time-zone of the 
#   MTA server sending the data, representing the start of the aggregation 
#   timeframe based on the source email message received date.
# 
# From: Domain
# 	
#   SMTP Domain Received appearing in the mail “envelope” from of the source 
#   email message. Null (if Rejected)
# 
# Source IP
# 	
#   XXX.XXX.XXX.XXX (IP address)
# 
#   The dotted‐quad IPv4 IP address which connected to the receiving MTA in 
#   order to deliver the source email message or messages.
#  
# Total Attempted
# 
#   Total number of recipients in transaction (sum of all the following 
#   elements)
# 
# Delivered
# 	
#   SMTP 250, accepted by the gateway MTA and handed off to the next process
# 
# Rejected
# 
#   5xx, decision made prior to .DATA portion (non-511)
# 
# Filtered
# 	
#   5xx, content based (non-511)
# 
# Unknown Users
# 	
#   511
# 
# Sample
# 
# 2009-03-22 00:30:33,creiu.com,110.37.11.11,5,0,5,0,0
# 2009-03-22 00:30:33,veccia.com,110.37.17.7,6,0,3,0,3
# 2009-03-22 00:30:33,runningwiththebulls.com,110.37.21.115,6,0,5,0,1
# 2009-03-22 00:30:33,dameindistress.com,110.37.26.191,6,0,6,0,0
# 2009-03-22 00:30:33,frecuentame.com,110.37.46.151,6,0,6,0,0
# 2009-03-22 00:30:33,viaenovae.com,110.37.47.228,6,0,5,0,1 
#
# File 2, an authentication data file, will be named 
# ${hostname}_auth.${fileDate}.csv where hostname is the name of the Ironport
# server (ideally, the second parameter passed to this progam) and fileDate 
# is derived from the time the parser is run.  This file will be a 
# tab-separated file, and will meet the following specifications:
#
# A file containing tab-delimited records with the following columns, in 
# the following order, of aggregated results from incoming SMTP connections
#
# date/time               YYYY-MM-DDTHH:MM:SSZ (UTC timestamp)
#   The date/time field is a UTC-formatted timestamp from the  timezone of 
#   the MTA server sending the data, representing the start of the aggregation 
#   timeframe based on the source email message received date.
# 
# source_ip               XXX.XXX.XXX.XXX (IP address)
#   The dotted-quad IPv4 IP address which connected to the receiving MTA in 
#   order to deliver the source email message or messages.
# 
# header_from_domain*               From: domain  
#   From: domain as it appears in the header of the source email message. 
#   (“Percent” encoded, length limited)
# 
# mail_from_domain*               SMTP domain received
#   Domain appearing in the mail “envelope” from of the source email message. 
#   (“Percent” encoded, length limited)
# 
# dkim_selector*               s= (RFC 4871)
#   The s= “selector” value from the source message DKIM header as defined in 
#   RFC 4871. (“Percent” encoded, length limited)
# 
# dkim_identity               i= (RFC 4871)
#   The i= “identity” value from the source message DKIM header as defined in 
#   RFC 4871. (“Percent” encoded, length limited)
# 
# dkim_canonicalization*               c= (RFC 4871)
#   The c= “canonicalization” value from the source message DKIM header as 
#   defined in RFC 4871. (“Percent” encoded, length limited)
# 
# dkim_domain*               d= (RFC 4871)
#   The d= “domain” value from the source message DKIM header as defined in 
#   RFC 4871. (“Percent” encoded, length limited)
# 
# dkim_result*                   string result of check  
#   Frequent results of the DKIM result may include “Pass”,  “Neutral”, 
#   “Fail”, “Error”, or the reason for the error. (“Percent” encoded, length 
#   limited)
# 
# dkim_pass_fail               valid results = 0 (fail), 1 (pass), null
#   DKIM validation results:
#   A result of “0” means the message received a “fail” result.
#   A result of “1” means the message received a “pass” result.
#   A result of “null” means the message was not observed to have a DKIM 
#   signature.
# 
# spf_result*               string result of check
#   Frequent results of the SPF result may include “Pass”, “Neutral”, “Fail”, 
#   “Error”, or the reason for the error. (“Percent” encoded, length limited)
# 
# spf_pass_fail               valid results = 0 (fail), 1 (pass), null
#   SPF validation results:
#   A result of “0” means the message received a “fail” result.
#   A result of “1” means the message received a “pass” result.
#   A result of “null” means the message was not observed to have an SPF record.
# 
# auth_policy_result               valid results = 0 (fail), 1 (pass), null
#   A result of “0” means the message was NOT blocked for authentication 
#   reasons. A result of “1” means the message was blocked for one or more 
#   authentication reasons, including being on the authentication policy 
#   registry. A result of “null” means no information was available about 
#   message disposition.
# 
# count               # (number of identical authentication attempts/results)
#   The number of observed identical authentication attempts or results, 
#   observed within the timeframe of the data chunk. Data should be a whole 
#   positive integer.
# 
# Example Aggregated Authentication data record:
# 
# timestamp=2010-01-22T11:00:59Z
# source_ip=1.1.1.1
# header_from_domain=example.com              
# smtp_mail_from=eng.example.com              
# dkim_selector=jun2005.eng              
# dkim_identity=user@eng.example.com              
# dkim_canonicalization=relaxed/simple              
# dkim_domain=example.com
# dkim_result=Bad signature
# dkim_pass_fail=0
# spf_result=pass              
# spf_pass_fail=1
# auth_policy_result=null
#        count=42 
#
#
# Notes About The Input File...
#
# At the time of this writing (June, 2012), we have no log samples from 
# customers doing authentication checks, so we can only do volume data
# outputs.
#
# Logs will be interleaved; the message ID is the atomic unit.
#
# For example:
#
# Jun 14 16:55:02 smta1 postfix/smtpd[8002]: 4AB51E00008A: 
#   client=mail-qc0-f175.google.com[209.85.216.175]
# Jun 14 16:55:02 smta1 postfix/cleanup[7156]: 4AB51E00008A: 
#   message-id=
#   <CAGQzBoLCP-4W0c1RQSY62GW4YLzsLV-5yh2BEBjbCG+--oy+6g@mail.gmail.com>
# Jun 14 16:55:02 smta1 postfix/cleanup[7156]: 4AB51E00008A: warning: header 
#   To: mail@sanghioverseas.com from mail-qc0-f175.google.com[209.85.216.175]; 
#   from=<rkgchd27@gmail.com> to=<mail@sanghioverseas.com> proto=ESMTP 
#   helo=<mail-qc0-f175.google.com>
# Jun 14 16:55:02 smta1 postfix/qmgr[30762]: 4AB51E00008A: 
#   from=<rkgchd27@gmail.com>, size=11973, nrcpt=1 (queue active)
# Jun 14 16:55:02 smta1 postfix/smtp[7684]: 4AB51E00008A: 
#   to=<mail@sanghioverseas.com>, relay=202.162.242.137[202.162.242.137]:25, 
#   conn_use=4, delay=0.34, delays=0.08/0/0/0.26, dsn=2.0.0, 
#   status=sent (250 2.0.0 secure6.netcore.co.in Ok: queued as 62D606381C3)
# Jun 14 16:55:02 smta1 postfix/qmgr[30762]: 4AB51E00008A: removed
#
# We'll know we're done with a message when we see the MID followed by 
# the word 'removed'.
#
# Connections that get rejected get logged a bit differently, but we know 
# how to handle them, too.

use warnings;
use strict;
use Getopt::Std;
use Date::Manip::DM5;
use Net::CIDR::Lite;
use IO::Compress::Gzip qw(gzip $GzipError);

Date_Init("ConvTZ=GMT");

my %opts = (r => 0);
my %mids = ();
my $exclude_ranges = Net::CIDR::Lite->new;
my $fileDate = UnixDate("today", "%Y%m%d%H%M%S");

my $volFile;
# my $authFile;

# First is normal syslog; second is rsyslog
my @dateRegex =
   (qr/\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}/,
    qr/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}-\d{2}:\d{2}/);

getopts('rx:l:h:', \%opts);

sub setupExcludeRanges () {
  # We always add RFC 1918 addresses
  #$exclude_ranges->add('10.0.0.0/8');
  #$exclude_ranges->add('172.16.0.0/12');
  #$exclude_ranges->add('192.168.0.0/16');

  if (defined($opts{x})) {
    open (FH, "<$opts{x}") or die "Can't open $opts{x} for reading\n";
    while (<FH>) {
      chomp;
      $exclude_ranges->add($_);
    }
  }
}


sub parseTimestamp ($;$) {
  # Goal is YYYY‐MM‐DD HH:MM:SSZ, per this:
  # Sample
  # 
  # 2009-03-22 00:30:33,creiu.com,110.37.11.11,5,0,5,0,0
  my $mid = shift;
  my $timestamp = shift;
  my $parsedDate = ParseDateString($timestamp);
  # $parsedDate is now YYYYMMDDHHMMSS
  # ParseDateString takes care of the pesky math to do timezone manipulation
  # (with the help of the Date_Init call above) but we still have to re-format
  # the timestamp to what we want 
  $parsedDate =~ s/(\d{4})(\d{2})(\d{2})(\d{2}:\d{2}:\d{2})/$1-$2-$3 $4Z/;
  $mids{$mid}->{timestamp} = $parsedDate;
}

sub printAndDeleteRecord ($) {
  # keeps the hash from getting too big
  my $mid = shift;
  # Only print if we got the whole record and it's an external layer
  # log line
  if ((exists($mids{$mid}->{timestamp})) &&
      (exists($mids{$mid}->{sourceIP})) &&
      ($mids{$mid}->{attempted} > 0) &&
      ($mids{$mid}->{attempted} == ($mids{$mid}->{delivered} +
                                    $mids{$mid}->{rejected} +
                                    $mids{$mid}->{filtered} +
                                    $mids{$mid}->{unknown})) &&
      (!$exclude_ranges->find($mids{$mid}->{sourceIP}))) {
    print VOLUME "$mids{$mid}->{timestamp},$mids{$mid}->{fromDomain},$mids{$mid}->{sourceIP},$mids{$mid}->{attempted},$mids{$mid}->{delivered},$mids{$mid}->{rejected},$mids{$mid}->{filtered},$mids{$mid}->{unknown}\n";
  }
  delete $mids{$mid};
}

setupExcludeRanges();

if (defined($opts{h})) {
  $volFile = "${opts{h}}.${fileDate}.csv";
  # If we ever get authentication data...
  # $authFile = "${opts{h}}_auth.${fileDate}.csv";
  open (VOLUME, ">$volFile") || die "Can't open $volFile for writing\n";
}
else {
  die "usage: $0 [-r] [-x exclude_file] -l logfile -h hostname\n";
}

if (defined($opts{l})) {
  open (FH, "<$opts{l}") || die "Can't open $opts{l} for reading\n";
}
else {
  die "usage: $0 [-r] [-x exclude_file] -l logfile -h hostname\n";
}

while (<FH>) {
  chomp;
  # Get the client IP and timestamp from the connection open line
  # Initialize everything else
  if (/($dateRegex[$opts{r}])\s.*tutadb-prod\/smtpd\[\d*\]:\s(\w*):\sclient=.*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/) {
    my $ts = $1;
    my $mid = $2;
    $mids{$mid}->{sourceIP} = $3;

    parseTimestamp($mid, $ts);
    $mids{$mid}->{fromDomain} = "null";
    $mids{$mid}->{attempted} = 0;
    $mids{$mid}->{delivered} = 0;
    $mids{$mid}->{rejected} = 0;
    $mids{$mid}->{filtered} = 0;
    $mids{$mid}->{unknown} = 0;
  }
  # Get the From Domain and Number Attempted
  elsif (/tutadb-prod\/qmgr\[\d+\]:\s(\w+):\sfrom=<(.*)>,\s.*,\snrcpt=(\d*)/) {
    my $mid = $1;
    my $from = $2;
    $mids{$mid}->{attempted} = $3;
    # For non-null senders...
    if ($from =~ /\@/) {
      my ($lhs, $rhs) = split /\@/, $from;
      $mids{$mid}->{fromDomain} = $rhs;
    }
  }
  # Get the Delivered Number
  elsif (/tutadb-prod\/smtp\[\d+\]:\s(\w+):\sto=<.*@.*>/) {
    my $mid = $1;
    $mids{$mid}->{attempted} += 1;
    $mids{$mid}->{delivered} += 1;
  }
  # Any user unknowns?
  elsif (/tutadb-prod\/bounce\[\d+\]:\s(\w+):/) {
    my $mid = $1;
    $mids{$mid}->{unknown} += 1;
  }
  # Or we're at the end of the line for this message
  elsif (/tutadb-prod\/qmgr\[\d+\]:\s(\w+):\sremoved/) {
    my $mid = $1;
    #print "End: ($mid)\n";
    printAndDeleteRecord ($mid);
  }
  # Self-contained log entries
  elsif (/($dateRegex[$opts{r}])\s.*tutadb-prod\/smtp\[\d+\]:\s\w+:\shost\s(.*)\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\ssaid:\s452\s4\.3\.1\sInsufficient system resources/) {
    # TODO: Is this type of entry important?
    my $mid = 0;
    my $ts = $1;
    $mids{$mid}->{sourceIP} = $3;
    $mids{$mid}->{fromDomain} = $2;
    $mids{$mid}->{attempted} = 1;
    $mids{$mid}->{delivered} = 0;
    $mids{$mid}->{rejected} = 0;
    $mids{$mid}->{filtered} = 0;
    $mids{$mid}->{unknown} = 1;
    parseTimestamp($mid,$ts);
    printAndDeleteRecord ($mid);
  }
  elsif (/($dateRegex[$opts{r}])\s.*tutadb-prod\/smtpd\[\d*\]:\s\w*:\sreject:\sRCPT from.*?\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]:\s550\s5\.1\.1.*<(.+)>/) {
    my $mid = 0;
    my $ts = $1;
    $mids{$mid}->{sourceIP} = $2;
    my $from = $3;
    my ($lhs, $rhs) = split /\@/, $from;
    $mids{$mid}->{fromDomain} = $rhs;
    $mids{$mid}->{attempted} = 1;
    $mids{$mid}->{delivered} = 0;
    $mids{$mid}->{rejected} = 1;
    $mids{$mid}->{filtered} = 0;
    $mids{$mid}->{unknown} = 0;
    parseTimestamp($mid,$ts);
    printAndDeleteRecord ($mid);
  }
  # Or we can process rejections, like these:
  #
  # 2012-06-06T04:05:43-04:00 dpmx10 postfix/smtpd[31046]: NOQUEUE: reject: 
  #  RCPT from unknown[190.146.22.64]: 554 5.7.1 Service unavailable; Client 
  #  host [190.146.22.64] blocked using b.barracudacentral.org; 
  #  http://www.barracudanetworks.com/reputation/?pr=1&ip=190.146.22.64; 
  #  from=<xyhsxu@ocbp.com> to=<hshipping@pretiumpkg.com> proto=ESMTP 
  #  helo=<Static-IP-cr1901462264.cable.net.co>
  #
  # 2012-06-06T04:05:43-04:00 dpmx09 postfix/smtpd[11158]: NOQUEUE: reject: 
  #  RCPT from 81.203.11.65.dyn.user.ono.com[81.203.11.65]: 554 5.7.1 
  #  <ramseyf@bg.fraserpapers.com>: Relay access denied; 
  #  from=<bcypert@zaobao.com> to=<ramseyf@bg.fraserpapers.com> proto=SMTP 
  #  helo=<81.203.11.65.dyn.user.ono.com>
  #
  elsif (/($dateRegex[$opts{r}])\s.*tutadb-prod\/smtpd\[\d*\]:\s\w*:\sreject:\sRCPT\sfrom\s.*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]:\s.*from=<(.*@.*)>$/) {
    my $mid = 0;
    my $ts = $1;
    $mids{$mid}->{sourceIP} = $2;
    my $from = $3;
    my ($lhs, $rhs) = split /\@/, $from;
    $mids{$mid}->{fromDomain} = $rhs;
    parseTimestamp($mid, $ts);
    $mids{$mid}->{attempted} = 1;
    $mids{$mid}->{delivered} = 0;
    $mids{$mid}->{rejected} = 1;
    $mids{$mid}->{filtered} = 0;
    $mids{$mid}->{unknown} = 0;
    printAndDeleteRecord ($mid);
  }
}
close (FH);
close (VOLUME);

gzip $volFile => "$volFile.gz"
  or die "gzip failed: $GzipError\n";

# Since this gzip keeps the original file around...
unlink $volFile or warn "Could not unlink $volFile: $!\n";

# Do same for auth data file if we ever get auth data

