#!/usr/bin/perl
#
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
# Parser for Ironport logs that will output two data files for consumption
# by Return Path.  Requires perl version 5.8.8 or later, plus the 
# Date::Manip::DM5 and Net::CIDR::Lite modules.
#
# Usage:
# ./ironportParser.pl [-x exclude_file ] -l logfile -h hostname
#
# Command-line parameters:
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
#   YYYY-­-MM-­-DDTHH:MM:SSZ (UTC timestamp)
# 
#   The date/time field is a UTC-­-formatted timestamp from time-zone of the 
#   MTA server sending the data, representing the start of the aggregation 
#   timeframe based on the source email message received date.
# 
# From: Domain
# 	
#   SMTP Domain Received appearing in the mail "envelope" from of the source 
#   email message. Null (if Rejected)
# 
# Source IP
# 	
#   XXX.XXX.XXX.XXX (IP address)
# 
#   The dotted-quad IPv4 IP address which connected to the receiving MTA in 
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
#   ("Percent" encoded, length limited)
# 
# mail_from_domain*               SMTP domain received
#   Domain appearing in the mail "envelope" from of the source email message. 
#   ("Percent" encoded, length limited)
# 
# dkim_selector*               s= (RFC 4871)
#   The s= "selector" value from the source message DKIM header as defined in 
#   RFC 4871. ("Percent" encoded, length limited)
# 
# dkim_identity               i= (RFC 4871)
#   The i= "identity" value from the source message DKIM header as defined in 
#   RFC 4871. ("Percent" encoded, length limited)
# 
# dkim_canonicalization*               c= (RFC 4871)
#   The c= "canonicalization" value from the source message DKIM header as 
#   defined in RFC 4871. ("Percent" encoded, length limited)
# 
# dkim_domain*               d= (RFC 4871)
#   The d= "domain" value from the source message DKIM header as defined in 
#   RFC 4871. ("Percent" encoded, length limited)
# 
# dkim_result*                   string result of check  
#   Frequent results of the DKIM result may include "Pass",  "Neutral", 
#   "Fail", "Error", or the reason for the error. ("Percent" encoded, length 
#   limited)
# 
# dkim_pass_fail               valid results = 0 (fail), 1 (pass), null
#   DKIM validation results:
#   A result of "0" means the message received a "fail" result.
#   A result of "1" means the message received a "pass" result.
#   A result of "null" means the message was not observed to have a DKIM 
#   signature.
# 
# spf_result*               string result of check
#   Frequent results of the SPF result may include "Pass", "Neutral", "Fail", 
#   "Error", or the reason for the error. ("Percent" encoded, length limited)
# 
# spf_pass_fail               valid results = 0 (fail), 1 (pass), null
#   SPF validation results:
#   A result of "0" means the message received a "fail" result.
#   A result of "1" means the message received a "pass" result.
#   A result of "null" means the message was not observed to have an SPF record.
# 
# auth_policy_result               valid results = 0 (fail), 1 (pass), null
#   A result of "0" means the message was NOT blocked for authentication 
#   reasons. A result of "1" means the message was blocked for one or more 
#   authentication reasons, including being on the authentication policy 
#   registry. A result of "null" means no information was available about 
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
# The Input File...
#
# An Ironport log will have information about a given connection, its messages,
# and the recipients for those messages interleaved in the log file with 
# similar information about other connections and messages.  Fortunately, there
# are tokens in each log line that will assist the creator in writing an 
# effective parser.
# 
# Connections - Each inbound connection will be identified by its Inbound 
# Connection ID number, as illustrated in the following line from an accepted 
# connection:
# 
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: New SMTP 
#  ICID 2106327026 interface LdapInbound (10.65.240.57) address 205.188.105.144
#   reverse dns host imr-da02.mx.aol.com verified yes
# 
# The above line tells us that the host 'mx07.lnh.mail.rcn.net' received a 
# connection at 'Oct 19 06:33:29 2011' from IP address 205.188.105.144, reverse
# DNS of 'imr-da02.mx.aol.com', and assigned the Inbound Connection ID (ICID) 
# number of 2106327026 to that connection.
# 
# Whether the connection is accepted or rejected is logged on separate lines:
# 
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: ICID 2106327026
#   ACCEPT SG GOOD match 205.188.105.0/24
# 
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: ICID 2106327021 
#   REJECT SG TCP-REFUSE match
# 
# The interesting bits in these lines, other than the obvious ACCEPT and REJECT
# tokens, are the ones starting with the 'SG' token.  SG stands for 'Sender 
# Group', and it's just the nomenclature used for sets of policies or rules.  
# While such data is not necessarily of interest to us at Return Path, it 
# might be interesting to our partners.
# 
# The closing of a connection is also logged:
# 
# Oct 19 06:33:30 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: ICID 2106327026
#   close
# 
# Messages - Each accepted connection can result in one or more attempts by the
# sending server at transmitting a message.  Each message will be assigned its 
# own Message ID, and that MID will initially be logged with its corresponding 
# ICID:
# 
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: Start MID 
#   1416566008 ICID 2106327026
# 
# The above line tells us that we're at the beginning of log information about 
# MID 1416566008, part of ICID 2106327026
# 
# The sender on each message will be the next piece of information logged about
# that message, e.g.,
# 
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: MID 1416566008 
#  ICID 2106327026 From: <semoon@aol.com>
# 
# And then there will be one line for each recipient for the message:
# 
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: MID 1416566008 
#  ICID 2106327026 RID 0 To: <salpukas@rcn.com>
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: MID 1416566008 
#  ICID 2106327026 RID 1 To: <jdphillips@rcn.com>
# 
# The Recipient ID numbers will be assigned sequentially, starting at 0 for 
# each message.
# 
# After the last Recipient line, other information about the message will be 
# logged; this information may or may not vary from provider to provider, and 
# may be of little interest to Return Path:
# 
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: MID 1416566008 
#  Message-ID '<8CE5C6197A1A643-176C-B77@webmail-d065.sysops.aol.com>'
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: MID 1416566008 
#  Subject 'Soccer- Wednesday Evening 5:30 PM at Diamond'
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: MID 1416566008 
#  ready 6911 bytes from <semoon@aol.com>
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: MID 1416566008 
#  matched all recipients for per-recipient policy DEFAULT in the inbound table
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: MID 1416566008 
#  queued for delivery
# 
# Ironports do not typically have local storage for messages; instead, they 
# pass their accepted messages off to another layer in the infrastructure; 
# this handoff is identified by Delivery Connection IDs (DCID):
# 
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: Delivery start 
#  DCID 126723200 MID 1416566008 to RID [0, 1, 2, 3, 4, 5]
# 
# Just like with ICIDs, DCIDs can be responsible for transmitting multiple 
# messages, and the MID will be the key to sussing out information for each 
# unique message.
# 
# Nominally, a DCID transaction will just look like this:
# 
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: Message done 
#   DCID 126723200 MID 1416566008 to RID [0, 1, 2, 3, 4, 5] [('subject', 
#   'Soccer- Wednesday Evening 5:30 PM at Diamond'), ('from', 'semoon@aol.com')]
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: MID 1416566008 
#   RID  [0, 1, 2, 3, 4, 5] Response 'CRR09734 Message accepted for delivery'
# Oct 19 06:33:29 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: Message 
#   finished MID 1416566008 done
# 
# 
# However, if the message is DKIM-signed, one piece of information that we may 
# find useful will be authentication information, which will also be logged in 
# the DCID transaction information, like this:
# 
# Oct 19 06:33:28 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: MID 1416566000 
#   DKIM: pass signature verified [TEST] (d=sbcglobal.net s=s1024 
#   i=@sbcglobal.net)
# Oct 19 06:33:30 2011 mx07.lnh.mail.rcn.net syslog_mail: Info: Message done 
#   DCID 126723200 MID 1416566000 to RID [0] [('dkim-signature', 'v=1; 
#   a=rsa-sha256; c=relaxed/relaxed; d=sbcglobal.net; s=s1024; t=1319020398; 
#   bh=2zS0OWmSNxLrK6WFuauTY92h6b9Ayiz/q1sC4IUfalo=; h=X-YMail-OSG:Received:
#   X-Mailer:References:Message-ID:Date:From:Reply-To:Subject:To:In-Reply-To:
#   MIME-Version:Content-Type; b=cphx68J3ohdvtoX/2/gIGRV6ll23x+bXJQPh5rmK4YYW73
#   yTRABJtWcX0OihhOtpriOhu0F7RC1gJL5Z38s4ElU9aoKyMxk058kxap0VlzRSaW4XR2Lqgav7B
#   qM+ZOXK5WnCAm9M7B39rvZqcB3K1IIG4sYEx6opVdzDVMFxDCg='), ('from', 'dave 
#   nieder <midnightrider319@sbcglobal.net>'), ('subject', 'Fw: Fwd: A class 
#   act by Canadians, Tribute!')]
# 
# Note that the validation information may very well be logged before the DKIM 
# signature information, not after.

use warnings;
use strict;
use Getopt::Std;
use Date::Manip::DM5 qw(UnixDate);
use Net::CIDR::Lite;

my %opts = ();
my $exclude_ranges = Net::CIDR::Lite->new;

# Number of lines to process before clearing the hash - set this lower if you
# experience memory/swapping issues, but keep as high as possible to prevent
# loss of data.
my $line_threshold = 10000000;

# Some global variables..
# To track Source IPs
my %icids = ();
# This hash will track all the data necessary for the DX Data Inputs file
my %mids = ();
# hash for mapping SPF results to SPF pass fail codes
my %spfs = (
  Pass => 1,
  None => "null",
  Neutral => "null",
  Fail => 0,
  SoftFail => 0,
  TempError => 0,
  PermError => 0);
  
# For reporting rejected connections;
my $rejectedConnx = 1;
# Input filename
my $logfile;
# For output filenames
my $hostname;
my $volDataFileName;
my $authDataFileName;
# UnixDate from Date::Manip package; we'll use this as part of the 
# name of the files to be uploaded
my $fileDate = UnixDate("today", "%Y%m%d%H%M%S");

printf "%d/%d %d:%02d:%02u\n", (localtime(time))[4,3,2,1,0];

my $year = &UnixDate("today","%Y");

my %monthmap = (
  Jan => '01',
  Feb => '02',
  Mar => '03',
  Apr => '04',
  May => '05',
  Jun => '06',
  Jul => '07',
  Aug => '08',
  Sep => '09',
  Oct => '10',
  Nov => '11',
  Dec => '12' );

sub setupExcludeRanges () {
  # We always add RFC 1918 addresses
  $exclude_ranges->add('10.0.0.0/8');
  $exclude_ranges->add('172.16.0.0/12');
  $exclude_ranges->add('192.168.0.0/16');

  if (defined($opts{x})) {
    open (FH, "<$opts{x}") or die "Can't open $opts{x} for reading\n";
    while (<FH>) {
      chomp;
      $exclude_ranges->add($_);
    }
  }
}

sub parseDate {
  my $timestamp = shift;
  my ($mo, $dy, $hr, $mi, $se, $yr) = $timestamp =~ /(\w+)\s+(\d{1,2})\s(\d\d):(\d\d):(\d\d)\s(\d{4})/;
  if (! defined $yr || $yr < 1900) {
    $yr = $year;
  }
  $mo = $monthmap{$mo};
  if ($dy < 10) {
    $dy = "0$dy";
  }
  return ($yr, $mo, $dy, $hr, $mi, $se);
}


# Write out the data we have accumulated so far in the %mids hash. After calling
# this method, we must clear the %mids hash before continuing to process the logs
# or we will write duplicate data. It is not necessary to clear the %icids hash.
sub write_output() {

  open (VOLUME, ">>$volDataFileName") || 
    die "can't open $volDataFileName for writing\n";

  open (AUTHDATA, ">>$authDataFileName") || 
    die "can't open $authDataFileName for writing\n";
  foreach my $key (keys %mids) {

# Due to log rollovers, we won't have much useful info for some 
# messages, so we'll just punt them.
    if ((exists($mids{$key}->{timestamp})) && 
        ($mids{$key}->{ip} ne "0.0.0.0") &&
        ($mids{$key}->{attempted} > 0) &&
        (!$exclude_ranges->find($mids{$key}->{ip})))  {
      my ($y, $m, $d, $h, $min, $s) = parseDate($mids{$key}->{timestamp});
      my $volDate = "$y-$m-$d $h:$min:$s";
      print VOLUME "$volDate,$mids{$key}->{mail_from_domain},$mids{$key}->{ip},$mids{$key}->{attempted},$mids{$key}->{delivered},$mids{$key}->{rejected},$mids{$key}->{filtered},$mids{$key}->{unknown}\n";

      if (($mids{$key}->{header_from_domain} ne "null") ||
          ($mids{$key}->{mail_from_domain} ne "null")) {
        my $authDate = "$y-$m-${d}T$h:$min:${s}Z";
        print AUTHDATA "timestamp=$authDate\tsource_ip=$mids{$key}->{ip}\theader_from_domain=$mids{$key}->{header_from_domain}\tsmtp_mail_from=$mids{$key}->{mail_from_domain}\tdkim_selector=$mids{$key}->{dkim_selector}\tdkim_identity=$mids{$key}->{dkim_identity}\tdkim_canonicalization=$mids{$key}->{dkim_canonicalization}\tdkim_domain=$mids{$key}->{dkim_domain}\tdkim_result=$mids{$key}->{dkim_result}\tdkim_pass_fail=$mids{$key}->{dkim_pass_fail}\tspf_result=$mids{$key}->{spf_result}\tspf_pass_fail=$mids{$key}->{spf_pass_fail}\tauth_policy_result=$mids{$key}->{auth_policy_result}\tcount=$mids{$key}->{dkim_count}\n\n";
      }
    }

  }

  close (VOLUME);
  close (AUTHDATA);
}

# does what it says
sub parse_dkim_signature ($;$) {
  my $mid = shift;
  my $sig = shift;

  # Parse the interesting bits out of $sig, which will look something 
  # like this:
  # v=1; q=dns/txt; a=rsa-sha256; c=relaxed/relaxed; s=27747; 
  # d=louiesrestaurant.ccsend.com; 
  # h=to:subject:mime-version:message-id:from:date:sender:list-unsubscribe:
  # reply-to; bh=b+H5hJn6ilDEAcrVDhs2eqCBdOTtLYUMHk/2s13jJVk=; 
  # b=ECs4r9LkMG6GIfr0+Kqg0pRBT5zx2e9JscQMLvGdMDoC8L92xYCsqrZR3Pfx1GH1NDmh9h
  # Awgl0FUTGS2H4x3g==##

  # We want to populate the following:
  #   - $mids{$mid}->{dkim_selector} (s=)
  #   - $mids{$mid}->{dkim_canonicalization} (c=)
  #   - $mids{$mid}->{dkim_domain} (d=)
  #   - $mids{$mid}->{dkim_identity} (i=)

  # A note about the linenoise looking patterns..
  # According to "Programming Perl, Chapter 2":
  #
  # "If you say /.*foo/, for example, the pattern matching engine will try to 
  # match the maximal number of any characters clear out to the end of the
  # line before it ever tries looking for 'foo', and will back up one character
  # at a time until it finds 'foo'.  If there is more than one 'foo' in the 
  # line, it'll stop on the last one, and throw away all the shorter choices
  # it could have made.
  #
  # By placing a question mark after any of the greedy quantifiers, they can 
  # be made to choose the smallest quantity for the first try, so /.*?foo/
  # finds the first 'foo', not the last."
  #
  # This is important, because some of the dkim-signature bits all run together
  # like the c= bits shown below:
  #
  # ('dkim-signature', 'a=rsa-sha1; 
  #  c=relaxed/relaxed;\r\n\td=mail.feedblitz.com; s=mdaemon; q=dns; 
  #  h=From:Reply-To:Sender:\r\n\tTo:Date:Subject:List-Unsubscribe:
  #  MIME-Version:Content-Type; b=Jx\r\n\tEHeugkVEJh/it34zzBy+YFiDx85HL76tXyv
  #  A6Tut9RdQ3JFb4rxUw9sLlVuWF8r2\r\n\tEYyuMlF2m6rcSOq8FeZ6CpklYQO1L0ExsP/
  #  25/LA/p1Kv1y/Qz3ICIUtfjFP9zfB\r\n\t+/tRgi2yCTDJXAiikIyEvGkNO90P+ge3meLMW
  #  d9BA='),
  #
  # Need to do the ?; magic to get c=relaxed/relaxed; as a match, rather than
  # c=relaxed/relaxed;\r\n\td=mail.feedblitz.com;
  #
  # Even with that, there are some corner cases due to UTF(?) encoding of
  # hashes that we'll just code around using defined();

  if ($sig =~ /s=(\w[\w\.\-]+)?;/) {
    if (defined($1)) {
      $mids{$mid}->{dkim_selector} = $1;
    }
  }

  # Generally, we'll see c=(relaxed|simple)/(relaxed|simple)
  if ($sig =~ /c=((relaxed|simple)\/(relaxed|simple));/) {
    $mids{$mid}->{dkim_canonicalization} = $1;
  }

  # However, it's valid to report just c=(relaxed|simple), and per RFC 4871:
  #
  # If only one algorithm is named, that algorithm is used for the header 
  # and "simple" is used for the body. For example, "c=relaxed" is treated 
  # the same as "c=relaxed/simple".
  #
  # So...
  if ($sig =~ /c=((relaxed|simple));/) {
    $mids{$mid}->{dkim_canonicalization} = $1 . "/simple";
  }

  if ($sig =~ /d=(\w[\w\.\-]+)?;/) {
    if (defined($1)) {
      $mids{$mid}->{dkim_domain} = $1;
    }
  }

  if ($sig =~ /i=([\w\.\-\@]+)?; /) {
    if (defined($1)) {
      $mids{$mid}->{dkim_identity} = $1;
    }
  }
} # end parse_dkim_signature

# Begin main processing
getopts('x:l:h:', \%opts);

setupExcludeRanges();

if (defined($opts{l})) {
  $logfile = $opts{l};
}
else {
  die "usage: $0 [-x exclude_file] -l logfile -h hostname\n";
}

if (defined($opts{h})) {
  $hostname = $opts{h}
}
else {
  die "usage: $0 [-x exclude_file] -l logfile -h hostname\n";
}

$volDataFileName = "${hostname}.${fileDate}.csv";
$authDataFileName = "${hostname}_auth.${fileDate}.csv";

# Open the log file for parsing
open (FH, "<$logfile") || die "Can't open $logfile for reading\n";

my @results;
my $logtime;

my $line = 0;
while (<FH>) {
  chomp;

  # matching on this:
  # Oct 19 06:33:29 2011 [...] Info: New SMTP ICID 2106327026 interface 
  # [...] address IP.ADD.RE.SS [...]
  if (/New SMTP ICID ([0-9]+)\s.*address\s([0-9.]+)\sreverse/) {
    $icids{$1}->{ip} = $2;
  }
  # matching on this:
  # Oct 19 06:33:29 2011 [...] Info: ICID 2106327021 REJECT SG [...]
  # Dummy up a record to show a connection with no attempted deliveries
  elsif (/^(\w+\s+\d{1,2}\s\d\d:\d\d:\d\d\s\d{4})\s.*ICID\s([0-9]+)\sREJECT/) {
    # We generally expect that REJECT SG will come after New SMTP ICID, but
    # it's not always so.
    if (exists ($icids{$2}->{ip})) {
      $mids{$rejectedConnx}->{ip} = $icids{$2}->{ip};
    }
    else {
      $mids{$rejectedConnx}->{ip} = "0.0.0.0";
    }
    $mids{$rejectedConnx}->{timestamp} = $1;
    $mids{$rejectedConnx}->{mail_from_domain} = "null";
    $mids{$rejectedConnx}->{attempted} = 1;
    $mids{$rejectedConnx}->{delivered} = 0;
    $mids{$rejectedConnx}->{rejected} = 1;
    $mids{$rejectedConnx}->{filtered} = 0;
    $mids{$rejectedConnx}->{unknown} = 0;
    $mids{$rejectedConnx}->{header_from_domain} = "null";
    $mids{$rejectedConnx}->{dkim_selector} = "null";
    $mids{$rejectedConnx}->{dkim_identity} = "null";
    $mids{$rejectedConnx}->{dkim_canonicalization} = "null";
    $mids{$rejectedConnx}->{dkim_domain} = "null";
    $mids{$rejectedConnx}->{dkim_result} = "null";
    $mids{$rejectedConnx}->{dkim_pass_fail} = "null";
    $mids{$rejectedConnx}->{spf_result} = "None";
    $mids{$rejectedConnx}->{spf_pass_fail} = "null";
    $mids{$rejectedConnx}->{auth_policy_result} = "null";
    $mids{$rejectedConnx}->{dkim_count} = 1;
    $rejectedConnx += 1;
  }
  # matching on this:
  # Oct 19 06:33:29 2011 [...] Info: Start MID 1416566008 ICID 2106327026
  elsif (/^(\w+\s+\d{1,2}\s\d\d:\d\d:\d\d\s\d+)\s.*Start MID\s([0-9]+)\sICID\s([0-9]+)/) {
    if (exists ($icids{$3}->{ip})) {
      $mids{$2}->{ip} = $icids{$3}->{ip};
    }
    else {
      $mids{$2}->{ip} = "0.0.0.0";
    }
    $mids{$2}->{timestamp} = $1;
    # preload for DKIM, whether it's there or not
    $mids{$2}->{header_from_domain} = "null";
    $mids{$2}->{mail_from_domain} = "null";
    $mids{$2}->{dkim_selector} = "null";
    $mids{$2}->{dkim_identity} = "null";
    $mids{$2}->{dkim_canonicalization} = "null";
    $mids{$2}->{dkim_domain} = "null";
    $mids{$2}->{dkim_result} = "null";
    $mids{$2}->{dkim_pass_fail} = "null";
    $mids{$2}->{spf_result} = "None";
    $mids{$2}->{spf_pass_fail} = "null";
    $mids{$2}->{auth_policy_result} = "null";
    $mids{$2}->{dkim_count} = 1;
    $mids{$2}->{attempted} = 0;
    $mids{$2}->{delivered} = 0;
    $mids{$2}->{rejected} = 0;
    $mids{$2}->{filtered} = 0;
    $mids{$2}->{unknown} = 0;
  }

  # matching on this:
  # Oct 19 06:33:29 2011 [...] Info: MID 1416566008 ICID 2106327026 
  # From: <$EMAIL_ADDRESS>
  #
  # (If it's a bounce, the sender will be <>, and so domain will stay 
  #  null from its initialization).
  elsif (/MID\s([0-9]+)\sICID\s[0-9]+\sFrom:\s<.*\@(.*)>/) {
    $mids{$1}->{mail_from_domain} = $2;
  }
  
  # matching on this:
  # Oct 19 06:33:29 2011 [...] Info: MID 1416566008 ICID 2106327026 
  # RID 0 To: <$EMAIL_ADDRESS>
  elsif (/MID\s([0-9]+)\sICID\s[0-9]+\sRID\s[0-9]+\sTo:\s/) {
    $mids{$1}->{attempted} += 1;
    $mids{$1}->{delivered} += 1;
  }

  # Count User Unknowns...
  # Tue Nov  8 23:52:03 2011 Info: MID 1347675626 ICID 306398794 To:
  # [...] Rejected by LDAPACCEPT
  elsif (/MID\s([0-9]+)\sICID\s.*?\sRejected by LDAPACCEPT/) {
    $mids{$1}->{attempted} += 1;
    $mids{$1}->{unknown} += 1;
  }

  # Count Rejected Recipients...
  # Tue Nov  8 23:52:03 2011 Info: MID 1347675626 ICID 306398794 To:
  # [...] Rejected by Receiving Control
  elsif (/MID\s([0-9]+)\sICID\s.*?\sRejected by Receiving Control/) {
    $mids{$1}->{attempted} += 1;
    $mids{$1}->{rejected} += 1;
  }

  # matching on SPF result:
  # Nov  9 00:05:42 2011 [...] Info: MID 28209724 SPF: mailfrom identity
  # $EMAIL_ADDRESS (Pass|Fail|SoftFail|None|Neutral|PermError|TempError)
  elsif (/MID\s([0-9]+)\sSPF: mailfrom identity .*\@(.*)?\s(\w+)\s/) {
    $mids{$1}->{mail_from_domain} = $2;
    $mids{$1}->{spf_result} = $3;
    $mids{$1}->{spf_pass_fail} = $spfs{$3};
  }

  # matching on DKIM pass:
  # Oct 19 06:32:32 2011 [...] Info: MID 1416565885 DKIM: pass signature 
  # verified (d=e.prevention.com s=20111007 i=@e.prevention.com)
  elsif (/MID\s([0-9]+)\sDKIM: (pass\s+\w+.*)\s(\([a-z]=.*\))/) {
    my $mid = $1;
    my $dkiminfo = $3;
    $mids{$mid}->{dkim_result} = $2;
    $mids{$mid}->{dkim_pass_fail} = 1;
    if ($dkiminfo =~ /\(d=(.*)\ss=(.*)\si=(.*)\)/) {
      $mids{$mid}->{dkim_domain} = $1;
      $mids{$mid}->{dkim_selector} = $2;
      $mids{$mid}->{dkim_identity} = $3;
    }
  }


  # matching on DKIM failure:
  # Oct 19 06:51:23 2011 [...] Info: MID 1416567588 DKIM: permfail no key 
  # for signature (d=e.ae.com s=20111007 i=@e.ae.com)
  #
  # There's some good stuff we can pull from here, probably...
  elsif (/MID\s([0-9]+)\sDKIM:\s+(\w+.*)\s(\([a-z]=.*\))/) {
    my $mid = $1;
    my $dkiminfo = $3;
    $mids{$mid}->{dkim_result} = $2;
    $mids{$mid}->{dkim_pass_fail} = 0;
    if ($dkiminfo =~ /\(d=(.*)\ss=(.*)\si=(.*)\)/) {
      $mids{$mid}->{dkim_domain} = $1;
      $mids{$mid}->{dkim_selector} = $2;
      $mids{$mid}->{dkim_identity} = $3;
    }
  }

  # some DKIM validation failures have different syntax:
  # Oct 19 07:00:30 2011 [...] Info: MID 1416568168 DKIM: malformed 
  # signature - signature missing required tag
  elsif (/MID\s([0-9]+)\sDKIM:\s+(\w+.*\s-\s\w+.*)/) {
    # But we don't want the ones that seem to indicate outbound mail
    # Oct 19 06:38:47 2011 [...] Info: 
    # MID 1416566508 DKIM: cannot sign - no profile matches 
    # barristerwater@yahoo.com.ph
    unless (/cannot sign - no profile matches/) {
      $mids{$1}->{dkim_result} = $2;
      $mids{$1}->{dkim_pass_fail} = 0;
    }
  }

  # matching on this for the whole DKIM shebang...
  # Oct 19 07:03:52 2011 [...] Info: Message done DCID 126723832 MID 
  # 1416568800 to RID [0] [('dkim-signature', 
  # 'v=1; a=rsa-sha1; c=relaxed/relaxed; s=200608; d=e.groupon.com;\r\n 
  # h=From:To:Subject:Date:List-Unsubscribe:MIME-Version:Reply-To:Message-ID:
  # Content-Type;\r\n bh=E8fMAldqnHcy3rUCuQrt/YkqQo4=;\r\n 
  # b=jtHIWUraJpLzQz+jD1fpo26fGf6s7XTmNCoeRGgT65ADyQZIxH4s7QspzfiNA92lMaLSLiH
  # Xv1vJ\r\n   TxDWhfDsK05aL7ZyT6wvlzRkcHe7F15WQOejYR4kc6JFEmXXRTGBLk8NlWP1a
  # TywampeLuXFWYs1\r\n   PiiLEqCKT6pgt1TmlIw='), ('from', '"Groupon" 
  # <mail@e.groupon.com>'), ('subject', '59% Off Facial and Deep-Tissue 
  # Massage in Melrose')]
  elsif (/DCID\s[0-9]+\sMID\s([0-9]+)\s.*dkim-signature',\s'(.*)'\),\s\('from',\s.*<.*\@(.*)>/) {
    # so we can follow our own work here...
    my $mid = $1;
    my $dkim_sig = $2;
    $mids{$mid}->{header_from_domain} = $3;
    parse_dkim_signature ($mid, $dkim_sig);
  }

  # we output what we have so far and clear the hash after the
  # configured number of lines to reduce memory requirements.
  if (++$line > $line_threshold) {
    write_output();
    undef %mids;
    $line = 0;
  }
}

close (FH);

write_output();

system ("gzip $volDataFileName");
system ("gzip $authDataFileName");

#my $endTime = UnixDate("today", "%Y%m%d%H%M%S");
#print "End: $endTime\n";
printf "%d/%d %d:%02d:%02u\n", (localtime(time))[4,3,2,1,0];
