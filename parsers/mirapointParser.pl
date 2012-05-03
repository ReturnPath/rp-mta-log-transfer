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

# For parsing logs from a Mirapoint MTA.
#
# Uses standard Perl plus the following two modules:
#
#   Date::Manip::DM5
#   IO::Compress::Gzip
#
# First set of logs provided seem to have only the following event types:
#
#   MTA.MESSAGE.HEADERS
#   MTA.MESSAGE.QUEUED
#   MTA.MESSAGE.RECEIVED
#   MTA.MESSAGE.REMOTE
#   MTA.MESSAGE.STATUS
#   UCE.MESSAGE.JUNKMAIL
#   UCE.MESSAGE.SCORE
#
# MTA.MESSAGE.HEADERS—A message has been received by SMTP with the
# following headers. It might not be delivered yet. The Received headers are
# filtered out. The individual headers are Tab separated; internal Tabs and
# newlines are translated to spaces. After identifier, event-specific fields
# are:
# - QID—Queue ID to uniquely identify the message.
# - Header fields (exclusive of Received: lines) with value
# - More header fields with their values
#
# MTA.MESSAGE.QUEUED—A message has been queued for later delivery. After
# identifier, event-specific fields are:
# - QID—Queue ID to uniquely identify the message.
# - To—Space-separated list of recipients.
#
# MTA.MESSAGE.RECEIVED—A message has been received for delivery by SMTP.
# After identifier, event-specific fields are:
# - QID—Queue ID to uniquely identify the message.
# - From—The envelope “from” address.
# - Msg-ID—SMTP message ID contained in header (generated if necessary).
# - Remote—Host name of remote machine that sent the message.
# - Encryption—Either (TLS) indicating secure connection, or () indicating the
#   message was received as cleartext.
# - Size—Message size in bytes before inserting Received and other headers.
# - Recipients—How many addresses this message was sent to.
#
# MTA.MESSAGE.REMOTE—A message has been delivered to a remote machine.
# After identifier, event-specific fields are:
# - QID—Queue ID to uniquely identify the message.
# - From—The envelope “from” address.
# - To—Space-separated list of recipients handled by this delivery.
# - Status—Additional information returned by remote machine. This field is
#   free-form, diagnostic, and intended for human interpretation.
# - Size—Message size in bytes before inserting Received and other headers.
# - Attachment—1 if there is at least one attachment, 0 otherwise.
# - Transport—CLR for cleartext or TLS for SSL-encoded
#
# MTA.MESSAGE.STATUS—Something unusual happened. After identifier,
# event-specific fields are:
# - QID—Queue ID to uniquely identify the message.
# - From—The envelope “from” address if appropriate
# - To—Space-separated list of recipients if applicable.
# - Info—What happened, for example one of the following error messages:
# – RBL server rejected connection—due to RBL server query.
# – Recipient does not exist—due to SMTP Recipientcheck.
# – Sender blacklisted—due to Uce Addexception blacklist.
# – Too many inbound SMTP connections—due to connection throttling.
# – UCE blacklist triggered—due to Uce Add block (reject list).
#
# UCE.MESSAGE.JUNKMAIL—This message was either scored as spam or was
# previously domain-level blacklisted. After identifier, fields are:
# - QID—Queue ID to uniquely identify the message.
# - MailFrom—Envelope sender address for the message.
# - RcptTo—Envelope recipient address, or space-separated addresses.
# - Host—The peer IP address of the originating mail server.
# - Source—Which facility was responsible for logging this event.
# - Score—Junkmail score or <NA> for blacklisting.
# - Msg-ID—SMTP message ID contained in header (generated if necessary).
# - Domain—Either blank, or gives the domain recognizing this junk mail.
#
# UCE.MESSAGE.SCORE—Junk mail recognized score. After identifier, fields are:
# - Domain—Either blank, or gives the domain recognizing this junk mail.
# - QID—Queue ID to uniquely identify the message.
# - Msg-ID—SMTP message ID contained in header (generated if necessary).
# - Sender—Originator of the message envelope.
# - Score—A positive number indicating degree of junkiness.
# - Recipients—A space-separated list of To or Cc addresses.
#
#
# Volume Data
#
# File 1, a volume data file, will be named ${hostname}.${fileDate}.csv
# where hostname is the name of the Mirapoint server (ideally, the second
# parameter passed to this program) and fileDate is derived from the time
# the parser is run.
#
# The target output is a CSV file with the following columns, in the following
# order, of aggregated results from incoming SMTP connections
#
# Date/Time
#
# YYYY-­‐MM-­‐DDTHH:MM:SSZ (UTC timestamp)
#
# The date/time field is a UTC-­‐formatted timestamp from
# time-zone of the MTA server sending the data, representing the start of
# the aggregation timeframe based on the source email message received date.
#
#
# From: Domain
#
# SMTP Domain Received appearing in the mail “envelope” from of the source
# email message. Null (if Rejected)
#
# Source IP
#
# XXX.XXX.XXX.XXX (IP address)
#
# The dotted-­ ‐ quad IPv4 IP address which connected to the receiving MTA
# in order to deliver the source email message or messages.
#
# Total Attempted
#
# Total number of recipients in transaction (sum of all the following elements)
#
# Delivered
#
# SMTP 250, accepted by the gateway MTA and handed off to the next process
#
# Rejected
#
# 5xx, decision made prior to .DATA portion (non-511)
#
# Filtered
#
# 5xx, content based (non-511)
#
# Unknown Users
#
# 511
#
# Sample
#
# 2009-03-22 00:30:33,creiu.com,110.37.11.11,5,0,5,0,0
# 2009-03-22 00:30:33,veccia.com,110.37.17.7,6,0,3,0,3
# 2009-03-22 00:30:33,runningwiththebulls.com,110.37.21.115,6,0,5,0,1
# 2009-03-22 00:30:33,dameindistress.com,110.37.26.191,6,0,6,0,0
# 2009-03-22 00:30:33,frecuentame.com,110.37.46.151,6,0,6,0,0
# 2009-03-22 00:30:33,viaenovae.com,110.37.47.228,6,0,5,0,1
# 2009-03-22 00:30:33,reiberfestival.com,110.37.6.32,6,0,3,0,3
# 2009-03-22 00:30:33,website-owner.com,110.37.6.32,6,0,6,0,0
# 2009-03-22 00:30:33,qianseceramics.com,110.37.62.74,6,0,6,0,0
# 2009-03-22 00:30:33,ziphvd.com,110.37.7.18,6,0,5,0,1
# 2009-03-22 00:30:33,tankogas.com,110.37.7.250,6,0,5,0,1
#
# File 2, an authentication data file, will be named
# ${hostname}_auth.${fileDate}.csv where hostname is the name of the Mirapoin
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
# Our initial contributor of Mirapoint logs is providing us with what appear
# to be logs from an internal layer of their infrastructure, rather than the
# outer edge layer.  This is not a full-stop problem, but does complicte
# matters WRT to how we'll get the data we want.
#
# The volume data will come to us from a combination of lines; we'll track
# them by the QID, which is the first field after the status type.
#
# First line will be MTA.MESSAGE.HEADERS line:
#
# 20120320 23:23:01 1824539579 mailrelay17.libero.it 1332285781.106
# MTA.MESSAGE.HEADERS EFH12942 Authentication-Results: mtalibero02.libero.it;
# dkim=neutral (message not signed) header.i=none Received-SPF: PermError
# identity=mailfrom; client-ip=85.37.17.79; receiver=mtalibero02.libero.it;
# envelope-from="bmwmotoclubcento@libero.it";
# x-sender="bmwmotoclubcento@libero.it"; x-conformance=spf_only;
# x-record-type="v=spf1" X-LREMOTE-IP: 85.37.17.79
#
# This line will give us the timestamp (UTC - either the first two fields or
# the number after the hostname, which is an epoch seconds representation
# of same), Source IP (X-LREMOTE-IP), From: Domain (envelope-from)
#
# Next, the MTA.MESSAGE.RECEIVED line:
#
# 20120320 23:23:01 1824539580 mailrelay17.libero.it 1332285781.106
# MTA.MESSAGE.RECEIVED EFH12942 bmwmotoclubcento@libero.it
# <000901cd06f0$603583d0$2801a8c0@Centottica.local> mtalibero02.libero.it
# [192.168.36.164] () 126619 27
#
# This will give us Total Attempted (the last number in the line).
#
# MTA.MESSAGE.STATUS will tell us which recipients were Unknown Users:
#
# 20120320 23:23:03 1824539818 mailrelay17.libero.it 1332285783.612
# MTA.MESSAGE.STATUS EFH12942 bmwmotoclubcento@libero.it  User unknown
# (from ims1a8.libero.it [192.168.39.188])
#
# MTA.MESSAGE.REMOTE will allow us to count the Delivered ones; the assumption
# here is "Mail accepted" == "Delivered" :
#
# 20120320 23:23:04 1824539838 mailrelay17.libero.it 1332285784.860
# MTA.MESSAGE.REMOTE EFH12942 bmwmotoclubcento@libero.it
# (ims3c4.libero.it: <4F68834300051335> Mail accepted) 127315 1 CLR
#
# MTA.MESSAGE.STATUS will also give us Filtered or Rejected:
#
# 20120320 23:44:03 1824625780 mailrelay17.libero.it 1332287043.501
# MTA.MESSAGE.STATUS EFH24482 info@vistaimmobiliare.it  Dropped by
# Message Filtering: 250 Silently rejected
#
# That seems like enough to start writing some code...
#
use warnings;
use strict;
use Date::Manip::DM5 qw(UnixDate);
use IO::Compress::Gzip qw(gzip $GzipError);

# Some global variables
my %qids = ();

# hash for mapping SPF results to SPF pass fail codes
my %spfs = (
    Pass      => 1,
    None      => "null",
    Neutral   => "null",
    Fail      => 0,
    SoftFail  => 0,
    TempError => 0,
    PermError => 0
);

# Input filename
my $logfile;

# For output filenames
my $hostname;

# UnixDate from Date::Manip package; we'll use this as part of the
# name of the files to be uploaded
my $fileDate = UnixDate( "today", "%Y%m%d%H%M%S" );

sub getAuthInfo ($;$) {
    my $qid     = shift;
    my $headers = shift;

    # Header sender seems to be logged as x-sender, e.g.,
    # x-sender="info@promozionibusiness.com";
    if ( $headers =~ /x-sender=".*\@(.*)";/ ) {
        $qids{$qid}->{header_from_domain} = $1;
    }

    # DKIM stuff...
    # selector, e.g., s=omr1prod;
    if ( $headers =~ /;\ss=(\w[\w\.\-]+)?;/ ) {
        $qids{$qid}->{dkim_selector} = $1;
    }

    # DKIM identity, e.g.,  header.i=mail@messaging.zoosk.com
    if ( $headers =~ /header\.i=([\w\.\-\@]+)?; / ) {
        if ( defined($1) ) {
            $qids{$qid}->{dkim_identity} = $1;
        }
    }

    # canonicalization, e.g., c=relaxed/relaxed;
    if ( $headers =~ /c=((relaxed|simple)\/(relaxed|simple));/ ) {
        $qids{$qid}->{dkim_canonicalization} = $1;
    }

    # However, it's valid to report just c=(relaxed|simple), and per RFC 4871
    #
    # So...
    if ( $headers =~ /c=((relaxed|simple));/ ) {
        $qids{$qid}->{dkim_canonicalization} = $1 . "/simple";
    }

    # DKIM domain, e.g., d=messaging.zoosk.com;
    if ( $headers =~ /d=(\w[\w\.\-]+)?;/ ) {
        if ( defined($1) ) {
            $qids{$qid}->{dkim_domain} = $1;
        }
    }

    # DKIM Result, e.g., dkim=pass (signature verified), or dkim=neutral
    # or dkim=somethingElse
    if ( $headers =~ /\sdkim=pass\s(\([\w\s]+\))/ ) {
        $qids{$qid}->{dkim_pass_fail} = 1;
        $qids{$qid}->{dkim_result}    = $1;
    }
    elsif ( $headers =~ /\sdkim=neutral\s(\([\w\s]+\))/ ) {
        $qids{$qid}->{dkim_pass_fail} = "null";
        $qids{$qid}->{dkim_result}    = $1;
    }
    elsif ( $headers =~ /\sdkim=(\w+)\s(\([\w\s]+\))/ ) {

        # Assume failure; $1 could be "permerror", "hardfail", or other values
        $qids{$qid}->{dkim_pass_fail} = 0;
        $qids{$qid}->{dkim_result}    = $2;
    }

    # SPF, e.g., Received-SPF: None
    if ( $headers =~ /Received-SPF:\s(\w+)\s/ ) {
        $qids{$qid}->{spf_result}    = $1;
        $qids{$qid}->{spf_pass_fail} = $spfs{$1};
    }

}

sub initializeQID ($;$;$;$) {
    my $timestamp    = shift;
    my $qid          = shift;
    my $ip           = shift;
    my $mfrom_domain = shift;

    $timestamp =~ s/^([0-9]{4})([0-9]{2})([0-9]{2})/$1-$2-$3/;
    $qids{$qid}->{timestamp}             = $timestamp;
    $qids{$qid}->{ip}                    = $ip;
    $qids{$qid}->{mail_from_domain}      = $mfrom_domain;
    $qids{$qid}->{header_from_domain}    = "null";
    $qids{$qid}->{dkim_selector}         = "null";
    $qids{$qid}->{dkim_identity}         = "null";
    $qids{$qid}->{dkim_canonicalization} = "null";
    $qids{$qid}->{dkim_domain}           = "null";
    $qids{$qid}->{dkim_result}           = "null";
    $qids{$qid}->{dkim_pass_fail}        = "null";
    $qids{$qid}->{spf_result}            = "None";
    $qids{$qid}->{spf_pass_fail}         = "null";
    $qids{$qid}->{auth_policy_result}    = "null";
    $qids{$qid}->{dkim_count}            = 1;
    $qids{$qid}->{delivered}             = 0;
    $qids{$qid}->{rejected}              = 0;
    $qids{$qid}->{filtered}              = 0;
    $qids{$qid}->{unknowns}              = 0;

}

# Begin main processing
if ( exists $ARGV[0] ) {
    $logfile = $ARGV[0];
}
else {
    die "usage: $0 <name of log file> <hostname of server>\n";
}

if ( exists $ARGV[1] ) {
    $hostname = $ARGV[1];
}
else {
    die "usage: $0 <name of log file> <hostname of server>\n";
}

open( LOG, "<$logfile" ) || die "Can't open $logfile for reading\n";

while (<LOG>) {
    chomp;

    # Gonna have to figure out how to get null senders (envelope-from="")
    if (
        /^([0-9]{8}\s[0-9]{2}:[0-9]{2}:[0-9]{2})\s.*MTA.MESSAGE.HEADERS\s([A-Z]{3}[0-9]{5})\s.*client-ip=([0-9.]+);\s.*envelope-from=".*\@(.*)";/
      ) {
        initializeQID( $1, $2, $3, $4 );
        getAuthInfo( $2, $_ );

        # print "QID: $2\tTIMESTAMP: $qids{$2}->{timestamp}\tMFROM DOMAIN: $qids{$2}->{mail_from_domain}\tIP: $qids{$2}->{ip}\n";
    }

    if (
        /^([0-9]{8}\s[0-9]{2}:[0-9]{2}:[0-9]{2})\s.*MTA.MESSAGE.HEADERS\s([A-Z]{3}[0-9]{5})\s.*client-ip=([0-9.]+);\s.*envelope-from="";/
      ) {
        initializeQID( $1, $2, $3, "null" );
        getAuthInfo( $2, $_ );

        # print "QID: $2\tMFROM DOMAIN: $qids{$2}->{mail_from_domain}\tIP: $qids{$2}->{ip}\n";
    }

    # While the total attempted is logged in the following line, inconsistencies
    # in the logs can result in the other four fields not adding up to the total
    # logged here.  Therefore, we'll just sum the other four to get the total.
    # if (/MTA.MESSAGE.RECEIVED\s([A-Z]{3}[0-9]{5})\s.*\s([0-9]+)$/) {
    #   unless (/ Administrator /) { $qids{$1}->{attempted} = $2; }
    #  }

    if (/MTA.MESSAGE.REMOTE\s([A-Z]{3}[0-9]{5})\s.*Mail accepted.*/) {

        # But we don't want these:
        # 20120321 04:38:51 1825985396 mailrelay17.libero.it 1332304731.778
        # MTA.MESSAGE.REMOTE EFJ25195 MAILER-DAEMON  ([192.168.32.64]:
        # <4F5A21B7034006DD> Mail accepted) 4511 1 CLR
        unless (/MAILER-DAEMON/) { $qids{$1}->{delivered} += 1; }
    }

    if (/MTA.MESSAGE.STATUS\s([A-Z]{3}[0-9]{5})\s.*User unknown.*/) {
        unless (/MAILER-DAEMON/) { $qids{$1}->{unknowns} += 1; }
    }

    if (/MTA.MESSAGE.STATUS\s([A-Z]{3}[0-9]{5})\s.*Dropped by Message Filtering.*/) {
        $qids{$1}->{filtered} += 1;
    }

}
close(LOG);

my $volDataFileName  = "${hostname}.${fileDate}.csv";
my $authDataFileName = "${hostname}_auth.${fileDate}.csv";

open( VOLDATA, ">$volDataFileName" ) || die "can't open $volDataFileName for writing\n";

open( AUTHDATA, ">$authDataFileName" ) || die "can't open $authDataFileName for writing\n";

foreach my $qid ( sort keys %qids ) {
    if ( exists( $qids{$qid}->{timestamp} ) ) {
        $qids{$qid}->{attempted} =
            $qids{$qid}->{delivered} 
          + $qids{$qid}->{rejected} 
          + $qids{$qid}->{filtered}
          + $qids{$qid}->{unknowns};
        if ( $qids{$qid}->{attempted} > 0 ) {
            print VOLDATA
              "$qids{$qid}->{timestamp},$qids{$qid}->{mail_from_domain},$qids{$qid}->{ip},$qids{$qid}->{attempted},$qids{$qid}->{delivered},$qids{$qid}->{rejected},$qids{$qid}->{filtered},$qids{$qid}->{unknowns}\n";
        }

        if (   ( $qids{$qid}->{header_from_domain} ne "null" )
            || ( $qids{$qid}->{mail_from_domain} ne "null" ) ) {
            print AUTHDATA
              "timestamp=$qids{$qid}->{timestamp}\tsource_ip=$qids{$qid}->{ip}\theader_from_domain=$qids{$qid}->{header_from_domain}\tsmtp_mail_from=$qids{$qid}->{mail_from_domain}\tdkim_selector=$qids{$qid}->{dkim_selector}\tdkim_identity=$qids{$qid}->{dkim_identity}\tdkim_canonicalization=$qids{$qid}->{dkim_canonicalization}\tdkim_domain=$qids{$qid}->{dkim_domain}\tdkim_result=$qids{$qid}->{dkim_result}\tdkim_pass_fail=$qids{$qid}->{dkim_pass_fail}\tspf_result=$qids{$qid}->{spf_result}\tspf_pass_fail=$qids{$qid}->{spf_pass_fail}\tauth_policy_result=$qids{$qid}->{auth_policy_result}\tcount=$qids{$qid}->{dkim_count}\n\n";
        }


    }
}
close(AUTHDATA);
close(VOLDATA);

gzip $volDataFileName => "$volDataFileName.gz" or die "gzip failed: $GzipError\n";

# Since this gzip keeps the original file around...
unlink $volDataFileName or warn "Could not unlink $volDataFileName: $!\n";

gzip $authDataFileName => "$authDataFileName.gz" or die "gzip failed: $GzipError\n";
unlink $authDataFileName or warn "Could not unlink $volDataFileName: $!\n";
