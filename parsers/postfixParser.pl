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

use strict;
use Time::Local;
use Date::Manip::DM5 qw(UnixDate);

# This the maximium number of messages we will store info for.
# This number should be way more than enough to make sure
#  we are done processing a message before deleting it's info,
#  but should be low enough that we don't use an absurd amount of memory
my $MAX_MESSAGE_INFO = 10000;

# We use this to store information about a message between different log lines
# It will never go above $MAX_MESSAGE_INFO
my %message_info = ();

# We use this to store an ordered list of mailing ids, so we can remove their info in the correct order
# It will never go above $MAX_MESSAGE_INFO
my @mids = ();

# Find the current year - we should override this if the log file came from a different year
# In the future, we should probably warn the user if this is likely
my ($year) = (localtime)[5];
$year += 1900;

# Used to convert month names to numbers for the dates
my %months = (
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
    Dec => '12',
);

# Input filename
my $logfile;

# For output filenames
my $hostname;

# UnixDate from Date::Manip package; we'll use this as part of the
# name of the files to be uploaded
my $fileDate = UnixDate( "today", "%Y%m%d%H%M%S" );

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

# open the output file
my $volDataFileName = "${hostname}.${fileDate}.csv";
open( VOLUME, ">$volDataFileName" ) || die "can't open $volDataFileName for writing\n";

# Print a header line for easier reading in Excel
my @fields =
  qw(Time From_Domain To_Domain Status Status_Code Status_Message HELO IP_Address Hostname);
print VOLUME join("\t", @fields), "\n";

# Open the log file for parsing
open( FH, "<$logfile" ) || die "Can't open $logfile for reading\n";
while (<FH>) {
    chomp;
    handle_line($_);
}

close(FH);
close(VOLUME);
system("gzip $volDataFileName");

exit;

#################

sub handle_line {

    # find the time, hostname, program, pid, and mid - if this doesn't match, it didn't come from postfix, so we can ignore it
    # Jul 10 00:00:02 205.158.62.206 <22>postfix/smtpd[28269]:
    my ( $mon, $day, $time, $hostname, $proc, $remainder ) = split( ' ', $_, 6 );

    # if we didn't get a proper $mid, it uses the remainder
    my $mid;
    if ( $remainder =~ /^([0-9A-F]{10}):/ ) {

        # $remainder = substr($remainder, 12);
        $mid = $1;

        #	print "Remainder is $remainder and mid is $mid\n";
    }

    # store all message-specific info but RCPT under the MID - when we find a rejection
    # or a delivery, we can combine that info with the specific recipient
    my $info = $message_info{$mid};
    if ( !defined $info ) {
        $info = {};
        $message_info{$mid} = $info;
        push @mids, $mid;

        # set the time for the message coming in
        my ( $hour, $min, $sec ) = ( $time =~ /^(\d+):(\d+):(\d+)$/ );
        $mon = $months{$mon};
        $info->{'time'} = "$year-$mon-$day $hour:$min:$sec";
    }

    #print "remainder is  $remainder\n";
    findattribs( $info, $remainder );

    # count accepted messages
    if ( $info->{'status'} eq 'sent' ) {
        $info->{'status'} = 'delivered';
    }

    # find rejected ones
    elsif ( $remainder =~ /^reject: (.*); from=/ ) {
        $info->{'status'}  = 'rejected';
        $info->{'message'} = $1;
    }

    # find filtered ones
    elsif ( $remainder =~ /^filter: (.*); from=/ ) {
        $info->{'status'}  = 'filtered';
        $info->{'message'} = $1;
    }
    else {
        next;
    }

    # we should have all the info we need, so we can print it out
    print_message($info);

    # We might want to look for exit info for the PID - we can then delete the info for that PID & associated MID
    # This doesn't appear to work, because even when one process is done with the MID,
    # another might still be working with it

    # There doesn't appear to be a real way to tell when we are done with a particular message ID, because
    # how many times it might show up and in what order the different programs process it is non-deterministic
    # (Note two attempts at doing so above, both of which lose some info for some messages)
    # Because of this, I'm just going to impose an upper limit on the number of messages we remember info for.
    # This should allow us to come up with a reasonable upper bound on the amount of memory we use,
    # with a very low (but not guaranteed) chance of losing some information about a message
    while ( @mids > $MAX_MESSAGE_INFO ) {
        my $mid = shift @mids;
        delete $message_info{$mid};
    }
}


sub findattribs {
    my ( $info, $remainder ) = @_;

    # find any extended attributes
    while ( $remainder =~ /([a-z]+)=(\S+)/g ) {
        $info->{$1} = $2;
    }

}

sub print_message {
    my $message = shift;

    # get to domain
    my $todomain;
    if ( $message->{'orig_to'} ) {
        $todomain = substr( $message->{'orig_to'}, index( $message->{'orig_to'}, '@' ) + 1 );
    }
    else {
        $todomain = substr( $message->{'to'}, index( $message->{'to'}, '@' ) + 1 );
    }
    $todomain =~ s/>$//;

    # get from domain
    my $fromdomain = substr( $message->{'from'}, index( $message->{'from'}, '@' ) + 1 );
    $fromdomain =~ s/>$//;

    # find actual IP & hostname if possible
    if ( $message->{'client'} =~ /^(\S+)\((\S+)\[([^\]])\]\)/ ) {
        $message->{'helo'}     = $1;
        $message->{'hostname'} = $2;
    }
    if ( $message->{'client'} =~ /\S+\[(\d+\.\d+\.\d+\.\d+)\]/ ) {
        $message->{'ip'} = $1;
    }

    # remove <> from helo if it is there
    $message->{'helo'} =~ s/<(.*)>/$1/;

    # find status code & message
    if ( $message->{'message'} =~ /:(\d{3}) (.*?):/ ) {
        $message->{'code'}    = $1;
        $message->{'message'} = $2;
    }

    my $newline = join(
        "\t", (
            $message->{'time'},   $fromdomain,        $todomain,
            $message->{'status'}, $message->{'code'}, $message->{'message'},
            $message->{'helo'},   $message->{'ip'},   $message->{'hostname'} ) );
    $newline =~ s/\>//g;
    $newline =~ s/\<//g;
    $newline =~ s/,//g;
    print VOLUME "$newline\n";
}
