Return Path MTA log transfer tools
==================================

This modules contains software intended to parse MTA logs and deliver them to
Return Path for inclusion into Return Path Reputation Netowrk

Example Usage
-------------

Modify these lines in rp-log-transfer.sh to match your configuration

    SCRIPT=rp-log-transfer.sh
    MTA_LOG_DIR=/var/log/mail
    STAGE_DIR=/var/rp-log-transfer/logs
    LOCK_FILE=/var/rp-log-transfer/lock
    RP_UNAME=xxxxxx
    RP_SERVER=sftp.senderscore.net
    SSH_KEY=/home/senderscore/key
    PARSER=/path/to/parsers/postfixParser.pl

Run this the rp-log-transfer.sh periodically from cron:

    */5 * * * * abuse /path/to/rp-log-transfer.sh

As MTA logs are often customized at each installation, these scripts should be seen as a
template, rather than code to be used in its current state. Please review and test the
code prior to production deployement. You may need to modify it to suit the needs of 
your logging format.

Included Scripts
----------------

    rp-log-transfer.sh - wrapper script to call parser and upload to sftp server

    parsers/bizangaParser.pl
    parsers/eximParser.pl
    parsers/ironportParser.pl
    parsers/mailsystemsParser_main.pl
    parsers/mailsystemsParser_reject.pl
    parsers/mirapointParser.pl
    parsers/postfixParser.pl

Parsers for other MTAs can be made available upon request.

Acknowledgements
----------------

Special thanks to Peter Blair of Tucows, Inc. and all other Return Path partners
for feedback and code contributions.

Legal
-----

Feel free to use and modify this however you would like.

Copyright (c) 2012 Return Path, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

