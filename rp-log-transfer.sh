#!/bin/bash

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

SCRIPT=rp-log-transfer.sh
MTA_LOG_DIR=/var/log/mail
STAGE_DIR=/var/rp-log-transfer/logs
LOCK_FILE=/var/rp-log-transfer/lock
RP_UNAME=xxxxxx
RP_SERVER=sftp.senderscore.net
SSH_KEY=/home/senderscore/key
PARSER=/path/to/parsers/postfixParser.pl

function log
{
	/usr/bin/logger -i -p mail.info -t "$0" "$1"
}

function err
{
	log "$1"
	exit 1
}

function create_lock
{
	LOCKFILE=$1
	APPLICATION=$2
	PID=$$

	if [ -f $LOCKFILE ]; then
		log "Warn: File [ $LOCKFILE ] already exists"
		sleep 1
		LOGPID=$(cat $LOCKFILE)
		RUNPID=$(ps aux grep $LOGPID | grep $SCRIPT | awk '{print $2}')
		if [ "$RUNPID" == "$LOGPID" ]; then
			err "Warn: Process $RUNPID still processing"
		fi

		if [ "X$RUNPID" == "X" ]; then
			log "Removing stale lock file"
			rm -f $LOCKFILE
			if [ -f $LOCKFILE ] ; then
				err "Error: Could not remove stale lockfile $LOCKFILE"
			fi
		fi
	fi

	echo $PID > $LOCKFILE
	if [ ! -f $LOCKFILE ]; then
		err "Error: Could not create $LOCKFILE"
	fi
}

PID=$$
create_lock $LOCK_FILE $SCRIPT $PID

cd $STAGE_DIR

for file in `find $MTA_LOG_DIR -type f`
do
    log "Processing $file"
	perl $PARSER $file `hostname`
	log "uploading to to ${RP_SERVER}"
    #echo "put $files" > cmd.txt
    #sftp -o IdentityFile=$SSH_KEY -b cmd.txt ${RP_UNAME}@${RP_SERVER} |
    rsync -e ssh -av $STAGE_DIR $RP_SERVER: 2>&1 |
	while read line
	do
	  log "$line"
	done
done

log "Finishing"
rm -f $LOCK_FILE || err "Error: Could not remove $LOCK_FILE"

cd -

