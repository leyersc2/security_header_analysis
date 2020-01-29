#!/bin/bash
# AWS EMR Setup script

server_info = ""
echo "ENTER SERVER ~NUMBERS~"

read server_info

echo "########### connecting to server and run commands in sequence ###########"
#ssh -i ~/commonCrawl.pem hadoop@ec2-3-14-86-205.us-east-2.compute.amazonaws.com
echo $server_info
