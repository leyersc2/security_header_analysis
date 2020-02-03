#!/bin/bash
# AWS EMR SCP transfer script

$server_info
echo "ENTER SERVER IP"
read server_info

chmod 400 commonCrawl.pem

echo "########### TRANSFERING SETUP FILES ###########"
scp -i commonCrawl.pem Make.sh hadoop@ec2-$server_info.us-east-2.compute.amazonaws.com:/home/hadoop


echo "########### connecting to server and run commands in sequence ###########"
ssh -i commonCrawl.pem hadoop@ec2-$server_info.us-east-2.compute.amazonaws.com

