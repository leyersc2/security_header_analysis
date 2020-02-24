#!/bin/bash
# AWS EMR Setup script

sudo yum install htop
sudo yum install git
git clone https://github.com/leyersc2/security_header_analysis.git
echo "~GIT Repo Cloned~"


sudo pip install wheel
sudo pip install spark
sudo pip install boto
sudo pip install warc
sudo pip install pyspark
sudo easy_install hashlib
sudo pip install https://github.com/commoncrawl/gzipstream/archive/master.zip
echo "~Packages installed~"
