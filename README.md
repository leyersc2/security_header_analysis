# Common Crawl - HTTP security header analysis
Authors: Connor Leyers, Joshua Paytosh, Nolan Worthy

## General Overview: 
This repository contains the files used to analyze on an AWS EMR cluster the use over time of HTTP response headers relating to security.

## Repo Contents:
**fortunePaths**
  * Directory containing the paths of the WAT files from every month as determined by the Common Crawl Index to contain records corresponding to the web pages of the Fortune 30  

**sampledPaths**
  * Directory containing the paths of the 10 WAT files from every month randomly sampled by an execution of `sampling.py`  
  
**Make.sh**
  * Makefile to be run on cluster that installs appropriate packages and clones this git repo  
  
**README.md**
  * This file  
  
**analysis.py**
  * Takes the results of `mapreduce.py` from S3 and determines how many total hosts and how many occurences of each header there are for a given month  
  
**ftp.sh**
  * Transfers Make.sh to cluster  
  
**mapreduce.py**
  * Takes the files from S3 whose paths are in a given .paths file, determines the presence of 21 different headers in the response records of every host, and stores results in .txt on S3  
  
**sampling.py**
  * Given one of Common Crawl's monthly .paths files, randomly samples a certain number of paths and places them in a new .paths file

## Resources: 
https://commoncrawl.org/  
http://urlsearch.commoncrawl.org/
