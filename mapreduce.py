    # stream name: thesis-stream
    # bucket name: winthropcsthesis
    
    # /*------------------------------------------------- mapreduce.py -----
    #  |  program name: mapreduce.py
    #  |
    #  |  Authors: Connor Leyers, Joshua Paytosh, Nolan Worthy
    #  |
    #  |  Purpose:  Aimed at analyzing a sample of the CommonCrawl dataset to
    #  |      assess security of hosts in 10 WAT files per month by
    #  |      looking at active presence of HTTPS secuirty Headers across
    #  |      multiple months in a crawled year.
    #  |
    #  |      This is done by sampling the data via an AWS S3 Bucket and
    #  |      utilizing an Elastic Map Reduce (EMR) cluster to partition
    #  |      and optimize the large scale computation required for this
    #  |      analysis.
    #  |
    #  |  Parameters:
    #  |             ***IN = USED TO PASS DATA INTO THIS FUNCTION
    #  |                OUT = USED TO PASS DATA OUT OF THIS FUNCTION
    #  |                IN/OUT = USED FOR BOTH PURPOSES***
    #  |
    #  |      CommonCrawl WARC Files (IN) -- Collection of WARC files
    #  |          containing raw HTML data from each crawled hosts

    #  |      CommonCrawl WAT Files (IN) -- Contains JSON formatted metadata
    #  |        containing components desired for analysis on unique hosts
    #  |
    #  |  Result: Sends 
    #  *-------------------------------------------------------------------*/



    # /*------------------------------------------------- Packages -----
    #  |    Packages:
    #  |    json : Allows for object manipulation into/out of JSON formatting.
    #  |
    #  |    boto :Boto is the Amazon Web Services (AWS) SDK for Python.
    #  |     It enables Python developers to create, configure, and manage
    #  |     AWS services, such as EC2 and S3.
    #  |
    #  |    boto.s3.key -> key : The Key object is used in boto to keep
    #  |     track of data stored in S3.
    #  |
    #  |    boto.s3.connection -> S3Connection : Connect to local
    #  |     Regions endpoint. Returns a connection object pointing
    #  |     to the endpoint associated with this region.
    #  |
    #  |    gzipstream -> GzipStreamFile : allows Python to process
    #  |     multi-part gzip files from a streaming source.
    #  |
    #  |    warc : extension of the ARC file format, which adds more
    #  |     freedom by adding more metadata to each record
    #  |     and allowing named headers.
    #  |
    #  |    pyspark -> SparkContext : SparkContext is the entry point to any
    #  |     spark functionality.
    #  |
    #  |    urlparse -> urlparse : provides functions for breaking URLs
    #  |    down into their component parts.
    #  |
    #  |    hashlib : implements a common interface to many different
    #  |     secure hash and message digest algorithms.
    #  |
    #  |    boto3: latest version of  Amazon Web Services (AWS) SDK for Python.
    #  |     It enables Python developers to create, configure, and manage
    #  |     AWS services, such as EC2 and S3.
    #  |    
    #  *-------------------------------------------------------------------*/

import json
import boto
from boto.s3.key import Key
from boto.s3.connection import S3Connection
from gzipstream import GzipStreamFile
import warc
from pyspark import SparkContext
from urlparse import urlparse
import hashlib
import boto3
import os
import os.path
import shutil

sc = SparkContext.getOrCreate()

#------------------------ HEADER FLAGS --------------------------------------+
#  Purpose: CREATE INTEGERS THAT, WHEN CONSIDERED TO BE BINARY
#     STRINGS, CAN BE USED FOR BITWISE OPERATIONS FOR OPERATING
#     ON A SINGLE HEADER
#
#  Parameters:  NONE
#
#  Result:  13 INTEGERS. ONE FOR EACH HEADER.
#----------------------------------------------------------------------------+

X_XSS_Protection_FLAG =                     0b100000000000000000000
Content_Security_Policy_FLAG =              0b010000000000000000000
X_Content_Security_Policy_FLAG =            0b001000000000000000000
X_Frame_Options_FLAG =                      0b000100000000000000000
Strict_Transport_Security_FLAG =            0b000010000000000000000
X_Content_Type_Options_FLAG =               0b000001000000000000000
X_Download_Options_FLAG =                   0b000000100000000000000
X_Permitted_Cross_Domain_Policies_FLAG =    0b000000010000000000000
Expect_CT_FLAG =                            0b000000001000000000000
Feature_Policy_FLAG =                       0b000000000100000000000
Referrer_Policy_FLAG =                      0b000000000010000000000
X_Public_Key_Pins_FLAG =                    0b000000000001000000000
X_Public_Key_Pins_Report_Only_FLAG =        0b000000000000100000000
Public_Key_Pins_FLAG =                      0b000000000000010000000
Public_Key_Pins_Report_Only_FLAG =          0b000000000000001000000
Access_Control_Allow_Origin_FLAG =          0b000000000000000100000
Access_Control_Allow_Credentials_FLAG =     0b000000000000000010000
Access_Control_Allow_Methods_FLAG =         0b000000000000000001000
Access_Control_Allow_Headers_FLAG =         0b000000000000000000100
Access_Control_Expose_Headers_FLAG =        0b000000000000000000010
Access_Control_Max_Age_FLAG =               0b000000000000000000001

partitions = 10

def getHeaders (id_, iterator):

    conn = S3Connection(host="s3.amazonaws.com")
    bucket = conn.get_bucket("commoncrawl")

    for uri in iterator:
        key_ = Key(bucket,uri)
        file_ = warc.WARCFile(fileobj = GzipStreamFile(key_))
        #print("URI READ: " + uri)
        for line in file_:
            try:
                data = json.loads(line.payload.read())

                #------------------------ BUILD DICTIONARY ------------------------------+
                #  Purpose:   FOR EVERY RESPONSE RECORD IN THE CURRENT WAT FILE,
                #     CODE BLOCK CREATES A DICTIONARY OBJECT retArray CONTAINING
                #     TWO ELEMENTS:
                #       -MD5 HASH OUTPUT OF HOSTNAME
                #       -AN INTEGER, WHICH WHEN DISPLAYED IN BINARY HAS ONE BIT
                #       REPRESENTATIVE OF THE PRESENCE OF EACH PARTICULAR HEADER
                #     IF ANY EXCEPTIONS ARE THROWN, DISREGARD AND CONTINUE.
                #
                #  Parameters:
                #     -HTTP RESPONSE SECURITY HEADERS FROM CURRENT WAT RECORD
                #     -FLAG BIT VARIABLES REPRESENTATIVE OF EACH HEADER
                #
                #  Result:    DICTIONARY OBJECT REPRESENTING ONE WAT RECORD
                #------------------------------------------------------------------------+
                retArray = [None, 0b000000000000000000000]
                if(data["Envelope"]["WARC-Header-Metadata"]["WARC-Type"] == "response"):

                    retArray[0] = hashlib.md5(urlparse(data["Envelope"]["WARC-Header-Metadata"].get("WARC-Target-URI", "")).hostname).digest()
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-XSS-Protection", "") != ""):
                        retArray[1] = retArray[1] | X_XSS_Protection_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Content-Security-Policy", "") != ""):
                        retArray[1] = retArray[1] | Content_Security_Policy_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Content-Security-Policy", "")!= ""):
                        retArray[1] = retArray[1] | X_Content_Security_Policy_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Frame-Options", "") != ""):
                        retArray[1] = retArray[1] | X_Frame_Options_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Strict-Transport-Security", "")!= ""):
                        retArray[1] = retArray[1] | Strict_Transport_Security_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Content-Type-Options", "")!= ""):
                        retArray[1] = retArray[1] | X_Content_Type_Options_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Download-Options", "")!= ""):
                        retArray[1] = retArray[1] | X_Download_Options_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Permitted-Cross-Domain-Policies", "")!= ""):
                        retArray[1] = retArray[1] | X_Permitted_Cross_Domain_Policies_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Expect-CT", "")!= ""):
                        retArray[1] = retArray[1] | Expect_CT_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Feature-Policy", "")!= ""):
                        retArray[1] = retArray[1] | Feature_Policy_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Referrer-Policy", "")!= ""):
                        retArray[1] = retArray[1] | Referrer_Policy_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Public-Key-Pins", "")!= ""):
                        retArray[1] = retArray[1] | X_Public_Key_Pins_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Public-Key-Pins-Report-Only", "")!= ""):
                        retArray[1] = retArray[1] | X_Public_Key_Pins_Report_Only_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Public-Key-Pins", "")!= ""):
                        retArray[1] = retArray[1] | Public_Key_Pins_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Public-Key-Pins-Report-Only", "")!= ""):
                        retArray[1] = retArray[1] | Public_Key_Pins_Report_Only_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Access-Control-Allow-Origin", "")!= ""):
                        retArray[1] = retArray[1] | Access_Control_Allow_Origin_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Access-Control-Allow-Credentials", "")!= ""):
                        retArray[1] = retArray[1] | Access_Control_Allow_Credentials_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Access-Control-Allow-Methods", "")!= ""):
                        retArray[1] = retArray[1] | Access_Control_Allow_Methods_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Access-Control-Allow-Headers", "")!= ""):
                        retArray[1] = retArray[1] | Access_Control_Allow_Headers_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Access-Control-Expose-Headers", "")!= ""):
                        retArray[1] = retArray[1] | Access_Control_Expose_Headers_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Access-Control-Max-Age", "")!= ""):
                        retArray[1] = retArray[1] | Access_Control_Max_Age_FLAG

                    yield retArray

            except ValueError:
                continue
            except KeyError:
                continue
            except UnboundLocalError:
                continue

#------------------------ MAPREDUCE AND OUTPUT ------------------------------+
#  Purpose:   PERFORM MAPREDUCE ON DICTIONARY OBJECTS AND OUTPUT AS TBD
#       -MAP STEP: CREATE KEY-VALUE PAIR FROM DICTIONARY ELEMENTS
#       -REDUCE STEP: REDUCE RECORDS WHERE HOSTNAMES MATCH INTO
#        SINGLE RECORD BY PERFORMING BITWISE-OR ON HEADER BITS
#       -OUTPUT STEP:
#
#  Parameters:
#     -files: FILE CONTAINING PATHS OF WAT FILES WITHIN S3 BUCKET
#
#  Result:    FINAL PRODUCT, WHATEVER THAT MAY BE
#----------------------------------------------------------------------------+
for yy in range(15, 21):
    for mm in range(1, 13):
        yymmstr = str(yy) + "-" + str(mm).zfill(2)
        print("processing " + yymmstr)

        files = sc.textFile("sampledPaths/" + yymmstr + "wat.paths")
        headers = files.mapPartitionsWithIndex(getHeaders) \
            .map(lambda x: (x[0], x[1])) \
            .reduceByKey(lambda x, y: x | y) \
            .partitionBy(partitions)

        headers.saveAsTextFile(yymmstr)

        s3 = boto3.resource('s3')

        for x in range(0, partitions):
            partname = yymmstr + '/part-'
            num = format(x, '05d')
            partname = partname + num

            s3.meta.client.upload_file(partname, 'winthropcsthesis', "nolan/"+ partname + '.txt')

        print("done processing " + yymmstr)
        shutil.rmtree(yymmstr, ignore_errors=True)
