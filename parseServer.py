#   NAME:       Joshua Paytosh, Connor Leyers, Nolan Worthy
#   DATE:       10/31/2019
#   PURPOSE:    Establishing a function to parse JSON for the purpose of analyzing common crawl security headers.
#               For testing purposes this file will utilize a local data file consisting of 100 lines of a WAT file.

#edits to be made bi-weekly

import json
import boto
from boto.s3.key import Key
from boto.s3.connection import S3Connection
from gzipstream import GzipStreamFile
import warc
from pyspark import SparkContext
from urlparse import urlparse

sc = SparkContext.getOrCreate()


# SHOULD PROBABLY BE A FILESTREAM
# f = open("/home/josh/Desktop/THESIS/DATA/CC-MAIN-20160524002110-00000-ip-10-185-217-139.ec2.internal.warc.wat")



def getHeaders (id_, iterator):
    # Counter variable to ensure keys are unique (So that the servers don't overwrite eachother)

    conn = S3Connection(host="s3.amazonaws.com")

    bucket = conn.get_bucket("commoncrawl")

    for uri in iterator:
        key_ = Key(bucket,uri)
        file_ = warc.WARCFile(fileobj = GzipStreamFile(key_))

        # Loops through the entire WAT file, and grabs relevant headers, stores them in a dictionary where the key is the server, and the values are the headers ordered in a standardized way.
        for line in file_:
            try:
                data = json.loads(line.payload.read())

                # Possibly attempt to yield each header value instead of a dictionary, map should be forming the key-value pairs
                # yield data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Server", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-XSS-Protection", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Content-Security-Policy", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Frame-Options", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Strict-Transport-Security", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Content-Type-Options", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Download-Options", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Permitted-Cross-Domain-Policies", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Public-Key-Pins", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Content-Security-Policy", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Expect-CT", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Feature-Policy", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Date", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Referer", ""), \
                #     data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Referer-Policy", "")

                retArray = [None] * 16
                retArray[0] = urlparse(data["Envelope"]["WARC-Header-Metadata"].get("WARC-Target-URI", "")).netloc
                if(retArray[0] != ""):
                    retArray[1] = 1
                else:
                    retArray[1] = 0
                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-XSS-Protection", "") != ""):
                    retArray[2] = 1
                else:
                    retArray[2] = 0
                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Content-Security-Policy", "") != ""):
                    retArray[3] = 1
                else:
                    retArray[3] = 0
                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Frame-Options", "") != ""):
                    retArray[4] = 1
                else:
                    retArray[4] = 0
                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Strict-Transport-Security", "")!= ""):
                    retArray[5] = 1
                else:
                    retArray[5] = 0
                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Content-Type-Options", "")!= ""):
                    retArray[6] = 1
                else:
                    retArray[6] = 0
                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Download-Options", "")!= ""):
                    retArray[7] = 1
                else:
                    retArray[7] = 0
                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Permitted-Cross-Domain-Policies", "")!= ""):
                    retArray[8] = 1
                else:
                    retArray[8] = 0
                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Public-Key-Pins", "")!= ""):
                    retArray[9] = 1
                else:
                    retArray[9] = 0

                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Content-Security-Policy", "")!= ""):
                    retArray[10] = 1
                else:
                    retArray[10] = 0
                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Expect-CT", "")!= ""):
                    retArray[11] = 1
                else:
                    retArray[11] = 0
                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Feature-Policy", "")!= ""):
                    retArray[12] = 1
                else:
                    retArray[12] = 0
                retArray[15] = data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Date", "")
                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Referer", "")!= ""):
                    retArray[13] = 1
                else:
                    retArray[13] = 0
                if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Referer-Policy", "")!= ""):
                    retArray[14] = 1
                else:
                    retArray[14] = 0

                yield retArray

            except ValueError:
                continue
            except KeyError:
                continue
            except UnboundLocalError:
                continue

files = sc.textFile("testwat.paths")
headers = files.mapPartitionsWithIndex(getHeaders) \
    .map(lambda x: (x[0], (x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14],x[15]))) \
    #.reduceByKey(lambda x, y: x + y)

sumcount = headers.aggregateByKey((0,0,0,0,0,0,0,0,0,0,0,0,0,0),\
    (lambda x, y: (x[0]+y[0], x[1]+y[1], x[2]+y[2], x[3]+y[3], x[4]+y[4], x[5]+y[5], x[6]+y[6], x[7]+y[7], x[8]+y[8], x[9]+y[9], x[10]+y[10], x[11]+y[11], x[12]+y[12], x[13]+y[13])),\
    (lambda rdd1, rdd2: (rdd1[0]+rdd2[0], rdd1[1]+rdd2[1], rdd1[2]+rdd2[2], rdd1[3]+rdd2[3],rdd1[4]+rdd2[4],rdd1[5]+rdd2[5],rdd1[6]+rdd2[6],rdd1[7]+rdd2[7],rdd1[8]+rdd2[8],rdd1[9]+rdd2[9], rdd1[10]+rdd2[10], rdd1[11]+rdd2[11], rdd1[12]+rdd2[12], rdd1[13]+rdd2[13])))


for x in sumcount.collect():
        string = x[0]
        for y in x[1]:
                string = string + ","
                if(y != 0):
                        string = string + str(y)
        print(string)
