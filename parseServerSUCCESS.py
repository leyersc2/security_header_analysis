#   NAME:       Joshua Paytosh, Connor Leyers, Nolan Worthy
#   DATE:       10/31/2019
#   PURPOSE:    Establishing a function to parse JSON for the purpose of analyzing common crawl security headers.
#               For testing purposes this file will utilize a local data file consisting of 100 lines of a WAT file.

import json
import boto
from boto.s3.key import Key
from boto.s3.connection import S3Connection
from gzipstream import GzipStreamFile
import warc
from pyspark import SparkContext

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
                yield data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Server", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-XSS-Protection", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Content-Security-Policy", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Frame-Options", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Strict-Transport-Security", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Content-Type-Options", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Download-Options", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Permitted-Cross-Domain-Policies", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Public-Key-Pins", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Content-Security-Policy", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Expect-CT", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Feature-Policy", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Date", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Referer", ""), \
                    data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Referer-Policy", "")


            except ValueError:
                continue
            except KeyError:
                continue
            except UnboundLocalError:
                continue

files = sc.textFile("testwat.paths")
headers = files.mapPartitionsWithIndex(getHeaders) \
    .map(lambda x: (x[0], x[1:14]))

print("DONE")

for x in headers.collect():
    print x
