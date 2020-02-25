import json
import boto
from boto.s3.key import Key
from boto.s3.connection import S3Connection
from gzipstream import GzipStreamFile
import warc
from pyspark import SparkContext
from urlparse import urlparse
import hashlib

sc = SparkContext.getOrCreate()


# SHOULD PROBABLY BE A FILESTREAM
# f = open("/home/josh/Desktop/THESIS/DATA/CC-MAIN-20160524002110-00000-ip-10-185-217-139.ec2.internal.warc.wat")


X_XSS_Protection_FLAG = 0b100000000000
Content_Security_Policy_FLAG = 0b010000000000
X_Frame_Options_FLAG = 0b001000000000
Strict_Transport_Security_FLAG = 0b000100000000
X_Content_Type_Options_FLAG = 0b000010000000
X_Download_Options_FLAG = 0b000001000000
X_Permitted_Cross_Domain_Policies_FLAG = 0b000000100000
X_Public_Key_Pins_FLAG = 0b000000010000
X_Content_Security_Policy_FLAG = 0b000000010000
Expect_CT_FLAG = 0b000000001000
Feature_Policy_FLAG = 0b000000000100
Referer_FLAG = 0b000000000010
Referer_Policy_FLAG = 0b000000000001

def getHeaders (id_, iterator):

    conn = S3Connection(host="s3.amazonaws.com")

    bucket = conn.get_bucket("commoncrawl")

    for uri in iterator:
        key_ = Key(bucket,uri)
        file_ = warc.WARCFile(fileobj = GzipStreamFile(key_))

        # Loops through the entire WAT file, and grabs relevant headers, stores them in a dictionary where the key is the server, and the values are the headers ordered in a standardized way.
        for line in file_:
            try:
                data = json.loads(line.payload.read())


                retArray = [None, 0b0000000000000]
                if(data["Envelope"]["WARC-Header-Metadata"]["WARC-Type"] == "response"):

                    retArray[0] = hashlib.md5(urlparse(data["Envelope"]["WARC-Header-Metadata"].get("WARC-Target-URI", "")).hostname).digest()
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-XSS-Protection", "") != ""):
                        retArray[1] = retArray[1] | X_XSS_Protection_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Content-Security-Policy", "") != ""):
                        retArray[1] = retArray[1] | Content_Security_Policy_FLAG
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
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Public-Key-Pins", "")!= ""):
                        retArray[1] = retArray[1] | X_Public_Key_Pins_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Content-Security-Policy", "")!= ""):
                        retArray[1] = retArray[1] | X_Content_Security_Policy_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Expect-CT", "")!= ""):
                        retArray[1] = retArray[1] | Expect_CT_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Feature-Policy", "")!= ""):
                        retArray[1] = retArray[1] | Feature_Policy_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Referer", "")!= ""):
                        retArray[1] = retArray[1] | Referer_FLAG
                    if(data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Referer-Policy", "")!= ""):
                        retArray[1] = retArray[1] | Referer_Policy_FLAG
                    yield retArray

            except ValueError:
                continue
            except KeyError:
                continue
            except UnboundLocalError:
                continue

files = sc.textFile("testwat.paths")
headers = files.mapPartitionsWithIndex(getHeaders) \
    .map(lambda x: (x[0], x[1])) \
    .reduceByKey(lambda x, y: x | y)

#print(headers.count())
for x in headers.take(1):
    print(x)
for x in headers.take(1):
    print(x)


