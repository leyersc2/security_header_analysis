#   NAME:       Joshua Paytosh, Connor Leyers, Nolan Worthy
#   DATE:       10/31/2019
#   PURPOSE:    Establishing a function to parse JSON for the purpose of analyzing common crawl security headers.
#               For testing purposes this file will utilize a local data file consisting of 100 lines of a WAT file.

import json

# SHOULD PROBABLY BE A FILESTREAM
f = open("DATA/CC-MAIN-20160524002110-00000-ip-10-185-217-139.ec2.internal.warc.wat")


# empty dictionary for storage purposes
item = {}

# Counter variable to ensure keys are unique (So that the servers don't overwrite eachother)
i = 0

# Loops through the entire WAT file, and grabs relevant headers, stores them in a dictionary where the key is the server, and the values are the headers ordered in a standardized way.
for line in f:
    try:   
        data = json.loads(line)
        i += 1


        # Possibly attempt to yield each header value instead of a dictionary, map should be forming the key-value pairs
        item[str(i) + "\t" + data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"]["Server"]] = \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-XSS-Protection", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Content-Security-Policy", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Frame-Options", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Strict-Transport-Security", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Content-Type-Options", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Download-Options", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Permitted-Cross-Domain-Policies", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Public-Key-Pins", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("X-Content-Security-Policy", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Expect-CT", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Feature-Policy", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Date", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Referer", "DNE"), \
            data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"].get("Referer-Policy", "DNE") 
            
        # item[data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"]["Server"]] = data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"]["X-XSS-Protection"], data["Envelope"]["Payload-Metadata"]["HTTP-Response-Metadata"]["Headers"]["Date"] 
    except ValueError:
        continue
    except KeyError:
        continue

# for key, value in item.iteritems() :
    # print key,":\t",value


# Changed to return or possibly yield
for key in sorted(item.keys()):
    print key, ":\t", item[key]
