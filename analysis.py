 # /*----------------------------- analysis.py -------------------------
 #  |   program name: analysis.py
 #  |
 #  |   Authors: Connor Leyers, Joshua Paytosh, Nolan Worthy
 #  |
 #  |   Purpose:  Analyzing output of mapreduce.py as retrieved from
 #  |       S3. For every month, counts total number of records (hosts)
 #  |       and number of records containing each header.
 #  |
 #  |  Result: .txt file
 #  *-------------------------------------------------------------------*/

from __future__ import division
import boto3
import codecs
import sys
import os

# connect to our s3 bucket (supply access key and secret key)
s3 = boto3.client('s3', aws_access_key_id='', aws_secret_access_key='')

# binary flags for headers
X_XSS_Protection_FLAG =                     0b100000000000000000000 # header 1
Content_Security_Policy_FLAG =              0b010000000000000000000 # header 2
X_Content_Security_Policy_FLAG =            0b001000000000000000000 # header 3
X_Frame_Options_FLAG =                      0b000100000000000000000 # header 4
Strict_Transport_Security_FLAG =            0b000010000000000000000 # header 5
X_Content_Type_Options_FLAG =               0b000001000000000000000 # header 6
X_Download_Options_FLAG =                   0b000000100000000000000 # header 7
X_Permitted_Cross_Domain_Policies_FLAG =    0b000000010000000000000 # header 8
Expect_CT_FLAG =                            0b000000001000000000000 # header 9
Feature_Policy_FLAG =                       0b000000000100000000000 # header 10
Referrer_Policy_FLAG =                      0b000000000010000000000 # header 11
X_Public_Key_Pins_FLAG =                    0b000000000001000000000 # header 12
X_Public_Key_Pins_Report_Only_FLAG =        0b000000000000100000000 # header 13
Public_Key_Pins_FLAG =                      0b000000000000010000000 # header 14
Public_Key_Pins_Report_Only_FLAG =          0b000000000000001000000 # header 15
Access_Control_Allow_Origin_FLAG =          0b000000000000000100000 # header 16
Access_Control_Allow_Credentials_FLAG =     0b000000000000000010000 # header 17
Access_Control_Allow_Methods_FLAG =         0b000000000000000001000 # header 18
Access_Control_Allow_Headers_FLAG =         0b000000000000000000100 # header 19
Access_Control_Expose_Headers_FLAG =        0b000000000000000000010 # header 20
Access_Control_Max_Age_FLAG =               0b000000000000000000001 # header 21

# loop by year, and by month within each year
for yy in range(15, 21):
    for mm in range(1, 13):
        failed = False

        yymmstr = str(yy) + "-" + str(mm).zfill(2)
        print(yymmstr + " - started")

        # if we haven't analyzed this month, analyze it
        if(not os.path.exists("./results/" + yymmstr + "results.txt")):

            # initialize counts for hosts and headers to 0 for current month
            host_ct = 0
            head1_ct = 0 # X-XSS-Protection
            head2_ct = 0 # Content-Security-Policy
            head3_ct = 0 # X-Content-Security-Policy
            head4_ct = 0 # X-Frame-Options
            head5_ct = 0 # Strict-Transport-Security
            head6_ct = 0 # X-Content-Type-Options
            head7_ct = 0 # X-Download-Options
            head8_ct = 0 # X-Permitted-Cross-Domain-Policies
            head9_ct = 0 # Expect-CT
            head10_ct = 0 # Feature-Policy
            head11_ct = 0 # Referrer-Policy
            head12_ct = 0 # X-Public-Key-Pins
            head13_ct = 0 # X-Public-Key-Pins-Report-Only
            head14_ct = 0 # Public-Key-Pins
            head15_ct = 0 # Public-Key-Pins-Report-Only
            head16_ct = 0 # Access-Control-Allow-Origin
            head17_ct = 0 # Access-Control-Allow-Credentials
            head18_ct = 0 # Access-Control-Allow-Methods
            head19_ct = 0 # Access-Control-Allow-Headers
            head20_ct = 0 # Access-Control-Expose-Headers
            head21_ct = 0 # Access-Control-Max-Age

            # loop through input files for current month (starts at zero, one for every partition)
            for x in range(0, 10):
                x = format(x, '05d')
                keystring = "nolan/" + yymmstr + "/part-" + str(x) + ".txt"

                # if the file we're looking for doesn't exist in bucket, skip this month
                try:
                    obj = s3.get_object(Bucket='winthropcsthesis', Key=keystring)
                except:
                    # set failed to True, break out of this loop, and use Failed to skip to next month
                    failed = True
                    print(yymmstr + " - " + keystring + " does not exist in s3. skipping month.")
                    break

                body = obj['Body']

                # for every record in the object retrieved from s3, do bitwise operations
                for ln in codecs.getreader('utf-8')(body):
                    host_ct = host_ct + 1
                    headers = ln.rsplit(', ')[-1][:-2] #splits string at commas, takes last element
                    if int(headers) & X_XSS_Protection_FLAG == X_XSS_Protection_FLAG:
                        head1_ct = head1_ct + 1
                    if int(headers) & Content_Security_Policy_FLAG == Content_Security_Policy_FLAG:
                        head2_ct = head2_ct + 1
                    if int(headers) & X_Content_Security_Policy_FLAG == X_Content_Security_Policy_FLAG:
                        head3_ct = head3_ct + 1
                    if int(headers) & X_Frame_Options_FLAG == X_Frame_Options_FLAG:
                        head4_ct = head4_ct + 1
                    if int(headers) & Strict_Transport_Security_FLAG == Strict_Transport_Security_FLAG:
                        head5_ct = head5_ct + 1
                    if int(headers) & X_Content_Type_Options_FLAG == X_Content_Type_Options_FLAG:
                        head6_ct = head6_ct + 1
                    if int(headers) & X_Download_Options_FLAG == X_Download_Options_FLAG:
                        head7_ct = head7_ct + 1
                    if int(headers) & X_Permitted_Cross_Domain_Policies_FLAG == X_Permitted_Cross_Domain_Policies_FLAG:
                        head8_ct = head8_ct + 1
                    if int(headers) & Expect_CT_FLAG == Expect_CT_FLAG:
                        head9_ct = head9_ct + 1
                    if int(headers) & Feature_Policy_FLAG == Feature_Policy_FLAG:
                        head10_ct = head10_ct + 1
                    if int(headers) & Referrer_Policy_FLAG == Referrer_Policy_FLAG:
                        head11_ct = head11_ct + 1
                    if int(headers) & X_Public_Key_Pins_FLAG == X_Public_Key_Pins_FLAG:
                        head12_ct = head12_ct + 1
                    if int(headers) & X_Public_Key_Pins_Report_Only_FLAG == X_Public_Key_Pins_Report_Only_FLAG:
                        head13_ct = head13_ct + 1
                    if int(headers) & Public_Key_Pins_FLAG == Public_Key_Pins_FLAG:
                        head14_ct = head14_ct + 1
                    if int(headers) & Public_Key_Pins_Report_Only_FLAG == Public_Key_Pins_Report_Only_FLAG:
                        head15_ct = head15_ct + 1
                    if int(headers) & Access_Control_Allow_Origin_FLAG == Access_Control_Allow_Origin_FLAG:
                        head16_ct = head16_ct + 1
                    if int(headers) & Access_Control_Allow_Credentials_FLAG == Access_Control_Allow_Credentials_FLAG:
                        head17_ct = head17_ct + 1
                    if int(headers) & Access_Control_Allow_Methods_FLAG == Access_Control_Allow_Methods_FLAG:
                        head18_ct = head18_ct + 1
                    if int(headers) & Access_Control_Allow_Headers_FLAG == Access_Control_Allow_Headers_FLAG:
                        head19_ct = head19_ct + 1
                    if int(headers) & Access_Control_Expose_Headers_FLAG == Access_Control_Expose_Headers_FLAG:
                        head20_ct = head20_ct + 1
                    if int(headers) & Access_Control_Max_Age_FLAG == Access_Control_Max_Age_FLAG:
                        head21_ct = head21_ct + 1

            if failed:
                print(yymmstr + " - aborted")
                continue

            # write results to file
            oFile = open("./results/" + yymmstr + "results.txt", "w")
            oFile.write(str(host_ct) + "\n")
            oFile.write(str(head1_ct) + "\n") # X-XSS-Protection
            oFile.write(str(head2_ct) + "\n") # Content-Security-Policy
            oFile.write(str(head3_ct) + "\n") # X-Content-Security-Policy
            oFile.write(str(head4_ct) + "\n") # X-Frame-Options
            oFile.write(str(head5_ct) + "\n") # Strict-Transport-Security
            oFile.write(str(head6_ct) + "\n") # X-Content-Type-Options
            oFile.write(str(head7_ct) + "\n") # X-Download-Options
            oFile.write(str(head8_ct) + "\n") # X-Permitted-Cross-Domain-Policies
            oFile.write(str(head9_ct) + "\n") # Expect-CT
            oFile.write(str(head10_ct) + "\n") # Feature-Policy
            oFile.write(str(head11_ct) + "\n") # Referrer-Policy
            oFile.write(str(head12_ct) + "\n") # X-Public-Key-Pins
            oFile.write(str(head13_ct) + "\n") # X-Public-Key-Pins-Report-Only
            oFile.write(str(head14_ct) + "\n") # Public-Key-Pins
            oFile.write(str(head15_ct) + "\n") # Public-Key-Pins-Report-Only
            oFile.write(str(head16_ct) + "\n") # Access-Control-Allow-Origin
            oFile.write(str(head17_ct) + "\n") # Access-Control-Allow-Credentials
            oFile.write(str(head18_ct) + "\n") # Access-Control-Allow-Methods
            oFile.write(str(head19_ct) + "\n") # Access-Control-Allow-Headers
            oFile.write(str(head20_ct) + "\n") # Access-Control-Expose-Headers
            oFile.write(str(head21_ct)) # Access-Control-Max-Age
            oFile.close()

            print(yymmstr + " - completed")
        else:
            print(yymmstr + " - already exists")
