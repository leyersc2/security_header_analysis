    # /*-------------------------------- sampling.py ----------------------
    #  |    program name: sampling.py
    #  |
    #  |    Authors: Connor Leyers, Joshua Paytosh, Nolan Worthy
    #  |
    #  |    Purpose:  Takes a random sample of a specified number of file
    #  |        paths for a given month.
    #  |
    #  |    Result: New paths file containing only the sampled paths with
    #  |        the naming convention YY-MMwat.paths
    #  *-------------------------------------------------------------------*/

from random import randint
from random import seed
from time import time
from linecache import getline
from os import path

seed(time())

filesToSample = 40

# loop by year, and by month within each year
for yy in range(15, 21):
    for mm in range(1, 13):
        yymmstr = str(yy) + "-" + str(mm).zfill(2)

        # tests for 2 possible filepath conventions. if neither are present, skip that month.
        if(path.exists("../paths/extracted/" + yymmstr + "wat.paths/" + yymmstr + "wat.paths")):
            inputFile = open("../paths/extracted/" + yymmstr + "wat.paths/" + yymmstr + "wat.paths", "r")
            pathType = 1
        elif(path.exists("../paths/extracted/" + yymmstr + "wat.paths/wat.paths")):
            inputFile = open("../paths/extracted/" + yymmstr + "wat.paths/wat.paths", "r")
            pathType = 2
        else:
            continue

        lineCount = len(inputFile.readlines())
        randList = [] # list of random numbers generated so far for the current iteration

        outputFile = open("sampledPaths/" + yymmstr + "wat.paths", "w")
        for i in range(0, filesToSample):
            #generate random number
            randInt = randint(1,lineCount)

            # check if random number has already been generated. if it has, get a new random number until it hasn't.
            while randInt in randList:
                randInt = randint(1,lineCount)

            # get path from file
            if(pathType == 1):
                line = getline("../paths/extracted/" + yymmstr + "wat.paths/" + yymmstr + "wat.paths", randInt)
            elif(pathType == 2):
                line = getline("../paths/extracted/" + yymmstr + "wat.paths/wat.paths", randInt)

            ################ THIS CODE CHECKS IF THE NEW SAMPLE CONTAINS ANY PATHS FROM A PREVIOUS SAMPLE ################
                
            # check previous random sample for current path. if it is present, generate new paths until it isn't.
            with open("prevSampleDir/" + yymmstr + "wat.paths", "r") as oldSample:
                while line in oldSample.read():
                    print("collision: " + line)

                    # generate new random number and get the corresponding path
                    randInt = randint(1,lineCount)
                    if(pathType == 1):
                        line = getline("../paths/extracted/" + yymmstr + "wat.paths/" + yymmstr + "wat.paths", randInt)
                    elif(pathType == 2):
                        line = getline("../paths/extracted/" + yymmstr + "wat.paths/wat.paths", randInt)

                    # go back to beginning of previous sample file
                    oldSample.seek(0)
                    
            ##############################################################################################################

            randList.append(randInt)
            outputFile.write(line)

        inputFile.close()
        outputFile.close()
