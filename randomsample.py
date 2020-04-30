from random import randint
from random import seed
from time import time
from linecache import getline
from os import path

seed(time())

filesToSample = 40


for yy in range(15, 21):
    for mm in range(1, 13):
        yymmstr = str(yy) + "-" + str(mm).zfill(2)

        # tests for 2 possible filepaths. if neither are present, skip that month.
        if(path.exists("../paths/extracted/" + yymmstr + "wat.paths/" + yymmstr + "wat.paths")):
            inputFile = open("../paths/extracted/" + yymmstr + "wat.paths/" + yymmstr + "wat.paths", "r")
            pathType = 1
        elif(path.exists("../paths/extracted/" + yymmstr + "wat.paths/wat.paths")):
            inputFile = open("../paths/extracted/" + yymmstr + "wat.paths/wat.paths", "r")
            pathType = 2
        else:
            continue

        lineCount = len(inputFile.readlines())
        randList = []

        outputFile = open("secondSample/" + yymmstr + "wat.paths", "w")
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

            # check previous random sample for current path. if it is present, generate new paths until it isn't.
            with open("sampledPaths/" + yymmstr + "wat.paths", "r") as oldSample:
                while line in oldSample.read():
                    # sound the alarm
                    print("collision: " + line)

                    # generate new random number and get the corresponding path
                    randInt = randint(1,lineCount)
                    if(pathType == 1):
                        line = getline("../paths/extracted/" + yymmstr + "wat.paths/" + yymmstr + "wat.paths", randInt)
                    elif(pathType == 2):
                        line = getline("../paths/extracted/" + yymmstr + "wat.paths/wat.paths", randInt)

                    # go back to beginning of previous sample file
                    oldSample.seek(0)

            randList.append(randInt)
            outputFile.write(line)

        inputFile.close()
        outputFile.close()
