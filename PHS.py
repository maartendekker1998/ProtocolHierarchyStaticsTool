__author__ = "Maarten Dekker"

# This scrip consist of three parts :
# 1: Sampling a library op PCAPs to the desired dataset size
# 2: Perfroming protocol hierarchy statistics using the tshark "io,psh" module and writing this to Redis
# 3: Retrieving the PHS data from a Redis DB and write it to a CSV file

import os
import io
import csv
import subprocess
import re
import redis
import datetime
from random import sample
from tqdm import tqdm

#Setup Redis client to communicate with the database
redisClient = redis.StrictRedis(host='localhost',
                                port=6379,
                                db=0,
                                charset='utf-8',
                                decode_responses=True)

# The two parts of the tshark command that will be concatinated with the PCAP filename
tshark = 'tshark -r '
iophs = ' -qz io,phs'

# For the application layer protocols it is neccesarry to have the protocol above it. Think about dns/tcp and dns/udp.
transportLayerProtocol = ''

#Directory that will be sampled for Protocol Hierarchy Statistics
dirName = './testdata'

# Sample size in bytes
#sampleSize = 50 gb 
sampleSize = 53687091200

# Get the list of all PCAPs in directory tree at given path
listOfFiles = list()
for (dirpath, dirnames, filenames) in os.walk(dirName):
    listOfFiles += [os.path.join(dirpath, file) for file in filenames if file.endswith(".pcap")]

# Sample the total list of PCAPs to the specified size

sampledList = list()
totalsize = 0 

# Check if the requested sample size has been reached
while totalsize < sampleSize:
    
    # Pick one random file from the list op PCAPs
    randomFile = sample(listOfFiles, 1)

    # Remove randomFile from the unsampled list to prevent duplicates
    listOfFiles.remove(randomFile[0])
    # Add randomFile to the sampled list
    sampledList.append(randomFile[0])

    # Reset filesize variable, get filesize and add it to the totalsize
    size = 0
    size = os.path.getsize(randomFile[0])
    totalsize += size

    print(str(randomFile[0]) + "with a size of " + str(size) + " bytes was added to the sample list")
    print("")

# Conclude dataset sampling with the following stats :

print("*******************************************************")
print("Sample list completed with a total size of " + str(totalsize))
print("*******************************************************")
print("")
print("Sample list contains the following files :")
print("")
print(sampledList)
print("")
print("file count is : " + str(len(sampledList)))

# Compute Protocol Hierarchy Statistics for the sampled files
# TQDM module is used for visualizing progress bars

for f in tqdm(sampledList):

    # Concatenating the command for tshark execution
    command = tshark + f + iophs
    print (command)

    # Executing the command
    phs = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)

    # Loop over each line of the tshark results
    for line in io.TextIOWrapper(phs.stdout, encoding="utf-8"):
        if "frames" in line and not re.findall("^\s{7}", line):

        # Regex magic for retrieving the values per layer of the internet protocol suite
        # The protocol name and number of frames are written to the redis DB
        # To replace the number of frames by the number of bytes, change "split[1]" to "split[2]"

        # Link Layer
        # Regex : check if the first char is a character

            if re.findall("^\S", line):
                split = line.split()

                
        # Internet Layer
        # Regex : check if the first 2 characters are whitespaces followed by a letter

            elif re.findall("^\s{2}\S", line):
                split = line.split()
                redisClient.lpush(split[0], ''.join(filter(str.isdigit, split[1])))

        # Transport Layer
        # Regex : check if the first 4 characters are whitespaces followed by a letter

            elif re.findall("^\s{4}\S", line):
                split = line.split()
                transportLayerProtocol = split[0]
                redisClient.lpush(split[0], ''.join(filter(str.isdigit, split[1])))

        # Application layer
        # Regex : check if the first 4 characters are whitespaces followed by a letter

            elif re.findall("^\s{6}\S", line):
                split = line.split()
                # The application layer protocol is concatinated with the transport layer protocol
                # This visualizes the differende between, for instance, dns/tcp and dns/udp
                redisClient.lpush((split[0] + "/" + transportLayerProtocol), ''.join(filter(str.isdigit, split[1])))

# End of the tshark PHS analysis
print("")
print("All PCAPS have been analysed by tshark and the PHS results are push to the redis DB")
print("")

# Retrieve all the protocols from the Redis DB
allProtocols = redisClient.keys('*')

now = datetime.datetime.now()

with open(str(now) + '-protocolHierarchyStatistics.csv', 'w', newline='') as csvFile:
    fieldnames = ['protocol','frames']
    writer = csv.DictWriter(csvFile, fieldnames=fieldnames)
    writer.writeheader()

    for protocol in allProtocols:

        # Range 0 to -1 means that all the values will get pulled
        frameArray = redisClient.lrange(protocol, 0, -1)
        intFrameArray = []
        for i in range(len(frameArray)):
            f = int(frameArray[i])
            intFrameArray.append(f)

        totalFrames = str(sum(intFrameArray))

        print('protocol ' + protocol + "    total frames : " + totalFrames )
        writer.writerow({'protocol': protocol, 'frames': totalFrames})