__author__ = 'Gauresh Pandit'
import binascii
import gzip
import sys
import os
import time
# from StringIO import StringIO
def do_tshark_follows(pcap_file, follow_folder):
    command = ("PCAP_FILE='" + pcap_file + "'\n" +
               "follow_folder='" + follow_folder + "'\n" +
               "END=$(tshark -r $PCAP_FILE -T fields -e tcp.stream | sort -n | tail -1)\n" +
               "echo $END+1 $PCAP_FILE\n" +
               "for i in $(seq 0 $END)\n" +
               "do\n" +
                "\ttshark -r $PCAP_FILE -qz follow,tcp,hex,$i >> $follow_folder/follow-stream-$i.txt\n" +
               "done"
              )
    os.system(command)

pcap_dir = sys.argv[1]
follow_folder = sys.argv[2]
if not os.path.isdir(follow_folder):
	os.makedirs(follow_folder)
for file in os.listdir(pcap_dir):
	do_tshark_follows(pcap_dir+file,follow_folder)

folder = sys.argv[0]
arr = []
flag = 0;
openedFile = None


def tryForGzip(strings):
    for val in strings:
        #print("\n\n\n\n\n\n\n In Here \n\n\n\n\n\n")
        #print(strings)
        try:
            print(gzip.decompress(binascii.unhexlify(val)).decode("utf-8"))
        except:
            #print("couldnt decompress")
            continue


def getPossibleStrings(fline, file):
    completeLine = fline.strip('\t ').split(' ', 1)[1][:-19].replace(" ", "")
    dict = []
    for line in file:
        if (not line.startswith("\t")):
            break
        completeLine += line.strip('\t ').split(' ', 1)[1][:-19].replace(" ", "")
    try:
        num = completeLine.index('1f8b')
    except ValueError:
        return dict
    while (num > -1):
        dict.append(completeLine[num:])
        time.sleep(1)
        curLine = completeLine[num + 1:]
        try:
            num += curLine.index('1f8b') + 1
        except ValueError:
            num = -1
    return dict


for dirname, subdirList, fileList in os.walk('.'):
    for fileInDir in fileList:
        if not fileInDir.endswith('.py'):
            openedFile = open(dirname + '/' + fileInDir)
            for line in openedFile:
                if (not line.startswith("\t")):
                    continue;
                else:
                    arr = getPossibleStrings(line, openedFile)
                    tryForGzip(arr)

hex = ''
first = 0