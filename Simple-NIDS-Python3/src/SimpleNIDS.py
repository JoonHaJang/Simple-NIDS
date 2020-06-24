from scapy.all import *
from sys import argv
import logging
import datetime
from HttpUtils import *
import RuleFileReader
from Sniffer import *

RED = '\033[91m'
BLUE = '\033[34m'
GREEN = '\033[32m'
ENDC = '\033[0m'

def main(filename):
    """Read the rule file and start listening."""
    now = datetime.now()
    logging.basicConfig(filename= "Simple-NIDS " + str(now) + '.log',level=logging.INFO)
    print ("\033[1m\033[32m\033[32m=====================================================================\nNetwork Instruction Detection System now started.\nReading Rulefile..\nFilename is %s\n=====================================================================\033[0m"%filename)
    # Read the rule file
    global ruleList
    ruleList, errorCount = RuleFileReader.read(filename);
    print ("\033[1m\033[32mReading Rule Completed!!\n")
    print("=====================================================================\033[0m")
    if (errorCount == 0):
        print("\033[1m\033[91m||All (" + str(len(ruleList)) + ") rules have been correctly read.||\n")
    else:
        print("\033[1m(" +str(errorCount)+ ")rules have errors and could not be read.")
    for index,rule in enumerate(ruleList):
        print("\033[1m\033[32mRulenumber %d. %50s" %(index, rule))
    # Begin sniffing with ruleList ruleList is features parsed from txtfile
    sniffer = Sniffer(ruleList)
    sniffer.run()
    # Stop sniffing if you command "ctrl+c"
    sniffer.stop()
    print("\n")
    print ("\033[1m\033[91m==================================================================\nNIDS is shutting down\033[0m")

ruleList = list()
script, filename = argv
main(filename)
