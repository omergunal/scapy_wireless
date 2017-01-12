#!/usr/bin/python

import sys
from scapy.all import *

file = open("wifi.txt", "w") #Toplanan bilgileri wifi.txt ye yaziyoruz

ssids = set()
def Packet(pkt):
	if pkt.haslayer(Dot11Beacon):
		if (pkt.info not in ssids) and pkt.info: # Adresi 2.kez yazmamak icin kontrol ediyoruz
			print len(ssids),pkt.addr2 , pkt.info # Sirali bir sekilde ekrana mac adres 
                                                              #ve ssid bilgilerini basiyoruz
			ssids.add(pkt.info)
			file.write(pkt.info + " " + pkt.addr2 + "\n")

sniff(iface = "wlan1", count = 500, prn = Packet)



